use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Arc;
use sxiaum_block::Block;
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use sxiaum_types::Address;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisAlloc {
    pub balance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vesting: Option<crate::GenesisVesting>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisVesting {
    pub start_ts: u64,
    pub cliff_secs: u64,
    pub duration_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisValidator {
    pub address: String,
    pub pubkey: String,
    pub stake: String,
    pub voting_power: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub alloc: std::collections::HashMap<String, GenesisAlloc>,
    pub validators: Vec<GenesisValidator>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Parser)]
#[command(name = "sxiaum-genesis")]
#[command(about = "SXIAUM Genesis block generation and configuration tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new genesis configuration template
    Init {
        #[arg(long, default_value = "genesis.json")]
        output: String,
        #[arg(long, default_value = "13689")]
        chain_id: String,
    },
    /// Generate a cryptographically secure random validator keypair with BLS PoP
    GenerateValidatorKey,
    /// Add a validator to the genesis configuration
    AddValidator {
        #[arg(long)]
        address: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        stake: String,
        #[arg(
            long,
            help = "Voting power (automatically derived from stake if omitted)"
        )]
        voting_power: Option<u64>,
        #[arg(long, default_value = "genesis.json")]
        config: String,
    },
    /// Add a funded allocation account to the genesis configuration
    AddAlloc {
        #[arg(long)]
        address: String,
        #[arg(long)]
        balance: String,
        #[arg(long, default_value = "genesis.json")]
        config: String,
        #[arg(long)]
        vesting_start: Option<u64>,
        #[arg(long)]
        cliff_secs: Option<u64>,
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    /// Finalize the genesis config and compute the deterministic genesis block hash
    Finalize {
        #[arg(long, default_value = "genesis.json")]
        config: String,
        #[arg(long)]
        set_timestamp: bool,
    },
    /// Verify a finalized genesis config locally
    Verify {
        #[arg(long, default_value = "genesis.json")]
        config: String,
    },
    /// Sign a genesis config attestation
    SignGenesis {
        #[arg(long, default_value = "genesis.json")]
        config: String,
        #[arg(long)]
        key: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { output, chain_id } => {
            let mut extra = std::collections::HashMap::new();
            extra.insert(
                "commit_reveal".to_string(),
                serde_json::json!({
                    "commit_fee": "1000000000000000000",
                    "reveal_window": 100,
                    "expiry_blocks": 50,
                    "no_show_slash": 100000000,
                    "max_commits_per_sender": 16
                }),
            );

            let config = GenesisConfig {
                chain_id: chain_id.clone(),
                alloc: std::collections::HashMap::new(),
                validators: Vec::new(),
                extra,
            };
            let data = serde_json::to_string_pretty(&config)?;
            fs::write(&output, data)?;
            println!(
                "Initialized new genesis configuration template at '{}'",
                output
            );
        }
        Commands::GenerateValidatorKey => {
            use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};

            let (ed_sk, ed_pk) = sxiaum_crypto::ed25519::generate_keypair();
            let address = sxiaum_types::Address::from_public_key(&ed_pk.0);

            let (bls_sk, bls_pk) = bls_generate_keypair();
            let pop = create_proof_of_possession(&bls_sk, &bls_pk)
                .context("Failed to generate BLS proof of possession")?;

            let result = serde_json::json!({
                "address": format!("0x{}", hex::encode(address.as_bytes())),
                "pubkey": format!("0x{}", hex::encode(ed_pk.0)),
                "bls_pubkey": format!("0x{}", hex::encode(bls_pk.0)),
                "bls_pop": format!("0x{}", hex::encode(pop.0)),
                "private_seed": format!("0x{}", hex::encode(ed_sk.0)),
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::AddValidator {
            address,
            pubkey,
            stake,
            voting_power,
            config,
        } => {
            use std::str::FromStr;
            let content = fs::read_to_string(&config)
                .context(format!("Failed to read config file '{}'", config))?;
            let mut genesis_config: GenesisConfig = serde_json::from_str(&content)?;

            // 1. Validate address format
            let addr = Address::from_str(&address)
                .context("Invalid validator address format (must be 40 or 64 hex chars)")?;

            // 2. Validate pubkey format & Ed25519 curve point
            let pk_clean = pubkey
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            let pk_bytes = hex::decode(pk_clean).context("Invalid validator pubkey hex format")?;
            if pk_bytes.len() != 32 {
                anyhow::bail!(
                    "Invalid validator pubkey length: expected 32 bytes, got {}",
                    pk_bytes.len()
                );
            }
            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);
            sxiaum_crypto::ed25519::PublicKey(pk_arr)
                .validate()
                .context("Invalid Ed25519 validator public key curve point")?;

            // 3. Validate address derivation matches pubkey
            let derived_addr = Address::from_public_key(&pk_arr);
            if addr != derived_addr {
                anyhow::bail!(
                    "Validator address does not match public key: provided {}, derived {}",
                    addr,
                    derived_addr
                );
            }

            // 4. Parse stake amount
            let stake_clean = stake.trim();
            let stake_u256 = if stake_clean.starts_with("0x") || stake_clean.starts_with("0X") {
                U256::from_str_radix(
                    stake_clean
                        .trim_start_matches("0x")
                        .trim_start_matches("0X"),
                    16,
                )?
            } else {
                U256::from_str_radix(stake_clean, 10)?
            };
            if stake_u256.is_zero() {
                anyhow::bail!("Validator stake cannot be zero");
            }

            // 5. Enforce protocol voting power conversion: 1 power per 10^18 wei
            let expected_power = sxiaum_types::Validator::calculate_voting_power(stake_u256);
            let final_voting_power = if let Some(provided_power) = voting_power {
                if provided_power != expected_power {
                    anyhow::bail!(
                        "Voting power mismatch for stake {}: expected {}, provided {}",
                        stake_clean,
                        expected_power,
                        provided_power
                    );
                }
                provided_power
            } else {
                expected_power
            };

            // 6. Build and validate Validator object
            let mut validator = sxiaum_types::Validator::new(addr, pk_arr, stake_u256);
            validator.voting_power = final_voting_power;
            validator
                .validate()
                .context("Validator invariant validation failed")?;

            // Check for duplicate in config
            if genesis_config.validators.iter().any(|v| {
                Address::from_str(&v.address)
                    .map(|a| a == addr)
                    .unwrap_or(false)
            }) {
                anyhow::bail!(
                    "Validator with address {} already exists in config",
                    address
                );
            }

            genesis_config.validators.push(GenesisValidator {
                address,
                pubkey,
                stake,
                voting_power: final_voting_power,
            });

            let data = serde_json::to_string_pretty(&genesis_config)?;
            fs::write(&config, data)?;
            println!("Added validator successfully to '{}'", config);
        }
        Commands::AddAlloc {
            address,
            balance,
            config,
            vesting_start,
            cliff_secs,
            duration_secs,
        } => {
            use std::str::FromStr;
            let content = fs::read_to_string(&config)
                .context(format!("Failed to read config file '{}'", config))?;
            let mut genesis_config: GenesisConfig = serde_json::from_str(&content)?;

            // Validate address format (accepts EVM 20-byte and native 32-byte)
            let _ = Address::from_str(&address).context("Invalid allocation address format")?;

            // Validate balance
            let balance_clean = balance.trim();
            let _ = if balance_clean.starts_with("0x") || balance_clean.starts_with("0X") {
                U256::from_str_radix(
                    balance_clean
                        .trim_start_matches("0x")
                        .trim_start_matches("0X"),
                    16,
                )?
            } else {
                U256::from_str_radix(balance_clean, 10)?
            };

            let vesting = if let (Some(start_ts), Some(cliff_secs), Some(duration_secs)) =
                (vesting_start, cliff_secs, duration_secs)
            {
                if cliff_secs > duration_secs {
                    anyhow::bail!("Vesting cliff cannot exceed duration");
                }
                Some(GenesisVesting {
                    start_ts,
                    cliff_secs,
                    duration_secs,
                })
            } else {
                None
            };

            genesis_config
                .alloc
                .insert(address, GenesisAlloc { balance, vesting });

            let data = serde_json::to_string_pretty(&genesis_config)?;
            fs::write(&config, data)?;
            println!("Added allocation successfully to '{}'", config);
        }
        Commands::Finalize {
            config,
            set_timestamp,
        } => {
            use std::str::FromStr;
            let content = fs::read_to_string(&config)
                .context(format!("Failed to read config file '{}'", config))?;
            let mut genesis_config: GenesisConfig = serde_json::from_str(&content)?;

            println!(
                "Finalizing genesis configuration for chain: {}...",
                genesis_config.chain_id
            );

            // Production validation: at least one validator
            if genesis_config.validators.is_empty() {
                anyhow::bail!("Cannot finalize genesis with zero validators. Add at least one validator before finalizing.");
            }

            // Production validation: independently revalidate all validators
            let mut seen_val_addrs = std::collections::HashSet::new();
            for (idx, val_entry) in genesis_config.validators.iter().enumerate() {
                let v_addr = Address::from_str(&val_entry.address)
                    .context(format!("Invalid validator address at index {idx}"))?;
                if !seen_val_addrs.insert(v_addr) {
                    anyhow::bail!("Duplicate validator address in genesis config: {}", v_addr);
                }

                let pk_clean = val_entry
                    .pubkey
                    .trim()
                    .trim_start_matches("0x")
                    .trim_start_matches("0X");
                let pk_bytes = hex::decode(pk_clean)
                    .context(format!("Invalid validator pubkey hex at index {idx}"))?;
                if pk_bytes.len() != 32 {
                    anyhow::bail!(
                        "Invalid validator pubkey length at index {idx}: expected 32 bytes, got {}",
                        pk_bytes.len()
                    );
                }
                let mut pk_arr = [0u8; 32];
                pk_arr.copy_from_slice(&pk_bytes);

                let stake_clean = val_entry.stake.trim();
                let stake_u256 = if stake_clean.starts_with("0x") || stake_clean.starts_with("0X") {
                    U256::from_str_radix(
                        stake_clean
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    )?
                } else {
                    U256::from_str_radix(stake_clean, 10)?
                };

                let mut validator = sxiaum_types::Validator::new(v_addr, pk_arr, stake_u256);
                validator.voting_power = val_entry.voting_power;
                validator.validate().context(format!(
                    "Genesis validator at index {idx} failed invariant validation"
                ))?;
            }

            // Production validation: non-zero timestamp
            let timestamp = if set_timestamp {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            } else {
                genesis_config
                    .extra
                    .get("genesis_timestamp")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            };
            if timestamp == 0 {
                anyhow::bail!("Cannot finalize genesis with zero timestamp. Use --set-timestamp or set genesis_timestamp in the config.");
            }
            genesis_config.extra.insert(
                "genesis_timestamp".to_string(),
                serde_json::Value::Number(timestamp.into()),
            );

            // Create a temporary database file
            let temp_db_path =
                std::env::temp_dir().join(format!("sxiaum-genesis-{}.redb", rand::random::<u32>()));
            let temp_db_str = temp_db_path
                .to_str()
                .context("Invalid temporary database path")?;
            let storage = Arc::new(StorageEngine::new(temp_db_str)?);
            let state = StateDB::new(storage.clone());

            // Precompute KZG basis
            sxiaum_crypto::kzg::precompute_kzg_basis();

            // Apply allocations
            for (address_str, alloc_data) in &genesis_config.alloc {
                let address = Address::from_str(address_str).context(format!(
                    "Invalid genesis allocation address: {}",
                    address_str
                ))?;

                let balance = if alloc_data.balance.starts_with("0x")
                    || alloc_data.balance.starts_with("0X")
                {
                    U256::from_str_radix(
                        alloc_data
                            .balance
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    )?
                } else {
                    U256::from_str_radix(&alloc_data.balance, 10)?
                };

                state.set_balance(&address, balance)?;

                if let Some(vesting) = &alloc_data.vesting {
                    let schedule = sxiaum_types::vesting::VestingSchedule {
                        total_wei: balance,
                        start_ts: vesting.start_ts,
                        cliff_secs: vesting.cliff_secs,
                        duration_secs: vesting.duration_secs,
                        released_wei: U256::zero(),
                    };
                    state.set_vesting_schedule(&address, schedule)?;
                }
            }

            state.commit()?;
            let state_root = state.state_root();

            // Construct deterministic genesis block
            let mut genesis_block = Block::genesis(state_root);
            genesis_block.header.set_timestamp(timestamp);
            let genesis_hash = genesis_block
                .try_hash()
                .context("Failed to compute genesis block hash")?;

            println!("Deterministic Genesis block computed successfully!");
            println!("--------------------------------------------------");
            println!("Chain ID:          {}", genesis_config.chain_id);
            println!("Timestamp:         {}", timestamp);
            println!("State Root Hash:   0x{}", hex::encode(state_root));
            println!("Genesis Block Hash: 0x{}", hex::encode(genesis_hash));
            println!("--------------------------------------------------");

            genesis_config.extra.insert(
                "initial_state_root".to_string(),
                serde_json::Value::String(format!("0x{}", hex::encode(state_root))),
            );
            genesis_config.extra.insert(
                "genesis_hash".to_string(),
                serde_json::Value::String(format!("0x{}", hex::encode(genesis_hash))),
            );

            let data = serde_json::to_string_pretty(&genesis_config)?;
            fs::write(&config, data)?;
            println!("Wrote finalized data back to {}", config);

            // Cleanup temp file
            drop(state);
            drop(storage);
            let _ = fs::remove_file(temp_db_path);
        }
        Commands::Verify { config } => {
            use std::str::FromStr;
            let content = fs::read_to_string(&config)
                .context(format!("Failed to read config file '{}'", config))?;
            let genesis_config: GenesisConfig = serde_json::from_str(&content)?;

            let expected_state_root = genesis_config
                .extra
                .get("initial_state_root")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000")
                .trim_start_matches("0x");

            let expected_genesis_hash = genesis_config
                .extra
                .get("genesis_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches("0x"));

            let timestamp = genesis_config
                .extra
                .get("genesis_timestamp")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let temp_db_path =
                std::env::temp_dir().join(format!("sxiaum-verify-{}.redb", rand::random::<u32>()));
            let temp_db_str = temp_db_path
                .to_str()
                .context("Invalid temporary database path")?;
            let storage = Arc::new(StorageEngine::new(temp_db_str)?);
            let state = StateDB::new(storage.clone());

            sxiaum_crypto::kzg::precompute_kzg_basis();

            for (address_str, alloc_data) in &genesis_config.alloc {
                let address = Address::from_str(address_str)
                    .context(format!("Invalid address format: {}", address_str))?;

                let balance = if alloc_data.balance.starts_with("0x")
                    || alloc_data.balance.starts_with("0X")
                {
                    U256::from_str_radix(
                        alloc_data
                            .balance
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    )?
                } else {
                    U256::from_str_radix(&alloc_data.balance, 10)?
                };

                state.set_balance(&address, balance)?;

                if let Some(vesting) = &alloc_data.vesting {
                    let schedule = sxiaum_types::vesting::VestingSchedule {
                        total_wei: balance,
                        start_ts: vesting.start_ts,
                        cliff_secs: vesting.cliff_secs,
                        duration_secs: vesting.duration_secs,
                        released_wei: U256::zero(),
                    };
                    state.set_vesting_schedule(&address, schedule)?;
                }
            }

            state.commit()?;
            let computed_state_root = hex::encode(state.state_root());

            if expected_state_root != computed_state_root {
                anyhow::bail!(
                    "Verification failed! Expected state root 0x{}, but got 0x{}",
                    expected_state_root,
                    computed_state_root
                );
            }

            let mut genesis_block = Block::genesis(state.state_root());
            if timestamp > 0 {
                genesis_block.header.set_timestamp(timestamp);
            }
            let computed_genesis_hash = hex::encode(
                genesis_block
                    .try_hash()
                    .context("Failed to compute genesis block hash")?,
            );

            if let Some(expected_hash) = expected_genesis_hash {
                if !expected_hash.is_empty() && expected_hash != computed_genesis_hash {
                    anyhow::bail!(
                        "Verification failed! Expected genesis hash 0x{}, but got 0x{}",
                        expected_hash,
                        computed_genesis_hash
                    );
                }
            }

            println!(
                "Verification successful! State root matches (0x{}) and Genesis hash matches (0x{})",
                computed_state_root, computed_genesis_hash
            );

            drop(state);
            drop(storage);
            let _ = fs::remove_file(temp_db_path);
        }
        Commands::SignGenesis { config, key } => {
            use sxiaum_crypto::ed25519::PrivateKey;
            use sxiaum_crypto::signer::Signer;
            let content = fs::read_to_string(&config)
                .context(format!("Failed to read config file '{}'", config))?;

            // Re-parse to verify structure, but sign the raw canonical content
            // To ensure everyone signs the exact same bytes, we could canonicalize,
            // but for this phase signing the block hash is safer.
            let genesis_config: GenesisConfig = serde_json::from_str(&content)?;
            let hash_hex = genesis_config
                .extra
                .get("genesis_hash")
                .and_then(|v| v.as_str())
                .context("No genesis_hash found in config")?
                .trim_start_matches("0x");
            let state_root = genesis_config
                .extra
                .get("initial_state_root")
                .and_then(|v| v.as_str())
                .context("No initial_state_root found in config")?;
            let timestamp = genesis_config
                .extra
                .get("genesis_timestamp")
                .and_then(|v| v.as_u64())
                .context("No genesis_timestamp found in config")?;

            let mut sk_bytes = [0u8; 32];
            hex::decode_to_slice(key.trim_start_matches("0x"), &mut sk_bytes)?;
            let sk = PrivateKey(sk_bytes);
            let pk = sk.public_key();

            let message = format!("sxiaum:genesis:v1:{}", hash_hex);
            let sig = sk.sign(message.as_bytes())?;

            let attestation = serde_json::json!({
                "schema_version": "v1",
                "chain_id": genesis_config.chain_id,
                "genesis_hash": format!("0x{}", hash_hex),
                "state_root": state_root,
                "timestamp_utc": timestamp,
                "signer_pubkey": format!("0x{}", hex::encode(pk.0)),
                "signature": format!("0x{}", hex::encode(sig.0)),
            });

            let attestation_json = serde_json::to_string_pretty(&attestation)?;
            fs::write("genesis_attestation.json", &attestation_json)?;
            println!("Wrote attestation to genesis_attestation.json");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;
    use std::str::FromStr;

    #[test]
    fn test_genesis_config_serde_roundtrip() {
        let mut alloc = std::collections::HashMap::new();
        alloc.insert(
            "0x1111111111111111111111111111111111111111".to_string(),
            GenesisAlloc {
                balance: "1000000000000000000000".to_string(),
                vesting: Some(GenesisVesting {
                    start_ts: 1700000000,
                    cliff_secs: 86400,
                    duration_secs: 31536000,
                }),
            },
        );

        let validators = vec![GenesisValidator {
            address: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            pubkey: "0x3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
            stake: "100000000000000000000".to_string(),
            voting_power: 100,
        }];

        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "genesis_timestamp".to_string(),
            serde_json::json!(1700000000),
        );

        let config = GenesisConfig {
            chain_id: "13689".to_string(),
            alloc,
            validators,
            extra,
        };

        let serialized = serde_json::to_string(&config).expect("serialization failed");
        let deserialized: GenesisConfig =
            serde_json::from_str(&serialized).expect("deserialization failed");

        assert_eq!(deserialized.chain_id, "13689");
        assert_eq!(deserialized.validators.len(), 1);
        assert_eq!(deserialized.validators[0].voting_power, 100);
        assert_eq!(deserialized.alloc.len(), 1);
    }

    #[test]
    fn test_validator_voting_power_calculation() {
        // 1 SX = 10^18 wei -> 1 voting power
        let stake_100_sx = U256::from(100) * U256::from(10).pow(U256::from(18));
        assert_eq!(
            sxiaum_types::Validator::calculate_voting_power(stake_100_sx),
            100
        );

        let stake_1000_sx = U256::from(1000) * U256::from(10).pow(U256::from(18));
        assert_eq!(
            sxiaum_types::Validator::calculate_voting_power(stake_1000_sx),
            1000
        );
    }

    #[test]
    fn test_address_validation_20_and_32_bytes() {
        // Valid 20-byte EVM address
        let evm_addr = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
        assert!(Address::from_str(evm_addr).is_ok());

        // Valid 32-byte native address
        let native_addr = "0x34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e";
        assert!(Address::from_str(native_addr).is_ok());

        // Invalid length
        let invalid_addr = "0x123456";
        assert!(Address::from_str(invalid_addr).is_err());
    }
}
