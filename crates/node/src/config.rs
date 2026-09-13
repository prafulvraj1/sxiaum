//! Unified Node configuration for the SXIAUM blockchain.
//!
//! This module provides the canonical configuration structure and validation
//! routines for SXIAUM nodes across all operation modes.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use sxiaum_mempool::MempoolConfig;
use sxiaum_state::state_db::PruningMode;

/// Synchronization mode for the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyncMode {
    /// Fast sync: downloads headers and state, then switches to full mode.
    #[default]
    Fast,
    /// Full sync: executes every block from genesis.
    Full,
    /// Light client: syncs only block headers with ZK proof verification.
    Light,
}

/// Operating mode for the node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    /// Full consensus participant: proposes blocks, votes, runs the EVM.
    Validator,
    /// Follows the chain, executes blocks, serves RPC — no proposing or voting.
    #[default]
    FullNode,
    /// Syncs only block headers via aggregated signatures; minimal resource use.
    LightClient,
}

/// Configuration for KZG polynomial commitments and SRS verification.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KzgConfig {
    pub srs_hash: String,
    pub domain_size: usize,
    pub curve: String,
}

/// Configuration for Zero-Knowledge proof verification.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkConfig {
    pub system: String,
    pub vk_hash: String,
    pub version: u32,
}

/// Comprehensive configuration for a SXIAUM node.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Path to persistent storage database (e.g. "data/blockchain.redb").
    pub storage_path: String,
    /// RPC listen socket address (e.g. "127.0.0.1:8080").
    pub rpc_addr: SocketAddr,
    /// Proposer private signing key (in-memory only; never written to JSON configs).
    pub proposer_private_key: sxiaum_crypto::ed25519::PrivateKey,
    /// P2P listen address (e.g. Some("/ip4/0.0.0.0/tcp/9000")).
    pub p2p_listen_addr: Option<libp2p::Multiaddr>,
    /// Bootstrap peers for initial network discovery.
    pub bootstrap_peers: Vec<(libp2p::PeerId, libp2p::Multiaddr)>,
    /// Interval between peer discovery cycles.
    pub discovery_interval: Duration,
    /// Backoff delay when peer discovery encounters failures.
    pub discovery_backoff: Duration,
    /// Maximum number of connected P2P peers.
    pub max_peers: usize,
    /// Mempool subsystem configuration.
    pub mempool: MempoolConfig,
    /// Operating mode (Validator, FullNode, LightClient).
    pub mode: NodeMode,
    /// Genesis pre-funded accounts: hex address -> balance string.
    pub genesis_alloc: HashMap<String, String>,
    /// Genesis validator set for HotStuff consensus.
    pub genesis_validators: Vec<sxiaum_types::Validator>,
    /// Optional 32-byte seed for deterministic libp2p PeerID across restarts.
    pub p2p_node_key_seed: Option<[u8; 32]>,
    /// Optional network identifier (e.g. "mainnet", "testnet", "devnet").
    pub network: Option<String>,
    /// Chain identity (must match compiled protocol chain ID).
    pub chain_id: u64,
    /// KZG commitment configuration.
    pub kzg: KzgConfig,
    /// ZK engine configuration.
    pub zk: ZkConfig,
    /// MEV protection / commit-reveal configuration.
    pub commit_reveal: sxiaum_mempool::ordering::CommitRevealConfig,
    /// Genesis timestamp as Unix UTC seconds.
    pub genesis_timestamp: u64,
    /// Synchronization mode (Fast, Full, Light).
    pub sync_mode: SyncMode,
    /// State pruning mode (Archive, Recent, Pruned).
    pub pruning_mode: PruningMode,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            storage_path: "data/blockchain.redb".to_string(),
            rpc_addr: SocketAddr::from(([127, 0, 0, 1], 8545)),
            proposer_private_key: sxiaum_crypto::ed25519::PrivateKey([1u8; 32]),
            p2p_listen_addr: None,
            bootstrap_peers: Vec::new(),
            discovery_interval: Duration::from_secs(30),
            discovery_backoff: Duration::from_secs(5),
            max_peers: 64,
            mempool: MempoolConfig::default(),
            mode: NodeMode::default(),
            genesis_alloc: HashMap::new(),
            genesis_validators: Vec::new(),
            p2p_node_key_seed: None,
            network: None,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            kzg: KzgConfig::default(),
            zk: ZkConfig::default(),
            commit_reveal: sxiaum_mempool::ordering::CommitRevealConfig {
                commit_fee: 10_000_000_000_000_000,
                reveal_window_blocks: 5,
                commit_expiry_blocks: 20,
                no_show_slash: 10,
                max_commits_per_sender: 16,
            },
            genesis_timestamp: 0,
            sync_mode: SyncMode::Fast,
            pruning_mode: PruningMode::Archive,
        }
    }
}

impl NodeConfig {
    /// Comprehensive validation of configuration values and consensus/security invariants.
    pub fn validate(&self) -> Result<()> {
        // 1. Chain ID check
        if self.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            bail!(
                "configured chain_id {} does not match compiled protocol chain_id {}",
                self.chain_id,
                sxiaum_types::SXIAUM_CHAIN_ID
            );
        }

        // 2. Storage path checks
        if self.storage_path.trim().is_empty() {
            bail!("storage_path cannot be empty");
        }

        // 3. Peer limits
        if self.max_peers == 0 {
            bail!("max_peers must be greater than 0");
        }
        if self.max_peers > 1024 {
            bail!(
                "max_peers ({}) exceeds maximum supported limit (1024)",
                self.max_peers
            );
        }

        // 4. Discovery intervals
        if self.discovery_interval.is_zero() {
            bail!("discovery_interval must be greater than 0");
        }
        if self.discovery_backoff.is_zero() {
            bail!("discovery_backoff must be greater than 0");
        }

        // 5. Commit-reveal configuration invariants
        if self.commit_reveal.reveal_window_blocks == 0 {
            bail!("commit_reveal.reveal_window_blocks must be greater than 0");
        }
        if self.commit_reveal.commit_expiry_blocks <= self.commit_reveal.reveal_window_blocks {
            bail!(
                "commit_reveal.commit_expiry_blocks ({}) must be greater than reveal_window_blocks ({})",
                self.commit_reveal.commit_expiry_blocks,
                self.commit_reveal.reveal_window_blocks
            );
        }
        if self.commit_reveal.max_commits_per_sender == 0 {
            bail!("commit_reveal.max_commits_per_sender must be greater than 0");
        }
        if self.commit_reveal.max_commits_per_sender > 1024 {
            bail!(
                "commit_reveal.max_commits_per_sender ({}) exceeds maximum supported (1024)",
                self.commit_reveal.max_commits_per_sender
            );
        }

        // 6. Genesis validator uniqueness and validity
        let mut seen_addrs = std::collections::HashSet::new();
        for (i, val) in self.genesis_validators.iter().enumerate() {
            val.validate()
                .with_context(|| format!("invalid genesis validator at index {}", i))?;
            if !seen_addrs.insert(val.address) {
                bail!(
                    "duplicate genesis validator address at index {}: {}",
                    i,
                    val.address
                );
            }
            if val.stake.is_zero() {
                bail!("genesis validator {} has zero stake", val.address);
            }
        }

        // 7. Genesis alloc validity
        for (addr_str, balance_str) in &self.genesis_alloc {
            let cleaned_addr = addr_str
                .trim()
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            let decoded = hex::decode(cleaned_addr)
                .with_context(|| format!("invalid hex address in genesis_alloc: {}", addr_str))?;
            if decoded.len() != 20 && decoded.len() != 32 {
                bail!(
                    "genesis_alloc address {} has invalid byte length (expected 20 or 32)",
                    addr_str
                );
            }
            if balance_str.trim().is_empty() {
                bail!("genesis_alloc for {} has empty balance", addr_str);
            }
        }

        Ok(())
    }

    /// Validate that the configuration satisfies all mainnet production requirements.
    pub fn validate_mainnet(&self) -> Result<()> {
        self.validate()?;

        // RPC address must be loopback unless TLS or reverse proxy is configured.
        let rpc_is_loopback = self.rpc_addr.ip().is_loopback();

        if !rpc_is_loopback {
            let has_tls = std::env::var("SXIAUM_TLS_CERT_PATH").is_ok()
                && std::env::var("SXIAUM_TLS_KEY_PATH").is_ok();
            let has_reverse_proxy = std::env::var("SXIAUM_REVERSE_PROXY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);

            if !has_tls && !has_reverse_proxy {
                bail!(
                    "RPC address {} is not loopback and no TLS or reverse proxy is configured. \
                     Set SXIAUM_TLS_CERT_PATH + SXIAUM_TLS_KEY_PATH or SXIAUM_REVERSE_PROXY=true.",
                    self.rpc_addr
                );
            }
        }

        // Genesis timestamp must be non-zero on mainnet
        if self.genesis_timestamp == 0 {
            bail!("genesis_timestamp must be non-zero for mainnet");
        }

        // Light client mode with Archive pruning check
        if self.mode == NodeMode::LightClient && self.pruning_mode == PruningMode::Archive {
            tracing::warn!(
                "Light client mode with Archive pruning is wasteful. Consider using Pruned or Recent mode."
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sxiaum_crypto::bls::{verify_proof_of_possession, BlsPublicKey, BlsSignature};

    #[test]
    fn test_mainnet_config_parses_4_valid_validators() {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mainnet_path = manifest_dir.join("../../configs/mainnet.json");
        let content =
            std::fs::read_to_string(&mainnet_path).expect("Failed to read configs/mainnet.json");

        // Parse using Startup parser
        let mut config = NodeConfig::default();
        let value: serde_json::Value = serde_json::from_str(&content).expect("Invalid JSON");

        // Set key for test
        let seed = [1u8; 32];
        config.proposer_private_key.0 = seed;

        // Verify validators array in JSON has 4 validators
        let val_arr = value
            .get("validators")
            .and_then(|v| v.as_array())
            .expect("Missing validators array");
        assert_eq!(val_arr.len(), 4, "Expected exactly 4 genesis validators");

        for (i, val_json) in val_arr.iter().enumerate() {
            let addr_str = val_json.get("address").unwrap().as_str().unwrap();
            let pubkey_str = val_json.get("pubkey").unwrap().as_str().unwrap();
            let bls_pk_str = val_json.get("bls_pubkey").unwrap().as_str().unwrap();
            let bls_pop_str = val_json.get("bls_pop").unwrap().as_str().unwrap();

            let pk_bytes = hex::decode(pubkey_str.trim_start_matches("0x")).unwrap();
            let bls_pk_bytes = hex::decode(bls_pk_str.trim_start_matches("0x")).unwrap();
            let bls_pop_bytes = hex::decode(bls_pop_str.trim_start_matches("0x")).unwrap();

            let addr: sxiaum_types::Address = addr_str.parse().unwrap();
            let derived_addr = sxiaum_types::Address::from_public_key(&pk_bytes);
            assert_eq!(
                addr, derived_addr,
                "Validator {} address must match Ed25519 public key",
                i
            );

            let bls_pk = BlsPublicKey(bls_pk_bytes.clone());
            let bls_pop = BlsSignature(bls_pop_bytes.clone());
            assert!(
                verify_proof_of_possession(&bls_pk, &bls_pop),
                "Validator {} BLS proof of possession must be valid",
                i
            );

            let mut pk_arr = [0u8; 32];
            pk_arr.copy_from_slice(&pk_bytes);
            let mut val = sxiaum_types::Validator::new(
                addr,
                pk_arr,
                primitive_types::U256::from(1000000000000000000000000u128),
            );
            val.bls_pubkey = Some(bls_pk_bytes);
            val.bls_pop = Some(bls_pop_bytes);
            val.validate().unwrap();
            config.genesis_validators.push(val);
        }

        assert_eq!(config.genesis_validators.len(), 4);
        config
            .validate()
            .expect("NodeConfig::validate failed with 4 validators");
    }
}
