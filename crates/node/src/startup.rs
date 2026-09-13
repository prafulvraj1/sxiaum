use crate::node::{Node, NodeConfig, NodeMode};
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use std::sync::Arc;
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use sxiaum_types::Address;
use tracing::{info, warn};

const DEFAULT_CONFIG_PATH: &str = "config/node.json";

pub struct Startup;

impl Startup {
    pub fn load_configuration_file(path: Option<&str>) -> Result<NodeConfig> {
        if let Some(explicit_path) = path {
            info!(
                "Loading node configuration from explicit path {}...",
                explicit_path
            );
            let contents = std::fs::read_to_string(explicit_path).with_context(|| {
                format!(
                    "Failed to read explicit configuration file: {}",
                    explicit_path
                )
            })?;
            let config = Self::parse_node_config(&contents)?;
            config.validate()?;
            return Ok(config);
        }

        let default_path = DEFAULT_CONFIG_PATH;
        match std::fs::read_to_string(default_path) {
            Ok(contents) => {
                info!(
                    "Loading node configuration from default path {}...",
                    default_path
                );
                let config = Self::parse_node_config(&contents)?;
                config.validate()?;
                Ok(config)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if crate::keys::is_production() {
                    anyhow::bail!(
                        "SECURITY ERROR: Configuration file '{}' not found and production mode is active. Explicit configuration is required.",
                        default_path
                    );
                }
                warn!(
                    "Configuration file {} not found. Falling back to defaults + env keys.",
                    default_path
                );
                let config = Self::apply_keys_to_config(NodeConfig::default(), None)?;
                config.validate()?;
                Ok(config)
            }
            Err(error) => Err(error).context("Failed to read configuration file"),
        }
    }

    pub fn initialize_logger() -> Result<()> {
        let subscriber = tracing_subscriber::fmt()
            .with_target(false)
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .finish();

        let _ = tracing::subscriber::set_global_default(subscriber);
        Ok(())
    }

    /// Load validator signing keys from the already-resolved `NodeConfig` seed.
    /// Key material is populated earlier by [`Self::apply_keys_to_config`].
    pub fn load_validator_keys(config: &NodeConfig) -> Result<(SigningKey, Address)> {
        let signing_key = SigningKey::from_bytes(&config.proposer_private_key.0);
        let validator_address = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        info!("Loaded validator keys for {}", validator_address);
        Ok((signing_key, validator_address))
    }

    /// Resolve private key material from env / file / keystore / Vault (never JSON hex).
    fn apply_keys_to_config(
        mut config: NodeConfig,
        config_json: Option<&serde_json::Value>,
    ) -> Result<NodeConfig> {
        let require_key = matches!(config.mode, NodeMode::Validator);
        match crate::keys::resolve_validator_seed(config_json) {
            Ok(seed) => {
                config.proposer_private_key.0 = *seed.as_bytes();
                config.p2p_node_key_seed =
                    crate::keys::resolve_p2p_seed(config_json, Some(seed.as_bytes()))?;
            }
            Err(err) if require_key => {
                return Err(err).context("validator mode requires a private key source");
            }
            Err(err) => {
                warn!(
                    "No external key source for non-validator node ({err}); using ephemeral identity"
                );
                // Ephemeral random seed for P2P identity only (not consensus).
                let mut rng_seed = [0u8; 32];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut rng_seed);
                config.proposer_private_key.0 = rng_seed;
                config.p2p_node_key_seed =
                    crate::keys::resolve_p2p_seed(config_json, Some(&rng_seed))?;
            }
        }
        Ok(config)
    }

    /// Initialize the storage engine, load latest metadata, and warm up the cache.
    pub fn init_storage(path: &str) -> Result<Arc<StorageEngine>> {
        info!("Initializing persistent storage engine at {}...", path);
        let engine = StorageEngine::new(path).context("Failed to open storage engine")?;

        let latest_height = engine.latest_block_height()?;
        info!(
            "Storage successfully initialized. Latest block height: {}",
            latest_height
        );

        // Performance: warm up the read cache with general system state
        let _ = engine.state_get_cached(b"system_config".to_vec());

        Ok(Arc::new(engine))
    }

    pub fn init_state(storage: Arc<StorageEngine>) -> Result<Arc<StateDB>> {
        let state = Arc::new(StateDB::new(storage.clone()));
        let latest_height = storage.latest_block_height()?;
        let restored_root = Self::restore_blockchain_state(storage.as_ref(), state.as_ref())?;

        // Don't validate expected root at height 0, since genesis allocations will change it
        let expected_root = if latest_height > 0 {
            Some(restored_root)
        } else {
            None
        };
        let hydrated_root = state.initialize_backend(latest_height, expected_root)?;

        info!(
            "State backend initialized. latest_height={}, state_root=0x{}",
            latest_height,
            hex::encode(hydrated_root)
        );

        // Warm the hot metadata keys and the current head into the storage LRU.
        let _ = storage.state_get_cached(b"metadata:state_root".to_vec());
        if latest_height > 0 {
            let mut block_root_key = b"execution:block:state_root:".to_vec();
            block_root_key.extend_from_slice(latest_height.to_string().as_bytes());
            let _ = storage.state_get_cached(block_root_key);
            let _ = storage.get_block_header(latest_height);
            let _ = storage.get_block_body(latest_height);
        }

        Ok(state)
    }

    /// Apply genesis account allocations to the state database.
    /// This loads pre-funded accounts from the genesis configuration.
    pub fn apply_genesis_allocations(
        state: &StateDB,
        storage: &StorageEngine,
        alloc: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let latest_height = storage.latest_block_height()?;

        // Only apply genesis allocations at block 0 (fresh chain)
        if latest_height > 0 {
            info!(
                "Chain already initialized (height={}). Skipping genesis allocations.",
                latest_height
            );
            return Ok(());
        }

        if alloc.is_empty() {
            info!("No genesis allocations configured.");
            return Ok(());
        }

        info!("Applying {} genesis allocations...", alloc.len());

        for (address_str, balance_str) in alloc.iter() {
            // Parse address from hex string
            let addr_bytes = hex::decode(address_str.trim_start_matches("0x"))
                .context(format!("Invalid address format: {}", address_str))?;

            let address = match addr_bytes.len() {
                32 => {
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&addr_bytes);
                    Address(addr)
                }
                20 => {
                    let mut addr = [0u8; 20];
                    addr.copy_from_slice(&addr_bytes);
                    Address::from_ethereum_address(addr)
                }
                _ => {
                    warn!(
                        "Genesis address {} has invalid length (expected 20 or 32 bytes)",
                        address_str
                    );
                    continue;
                }
            };

            // Parse balance from string (vc amount, usually very large)
            // Try decimal first, then hex if it starts with 0x
            let balance = if balance_str.starts_with("0x") || balance_str.starts_with("0X") {
                U256::from_str_radix(
                    balance_str
                        .trim_start_matches("0x")
                        .trim_start_matches("0X"),
                    16,
                )
                .context(format!("Invalid hex balance format: {}", balance_str))?
            } else {
                U256::from_str_radix(balance_str, 10)
                    .context(format!("Invalid decimal balance format: {}", balance_str))?
            };

            state
                .set_balance(&address, balance)
                .context(format!("Failed to set balance for {}", address_str))?;

            info!("Genesis allocation: {} -> {} vc", address_str, balance);
        }

        info!("Genesis allocations applied successfully");
        Ok(())
    }

    pub fn restore_blockchain_state(storage: &StorageEngine, state: &StateDB) -> Result<[u8; 32]> {
        let latest_height = storage.latest_block_height()?;
        if latest_height == 0 {
            info!("No persisted blockchain height found. Using current state root.");
            return Ok(state.state_root());
        }

        if let Some(state_root_bytes) = storage.state_get(b"metadata:state_root".to_vec())? {
            if state_root_bytes.len() == 32 {
                let mut state_root = [0u8; 32];
                state_root.copy_from_slice(&state_root_bytes);
                info!(
                    "Restored blockchain state at height {} with persisted state root.",
                    latest_height
                );
                return Ok(state_root);
            }
        }

        warn!(
            "Latest block height is {}, but persisted state root metadata was missing. Falling back to in-memory root.",
            latest_height
        );
        Ok(state.state_root())
    }

    pub fn restore_mempool_state(node: &Node) -> Result<usize> {
        node.mempool.start()?;
        let pending = node.mempool.pending_count()?;
        info!("Mempool state restored. pending_transactions={}", pending);
        Ok(pending)
    }

    pub async fn restore_consensus_state(node: &Node) -> Result<u64> {
        let view = node.consensus.write().await.start()?;
        info!("Consensus state restored at view {}.", view);
        Ok(view)
    }

    pub async fn start_networking_layer(node: &Node) -> Result<()> {
        if let Some(address) = node.config.p2p_listen_addr.clone() {
            node.networking.lock().await.listen_on(address)?;
            info!("Networking layer listening on configured address.");
        } else {
            info!("Networking layer initialized without a listen address.");
        }
        Ok(())
    }

    pub async fn start_node_event_loop(node: &mut Node) -> Result<()> {
        info!("Starting node background services and event loop...");

        // Start background services (consensus tick, block production poller, mempool sweep, P2P discovery)
        crate::services::spawn_background_services(node);

        // Start node services and run event loop
        node.start().await
    }

    pub async fn bootstrap_node(path: Option<&str>) -> Result<Node> {
        // - Step 1: load configuration file -
        // Try the supplied path first; fall back to DEFAULT_CONFIG_PATH; if
        // that is also absent, fall back to compiled-in defaults.  This is the
        // only step that must succeed before the logger is running, so errors
        // surface as plain stderr output.
        let config = Self::load_configuration_file(path)?;

        // - Step 2: initialize logger -
        // Set up the global tracing subscriber as early as possible so that
        // every subsequent step emits structured log lines.
        Self::initialize_logger()?;

        // - Step 2.1: Production preflight checks -
        // Fail-closed: if SXIAUM_ENV=production, every security gate (ZK mode,
        // SRS mode, JWT entropy, TLS config, validator key quality) must pass
        // or the process exits with a clear error before any subsystem starts.
        // No-op for dev / testnet environments.
        crate::preflight::run_production_preflight(&config);

        // - Step 2.5: Precompute KZG / Lagrange basis -
        sxiaum_crypto::kzg::precompute_kzg_basis();

        // - Step 3: load validator keys -
        // Key material already resolved in parse_node_config via crate::keys
        // (env / file / keystore / Vault - never JSON hex).
        let _ = Self::load_validator_keys(&config)?;

        // - Step 4: initialize storage database -
        // Steps 4 and 5 are performed inside `Node::new`; the storage engine
        // is opened and the state trie is loaded before the rest of the
        // subsystems are constructed.  The per-step functions `init_storage`
        // and `init_state` are also callable individually for tooling / tests.
        info!("Initializing storage and state subsystems via Node::new...");
        let node = Node::new(config.clone()).await?;

        // - Step 5: restore blockchain state -
        // Read the persisted state-root metadata key and re-hydrate the trie
        // so the in-memory root matches the last committed block.
        let restored_root = node.state.state_root();
        info!(
            "Blockchain state recovery complete. state_root=0x{}",
            hex::encode(restored_root)
        );

        // - Step 5.5: apply genesis allocations -
        // Load pre-funded accounts from genesis configuration.
        // Only applies on fresh chain (height 0).
        Self::apply_genesis_allocations(&node.state, &node.storage, &config.genesis_alloc)?;

        let latest = node.storage.latest_block_height()?;
        if latest == 0 && node.storage.get_block_header(0)?.is_none() {
            node.state.commit()?;
            let state_root = node.state.state_root();
            let genesis_block = sxiaum_block::Block::genesis(state_root);
            let genesis_hash = genesis_block.try_hash()?;
            node.storage.atomic_block_commit_typed(
                0,
                &genesis_block.header,
                &genesis_block.body,
            )?;
            node.storage
                .state_put(b"metadata:state_root".to_vec(), state_root.to_vec())?;
            node.storage
                .state_put(b"metadata:genesis_hash".to_vec(), genesis_hash.to_vec())?;
            node.storage.state_put(
                b"metadata:chain_id".to_vec(),
                config.chain_id.to_le_bytes().to_vec(),
            )?;
            info!(
                "Genesis block written to storage successfully. state_root=0x{}, genesis_hash=0x{}",
                hex::encode(state_root),
                hex::encode(genesis_hash)
            );

            // Populate consensus validator set and staking manager
            let mut consensus = node.consensus.write().await;
            for validator in &config.genesis_validators {
                consensus.validator_set.add_validator(validator.clone())?;
                consensus
                    .staking_manager
                    .stake_tokens(validator.address, validator.stake)?;
            }
            consensus.persist_validator_set()?;
            info!(
                "Consensus validator set initialized with {} validators",
                config.genesis_validators.len()
            );
        } else {
            // Verify chain identity against existing database
            if let Some(persisted_chain_id_bytes) =
                node.storage.state_get(b"metadata:chain_id".to_vec())?
            {
                if persisted_chain_id_bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&persisted_chain_id_bytes);
                    let stored_chain_id = u64::from_le_bytes(arr);
                    if stored_chain_id != config.chain_id {
                        anyhow::bail!(
                            "CHAIN ISOLATION ERROR: database belongs to chain_id {}, but node is configured for chain_id {}",
                            stored_chain_id,
                            config.chain_id
                        );
                    }
                }
            }
        }

        // - Step 6: restore mempool state -
        // Re-insert transactions that were persisted to disk before the last
        // shutdown; any expired entries are silently dropped during insertion.
        let _ = Self::restore_mempool_state(&node)?;

        // - Step 7: restore consensus state -
        // Reload the last committed view number and validator set so HotStuff
        // can resume from where it left off.
        let _ = Self::restore_consensus_state(&node).await?;

        // - Step 7.5: validator set fallback -
        // If the restored validator set is empty (e.g. crash before persist_validator_set),
        // re-populate from genesis config and persist so future restarts recover correctly.
        {
            let active_count = node
                .consensus
                .read()
                .await
                .validator_set
                .active_validator_count();
            info!(
                "Consensus validator set has {} active validator(s) after restore.",
                active_count
            );
            if active_count == 0 && !config.genesis_validators.is_empty() {
                warn!(
                    "Validator set is empty after restore — re-loading {} genesis validator(s) from config.",
                    config.genesis_validators.len()
                );
                let mut consensus = node.consensus.write().await;
                for validator in &config.genesis_validators {
                    consensus.validator_set.add_validator(validator.clone())?;
                    // Only stake if not already present in the staking manager
                    // (avoids double-counting on repeated fallback invocations).
                    if consensus
                        .staking_manager
                        .get_stake(&validator.address)
                        .is_zero()
                    {
                        consensus
                            .staking_manager
                            .stake_tokens(validator.address, validator.stake)?;
                    }
                }
                consensus.persist_validator_set()?;
                info!("Validator set recovered and persisted successfully.");
            }
        }

        // - Step 8: start networking layer -
        // Bind the P2P listen address (if configured) and connect to bootstrap
        // peers so the node begins participating in the gossip overlay.
        Self::start_networking_layer(&node).await?;

        // - Step 9: Startup fingerprint -
        // Print a cryptographically binding summary of this node's identity so
        // operators can verify network consistency by comparing across nodes.
        {
            let state_root = node.state.state_root();
            let srs_hash = &config.kzg.srs_hash;
            let vk_hash = &config.zk.vk_hash;
            let validator_count = config.genesis_validators.len();
            let chain_id = config.chain_id;
            let genesis_ts = config.genesis_timestamp;
            let network = config.network.as_deref().unwrap_or("(unset)");

            info!("╔════════════════════════════════════════════════════════════════╗");
            info!("║  SXIAUM NODE STARTUP FINGERPRINT                              ║");
            info!("║  network          : {:<47}║", network);
            info!("║  chain_id         : {:<47}║", chain_id);
            info!("║  genesis_timestamp: {:<47}║", genesis_ts);
            info!("║  state_root       : 0x{}   ║", hex::encode(state_root));
            info!("║  srs_hash         : {:<47}║", srs_hash);
            info!("║  vk_hash          : {:<47}║", vk_hash);
            info!("║  validators       : {:<47}║", validator_count);
            info!("╚════════════════════════════════════════════════════════════════╝");
        }

        Ok(node)
    }

    /// Full node lifecycle: runs all 10 startup steps and then blocks until the
    /// event loop exits (either cleanly via `Node::stop` or on a fatal error).
    ///
    /// Step 9 -- start node event loop -- is intentionally separated from
    /// `bootstrap_node` so that callers (tests, tooling) can inspect or modify
    /// the node after initialisation before handing control to the loop.
    pub async fn run(path: Option<&str>) -> Result<()> {
        let mut node = Self::bootstrap_node(path).await?;

        // - Step 9: start node event loop -
        // Spawns the RPC server and all background services, then enters the
        // continuous `tokio::select!` loop that dispatches P2P messages, RPC
        // requests, consensus events, and new transactions until `Node::stop`
        // is called.
        Self::start_node_event_loop(&mut node).await
    }

    fn parse_node_config(contents: &str) -> Result<NodeConfig> {
        let value: serde_json::Value =
            serde_json::from_str(contents).context("Invalid node config JSON")?;

        let mut config = NodeConfig::default();

        if let Some(net) = value
            .get("network")
            .or_else(|| value.get("_network"))
            .and_then(|v| v.as_str())
        {
            config.network = Some(net.to_string());
            if net.eq_ignore_ascii_case("mainnet") {
                // Enforce production mode environment variables
                let env_mode = std::env::var("SXIAUM_ENV").unwrap_or_default();
                if !env_mode.eq_ignore_ascii_case("production") {
                    anyhow::bail!("SECURITY ERROR: Mainnet configuration loaded but SXIAUM_ENV!=production. You must opt-in to production trust policies.");
                }

                let srs_mode = std::env::var("SXIAUM_SRS_MODE").unwrap_or_default();
                if !srs_mode.eq_ignore_ascii_case("production") {
                    anyhow::bail!("SECURITY ERROR: Mainnet configuration loaded but SXIAUM_SRS_MODE!=production. You must opt-in to production ZK mode.");
                }

                if std::env::var("SXIAUM_ALLOW_HTTP")
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("true")
                {
                    anyhow::bail!("SECURITY ERROR: SXIAUM_ALLOW_HTTP=true is forbidden in mainnet. TLS is required for public endpoints.");
                }

                if std::env::var("SXIAUM_KZG_SRS_PATH").is_err() {
                    anyhow::bail!("SECURITY ERROR: SXIAUM_KZG_SRS_PATH must be set for mainnet to load the trusted KZG SRS.");
                }
                tracing::info!("Mainnet network detected: Production security policies enforced.");
            }
        }

        if let Some(storage_path) = value.get("storage_path").and_then(|v| v.as_str()) {
            config.storage_path = storage_path.to_owned();
        }

        if let Some(rpc_addr) = value.get("rpc_addr").and_then(|v| v.as_str()) {
            config.rpc_addr = rpc_addr.parse().context("Invalid rpc_addr in config")?;
        }

        // Genesis timestamp — must be non-zero for mainnet (Gate 11).
        if let Some(ts) = value.get("genesis_timestamp").and_then(|v| v.as_u64()) {
            config.genesis_timestamp = ts;
        }

        if let Some(mode_str) = value.get("mode").and_then(|v| v.as_str()) {
            config.mode = match mode_str.to_lowercase().as_str() {
                "validator" => NodeMode::Validator,
                "fullnode" | "full_node" | "full" => NodeMode::FullNode,
                "lightclient" | "light_client" | "light" => NodeMode::LightClient,
                _ => anyhow::bail!("Invalid node mode: {}", mode_str),
            };
        }

        if let Some(p2p_addr_str) = value.get("p2p_listen_addr").and_then(|v| v.as_str()) {
            config.p2p_listen_addr = Some(
                p2p_addr_str
                    .parse()
                    .context("Invalid p2p_listen_addr in config")?,
            );
        }

        if let Some(max_peers) = value.get("max_peers").and_then(|v| v.as_u64()) {
            config.max_peers = max_peers as usize;
        }

        if let Some(peers_arr) = value.get("bootstrap_peers").and_then(|v| v.as_array()) {
            for peer_val in peers_arr {
                if let Some(peer_str) = peer_val.as_str() {
                    let multiaddr: libp2p::Multiaddr = peer_str
                        .parse()
                        .context("Invalid bootstrap peer multiaddr")?;
                    let mut addr = multiaddr.clone();
                    let last_proto = addr.pop();
                    if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = last_proto {
                        config.bootstrap_peers.push((peer_id, addr));
                    } else {
                        // fallback or direct parse
                        if let Some(peer_id) = peer_str.split("/p2p/").last() {
                            if let Ok(peer_id) = peer_id.parse::<libp2p::PeerId>() {
                                config.bootstrap_peers.push((peer_id, addr));
                            }
                        }
                    }
                }
            }
        }

        config = Self::apply_keys_to_config(config, Some(&value))?;

        // Load genesis allocations (pre-funded accounts)
        if let Some(alloc_obj) = value.get("alloc").and_then(|v| v.as_object()) {
            for (address, account) in alloc_obj.iter() {
                if let Some(balance_str) = account.get("balance").and_then(|v| v.as_str()) {
                    config
                        .genesis_alloc
                        .insert(address.clone(), balance_str.to_string());
                    info!(
                        "Loaded genesis allocation: {} balance={}",
                        address, balance_str
                    );
                }
            }
        }

        // Load genesis validators (populate consensus validator set)
        if let Some(validators_arr) = value.get("validators").and_then(|v| v.as_array()) {
            for val_val in validators_arr {
                if let Some(val_obj) = val_val.as_object() {
                    let address_str = val_obj
                        .get("address")
                        .and_then(|v| v.as_str())
                        .context("Missing validator address")?;
                    let pubkey_str = val_obj
                        .get("pubkey")
                        .and_then(|v| v.as_str())
                        .context("Missing validator pubkey")?;
                    let stake_str = val_obj
                        .get("stake")
                        .and_then(|v| v.as_str())
                        .context("Missing validator stake")?;
                    let voting_power = val_obj
                        .get("voting_power")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    let address: Address = std::str::FromStr::from_str(address_str)
                        .context("Invalid validator address in configuration JSON")?;

                    let pk_clean = pubkey_str
                        .trim()
                        .trim_start_matches("0x")
                        .trim_start_matches("0X");
                    let pubkey_bytes = hex::decode(pk_clean)
                        .context("Invalid validator pubkey hex in configuration JSON")?;
                    if pubkey_bytes.len() != 32 {
                        bail!(
                            "Invalid validator pubkey length: expected 32 bytes, got {}",
                            pubkey_bytes.len()
                        );
                    }
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&pubkey_bytes);

                    let stake = U256::from_str_radix(
                        stake_str.trim_start_matches("0x").trim_start_matches("0X"),
                        10,
                    )
                    .or_else(|_| {
                        U256::from_str_radix(
                            stake_str.trim_start_matches("0x").trim_start_matches("0X"),
                            16,
                        )
                    })
                    .context("Invalid validator stake")?;

                    let mut validator = sxiaum_types::Validator::new(address, pubkey, stake);
                    let expected_power = sxiaum_types::Validator::calculate_voting_power(stake);
                    validator.voting_power = if voting_power == 0 {
                        expected_power
                    } else {
                        voting_power
                    };
                    validator.status = sxiaum_types::validator::ValidatorStatus::Active;

                    if let Some(bls_pubkey_str) = val_obj.get("bls_pubkey").and_then(|v| v.as_str())
                    {
                        let bls_pubkey_bytes = hex::decode(
                            bls_pubkey_str
                                .trim_start_matches("0x")
                                .trim_start_matches("0X"),
                        )
                        .context("Invalid validator bls_pubkey hex")?;
                        if bls_pubkey_bytes.len() != sxiaum_types::validator::BLS_PUBKEY_LEN {
                            bail!("Invalid BLS public key length in config: expected {} bytes, got {}", sxiaum_types::validator::BLS_PUBKEY_LEN, bls_pubkey_bytes.len());
                        }
                        validator.bls_pubkey = Some(bls_pubkey_bytes);
                    }
                    if let Some(bls_pop_str) = val_obj.get("bls_pop").and_then(|v| v.as_str()) {
                        let bls_pop_bytes = hex::decode(
                            bls_pop_str
                                .trim_start_matches("0x")
                                .trim_start_matches("0X"),
                        )
                        .context("Invalid validator bls_pop hex")?;
                        if bls_pop_bytes.len() != sxiaum_types::validator::BLS_POP_LEN {
                            bail!(
                                "Invalid BLS PoP length in config: expected {} bytes, got {}",
                                sxiaum_types::validator::BLS_POP_LEN,
                                bls_pop_bytes.len()
                            );
                        }
                        validator.bls_pop = Some(bls_pop_bytes);
                    }

                    validator
                        .validate()
                        .context("Validator invariant validation failed for genesis validator")?;
                    config.genesis_validators.push(validator);
                }
            }
        }

        // Load kzg config
        if let Some(kzg_obj) = value.get("kzg").and_then(|v| v.as_object()) {
            if let Some(srs_hash) = kzg_obj.get("srs_hash").and_then(|v| v.as_str()) {
                config.kzg.srs_hash = srs_hash.to_string();
            }
            if let Some(domain_size) = kzg_obj.get("domain_size").and_then(|v| v.as_u64()) {
                config.kzg.domain_size = domain_size as usize;
            }
            if let Some(curve) = kzg_obj.get("curve").and_then(|v| v.as_str()) {
                config.kzg.curve = curve.to_string();
            }
        }

        // Load zk config
        if let Some(zk_obj) = value.get("zk").and_then(|v| v.as_object()) {
            if let Some(system) = zk_obj.get("system").and_then(|v| v.as_str()) {
                config.zk.system = system.to_string();
            }
            if let Some(vk_hash) = zk_obj.get("vk_hash").and_then(|v| v.as_str()) {
                config.zk.vk_hash = vk_hash.to_string();
            }
            if let Some(version) = zk_obj.get("version").and_then(|v| v.as_u64()) {
                config.zk.version = version as u32;
            }
        }

        // Load commit_reveal config
        let cr_obj = value
            .get("commit_reveal")
            .and_then(|v| v.as_object())
            .context("Missing or invalid 'commit_reveal' block in genesis config")?;

        let commit_fee_str = cr_obj
            .get("commit_fee")
            .and_then(|v| v.as_str())
            .context("Missing 'commit_fee' in commit_reveal block")?;

        let commit_fee =
            primitive_types::U256::from_str_radix(commit_fee_str.trim_start_matches("0x"), 10)
                .or_else(|_| {
                    primitive_types::U256::from_str_radix(
                        commit_fee_str.trim_start_matches("0x"),
                        16,
                    )
                })
                .context("Invalid 'commit_fee' format")?;
        if commit_fee > primitive_types::U256::from(u128::MAX) {
            anyhow::bail!("commit_fee exceeds supported u128 range");
        }

        let reveal_window = cr_obj
            .get("reveal_window")
            .and_then(|v| v.as_u64())
            .context("Missing 'reveal_window' in commit_reveal block")?;

        let expiry_blocks = cr_obj
            .get("expiry_blocks")
            .and_then(|v| v.as_u64())
            .context("Missing 'expiry_blocks' in commit_reveal block")?;

        let no_show_slash = cr_obj
            .get("no_show_slash")
            .and_then(|v| v.as_u64())
            .context("Missing 'no_show_slash' in commit_reveal block")?;

        let max_commits_per_sender = cr_obj
            .get("max_commits_per_sender")
            .and_then(|v| v.as_u64())
            .unwrap_or(16) as usize; // Default to 16 if not specified

        config.commit_reveal = sxiaum_mempool::ordering::CommitRevealConfig {
            commit_fee: commit_fee.as_u128(),
            reveal_window_blocks: reveal_window,
            commit_expiry_blocks: expiry_blocks,
            no_show_slash,
            max_commits_per_sender,
        };

        if let Some(chain_val) = value.get("chain_id") {
            let parsed_chain_id = if let Some(s) = chain_val.as_str() {
                s.parse::<u64>().context("Invalid chain_id string")?
            } else if let Some(n) = chain_val.as_u64() {
                n
            } else {
                anyhow::bail!("chain_id must be a string or integer");
            };
            if parsed_chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
                anyhow::bail!(
                    "configured chain_id {} does not match compiled protocol chain_id {}",
                    parsed_chain_id,
                    sxiaum_types::SXIAUM_CHAIN_ID
                );
            }
            config.chain_id = parsed_chain_id;
        }
        if let Some(protocol) = value.get("protocol").and_then(|value| value.as_object()) {
            if let Some(max_block_gas) = protocol
                .get("max_block_gas")
                .and_then(|value| value.as_u64())
            {
                if max_block_gas != sxiaum_block::MAX_BLOCK_GAS_LIMIT {
                    anyhow::bail!(
                        "configured max_block_gas {} does not match compiled protocol maximum {}",
                        max_block_gas,
                        sxiaum_block::MAX_BLOCK_GAS_LIMIT
                    );
                }
            }
            if let Some(block_time_ms) = protocol
                .get("block_time_ms")
                .and_then(|value| value.as_u64())
            {
                let compiled = sxiaum_block::BLOCK_INTERVAL_SECS.saturating_mul(1000);
                if block_time_ms != compiled {
                    anyhow::bail!(
                        "configured block_time_ms {} does not match compiled protocol interval {}",
                        block_time_ms,
                        compiled
                    );
                }
            }
        }

        config.validate()?;
        Ok(config)
    }
}
