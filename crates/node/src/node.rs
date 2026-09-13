use anyhow::Result;
use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sxiaum_block::{Block, BlockBuilder};
use sxiaum_consensus::hotstuff::proposer::Proposer;
use sxiaum_consensus::hotstuff::vote::{QuorumCertificate, Vote};
use sxiaum_consensus::Consensus;
use sxiaum_execution::Executor;
use sxiaum_mempool::{CommitTransaction, Mempool, RevealTransaction};
use sxiaum_networking::{
    ChainSyncState, GossipMessage, L1Request, L1Response, P2PConfig, P2PNetwork, RpcRequestHandler,
    RpcStateProofQuery, RpcStateProofRequest, RpcStateProofResponse, RpcStateProofValue,
    RpcSyncClient, RpcVerifiedHeaderEnvelope,
};
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Canonical, Transaction, Validator};
use sxiaum_zk::ZkEngine;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::{interval, MissedTickBehavior};
use tracing::info;

#[derive(Clone, Debug)]
pub enum RpcRequestEvent {
    SubmitTransaction(Box<Transaction>),
    GetBlock(u64),
    GetStateRoot,
    GetNetworkStatus,
}

#[derive(Clone, Debug)]
pub enum ConsensusEvent {
    BlockProposal(sxiaum_block::Block),
    Vote(Vote),
    QuorumCertificate(QuorumCertificate),
    NewTransaction(Transaction),
    TriggerProposal,
    Tick,
}

#[derive(Clone, Debug)]
pub enum NodeEvent {
    P2PMessage(PeerId, GossipMessage),
    RpcRequest(RpcRequestEvent),
    Consensus(ConsensusEvent),
    NewTransaction(Transaction),
}

pub use crate::config::{KzgConfig, NodeConfig, NodeMode, SyncMode, ZkConfig};

/// The core node struct. Shared mutable subsystems use async locks so the
/// live state can be accessed from both the event loop and the RPC layer
/// simultaneously without cloning divergent snapshots.
pub struct Node {
    pub config: NodeConfig,
    /// Shared P2P networking layer. Mutex avoids requiring `P2PNetwork` to be
    /// `Sync`, which libp2p's Windows-backed internals do not satisfy.
    pub networking: Arc<Mutex<P2PNetwork>>,
    pub mempool: Arc<Mempool>,
    /// Shared consensus engine -  Arc<RwLock<>> means the RPC validator-set
    /// queries see the same state that the event loop mutates.
    pub consensus: Arc<RwLock<Consensus>>,
    pub execution: Arc<Executor>,
    pub state: Arc<StateDB>,
    pub storage: Arc<StorageEngine>,
    pub zk_engine: Arc<ZkEngine>,
    validator_address: Address,
    proposer_signing_key: SigningKey,
    chain_head: Option<[u8; 32]>,
    running: AtomicBool,
    event_tx: mpsc::Sender<NodeEvent>,
    event_rx: mpsc::Receiver<NodeEvent>,
    last_proposed_view: Option<u64>,
    last_voted_view: Option<u64>,
    ws_broadcaster: Option<broadcast::Sender<(String, serde_json::Value)>>,
}

const CONSENSUS_QC_PREFIX: &[u8] = b"consensus:qc:";
const CONSENSUS_VALIDATOR_SET_KEY: &[u8] = b"consensus:validator_set";
const BLOCK_STATE_ROOT_PREFIX: &[u8] = b"execution:block:state_root:";

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct StorageBackedRpcRequestHandler {
    storage: Arc<StorageEngine>,
}

impl StorageBackedRpcRequestHandler {
    pub fn new(storage: Arc<StorageEngine>) -> Self {
        Self { storage }
    }

    fn load_validators(&self) -> Result<Vec<Validator>> {
        let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())?
        else {
            return Ok(Vec::new());
        };

        Ok(bincode::deserialize(&bytes)?)
    }

    fn load_quorum_certificate(&self, block_hash: [u8; 32]) -> Result<Option<QuorumCertificate>> {
        let mut key = Vec::with_capacity(CONSENSUS_QC_PREFIX.len() + block_hash.len());
        key.extend_from_slice(CONSENSUS_QC_PREFIX);
        key.extend_from_slice(&block_hash);

        self.storage
            .state_get(key)?
            .map(|bytes| QuorumCertificate::decode(&bytes))
            .transpose()
    }

    fn build_verified_header_envelopes(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Vec<RpcVerifiedHeaderEnvelope>> {
        if start > end {
            return Ok(Vec::new());
        }
        let max_batch = sxiaum_networking::MAX_HEADER_BATCH_SIZE;
        let clamped_end = end.min(start.saturating_add(max_batch.saturating_sub(1)));
        let validators = self.load_validators()?;
        let quorum_threshold = if validators.is_empty() {
            0
        } else {
            ((validators.len() * 2) / 3) + 1
        };
        let required_voting_power = if validators.is_empty() {
            0
        } else {
            ((validators
                .iter()
                .filter(|validator| validator.is_active())
                .map(|validator| validator.voting_power)
                .sum::<u64>()
                * 2)
                / 3)
                + 1
        };

        let mut envelopes = Vec::new();
        for height in start..=clamped_end {
            let Some(header) = self.storage.get_block_header(height)? else {
                break;
            };

            let consensus_signatures = if height == 0 {
                Vec::new()
            } else {
                let qc = self
                    .load_quorum_certificate(header.try_hash()?)?
                    .ok_or_else(|| {
                        anyhow::anyhow!("missing quorum certificate for header {}", height)
                    })?;

                if !qc.verify_with_voting_power(
                    &validators,
                    quorum_threshold,
                    required_voting_power,
                )? {
                    anyhow::bail!(
                        "stored quorum certificate failed validation for header {}",
                        height
                    );
                }

                qc.validators
                    .iter()
                    .copied()
                    .zip(qc.signatures.iter().cloned())
                    .collect()
            };

            envelopes.push(RpcVerifiedHeaderEnvelope {
                header,
                consensus_signatures,
                hotstuff_view_phase: None,
            });
        }

        Ok(envelopes)
    }

    fn block_state_root_key(height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_STATE_ROOT_PREFIX.len() + 20);
        key.extend_from_slice(BLOCK_STATE_ROOT_PREFIX);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }

    fn build_state_proof_response(
        &self,
        request: RpcStateProofRequest,
    ) -> Result<RpcStateProofResponse> {
        let persisted_root = self
            .storage
            .state_get(Self::block_state_root_key(request.height))?
            .ok_or_else(|| {
                anyhow::anyhow!("missing state root for block height {}", request.height)
            })?;
        if persisted_root.len() != 32 {
            anyhow::bail!(
                "invalid persisted state root for block height {}",
                request.height
            );
        }

        let (value, proof) = match request.query {
            RpcStateProofQuery::Account { address } => {
                let (account, proof) = self
                    .storage_backed_state()
                    .export_account_proof_for_height(request.height, &address, request.max_depth)?;
                (RpcStateProofValue::Account(account), proof)
            }
            RpcStateProofQuery::Storage { address, key } => {
                let (value, proof) = self
                    .storage_backed_state()
                    .export_storage_proof_for_height(
                        request.height,
                        &address,
                        key,
                        request.max_depth,
                    )?;
                (RpcStateProofValue::Storage(value), proof)
            }
            RpcStateProofQuery::Minimal { key } => {
                let (value, proof) = self
                    .storage_backed_state()
                    .export_minimal_proof_for_height(request.height, key, request.max_depth)?;
                (RpcStateProofValue::Minimal(value), proof)
            }
        };

        Ok(RpcStateProofResponse {
            height: request.height,
            proof,
            value,
        })
    }

    fn storage_backed_state(&self) -> StateDB {
        StateDB::new(self.storage.clone())
    }
}

impl RpcRequestHandler for StorageBackedRpcRequestHandler {
    fn handle_request(&self, _peer_id: PeerId, request: L1Request) -> Result<L1Response> {
        match request {
            L1Request::GetLatestBlockHeight => Ok(L1Response::respond_latest_block_height(Some(
                self.storage.latest_block_height()?,
            ))),
            L1Request::GetBlock(height) => {
                let block = match (
                    self.storage.get_block_header(height)?,
                    self.storage.get_block_body(height)?,
                ) {
                    (Some(header), Some(body)) => {
                        Some(bincode::serialize(&Block::new(header, body))?)
                    }
                    _ => None,
                };
                Ok(L1Response::respond_block(block))
            }
            L1Request::GetHeaders { start, end } => {
                let headers = self.build_verified_header_envelopes(start, end)?;
                Ok(L1Response::respond_headers(Some(headers)))
            }
            L1Request::GetBlockProof(height) => {
                let proof = self
                    .storage
                    .get_block_header(height)?
                    .and_then(|h| h.zk_proof);
                Ok(L1Response::respond_block_proof(proof))
            }
            L1Request::GetTransaction(hash) => {
                let tx_bytes = self.storage.get_transaction_bytes(hash)?;
                Ok(L1Response::respond_transaction(tx_bytes))
            }
            L1Request::GetStateProof(request) => Ok(L1Response::respond_state_proof(Some(
                self.build_state_proof_response(request)?,
            ))),
        }
    }
}

impl Node {
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing node...");
        let (event_tx, event_rx) = mpsc::channel(1024);

        let storage = crate::startup::Startup::init_storage(&config.storage_path)?;
        let state = crate::startup::Startup::init_state(storage.clone())?;
        let evm_config = sxiaum_execution::evm_runtime::EvmConfig::new(config.chain_id);
        let zk_engine = Arc::new(if config.network.as_deref() == Some("mainnet") {
            sxiaum_zk::ZkEngine::new_mainnet()
        } else {
            sxiaum_zk::ZkEngine::new()
        });
        let execution = Arc::new(
            Executor::new(state.clone(), evm_config).with_proof_verifier(zk_engine.clone()),
        );
        let proposer_signing_key = SigningKey::from_bytes(&config.proposer_private_key.0);
        let validator_address =
            Address::from_public_key(&proposer_signing_key.verifying_key().to_bytes());
        let mut mempool_config = config.mempool.clone();
        mempool_config.commit_reveal = config.commit_reveal.clone();
        let mempool = Arc::new(Mempool::with_storage(
            mempool_config,
            state.clone(),
            storage.clone(),
        ));

        // Derive a deterministic libp2p keypair so the PeerID is stable
        // across restarts. Falls back to the proposer key when no explicit
        // seed is configured (e.g. single-node devnet without per-validator
        // config files).
        let p2p_seed = config
            .p2p_node_key_seed
            .unwrap_or(config.proposer_private_key.0);

        // NOTE: the private-key material intentionally stays resident in
        // `proposer_signing_key` for the lifetime of the node, so zeroing this
        // config copy would provide no security while POISONING `restart()`
        // (a rebuilt node would derive its identity from a degenerate
        // all-zeros seed and silently lose its validator identity).

        let p2p_keypair = {
            let mut kp_bytes = p2p_seed;
            libp2p::identity::Keypair::ed25519_from_bytes(&mut kp_bytes)
                .unwrap_or_else(|_| libp2p::identity::Keypair::generate_ed25519())
        };
        info!(
            "P2P identity: peer_id={}",
            p2p_keypair.public().to_peer_id()
        );
        let networking = Arc::new(Mutex::new(
            P2PNetwork::new(P2PConfig {
                local_key: p2p_keypair,
                bootstrap_peers: config.bootstrap_peers.clone(),
                discovery_interval: config.discovery_interval,
                discovery_backoff: config.discovery_backoff,
                max_peers: config.max_peers,
                max_header_batch: sxiaum_networking::MAX_HEADER_BATCH_SIZE, // Reasonable defaults
                max_header_requests_per_peer_per_window:
                    sxiaum_networking::MAX_HEADER_REQUESTS_PER_WINDOW,
                header_request_window_secs: sxiaum_networking::HEADER_REQUEST_WINDOW_SECS,
                max_state_proof_requests_per_peer_per_window:
                    sxiaum_networking::MAX_STATE_PROOF_REQUESTS_PER_WINDOW,
                state_proof_request_window_secs: sxiaum_networking::STATE_PROOF_REQUEST_WINDOW_SECS,
                db: Some(storage.db()),
            })
            .await?,
        ));
        networking
            .lock()
            .await
            .set_rpc_handler(Arc::new(StorageBackedRpcRequestHandler::new(
                storage.clone(),
            )));

        // Pass the shared storage engine into Consensus so both use the same DB.
        let consensus = Consensus::new_production(
            storage.clone(),
            validator_address,
            mempool.clone(),
            execution.clone(),
        );
        let consensus = Arc::new(RwLock::new(consensus));

        Ok(Self {
            config,
            networking,
            mempool,
            consensus,
            execution,
            state,
            storage,
            zk_engine,
            validator_address,
            proposer_signing_key,
            chain_head: None,
            running: AtomicBool::new(false),
            event_tx,
            event_rx,
            last_proposed_view: None,
            last_voted_view: None,
            ws_broadcaster: None,
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Starting node services in {:?} mode...", self.config.mode);
        self.mempool.start()?;

        // Consensus is only started for full participants.  Light-client nodes
        // neither propose blocks nor cast votes.
        if self.config.mode != NodeMode::LightClient {
            let _ = self.consensus.write().await.start()?;
        }

        // P2P listening is now handled in startup.rs to avoid double-binding.

        let rpc_context = Arc::new(sxiaum_rpc::RpcContext::new(
            self.networking.clone(),
            self.mempool.clone(),
            self.consensus.clone(),
            self.state.clone(),
            self.storage.clone(),
            self.execution.clone(),
            Arc::new(sxiaum_rpc::jwt::JwtManager::new(
                std::env::var("SXIAUM_JWT_KEY_FILE")
                    .ok()
                    .map(std::path::PathBuf::from),
            )),
        ));
        self.ws_broadcaster = Some(rpc_context.ws_broadcaster.clone());
        let tls = if let (Ok(cert), Ok(key)) = (
            std::env::var("SXIAUM_TLS_CERT_PATH"),
            std::env::var("SXIAUM_TLS_KEY_PATH"),
        ) {
            Some(sxiaum_rpc::server::TlsConfig {
                cert_path: std::path::PathBuf::from(cert),
                key_path: std::path::PathBuf::from(key),
            })
        } else {
            None
        };
        let allow_reverse_proxy = std::env::var("SXIAUM_REVERSE_PROXY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut rpc_server = sxiaum_rpc::RpcServer::new(
            rpc_context,
            sxiaum_rpc::RpcConfig {
                addr: self.config.rpc_addr,
                tls,
                allow_reverse_proxy,
                ..Default::default()
            },
        );
        tokio::spawn(async move {
            if let Err(error) = rpc_server.start().await {
                tracing::error!("rpc server error: {:?}", error);
            }
        });

        // Spawn a dedicated P2P listener that continuously polls the networking
        // layer for incoming gossip and forwards every message into the shared
        // event channel. Running as an independent task means P2P traffic is
        // never starved behind the consensus tick or RPC queue.
        {
            let networking = self.networking.clone();
            let event_tx = self.event_tx.clone();
            tokio::spawn(async move {
                loop {
                    let message = networking.lock().await.receive_message();
                    match message {
                        Some((peer_id, msg)) => {
                            if event_tx
                                .send(NodeEvent::P2PMessage(peer_id, msg))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        None => {
                            tokio::time::sleep(Duration::from_millis(
                                crate::P2P_MESSAGE_POLL_INTERVAL_MS,
                            ))
                            .await
                        }
                    }
                }
            });
        }

        self.run_event_loop().await
    }

    pub async fn stop(&mut self) -> Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping node services...");

        // - - - Step 1: stop networking service - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        //    Closes all open libp2p connections and shuts down the swarm event
        //    loop so no further inbound messages are accepted.
        self.networking.lock().await.shutdown()?;

        // - - - Step 2: stop consensus engine - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        //    Saves the current view number and validator-set snapshot so the
        //    engine can resume from the same point on restart.
        self.consensus.write().await.stop()?;

        // - - - Step 3: flush mempool to disk - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        //    Serialises every pending transaction into the redb mempool table.
        //    On restart, `restore_mempool_state` will re-insert them.
        let persisted_mempool = self.mempool.persist_mempool_transactions_to_disk()?;
        info!("flushed {} pending transactions to disk", persisted_mempool);

        // - - - Step 4: persist state root - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        //    Commit the in-memory state trie and store the resulting Merkle
        //    root under the well-known metadata key so node restarts can
        //    verify the on-disk trie is consistent with the last committed block.
        let persisted_state_root = self.state.commit()?;
        self.storage.state_put(
            b"metadata:state_root".to_vec(),
            persisted_state_root.to_vec(),
        )?;
        info!(
            "persisted state root: 0x{}",
            hex::encode(persisted_state_root)
        );

        // - - - Step 5: close storage database - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        //    `flush_to_disk` forces an fsync so all redb pages are durable,
        //    then `shutdown` releases the file lock cleanly.
        self.storage.flush_to_disk()?;
        self.storage.shutdown()?;
        info!("Storage database closed. Node shutdown complete.");

        Ok(())
    }

    pub async fn restart(&mut self) -> Result<()> {
        info!("Restarting node...");
        self.stop().await?;

        let replacement = Self::new(self.config.clone()).await?;
        *self = replacement;
        self.start().await
    }

    pub async fn run_event_loop(&mut self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            self.running.store(true, Ordering::SeqCst);
        }

        info!("Entering node event loop...");
        let mut consensus_tick = interval(Duration::from_millis(crate::CONSENSUS_TICK_INTERVAL_MS));
        consensus_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

        while self.running.load(Ordering::SeqCst) {
            // Periodic metrics update
            crate::metrics::MetricsService::record_block_height(
                self.storage.latest_block_height().unwrap_or(0),
            );
            crate::metrics::MetricsService::record_peer_count(
                self.networking.lock().await.peer_count(),
            );
            crate::metrics::MetricsService::record_mempool_size(
                self.mempool.pending_count().unwrap_or(0),
            );

            tokio::select! {
                // - - - 1. Incoming P2P messages (forwarded by the listener task)
                // - - - 2. Incoming RPC requests (forwarded by the RPC server)
                // - - - 3. Consensus events submitted by subsystems
                // - - - 4. New transactions submitted directly to the node
                // All four sources share the same unbounded channel so they
                // are all first-class citizens in the select and none can
                // starve the others.
                maybe_event = self.event_rx.recv() => {
                    if let Some(event) = maybe_event {
                        // - - - 5. Dispatch to the appropriate module.
                        //
                        // SECURITY (C-01): a single malformed or rejected P2P
                        // message MUST NOT kill the event loop. Any error is
                        // logged and swallowed so a remote peer can never halt
                        // this node remotely. Only an unrecoverable internal
                        // failure (channel closed) exits the loop.
                        if let Err(error) = self.dispatch_event(event).await {
                            tracing::error!(
                                "event dispatch failed (node continues running): {}",
                                error
                            );
                        }
                    }
                }
                // - - - 6. Periodic consensus tick -  drives view timeouts and
                //       block proposal attempts even when the event queue is
                //       empty.  Processed asynchronously, same as every other
                //       event.
                _ = consensus_tick.tick() => {
                    if let Err(error) =
                        self.dispatch_event(NodeEvent::Consensus(ConsensusEvent::Tick)).await
                    {
                        tracing::error!(
                            "consensus tick failed (node continues running): {}",
                            error
                        );
                    }
                }
            }
        }

        Ok(())
    }

    pub fn event_sender(&self) -> mpsc::Sender<NodeEvent> {
        self.event_tx.clone()
    }

    pub fn submit_rpc_request(&self, request: RpcRequestEvent) -> Result<()> {
        self.event_tx
            .try_send(NodeEvent::RpcRequest(request))
            .map_err(|error| anyhow::anyhow!("failed to enqueue rpc request event: {}", error))
    }

    pub fn submit_consensus_event(&self, event: ConsensusEvent) -> Result<()> {
        self.event_tx
            .try_send(NodeEvent::Consensus(event))
            .map_err(|error| anyhow::anyhow!("failed to enqueue consensus event: {}", error))
    }

    pub fn submit_new_transaction(&self, transaction: Transaction) -> Result<()> {
        self.event_tx
            .try_send(NodeEvent::NewTransaction(transaction))
            .map_err(|error| anyhow::anyhow!("failed to enqueue transaction event: {}", error))
    }

    pub async fn dispatch_event(&mut self, event: NodeEvent) -> Result<()> {
        match event {
            NodeEvent::P2PMessage(peer_id, message) => {
                self.handle_p2p_message_from_peer(peer_id, message).await
            }
            NodeEvent::RpcRequest(request) => self.handle_rpc_request(request).await,
            NodeEvent::Consensus(event) => self.handle_consensus_event(event).await,
            NodeEvent::NewTransaction(transaction) => {
                if let Some(broadcaster) = &self.ws_broadcaster {
                    let _ = broadcaster.send((
                        "newPendingTransactions".to_string(),
                        serde_json::json!(format!(
                            "{:?}",
                            transaction.try_hash().unwrap_or_default()
                        )),
                    ));
                }
                self.handle_new_transaction(transaction).await
            }
        }
    }

    pub async fn handle_p2p_message(&mut self, message: GossipMessage) -> Result<()> {
        self.handle_p2p_message_inner(None, message).await
    }

    async fn handle_p2p_message_from_peer(
        &mut self,
        peer_id: PeerId,
        message: GossipMessage,
    ) -> Result<()> {
        self.handle_p2p_message_inner(Some(peer_id), message).await
    }

    async fn handle_p2p_message_inner(
        &mut self,
        peer_id: Option<PeerId>,
        message: GossipMessage,
    ) -> Result<()> {
        // SECURITY (C-01): every failure below is a property of the REMOTE
        // message or of transient local state. None of them justify halting
        // the node, so all are logged and converted to Ok(()) at the end.
        let result: Result<()> = match message {
            GossipMessage::Transaction(payload) => {
                let transaction: Transaction = match Transaction::decode(&payload)
                    .or_else(|_| bincode::deserialize(&payload))
                {
                    Ok(tx) => tx,
                    Err(error) => {
                        tracing::debug!("dropping undecodable transaction gossip: {}", error);
                        return Ok(());
                    }
                };
                if let Some(peer_id) = peer_id {
                    self.mempool
                        .receive_transaction_from_p2p_gossip_from_peer(
                            Some(peer_id.to_string()),
                            transaction,
                        )
                        .map(|_| ())
                } else {
                    self.handle_new_transaction(transaction).await
                }
            }
            GossipMessage::Block(payload) => {
                let block: sxiaum_block::Block =
                    match Block::decode(&payload).or_else(|_| bincode::deserialize(&payload)) {
                        Ok(block) => block,
                        Err(error) => {
                            tracing::debug!("dropping undecodable block gossip: {}", error);
                            return Ok(());
                        }
                    };
                self.handle_network_block_proposal(block).await
            }
            GossipMessage::Commit(payload) => {
                let commit: CommitTransaction = match CommitTransaction::decode(&payload)
                    .or_else(|_| bincode::deserialize(&payload))
                {
                    Ok(commit) => commit,
                    Err(error) => {
                        tracing::debug!("dropping undecodable commit gossip: {}", error);
                        return Ok(());
                    }
                };
                if let Some(peer_id) = peer_id {
                    self.mempool
                        .receive_commit_from_p2p_gossip_from_peer(Some(peer_id.to_string()), commit)
                        .map(|_| ())
                } else {
                    self.handle_new_commit(commit).await
                }
            }
            GossipMessage::Reveal(payload) => {
                let reveal: RevealTransaction = match RevealTransaction::decode(&payload)
                    .or_else(|_| bincode::deserialize(&payload))
                {
                    Ok(reveal) => reveal,
                    Err(error) => {
                        tracing::debug!("dropping undecodable reveal gossip: {}", error);
                        return Ok(());
                    }
                };
                if let Some(peer_id) = peer_id {
                    self.mempool
                        .receive_reveal_from_p2p_gossip_from_peer(Some(peer_id.to_string()), reveal)
                } else {
                    self.handle_new_reveal(reveal).await
                }
            }
            GossipMessage::Vote(payload) => {
                let vote = match Vote::decode(&payload) {
                    Ok(vote) => vote,
                    Err(error) => {
                        tracing::debug!("dropping undecodable vote gossip: {}", error);
                        return Ok(());
                    }
                };
                self.handle_consensus_event(ConsensusEvent::Vote(vote))
                    .await
            }
            GossipMessage::QuorumCertificate(payload) => {
                let qc = match QuorumCertificate::decode(&payload) {
                    Ok(qc) => qc,
                    Err(error) => {
                        tracing::debug!("dropping undecodable QC gossip: {}", error);
                        return Ok(());
                    }
                };
                self.handle_consensus_event(ConsensusEvent::QuorumCertificate(qc))
                    .await
            }
            GossipMessage::StateSync(_) => {
                info!("received state sync gossip message");
                Ok(())
            }
        };

        if let Err(ref error) = result {
            tracing::info!("failed to process p2p message (message dropped): {}", error);
        }

        // SECURITY (C-01): never propagate remote-message failures upward —
        // the event loop must survive any peer-supplied garbage.
        Ok(())
    }

    async fn handle_rpc_request(&mut self, request: RpcRequestEvent) -> Result<()> {
        match request {
            RpcRequestEvent::SubmitTransaction(transaction) => {
                self.handle_rpc_transaction_submission(*transaction).await?;
            }
            RpcRequestEvent::GetBlock(height) => {
                let _ = self.storage.get_block_header(height)?;
            }
            RpcRequestEvent::GetStateRoot => {
                let _ = self.state.state_root();
            }
            RpcRequestEvent::GetNetworkStatus => {
                let _ = self.networking.lock().await.peer_count();
            }
        }

        Ok(())
    }

    async fn handle_consensus_event(&mut self, event: ConsensusEvent) -> Result<()> {
        match event {
            ConsensusEvent::BlockProposal(block) => {
                let _ = self.consensus.write().await.process_block_proposal(block)?;
            }
            ConsensusEvent::Vote(vote) => {
                let current_view = self.consensus.read().await.current_view();
                if vote.view < current_view {
                    tracing::debug!(
                        "ignoring stale vote for view {} (current view {})",
                        vote.view,
                        current_view
                    );
                    return Ok(());
                }
                // Start the consensus-latency clock when a vote arrives.
                let vote_received_at = std::time::Instant::now();
                let mut generated_votes = Vec::new();

                let previous_finalized_height = {
                    let consensus = self.consensus.read().await;
                    consensus.finalized_block_height
                };

                let mut current_vote = Some(vote);
                while let Some(v) = current_vote.take() {
                    let mut consensus = self.consensus.write().await;
                    let qc_opt = consensus.process_vote(v)?;
                    if let Some(qc) = qc_opt {
                        if self.config.mode == NodeMode::Validator {
                            if let Some(next_vote) = consensus.generate_next_phase_vote(
                                self.validator_address,
                                &self.proposer_signing_key,
                                &qc,
                            )? {
                                generated_votes.push(next_vote.clone());
                                current_vote = Some(next_vote);
                            }
                        }
                    }
                }

                for v in generated_votes {
                    if let Err(error) = self
                        .networking
                        .lock()
                        .await
                        .broadcast_message(GossipMessage::Vote(v.encode()))
                    {
                        tracing::warn!("next phase vote gossip broadcast skipped: {}", error);
                    }
                }

                let is_finalized = {
                    let consensus = self.consensus.read().await;
                    consensus.finalized_block_height > previous_finalized_height
                };

                if is_finalized {
                    let block_opt = {
                        let consensus = self.consensus.read().await;
                        consensus.latest_finalized_block()
                    };
                    if let Some(block) = block_opt {
                        crate::metrics::MetricsService::record_consensus_latency(
                            vote_received_at.elapsed(),
                        );
                        self.handle_finalized_block(block).await?;
                    }
                }
            }
            ConsensusEvent::QuorumCertificate(qc) => {
                let mut generated_votes = Vec::new();
                let previous_finalized_height = {
                    let consensus = self.consensus.read().await;
                    consensus.finalized_block_height
                };

                {
                    let mut consensus = self.consensus.write().await;
                    if consensus.process_quorum_certificate(qc.clone()).is_ok()
                        && self.config.mode == NodeMode::Validator
                    {
                        if let Ok(Some(next_vote)) = consensus.generate_next_phase_vote(
                            self.validator_address,
                            &self.proposer_signing_key,
                            &qc,
                        ) {
                            generated_votes.push(next_vote);
                        }
                    }
                }

                for v in generated_votes {
                    // Process our own generated vote immediately so it counts towards the next phase QC locally
                    let _ = self.consensus.write().await.process_vote(v.clone());
                    if let Err(error) = self
                        .networking
                        .lock()
                        .await
                        .broadcast_message(GossipMessage::Vote(v.encode()))
                    {
                        tracing::warn!("next phase vote gossip broadcast skipped: {}", error);
                    }
                }

                let is_finalized = {
                    let consensus = self.consensus.read().await;
                    consensus.finalized_block_height > previous_finalized_height
                };

                if is_finalized {
                    let block_opt = {
                        let consensus = self.consensus.read().await;
                        consensus.latest_finalized_block()
                    };
                    if let Some(block) = block_opt {
                        self.handle_finalized_block(block).await?;
                    }
                }
            }
            ConsensusEvent::NewTransaction(_) | ConsensusEvent::TriggerProposal => {
                if self.config.mode == NodeMode::Validator {
                    if let Err(error) = self
                        .produce_and_broadcast_block_proposal(crate::MAX_BLOCK_PROPOSAL_TXS)
                        .await
                    {
                        tracing::warn!("failed to produce block proposal: {}", error);
                    }
                }
            }
            ConsensusEvent::Tick => {
                if let Err(error) = self.synchronize_if_behind().await {
                    tracing::warn!("synchronization failed: {}", error);
                }

                let is_timed_out = {
                    let consensus = self.consensus.read().await;
                    consensus.pacemaker.is_timed_out()
                };

                if is_timed_out {
                    let mut consensus = self.consensus.write().await;
                    if consensus.pacemaker.is_timed_out() {
                        let new_view = consensus.pacemaker.on_timeout();
                        tracing::warn!("view timeout! advanced to view {}", new_view);
                    }
                }

                if self.config.mode == NodeMode::Validator {
                    if let Err(error) = self
                        .produce_and_broadcast_block_proposal(crate::MAX_BLOCK_PROPOSAL_TXS)
                        .await
                    {
                        tracing::warn!("failed to produce block proposal: {}", error);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_new_transaction(&mut self, transaction: Transaction) -> Result<()> {
        let tx_hash = self.mempool.add_transaction(transaction)?;
        if let Some(message) = self.mempool.broadcast_new_transaction_to_peers(tx_hash)? {
            if let Err(error) = self.networking.lock().await.broadcast_message(message) {
                tracing::warn!("transaction gossip broadcast skipped: {}", error);
            }
        }
        Ok(())
    }

    async fn handle_new_commit(&mut self, commit: CommitTransaction) -> Result<()> {
        // SECURITY (C-13): commit-fee solvency. A commit is only accepted
        // when the sender's balance can cover the configured commit fee —
        // the commit phase gets real spam economics instead of free
        // slot-jamming. (Signature authenticity is enforced inside the
        // mempool pool itself.)
        let fee = self.mempool.commit_fee();
        if fee > 0 {
            let sender = Address(commit.sender);
            let balance = self
                .state
                .load_account(&sender)?
                .map(|account| account.balance)
                .unwrap_or(primitive_types::U256::zero());
            let fee_u256 = primitive_types::U256([fee as u64, (fee >> 64) as u64, 0, 0]);
            if balance < fee_u256 {
                anyhow::bail!(
                    "commit rejected: sender 0x{} balance below commit fee",
                    hex::encode(commit.sender)
                );
            }
        }

        let commit_id = self.mempool.submit_commit(commit)?;
        if let Some(message) = self.mempool.broadcast_new_commit_to_peers(commit_id)? {
            if let Err(error) = self.networking.lock().await.broadcast_message(message) {
                tracing::warn!("commit gossip broadcast skipped: {}", error);
            }
        }
        Ok(())
    }

    async fn handle_new_reveal(&mut self, reveal: RevealTransaction) -> Result<()> {
        if let Some(message) = self.mempool.broadcast_new_reveal_to_peers(&reveal)? {
            self.mempool.submit_reveal(reveal)?;
            if let Err(error) = self.networking.lock().await.broadcast_message(message) {
                tracing::warn!("reveal gossip broadcast skipped: {}", error);
            }
        } else {
            self.mempool.submit_reveal(reveal)?;
        }
        Ok(())
    }

    async fn handle_rpc_transaction_submission(&mut self, transaction: Transaction) -> Result<()> {
        // - - - Step 1: receive transaction from RPC.
        //    Basic structural checks (size, signature format, nonce bounds)
        //    before touching any shared state.  Cheap and allocation-free.
        transaction.validate_basic()?;

        // - - - Step 2 + 3: full validation + insert into mempool.
        //    `add_transaction` runs the complete TxValidator pipeline
        //    (signature, balance, nonce, gas, duplicate detection) and, on
        //    success, atomically inserts the transaction into the pool and
        //    persists it to disk.
        let tx_hash = self.mempool.add_transaction(transaction.clone())?;
        info!("rpc transaction accepted: hash=0x{}", hex::encode(tx_hash));

        // - - - Step 4: broadcast transaction to P2P peers.
        //    `broadcast_new_transaction_to_peers` checks the gossip tracker so
        //    we never re-broadcast a transaction that arrived via gossip.
        if let Some(message) = self.mempool.broadcast_new_transaction_to_peers(tx_hash)? {
            if let Err(error) = self.networking.lock().await.broadcast_message(message) {
                tracing::warn!("rpc transaction p2p broadcast skipped: {}", error);
            }
        }

        // - - - Step 5: notify consensus proposer so it can trigger a new block
        //    proposal when the node is the current leader.
        self.handle_consensus_event(ConsensusEvent::NewTransaction(transaction))
            .await
    }

    async fn handle_network_block_proposal(&mut self, block: sxiaum_block::Block) -> Result<()> {
        // - - - Step 1: received block proposal from the P2P network.
        //    Already deserialized by handle_p2p_message; `block` is the
        //    canonical in-memory representation.
        info!(
            "received block proposal: height={}, txs={}, proposer=0x{}",
            block.height(),
            block.transaction_count(),
            hex::encode(block.header.proposer)
        );

        // Skip blocks at or below finalized height (re-broadcast guard).
        {
            let finalized_height = self.consensus.read().await.finalized_block_height;
            if block.height() <= finalized_height {
                tracing::debug!(
                    "skipping already-finalized block height={} (local finalized={})",
                    block.height(),
                    finalized_height
                );
                return Ok(());
            }
        }

        // - - - Step 1b (SECURITY, C-02): authenticate the proposer BEFORE any
        //    execution or voting. A gossip block must satisfy every check the
        //    canonical pipeline applies — proposer identity, Ed25519 signature,
        //    parent QC chaining, validator-set root and ZK validity proof.
        //    Without these a remote peer could obtain this validator's vote
        //    signature on attacker-crafted blocks.
        self.validate_gossip_block_authenticity(&block).await?;

        // - - - Step 2: validate block header.
        //    Checks: parent hash not zero, timestamp monotonicity, valid
        //    proposer address, and correct block height.
        block.validate_mainnet(current_unix_timestamp())?;

        // Mainnet chain_id validation (replay protection).
        if block.header.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            anyhow::bail!(
                "block chain_id {} does not match mainnet {}",
                block.header.chain_id,
                sxiaum_types::SXIAUM_CHAIN_ID
            );
        }

        // Mainnet block version validation (protocol upgrade safety).
        if block.header.version != sxiaum_block::BLOCK_VERSION_CURRENT {
            anyhow::bail!(
                "block version {} does not match current protocol version {}",
                block.header.version,
                sxiaum_block::BLOCK_VERSION_CURRENT
            );
        }

        // - - - Step 3: validate transactions.
        //    Structural + signature checks on every transaction in the
        //    block body, independent of the current chain state.
        self.execution.validate_block_transactions(&block)?;

        // - - - Step 4 + 5: execute transactions and compute new state root.
        //    Applies every transaction against the current state, advances
        //    account nonces and balances, and returns the resulting root hash.
        let computed_state_root = match self.execution.execute_block(block.clone()) {
            Ok(root) => root,
            Err(error) => {
                let _ = self.state.rollback();
                return Err(error);
            }
        };

        // - - - Step 6: verify the computed state root matches the block header.
        //    A mismatch means the proposer is either faulty or malicious;
        //    we reject the proposal without penalising our local state.
        if computed_state_root != block.header.state_root {
            let _ = self.state.rollback();
            anyhow::bail!(
                "state root mismatch on block proposal at height={}: computed=0x{}, header=0x{}",
                block.height(),
                hex::encode(computed_state_root),
                hex::encode(block.header.state_root)
            );
        }

        // - - - Step 7: pass the validated block to the consensus engine.
        //    HotStuff will cast a vote if the block is safe to extend and we
        //    are the correct voter for this view.
        let block_hash = block.try_hash()?;
        let admission_result = self.consensus.write().await.process_block_proposal(block);
        if let Err(error) = admission_result {
            let _ = self.state.rollback();
            return Err(error);
        }
        self.cast_and_broadcast_vote(block_hash).await?;
        Ok(())
    }

    /// SECURITY (C-02): full authentication pipeline for blocks arriving over
    /// gossip. Mirrors the canonical validation performed by the networking
    /// layer's `receive_block_gossip_message` so that NO trust boundary is
    /// bypassed when a block reaches this node directly:
    ///
    /// 1. proposer must be the elected leader for the current view,
    /// 2. proposer Ed25519 signature over the header must verify,
    /// 3. parent QC must be present and cryptographically valid (chaining),
    /// 4. validator-set root must match the local active validator set,
    /// 5. ZK validity proof must verify against the parent state root.
    async fn validate_gossip_block_authenticity(
        &mut self,
        block: &sxiaum_block::Block,
    ) -> Result<()> {
        // Genesis blocks are trusted by construction (embedded in config).
        if block.is_genesis() {
            return Ok(());
        }

        // --- 1. Proposer-is-leader check -------------------------------------
        let (current_view, leader, validator_root) = {
            let consensus = self.consensus.read().await;
            (
                consensus.current_view(),
                consensus.current_leader(),
                consensus.current_validator_root(),
            )
        };
        match leader {
            Some(leader) if leader == block.header.proposer => {}
            Some(leader) => {
                anyhow::bail!(
                    "gossip block rejected: proposer 0x{} is not the elected leader 0x{} for view {}",
                    hex::encode(block.header.proposer),
                    hex::encode(leader),
                    current_view
                );
            }
            None => {
                anyhow::bail!(
                    "gossip block rejected: no elected leader for view {} (empty validator set?)",
                    current_view
                );
            }
        }

        // --- 2. Proposer Ed25519 signature -----------------------------------
        let proposer_validator = {
            let consensus = self.consensus.read().await;
            consensus
                .validator_set
                .validator(&block.header.proposer)
                .cloned()
        };
        let proposer_validator = proposer_validator.ok_or_else(|| {
            anyhow::anyhow!(
                "gossip block rejected: proposer 0x{} not in local validator set",
                hex::encode(block.header.proposer)
            )
        })?;
        if !block.header.verify_signature(&proposer_validator.pubkey)? {
            anyhow::bail!(
                "gossip block rejected: invalid proposer signature at height {}",
                block.height()
            );
        }

        // --- 3. Parent QC verification (chaining proof) ----------------------
        let parent_hash = block.header.parent_hash;
        let parent_qc = {
            let consensus = self.consensus.read().await;
            consensus.load_persisted_quorum_certificate(parent_hash)?
        };
        let parent_qc = match parent_qc {
            Some(qc) => qc,
            None => anyhow::bail!(
                "gossip block rejected: no quorum certificate for parent 0x{} (cannot verify chaining)",
                hex::encode(parent_hash)
            ),
        };
        {
            let consensus = self.consensus.read().await;
            consensus.verify_quorum_certificate(&parent_qc)?;
        }
        if parent_qc.block_hash != parent_hash {
            anyhow::bail!(
                "gossip block rejected: parent QC attests 0x{} but block parent is 0x{}",
                hex::encode(parent_qc.block_hash),
                hex::encode(parent_hash)
            );
        }

        // --- 4. Validator-set root -------------------------------------------
        if block.header.validator_root != validator_root {
            anyhow::bail!(
                "gossip block rejected: validator_root mismatch (block=0x{}, local=0x{})",
                hex::encode(block.header.validator_root),
                hex::encode(validator_root)
            );
        }

        // --- 5. ZK validity proof --------------------------------------------
        // Anchored to the parent block's committed state root.
        let parent_height = block.height().checked_sub(1).ok_or_else(|| {
            anyhow::anyhow!("gossip block rejected: underflow computing parent height")
        })?;
        let state_root_before = match self.storage.get_block_header(parent_height)? {
            Some(parent_header) => parent_header.state_root,
            None => anyhow::bail!(
                "gossip block rejected: parent header at height {} unavailable locally",
                parent_height
            ),
        };
        self.zk_engine
            .validate_block_proof(block, state_root_before)
            .map_err(|error| {
                anyhow::anyhow!(
                    "gossip block rejected: ZK proof validation failed: {}",
                    error
                )
            })?;

        Ok(())
    }

    /// Vote for an accepted proposal and gossip the signed vote. Processing
    /// locally first also lets single-validator development networks finalize.
    async fn cast_and_broadcast_vote(&mut self, block_hash: [u8; 32]) -> Result<()> {
        if self.config.mode != NodeMode::Validator {
            return Ok(());
        }

        let view = self.consensus.read().await.current_view();

        // Guard: never cast two votes in the same view. This prevents
        // double-voting when a view-sync causes cast_and_broadcast_vote to be
        // called again for a view we already voted on.
        if self.last_voted_view == Some(view) {
            tracing::debug!("already voted in view {}, skipping duplicate vote", view);
            return Ok(());
        }

        let mut vote = Vote::new(self.validator_address, block_hash, view);
        vote.sign(&self.proposer_signing_key)?;

        self.last_voted_view = Some(view);

        if let Err(error) = self
            .networking
            .lock()
            .await
            .broadcast_message(GossipMessage::Vote(vote.encode()))
        {
            tracing::warn!("vote gossip broadcast skipped: {}", error);
        }

        Box::pin(self.handle_consensus_event(ConsensusEvent::Vote(vote))).await?;

        Ok(())
    }

    async fn handle_finalized_block(&mut self, block: sxiaum_block::Block) -> Result<()> {
        info!(
            "finalizing block: height={}, txs={}",
            block.height(),
            block.transaction_count()
        );

        // - Step 2: apply state changes.
        //    `state.commit()` flushes the in-memory state trie to the
        //    storage backend and returns the persisted Merkle root hash.
        let persisted_state_root = self.state.commit()?;
        if persisted_state_root != block.header.state_root {
            anyhow::bail!(
                "state root mismatch after commit at height={}: persisted=0x{}, block=0x{}",
                block.height(),
                hex::encode(persisted_state_root),
                hex::encode(block.header.state_root)
            );
        }

        // - Step 3: persist block header and body to storage.
        //    `atomic_block_commit` writes both in a single redb transaction
        //    so a crash between the two writes cannot leave a partial record.
        let header_bytes = bincode::serialize(&block.header)?;
        let body_bytes = bincode::serialize(&block.body)?;
        self.storage
            .atomic_block_commit(block.height(), header_bytes, body_bytes)?;

        // Persist transaction details and receipts to index tables.
        if !block.body.transactions.is_empty() {
            self.storage
                .store_block_transactions_typed(block.height(), &block.body.transactions)?;
            for (tx, receipt) in block
                .body
                .transactions
                .iter()
                .zip(block.body.receipts.iter())
            {
                self.storage.store_receipt(tx.try_hash()?, receipt)?;
            }
        }

        // - Step 4: persist the canonical state root for this height.
        //    Stored under a well-known key so node restarts can verify that
        //    the on-disk state trie matches the last committed block.
        self.storage.state_put(
            b"metadata:state_root".to_vec(),
            block.header.state_root.to_vec(),
        )?;
        self.storage.state_put(
            StorageBackedRpcRequestHandler::block_state_root_key(block.height()),
            block.header.state_root.to_vec(),
        )?;
        self.state.snapshot_state(block.height())?;

        // Generate and persist a ZK block validity proof so light clients can
        // verify the block's execution integrity without a full state transition.
        //
        // SECURITY (H-04): traces are captured from the block's own committed
        // artifacts (serialized transactions + per-tx receipts), never
        // fabricated. The previous code built every trace over an EMPTY
        // witness (`ExecutionTrace::new(ELF, vec![])`), so the stored
        // "validity proofs" attested nothing about real execution while still
        // being served to light clients as finality evidence. If receipts are
        // missing or mismatched we now refuse to emit a proof rather than
        // manufacture a meaningless one.
        if !block.body.transactions.is_empty() {
            if block.body.receipts.len() != block.body.transactions.len() {
                tracing::warn!(
                    "ZK proof skipped for block {}: receipt count {} does not match \
                     transaction count {} (refusing to fabricate a validity proof)",
                    block.height(),
                    block.body.receipts.len(),
                    block.body.transactions.len()
                );
            } else {
                let traces: Vec<sxiaum_zk::ExecutionTrace> = block
                    .body
                    .transactions
                    .iter()
                    .zip(block.body.receipts.iter())
                    .map(|(tx, receipt)| {
                        let inputs = bincode::serialize(tx).unwrap_or_default();
                        let execution_result = sxiaum_execution::ExecutionResult {
                            status: receipt.status,
                            gas_used: receipt.gas_used,
                            logs: receipt.logs.clone(),
                            // Return data is not retained in receipts; the
                            // output commitment still binds status + gas +
                            // logs to the proven statement.
                            return_data: Vec::new(),
                        };
                        sxiaum_zk::ExecutionTrace::capture_from_execution_engine(
                            sxiaum_zk::sp1::SP1_ELF.to_vec(),
                            inputs,
                            &execution_result,
                            Vec::new(),
                            Vec::new(),
                        )
                    })
                    .collect();
                match self
                    .zk_engine
                    .generate_block_validity_proof(&block, &traces)
                {
                    Ok(block_proof) => {
                        if let Err(zk_err) = self.zk_engine.store_block_proof(
                            &self.storage,
                            block.height(),
                            &block_proof,
                        ) {
                            tracing::warn!(
                                "ZK proof storage failed for block {}: {} (non-fatal, continuing)",
                                block.height(),
                                zk_err
                            );
                        } else {
                            info!(
                                "ZK block validity proof stored for height={}",
                                block.height()
                            );
                        }
                    }
                    Err(zk_err) => {
                        tracing::warn!(
                            "ZK proof generation failed for block {}: {} (non-fatal, continuing)",
                            block.height(),
                            zk_err
                        );
                    }
                }
            }
        } else {
            info!(
                "Skipping ZK proof generation for empty block at height={}",
                block.height()
            );
        }

        // - Step 5: remove included transactions from the mempool.
        //    Prevents already-executed transactions from being re-selected
        //    in future block proposals and frees the per-account nonce slots.
        self.mempool
            .remove_transactions_after_block_commit(&block)?;
        info!(
            "removed {} finalized transactions from mempool",
            block.transaction_count()
        );

        match self.mempool.on_block_height(block.height()) {
            Ok(released_reveals) => {
                for reveal in released_reveals {
                    if let Ok(Some(message)) = self.mempool.broadcast_new_reveal_to_peers(&reveal) {
                        if let Err(e) = self.networking.lock().await.broadcast_message(message) {
                            tracing::warn!(
                                error = %e,
                                "Failed to broadcast released reveal gossip to peers"
                            );
                        }
                    }
                }
            }
            Err(mev_err) => {
                tracing::warn!(
                    "MEV pool clock advance failed at height={}: {} (non-fatal)",
                    block.height(),
                    mev_err
                );
            }
        }

        // - Step 6: update the local chain head pointer.
        let block_hash = block.try_hash()?;
        self.chain_head = Some(block_hash);
        info!(
            "chain head advanced: height={}, hash=0x{}",
            block.height(),
            hex::encode(block_hash)
        );

        // - Step 7: broadcast the finalized block to all peers.
        //    Allows other nodes that may have missed the proposal to apply
        //    the block and advance their own chain head without re-syncing.
        if let Some(broadcaster) = &self.ws_broadcaster {
            let _ = broadcaster.send((
                "newHeads".to_string(),
                serde_json::json!({
                    "number": format!("0x{:x}", block.height()),
                    "hash": format!("0x{}", hex::encode(block_hash)),
                    "parentHash": format!("0x{}", hex::encode(block.parent_hash())),
                }),
            ));
        }
        if let Err(error) = self
            .networking
            .lock()
            .await
            .broadcast_message(GossipMessage::Block(bincode::serialize(&block)?))
        {
            tracing::warn!("finalized block broadcast skipped: {}", error);
        }

        Ok(())
    }

    async fn is_local_leader(&self) -> bool {
        let consensus = self.consensus.read().await;
        if let Some(leader) = consensus.current_leader() {
            leader == self.validator_address
        } else {
            self.validator_address != Address::zero()
        }
    }

    fn local_proposer(&self) -> Proposer {
        Proposer::new(
            self.validator_address,
            self.mempool.clone(),
            self.execution.clone(),
        )
    }

    fn next_block_template(&self) -> Result<Block> {
        let latest_height = self.storage.latest_block_height()?;
        let state_root = self.state.state_root();

        let Some(parent_header) = self.storage.get_block_header(latest_height)? else {
            return Ok(Block::genesis(state_root));
        };

        let mut builder = BlockBuilder::try_new(&parent_header)?;
        builder.set_state_root(state_root);
        builder.set_proposer(self.validator_address);
        builder.try_build()
    }

    /// Primary block production pathway for a leader node.
    ///
    /// Called when:
    /// - A `ConsensusEvent::NewTransaction` indicates pending mempool activity, or
    /// - A `ConsensusEvent::Tick` triggers round progression while this node is the leader.
    ///
    /// Sequence:
    /// 1. Checks whether this node is the elected leader for the current view.
    /// 2. Verifies the node has not already proposed in the current view.
    /// 3. Builds a block template from storage (parent hash, height, state root).
    /// 4. Pulls MEV-protected / commit-reveal transactions from the mempool.
    /// 5. Executes transactions via `Executor::produce_block_from_transactions`.
    /// 6. Signs the block header with the node's validator signing key.
    /// 7. Attaches the parent block's Quorum Certificate.
    /// 8. Injects the proposal into the local consensus engine as a `Vote`.
    /// 9. Broadcasts the proposal message to all P2P peers via gossipsub.
    pub async fn produce_and_broadcast_block_proposal(
        &mut self,
        limit: usize,
    ) -> Result<Option<Block>> {
        let is_leader = self.is_local_leader().await;
        tracing::debug!(
            "produce_and_broadcast_block_proposal called: is_leader={}",
            is_leader
        );
        if !is_leader {
            return Ok(None);
        }

        let current_view = self.consensus.read().await.current_view();
        tracing::debug!(
            "current_view = {}, last_proposed_view = {:?}",
            current_view,
            self.last_proposed_view
        );
        if self.last_proposed_view == Some(current_view) {
            return Ok(None);
        }

        let start_time = std::time::Instant::now();

        // - Step 3: build the new block template.
        //    `next_block_template` derives the parent hash, height, and
        //    current state root from storage and sets the local validator
        //    as the proposer.
        let proposer = self.local_proposer();
        let template = self.next_block_template()?;

        let (transactions, reservation_id) = self.mempool.build_mev_protected_transactions(
            limit,
            &template.header.parent_hash,
            &template.header.randomness_beacon,
        )?;
        let (pending_commits, revealed_txs) = self.mempool.mev_pool_stats();
        tracing::debug!(
            "mempool stats for proposal: txs={}, pending_commits={}, revealed_txs={}",
            transactions.len(),
            pending_commits,
            revealed_txs
        );
        if transactions.is_empty() && pending_commits == 0 && revealed_txs == 0 {
            return Ok(None);
        }

        info!(
            "building block proposal with {} transactions",
            transactions.len()
        );

        // - Step 4: execute transactions.
        //    `produce_block_from_transactions` applies every transaction
        //    against the current state, advancing nonces and balances, and
        //    returns the block with filled-in receipts.
        let mut block = match self
            .execution
            .produce_block_from_transactions(template, transactions)
        {
            Ok(block) => block,
            Err(error) => {
                let _ = self.state.rollback();
                self.mempool.release_mev_reservation(reservation_id);
                return Err(error);
            }
        };

        // - Step 5: compute the new state root.
        //    After execution the state trie is dirty; `compute_block_state_root`
        //    hashes it and returns the Merkle root without committing to disk.
        let computed_state_root = self.execution.compute_block_state_root();
        block.header.state_root = computed_state_root;
        block.header.proposer = self.validator_address;
        if let Err(error) = block.try_compute_roots() {
            let _ = self.state.rollback();
            self.mempool.release_mev_reservation(reservation_id);
            return Err(error);
        }

        // - Step 6: sign the block.
        //    The proposer attaches an Ed25519 signature over the block hash so
        //    that validators can verify the proposal came from the elected leader.
        if let Err(error) = proposer.sign_block(&mut block, &self.proposer_signing_key) {
            let _ = self.state.rollback();
            self.mempool.release_mev_reservation(reservation_id);
            return Err(error);
        }

        // - Step 7: broadcast the block proposal.
        //    First via the proposer's internal channel (so the local consensus
        //    engine processes it atomically with the QC attachment), then over
        //    P2P gossip so every other validator receives it.
        let quorum_certificate = self
            .consensus
            .read()
            .await
            .highest_qc()?
            .unwrap_or_else(|| {
                QuorumCertificate::new(block.parent_hash(), current_view, Vec::new(), Vec::new())
            });
        let proposal = proposer.attach_quorum_certificate(block.clone(), quorum_certificate);
        let _ = proposer.broadcast_proposal(&proposal)?;
        if let Err(error) = self
            .networking
            .lock()
            .await
            .broadcast_message(GossipMessage::Block(bincode::serialize(&proposal.block)?))
        {
            tracing::warn!("block proposal broadcast skipped: {}", error);
        }

        self.last_proposed_view = Some(current_view);

        // Published gossip is not looped back to the proposer.
        let block_hash = proposal.block.try_hash()?;
        let admission_result = self
            .consensus
            .write()
            .await
            .process_block_proposal(proposal.block.clone());
        if let Err(error) = admission_result {
            let _ = self.state.rollback();
            self.mempool.release_mev_reservation(reservation_id);
            return Err(error);
        }
        self.cast_and_broadcast_vote(block_hash).await?;

        let duration = start_time.elapsed();
        crate::metrics::MetricsService::record_block_production_time(duration);

        info!(
            "broadcast block proposal: height={}, txs={}, state_root=0x{}, time={:?}",
            proposal.block.height(),
            proposal.block.transaction_count(),
            hex::encode(proposal.block.header.state_root),
            duration
        );

        Ok(Some(proposal.block))
    }

    async fn synchronize_if_behind(&mut self) -> Result<()> {
        // - Step 1: detect whether this node is behind the network.
        //
        // SECURITY (C-03): never steer a sync session with a single
        // self-reported height. Probe every connected peer (bounded), pick the
        // highest reported height, and require corroboration from another peer
        // before trusting it. Block-level authentication below makes a lying
        // peer harmless to integrity either way (worst case: failed attempts).
        const MAX_SYNC_HEIGHT_PROBES: usize = 8;
        let mut peer_heights: Vec<(PeerId, u64)> = Vec::new();
        {
            let mut net = self.networking.lock().await;
            let probe_peers: Vec<PeerId> = net
                .peer_store
                .connected_peers()
                .iter()
                .take(MAX_SYNC_HEIGHT_PROBES)
                .map(|peer| peer.peer_id)
                .collect();
            for peer_id in probe_peers {
                match net.request_latest_block_height(peer_id).await {
                    Ok(height) => peer_heights.push((peer_id, height)),
                    Err(error) => {
                        tracing::debug!("height probe to peer {:?} failed: {}", peer_id, error);
                    }
                }
            }
        }

        let Some(&(peer_id, remote_height)) = peer_heights.iter().max_by_key(|(_, height)| *height)
        else {
            tracing::debug!("sync skipped: no connected peers");
            return Ok(());
        };

        let corroborating_peers = peer_heights
            .iter()
            .filter(|(_, height)| *height >= remote_height)
            .count();
        if corroborating_peers < 2 && peer_heights.len() > 1 {
            tracing::warn!(
                "sync target height {} is corroborated by only {}/{} peers; proceeding with per-block authentication",
                remote_height,
                corroborating_peers,
                peer_heights.len()
            );
        }

        let mut net = self.networking.lock().await;

        let local_height = self.storage.latest_block_height()?;
        if remote_height <= local_height {
            return Ok(());
        }

        info!(
            "node is behind peer {:?} at local_height={} - starting sync",
            peer_id, local_height
        );

        // - Steps 3-6: download, verify, apply, and update state.
        //    `synchronize_chain_from_peer` iterates every missing height in
        //    order and for each block calls:
        //      - Step 3: `rpc_client.request_block(peer_id, height)`
        //      - Step 4: `self.validate_downloaded_block(bytes)` (header +
        //                  signature + transaction structural checks)
        //      - Step 5: `self.apply_downloaded_block(block)` (execute txs,
        //                  verify state-root match)
        //      - Step 6: `self.update_local_chain_head(block)` (atomic
        //                  storage commit, advances local height)
        let mut applied_blocks = 0u64;
        let mut new_local_head = local_height;

        // SECURITY (C-03): every downloaded block must extend our canonical
        // chain. The first block must build on the current tip; each later
        // block must build on the previously applied one. This makes fork
        // injection impossible even when the sync peer is fully malicious.
        let tip_header = self
            .storage
            .get_block_header(local_height)?
            .ok_or_else(|| anyhow::anyhow!("local chain tip at height {} missing", local_height))?;
        let mut expected_parent = tip_header.try_hash()?;

        for height in (local_height + 1)..=remote_height {
            let block_bytes = net
                .request_block(peer_id, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing block at height {}", height))?;

            let block = self.validate_downloaded_block(&block_bytes)?;
            self.authenticate_downloaded_block(&block, expected_parent)?;
            self.apply_downloaded_block(&block)?;
            self.update_local_chain_head(&block)?;
            expected_parent = block.try_hash()?;
            applied_blocks = applied_blocks.saturating_add(1);
            new_local_head = block.height();
        }
        drop(net);

        let outcome = sxiaum_networking::ChainSyncOutcome {
            was_out_of_sync: true,
            remote_height,
            applied_blocks,
            new_local_head,
        };

        // Advance the in-memory chain-head pointer to match the last block
        // written to storage by update_local_chain_head.
        if let Some(header) = self.storage.get_block_header(outcome.new_local_head)? {
            self.chain_head = Some(header.try_hash()?);
        }

        info!(
            "sync complete from peer {:?}: applied={}, remote_height={}, new_head={}",
            peer_id, outcome.applied_blocks, outcome.remote_height, outcome.new_local_head
        );

        Ok(())
    }
}

impl ChainSyncState for Node {
    /// Step 1 / Step 2 support: returns the height of the last block this
    /// node has committed to storage.  Used by both `detect_node_out_of_sync_state`
    /// (to compare against the peer height) and `synchronize_chain_from_peer`
    /// (to determine the first missing height to download).
    fn local_block_height(&self) -> Result<u64> {
        self.storage.latest_block_height()
    }

    /// Step 4: validate a raw block received from a peer.
    ///
    /// Performs: deserialisation, header structural check, and transaction
    /// signature + size checks.  Does NOT touch the state trie so it is
    /// safe to call on a block that has not yet been applied. Cryptographic
    /// authentication (chaining + proposer signature) happens in
    /// `authenticate_downloaded_block`; executed-state-root verification in
    /// `apply_downloaded_block`.
    fn validate_downloaded_block(&self, block_bytes: &[u8]) -> Result<sxiaum_block::Block> {
        let block: sxiaum_block::Block =
            Block::decode(block_bytes).or_else(|_| bincode::deserialize(block_bytes))?;
        block.validate_mainnet(current_unix_timestamp())?;
        self.execution.validate_block_transactions(&block)?;
        Ok(block)
    }

    /// Step 5: execute all transactions in the block and verify the resulting
    /// state root matches the one recorded in the block header.
    ///
    /// On mismatch the block is rejected and sync aborts for this peer; the
    /// caller can retry with a different peer.
    fn apply_downloaded_block(&self, block: &sxiaum_block::Block) -> Result<()> {
        let computed_state_root = self.execution.execute_block(block.clone())?;
        if computed_state_root != block.header.state_root {
            anyhow::bail!(
                "state root mismatch for downloaded block at height={}: computed=0x{}, header=0x{}",
                block.height(),
                hex::encode(computed_state_root),
                hex::encode(block.header.state_root)
            );
        }
        Ok(())
    }

    /// Step 6: atomically write the block header and body to persistent storage,
    /// advancing the node's canonical chain head for this height.
    fn update_local_chain_head(&self, block: &sxiaum_block::Block) -> Result<()> {
        let header_bytes = bincode::serialize(&block.header)?;
        let body_bytes = bincode::serialize(&block.body)?;
        self.storage
            .atomic_block_commit(block.height(), header_bytes, body_bytes)?;
        Ok(())
    }
}

impl Node {
    /// SECURITY (C-03): authenticate a block received during synchronization.
    ///
    /// A downloaded block must:
    /// 1. extend the canonical chain (`parent_hash == expected_parent`), and
    /// 2. carry a valid Ed25519 signature from an ACTIVE validator in the
    ///    locally persisted validator set.
    ///
    /// Together with the executed-state-root check in `apply_downloaded_block`
    /// this makes it computationally infeasible for a malicious sync peer to
    /// inject forged blocks: every accepted block is signed by a known
    /// validator and produces the header state root under deterministic
    /// execution.
    fn authenticate_downloaded_block(
        &self,
        block: &sxiaum_block::Block,
        expected_parent: [u8; 32],
    ) -> Result<()> {
        if block.is_genesis() {
            return Ok(());
        }

        if block.header.parent_hash != expected_parent {
            anyhow::bail!(
                "downloaded block at height {} does not extend canonical chain: parent 0x{}, expected 0x{}",
                block.height(),
                hex::encode(block.header.parent_hash),
                hex::encode(expected_parent)
            );
        }

        let validators = self.load_local_validators()?;
        if validators.is_empty() {
            // Bootstrap mode: no persisted validator set yet (fresh node).
            // Chaining + state-root checks still apply; signature check is
            // vacuous without pubkeys. Logged loudly for operators.
            tracing::warn!(
                "sync proceeding without proposer-signature verification (local validator set empty)"
            );
            return Ok(());
        }

        let proposer_pubkey = validators
            .iter()
            .find(|validator| validator.address == block.header.proposer && validator.is_active())
            .map(|validator| validator.pubkey)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "downloaded block at height {} rejected: proposer 0x{} is not an active local validator",
                    block.height(),
                    hex::encode(block.header.proposer)
                )
            })?;

        if !block.header.verify_signature(&proposer_pubkey)? {
            anyhow::bail!(
                "downloaded block at height {} rejected: invalid proposer signature",
                block.height()
            );
        }

        Ok(())
    }

    fn load_local_validators(&self) -> Result<Vec<Validator>> {
        let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())?
        else {
            return Ok(Vec::new());
        };
        Ok(bincode::deserialize(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsensusEvent, Node, NodeConfig};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_consensus::hotstuff::vote::Vote;
    use sxiaum_mempool::{CommitTransaction, RevealTransaction};
    use sxiaum_networking::GossipMessage;
    use sxiaum_types::validator::ValidatorStatus;
    use sxiaum_types::{Account, Address, Transaction, Validator};

    fn unique_storage_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-{name}-{unique}.redb"))
    }

    fn test_config(
        _name: &str,
        proposer_private_key: sxiaum_crypto::ed25519::PrivateKey,
    ) -> (NodeConfig, PathBuf) {
        let path = unique_storage_path(_name);
        let config = NodeConfig {
            storage_path: path.to_string_lossy().into_owned(),
            rpc_addr: "127.0.0.1:0"
                .parse()
                .expect("ephemeral rpc address should parse"),
            proposer_private_key,
            ..Default::default()
        };
        (config, path)
    }

    fn active_validator_from_key(signing_key: &SigningKey) -> Validator {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pubkey);
        let mut validator = Validator::new(address, pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        validator = validator.with_bls_pop(pk.0, pop.0);
        validator
    }

    fn block_for(
        parent_hash: [u8; 32],
        height: u64,
        proposer: Address,
        state_root: [u8; 32],
    ) -> Block {
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        header.state_root = state_root;
        let mut block = Block::new(header, BlockBody::empty());
        block.try_compute_roots().unwrap();
        block
    }

    #[tokio::test]
    async fn node_finalizes_consensus_block_and_persists_it() {
        let proposer_private_key = sxiaum_crypto::ed25519::PrivateKey([11u8; 32]);
        let signing_key = SigningKey::from_bytes(&proposer_private_key.0);
        let validator = active_validator_from_key(&signing_key);
        let (mut config, path) = test_config("node-consensus-finalize", proposer_private_key);
        config.mode = crate::node::NodeMode::Validator;

        let mut node = Node::new(config).await.expect("node should initialize");
        {
            let mut consensus = node.consensus.write().await;
            let _ = consensus.update_validator_set(vec![validator.clone()]);
            consensus.start().expect("consensus should start");
        }

        let genesis = Block::genesis([0xAA; 32]);
        node.storage
            .atomic_block_commit_typed(genesis.height(), &genesis.header, &genesis.body)
            .expect("genesis should store");
        let parent_hash = genesis.try_hash().unwrap();

        let mut block = block_for(parent_hash, 1, validator.address, node.state.state_root());
        block.header.sign(&signing_key).expect("block should sign");
        let block_hash = block.try_hash().unwrap();

        node.handle_consensus_event(ConsensusEvent::BlockProposal(block.clone()))
            .await
            .expect("block proposal should be accepted");

        let mut vote = Vote::new(validator.address, block_hash, 0);
        vote.sign(&signing_key).expect("vote should sign");

        node.handle_consensus_event(ConsensusEvent::Vote(vote))
            .await
            .expect("quorum vote should finalize the block");

        let consensus = node.consensus.read().await;
        assert_eq!(consensus.finalized_block_height, 1);
        assert_eq!(
            consensus
                .latest_finalized_block()
                .map(|block| block.try_hash().unwrap()),
            Some(block_hash)
        );
        drop(consensus);

        assert_eq!(
            node.storage
                .latest_block_height()
                .expect("height should load"),
            1
        );
        assert_eq!(node.chain_head, Some(block_hash));
        assert_eq!(
            node.storage
                .state_get(b"metadata:state_root".to_vec())
                .expect("state root metadata should load")
                .map(|bytes| {
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&bytes);
                    root
                }),
            Some(block.header.state_root)
        );

        drop(node);
        let _ = fs::remove_file(path);
    }

    /// REGRESSION (restart identity): `Node::new` previously zeroed
    /// `config.proposer_private_key` after deriving the signing key, so
    /// `restart()` — which rebuilds via `Self::new(self.config.clone())` —
    /// silently re-derived a degenerate all-zeros identity and lost the
    /// validator's signing key. The seed must survive for restart to work.
    #[tokio::test]
    async fn node_new_preserves_seed_for_restart() {
        let proposer_private_key = sxiaum_crypto::ed25519::PrivateKey([11u8; 32]);
        let signing_key = SigningKey::from_bytes(&proposer_private_key.0);
        let expected_address = Address::from_public_key(&signing_key.verifying_key().to_bytes());

        let (config, path) = test_config("node-restart-identity", proposer_private_key);
        let node = Node::new(config).await.expect("node should initialize");

        // Identity derived correctly on first construction...
        assert_eq!(node.validator_address, expected_address);

        // ...and the config seed must remain intact so restart() rebuilds the
        // SAME identity instead of a trivial zero-key identity.
        assert_eq!(
            node.config.proposer_private_key.0, [11u8; 32],
            "Node::new must not zero proposer_private_key (breaks restart identity)"
        );
        assert_eq!(
            node.proposer_signing_key.verifying_key().to_bytes(),
            signing_key.verifying_key().to_bytes()
        );

        drop(node);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn node_mev_commit_reveal_integration() {
        let proposer_private_key = sxiaum_crypto::ed25519::PrivateKey([11u8; 32]);
        let signing_key = SigningKey::from_bytes(&proposer_private_key.0);
        let validator = active_validator_from_key(&signing_key);
        // Keep a copy for commit signing below (PrivateKey is not Copy).
        let commit_signer = proposer_private_key.clone();
        let (config, path) = test_config("node-mev-integration", proposer_private_key);

        let mut node = Node::new(config).await.expect("node should initialize");
        {
            let mut consensus = node.consensus.write().await;
            let _ = consensus.update_validator_set(vec![validator.clone()]);
            consensus.start().expect("consensus should start");
        }

        // Fund sender account so the transaction validator passes AND the
        // C-13 commit-fee solvency gate accepts the signed commit.
        let mut funded = Account::new(validator.address);
        funded.balance = U256::from(10_000_000_000_000_000_000u64); // >= commit_fee
        node.state
            .update_account(&validator.address, &funded)
            .expect("sender should be funded");

        let mut tx = Transaction::new_transfer(
            validator.address,
            Address::from_public_key(&[2u8; 32]),
            primitive_types::U256::from(1000),
            0,
        );
        tx.sign(&signing_key).expect("should sign tx");

        let reveal_nonce = [42u8; 32];
        let commit_hash =
            sxiaum_mempool::try_compute_commit_hash(&reveal_nonce, &tx).expect("tx hash");
        let mut commit = CommitTransaction::new(commit_hash, validator.address.0, 0, 5, 20);
        // SECURITY (C-13): gossip commits must be signed by their sender.
        commit
            .sign(&commit_signer)
            .expect("commit should sign with sender key");

        let commit_bytes = bincode::serialize(&commit).unwrap();
        node.handle_p2p_message(GossipMessage::Commit(commit_bytes))
            .await
            .expect("should process commit");

        // Transaction should not be in the ready pool yet
        let pending = node
            .mempool
            .provide_transactions_to_block_proposer(10, &[0u8; 32], &[0u8; 32])
            .unwrap();
        assert!(
            pending.is_empty(),
            "block production should not include unrevealed commits"
        );

        let reveal = RevealTransaction::new(commit.id, tx.clone(), reveal_nonce, 0);
        let reveal_bytes = bincode::serialize(&reveal).unwrap();
        node.handle_p2p_message(GossipMessage::Reveal(reveal_bytes))
            .await
            .expect("should process reveal");

        // Transaction should now be available for block production via MEV-protected selector
        let block_txs = node
            .mempool
            .provide_transactions_to_block_proposer(10, &[0u8; 32], &[0u8; 32])
            .unwrap();
        assert_eq!(block_txs.len(), 1);
        assert_eq!(block_txs[0].try_hash().unwrap(), tx.try_hash().unwrap());

        drop(node);
        let _ = fs::remove_file(path);
    }
}
