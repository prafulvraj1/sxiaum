use crate::gossip::{
    BlockConsensusSink, BlockGossipOutcome, BlockParentLookup, BlockPoolSink, BlockProofVerifier,
    BlockSignatureVerifier, CommitGossipOutcome, CommitPoolSink, Gossip, GossipMessage,
    QuorumCertificateBroadcaster, QuorumCertificateConsensusSink, QuorumCertificateGossipOutcome,
    QuorumCertificateVerifier, RevealGossipOutcome, RevealPoolSink, TransactionGossipOutcome,
    TransactionPoolSink, TransactionSignatureVerifier, VoteConsensusSink, VoteGossipOutcome,
    VoteSignatureVerifier, TOPIC_BLOCKS, TOPIC_COMMITS, TOPIC_QUORUM_CERTIFICATES, TOPIC_REVEALS,
    TOPIC_STATE_SYNC, TOPIC_TRANSACTIONS, TOPIC_VOTES,
};
use crate::metrics::NetworkingMetrics;
use crate::peer::{Peer, PeerStore};
use crate::rpc::{
    L1Codec, L1Request, L1Response, RpcStateProofRequest, RpcStateProofResponse,
    RpcVerifiedHeaderEnvelope,
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{
    gossipsub, identify, kad, mdns, noise, request_response, swarm::behaviour::toggle::Toggle,
    swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, Multiaddr, PeerId, Swarm,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sxiaum_block::Block;
use tokio::time::{sleep, timeout};
use tracing::info;

const DEFAULT_MAX_HEADER_BATCH: u64 = crate::MAX_HEADER_BATCH_SIZE;

/// Production-mode detection matching the canonical predicate used across the
/// stack (see `sxiaum_keystore::password::is_production`): `SXIAUM_ENV` or
/// `SXIAUM_SRS_MODE` set to `production`, case-insensitive.
fn is_production_mode() -> bool {
    std::env::var("SXIAUM_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
        || std::env::var("SXIAUM_SRS_MODE")
            .map(|v| v.eq_ignore_ascii_case("production"))
            .unwrap_or(false)
}
const DEFAULT_MAX_HEADER_REQUESTS_PER_WINDOW: usize = crate::MAX_HEADER_REQUESTS_PER_WINDOW;
const DEFAULT_HEADER_REQUEST_WINDOW_SECS: u64 = crate::HEADER_REQUEST_WINDOW_SECS;
const DEFAULT_MAX_STATE_PROOF_REQUESTS_PER_WINDOW: usize =
    crate::MAX_STATE_PROOF_REQUESTS_PER_WINDOW;
const DEFAULT_STATE_PROOF_REQUEST_WINDOW_SECS: u64 = crate::STATE_PROOF_REQUEST_WINDOW_SECS;
const RPC_RESPONSE_POLL_SLICE_MS: u64 = crate::RPC_RESPONSE_POLL_SLICE_MS;

// SECURITY (H-02): explicit gossipsub limits. The transmit ceiling is the
// 2 MiB canonical message cap plus headroom for gossipsub signature and
// protobuf framing so legitimate max-size messages are never rejected.
const MAX_GOSSIP_TRANSMIT_SIZE: usize = sxiaum_types::MAX_CANONICAL_MESSAGE_SIZE + 1024 * 1024;
const DUPLICATE_CACHE_SECS: u64 = 120;
const GOSSIP_HEARTBEAT_MS: u64 = 700;
const HISTORY_LENGTH: usize = 12;
const HISTORY_GOSSIP: usize = 6;
const MESH_OUTBOUND_MIN: usize = 2;
const MESH_N_LOW: usize = 6;
const MESH_N: usize = 8;
const MESH_N_HIGH: usize = 12;

pub trait ChainSyncState {
    fn local_block_height(&self) -> Result<u64>;
    fn validate_downloaded_block(&self, block_bytes: &[u8]) -> Result<Block>;
    fn apply_downloaded_block(&self, block: &Block) -> Result<()>;
    fn update_local_chain_head(&self, block: &Block) -> Result<()>;
}

#[async_trait]
pub trait RpcSyncClient {
    async fn request_latest_block_height(&mut self, peer_id: PeerId) -> Result<u64>;
    async fn request_block(&mut self, peer_id: PeerId, height: u64) -> Result<Option<Vec<u8>>>;
    async fn request_headers(
        &mut self,
        peer_id: PeerId,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<RpcVerifiedHeaderEnvelope>>>;
    async fn request_state_proof(
        &mut self,
        peer_id: PeerId,
        request: RpcStateProofRequest,
    ) -> Result<Option<RpcStateProofResponse>>;
    async fn request_block_proof(
        &mut self,
        peer_id: PeerId,
        height: u64,
    ) -> Result<Option<Vec<u8>>>;
}

pub trait RpcRequestHandler: Send + Sync {
    fn handle_request(&self, peer_id: PeerId, request: L1Request) -> Result<L1Response>;
}

#[derive(Clone, Debug)]
pub struct ChainSyncOutcome {
    pub was_out_of_sync: bool,
    pub remote_height: u64,
    pub applied_blocks: u64,
    pub new_local_head: u64,
}

#[derive(Clone, Debug)]
pub struct P2PConfig {
    pub local_key: libp2p::identity::Keypair,
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    pub discovery_interval: Duration,
    pub discovery_backoff: Duration,
    pub max_peers: usize,
    pub max_header_batch: u64,
    pub max_header_requests_per_peer_per_window: usize,
    pub header_request_window_secs: u64,
    pub max_state_proof_requests_per_peer_per_window: usize,
    pub state_proof_request_window_secs: u64,
    pub db: Option<std::sync::Arc<redb::Database>>,
}

#[derive(NetworkBehaviour)]
pub struct L1Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub request_response: request_response::Behaviour<L1Codec>,
}

pub struct P2PNetwork {
    pub swarm: Swarm<L1Behaviour>,
    pub peer_store: PeerStore,
    pub consensus_message_queue: VecDeque<(PeerId, GossipMessage)>,
    pub standard_message_queue: VecDeque<(PeerId, GossipMessage)>,
    gossip: Gossip,
    discovery_interval: Duration,
    discovery_backoff: Duration,
    next_discovery_at: Instant,
    discovery_failures: HashMap<PeerId, u32>,
    max_peers: usize,
    rpc_handler: Option<Arc<dyn RpcRequestHandler>>,
    /// SECURITY (C-14): test-only loopback responder. Compiled in exclusively
    /// under the `test-loopback-rpc` feature so production binaries cannot
    /// answer their own outbound RPC requests. See `await_rpc_response`.
    #[cfg(feature = "test-loopback-rpc")]
    test_loopback_responder: Option<Arc<dyn RpcRequestHandler>>,
    /// Outbound request payloads keyed by request id, used only by the
    /// test-only loopback responder (see above).
    #[cfg(feature = "test-loopback-rpc")]
    loopback_requests: HashMap<request_response::OutboundRequestId, L1Request>,
    max_header_batch: u64,
    max_header_requests_per_peer_per_window: usize,
    header_request_window_secs: u64,
    pub header_request_windows: HashMap<PeerId, (u64, usize)>,
    max_state_proof_requests_per_peer_per_window: usize,
    state_proof_request_window_secs: u64,
    pub state_proof_request_windows: HashMap<PeerId, (u64, usize)>,
    pub block_request_windows: HashMap<PeerId, (u64, usize)>,
    pub tx_request_windows: HashMap<PeerId, (u64, usize)>,
    consensus_burst_count: usize,
    pub pending_rpc_responses: HashMap<request_response::OutboundRequestId, (Instant, L1Response)>,
    bloom_filter: MessageBloomFilter,
}

/// SECURITY: hard per-round cap on blocks pulled from a single peer. The
/// remote height in a sync round is a single-peer claim; without a cap a
/// malicious peer advertising `u64::MAX` could keep this loop issuing
/// sequential RPC requests indefinitely (each subject to the 10s timeout),
/// stalling the node's sync task. Larger gaps are handled by repeated rounds,
/// each of which re-evaluates peer health.
const MAX_SYNC_BLOCKS_PER_ROUND: u64 = 10_000;

impl P2PNetwork {
    pub async fn new(config: P2PConfig) -> Result<Self> {
        let local_peer_id = PeerId::from(config.local_key.public());
        info!("Local peer id: {:?}", local_peer_id);

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(config.local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| {
                // TICKET-11: Disable mDNS discovery on mainnet/production to prevent
                // leaking local topologies and unnecessary broadcast traffic.
                let is_production = is_production_mode();
                let mdns_behaviour = if is_production {
                    info!("mDNS discovery disabled for production environment");
                    Toggle::from(None)
                } else {
                    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
                    Toggle::from(Some(mdns))
                };

                // SECURITY (H-02): hardened gossipsub configuration. The
                // previous build used `Config::default()`, which ships no
                // explicit transmit ceiling, no strict validation mode, and
                // no peer scoring, so all spam defense was ad-hoc downstream.
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    // 2 MiB canonical message ceiling + signature/protobuf
                    // framing headroom; anything larger is rejected at the
                    // gossipsub layer before it reaches application code.
                    .max_transmit_size(MAX_GOSSIP_TRANSMIT_SIZE)
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .duplicate_cache_time(Duration::from_secs(DUPLICATE_CACHE_SECS))
                    .heartbeat_interval(Duration::from_millis(GOSSIP_HEARTBEAT_MS))
                    .history_length(HISTORY_LENGTH)
                    .history_gossip(HISTORY_GOSSIP)
                    .mesh_outbound_min(MESH_OUTBOUND_MIN)
                    .mesh_n_low(MESH_N_LOW)
                    .mesh_n(MESH_N)
                    .mesh_n_high(MESH_N_HIGH)
                    .build()
                    .map_err(|e| anyhow::anyhow!("invalid gossipsub config: {}", e))?;

                let mut gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("valid gossipsub config");

                // SECURITY (H-02): enable gossipsub peer scoring so
                // misbehaving peers (invalid messages, graft/prune abuse,
                // colocation) accumulate negative scores and are pruned from
                // the mesh instead of being treated as honest forever.
                let peer_score_params = gossipsub::PeerScoreParams {
                    app_specific_weight: 1.0,
                    ip_colocation_factor_weight: -5.0,
                    ip_colocation_factor_threshold: crate::MAX_PEERS_PER_SUBNET as f64,
                    behaviour_penalty_weight: -10.0,
                    behaviour_penalty_threshold: 0.0,
                    behaviour_penalty_decay: 0.9,
                    decay_interval: Duration::from_secs(60),
                    decay_to_zero: 0.01,
                    retain_score: Duration::from_secs(3600),
                    ..Default::default()
                };
                let peer_score_thresholds = gossipsub::PeerScoreThresholds {
                    // Invariant: graylist <= publish <= gossip <= 0 and
                    // accept_px >= 0 (gossipsub validation rules).
                    gossip_threshold: -5.0,
                    publish_threshold: -10.0,
                    graylist_threshold: -20.0,
                    accept_px_threshold: 0.0,
                    opportunistic_graft_threshold: 0.0,
                };
                gossipsub
                    .with_peer_score(peer_score_params, peer_score_thresholds)
                    .map_err(|e| anyhow::anyhow!("failed to enable peer scoring: {}", e))?;

                Ok(L1Behaviour {
                    gossipsub,
                    mdns: mdns_behaviour,
                    identify: identify::Behaviour::new(identify::Config::new(
                        "sxiaum/0.1.0".to_string(),
                        key.public(),
                    )),
                    kademlia: kad::Behaviour::new(
                        local_peer_id,
                        kad::store::MemoryStore::new(local_peer_id),
                    ),
                    request_response: request_response::Behaviour::<L1Codec>::new(
                        std::iter::once((
                            libp2p::StreamProtocol::new("/l1/rpc/1.0.0"),
                            request_response::ProtocolSupport::Full,
                        )),
                        request_response::Config::default(),
                    ),
                })
            })?
            .build();

        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_BLOCKS))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_TRANSACTIONS))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_VOTES))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_QUORUM_CERTIFICATES))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_STATE_SYNC))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_COMMITS))?;
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&gossipsub::IdentTopic::new(TOPIC_REVEALS))?;

        let mut network = Self {
            swarm,
            peer_store: PeerStore::new(config.db.clone()),
            consensus_message_queue: VecDeque::new(),
            standard_message_queue: VecDeque::new(),
            gossip: {
                let mut gossip = Gossip::new();
                gossip.subscribe(TOPIC_BLOCKS);
                gossip.subscribe(TOPIC_TRANSACTIONS);
                gossip.subscribe(TOPIC_VOTES);
                gossip.subscribe(TOPIC_QUORUM_CERTIFICATES);
                gossip.subscribe(TOPIC_STATE_SYNC);
                gossip.subscribe(TOPIC_COMMITS);
                gossip.subscribe(TOPIC_REVEALS);
                gossip
            },
            discovery_interval: config.discovery_interval,
            discovery_backoff: config.discovery_backoff,
            next_discovery_at: Instant::now() + config.discovery_interval,
            discovery_failures: HashMap::new(),
            max_peers: config.max_peers,
            rpc_handler: None,
            max_header_batch: DEFAULT_MAX_HEADER_BATCH,
            max_header_requests_per_peer_per_window: DEFAULT_MAX_HEADER_REQUESTS_PER_WINDOW,
            header_request_window_secs: DEFAULT_HEADER_REQUEST_WINDOW_SECS,
            header_request_windows: HashMap::new(),
            max_state_proof_requests_per_peer_per_window:
                DEFAULT_MAX_STATE_PROOF_REQUESTS_PER_WINDOW,
            state_proof_request_window_secs: DEFAULT_STATE_PROOF_REQUEST_WINDOW_SECS,
            state_proof_request_windows: HashMap::new(),
            block_request_windows: HashMap::new(),
            tx_request_windows: HashMap::new(),
            consensus_burst_count: 0,
            pending_rpc_responses: HashMap::new(),
            #[cfg(feature = "test-loopback-rpc")]
            test_loopback_responder: None,
            #[cfg(feature = "test-loopback-rpc")]
            loopback_requests: HashMap::new(),
            bloom_filter: MessageBloomFilter::new(
                crate::BLOOM_FILTER_CAPACITY,
                crate::BLOOM_FILTER_HASH_FUNCTIONS,
            ),
        };

        network.load_bootstrap_peer_list(config.bootstrap_peers)?;
        Ok(network)
    }

    pub async fn start(&mut self) -> Result<()> {
        self.run_periodic_peer_discovery()?;
        self.handle_incoming_connections().await
    }

    pub async fn poll_once(&mut self, wait_for: Duration) -> Result<()> {
        self.run_periodic_peer_discovery()?;

        let event = timeout(wait_for, self.swarm.next()).await;
        let Ok(maybe_event) = event else {
            return Ok(());
        };

        if let Some(event) = maybe_event {
            self.handle_swarm_event(event).await?;
        }

        Ok(())
    }

    pub fn set_rpc_handler(&mut self, handler: Arc<dyn RpcRequestHandler>) {
        self.rpc_handler = Some(handler);
    }

    /// SECURITY (C-14): test-only loopback RPC responder.
    ///
    /// Answers outbound RPC requests from a local handler instead of a real
    /// wire peer. Only available under the `test-loopback-rpc` feature so
    /// production binaries are physically incapable of fabricating peer
    /// responses (the implicit self-answering bug fixed by C-14). Never call
    /// this from non-test code.
    #[cfg(feature = "test-loopback-rpc")]
    pub fn set_test_loopback_rpc_responder(&mut self, handler: Arc<dyn RpcRequestHandler>) {
        self.test_loopback_responder = Some(handler);
    }

    pub fn listen_on(&mut self, address: Multiaddr) -> Result<()> {
        self.swarm.listen_on(address)?;
        Ok(())
    }

    pub fn dial_peer(&mut self, peer_id: PeerId, address: Multiaddr) -> Result<()> {
        if self.peer_count() >= self.max_peers {
            bail!(
                "cannot dial peer {:?}: max peers limit ({}) reached",
                peer_id,
                self.max_peers
            );
        }
        if let Some(peer) = self.peer_store.get_peer(&peer_id) {
            if peer.is_banned() {
                bail!("cannot dial banned peer {:?}", peer_id);
            }
        }
        if !self
            .peer_store
            .check_ip_prefix_limit(&address, crate::MAX_PEERS_PER_SUBNET)
        {
            bail!(
                "cannot dial peer {:?}: IP prefix limit exceeded for {:?}",
                peer_id,
                address
            );
        }
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, address.clone());
        self.swarm.dial(address.clone())?;
        self.peer_store.add_peer(Peer::new(peer_id, address));
        NetworkingMetrics::record_connection("outbound");
        NetworkingMetrics::update_peer_count(self.peer_count());
        self.advertise_peer_address(peer_id)?;
        self.evict_peers();
        Ok(())
    }

    pub async fn handle_incoming_connections(&mut self) -> Result<()> {
        while let Some(event) = self.swarm.next().await {
            self.handle_swarm_event(event).await?;
        }

        Ok(())
    }

    pub async fn handle_outgoing_connections(&mut self) -> Result<()> {
        while let Some((_source, message)) = self.receive_message() {
            self.broadcast_message(message)?;
        }
        Ok(())
    }

    pub fn disconnect_peer(&mut self, peer_id: PeerId) -> Result<()> {
        if self.peer_store.remove_peer(&peer_id).is_none() {
            bail!("peer {:?} not found", peer_id);
        }
        let _ = self.swarm.disconnect_peer_id(peer_id);
        NetworkingMetrics::record_disconnection("manual");
        NetworkingMetrics::update_peer_count(self.peer_count());
        Ok(())
    }

    pub fn peer_count(&self) -> usize {
        self.peer_store.connected_peers().len()
    }

    pub fn broadcast_message(&mut self, message: GossipMessage) -> Result<()> {
        let topic_name = match &message {
            GossipMessage::Block(_) => TOPIC_BLOCKS,
            GossipMessage::Transaction(_) => TOPIC_TRANSACTIONS,
            GossipMessage::Commit(_) => TOPIC_COMMITS,
            GossipMessage::Reveal(_) => TOPIC_REVEALS,
            GossipMessage::Vote(_) => TOPIC_VOTES,
            GossipMessage::QuorumCertificate(_) => TOPIC_QUORUM_CERTIFICATES,
            GossipMessage::StateSync(_) => TOPIC_STATE_SYNC,
        };
        let topic = message.topic();
        let data = message.try_encode()?;
        NetworkingMetrics::record_messages("outbound", topic_name, 1);
        NetworkingMetrics::record_messages_per_second("outbound", topic_name, 1.0);
        NetworkingMetrics::record_bandwidth("outbound", data.len() as u64);
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;
        Ok(())
    }

    pub fn send_message(&mut self, peer_id: PeerId, message: L1Request) -> Result<()> {
        let _ = self.send_rpc_request(peer_id, message)?;
        Ok(())
    }

    fn send_rpc_request(
        &mut self,
        peer_id: PeerId,
        message: L1Request,
    ) -> Result<request_response::OutboundRequestId> {
        let Some(peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found", peer_id);
        };
        if peer.is_banned() {
            bail!("peer {:?} is banned", peer_id);
        }

        if let Ok(bytes) = message.encode() {
            NetworkingMetrics::record_messages("outbound", TOPIC_STATE_SYNC, 1);
            NetworkingMetrics::record_bandwidth("outbound", bytes.len() as u64);
        }

        // SECURITY (C-14): test-only loopback bookkeeping (feature-gated).
        // The request payload is cloned only when the loopback responder needs
        // it; production builds move it straight into the wire send.
        #[cfg(feature = "test-loopback-rpc")]
        let request_id = {
            const MAX_LOOPBACK_REQUESTS: usize = 256;
            if self.loopback_requests.len() >= MAX_LOOPBACK_REQUESTS {
                if let Some(first) = self.loopback_requests.keys().next().copied() {
                    self.loopback_requests.remove(&first);
                }
            }
            let id = self
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, message.clone());
            self.loopback_requests.insert(id, message);
            id
        };

        #[cfg(not(feature = "test-loopback-rpc"))]
        let request_id = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, message);

        // SECURITY (C-14): never answer our own outbound RPC requests from the
        // local handler. Previously the outgoing request was fed to
        // `rpc_handler.handle_request` and its result was pre-inserted into
        // `pending_rpc_responses`, so `await_rpc_response` returned a locally
        // fabricated response as if a remote peer had vouched for it. That let
        // this node "corroborate" chain/state data against itself, defeating
        // peer-based validation (e.g. C-03 height corroboration) and masking
        // dead/unresponsive peers. Responses must only come from the wire
        // (`request_response::Message::Response`).

        Ok(request_id)
    }

    pub fn receive_message(&mut self) -> Option<(PeerId, GossipMessage)> {
        const MAX_CONSENSUS_BURST: usize = 32;

        // Priority drain with anti-starvation fair interleaving (32:1):
        // If consensus messages are present, yield up to MAX_CONSENSUS_BURST.
        // If burst limit reached and standard messages exist, yield 1 standard message and reset burst counter.
        if !self.consensus_message_queue.is_empty() {
            if self.consensus_burst_count >= MAX_CONSENSUS_BURST
                && !self.standard_message_queue.is_empty()
            {
                self.consensus_burst_count = 0;
                return self.standard_message_queue.pop_front();
            }
            self.consensus_burst_count = self.consensus_burst_count.saturating_add(1);
            return self.consensus_message_queue.pop_front();
        }

        // Reset burst counter when consensus queue is drained
        self.consensus_burst_count = 0;
        self.standard_message_queue.pop_front()
    }

    fn handle_rpc_sync_request(
        &mut self,
        peer_id: PeerId,
        request: L1Request,
    ) -> Result<L1Response> {
        match &request {
            L1Request::GetHeaders { start, end } => {
                if end < start {
                    return Err(crate::error::NetworkingError::InvalidHeaderRange {
                        start: *start,
                        end: *end,
                    }
                    .into());
                }

                let batch_len = end.saturating_sub(*start).saturating_add(1);
                if batch_len > self.max_header_batch {
                    return Err(crate::error::NetworkingError::HeaderBatchSizeExceeded {
                        batch_size: batch_len,
                        max: self.max_header_batch,
                    }
                    .into());
                }

                self.enforce_get_headers_rate_limit(peer_id)?;
            }
            L1Request::GetStateProof(_) => {
                self.enforce_get_state_proof_rate_limit(peer_id)?;
            }
            L1Request::GetBlock(_)
            | L1Request::GetBlockProof(_)
            | L1Request::GetLatestBlockHeight => {
                self.enforce_get_block_rate_limit(peer_id)?;
            }
            L1Request::GetTransaction(_) => {
                self.enforce_get_tx_rate_limit(peer_id)?;
            }
        }

        let handler = self
            .rpc_handler
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no rpc request handler registered"))?;
        handler.handle_request(peer_id, request)
    }

    fn enforce_get_headers_rate_limit(&mut self, peer_id: PeerId) -> Result<()> {
        let now = unix_timestamp();

        const MAX_RATE_LIMIT_ENTRIES: usize = 4096;
        if self.header_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES
            && !self.header_request_windows.contains_key(&peer_id)
        {
            self.header_request_windows.retain(|_, (ts, _)| {
                now.saturating_sub(*ts) < self.header_request_window_secs * 10
            });
            if self.header_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES {
                if let Some(oldest) = self.header_request_windows.keys().next().copied() {
                    self.header_request_windows.remove(&oldest);
                }
            }
        }

        let entry = self
            .header_request_windows
            .entry(peer_id)
            .or_insert((now, 0));

        if now.saturating_sub(entry.0) >= self.header_request_window_secs {
            *entry = (now, 0);
        }

        if entry.1 >= self.max_header_requests_per_peer_per_window {
            return Err(crate::error::NetworkingError::RpcRateLimitExceeded {
                endpoint: "GetHeaders".to_string(),
                limit: self.max_header_requests_per_peer_per_window,
                window_secs: self.header_request_window_secs,
            }
            .into());
        }

        entry.1 += 1;
        Ok(())
    }

    fn enforce_get_state_proof_rate_limit(&mut self, peer_id: PeerId) -> Result<()> {
        let now = unix_timestamp();

        const MAX_RATE_LIMIT_ENTRIES: usize = 4096;
        if self.state_proof_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES
            && !self.state_proof_request_windows.contains_key(&peer_id)
        {
            self.state_proof_request_windows.retain(|_, (ts, _)| {
                now.saturating_sub(*ts) < self.state_proof_request_window_secs * 10
            });
            if self.state_proof_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES {
                if let Some(oldest) = self.state_proof_request_windows.keys().next().copied() {
                    self.state_proof_request_windows.remove(&oldest);
                }
            }
        }

        let entry = self
            .state_proof_request_windows
            .entry(peer_id)
            .or_insert((now, 0));

        if now.saturating_sub(entry.0) >= self.state_proof_request_window_secs {
            *entry = (now, 0);
        }

        if entry.1 >= self.max_state_proof_requests_per_peer_per_window {
            return Err(crate::error::NetworkingError::RpcRateLimitExceeded {
                endpoint: "GetStateProof".to_string(),
                limit: self.max_state_proof_requests_per_peer_per_window,
                window_secs: self.state_proof_request_window_secs,
            }
            .into());
        }

        entry.1 += 1;
        Ok(())
    }

    fn enforce_get_block_rate_limit(&mut self, peer_id: PeerId) -> Result<()> {
        let now = unix_timestamp();

        const MAX_RATE_LIMIT_ENTRIES: usize = 4096;
        if self.block_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES
            && !self.block_request_windows.contains_key(&peer_id)
        {
            self.block_request_windows.retain(|_, (ts, _)| {
                now.saturating_sub(*ts) < crate::BLOCK_REQUEST_WINDOW_SECS * 10
            });
            if self.block_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES {
                if let Some(oldest) = self.block_request_windows.keys().next().copied() {
                    self.block_request_windows.remove(&oldest);
                }
            }
        }

        let entry = self
            .block_request_windows
            .entry(peer_id)
            .or_insert((now, 0));

        if now.saturating_sub(entry.0) >= crate::BLOCK_REQUEST_WINDOW_SECS {
            *entry = (now, 0);
        }

        if entry.1 >= crate::MAX_BLOCK_REQUESTS_PER_WINDOW {
            return Err(crate::error::NetworkingError::RpcRateLimitExceeded {
                endpoint: "GetBlock/GetBlockProof/GetLatestBlockHeight".to_string(),
                limit: crate::MAX_BLOCK_REQUESTS_PER_WINDOW,
                window_secs: crate::BLOCK_REQUEST_WINDOW_SECS,
            }
            .into());
        }

        entry.1 += 1;
        Ok(())
    }

    fn enforce_get_tx_rate_limit(&mut self, peer_id: PeerId) -> Result<()> {
        let now = unix_timestamp();

        const MAX_RATE_LIMIT_ENTRIES: usize = 4096;
        if self.tx_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES
            && !self.tx_request_windows.contains_key(&peer_id)
        {
            self.tx_request_windows.retain(|_, (ts, _)| {
                now.saturating_sub(*ts) < crate::TRANSACTION_REQUEST_WINDOW_SECS * 10
            });
            if self.tx_request_windows.len() >= MAX_RATE_LIMIT_ENTRIES {
                if let Some(oldest) = self.tx_request_windows.keys().next().copied() {
                    self.tx_request_windows.remove(&oldest);
                }
            }
        }

        let entry = self.tx_request_windows.entry(peer_id).or_insert((now, 0));

        if now.saturating_sub(entry.0) >= crate::TRANSACTION_REQUEST_WINDOW_SECS {
            *entry = (now, 0);
        }

        if entry.1 >= crate::MAX_TRANSACTION_REQUESTS_PER_WINDOW {
            return Err(crate::error::NetworkingError::RpcRateLimitExceeded {
                endpoint: "GetTransaction".to_string(),
                limit: crate::MAX_TRANSACTION_REQUESTS_PER_WINDOW,
                window_secs: crate::TRANSACTION_REQUEST_WINDOW_SECS,
            }
            .into());
        }

        entry.1 += 1;
        Ok(())
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<L1BehaviourEvent>) -> Result<()> {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if let Some(peer) = self.peer_store.get_peer(&peer_id) {
                    if peer.is_banned() {
                        tracing::warn!("Banned peer tried to connect: {}. Disconnecting.", peer_id);
                        let _ = self.swarm.disconnect_peer_id(peer_id);
                        return Ok(());
                    }
                }
                let address = endpoint.get_remote_address();
                if self.peer_count() >= self.max_peers {
                    tracing::warn!(
                        "Max peers limit ({}) reached. Disconnecting inbound peer: {}.",
                        self.max_peers,
                        peer_id
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return Ok(());
                }
                if !self
                    .peer_store
                    .check_ip_prefix_limit(address, crate::MAX_PEERS_PER_SUBNET)
                {
                    tracing::warn!(
                        "IP prefix limit exceeded for peer: {} ({:?}). Disconnecting.",
                        peer_id,
                        address
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return Ok(());
                }
                self.peer_store
                    .add_peer(Peer::new(peer_id, address.clone()));
                NetworkingMetrics::record_connection("inbound");
                NetworkingMetrics::update_peer_count(self.peer_count());
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                self.peer_store.remove_peer(&peer_id);
                let reason = cause
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "closed".to_string());
                NetworkingMetrics::record_disconnection(&reason);
                NetworkingMetrics::update_peer_count(self.peer_count());
                self.header_request_windows.remove(&peer_id);
                self.state_proof_request_windows.remove(&peer_id);
                self.block_request_windows.remove(&peer_id);
                self.tx_request_windows.remove(&peer_id);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {:?}", address);
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                ..
            } => {
                // Record the failure so the exponential discovery backoff
                // engages instead of hammering an unreachable peer.
                self.record_discovery_failure(peer_id);
                NetworkingMetrics::record_disconnection("dial_failure");
            }
            SwarmEvent::Behaviour(L1BehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    info!("mDNS discovered a new peer: {:?}", peer_id);
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, multiaddr.clone());
                    self.peer_store.add_peer(Peer::new(peer_id, multiaddr));
                    NetworkingMetrics::record_connection("inbound");
                    NetworkingMetrics::update_peer_count(self.peer_count());
                    self.discovery_failures.remove(&peer_id);
                    self.evict_peers();
                }
            }
            SwarmEvent::Behaviour(L1BehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
                peer,
                ..
            })) => {
                self.discovery_failures.remove(&peer);
                if let Some(existing) = self.peer_store.get_peer_mut(&peer) {
                    existing.update_last_seen();
                }
            }
            SwarmEvent::Behaviour(L1BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            })) => {
                let msg_hash = message
                    .source
                    .map(|s| {
                        let mut bytes = message.data.clone();
                        bytes.extend_from_slice(&s.to_bytes());
                        bytes
                    })
                    .unwrap_or_else(|| message.data.clone());

                if self.bloom_filter.contains(&msg_hash) {
                    // Normal duplicate gossip delivery across mesh topology - drop cleanly without penalizing peer
                    return Ok(());
                } else {
                    self.bloom_filter.insert(&msg_hash);
                    if message.data.len() > sxiaum_types::MAX_CANONICAL_MESSAGE_SIZE {
                        self.peer_store
                            .penalize_invalid_message(&propagation_source);
                        return Ok(());
                    }
                    if let Some(decoded) = GossipMessage::decode(&message.data) {
                        if message.topic != decoded.topic().hash() {
                            self.peer_store
                                .penalize_invalid_message(&propagation_source);
                            return Ok(());
                        }
                        let decoded = match self.gossip.handle_message(propagation_source, decoded)
                        {
                            Ok(decoded) => decoded,
                            Err(_) => {
                                return Ok(());
                            }
                        };

                        // Priority Queue Segregation: consensus vs standard messages
                        match &decoded {
                            GossipMessage::Block(_)
                            | GossipMessage::Vote(_)
                            | GossipMessage::QuorumCertificate(_)
                            | GossipMessage::Commit(_)
                            | GossipMessage::Reveal(_) => {
                                // SECURITY (H-01): on overflow, drop the NEWEST
                                // (just-arrived) message and penalize the
                                // sender. Dropping the OLDEST entry evicted
                                // legitimate already-queued consensus traffic,
                                // letting a single flooding peer stall HotStuff
                                // phases; the flooding peer now bears the cost.
                                const MAX_CONSENSUS_QUEUE: usize = 2048;
                                if self.consensus_message_queue.len() >= MAX_CONSENSUS_QUEUE {
                                    self.peer_store
                                        .penalize_rate_limit_violation(&propagation_source);
                                    return Ok(());
                                }
                                self.consensus_message_queue
                                    .push_back((propagation_source, decoded));
                            }
                            GossipMessage::Transaction(_) | GossipMessage::StateSync(_) => {
                                const MAX_STANDARD_QUEUE: usize = 1024;
                                if self.standard_message_queue.len() >= MAX_STANDARD_QUEUE {
                                    self.peer_store
                                        .penalize_rate_limit_violation(&propagation_source);
                                    return Ok(());
                                }
                                self.standard_message_queue
                                    .push_back((propagation_source, decoded));
                            }
                        }
                    } else {
                        self.peer_store
                            .penalize_invalid_message(&propagation_source);
                    }
                }
            }
            SwarmEvent::Behaviour(L1BehaviourEvent::RequestResponse(
                request_response::Event::Message { peer, message, .. },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    let response = match self.handle_rpc_sync_request(peer, request) {
                        Ok(response) => response,
                        Err(error) => L1Response::Error(error.to_string()),
                    };
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .request_response
                        .send_response(channel, response);
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    const MAX_PENDING_RESPONSES: usize = 1024;
                    // Prune stale responses (> 60 seconds old)
                    self.pending_rpc_responses
                        .retain(|_, (ts, _)| ts.elapsed() < Duration::from_secs(60));
                    if self.pending_rpc_responses.len() >= MAX_PENDING_RESPONSES {
                        if let Some(first_key) = self.pending_rpc_responses.keys().next().copied() {
                            self.pending_rpc_responses.remove(&first_key);
                        }
                    }
                    self.pending_rpc_responses
                        .insert(request_id, (Instant::now(), response));
                }
            },
            _ => {}
        }

        Ok(())
    }

    async fn await_rpc_response(
        &mut self,
        request_id: request_response::OutboundRequestId,
        timeout_duration: Duration,
    ) -> Result<L1Response> {
        let started = Instant::now();
        loop {
            if let Some((_, response)) = self.pending_rpc_responses.remove(&request_id) {
                return Ok(response);
            }

            // SECURITY (C-14): loopback answering exists only under the
            // `test-loopback-rpc` feature and only when a test explicitly
            // installed a responder. Production builds cannot reach this code.
            #[cfg(feature = "test-loopback-rpc")]
            if let Some(handler) = self.test_loopback_responder.clone() {
                // The responder needs the request payload; keep a copy of the
                // last outbound request per id so the loopback can answer it.
                if let Some(request) = self.loopback_requests.get(&request_id).cloned() {
                    if let Ok(response) = handler.handle_request(PeerId::random(), request) {
                        return Ok(response);
                    }
                }
            }

            if started.elapsed() >= timeout_duration {
                // Ensure request_id is cleaned up
                self.pending_rpc_responses.remove(&request_id);
                return Err(crate::error::NetworkingError::RpcTimeout(timeout_duration).into());
            }

            self.poll_once(Duration::from_millis(RPC_RESPONSE_POLL_SLICE_MS))
                .await?;
            sleep(Duration::from_millis(1)).await;
        }
    }

    pub fn receive_transaction_gossip_message<P, V>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        mempool: &P,
        signature_verifier: &V,
    ) -> Result<TransactionGossipOutcome>
    where
        P: TransactionPoolSink,
        V: TransactionSignatureVerifier,
    {
        let start = Instant::now();
        let result = self.gossip.receive_transaction_gossip_message(
            peer_id,
            payload,
            mempool,
            signature_verifier,
        );

        self.record_inbound_message_metrics(TOPIC_TRANSACTIONS, payload.len());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.penalize_peer_for_gossip_error(peer_id, &error);
                return Err(error);
            }
        };
        NetworkingMetrics::record_gossip_propagation_latency(TOPIC_TRANSACTIONS, start.elapsed());

        if let Some(message) = outcome.rebroadcast.clone() {
            self.broadcast_message(message)?;
        }

        Ok(outcome)
    }

    pub fn receive_commit_gossip_message<P>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        commit_pool: &P,
    ) -> Result<CommitGossipOutcome>
    where
        P: CommitPoolSink,
    {
        let start = Instant::now();
        let result = self
            .gossip
            .receive_commit_gossip_message(peer_id, payload, commit_pool);

        self.record_inbound_message_metrics(TOPIC_COMMITS, payload.len());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.penalize_peer_for_gossip_error(peer_id, &error);
                return Err(error);
            }
        };
        NetworkingMetrics::record_gossip_propagation_latency(TOPIC_COMMITS, start.elapsed());

        if let Some(message) = outcome.rebroadcast.clone() {
            self.broadcast_message(message)?;
        }

        Ok(outcome)
    }

    pub fn receive_reveal_gossip_message<P>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        reveal_pool: &P,
    ) -> Result<RevealGossipOutcome>
    where
        P: RevealPoolSink,
    {
        let start = Instant::now();
        let result = self
            .gossip
            .receive_reveal_gossip_message(peer_id, payload, reveal_pool);

        self.record_inbound_message_metrics(TOPIC_REVEALS, payload.len());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.penalize_peer_for_gossip_error(peer_id, &error);
                return Err(error);
            }
        };
        NetworkingMetrics::record_gossip_propagation_latency(TOPIC_REVEALS, start.elapsed());

        if let Some(message) = outcome.rebroadcast.clone() {
            self.broadcast_message(message)?;
        }

        Ok(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_block_gossip_message<P, L, C, V, Z, S, Q>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        block_pool: &P,
        parent_lookup: &L,
        consensus: &C,
        signature_verifier: &V,
        proof_verifier: &Z,
        validator_set_verifier: &S,
        quorum_certificate_verifier: &Q,
    ) -> Result<BlockGossipOutcome>
    where
        P: BlockPoolSink,
        L: BlockParentLookup,
        C: BlockConsensusSink,
        V: BlockSignatureVerifier,
        Z: BlockProofVerifier,
        S: crate::gossip::BlockValidatorSetVerifier,
        Q: crate::gossip::BlockQuorumCertificateVerifier,
    {
        let start = Instant::now();
        let result = self.gossip.receive_block_gossip_message(
            peer_id,
            payload,
            block_pool,
            parent_lookup,
            consensus,
            signature_verifier,
            proof_verifier,
            validator_set_verifier,
            quorum_certificate_verifier,
        );

        self.record_inbound_message_metrics(TOPIC_BLOCKS, payload.len());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.penalize_peer_for_gossip_error(peer_id, &error);
                return Err(error);
            }
        };
        NetworkingMetrics::record_gossip_propagation_latency(TOPIC_BLOCKS, start.elapsed());

        if let Some(message) = outcome.rebroadcast.clone() {
            self.broadcast_message(message)?;
        }

        Ok(outcome)
    }

    pub fn receive_vote_gossip_message<C, V>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        consensus: &C,
        signature_verifier: &V,
    ) -> Result<VoteGossipOutcome>
    where
        C: VoteConsensusSink,
        V: VoteSignatureVerifier,
    {
        let start = Instant::now();
        let result = self.gossip.receive_vote_gossip_message(
            peer_id,
            payload,
            consensus,
            signature_verifier,
        );
        self.record_inbound_message_metrics(TOPIC_VOTES, payload.len());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.penalize_peer_for_gossip_error(peer_id, &error);
                return Err(error);
            }
        };
        NetworkingMetrics::record_gossip_propagation_latency(TOPIC_VOTES, start.elapsed());
        Ok(outcome)
    }

    pub fn receive_quorum_certificate_gossip_message<C, V, B>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        consensus: &C,
        verifier: &V,
        broadcaster: &B,
    ) -> Result<QuorumCertificateGossipOutcome>
    where
        C: QuorumCertificateConsensusSink,
        V: QuorumCertificateVerifier,
        B: QuorumCertificateBroadcaster,
    {
        let start = Instant::now();
        let result = self.gossip.receive_quorum_certificate_gossip_message(
            peer_id,
            payload,
            consensus,
            verifier,
            broadcaster,
        );

        self.record_inbound_message_metrics(TOPIC_QUORUM_CERTIFICATES, payload.len());
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                self.penalize_peer_for_gossip_error(peer_id, &error);
                return Err(error);
            }
        };
        NetworkingMetrics::record_gossip_propagation_latency(
            TOPIC_QUORUM_CERTIFICATES,
            start.elapsed(),
        );

        if let Some(message) = outcome.rebroadcast.clone() {
            self.broadcast_message(message)?;
        }

        Ok(outcome)
    }

    pub fn shutdown(&mut self) -> Result<()> {
        let peer_ids: Vec<PeerId> = self.peer_store.peers.keys().copied().collect();
        for peer_id in peer_ids {
            let _ = self.swarm.disconnect_peer_id(peer_id);
        }
        if !self.peer_store.peers.is_empty() {
            NetworkingMetrics::record_disconnection("shutdown");
        }
        self.peer_store.peers.clear();
        self.consensus_message_queue.clear();
        self.standard_message_queue.clear();
        self.pending_rpc_responses.clear();
        self.header_request_windows.clear();
        self.state_proof_request_windows.clear();
        self.block_request_windows.clear();
        self.tx_request_windows.clear();
        self.discovery_failures.clear();
        self.consensus_burst_count = 0;
        NetworkingMetrics::update_peer_count(0);
        Ok(())
    }

    fn record_inbound_message_metrics(&self, topic: &str, bytes: usize) {
        NetworkingMetrics::record_messages("inbound", topic, 1);
        NetworkingMetrics::record_messages_per_second("inbound", topic, 1.0);
        NetworkingMetrics::record_bandwidth("inbound", bytes as u64);
    }

    fn penalize_peer_for_gossip_error(&mut self, peer_id: PeerId, error: &anyhow::Error) {
        use crate::gossip::MessageValidationFailure;

        match Gossip::classify_message_error(error) {
            MessageValidationFailure::DuplicateMessage => {
                self.peer_store.penalize_duplicate_message(&peer_id);
            }
            MessageValidationFailure::RateLimitExceeded => {
                self.peer_store.penalize_rate_limit_violation(&peer_id);
            }
            MessageValidationFailure::EmptyPayload
            | MessageValidationFailure::MessageTooLarge
            | MessageValidationFailure::UnsubscribedTopic
            | MessageValidationFailure::InvalidPayload => {
                self.peer_store.penalize_invalid_message(&peer_id);
            }
        }
    }

    pub async fn detect_node_out_of_sync_state<S, C>(
        &mut self,
        peer_id: PeerId,
        state: &S,
        rpc_client: &mut C,
    ) -> Result<bool>
    where
        S: ChainSyncState,
        C: RpcSyncClient,
    {
        let local_height = state.local_block_height()?;
        let remote_height = rpc_client.request_latest_block_height(peer_id).await?;
        Ok(remote_height > local_height)
    }

    pub async fn synchronize_chain_from_peer<S, C>(
        &mut self,
        peer_id: PeerId,
        state: &S,
        rpc_client: &mut C,
    ) -> Result<ChainSyncOutcome>
    where
        S: ChainSyncState,
        C: RpcSyncClient,
    {
        let local_height = state.local_block_height()?;
        let remote_height = rpc_client.request_latest_block_height(peer_id).await?;

        if remote_height <= local_height {
            return Ok(ChainSyncOutcome {
                was_out_of_sync: false,
                remote_height,
                applied_blocks: 0,
                new_local_head: local_height,
            });
        }

        let round_end = local_height
            .saturating_add(MAX_SYNC_BLOCKS_PER_ROUND)
            .min(remote_height);

        let mut applied_blocks = 0u64;
        let mut current_head = local_height;

        for height in (local_height + 1)..=round_end {
            let block_bytes = rpc_client
                .request_block(peer_id, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing block at height {}", height))?;

            let block = state.validate_downloaded_block(&block_bytes)?;
            state.apply_downloaded_block(&block)?;
            state.update_local_chain_head(&block)?;

            applied_blocks = applied_blocks.saturating_add(1);
            current_head = block.height();
        }

        Ok(ChainSyncOutcome {
            was_out_of_sync: true,
            remote_height,
            applied_blocks,
            new_local_head: current_head,
        })
    }

    fn load_bootstrap_peer_list(
        &mut self,
        bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    ) -> Result<()> {
        for (peer_id, address) in bootstrap_peers {
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, address.clone());
            self.peer_store.add_peer(Peer::new(peer_id, address));
        }
        Ok(())
    }

    fn advertise_peer_address(&mut self, peer_id: PeerId) -> Result<()> {
        let Some(peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found for advertisement", peer_id);
        };

        let address: Multiaddr = peer.address.parse()?;
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, address);
        Ok(())
    }

    pub fn peer_lookup_query(&mut self, peer_id: PeerId) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(peer_id);
    }

    pub fn trigger_peer_discovery(&mut self) -> Result<()> {
        self.run_periodic_peer_discovery()
    }

    fn run_periodic_peer_discovery(&mut self) -> Result<()> {
        if Instant::now() < self.next_discovery_at {
            return Ok(());
        }

        let peer_ids: Vec<PeerId> = self
            .peer_store
            .connected_peers()
            .into_iter()
            .map(|peer| peer.peer_id)
            .collect();

        for peer_id in peer_ids {
            self.peer_lookup_query(peer_id);
        }

        self.next_discovery_at = Instant::now() + self.discovery_interval;
        Ok(())
    }

    fn discovery_backoff_duration(&self, peer_id: &PeerId) -> Duration {
        let attempts = self.discovery_failures.get(peer_id).copied().unwrap_or(0);
        self.discovery_backoff
            .saturating_mul(attempts.saturating_add(1))
    }

    fn record_discovery_failure(&mut self, peer_id: PeerId) {
        let attempts = self.discovery_failures.entry(peer_id).or_insert(0);
        *attempts = attempts.saturating_add(1);
        self.next_discovery_at = Instant::now() + self.discovery_backoff_duration(&peer_id);
    }

    fn evict_peers(&mut self) {
        if self.peer_store.peers.len() <= self.max_peers {
            return;
        }

        let mut peers: Vec<(PeerId, i32, u64)> = self
            .peer_store
            .peers
            .iter()
            .map(|(peer_id, peer)| (*peer_id, peer.reputation, peer.last_seen))
            .collect();
        peers.sort_by_key(|(_, reputation, last_seen)| (*reputation, *last_seen));

        let overflow = self.peer_store.peers.len().saturating_sub(self.max_peers);
        for (peer_id, _, _) in peers.into_iter().take(overflow) {
            let _ = self.peer_store.remove_peer(&peer_id);
        }
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl RpcSyncClient for P2PNetwork {
    async fn request_latest_block_height(&mut self, peer_id: PeerId) -> Result<u64> {
        let Some(_peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found", peer_id);
        };

        let request_id =
            self.send_rpc_request(peer_id, L1Request::request_latest_block_height())?;
        match self
            .await_rpc_response(request_id, crate::rpc::DEFAULT_RPC_TIMEOUT)
            .await?
        {
            L1Response::LatestBlockHeight(Some(height)) => Ok(height),
            L1Response::Error(error) => bail!("latest block height request failed: {}", error),
            _ => bail!("unexpected response for latest block height request"),
        }
    }

    async fn request_block(&mut self, peer_id: PeerId, height: u64) -> Result<Option<Vec<u8>>> {
        let Some(_peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found", peer_id);
        };

        let request_id = self.send_rpc_request(peer_id, L1Request::request_block(height))?;
        match self
            .await_rpc_response(request_id, crate::rpc::DEFAULT_RPC_TIMEOUT)
            .await?
        {
            L1Response::Block(block) => Ok(block),
            L1Response::Error(error) => bail!("block request failed: {}", error),
            _ => bail!("unexpected response for block request"),
        }
    }

    async fn request_headers(
        &mut self,
        peer_id: PeerId,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<RpcVerifiedHeaderEnvelope>>> {
        let Some(_peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found", peer_id);
        };

        let request_id = self.send_rpc_request(peer_id, L1Request::request_headers(start, end))?;
        match self
            .await_rpc_response(request_id, crate::rpc::DEFAULT_RPC_TIMEOUT)
            .await?
        {
            L1Response::Headers(headers) => Ok(headers),
            L1Response::Error(error) => bail!("headers request failed: {}", error),
            _ => bail!("unexpected response for headers request"),
        }
    }

    async fn request_state_proof(
        &mut self,
        peer_id: PeerId,
        request: RpcStateProofRequest,
    ) -> Result<Option<RpcStateProofResponse>> {
        let Some(_peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found", peer_id);
        };

        let request_id = self.send_rpc_request(peer_id, L1Request::request_state_proof(request))?;
        match self
            .await_rpc_response(request_id, crate::rpc::DEFAULT_RPC_TIMEOUT)
            .await?
        {
            L1Response::StateProof(proof) => Ok(*proof),
            L1Response::Error(error) => bail!("state proof request failed: {}", error),
            _ => bail!("unexpected response for state proof request"),
        }
    }

    async fn request_block_proof(
        &mut self,
        peer_id: PeerId,
        height: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(_peer) = self.peer_store.get_peer(&peer_id) else {
            bail!("peer {:?} not found", peer_id);
        };

        let request_id = self.send_rpc_request(peer_id, L1Request::request_block_proof(height))?;
        match self
            .await_rpc_response(request_id, crate::rpc::DEFAULT_RPC_TIMEOUT)
            .await?
        {
            L1Response::BlockProof(proof) => Ok(proof),
            L1Response::Error(error) => bail!("block proof request failed: {}", error),
            _ => bail!("unexpected response for block proof request"),
        }
    }
}

pub struct MessageBloomFilter {
    lru: std::sync::Mutex<lru::LruCache<[u8; 32], ()>>,
}

impl MessageBloomFilter {
    pub fn new(size: usize, _hash_count: usize) -> Self {
        let non_zero = std::num::NonZeroUsize::new(size.max(100)).unwrap();
        Self {
            lru: std::sync::Mutex::new(lru::LruCache::new(non_zero)),
        }
    }

    pub fn insert(&mut self, item: &[u8]) {
        let hash: [u8; 32] = Sha256::digest(item).into();
        let mut cache = self.lru.lock().unwrap();
        cache.put(hash, ());
    }

    pub fn contains(&self, item: &[u8]) -> bool {
        let hash: [u8; 32] = Sha256::digest(item).into();
        let cache = self.lru.lock().unwrap();
        cache.contains(&hash)
    }
}
#[cfg(test)]
mod tests {
    use super::{ChainSyncState, P2PConfig, P2PNetwork, RpcSyncClient};
    use crate::gossip::GossipMessage;
    use crate::peer::Peer;
    use crate::rpc::{
        L1Request, L1Response, RpcStateProofRequest, RpcStateProofResponse,
        RpcVerifiedHeaderEnvelope,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use libp2p::{identity::Keypair, Multiaddr, PeerId};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_consensus::hotstuff::vote::Vote;
    use sxiaum_types::Address;
    use sxiaum_types::MAX_CANONICAL_MESSAGE_SIZE;

    fn test_config() -> P2PConfig {
        P2PConfig {
            local_key: Keypair::generate_ed25519(),
            bootstrap_peers: Vec::new(),
            discovery_interval: Duration::from_millis(25),
            discovery_backoff: Duration::from_millis(10),
            max_peers: 8,
            max_header_batch: 128,
            max_header_requests_per_peer_per_window: 4,
            header_request_window_secs: 10,
            max_state_proof_requests_per_peer_per_window: 4,
            state_proof_request_window_secs: 10,
            db: None,
        }
    }

    fn tcp_addr(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}")
            .parse()
            .expect("tcp multiaddr should parse")
    }

    fn signed_block(parent_hash: [u8; 32], height: u64, seed: u8) -> Block {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        let mut block = Block::new(header, BlockBody::empty());
        block.try_compute_roots().expect("compute roots");
        block.header.sign(&signing_key).expect("block should sign");
        block
    }

    fn signed_vote(seed: u8, block_hash: [u8; 32], view: u64) -> Vote {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let validator = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut vote = Vote::new(validator, block_hash, view);
        vote.sign(&signing_key).expect("vote should sign");
        vote
    }

    #[derive(Default)]
    struct MockChainState {
        local_height: u64,
        validated_heights: RefCell<Vec<u64>>,
        applied_heights: RefCell<Vec<u64>>,
        updated_heads: RefCell<Vec<u64>>,
    }

    impl ChainSyncState for MockChainState {
        fn local_block_height(&self) -> Result<u64> {
            Ok(self.local_height)
        }

        fn validate_downloaded_block(&self, block_bytes: &[u8]) -> Result<Block> {
            let block: Block = bincode::deserialize(block_bytes)?;
            self.validated_heights.borrow_mut().push(block.height());
            Ok(block)
        }

        fn apply_downloaded_block(&self, block: &Block) -> Result<()> {
            self.applied_heights.borrow_mut().push(block.height());
            Ok(())
        }

        fn update_local_chain_head(&self, block: &Block) -> Result<()> {
            self.updated_heads.borrow_mut().push(block.height());
            Ok(())
        }
    }

    struct MockRpcSyncClient {
        remote_height: u64,
        blocks: HashMap<u64, Vec<u8>>,
        requested_heights: RefCell<Vec<u64>>,
        latest_height_requests: RefCell<Vec<PeerId>>,
    }

    impl MockRpcSyncClient {
        fn with_blocks(remote_height: u64, blocks: HashMap<u64, Vec<u8>>) -> Self {
            Self {
                remote_height,
                blocks,
                requested_heights: RefCell::new(Vec::new()),
                latest_height_requests: RefCell::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl RpcSyncClient for MockRpcSyncClient {
        async fn request_latest_block_height(&mut self, peer_id: PeerId) -> Result<u64> {
            self.latest_height_requests.borrow_mut().push(peer_id);
            Ok(self.remote_height)
        }

        async fn request_block(
            &mut self,
            _peer_id: PeerId,
            height: u64,
        ) -> Result<Option<Vec<u8>>> {
            self.requested_heights.borrow_mut().push(height);
            Ok(self.blocks.get(&height).cloned())
        }

        async fn request_headers(
            &mut self,
            _peer_id: PeerId,
            start: u64,
            end: u64,
        ) -> Result<Option<Vec<RpcVerifiedHeaderEnvelope>>> {
            let mut headers = Vec::new();
            for height in start..=end {
                if let Some(bytes) = self.blocks.get(&height) {
                    let block: Block = bincode::deserialize(bytes)?;
                    headers.push(RpcVerifiedHeaderEnvelope {
                        header: block.header,
                        consensus_signatures: Vec::new(),
                        hotstuff_view_phase: None,
                    });
                }
            }
            Ok(Some(headers))
        }

        async fn request_state_proof(
            &mut self,
            _peer_id: PeerId,
            _request: RpcStateProofRequest,
        ) -> Result<Option<RpcStateProofResponse>> {
            Ok(None)
        }

        async fn request_block_proof(
            &mut self,
            _peer_id: PeerId,
            _height: u64,
        ) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct MockVoteConsensus {
        forwarded: RefCell<Vec<Vote>>,
    }

    impl crate::gossip::VoteConsensusSink for MockVoteConsensus {
        fn forward_vote_to_consensus(&self, vote: Vote) -> Result<()> {
            self.forwarded.borrow_mut().push(vote);
            Ok(())
        }
    }

    struct MockVoteVerifier {
        valid: bool,
    }

    impl crate::gossip::VoteSignatureVerifier for MockVoteVerifier {
        fn verify_vote_signature(&self, _vote: &Vote) -> Result<bool> {
            Ok(self.valid)
        }
    }

    #[tokio::test]
    async fn new_initializes_swarm_peer_store_and_message_queue() {
        let network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");

        assert_eq!(network.peer_count(), 0);
        assert!(network.standard_message_queue.is_empty());
        assert_eq!(network.max_peers, 8);
    }

    #[tokio::test]
    async fn listen_dial_disconnect_and_shutdown_manage_peer_state() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        network
            .listen_on(tcp_addr(0))
            .expect("listen should succeed");

        let peer_key = Keypair::generate_ed25519();
        let peer_id = PeerId::from(peer_key.public());
        let peer_addr = tcp_addr(10002);
        network
            .dial_peer(peer_id, peer_addr.clone())
            .expect("dial should succeed");

        assert_eq!(network.peer_count(), 1);
        assert!(network.peer_store.get_peer(&peer_id).is_some());

        network
            .disconnect_peer(peer_id)
            .expect("disconnect should succeed");
        assert_eq!(network.peer_count(), 0);

        network
            .dial_peer(peer_id, peer_addr)
            .expect("re-dial should succeed");
        network
            .shutdown()
            .expect("shutdown should clear network state");
        assert_eq!(network.peer_count(), 0);
        assert!(network.standard_message_queue.is_empty());
    }

    #[tokio::test]
    async fn receive_message_and_empty_outgoing_handler_manage_queue() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let message = GossipMessage::StateSync(vec![1, 2, 3]);
        let peer_id = PeerId::random();
        network
            .standard_message_queue
            .push_back((peer_id, message.clone()));

        assert!(
            matches!(network.receive_message(), Some((source, GossipMessage::StateSync(bytes))) if source == peer_id && bytes == vec![1, 2, 3])
        );
        assert!(network.receive_message().is_none());

        network
            .handle_outgoing_connections()
            .await
            .expect("empty outgoing queue should be handled");
    }

    #[tokio::test]
    async fn send_message_requires_known_non_banned_peer() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_key = Keypair::generate_ed25519();
        let peer_id = PeerId::from(peer_key.public());

        assert!(network
            .send_message(peer_id, L1Request::request_latest_block_height())
            .is_err());

        network
            .peer_store
            .add_peer(Peer::new(peer_id, tcp_addr(10003)));
        network.peer_store.ban_peer(&peer_id);
        assert!(network
            .send_message(peer_id, L1Request::request_block(1))
            .is_err());
    }

    #[tokio::test]
    async fn disconnect_unknown_peer_returns_error() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let unknown_peer = PeerId::from(Keypair::generate_ed25519().public());

        assert!(network.disconnect_peer(unknown_peer).is_err());
    }

    #[tokio::test]
    async fn bootstrap_loading_peer_discovery_backoff_and_eviction_work() {
        let bootstrap_peer_one = PeerId::from(Keypair::generate_ed25519().public());
        let bootstrap_peer_two = PeerId::from(Keypair::generate_ed25519().public());
        let config = P2PConfig {
            bootstrap_peers: vec![
                (bootstrap_peer_one, tcp_addr(11001)),
                (bootstrap_peer_two, tcp_addr(11002)),
            ],
            max_peers: 2,
            ..test_config()
        };
        let mut network = P2PNetwork::new(config)
            .await
            .expect("network should initialize");

        assert!(network.peer_store.get_peer(&bootstrap_peer_one).is_some());
        assert!(network.peer_store.get_peer(&bootstrap_peer_two).is_some());
        assert_eq!(network.peer_count(), 2);

        let discovered_peer = PeerId::from(Keypair::generate_ed25519().public());
        network
            .peer_store
            .add_peer(Peer::new(discovered_peer, tcp_addr(11003)));
        let next_before = network.next_discovery_at;
        network
            .trigger_peer_discovery()
            .expect("no-op discovery should succeed");
        assert_eq!(network.next_discovery_at, next_before);

        network.next_discovery_at = std::time::Instant::now();
        network
            .trigger_peer_discovery()
            .expect("scheduled discovery should succeed");
        assert!(network.next_discovery_at > std::time::Instant::now());

        let peer = network
            .peer_store
            .get_peer_mut(&bootstrap_peer_one)
            .expect("bootstrap peer should exist");
        peer.reputation = -50;
        peer.last_seen = 1;
        let extra_peer = PeerId::from(Keypair::generate_ed25519().public());
        let mut extra = Peer::new(extra_peer, tcp_addr(11004));
        extra.reputation = 5;
        extra.last_seen = 10;
        network.peer_store.add_peer(extra);
        network.evict_peers();
        assert_eq!(network.peer_store.peers.len(), 2);
        assert!(!network.peer_store.peers.contains_key(&bootstrap_peer_one));

        let backoff_peer = PeerId::from(Keypair::generate_ed25519().public());
        let first_backoff = network.discovery_backoff_duration(&backoff_peer);
        assert_eq!(first_backoff, Duration::from_millis(10));
        network.record_discovery_failure(backoff_peer);
        assert_eq!(network.discovery_failures.get(&backoff_peer), Some(&1));
        assert_eq!(
            network.discovery_backoff_duration(&backoff_peer),
            Duration::from_millis(20)
        );
    }

    #[tokio::test]
    async fn advertise_peer_address_and_lookup_query_accept_known_peer() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        network
            .peer_store
            .add_peer(Peer::new(peer_id, tcp_addr(11005)));

        network
            .advertise_peer_address(peer_id)
            .expect("advertise peer address should succeed");
        network.peer_lookup_query(peer_id);
    }

    #[tokio::test]
    async fn detect_out_of_sync_and_synchronize_chain_sequentially() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        let state = MockChainState {
            local_height: 3,
            ..Default::default()
        };
        let block_four = signed_block([4u8; 32], 4, 1);
        let block_five = signed_block(block_four.try_hash().unwrap(), 5, 2);
        let mut client = MockRpcSyncClient::with_blocks(
            5,
            HashMap::from([
                (
                    4,
                    bincode::serialize(&block_four).expect("block should encode"),
                ),
                (
                    5,
                    bincode::serialize(&block_five).expect("block should encode"),
                ),
            ]),
        );

        assert!(network
            .detect_node_out_of_sync_state(peer_id, &state, &mut client)
            .await
            .expect("sync detection should succeed"));

        let outcome = network
            .synchronize_chain_from_peer(peer_id, &state, &mut client)
            .await
            .expect("chain sync should succeed");

        assert!(outcome.was_out_of_sync);
        assert_eq!(outcome.remote_height, 5);
        assert_eq!(outcome.applied_blocks, 2);
        assert_eq!(outcome.new_local_head, 5);
        assert_eq!(&*client.requested_heights.borrow(), &[4, 5]);
        assert_eq!(&*state.validated_heights.borrow(), &[4, 5]);
        assert_eq!(&*state.applied_heights.borrow(), &[4, 5]);
        assert_eq!(&*state.updated_heads.borrow(), &[4, 5]);
    }

    #[tokio::test]
    async fn synchronize_chain_reports_up_to_date_and_missing_blocks_fail() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        let state = MockChainState {
            local_height: 6,
            ..Default::default()
        };
        let mut up_to_date_client = MockRpcSyncClient::with_blocks(6, HashMap::new());

        assert!(!network
            .detect_node_out_of_sync_state(peer_id, &state, &mut up_to_date_client)
            .await
            .expect("sync detection should succeed"));

        let outcome = network
            .synchronize_chain_from_peer(peer_id, &state, &mut up_to_date_client)
            .await
            .expect("up-to-date sync should succeed");
        assert!(!outcome.was_out_of_sync);
        assert_eq!(outcome.applied_blocks, 0);
        assert_eq!(outcome.new_local_head, 6);

        let mut missing_block_client = MockRpcSyncClient::with_blocks(7, HashMap::new());
        let error = network
            .synchronize_chain_from_peer(peer_id, &state, &mut missing_block_client)
            .await
            .expect_err("missing block should fail");
        assert!(error.to_string().contains("missing block at height 7"));
    }

    #[tokio::test]
    async fn synchronize_chain_recovers_after_partition_and_late_blocks_arrive() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        let state = MockChainState {
            local_height: 4,
            ..Default::default()
        };

        let mut partitioned_client = MockRpcSyncClient::with_blocks(6, HashMap::new());
        let partition_error = network
            .synchronize_chain_from_peer(peer_id, &state, &mut partitioned_client)
            .await
            .expect_err("partitioned sync should fail until missing blocks arrive");
        assert!(partition_error
            .to_string()
            .contains("missing block at height 5"));

        let block_five = signed_block([5u8; 32], 5, 10);
        let block_six = signed_block(block_five.try_hash().unwrap(), 6, 11);
        let mut recovered_client = MockRpcSyncClient::with_blocks(
            6,
            HashMap::from([
                (
                    5,
                    bincode::serialize(&block_five).expect("block should encode"),
                ),
                (
                    6,
                    bincode::serialize(&block_six).expect("block should encode"),
                ),
            ]),
        );

        let outcome = network
            .synchronize_chain_from_peer(peer_id, &state, &mut recovered_client)
            .await
            .expect("sync should recover after partition heals");

        assert!(outcome.was_out_of_sync);
        assert_eq!(outcome.applied_blocks, 2);
        assert_eq!(outcome.new_local_head, 6);
        assert_eq!(&*state.applied_heights.borrow(), &[5, 6]);
        assert_eq!(&*state.updated_heads.borrow(), &[5, 6]);
    }

    #[tokio::test]
    async fn rpc_sync_handler_responds_to_latest_height_block_and_header_requests() {
        struct TestHandler {
            block_payload: Vec<u8>,
        }
        impl crate::p2p::RpcRequestHandler for TestHandler {
            fn handle_request(&self, _peer_id: PeerId, request: L1Request) -> Result<L1Response> {
                match request {
                    L1Request::GetLatestBlockHeight => {
                        Ok(L1Response::respond_latest_block_height(Some(11)))
                    }
                    L1Request::GetBlock(11) => {
                        Ok(L1Response::respond_block(Some(self.block_payload.clone())))
                    }
                    L1Request::GetHeaders { start: 1, end: 11 } => {
                        Ok(L1Response::respond_headers(Some(vec![
                            RpcVerifiedHeaderEnvelope {
                                header: BlockHeader::new([0u8; 32], 11),
                                consensus_signatures: vec![(Address([1u8; 32]), vec![3u8; 64])],
                                hotstuff_view_phase: None,
                            },
                        ])))
                    }
                    _ => Ok(L1Response::Error("not found".into())),
                }
            }
        }

        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        network
            .peer_store
            .add_peer(Peer::new(peer_id, tcp_addr(12001)));
        let block_payload = vec![1u8, 2, 3, 4];
        network.set_rpc_handler(Arc::new(TestHandler {
            block_payload: block_payload.clone(),
        }));

        let resp_height = network
            .handle_rpc_sync_request(peer_id, L1Request::GetLatestBlockHeight)
            .expect("height request should succeed");
        assert!(matches!(
            resp_height,
            L1Response::LatestBlockHeight(Some(11))
        ));

        let resp_block = network
            .handle_rpc_sync_request(peer_id, L1Request::GetBlock(11))
            .expect("block request should succeed");
        assert!(matches!(resp_block, L1Response::Block(Some(payload)) if payload == block_payload));

        let resp_headers = network
            .handle_rpc_sync_request(peer_id, L1Request::GetHeaders { start: 1, end: 11 })
            .expect("header request should succeed");
        if let L1Response::Headers(Some(headers)) = resp_headers {
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[0].header.height, 11);
        } else {
            panic!("expected headers response");
        }
    }

    #[tokio::test]
    async fn duplicate_and_oversized_gossip_penalize_peers() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        network
            .peer_store
            .add_peer(Peer::new(peer_id, tcp_addr(12002)));

        let consensus = MockVoteConsensus::default();
        let vote = signed_vote(10, [6u8; 32], 2);
        let payload = vote.encode();

        network
            .receive_vote_gossip_message(
                peer_id,
                &payload,
                &consensus,
                &MockVoteVerifier { valid: true },
            )
            .expect("first vote should succeed");
        let duplicate_error = network
            .receive_vote_gossip_message(
                peer_id,
                &payload,
                &consensus,
                &MockVoteVerifier { valid: true },
            )
            .expect_err("duplicate vote should fail");
        assert!(
            duplicate_error.to_string().contains("DuplicateMessage")
                || duplicate_error.to_string().contains("duplicate")
        );
        assert_eq!(
            network
                .peer_store
                .get_peer(&peer_id)
                .expect("peer should exist")
                .reputation,
            -5
        );

        let oversized_payload = vec![1u8; MAX_CANONICAL_MESSAGE_SIZE + 1];
        let oversized_error = network
            .receive_vote_gossip_message(
                peer_id,
                &oversized_payload,
                &consensus,
                &MockVoteVerifier { valid: true },
            )
            .expect_err("oversized vote should fail");
        assert!(
            oversized_error.to_string().contains("MessageTooLarge")
                || oversized_error.to_string().contains("max size")
        );
        assert_eq!(
            network
                .peer_store
                .get_peer(&peer_id)
                .expect("peer should exist")
                .reputation,
            -30
        );
    }

    #[tokio::test]
    async fn repeated_invalid_messages_ban_peer() {
        let mut network = P2PNetwork::new(test_config())
            .await
            .expect("network should initialize");
        let peer_id = PeerId::from(Keypair::generate_ed25519().public());
        network
            .peer_store
            .add_peer(Peer::new(peer_id, tcp_addr(12003)));
        let consensus = MockVoteConsensus::default();

        for invalid_payload in [
            b"bad-vote-1".as_slice(),
            b"bad-vote-2".as_slice(),
            b"bad-vote-3".as_slice(),
            b"bad-vote-4".as_slice(),
        ] {
            let _ = network.receive_vote_gossip_message(
                peer_id,
                invalid_payload,
                &consensus,
                &MockVoteVerifier { valid: true },
            );
        }

        let peer = network
            .peer_store
            .get_peer(&peer_id)
            .expect("peer should exist");
        assert!(peer.is_banned());
        assert!(peer.reputation <= -100);
    }

    #[test]
    fn test_message_bloom_filter_operations() {
        use super::MessageBloomFilter;
        let mut filter = MessageBloomFilter::new(1000, 3);
        let msg1 = b"test-message-1";
        let msg2 = b"test-message-2";
        let msg3 = b"test-message-3";

        assert!(!filter.contains(msg1));
        assert!(!filter.contains(msg2));
        assert!(!filter.contains(msg3));

        filter.insert(msg1);
        assert!(filter.contains(msg1));
        assert!(!filter.contains(msg2));
        assert!(!filter.contains(msg3));

        filter.insert(msg2);
        assert!(filter.contains(msg1));
        assert!(filter.contains(msg2));
        assert!(!filter.contains(msg3));
    }
}
