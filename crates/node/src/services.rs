use crate::node::{ConsensusEvent, NodeEvent};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use sxiaum_block::BlockHeader;
use sxiaum_execution::Executor;
use sxiaum_light_client::LightClient;
use sxiaum_mempool::Mempool;
use sxiaum_networking::P2PNetwork;
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::info;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub consensus_interval: Duration,
    pub block_production_interval: Duration,
    pub state_pruning_interval: Duration,
    pub peer_discovery_interval: Duration,
    pub metrics_interval: Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            consensus_interval: Duration::from_millis(250),
            block_production_interval: Duration::from_secs(1),
            state_pruning_interval: Duration::from_secs(300),
            peer_discovery_interval: Duration::from_secs(30),
            metrics_interval: Duration::from_secs(10),
        }
    }
}

pub struct ServiceManager {
    handles: Vec<JoinHandle<Result<()>>>,
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub fn spawn<F>(&mut self, f: F)
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        let handle = tokio::spawn(f);
        self.handles.push(handle);
    }

    pub fn start_networking_service(&mut self, networking: Arc<Mutex<P2PNetwork>>) {
        self.spawn(async move {
            info!("starting networking service");
            loop {
                networking
                    .lock()
                    .await
                    .poll_once(Duration::from_millis(50))
                    .await?;
            }
        });
    }

    pub fn start_mempool_service(&mut self, mempool: Arc<Mempool>) {
        self.spawn(async move {
            info!("starting mempool service");
            mempool.start()?;
            loop {
                // Transient storage errors must not kill the sweep loop
                // permanently — a dead expiry sweep silently accumulates
                // stale transactions forever. Log and retry on next tick.
                if let Err(error) = mempool.remove_expired_transactions_periodically() {
                    tracing::error!("mempool expiry sweep failed (retrying): {}", error);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    pub fn start_consensus_service(
        &mut self,
        event_tx: mpsc::Sender<NodeEvent>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting consensus tick service");
            let mut ticker = interval(config.consensus_interval);
            loop {
                ticker.tick().await;
                event_tx
                    .send(NodeEvent::Consensus(ConsensusEvent::Tick))
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("failed to dispatch consensus tick: {}", error)
                    })?;
            }
        });
    }

    pub fn start_block_production_service(
        &mut self,
        mempool: Arc<Mempool>,
        event_tx: mpsc::Sender<NodeEvent>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting block production service");
            let mut ticker = interval(config.block_production_interval);
            loop {
                ticker.tick().await;
                let pending_count = mempool.pending_count().unwrap_or(0);
                let (pending_commits, revealed_txs) = mempool.mev_pool_stats();
                if pending_count == 0 && pending_commits == 0 && revealed_txs == 0 {
                    continue;
                }
                event_tx
                    .send(NodeEvent::Consensus(ConsensusEvent::TriggerProposal))
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!("failed to dispatch block production event: {}", error)
                    })?;
            }
        });
    }

    pub fn start_state_pruning_service(&mut self, state: Arc<StateDB>, config: ServiceConfig) {
        self.spawn(async move {
            info!("starting state pruning service");
            let mut ticker = interval(config.state_pruning_interval);
            loop {
                ticker.tick().await;
                // Transient errors must not kill the pruning loop permanently;
                // unbounded snapshot growth would go unnoticed until disk
                // exhaustion. Log and retry on the next tick.
                match state.prune_old_state() {
                    Ok(pruned) => {
                        if pruned > 0 {
                            info!("pruned {} old state snapshot entries", pruned);
                        }
                    }
                    Err(error) => {
                        tracing::error!("state pruning failed (retrying): {}", error);
                    }
                }
            }
        });
    }

    pub fn start_peer_discovery_service(
        &mut self,
        networking: Arc<Mutex<P2PNetwork>>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting peer discovery service");
            let mut ticker = interval(config.peer_discovery_interval);
            loop {
                ticker.tick().await;
                // A single failed discovery cycle (e.g. swarm temporarily
                // busy) must not kill the discovery service forever.
                if let Err(error) = networking.lock().await.trigger_peer_discovery() {
                    tracing::error!("peer discovery cycle failed (retrying): {}", error);
                }
            }
        });
    }

    pub fn start_metrics_service(
        &mut self,
        networking: Arc<Mutex<P2PNetwork>>,
        mempool: Arc<Mempool>,
        execution: Arc<Executor>,
        storage: Arc<StorageEngine>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting metrics service");
            let mut ticker = interval(config.metrics_interval);
            loop {
                ticker.tick().await;

                let peer_count = networking.lock().await.peer_count();
                let mempool_metrics = mempool.metrics_snapshot();
                let execution_metrics = execution.execution_metrics();
                // Transient storage read errors must not kill the metrics
                // loop permanently — observability silently disappearing is
                // an operational hazard during incidents.
                let storage_metrics = match storage.get_metrics() {
                    Ok(metrics) => metrics,
                    Err(error) => {
                        tracing::error!("storage metrics collection failed (retrying): {}", error);
                        continue;
                    }
                };
                let tps = execution_metrics.executed_transactions as f64
                    / config.metrics_interval.as_secs_f64().max(1.0);

                crate::metrics::MetricsService::record_peer_count(peer_count);
                crate::metrics::MetricsService::record_mempool_size(mempool_metrics.mempool_size);
                crate::metrics::MetricsService::record_tps(tps);

                info!(
                    "metrics: peers={}, mempool_size={}, tx_rate={}, tps={}, rejected_txs={}, executed_txs={}, executed_blocks={}, gas_used={}, storage={}",
                    peer_count,
                    mempool_metrics.mempool_size,
                    mempool_metrics.transaction_arrival_rate,
                    tps,
                    mempool_metrics.rejected_transactions,
                    execution_metrics.executed_transactions,
                    execution_metrics.executed_blocks,
                    execution_metrics.gas_used,
                    storage_metrics
                );
            }
        });
    }

    /// Periodically syncs block headers using the light-client engine.
    /// On each tick, it looks for a connected peer and runs the header sync
    /// loop - verifying parent-child linkage, BFT quorum signatures, and
    /// ZK validity proofs before accepting each header.
    pub fn start_light_client_sync_service(
        &mut self,
        networking: Arc<Mutex<P2PNetwork>>,
        trusted_header: BlockHeader,
        validator_set: Vec<sxiaum_types::Validator>,
        zk_verification_key: Vec<u8>,
        config: ServiceConfig,
    ) {
        self.spawn(async move {
            info!("starting light-client sync service");
            let mut ticker = interval(config.peer_discovery_interval);
            let mut light_client: Option<LightClient> = None;
            loop {
                ticker.tick().await;

                // Pick the first connected peer as the sync anchor.
                let peer_id = {
                    let net = networking.lock().await;
                    net.peer_store.connected_peers().first().map(|p| p.peer_id)
                };

                let Some(peer_id) = peer_id else {
                    // No peers yet - wait for the next tick.
                    continue;
                };

                let client = match &light_client {
                    Some(client) => {
                        if client.tracking_peer().await != peer_id {
                            client.update_tracking_peer(peer_id).await;
                        }
                        client
                    }
                    None => {
                        let new_client = match LightClient::new_trusted(
                            networking.clone(),
                            peer_id,
                            trusted_header.clone(),
                            validator_set.clone(),
                            zk_verification_key.clone(),
                        ) {
                            Ok(client) => client,
                            Err(error) => {
                                tracing::error!(
                                    "light-client trust initialization failed: {}",
                                    error
                                );
                                return Err(error);
                            }
                        };
                        light_client = Some(new_client);
                        match light_client.as_ref() {
                            Some(c) => c,
                            None => return Ok(()),
                        }
                    }
                };
                if let Err(error) = client.run_sync_loop().await {
                    tracing::warn!("light-client sync error: {}", error);
                }
            }
        });
    }

    pub async fn wait_all(self) {
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

/// Spawns all background service tasks from the node's shared components.
/// Called once from `startup.rs` before entering the main event loop.
///
/// Services spawned here run as independent Tokio tasks and are automatically
/// terminated when the process exits or the runtime shuts down.
pub fn spawn_background_services(node: &crate::node::Node) {
    let config = ServiceConfig::default();
    let mut manager = ServiceManager::new();

    // 1. Networking service - drives the libp2p swarm event loop so that
    //    connection upgrades, DHT queries, and gossip propagation are
    //    continuously processed in the background.
    manager.start_networking_service(node.networking.clone());

    // 2. Mempool service - starts the pool and runs the periodic TTL expiry
    //    sweep so stale transactions are evicted without blocking the event loop.
    manager.start_mempool_service(node.mempool.clone());

    // 3. Block production service - polls the mempool and fires a
    //    ConsensusEvent::TriggerProposal when there is work available, prompting
    //    the node to attempt a block proposal if it is the current leader.
    manager.start_block_production_service(
        node.mempool.clone(),
        node.event_sender(),
        config.clone(),
    );

    // 5. State pruning service - periodically trims old state-trie snapshots
    //    to keep on-disk storage bounded as the chain grows.
    manager.start_state_pruning_service(node.state.clone(), config.clone());

    // 6. Peer discovery service - triggers Kademlia lookups on a timer so
    //    the node continuously expands its peer table without manual bootstrapping.
    manager.start_peer_discovery_service(node.networking.clone(), config.clone());

    // 7. Metrics service - collects and logs peer count, mempool stats,
    //    execution counters, and storage statistics on every metrics interval.
    manager.start_metrics_service(
        node.networking.clone(),
        node.mempool.clone(),
        node.execution.clone(),
        node.storage.clone(),
        config.clone(),
    );

    if node.config.mode == crate::node::NodeMode::LightClient {
        let trusted_header = match node.storage.get_block_header(0) {
            Ok(Some(header)) => header,
            Ok(None) => {
                tracing::error!("light-client sync disabled: canonical genesis header is missing");
                return;
            }
            Err(error) => {
                tracing::error!(
                    "light-client sync disabled: failed to load genesis: {}",
                    error
                );
                return;
            }
        };
        let zk_verification_key =
            match sxiaum_light_client::HeaderVerifier::load_zk_verification_key() {
                Ok(key) => key,
                Err(error) => {
                    tracing::error!("light-client sync disabled: {}", error);
                    return;
                }
            };
        manager.start_light_client_sync_service(
            node.networking.clone(),
            trusted_header,
            node.config.genesis_validators.clone(),
            zk_verification_key,
            config,
        );
    }

    // Background tasks are running independently. The node's main event loop
    // (run_event_loop) is the primary blocking point - we do not await here.
}
