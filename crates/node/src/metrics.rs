use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Point-in-time snapshot of all five tracked node metrics.
///
/// | Field | Metric | Gauge/Histogram |
/// |---|---|---|
/// | `current_block_height` | Track 1: block height | gauge |
/// | `connected_peers` | Track 2: peer count | gauge |
/// | `mempool_size` | Track 3: mempool size | gauge |
/// | `last_block_production_time_ms` | Track 4: block production time | histogram |
/// | `average_consensus_latency_ms` | Track 5: consensus latency | histogram |
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NodeMetrics {
    /// Track 1 - current canonical chain height.
    pub current_block_height: u64,
    /// Track 2 - number of peers currently connected via libp2p.
    pub connected_peers: usize,
    /// Track 3 - number of transactions waiting in the mempool.
    pub mempool_size: usize,
    /// Track 4 - wall-clock time of the most recent block production attempt.
    pub last_block_production_time_ms: u64,
    /// Track 5 - rolling average time between vote submission and block
    ///           finalization, in milliseconds.
    pub average_consensus_latency_ms: u64,
    /// Total cumulative transaction count for informational logging.
    pub total_transactions_processed: u64,
}

impl NodeMetrics {
    /// Refresh all five metrics from the live node subsystems.
    pub async fn update_from_node(&mut self, node: &crate::node::Node) {
        // Track 1: block height
        self.current_block_height = node.storage.latest_block_height().unwrap_or(0);
        // Track 2: peer count
        self.connected_peers = node.networking.lock().await.peer_count();
        // Track 3: mempool size
        self.mempool_size = node.mempool.pending_count().unwrap_or(0);
        // Tracks 4 and 5 are updated by specific events via MetricsService.
    }
}

/// Stateless helper that pushes named metric observations into the `metrics`
/// crate backend (Prometheus-compatible).  Each `record_*` call maps to one
/// of the five tracked metrics.
pub struct MetricsService;

impl MetricsService {
    pub fn record_tps(tps: f64) {
        metrics::gauge!("node.tps").set(tps);
    }

    /// Track 1 - record the current canonical block height.
    ///
    /// Called from the event loop on every consensus tick so the gauge
    /// reflects the latest committed height without polling.
    pub fn record_block_height(height: u64) {
        metrics::gauge!("node.block_height").set(height as f64);
    }

    /// Track 2 - record the number of connected P2P peers.
    ///
    /// Updated after every peer-store change and on the metrics-service timer.
    pub fn record_peer_count(count: usize) {
        metrics::gauge!("node.peer_count").set(count as f64);
    }

    /// Track 3 - record the current mempool transaction count.
    ///
    /// Sampled after every `add_transaction` / `remove_transaction` cycle and
    /// on the metrics-service timer.
    pub fn record_mempool_size(size: usize) {
        metrics::gauge!("node.mempool_size").set(size as f64);
    }

    /// Track 4 - record the wall-clock duration of a block production attempt.
    ///
    /// Measured from just before `provide_transactions_to_block_proposer` to
    /// just after the P2P broadcast completes.  Exposed as a histogram so
    /// p50/p95/p99 latencies are visible in Prometheus.
    pub fn record_block_production_time(duration: Duration) {
        metrics::histogram!("node.block_production_time_ms").record(duration.as_millis() as f64);
    }

    /// Track 5 - record the consensus round latency.
    ///
    /// Measured from the moment a `ConsensusEvent::Vote` is received to the
    /// moment a new block is finalized as a result of that vote forming a QC.
    /// High values indicate slow quorum formation or network partitions.
    pub fn record_consensus_latency(duration: Duration) {
        metrics::histogram!("node.consensus_latency_ms").record(duration.as_millis() as f64);
    }
}
