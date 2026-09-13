use metrics::{counter, gauge, histogram};
use std::time::Instant;

/// Comprehensive Prometheus/OpenTelemetry metrics for tracking block production
/// and consensus performance.
///
/// All recorders are no-ops until a metrics recorder is installed by the node
/// binary; consensus code can call these unconditionally.
pub struct ConsensusMetrics;

impl ConsensusMetrics {
    /// Track a successfully produced block.
    pub fn record_block_mined(height: u64, proposer: &str) {
        counter!("sxiaum_blocks_produced_total", "proposer" => proposer.to_string()).increment(1);
        gauge!("sxiaum_chain_head_height").set(height as f64);
    }

    /// Record the latency between view starts and block finalization.
    pub fn record_consensus_latency(view: u64, start_time: Instant) {
        let duration = start_time.elapsed();
        histogram!("sxiaum_consensus_latency_seconds", "view" => view.to_string())
            .record(duration.as_secs_f64());
    }

    /// Record a timeout event in the HotStuff view.
    pub fn record_view_timeout(view: u64) {
        counter!("sxiaum_consensus_timeouts_total", "view" => view.to_string()).increment(1);
    }

    /// Track the current number of active validators.
    pub fn record_validator_count(count: usize) {
        gauge!("sxiaum_validators_active_count").set(count as f64);
    }

    /// Track a validator's consecutive missed blocks.
    pub fn record_validator_missed_block(validator: &str, missed_count: u64) {
        gauge!("sxiaum_validator_missed_blocks_consecutive", "validator" => validator.to_string())
            .set(missed_count as f64);
    }

    /// Track fast-path optimistic commits.
    pub fn record_fast_path_commit(view: u64) {
        counter!("sxiaum_consensus_fast_path_commits_total", "view" => view.to_string())
            .increment(1);
    }

    /// Track verified slashing events.
    pub fn record_slashing_event(kind: &str) {
        counter!("sxiaum_consensus_slashing_events_total", "kind" => kind.to_string()).increment(1);
    }

    /// Track upgrade activations.
    pub fn record_upgrade_activation(version: &str) {
        counter!("sxiaum_consensus_upgrades_activated_total", "version" => version.to_string())
            .increment(1);
    }
}
