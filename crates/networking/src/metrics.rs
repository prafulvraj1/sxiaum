use metrics::{counter, gauge, histogram};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Internal sliding-window counters backing honest per-second message rates.
///
/// The previous implementation recorded a hardcoded `1.0` messages/second
/// gauge, which made the metric meaningless for monitoring. Rates are now
/// computed from real per-topic arrival counts over 1-second windows.
static RATE_TRACKERS: Mutex<Option<HashMap<String, (u64, u64)>>> = Mutex::new(None);

fn compute_rate(topic: &str, direction: &str, count: u64, now_secs: u64) -> f64 {
    let key = format!("{direction}:{topic}");
    let mut guard = RATE_TRACKERS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    let entry = map.entry(key).or_insert((now_secs, 0));
    if now_secs > entry.0 {
        // Window rolled over: rate is what accumulated in the previous window.
        let rate = entry.1 as f64 / (now_secs - entry.0) as f64;
        *entry = (now_secs, count.min(u64::MAX - count));
        return rate;
    }
    entry.1 = entry.1.saturating_add(count);
    // Within the same window: report the running total so far.
    entry.1 as f64
}

/// Metrics for tracking P2P connectivity and peer health.
pub struct NetworkingMetrics;

impl NetworkingMetrics {
    /// Update the current number of active P2P peers.
    pub fn update_peer_count(count: usize) {
        gauge!("sxiaum_p2p_peers_connected").set(count as f64);
    }

    /// Record a successfully established inbound/outbound P2P connection.
    pub fn record_connection(direction: &str) {
        counter!("sxiaum_p2p_connections_total", "direction" => direction.to_string()).increment(1);
    }

    /// Record a disconnected peer with a failure reason.
    pub fn record_disconnection(reason: &str) {
        counter!("sxiaum_p2p_disconnections_total", "reason" => reason.to_string()).increment(1);
    }

    /// Record the number of messages handled for a topic and direction and
    /// update the derived messages-per-second gauge from real arrival counts.
    pub fn record_messages(direction: &str, topic: &str, count: u64) {
        counter!(
            "sxiaum_p2p_messages_total",
            "direction" => direction.to_string(),
            "topic" => topic.to_string()
        )
        .increment(count);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let rate = compute_rate(topic, direction, count, now);
        Self::record_messages_per_second(direction, topic, rate);
    }

    /// Record an externally measured messages-per-second rate for a topic.
    pub fn record_messages_per_second(direction: &str, topic: &str, messages_per_second: f64) {
        gauge!(
            "sxiaum_p2p_messages_per_second",
            "direction" => direction.to_string(),
            "topic" => topic.to_string()
        )
        .set(messages_per_second);
    }

    /// Record total bandwidth usage in bytes.
    pub fn record_bandwidth(direction: &str, bytes: u64) {
        counter!(
            "sxiaum_p2p_bandwidth_bytes_total",
            "direction" => direction.to_string()
        )
        .increment(bytes);
    }

    /// Record end-to-end gossip propagation latency.
    pub fn record_gossip_propagation_latency(topic: &str, latency: Duration) {
        histogram!(
            "sxiaum_p2p_gossip_propagation_latency_seconds",
            "topic" => topic.to_string()
        )
        .record(latency.as_secs_f64());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_second_rate_accumulates_within_window() {
        let topic = "test-topic-rate";
        let base = 1_700_000_000u64;
        let r1 = compute_rate(topic, "inbound", 5, base);
        assert!((r1 - 5.0).abs() < f64::EPSILON);
        let r2 = compute_rate(topic, "inbound", 3, base);
        assert!((r2 - 8.0).abs() < f64::EPSILON);

        // New window: rate reflects previous window's total spread over elapsed secs.
        let r3 = compute_rate(topic, "inbound", 2, base + 4);
        assert!((r3 - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rates_are_tracked_per_topic_and_direction() {
        let base = 1_700_000_100u64;
        let a = compute_rate("topic-a", "outbound", 7, base);
        let b = compute_rate("topic-b", "outbound", 9, base);
        assert!((a - 7.0).abs() < f64::EPSILON);
        assert!((b - 9.0).abs() < f64::EPSILON);
        // Same topic, different direction: independent tracker.
        let c = compute_rate("topic-a", "inbound", 11, base);
        assert!((c - 11.0).abs() < f64::EPSILON);
    }
}
