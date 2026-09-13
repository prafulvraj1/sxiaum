use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::OnceLock;
use std::time::Instant;

/// Global handle to the Prometheus recorder, set once during initialization.
static PROMETHEUS_HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Initialize the global Prometheus recorder.
///
/// Must be called once at startup before any metrics are recorded.
/// Subsequent calls are no-ops.
///
/// Correctness note: `install_recorder()` builds the recorder, installs it as
/// the GLOBAL recorder, and returns the matching render handle in one step.
/// The previous implementation built TWO independent recorders and stored the
/// handle of the never-installed one, so `/metrics` rendered an empty scrape
/// forever while all recorded metrics went into the second (installed)
/// recorder with no readable handle.
pub fn init_metrics_recorder() {
    if PROMETHEUS_HANDLE.get().is_some() {
        return;
    }
    match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            let _ = PROMETHEUS_HANDLE.set(handle);
        }
        Err(err) => {
            // A global recorder may already be installed by another crate
            // (e.g., the node binary). Metrics stay functional through that
            // recorder; rendering falls back to the not-initialized notice.
            tracing::warn!("failed to install Prometheus recorder: {}", err);
        }
    }
}

/// Track a new incoming RPC request by method name.
pub fn record_request(method: &str) {
    counter!("rpc_requests_total", "method" => method.to_string()).increment(1);
}

/// Track a failed RPC request with specific method and error code labels.
pub fn record_error(method: &str, code: i32) {
    counter!(
        "rpc_requests_failed_total",
        "method" => method.to_string(),
        "code" => code.to_string()
    )
    .increment(1);
}

/// Record the latency of a successful RPC response into a histogram.
pub fn record_latency(method: &str, start_time: Instant) {
    let duration = start_time.elapsed();
    histogram!(
        "rpc_request_duration_seconds",
        "method" => method.to_string()
    )
    .record(duration.as_secs_f64());
}

/// Export current metrics as a Prometheus-formatted string for the `/metrics` endpoint.
pub fn render_metrics() -> String {
    PROMETHEUS_HANDLE
        .get()
        .map(|h| h.render())
        .unwrap_or_else(|| "# metrics recorder not initialized\n".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_recorder_renders_recorded_metrics() {
        init_metrics_recorder();
        counter!("rpc_test_counter_total", "method" => "probe").increment(1);
        let rendered = render_metrics();
        assert!(
            rendered.contains("rpc_test_counter_total"),
            "recorder must be installed and render recorded metrics"
        );
    }
}
