use crate::node::Node;
use anyhow::Result;
use tracing::info;

pub struct Shutdown;

impl Shutdown {
    /// Perform a graceful shutdown of all node services and persist final state.
    pub async fn gracefully_stop_node(node: &mut Node) -> Result<()> {
        info!("Initiating graceful shutdown of SXIAUM node...");
        node.stop().await
    }

    /// Higher-level wrapper for handling OS signals and triggering shutdown.
    pub async fn wait_for_signal_and_shutdown(node: &mut Node) -> Result<()> {
        tokio::signal::ctrl_c().await?;
        info!("Received shutdown signal (Ctrl+C). Starting cleanup...");
        Self::gracefully_stop_node(node).await
    }
}
