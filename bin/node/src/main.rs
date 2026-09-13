use clap::Parser;
use std::path::PathBuf;
use sxiaum_node::Startup;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "sxiaum",
    author,
    version,
    about = "SXIAUM L1 Node binary",
    long_about = "SXIAUM Layer-1 high-throughput blockchain node supporting HotStuff BFT, Parallel EVM execution, and MEV-resistant mempool."
)]
struct Args {
    /// Path to the node configuration file (e.g., config/node.json)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Override the log level (default: info, or uses RUST_LOG)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize tracing/logging with comprehensive module filtering and RUST_LOG override support
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!(
            "sxiaum={},sxiaum_node={},sxiaum_consensus={},sxiaum_execution={},sxiaum_mempool={},sxiaum_storage={},sxiaum_networking={},sxiaum_rpc={},sxiaum_state={}",
            args.log_level,
            args.log_level,
            args.log_level,
            args.log_level,
            args.log_level,
            args.log_level,
            args.log_level,
            args.log_level,
            args.log_level
        ))
    });
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    info!(
        "SXIAUM L1 Node v{} starting up...",
        env!("CARGO_PKG_VERSION")
    );

    // Convert Option<PathBuf> to Option<&str> for bootstrap_node and execute
    let config_path = args.config.as_ref().and_then(|p| p.to_str());
    let mut node = Startup::bootstrap_node(config_path).await?;

    info!("Bootstrap complete. Entering main event loop.");
    Startup::start_node_event_loop(&mut node).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_default_parsing() {
        let args = Args::parse_from(["sxiaum"]);
        assert!(args.config.is_none());
        assert_eq!(args.log_level, "info");
    }

    #[test]
    fn test_args_custom_config_and_log_level() {
        let args = Args::parse_from([
            "sxiaum",
            "--config",
            "custom/path.json",
            "--log-level",
            "debug",
        ]);
        assert_eq!(args.config, Some(PathBuf::from("custom/path.json")));
        assert_eq!(args.log_level, "debug");
    }
}
