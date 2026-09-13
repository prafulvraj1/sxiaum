use crate::NodeCommands;
use anyhow::Result;
use std::path::PathBuf;

pub async fn handle_node_command(action: NodeCommands) -> Result<()> {
    match action {
        NodeCommands::Start { config, log_level } => {
            start_node(config, log_level).await?;
        }
        NodeCommands::Status => {
            show_status().await?;
        }
        NodeCommands::Peers => {
            show_peers().await?;
        }
    }
    Ok(())
}

async fn start_node(config: Option<PathBuf>, log_level: Option<String>) -> Result<()> {
    let config_path = config.unwrap_or_else(|| PathBuf::from("configs/mainnet.json"));
    let log_level_str = log_level.unwrap_or_else(|| "info".to_string());

    println!("-  Starting SXIAUM Node");
    println!("-");
    println!("Config file: {}", config_path.display());
    println!("Log level:   {}", log_level_str);
    println!();

    // Locate and actually spawn the node binary, inheriting stdio so the
    // operator watches live logs. The previous implementation printed
    // "Launching the node process..." but never launched anything.
    let target_dir = if cfg!(debug_assertions) {
        "target/debug"
    } else {
        "target/release"
    };

    let node_binary = if cfg!(windows) {
        format!("{}\\sxiaum.exe", target_dir)
    } else {
        format!("{}/sxiaum", target_dir)
    };

    if !std::path::Path::new(&node_binary).exists() {
        println!("-  Node binary not found at: {}", node_binary);
        println!("Build the project first with: cargo build --release");
        return Ok(());
    }

    println!(
        "- Spawning node: {} --config {}",
        node_binary,
        config_path.display()
    );
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(&node_binary)
            .arg("--config")
            .arg(&config_path)
            .env("RUST_LOG", format!("sxiaum={}", log_level_str))
            .status()
    })
    .await??;

    if !status.success() {
        anyhow::bail!("node process exited with status {}", status);
    }
    Ok(())
}

async fn show_status() -> Result<()> {
    let client = reqwest::Client::new();
    let rpc_url = "http://127.0.0.1:8080/rpc";

    println!("- SXIAUM Node Status");
    println!("-");

    // Try to connect
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "sxiaum_getStateRoot",
        "params": [],
        "id": 1
    });

    match client.post(rpc_url).json(&payload).send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(result) => {
                println!("- Node is running!");
                println!("RPC URL: {}", rpc_url);
                if let Some(state_root) = result.get("result") {
                    println!("State Root: {}", state_root);
                }
            }
            Err(_) => {
                println!("- Node is not responding properly");
            }
        },
        Err(_) => {
            println!("- Cannot connect to node");
            println!("- RPC URL: {}", rpc_url);
            println!("- Make sure the node is running: sxiaumcli node start");
        }
    }

    Ok(())
}

async fn show_peers() -> Result<()> {
    let client = reqwest::Client::new();
    let rpc_url = "http://127.0.0.1:8080/rpc";

    println!("- Network Peers");
    println!("-");

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "sxiaum_peerCount",
        "params": [],
        "id": 1
    });

    match client.post(rpc_url).json(&payload).send().await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(result) => {
                if let Some(peers) = result.get("result") {
                    println!("Connected Peers: {}", peers);
                }
            }
            Err(_) => {
                println!("- Failed to fetch peer count");
            }
        },
        Err(_) => {
            println!("- Cannot connect to RPC endpoint at {}", rpc_url);
        }
    }

    Ok(())
}
