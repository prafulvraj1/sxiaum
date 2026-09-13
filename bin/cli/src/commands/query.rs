use crate::{ui, units, utils};
use anyhow::Result;
use comfy_table::{Attribute, Cell, Color, Table};
use serde_json::json;

pub async fn query_balance(client: &reqwest::Client, url: &str, address: &str) -> Result<()> {
    let pb = ui::create_spinner("Fetching balance from chain...");
    let response = utils::call_rpc(client, url, "sxiaum_getBalance", vec![json!(address)]).await?;
    pb.finish_and_clear();

    // RPC returns a decimal string of the raw aSXI balance (U256). Prefer the
    // full string for display; compact SXI formatting uses u128 when it fits.
    let balance_str = if let Some(s) = response.as_str() {
        s.trim().to_string()
    } else if let Some(n) = response.as_u64() {
        n.to_string()
    } else {
        response.to_string().trim_matches('"').to_string()
    };

    let sx_display = balance_str
        .parse::<u128>()
        .map(units::format_sx_compact)
        .unwrap_or_else(|_| format!("{} aSXI", balance_str));

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("Address").add_attribute(Attribute::Bold),
            Cell::new("Balance (aSXI)").add_attribute(Attribute::Bold),
            Cell::new("Balance (SXI)")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ])
        .add_row(vec![
            Cell::new(address),
            Cell::new(&balance_str),
            Cell::new(sx_display).fg(Color::Green),
        ]);

    println!("\n{}\n", table);
    Ok(())
}

pub async fn query_nonce(client: &reqwest::Client, url: &str, address: &str) -> Result<()> {
    let pb = ui::create_spinner("Fetching nonce...");
    let response = utils::call_rpc(client, url, "sxiaum_getNonce", vec![json!(address)]).await?;
    pb.finish_and_clear();

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("Address").add_attribute(Attribute::Bold),
            Cell::new("Nonce").add_attribute(Attribute::Bold),
        ])
        .add_row(vec![address, &response.to_string()]);

    println!("\n{}\n", table);
    Ok(())
}

pub async fn query_block(client: &reqwest::Client, url: &str, height: u64) -> Result<()> {
    let pb = ui::create_spinner(&format!("Fetching block #{}...", height));
    let response = utils::call_rpc(
        client,
        url,
        "sxiaum_getBlockByNumber",
        vec![json!(format!("0x{:x}", height))],
    )
    .await?;
    pb.finish_and_clear();

    if response.is_null() {
        ui::print_error(&format!("Block #{} not found", height));
        return Ok(());
    }

    let header = response.get("header").unwrap_or(&response);
    let body = response.get("body").unwrap_or(&response);

    let hash = response["hash"]
        .as_str()
        .or_else(|| header["hash"].as_str())
        .unwrap_or("unknown");
    let state_root = header["state_root"]
        .as_str()
        .or_else(|| response["state_root"].as_str())
        .unwrap_or("unknown");
    let parent_hash = header["parent_hash"]
        .as_str()
        .or_else(|| response["parent_hash"].as_str())
        .unwrap_or("unknown");
    let txs = body["transactions"]
        .as_array()
        .or_else(|| response["transactions"].as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let gas_used = response["gas_used"]
        .as_u64()
        .or_else(|| header["gas_used"].as_u64())
        .unwrap_or(0);
    let timestamp = header["timestamp"]
        .as_u64()
        .or_else(|| response["timestamp"].as_u64())
        .unwrap_or(0);

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("Property").add_attribute(Attribute::Bold),
            Cell::new("Value").add_attribute(Attribute::Bold),
        ])
        .add_row(vec![
            Cell::new("Height").fg(Color::Yellow),
            Cell::new(height.to_string()).add_attribute(Attribute::Bold),
        ])
        .add_row(vec![
            Cell::new("Block Hash").fg(Color::Yellow),
            Cell::new(hash),
        ])
        .add_row(vec![
            Cell::new("Parent Hash").fg(Color::Yellow),
            Cell::new(parent_hash),
        ])
        .add_row(vec![
            Cell::new("State Root").fg(Color::Yellow),
            Cell::new(state_root),
        ])
        .add_row(vec![
            Cell::new("Transactions").fg(Color::Yellow),
            Cell::new(txs.to_string()).fg(Color::Cyan),
        ])
        .add_row(vec![
            Cell::new("Gas Used").fg(Color::Yellow),
            Cell::new(gas_used.to_string()),
        ])
        .add_row(vec![
            Cell::new("Timestamp").fg(Color::Yellow),
            Cell::new(if timestamp > 0 {
                chrono::DateTime::from_timestamp(timestamp as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| timestamp.to_string())
            } else {
                "N/A".to_string()
            }),
        ]);

    println!("\n{}\n", table);
    Ok(())
}

pub async fn query_state_root(client: &reqwest::Client, url: &str) -> Result<()> {
    let pb = ui::create_spinner("Fetching state root...");
    let response = utils::call_rpc(client, url, "sxiaum_getStateRoot", vec![]).await?;
    pb.finish_and_clear();
    ui::print_info(&format!("State Root: {}", response));
    Ok(())
}
