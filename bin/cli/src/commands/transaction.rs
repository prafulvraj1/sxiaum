use crate::{commands::wallet, keystore::AddressBook, ui, units, utils, TransactionCommands};
use anyhow::Result;
use comfy_table::{Attribute, Cell, Color, Table};
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::io::{self, Write};
use std::time::Duration;
use tokio::time::sleep;
use zeroize::Zeroize;

/// Tokens above this threshold trigger a large-value warning (10,000 SXI)
const LARGE_AMOUNT_THRESHOLD_ASX: u128 = 10_000 * units::ASX_PER_SX;

pub async fn handle_transaction_command(rpc_url: &str, action: TransactionCommands) -> Result<()> {
    let client = reqwest::Client::new();

    match action {
        TransactionCommands::Send {
            from,
            to,
            value,

            wallet: wallet_alias,
            nonce,
            gas,
            yes,
        } => {
            // - Resolve address book entries -
            let ab_path = wallet::address_book_path()?;
            let ab = AddressBook::load(&ab_path).unwrap_or_default();
            let resolved_to = ab.resolve(&to).to_string();

            // - Resolve private key (wallet alias - encrypted - password) -
            let mut pk = if let Some(alias) = wallet_alias {
                wallet::unlock_key(&alias)?
            } else {
                anyhow::bail!("Must provide a --wallet <alias> to sign the transaction");
            };

            // - Derive sender address if not supplied -
            let from_addr = if from.is_empty() {
                let seed = utils::parse_hex32(&format!("0x{}", pk))?;
                let signing_key = SigningKey::from_bytes(&seed);
                let vk = ed25519_dalek::VerifyingKey::from(&signing_key);
                let address = sxiaum_types::Address::from_public_key(vk.as_bytes());
                format!("0x{}", hex::encode(address.0))
            } else {
                from
            };

            let result = send_transaction(
                &client,
                rpc_url,
                &from_addr,
                &resolved_to,
                &value,
                &pk,
                nonce,
                gas,
                yes,
            )
            .await;

            // Always zeroize the private key from memory
            pk.zeroize();
            result?;
        }

        TransactionCommands::Status {
            hash,
            poll_interval,
            poll_max,
        } => {
            check_transaction_status(&client, rpc_url, &hash, poll_interval, poll_max).await?;
        }

        TransactionCommands::Pending { limit } => {
            get_pending_transactions(&client, rpc_url, limit).await?;
        }
    }

    Ok(())
}

// - Send transaction -

#[allow(clippy::too_many_arguments)]
async fn send_transaction(
    client: &reqwest::Client,
    rpc_url: &str,
    from: &str,
    to: &str,
    value: &str,
    private_key: &str,
    nonce: u64,
    gas: u64,
    skip_confirm: bool,
) -> Result<()> {
    // Parse addresses
    let from_addr: sxiaum_types::Address = std::str::FromStr::from_str(from).map_err(|_| {
        anyhow::anyhow!(
            "Invalid sender address: {}. Must be valid 20-byte or 32-byte hex.",
            from
        )
    })?;
    let to_addr: sxiaum_types::Address = std::str::FromStr::from_str(to).map_err(|_| {
        anyhow::anyhow!(
            "Invalid recipient address: {}. Check address book or spelling.",
            to
        )
    })?;

    // Parse value - accepts plain aSXI or "1.5SX"
    let value_asx = units::parse_value(value)?;

    // - Transaction summary table -
    println!();
    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("Field").add_attribute(Attribute::Bold),
            Cell::new("Value").add_attribute(Attribute::Bold),
        ])
        .add_row(vec![
            Cell::new("From").fg(Color::DarkGrey),
            Cell::new(from).fg(Color::Yellow),
        ])
        .add_row(vec![
            Cell::new("To").fg(Color::DarkGrey),
            Cell::new(to).fg(Color::Magenta),
        ])
        .add_row(vec![
            Cell::new("Amount (aSXI)").fg(Color::DarkGrey),
            Cell::new(value_asx.to_string()),
        ])
        .add_row(vec![
            Cell::new("Amount (SXI)").fg(Color::DarkGrey),
            Cell::new(units::format_sx_compact(value_asx))
                .fg(Color::Green)
                .add_attribute(Attribute::Bold),
        ])
        .add_row(vec![
            Cell::new("Gas limit").fg(Color::DarkGrey),
            Cell::new(gas.to_string()),
        ])
        .add_row(vec![
            Cell::new("Nonce").fg(Color::DarkGrey),
            Cell::new(nonce.to_string()),
        ]);

    println!("{}\n", table);

    // - Large-amount warning -
    if value_asx >= LARGE_AMOUNT_THRESHOLD_ASX {
        println!();
        println!("  -");
        println!("  -  -  LARGE TRANSACTION WARNING                           -");
        println!(
            "  -  You are sending {:<30} SXI                      -",
            units::format_sx_compact(value_asx)
        );
        println!("  -  Blockchain transactions are IRREVERSIBLE.               -");
        println!("  -");
        println!();
    }

    // - Recipient self-send warning -
    if from.eq_ignore_ascii_case(to) {
        ui::print_warning("Sender and recipient are the same address (self-transfer).");
    }

    // - Confirmation prompt -
    if !skip_confirm {
        print!("  Confirm transaction? [yes/N]: ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        if input != "yes" && input != "y" {
            ui::print_warning("Transaction cancelled.");
            return Ok(());
        }
    }

    println!();
    let pb = ui::create_spinner("Signing with Ed25519...");
    let seed = utils::parse_hex32(&format!("0x{}", private_key))?;
    let signing_key = SigningKey::from_bytes(&seed);

    let mut tx_obj = sxiaum_types::Transaction::new_transfer(
        from_addr,
        to_addr,
        primitive_types::U256::from(value_asx),
        nonce,
    );
    tx_obj.gas_limit = gas;
    tx_obj.sign(&signing_key)?;

    let tx = serde_json::to_value(&tx_obj)?;
    pb.set_message("Submitting to RPC endpoint...");

    let response_result =
        utils::call_rpc(client, rpc_url, "sxiaum_sendTransaction", vec![tx]).await;

    let tx_hash = match response_result {
        Ok(response) => {
            if let Some(s) = response.as_str() {
                s.to_string()
            } else if let Some(obj) = response.as_object() {
                obj.get("txHash")
                    .or_else(|| obj.get("tx_hash"))
                    .or_else(|| obj.get("hash"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else if let Some(arr) = response.as_array() {
                let bytes: Vec<u8> = arr
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();
                format!("0x{}", hex::encode(bytes))
            } else {
                response.to_string().trim_matches('"').to_string()
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("duplicate transaction") || err_str.contains("already submitted") {
                let hash = tx_obj.try_hash()?;
                let hash_str = format!("0x{}", hex::encode(hash));
                pb.finish_and_clear();
                ui::print_warning(&format!("Already in mempool. Hash: {}", hash_str));
                hash_str
            } else {
                pb.finish_and_clear();
                return Err(e);
            }
        }
    };

    pb.finish_and_clear();
    ui::print_success(&format!("Transaction submitted! Hash: {}", tx_hash));

    // Auto poll for confirmation
    check_transaction_status(client, rpc_url, &tx_hash, 1, 20).await?;
    Ok(())
}

// - Transaction status -

async fn check_transaction_status(
    client: &reqwest::Client,
    rpc_url: &str,
    hash: &str,
    poll_interval: u64,
    poll_max: u32,
) -> Result<()> {
    let mut poll_count = 0u32;
    let pb = ui::create_spinner(&format!("Waiting for finalization of {}...", hash));

    loop {
        poll_count += 1;

        let response = utils::call_rpc(
            client,
            rpc_url,
            "sxiaum_getTransactionReceipt",
            vec![json!(hash)],
        )
        .await
        .ok();

        if let Some(resp) = response.filter(|v| !v.is_null()) {
            pb.finish_and_clear();
            ui::print_success(&format!("Transaction finalized: {}", hash));

            let status = resp["status"].as_bool().unwrap_or(false);
            let gas_used = resp["gas_used"].as_u64().unwrap_or(0);
            let block_height = resp["block_height"].as_u64();

            let mut table = Table::new();
            table
                .load_preset(comfy_table::presets::UTF8_FULL)
                .set_header(vec![
                    Cell::new("Field").add_attribute(Attribute::Bold),
                    Cell::new("Value").add_attribute(Attribute::Bold),
                ])
                .add_row(vec![
                    Cell::new("Status"),
                    if status {
                        Cell::new("-  Success")
                            .fg(Color::Green)
                            .add_attribute(Attribute::Bold)
                    } else {
                        Cell::new("-  Failed")
                            .fg(Color::Red)
                            .add_attribute(Attribute::Bold)
                    },
                ])
                .add_row(vec![Cell::new("Gas used"), Cell::new(gas_used.to_string())]);

            if let Some(h) = block_height {
                table.add_row(vec![
                    Cell::new("Block"),
                    Cell::new(format!("#{}", h)).fg(Color::Cyan),
                ]);
            }

            println!("\n{}\n", table);
            return Ok(());
        }

        if poll_interval > 0 && poll_count < poll_max {
            pb.set_message(format!("Pending... ({}/{})", poll_count, poll_max));
            sleep(Duration::from_secs(poll_interval)).await;
        } else {
            break;
        }
    }

    pb.finish_and_clear();
    ui::print_warning(&format!(
        "TX still pending. Check later: transaction status {}",
        hash
    ));
    Ok(())
}

// - Pending transactions -

async fn get_pending_transactions(
    client: &reqwest::Client,
    rpc_url: &str,
    limit: usize,
) -> Result<()> {
    let pb = ui::create_spinner("Fetching mempool...");
    let response = utils::call_rpc(
        client,
        rpc_url,
        "sxiaum_getPendingTransactions",
        vec![json!(limit)],
    )
    .await?;
    pb.finish_and_clear();

    if let Some(txs) = response.as_array() {
        if txs.is_empty() {
            ui::print_info("Mempool is empty.");
            return Ok(());
        }

        let mut table = Table::new();
        table
            .load_preset(comfy_table::presets::UTF8_FULL)
            .set_header(vec![
                Cell::new("#").add_attribute(Attribute::Bold),
                Cell::new("Hash").add_attribute(Attribute::Bold),
                Cell::new("From").add_attribute(Attribute::Bold),
                Cell::new("To").add_attribute(Attribute::Bold),
                Cell::new("Amount (SXI)")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Cyan),
                Cell::new("Nonce").add_attribute(Attribute::Bold),
            ]);

        for (idx, tx) in txs.iter().enumerate() {
            let hash = tx["hash"].as_str().unwrap_or("?");
            let from = tx["from"].as_str().unwrap_or("?");
            let to = tx["to"].as_str().unwrap_or("?");
            let value_asx: u128 = tx["value"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let nonce = tx["nonce"].as_u64().unwrap_or(0);

            table.add_row(vec![
                Cell::new(idx + 1),
                Cell::new(hash).fg(Color::Yellow),
                Cell::new(from),
                Cell::new(to),
                Cell::new(units::format_sx_compact(value_asx)).fg(Color::Green),
                Cell::new(nonce.to_string()),
            ]);
        }

        println!("\n{}\n", table);
        ui::print_info(&format!("{} pending transaction(s)", txs.len()));
    } else {
        ui::print_info("Mempool is empty.");
    }

    Ok(())
}
