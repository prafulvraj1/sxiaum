use crate::{
    keystore::{self, AddressBook, KeystoreV2, WalletPayload},
    ui, units, utils,
};
use anyhow::{bail, Context, Result};
use comfy_table::{Attribute, Cell, Color, Table};
use directories::ProjectDirs;
use std::path::PathBuf;

// - Path helpers -

pub fn keystore_path() -> Result<PathBuf> {
    proj_dirs().map(|d| d.data_dir().join("wallet.enc.json"))
}

pub fn address_book_path() -> Result<PathBuf> {
    proj_dirs().map(|d| d.data_dir().join("address_book.json"))
}

fn proj_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("", "SXIAUM", "sxiaum-cli")
        .ok_or_else(|| anyhow::anyhow!("Cannot determine local data directory"))
}

// - Password helpers -

/// Prompt for an existing wallet password (single prompt, no confirm).
pub fn prompt_password_open(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(format!("- {} ", prompt))?)
}

/// Prompt for a new wallet password with confirmation.
fn prompt_password_new() -> Result<String> {
    loop {
        let pw1 = rpassword::prompt_password("- New wallet password: ")?;
        if let Err(e) = sxiaum_keystore::password::validate_password(&pw1) {
            ui::print_error(&format!("Password policy: {e}"));
            continue;
        }
        let pw2 = rpassword::prompt_password("- Confirm password:     ")?;
        if pw1 == pw2 {
            return Ok(pw1);
        }
        ui::print_error("Passwords do not match. Try again.");
    }
}

// - Load / save encrypted wallet -

/// Load and decrypt the wallet. Returns `None` if the file doesn't exist yet.
pub fn load_wallet(password: &str) -> Result<WalletPayload> {
    let path = keystore_path()?;
    if !path.exists() {
        return Ok(WalletPayload::default());
    }
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Cannot read wallet file: {}", path.display()))?;
    let ks: KeystoreV2 = serde_json::from_str(&data)
        .context("Wallet file is corrupted or in an unsupported format")?;
    keystore::decrypt_wallet(&ks, password)
}

/// Encrypt and save the wallet. Always re-encrypts with a fresh salt+nonce.
pub fn save_wallet(payload: &WalletPayload, password: &str) -> Result<()> {
    let path = keystore_path()?;
    let ks = keystore::encrypt_wallet(payload, password).context("Failed to encrypt wallet")?;
    let data = serde_json::to_string_pretty(&ks)?;
    sxiaum_keytool::io::write_secure_file(&path, &data)
        .map_err(|e| anyhow::anyhow!("Failed to write secure wallet file: {e}"))?;
    Ok(())
}

// - Derive address from stored hex private key -

pub fn address_from_pk(pk_hex: &str) -> Result<String> {
    let seed = hex::decode(pk_hex)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(
        seed.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
    );
    let vk = ed25519_dalek::VerifyingKey::from(&signing_key);
    let address = sxiaum_types::Address::from_public_key(vk.as_bytes());
    Ok(format!("0x{}", hex::encode(address.0)))
}

// - wallet init -

pub fn init_wallet() -> Result<()> {
    let path = keystore_path()?;
    if path.exists() {
        ui::print_warning("Wallet already exists. Use 'wallet import' to add keys.");
        ui::print_info(&format!("Wallet path: {}", path.display()));
        return Ok(());
    }

    ui::print_section("Creating new encrypted wallet");
    println!("  This wallet is protected with AES-256-GCM encryption.");
    println!("  Your password is never stored - keep it safe!\n");

    let password = prompt_password_new()?;
    let pb = ui::create_spinner("Deriving encryption key with Argon2id...");
    save_wallet(&WalletPayload::default(), &password)?;
    pb.finish_and_clear();

    ui::print_success("Wallet created and encrypted successfully!");
    ui::print_info(&format!("Stored at: {}", path.display()));
    Ok(())
}

// - wallet import -

pub fn import_key(alias: &str, private_key: &str) -> Result<()> {
    let pk_cleaned = private_key.trim_start_matches("0x");
    if pk_cleaned.len() != 64 || hex::decode(pk_cleaned).is_err() {
        ui::print_error(
            "Invalid private key. Must be 32 bytes (64 hex chars), optionally 0x-prefixed.",
        );
        return Ok(());
    }

    let path = keystore_path()?;
    let password = if path.exists() {
        prompt_password_open("Wallet password to unlock:")?
    } else {
        ui::print_section("Creating new encrypted wallet");
        println!("  No wallet found. Creating one now.\n");
        prompt_password_new()?
    };

    let pb = ui::create_spinner("Unlocking wallet...");
    let mut payload = load_wallet(&password)?;
    pb.finish_and_clear();

    let overwriting = payload.keys.contains_key(alias);
    payload
        .keys
        .insert(alias.to_string(), pk_cleaned.to_string());

    let pb = ui::create_spinner("Re-encrypting wallet with fresh nonce...");
    save_wallet(&payload, &password)?;
    pb.finish_and_clear();

    let address = address_from_pk(pk_cleaned)?;
    if overwriting {
        ui::print_warning(&format!("Overwrote existing alias '{}'", alias));
    } else {
        ui::print_success(&format!("Key '{}' imported and encrypted", alias));
    }
    ui::print_info(&format!("Address: {}", address));
    Ok(())
}

// - wallet export -

/// Export a key for `alias`.
///
/// - Prefer `--output <path>`: writes Argon2id + AES-GCM encrypted keystore (no plaintext).
/// - Plaintext stdout is only allowed with `--i-understand-plaintext`.
pub fn export_key(
    alias: &str,
    output: Option<&std::path::Path>,
    allow_plaintext: bool,
) -> Result<()> {
    let password = prompt_password_open("Wallet password:")?;
    let pb = ui::create_spinner("Decrypting wallet...");
    let payload = load_wallet(&password)?;
    pb.finish_and_clear();

    let Some(pk) = payload.keys.get(alias) else {
        ui::print_error(&format!("Alias '{}' not found in wallet", alias));
        return Ok(());
    };

    let address = address_from_pk(pk)?;

    if let Some(path) = output {
        // Re-encrypt under a fresh password for the export file.
        let export_pw = rpassword::prompt_password("New keystore password for export: ")
            .context("failed to read export password")?;
        if let Err(e) = sxiaum_keystore::password::validate_password(&export_pw) {
            bail!("Password policy violation: {e}");
        }
        let confirm = rpassword::prompt_password("Confirm export password: ")
            .context("failed to read confirmation")?;
        if export_pw != confirm {
            bail!("Export passwords do not match");
        }

        let mut single = WalletPayload::default();
        single.keys.insert(alias.to_string(), pk.clone());
        let ks = keystore::encrypt_wallet(&single, &export_pw)?;
        let json = serde_json::to_string_pretty(&ks)?;
        sxiaum_keytool::io::write_secure_file(path, &json)
            .map_err(|e| anyhow::anyhow!("Failed to write secure keystore: {e}"))?;
        ui::print_success(&format!(
            "Encrypted keystore for '{}' written to {}",
            alias,
            path.display()
        ));
        ui::print_info(&format!("Address: {}", address));
        return Ok(());
    }

    let is_prod = std::env::var("SXIAUM_ENV").unwrap_or_default() == "production";
    if is_prod {
        bail!("Plaintext private key export is strictly forbidden when SXIAUM_ENV=production. Use --output <path> instead.");
    }

    if !allow_plaintext {
        bail!(
            "Refusing to print private key to stdout. \
             Use --output <path> for an encrypted keystore, or pass \
             --i-understand-plaintext if you really need raw hex on the terminal."
        );
    }

    println!();
    println!("  *** SENSITIVE — NEVER SHARE YOUR PRIVATE KEY ***");
    println!();
    println!("  Alias:       {}", alias);
    println!("  Address:     {}", address);
    println!("  Private Key: 0x{}", pk);
    println!();
    Ok(())
}

// - wallet remove -

pub fn remove_key(alias: &str) -> Result<()> {
    let password = prompt_password_open("Wallet password to confirm removal:")?;
    let pb = ui::create_spinner("Unlocking wallet...");
    let mut payload = load_wallet(&password)?;
    pb.finish_and_clear();

    if payload.keys.remove(alias).is_some() {
        let pb = ui::create_spinner("Re-encrypting wallet...");
        save_wallet(&payload, &password)?;
        pb.finish_and_clear();
        ui::print_success(&format!(
            "Removed alias '{}' and re-encrypted wallet",
            alias
        ));
    } else {
        ui::print_error(&format!("Alias '{}' not found", alias));
    }
    Ok(())
}

// - wallet change-password -

pub fn change_password() -> Result<()> {
    ui::print_section("Change Wallet Password");
    let old_pw = prompt_password_open("Current password:")?;
    let pb = ui::create_spinner("Verifying current password...");
    let payload = load_wallet(&old_pw)?;
    pb.finish_and_clear();
    ui::print_success("Current password verified.");

    println!();
    let new_pw = prompt_password_new()?;
    let pb = ui::create_spinner("Re-encrypting all keys with new password...");
    save_wallet(&payload, &new_pw)?;
    pb.finish_and_clear();
    ui::print_success("Password changed. Wallet re-encrypted with new password.");
    Ok(())
}

// - wallet list -

pub fn list_keys() -> Result<()> {
    let path = keystore_path()?;
    if !path.exists() {
        ui::print_info("No wallet found. Run 'wallet init' to create one.");
        return Ok(());
    }

    let password = prompt_password_open("Wallet password:")?;
    let pb = ui::create_spinner("Decrypting wallet...");
    let payload = load_wallet(&password)?;
    pb.finish_and_clear();

    if payload.keys.is_empty() {
        ui::print_info("Wallet is empty. Use 'wallet import' to add keys.");
        return Ok(());
    }

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("#").add_attribute(Attribute::Bold),
            Cell::new("Alias").add_attribute(Attribute::Bold),
            Cell::new("Address")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);

    let mut sorted: Vec<(&String, &String)> = payload.keys.iter().collect();
    sorted.sort_by_key(|(alias, _)| alias.as_str());
    for (idx, (alias, pk)) in sorted.iter().enumerate() {
        let address = address_from_pk(pk).unwrap_or_else(|_| "<invalid>".to_string());
        table.add_row(vec![
            Cell::new(idx + 1),
            Cell::new(alias).fg(Color::Yellow),
            Cell::new(&address),
        ]);
    }

    println!("\n{}\n", table);
    ui::print_info(&format!(
        "{} key(s) in encrypted wallet",
        payload.keys.len()
    ));
    ui::print_info(&format!("Keystore: {}", path.display()));
    Ok(())
}

// - wallet balance -

pub async fn show_all_balances(rpc_url: &str) -> Result<()> {
    let path = keystore_path()?;
    if !path.exists() {
        ui::print_info("No wallet found. Run 'wallet init' to create one.");
        return Ok(());
    }

    let password = prompt_password_open("Wallet password:")?;
    let pb = ui::create_spinner("Decrypting wallet...");
    let payload = load_wallet(&password)?;
    pb.finish_and_clear();

    if payload.keys.is_empty() {
        ui::print_info("Wallet is empty - no balances to show.");
        return Ok(());
    }

    let client = reqwest::Client::new();
    let pb = ui::create_spinner("Fetching on-chain balances...");

    let mut sorted: Vec<(&String, &String)> = payload.keys.iter().collect();
    sorted.sort_by_key(|(alias, _)| alias.as_str());

    let mut rows: Vec<(String, String, u128)> = Vec::new();
    for (alias, pk) in &sorted {
        let address = match address_from_pk(pk) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let balance: u128 = utils::call_rpc(
            &client,
            rpc_url,
            "sxiaum_getBalance",
            vec![serde_json::json!(address)],
        )
        .await
        .ok()
        .and_then(|v| {
            if let Some(s) = v.as_str() {
                s.trim().parse::<u128>().ok()
            } else if let Some(n) = v.as_u64() {
                Some(n as u128)
            } else {
                v.to_string().trim_matches('"').parse::<u128>().ok()
            }
        })
        .unwrap_or(0);
        rows.push((alias.to_string(), address, balance));
    }
    pb.finish_and_clear();

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("#").add_attribute(Attribute::Bold),
            Cell::new("Alias").add_attribute(Attribute::Bold),
            Cell::new("Address").add_attribute(Attribute::Bold),
            Cell::new("Balance (SXI)")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);

    let mut total: u128 = 0;
    for (idx, (alias, address, balance)) in rows.iter().enumerate() {
        total = total.saturating_add(*balance);
        table.add_row(vec![
            Cell::new(idx + 1),
            Cell::new(alias).fg(Color::Yellow),
            Cell::new(address),
            Cell::new(units::format_sx_compact(*balance))
                .fg(if *balance > 0 {
                    Color::Green
                } else {
                    Color::DarkGrey
                })
                .add_attribute(Attribute::Bold),
        ]);
    }

    println!("\n{}\n", table);
    ui::print_info(&format!(
        "Total across all wallets: {}",
        units::format_sx_compact(total)
    ));
    Ok(())
}

// - wallet info -

pub fn wallet_info() -> Result<()> {
    let path = keystore_path()?;
    let ab_path = address_book_path()?;

    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("Property").add_attribute(Attribute::Bold),
            Cell::new("Value").add_attribute(Attribute::Bold),
        ]);

    if path.exists() {
        let data = std::fs::read_to_string(&path)?;
        let ks: KeystoreV2 = serde_json::from_str(&data).unwrap_or(KeystoreV2 {
            version: 0,
            kdf: "unknown".into(),
            kdf_params: crate::keystore::Argon2Params {
                m_cost: 0,
                t_cost: 0,
                p_cost: 0,
                salt: String::new(),
            },
            cipher: "unknown".into(),
            nonce: String::new(),
            ciphertext: String::new(),
        });

        let meta = std::fs::metadata(&path)?;
        let size = meta.len();

        table
            .add_row(vec![
                Cell::new("Wallet file").fg(Color::Yellow),
                Cell::new(path.display().to_string()).fg(Color::Green),
            ])
            .add_row(vec![
                Cell::new("Format version").fg(Color::Yellow),
                Cell::new(format!("v{}", ks.version)),
            ])
            .add_row(vec![
                Cell::new("KDF").fg(Color::Yellow),
                Cell::new(format!(
                    "{} (m={} KiB, t={}, p={})",
                    ks.kdf, ks.kdf_params.m_cost, ks.kdf_params.t_cost, ks.kdf_params.p_cost
                )),
            ])
            .add_row(vec![
                Cell::new("Cipher").fg(Color::Yellow),
                Cell::new(&ks.cipher),
            ])
            .add_row(vec![
                Cell::new("File size").fg(Color::Yellow),
                Cell::new(format!("{} bytes", size)),
            ])
            .add_row(vec![
                Cell::new("Status").fg(Color::Yellow),
                Cell::new("- Encrypted")
                    .fg(Color::Cyan)
                    .add_attribute(Attribute::Bold),
            ]);
    } else {
        table.add_row(vec![
            Cell::new("Wallet").fg(Color::Yellow),
            Cell::new("Not initialised - run 'wallet init'").fg(Color::Red),
        ]);
    }

    let ab = AddressBook::load(&ab_path).unwrap_or_default();
    table.add_row(vec![
        Cell::new("Address book").fg(Color::Yellow),
        Cell::new(format!("{} saved address(es)", ab.entries.len())),
    ]);

    println!("\n{}\n", table);
    Ok(())
}

// - address book -

pub fn addr_add(label: &str, address: &str) -> Result<()> {
    use std::str::FromStr;
    let addr = address.trim();
    if let Err(e) = sxiaum_types::Address::from_str(addr) {
        ui::print_error(&format!(
            "Invalid address format (must be valid 20-byte or 32-byte hex): {e}"
        ));
        return Ok(());
    }

    let path = address_book_path()?;
    let mut ab = AddressBook::load(&path).unwrap_or_default();
    let overwriting = ab.entries.contains_key(label);
    ab.entries.insert(label.to_string(), addr.to_string());
    ab.save(&path)?;

    if overwriting {
        ui::print_warning(&format!("Updated address book entry '{}'", label));
    } else {
        ui::print_success(&format!("Added '{}' - {} to address book", label, addr));
    }
    Ok(())
}

pub fn addr_remove(label: &str) -> Result<()> {
    let path = address_book_path()?;
    let mut ab = AddressBook::load(&path).unwrap_or_default();
    if ab.entries.remove(label).is_some() {
        ab.save(&path)?;
        ui::print_success(&format!("Removed '{}' from address book", label));
    } else {
        ui::print_error(&format!("Label '{}' not found in address book", label));
    }
    Ok(())
}

pub fn addr_list() -> Result<()> {
    let path = address_book_path()?;
    let ab = AddressBook::load(&path).unwrap_or_default();
    if ab.entries.is_empty() {
        ui::print_info("Address book is empty. Use 'wallet addr add <label> <address>'.");
        return Ok(());
    }
    let mut table = Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .set_header(vec![
            Cell::new("Label").add_attribute(Attribute::Bold),
            Cell::new("Address")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);
    let mut sorted: Vec<(&String, &String)> = ab.entries.iter().collect();
    sorted.sort_by_key(|(l, _)| l.as_str());
    for (label, address) in sorted {
        table.add_row(vec![Cell::new(label).fg(Color::Yellow), Cell::new(address)]);
    }
    println!("\n{}\n", table);
    ui::print_info(&format!("{} address(es) in book", ab.entries.len()));
    Ok(())
}

// - Expose for use in transaction signing -

/// Retrieve a raw private key hex for a given alias after password verification.
/// The returned string must be zeroized by the caller after use.
pub fn unlock_key(alias: &str) -> Result<String> {
    let path = keystore_path()?;
    if !path.exists() {
        anyhow::bail!("No wallet found. Run 'wallet init' first.");
    }
    let password = prompt_password_open(&format!("Password to sign with '{}':", alias))?;
    let pb = ui::create_spinner("Unlocking wallet...");
    let payload = load_wallet(&password)?;
    pb.finish_and_clear();
    payload
        .keys
        .get(alias)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Alias '{}' not found in wallet", alias))
}
