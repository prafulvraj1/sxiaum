use crate::{utils, AccountCommands};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// TICKET-07: CLI must never print or write private keys in plaintext.
//
// Changes from the original:
//  - generate_keypairs: removed `Private Key: {}` line; directs users to
//    `--output` which writes an encrypted keystore, not raw JSON.
//  - derive_address_from_key: removed `Private Key: {}` echo.
//  - import_account: removed `Private Key: {}` echo; `--output` writes an
//    Argon2id-encrypted AES-256-GCM keystore (EIP-55 / Web3 Secret Storage
//    compatible format) and never stores the private key in plaintext.
// ---------------------------------------------------------------------------

pub async fn handle_account_command(action: AccountCommands) -> Result<()> {
    match action {
        AccountCommands::Generate {
            output,
            count,
            password_file,
        } => {
            generate_keypairs(output, count, password_file).await?;
        }
        AccountCommands::Derive { private_key } => {
            derive_address_from_key(&private_key).await?;
        }
        AccountCommands::ListDevnet => {
            list_devnet_accounts().await?;
        }
        AccountCommands::Import {
            private_key,
            output,
        } => {
            import_account(&private_key, output).await?;
        }
        AccountCommands::Show { address } => {
            show_account(&address).await?;
        }
    }
    Ok(())
}

async fn generate_keypairs(
    output: Option<PathBuf>,
    count: usize,
    password_file: Option<PathBuf>,
) -> Result<()> {
    println!("Generating {} keypair(s)...\n", count);

    let mut accounts = Vec::new();

    for i in 1..=count {
        let (privkey, pubkey) = utils::generate_keypair();
        let address = utils::derive_address(&pubkey)?;

        println!("===========================================================");
        println!("Account #{}", i);
        println!("===========================================================");
        println!("Address:     {}", address);
        println!("Public Key:  {}", pubkey);
        // TICKET-07: private key is NOT printed to stdout.
        // Use --output to save an encrypted keystore instead.
        println!("Private Key: [hidden] -- use --output to save an encrypted keystore");
        println!();

        accounts.push(serde_json::json!({
            "address": address,
            "pubkey": pubkey,
            // TICKET-07: private key is stored encrypted, never as plaintext JSON.
            // The raw key is captured here only to pass to the keystore writer.
            "_privkey_for_encryption": privkey,
        }));
    }

    if let Some(path) = output {
        // For each account, write a separate encrypted keystore file.
        // The raw private key is never written to disk in plaintext.
        // Non-interactive support: read the keystore password from a file
        // (mirrors keytool). Falls back to the interactive prompt only when
        // no --password-file was supplied.
        let password = match &password_file {
            Some(pf) => {
                let raw = std::fs::read_to_string(pf)
                    .with_context(|| format!("failed to read password file {}", pf.display()))?;
                let trimmed = raw.trim_end_matches(['\r', '\n']).to_string();
                sxiaum_keystore::password::validate_password(&trimmed)?;
                trimmed
            }
            None => prompt_password_twice("Enter keystore password: ")?,
        };

        for (i, acc) in accounts.iter().enumerate() {
            let privkey_hex = acc["_privkey_for_encryption"]
                .as_str()
                .context("privkey missing")?;
            let address = acc["address"].as_str().context("address missing")?;

            let keystore_path = if accounts.len() == 1 {
                path.clone()
            } else {
                path.with_file_name(format!(
                    "{}-{}.json",
                    path.file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("account"),
                    i + 1
                ))
            };

            write_encrypted_keystore(privkey_hex, address, &password, &keystore_path)?;
            println!(
                "  [{}] Encrypted keystore saved to: {}",
                i + 1,
                keystore_path.display()
            );
        }
        println!("\nKeystores are encrypted with Argon2id + AES-256-GCM.");
        println!("Keep your password safe -- it cannot be recovered.");
    } else {
        println!("Tip: use --output <path> to save encrypted keystores to disk.");
    }

    Ok(())
}

async fn derive_address_from_key(private_key: &str) -> Result<()> {
    let seed = utils::parse_hex32(private_key)?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = format!("0x{}", hex::encode(verifying_key.as_bytes()));

    let address = utils::derive_address(&pubkey_hex)?;

    println!("Address Derivation");
    println!("===========================================================");
    // TICKET-07: do NOT echo the private key back. The user already knows it.
    println!("Public Key:  {}", pubkey_hex);
    println!("Address:     {}", address);

    Ok(())
}

async fn list_devnet_accounts() -> Result<()> {
    println!("DEVNET PRE-FUNDED ACCOUNTS (public identities)");
    println!("===========================================================\n");

    let accounts = utils::load_devnet_config()?;

    for (idx, (address, key_ref, balance)) in accounts.iter().enumerate() {
        let balance_wei: u128 = balance.parse()?;
        let balance_tokens = balance_wei as f64 / 1e18;

        println!("Validator #{}", idx + 1);
        println!("-----------------------------------------------------------");
        println!("Address:     {}", address);
        println!("Key source:  {}", key_ref);
        println!("Balance:     {} aSXI ({:.6} SXI)", balance, balance_tokens);
        println!();
    }

    println!("Private keys are not embedded in the repo.");
    println!("  * Export env var SXIAUM_VALIDATOR_KEY with your private key");
    println!("  * Or set SXIAUM_SHOW_DEVNET_KEYS=1 to display local test seeds");
    println!("  * See docs/KEY_MANAGEMENT.md");

    Ok(())
}

async fn import_account(private_key: &str, output: Option<PathBuf>) -> Result<()> {
    let seed = utils::parse_hex32(private_key)?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = format!("0x{}", hex::encode(verifying_key.as_bytes()));

    let address = utils::derive_address(&pubkey_hex)?;

    println!("Imported Account");
    println!("===========================================================");
    println!("Address:     {}", address);
    println!("Public Key:  {}", pubkey_hex);
    // TICKET-07: private key is NOT printed to stdout.
    println!("Private Key: [hidden] -- use --output to save an encrypted keystore");

    if let Some(path) = output {
        let password = prompt_password_twice("Enter keystore password: ")?;
        write_encrypted_keystore(private_key, &address, &password, &path)?;
        println!("\nEncrypted keystore saved to: {}", path.display());
        println!("Keystore is encrypted with Argon2id + AES-256-GCM.");
        println!("Keep your password safe -- it cannot be recovered.");
    } else {
        println!("\nTip: use --output <path> to save an encrypted keystore.");
    }

    Ok(())
}

async fn show_account(address: &str) -> Result<()> {
    println!("Account: {}", address);
    println!("===========================================================");
    println!("To query balance, use: sxiaumcli query balance {}", address);
    println!("To query nonce, use:   sxiaumcli query nonce {}", address);

    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypted keystore helpers (Argon2id + AES-256-GCM)
// ---------------------------------------------------------------------------

/// Prompt for a password twice (for confirmation) and validate strength against policy.
/// Uses `rpassword` for hidden input (no terminal echo).
fn prompt_password_twice(prompt: &str) -> Result<String> {
    let pw1 = rpassword::prompt_password(prompt).context("failed to read password")?;
    if let Err(e) = sxiaum_keystore::password::validate_password(&pw1) {
        bail!("Password policy violation: {e}");
    }
    let pw2 = rpassword::prompt_password("Confirm password: ")
        .context("failed to read confirmation password")?;
    if pw1 != pw2 {
        bail!("Passwords do not match");
    }
    Ok(pw1)
}

/// Write a keystore JSON file encrypted with Argon2id (KDF) + AES-256-GCM (cipher).
fn write_encrypted_keystore(
    privkey_hex: &str,
    address: &str,
    password: &str,
    path: &Path,
) -> Result<()> {
    use sxiaum_keystore::format::native::NativeKeystoreWrapper;
    use sxiaum_keystore::KeyEntry;

    let raw_hex = privkey_hex.trim_start_matches("0x");
    let key_bytes = hex::decode(raw_hex).context("invalid private key hex")?;
    if key_bytes.len() != 32 {
        bail!("private key must be exactly 32 bytes (Ed25519 seed)");
    }

    let entry = KeyEntry::new(
        address.to_string(),
        sxiaum_keystore::KEY_TYPE_ED25519.to_string(),
        key_bytes,
    )?;

    let native = NativeKeystoreWrapper::encrypt(&entry, password)?;
    let keystore_json = serde_json::json!({
        "address": address,
        "kind": sxiaum_keystore::KEY_TYPE_ED25519,
        "keystore": native,
    });

    sxiaum_keytool::io::write_secure_file(path, &serde_json::to_string_pretty(&keystore_json)?)
        .map_err(|e| anyhow::anyhow!("Failed to write secure keystore: {e}"))?;

    Ok(())
}
