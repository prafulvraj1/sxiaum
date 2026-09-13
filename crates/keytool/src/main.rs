//! SXIAUM Keytool CLI binary.

use clap::Parser;
use std::fs;
use sxiaum_crypto::bls::{
    create_proof_of_possession, verify_proof_of_possession, BlsPrivateKey, BlsPublicKey,
    BlsSignature,
};
use sxiaum_keystore::fs_adapter::FsKeyStore;
use sxiaum_keystore::{KeyEntry, KeyStore};
use sxiaum_keytool::cli::{Cli, Commands, KeyType, MnemonicCommands, PopCommands};
use sxiaum_keytool::generator::{
    bls_public_key_from_secret, decrypt_key_json, detect_key_type, detect_key_type_from_json,
};
use sxiaum_keytool::io::{confirm_or_abort, get_passphrase, write_secure_file, SECURITY_BANNER};
use sxiaum_keytool::signer::{sign_message, verify_message_signature};
use sxiaum_keytool::validator_payload::create_validator_deposit_payload;
use sxiaum_keytool::{
    generate_mnemonic_phrase, handle_change_password, handle_generate, handle_generate_batch,
    handle_mnemonic_derive,
};
use sxiaum_types::Address;

/// Shared production-mode detection (single source of truth in the keystore crate).
fn is_production() -> bool {
    sxiaum_keystore::password::is_production()
}

/// Strip an optional `0x`/`0X` prefix and surrounding whitespace from a hex string.
fn clean_hex(input: &str) -> &str {
    input
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            out,
            key_type,
            format,
            password_file,
            unsafe_export,
            allow_insecure_production_plaintext,
            yes,
        } => {
            let key = handle_generate(
                &out,
                key_type,
                format,
                password_file.as_deref(),
                unsafe_export,
                allow_insecure_production_plaintext,
                yes,
            )?;

            println!(
                "✓ Keypair generated and securely written to {}",
                out.display()
            );
            println!("  Key Type:   {:?}", key_type);
            println!("  Format:     {:?}", format);
            println!("  Public Key: {}", key.public_key_hex);
            if let Some(addr) = key.address_hex {
                println!("  Address:    0x{}", addr);
            }
            if unsafe_export {
                eprintln!("  Status:     PLAINTEXT (DANGEROUS — DELETE IMMEDIATELY AFTER USE)");
            } else {
                println!("  Status:     Encrypted (Argon2id / AES-GCM / CTR)");
            }
        }

        Commands::GenerateBatch {
            out_dir,
            count,
            key_type,
            format,
            password_file,
            yes,
        } => {
            let keys = handle_generate_batch(
                &out_dir,
                count,
                key_type,
                format,
                password_file.as_deref(),
                yes,
            )?;

            println!(
                "✓ Batch generated {} {:?} keys into directory {}",
                keys.len(),
                key_type,
                out_dir.display()
            );
        }

        Commands::Mnemonic { subcommand } => match subcommand {
            MnemonicCommands::Generate { words } => {
                let (phrase, entropy_bits) = generate_mnemonic_phrase(words)?;
                println!("══════════════════════════════════════════════════════════════════");
                println!(
                    "  SXIAUM BIP-39 RECOVERY MNEMONIC PHRASE ({} words / {} bits)",
                    phrase.split_whitespace().count(),
                    entropy_bits
                );
                println!("══════════════════════════════════════════════════════════════════");
                println!("\n  {}\n", phrase);
                println!("══════════════════════════════════════════════════════════════════");
                println!("⚠  Write these words down on paper in exact order.");
                println!("   Never store this phrase digitally or share it with anyone.");
            }
            MnemonicCommands::Derive {
                phrase,
                passphrase,
                key_type,
                out,
                format,
                password_file,
                unsafe_export,
                yes,
            } => {
                let key = handle_mnemonic_derive(
                    &phrase,
                    &passphrase,
                    key_type,
                    &out,
                    format,
                    password_file.as_deref(),
                    unsafe_export,
                    yes,
                )?;
                println!(
                    "✓ Key derived from mnemonic and written to {}",
                    out.display()
                );
                println!("  Key Type:   {:?}", key_type);
                println!("  Public Key: {}", key.public_key_hex);
                if let Some(addr) = key.address_hex {
                    println!("  Address:    0x{}", addr);
                }
            }
        },

        Commands::ValidatorDeposit {
            out,
            keystore_out,
            withdrawal_address,
            amount,
            password_file,
            yes,
        } => {
            confirm_or_abort("generate a new validator staking deposit payload", yes)?;

            let enc_pw = get_passphrase(
                "Enter passphrase to encrypt the validator keystore: ",
                true,
                password_file.as_deref(),
                true,
            )?;

            let key = sxiaum_keytool::generator::generate_keypair_typed(KeyType::Bls);

            let deposit_payload =
                create_validator_deposit_payload(&key.private_key, &withdrawal_address, &amount)?;

            // Save encrypted validator keystore (EIP-2335 format)
            let keystore_json = sxiaum_keytool::generator::serialize_key_json(
                &key,
                sxiaum_keytool::cli::KeystoreFormat::Eip2335,
                Some(&enc_pw),
                false,
            )?;
            write_secure_file(&keystore_out, &keystore_json)?;

            // Save deposit payload JSON
            let deposit_json = serde_json::to_string_pretty(&deposit_payload)?;
            write_secure_file(&out, &deposit_json)?;

            println!("✓ Validator staking deposit payload generated successfully!");
            println!("  Deposit Data:  {}", out.display());
            println!("  Keystore File: {}", keystore_out.display());
            println!("  Validator BLS: {}", deposit_payload.pubkey);
            println!(
                "  Withdrawal:    {}",
                deposit_payload.withdrawal_credentials
            );
            println!("  Deposit Amount: {} SXIAUM", deposit_payload.amount);
            println!("  PoP Signature: {}", deposit_payload.proof_of_possession);
        }

        Commands::Pop { subcommand } => match subcommand {
            PopCommands::Generate {
                file,
                password_file,
            } => {
                let content = fs::read_to_string(&file)?;
                let pw = get_passphrase(
                    "Enter passphrase for BLS key: ",
                    false,
                    password_file.as_deref(),
                    false,
                )?;
                let secret_bytes = decrypt_key_json(&content, &pw)?;

                let public_key = bls_public_key_from_secret(&secret_bytes)?;
                let sk = BlsPrivateKey(secret_bytes.to_vec());
                let pop = create_proof_of_possession(&sk, &public_key)?;

                println!("BLS Public Key:        {}", hex::encode(&public_key.0));
                println!("Proof-of-Possession:   {}", hex::encode(&pop.0));
            }
            PopCommands::Verify { public_key, pop } => {
                // Length-validated decode with 0x-prefix tolerance and precise errors.
                let pk_bytes = hex::decode(clean_hex(&public_key))?;
                if pk_bytes.len() != sxiaum_types::validator::BLS_PUBKEY_LEN {
                    anyhow::bail!(
                        "BLS public key must be {} bytes (got {})",
                        sxiaum_types::validator::BLS_PUBKEY_LEN,
                        pk_bytes.len()
                    );
                }
                let pop_bytes = hex::decode(clean_hex(&pop))?;
                if pop_bytes.len() != sxiaum_types::validator::BLS_POP_LEN {
                    anyhow::bail!(
                        "Proof-of-Possession must be {} bytes (got {})",
                        sxiaum_types::validator::BLS_POP_LEN,
                        pop_bytes.len()
                    );
                }
                let pk = BlsPublicKey(pk_bytes);
                let sig = BlsSignature(pop_bytes);

                let valid = verify_proof_of_possession(&pk, &sig);
                if valid {
                    println!(
                        "✓ Proof-of-Possession is VALID for public key {}",
                        public_key
                    );
                } else {
                    println!(
                        "✗ Proof-of-Possession is INVALID for public key {}",
                        public_key
                    );
                    std::process::exit(1);
                }
            }
        },

        Commands::Sign {
            file,
            message,
            hex_message,
            password_file,
        } => {
            let content = fs::read_to_string(&file)?;
            let pw = get_passphrase(
                "Enter passphrase to decrypt key for signing: ",
                false,
                password_file.as_deref(),
                false,
            )?;
            let raw_key = decrypt_key_json(&content, &pw)?;

            // Resolve the algorithm from the file's kind field. Never guess:
            // signing BLS scalar bytes with Ed25519 would silently produce an
            // unusable signature.
            let parsed: serde_json::Value = serde_json::from_str(&content)?;
            let key_type = detect_key_type_from_json(&parsed)?;

            let msg_bytes = if hex_message {
                hex::decode(message.trim())?
            } else {
                message.as_bytes().to_vec()
            };

            let sig_hex = sign_message(key_type, &raw_key, &msg_bytes)?;
            println!("Key Type:   {:?}", key_type);
            println!("Signature:  {}", sig_hex);
        }

        Commands::Verify {
            public_key,
            message,
            hex_message,
            signature,
            key_type,
        } => {
            let msg_bytes = if hex_message {
                hex::decode(message.trim())?
            } else {
                message.as_bytes().to_vec()
            };

            let valid = verify_message_signature(key_type, &public_key, &msg_bytes, &signature)?;
            if valid {
                println!("✓ Signature is VALID for {:?}", key_type);
            } else {
                println!("✗ Signature is INVALID for {:?}", key_type);
                std::process::exit(1);
            }
        }

        Commands::Inspect { file } => {
            let data = fs::read_to_string(&file)?;
            let json: serde_json::Value = serde_json::from_str(&data)?;

            let kind = json
                .get("kind")
                .and_then(|k| k.as_str())
                .unwrap_or("(unlabeled)");
            let pubkey = json
                .get("public_key")
                .and_then(|k| k.as_str())
                .unwrap_or("Unknown");
            let address = json.get("address").and_then(|k| k.as_str());

            println!("Key File:   {}", file.display());
            println!("Key Type:   {}", kind);
            println!("Public Key: {}", pubkey);
            if let Some(addr) = address {
                println!("Address:    0x{}", addr);
            } else if matches!(
                detect_key_type(kind),
                Ok(sxiaum_keytool::cli::KeyType::Ed25519)
            ) {
                if let Ok(pk_bytes) = hex::decode(clean_hex(pubkey)) {
                    if pk_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&pk_bytes);
                        let derived_addr = Address::from_public_key(&arr);
                        println!("Address:    0x{}", hex::encode(derived_addr.as_bytes()));
                    }
                }
            }

            if json.get("secret_key").is_some() {
                eprintln!(
                    "⚠  WARNING: This file contains a PLAINTEXT private key. \
                     Delete it immediately and migrate to an encrypted keystore."
                );
            } else if json.get("keystore").is_some() || json.get("crypto").is_some() {
                println!("Status:     Encrypted Keystore");
            }
        }

        Commands::DeriveAddress { public_key, file } => {
            let pk_hex = match (public_key, file) {
                (Some(pk), _) => pk,
                (None, Some(f)) => {
                    let data = fs::read_to_string(&f)?;
                    let json: serde_json::Value = serde_json::from_str(&data)?;
                    json.get("public_key")
                        .and_then(|p| p.as_str())
                        .ok_or_else(|| anyhow::anyhow!("missing public_key in file"))?
                        .to_string()
                }
                (None, None) => {
                    anyhow::bail!("Must provide either --public-key <HEX> or --file <PATH>");
                }
            };

            let pk_bytes = hex::decode(clean_hex(&pk_hex))?;
            if pk_bytes.len() != 32 {
                anyhow::bail!(
                    "Ed25519 public key must be 32 bytes (got {})",
                    pk_bytes.len()
                );
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            let addr = Address::from_public_key(&arr);
            println!("Public Key: {}", pk_hex.trim());
            println!("Address:    0x{}", hex::encode(addr.as_bytes()));
        }

        Commands::ExportPrivateKey {
            file,
            password_file,
            unsafe_export: _,
            allow_insecure_production_plaintext,
            yes,
        } => {
            // Shared production policy (SXIAUM_ENV / SXIAUM_SRS_MODE).
            if is_production() && !allow_insecure_production_plaintext {
                anyhow::bail!(
                    "Exporting plaintext private keys is forbidden when SXIAUM_ENV=production"
                );
            }

            eprintln!("{}", SECURITY_BANNER);
            eprintln!(
                "⚠  You are about to export a RAW PRIVATE KEY to stdout.\n\
                 Ensure your terminal session is not being recorded or logged.\n"
            );

            confirm_or_abort("export the raw private key", yes)?;

            let data = fs::read_to_string(&file)?;
            let pw = get_passphrase(
                "Enter decryption passphrase: ",
                false,
                password_file.as_deref(),
                false,
            )?;
            let raw_key = decrypt_key_json(&data, &pw)?;

            println!("{}", hex::encode(&*raw_key));
        }

        Commands::ChangePassword {
            file,
            old_password_file,
            new_password_file,
        } => {
            handle_change_password(
                &file,
                old_password_file.as_deref(),
                new_password_file.as_deref(),
            )?;
            println!(
                "✓ Password rotated and key re-encrypted successfully in {}",
                file.display()
            );
        }

        Commands::ImportKeystore {
            file,
            keystore_dir,
            key_id,
            password_file,
            dest_password_file,
        } => {
            let data = fs::read_to_string(&file)?;
            let pw = get_passphrase(
                "Enter current file decryption passphrase: ",
                false,
                password_file.as_deref(),
                false,
            )?;
            let raw_key = decrypt_key_json(&data, &pw)?;

            let parsed: serde_json::Value = serde_json::from_str(&data)?;
            // Reject files without a recognizable kind rather than defaulting
            // to ed25519 and importing BLS material under the wrong label.
            let key_type = detect_key_type_from_json(&parsed)?;
            let kind = match key_type {
                KeyType::Ed25519 => sxiaum_keystore::KEY_TYPE_ED25519.to_string(),
                KeyType::Bls => sxiaum_keystore::KEY_TYPE_BLS.to_string(),
            };

            let dest_pw = get_passphrase(
                "Enter destination keystore passphrase: ",
                true,
                dest_password_file.as_deref(),
                true,
            )?;

            let keystore = FsKeyStore::new_encrypted(&keystore_dir, dest_pw.to_string())
                .map_err(|e| anyhow::anyhow!("invalid destination passphrase: {e}"))?;
            let entry = KeyEntry::new(key_id.clone(), kind, raw_key.to_vec())?;
            keystore.put(entry).await?;

            println!(
                "✓ Key '{}' imported successfully into {}",
                key_id,
                keystore_dir.display()
            );
        }
    }

    Ok(())
}
