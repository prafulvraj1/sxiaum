//! SXIAUM Keytool Library API.
//!
//! Provides production-grade cryptographic key management, multi-format keystore serialization,
//! BIP-39 mnemonic generation & HD key derivation, BLS Proof-of-Possession, and message signing.

pub mod cli;
pub mod error;
pub mod generator;
pub mod io;
pub mod signer;
pub mod validator_payload;

pub use cli::{Cli, Commands, KeyType, KeystoreFormat, MnemonicCommands, PopCommands, WordCount};
pub use error::{KeytoolError, Result};
pub use generator::{
    derive_keypair_from_mnemonic, generate_keypair_typed, generate_mnemonic_phrase,
    serialize_key_json, GeneratedKey,
};
pub use io::{confirm_or_abort, get_passphrase, write_secure_file, SECURITY_BANNER};
pub use signer::{sign_message, verify_message_signature};
pub use validator_payload::{create_validator_deposit_payload, ValidatorDepositPayload};

use std::fs;
use std::path::Path;

/// Shared production-mode detection (single source of truth from the keystore
/// crate: `SXIAUM_ENV=production` or `SXIAUM_SRS_MODE=production`, case-insensitive).
fn is_production() -> bool {
    sxiaum_keystore::password::is_production()
}

/// Validate that a key-type/format combination is serializable before any
/// key material is generated, so batch runs never fail halfway through.
pub fn validate_format_compatibility(key_type: KeyType, format: KeystoreFormat) -> Result<()> {
    match format {
        KeystoreFormat::Eip2335 if key_type != KeyType::Bls => Err(KeytoolError::InvalidFormat(
            "EIP-2335 format is only valid for BLS12-381 validator keys".to_string(),
        )),
        KeystoreFormat::Web3 if key_type != KeyType::Ed25519 => Err(KeytoolError::InvalidFormat(
            "Web3 v3 format is only valid for Ed25519/Account keys".to_string(),
        )),
        _ => Ok(()),
    }
}

/// Execute the high-level key generation command.
pub fn handle_generate(
    out: &Path,
    key_type: KeyType,
    format: KeystoreFormat,
    password_file: Option<&Path>,
    unsafe_export: bool,
    allow_insecure_production_plaintext: bool,
    yes: bool,
) -> Result<GeneratedKey> {
    validate_format_compatibility(key_type, format)?;

    let prod = is_production();
    if unsafe_export && prod && !allow_insecure_production_plaintext {
        return Err(KeytoolError::PlaintextInProductionForbidden);
    }

    if unsafe_export {
        eprintln!("{}", SECURITY_BANNER);
        confirm_or_abort("export private key in PLAINTEXT", yes)?;
    }

    let key = generate_keypair_typed(key_type);

    let passphrase_opt = if !unsafe_export {
        let pw = get_passphrase(
            "Enter encryption passphrase: ",
            true,
            password_file,
            true, // enforce strength policy
        )?;
        Some(pw)
    } else {
        None
    };

    let json_content = serialize_key_json(
        &key,
        format,
        passphrase_opt.as_deref().map(|s| s.as_str()),
        unsafe_export,
    )?;

    write_secure_file(out, &json_content)?;
    Ok(key)
}

/// Execute batch key generation for enterprise validators.
pub fn handle_generate_batch(
    out_dir: &Path,
    count: usize,
    key_type: KeyType,
    format: KeystoreFormat,
    password_file: Option<&Path>,
    yes: bool,
) -> Result<Vec<GeneratedKey>> {
    if count == 0 || count > 10_000 {
        return Err(KeytoolError::Other(
            "Batch count must be between 1 and 10,000".to_string(),
        ));
    }

    // Pre-flight: reject incompatible key-type/format combinations before any
    // key material exists so a batch never fails halfway through leaving a
    // partially-written output directory.
    validate_format_compatibility(key_type, format)?;

    confirm_or_abort(
        &format!("batch-generate {} keys in {:?}", count, out_dir),
        yes,
    )?;

    let passphrase = get_passphrase(
        "Enter encryption passphrase for batch keystores: ",
        true,
        password_file,
        true,
    )?;

    fs::create_dir_all(out_dir)?;

    let mut generated = Vec::with_capacity(count);
    for idx in 0..count {
        let key = generate_keypair_typed(key_type);
        let filename = format!("validator_key_{:04}.json", idx);
        let out_path = out_dir.join(filename);

        let json_content = serialize_key_json(&key, format, Some(&passphrase), false)?;

        write_secure_file(&out_path, &json_content)?;
        generated.push(key);
    }

    Ok(generated)
}

/// Execute BIP-39 mnemonic derivation command.
#[allow(clippy::too_many_arguments)]
pub fn handle_mnemonic_derive(
    phrase: &str,
    passphrase: &str,
    key_type: KeyType,
    out: &Path,
    format: KeystoreFormat,
    password_file: Option<&Path>,
    unsafe_export: bool,
    yes: bool,
) -> Result<GeneratedKey> {
    validate_format_compatibility(key_type, format)?;

    // Same production plaintext policy as `handle_generate`.
    if unsafe_export && is_production() {
        return Err(KeytoolError::PlaintextInProductionForbidden);
    }

    if unsafe_export {
        eprintln!("{}", SECURITY_BANNER);
        confirm_or_abort("derive and write PLAINTEXT private key", yes)?;
    }

    let key = derive_keypair_from_mnemonic(phrase, passphrase, key_type)?;

    let enc_pw = if !unsafe_export {
        let pw = get_passphrase(
            "Enter encryption passphrase for keystore: ",
            true,
            password_file,
            true,
        )?;
        Some(pw)
    } else {
        None
    };

    let json_content = serialize_key_json(
        &key,
        format,
        enc_pw.as_deref().map(|s| s.as_str()),
        unsafe_export,
    )?;

    write_secure_file(out, &json_content)?;
    Ok(key)
}

/// Change the encryption passphrase on an existing key file.
///
/// The original key type is preserved exactly: the `kind` field is resolved
/// through [`generator::detect_key_type_from_json`] so a BLS12-381 key is never
/// re-labelled (or re-validated) as an Ed25519 seed.
pub fn handle_change_password(
    file: &Path,
    old_password_file: Option<&Path>,
    new_password_file: Option<&Path>,
) -> Result<()> {
    let content = fs::read_to_string(file)?;
    let old_pw = get_passphrase(
        "Enter current passphrase: ",
        false,
        old_password_file,
        false,
    )?;
    let raw_key = generator::decrypt_key_json(&content, &old_pw)?;

    let new_pw = get_passphrase("Enter new passphrase: ", true, new_password_file, true)?;

    let parsed: serde_json::Value = serde_json::from_str(&content)?;
    let key_type = generator::detect_key_type_from_json(&parsed)?;

    let pub_hex = parsed
        .get("public_key")
        .and_then(|k| k.as_str())
        .unwrap_or_default();
    let addr_hex = parsed
        .get("address")
        .and_then(|a| a.as_str())
        .map(ToString::to_string);

    let key = GeneratedKey {
        key_type,
        public_key_hex: pub_hex.to_string(),
        address_hex: addr_hex,
        private_key: raw_key,
    };

    let new_json = serialize_key_json(&key, KeystoreFormat::Native, Some(&new_pw), false)?;
    write_secure_file(file, &new_json)?;
    Ok(())
}
