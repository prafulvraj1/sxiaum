//! Cryptographic key generation, encryption, multi-format serialization, and HD derivation.

use crate::cli::{KeyType, KeystoreFormat, WordCount};
use crate::error::{KeytoolError, Result};
use ark_bls12_381::{Fr, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sxiaum_crypto::bls::{bls_generate_keypair, BlsPublicKey};
use sxiaum_crypto::ed25519::{generate_keypair, keypair_from_seed};
use sxiaum_keystore::bip39::{Mnemonic, MnemonicType};
use sxiaum_keystore::format::detect_and_decrypt;
use sxiaum_keystore::format::eip2335::Eip2335Keystore;
use sxiaum_keystore::format::native::NativeKeystoreWrapper;
use sxiaum_keystore::format::web3_v3::Web3Keystore;
use sxiaum_keystore::{
    validate_bls12_381_secret_key, validate_ed25519_secret_key, KeyEntry, MAX_KEY_DATA_SIZE,
};
use sxiaum_types::validator::BLS_PUBKEY_LEN;
use sxiaum_types::Address;
use zeroize::Zeroizing;

/// Represents generated key material with public identifiers and zeroizable private key.
pub struct GeneratedKey {
    pub key_type: KeyType,
    pub public_key_hex: String,
    pub address_hex: Option<String>,
    pub private_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for GeneratedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedKey")
            .field("key_type", &self.key_type)
            .field("public_key_hex", &self.public_key_hex)
            .field("address_hex", &self.address_hex)
            .field(
                "private_key",
                &format!("<redacted {} bytes>", self.private_key.len()),
            )
            .finish()
    }
}

/// Resolve a [`KeyType`] from the `kind` field of a serialized key JSON document.
///
/// Accepts both the canonical SXIAUM kind strings (`ed25519`, `bls12-381`) and
/// the common short alias `bls`. Unknown kinds are rejected instead of
/// silently defaulting to ed25519 — silently re-labelling a BLS scalar as an
/// Ed25519 seed produces signatures with the wrong algorithm.
///
/// Documents without a `kind` field are resolved from their self-describing
/// standard format markers:
/// - EIP-2335 (`version: 4` + `crypto`) → BLS12-381 validator keys
/// - Web3 Secret Storage v3 (`version: 3` + `crypto`) → Ed25519 account keys
pub fn detect_key_type_from_json(parsed: &serde_json::Value) -> Result<KeyType> {
    if let Some(kind) = parsed.get("kind").and_then(|k| k.as_str()) {
        return detect_key_type(kind);
    }

    let version = parsed.get("version").and_then(|v| v.as_u64());
    let has_crypto = parsed.get("crypto").map(|c| c.is_object()).unwrap_or(false);
    match (version, has_crypto) {
        (Some(4), true) => Ok(KeyType::Bls),
        (Some(3), true) => Ok(KeyType::Ed25519),
        _ => Err(KeytoolError::InvalidFormat(
            "key JSON is missing the 'kind' field and is not a recognizable \
             EIP-2335 or Web3 v3 keystore"
                .to_string(),
        )),
    }
}

/// Resolve a [`KeyType`] from a raw kind string.
pub fn detect_key_type(kind: &str) -> Result<KeyType> {
    match kind {
        "ed25519" => Ok(KeyType::Ed25519),
        "bls12-381" | "bls" => Ok(KeyType::Bls),
        other => Err(KeytoolError::InvalidFormat(format!(
            "unrecognized key kind '{other}' (expected \"ed25519\" or \"bls12-381\")"
        ))),
    }
}

/// Derive the compressed G1 public key (48 bytes) from canonical BLS secret bytes.
///
/// Shared by PoP generation, mnemonic derivation, and deposit payload creation
/// so every code path derives public keys identically.
pub fn bls_public_key_from_secret(secret_key_bytes: &[u8]) -> Result<BlsPublicKey> {
    validate_bls12_381_secret_key(secret_key_bytes)?;
    let fr = Fr::deserialize_compressed(secret_key_bytes)
        .map_err(|e| KeytoolError::Crypto(format!("Invalid BLS secret key Fr element: {e}")))?;
    let pk_proj = G1Projective::generator() * fr;
    let pk = BlsPublicKey::from_g1(&pk_proj);
    if pk.0.len() != BLS_PUBKEY_LEN {
        return Err(KeytoolError::Crypto(format!(
            "Derived BLS public key invalid length: expected {BLS_PUBKEY_LEN} bytes, got {}",
            pk.0.len()
        )));
    }
    Ok(pk)
}

/// Generate a fresh random keypair of the specified type with strict scalar validation.
pub fn generate_keypair_typed(key_type: KeyType) -> GeneratedKey {
    match key_type {
        KeyType::Ed25519 => {
            let (priv_key, pub_key) = generate_keypair();
            validate_ed25519_secret_key(&priv_key.0)
                .expect("cryptographically generated Ed25519 key must be valid");
            let addr = Address::from_public_key(&pub_key.0);
            GeneratedKey {
                key_type,
                public_key_hex: hex::encode(pub_key.0),
                address_hex: Some(hex::encode(addr.as_bytes())),
                private_key: Zeroizing::new(priv_key.0.to_vec()),
            }
        }
        KeyType::Bls => {
            let (secret_key, pub_key) = bls_generate_keypair();
            let secret_bytes = secret_key.0.clone();
            validate_bls12_381_secret_key(&secret_bytes)
                .expect("cryptographically generated BLS key must be valid");
            GeneratedKey {
                key_type,
                public_key_hex: hex::encode(&pub_key.0),
                address_hex: None,
                private_key: Zeroizing::new(secret_bytes),
            }
        }
    }
}

/// Derive a keypair from a BIP-39 mnemonic phrase and optional passphrase.
pub fn derive_keypair_from_mnemonic(
    phrase: &str,
    passphrase: &str,
    key_type: KeyType,
) -> Result<GeneratedKey> {
    let mnemonic = Mnemonic::from_phrase(phrase)?;
    match key_type {
        KeyType::Ed25519 => {
            let seed = mnemonic.to_seed(passphrase)?;
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(&seed[0..32]);
            validate_ed25519_secret_key(&priv_bytes)?;
            let (priv_key, pub_key) = keypair_from_seed(priv_bytes);
            let addr = Address::from_public_key(&pub_key.0);
            Ok(GeneratedKey {
                key_type,
                public_key_hex: hex::encode(pub_key.0),
                address_hex: Some(hex::encode(addr.as_bytes())),
                private_key: Zeroizing::new(priv_key.0.to_vec()),
            })
        }
        KeyType::Bls => {
            let master_seed = mnemonic.to_validator_seed(passphrase)?;
            let fr = Fr::from_le_bytes_mod_order(&*master_seed);
            let mut sk_bytes = Vec::new();
            fr.serialize_compressed(&mut sk_bytes)
                .map_err(|e| KeytoolError::Crypto(format!("BLS Fr serialization failed: {e}")))?;

            validate_bls12_381_secret_key(&sk_bytes)?;

            let pk = bls_public_key_from_secret(&sk_bytes)?;

            Ok(GeneratedKey {
                key_type,
                public_key_hex: hex::encode(&pk.0),
                address_hex: None,
                private_key: Zeroizing::new(sk_bytes),
            })
        }
    }
}

/// Generate a BIP-39 recovery mnemonic phrase.
pub fn generate_mnemonic_phrase(word_count: WordCount) -> Result<(String, usize)> {
    let mtype = match word_count {
        WordCount::Words12 => MnemonicType::Words12,
        WordCount::Words18 => MnemonicType::Words18,
        WordCount::Words24 => MnemonicType::Words24,
    };
    let mnemonic = Mnemonic::generate(mtype)?;
    let bits = mtype.entropy_bits();
    Ok((mnemonic.phrase().to_string(), bits))
}

/// Format key material into JSON using the specified format.
pub fn serialize_key_json(
    key: &GeneratedKey,
    format: KeystoreFormat,
    passphrase: Option<&str>,
    unsafe_export: bool,
) -> Result<String> {
    let kind_str = match key.key_type {
        KeyType::Ed25519 => sxiaum_keystore::KEY_TYPE_ED25519,
        KeyType::Bls => sxiaum_keystore::KEY_TYPE_BLS,
    };

    // Pre-validate scalar before serializing
    match key.key_type {
        KeyType::Ed25519 => validate_ed25519_secret_key(&key.private_key)?,
        KeyType::Bls => validate_bls12_381_secret_key(&key.private_key)?,
    }

    if unsafe_export {
        let mut json = serde_json::json!({
            "kind": kind_str,
            "public_key": key.public_key_hex,
            "secret_key": hex::encode(&*key.private_key),
            "warning": "PLAINTEXT PRIVATE KEY — DELETE IMMEDIATELY AFTER USE",
        });
        if let Some(ref addr) = key.address_hex {
            json["address"] = serde_json::json!(addr);
        }
        return Ok(serde_json::to_string_pretty(&json)?);
    }

    let pw = passphrase.ok_or_else(|| {
        KeytoolError::InvalidFormat(
            "Passphrase required for encrypted keystore serialization".to_string(),
        )
    })?;

    match format {
        KeystoreFormat::Native => {
            let entry = KeyEntry::new(
                "validator".to_string(),
                kind_str.to_string(),
                key.private_key.to_vec(),
            )?;
            let native = NativeKeystoreWrapper::encrypt(&entry, pw)?;
            let mut json = serde_json::json!({
                "kind": kind_str,
                "public_key": key.public_key_hex,
                "keystore": native,
            });
            if let Some(ref addr) = key.address_hex {
                json["address"] = serde_json::json!(addr);
            }
            Ok(serde_json::to_string_pretty(&json)?)
        }
        KeystoreFormat::Eip2335 => {
            if key.key_type != KeyType::Bls {
                return Err(KeytoolError::InvalidFormat(
                    "EIP-2335 format is only valid for BLS12-381 validator keys".to_string(),
                ));
            }
            if key.private_key.len() != 32 {
                return Err(KeytoolError::Crypto(format!(
                    "EIP-2335 requires 32-byte secret key (got {})",
                    key.private_key.len()
                )));
            }
            let mut secret_arr = [0u8; 32];
            secret_arr.copy_from_slice(&key.private_key);
            let eip = Eip2335Keystore::encrypt(&secret_arr, &key.public_key_hex, pw, None, None)?;
            Ok(serde_json::to_string_pretty(&eip)?)
        }
        KeystoreFormat::Web3 => {
            if key.key_type != KeyType::Ed25519 {
                return Err(KeytoolError::InvalidFormat(
                    "Web3 v3 format is only valid for Ed25519/Account keys".to_string(),
                ));
            }
            if key.private_key.len() != 32 {
                return Err(KeytoolError::Crypto(format!(
                    "Web3 v3 requires 32-byte secret key (got {})",
                    key.private_key.len()
                )));
            }
            let mut secret_arr = [0u8; 32];
            secret_arr.copy_from_slice(&key.private_key);
            let addr_str = key
                .address_hex
                .clone()
                .unwrap_or_else(|| key.public_key_hex.clone());
            let web3 = Web3Keystore::encrypt(&secret_arr, &addr_str, pw)?;
            Ok(serde_json::to_string_pretty(&web3)?)
        }
    }
}

/// Decrypt private key bytes from any supported keystore JSON string.
pub fn decrypt_key_json(json_str: &str, passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    if json_str.is_empty() {
        return Err(KeytoolError::InvalidFormat(
            "keystore json payload is empty".to_string(),
        ));
    }
    if json_str.len() > MAX_KEY_DATA_SIZE {
        return Err(KeytoolError::InvalidFormat(format!(
            "keystore json payload exceeds maximum allowed size ({} > {})",
            json_str.len(),
            MAX_KEY_DATA_SIZE
        )));
    }

    let parsed: serde_json::Value = serde_json::from_str(json_str)?;

    // If plaintext secret_key is present:
    if let Some(secret_hex) = parsed.get("secret_key").and_then(|v| v.as_str()) {
        // Plaintext imports are a migration path only; make the risk visible in
        // production environments without breaking legitimate recovery flows.
        if sxiaum_keystore::password::is_production() {
            eprintln!(
                "SECURITY WARNING: importing PLAINTEXT private key material while SXIAUM_ENV=production. \
                 Re-encrypt into an encrypted keystore immediately."
            );
        }
        let bytes = hex::decode(secret_hex)?;
        return Ok(Zeroizing::new(bytes));
    }

    // If wrapped in "keystore" sub-object (Native format):
    if let Some(keystore_val) = parsed.get("keystore") {
        let ks_str = serde_json::to_string(keystore_val)?;
        let entry = detect_and_decrypt(ks_str.as_bytes(), passphrase, "validator")?;
        return Ok(Zeroizing::new(entry.data.clone()));
    }

    // Direct root JSON format (EIP-2335, Web3 v3, or direct Native v2):
    let entry = detect_and_decrypt(json_str.as_bytes(), passphrase, "validator")?;
    Ok(Zeroizing::new(entry.data.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{KeyType, KeystoreFormat};

    #[test]
    fn detect_key_type_accepts_canonical_and_alias() {
        assert!(matches!(detect_key_type("ed25519"), Ok(KeyType::Ed25519)));
        // Canonical SXIAUM kind for BLS is "bls12-381"; "bls" is an accepted alias.
        assert!(matches!(detect_key_type("bls12-381"), Ok(KeyType::Bls)));
        assert!(matches!(detect_key_type("bls"), Ok(KeyType::Bls)));
        assert!(detect_key_type("rsa").is_err());
        assert!(detect_key_type("").is_err());
        assert!(detect_key_type("BLS").is_err()); // case-sensitive, no silent fallback
    }

    #[test]
    fn detect_key_type_from_json_requires_kind_field() {
        let missing = serde_json::json!({ "public_key": "aa" });
        assert!(detect_key_type_from_json(&missing).is_err());

        let bls = serde_json::json!({ "kind": "bls12-381" });
        assert!(matches!(detect_key_type_from_json(&bls), Ok(KeyType::Bls)));

        let ed = serde_json::json!({ "kind": "ed25519" });
        assert!(matches!(
            detect_key_type_from_json(&ed),
            Ok(KeyType::Ed25519)
        ));
    }

    #[test]
    fn detect_key_type_infers_from_standard_format_markers() {
        // EIP-2335 keystores carry no SXIAUM 'kind'; version 4 → BLS.
        let eip = serde_json::json!({
            "version": 4,
            "crypto": { "kdf": {}, "checksum": {}, "cipher": {} }
        });
        assert!(matches!(detect_key_type_from_json(&eip), Ok(KeyType::Bls)));

        // Web3 v3 keystores carry no SXIAUM 'kind'; version 3 → Ed25519.
        let web3 = serde_json::json!({
            "version": 3,
            "crypto": { "cipher": "", "cipherparams": {}, "ciphertext": "",
                        "kdf": "", "kdfparams": {}, "mac": "" }
        });
        assert!(matches!(
            detect_key_type_from_json(&web3),
            Ok(KeyType::Ed25519)
        ));

        // Unknown versions with a crypto block must NOT be guessed.
        let unknown = serde_json::json!({ "version": 9, "crypto": {} });
        assert!(detect_key_type_from_json(&unknown).is_err());

        // Version without crypto must NOT be guessed.
        let bare = serde_json::json!({ "version": 4 });
        assert!(detect_key_type_from_json(&bare).is_err());
    }

    #[test]
    fn bls_public_key_derivation_is_consistent_with_generate() {
        let generated = generate_keypair_typed(KeyType::Bls);
        let derived = bls_public_key_from_secret(&generated.private_key).unwrap();
        assert_eq!(hex::encode(&derived.0), generated.public_key_hex);
        assert_eq!(derived.0.len(), 48);
    }

    #[test]
    fn bls_public_key_rejects_zero_scalar() {
        assert!(bls_public_key_from_secret(&[0u8; 32]).is_err());
    }

    #[test]
    fn mnemonic_derive_bls_matches_public_key_helper() {
        // Official BIP-39 vector V0.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let key = derive_keypair_from_mnemonic(phrase, "TREZOR", KeyType::Bls).unwrap();
        let pk = bls_public_key_from_secret(&key.private_key).unwrap();
        assert_eq!(hex::encode(&pk.0), key.public_key_hex);
    }

    #[test]
    fn decrypt_key_json_round_trips_native_wrapper() {
        let key = generate_keypair_typed(KeyType::Ed25519);
        let json = serialize_key_json(
            &key,
            KeystoreFormat::Native,
            Some("Str0ng-Passphrase!"),
            false,
        )
        .unwrap();
        let decrypted = decrypt_key_json(&json, "Str0ng-Passphrase!").unwrap();
        assert_eq!(&*decrypted, &*key.private_key);

        // Wrong passphrase must fail.
        assert!(decrypt_key_json(&json, "Wr0ng-Passphrase!").is_err());
    }
}
