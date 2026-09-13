//! Keystore abstractions and implementations for the SXIAUM blockchain.
//!
//! This crate provides pluggable, production-grade key storage backends:
//! - [`fs_adapter::FsKeyStore`]: Filesystem-backed encrypted keystore (AES-256-GCM + Argon2id, EIP-2335, Web3 v3)
//! - [`vault_adapter::VaultKeyStore`]: HashiCorp Vault-backed keystore for HSM-grade security
//!
//! # Mainnet Security Invariants
//!
//! - All key material is encrypted at rest with AES-256-GCM or AES-128-CTR (EIP-2335/Web3 v3).
//! - Argon2id KDF is used for password-based key derivation (memory-hard, resistant to GPU/ASIC attacks).
//! - Plaintext keystores and legacy v1 keystores are forbidden in production (`SXIAUM_ENV=production`).
//! - Path traversal attacks are strictly prevented via strict alphanumeric key ID validation.
//! - All sensitive key material is securely zeroized in memory after use.
//! - Standard BIP-39 mnemonic phrase generation and seed recovery.
//! - No silent migration, silent replacement, or silent mutation on read operations.

pub mod bip39;
pub mod cipher;
pub mod error;
pub mod format;
#[cfg(feature = "fs")]
pub mod fs_adapter;
pub mod kdf;
pub mod password;
#[cfg(feature = "vault")]
pub mod vault_adapter;

pub use bip39::{Mnemonic, MnemonicType};
pub use error::{KeystoreError, Result};
pub use format::eip2335::Eip2335Keystore;
pub use format::native::NativeKeystoreWrapper;
pub use format::web3_v3::Web3Keystore;
#[cfg(feature = "fs")]
pub use fs_adapter::FsKeyStore;
pub use password::{calculate_entropy_bits, is_production, validate_password};
#[cfg(feature = "vault")]
pub use vault_adapter::VaultKeyStore;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sxiaum_crypto::bls::BlsPrivateKey;
use sxiaum_crypto::ed25519::PrivateKey as Ed25519PrivateKey;
use sxiaum_types::Address;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Mainnet keystore constants
// ---------------------------------------------------------------------------

/// Current keystore format version (v2 = Argon2id + AES-256-GCM).
pub const KEYSTORE_VERSION: u8 = 2;

/// Maximum allowed key data size (1 MB).
pub const MAX_KEY_DATA_SIZE: usize = 1024 * 1024;

/// Maximum allowed key ID length.
pub const MAX_KEY_ID_LEN: usize = 128;

/// PBKDF2 iteration count for legacy keystore compatibility.
/// New keystores use Argon2id instead.
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Argon2id memory cost in KiB (64 MB).
pub const ARGON2_MEMORY_KIB: u32 = 65_536;

/// Argon2id time cost (iterations).
pub const ARGON2_TIME_COST: u32 = 3;

/// Argon2id parallelism (lanes).
pub const ARGON2_PARALLELISM: u32 = 1;

/// Valid key types for the keystore.
pub const KEY_TYPE_ED25519: &str = "ed25519";
pub const KEY_TYPE_BLS: &str = "bls12-381";
pub const KEY_TYPE_ACCOUNT: &str = "account";
pub const KEY_TYPE_PROVING: &str = "proving-key";
pub const KEY_TYPE_VERIFYING: &str = "verifying-key";
pub const KEY_TYPE_SRS: &str = "srs";

/// secp256k1 group order n in big-endian byte representation.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Validate that a 32-byte secret key is a valid secp256k1 scalar (0 < k < n).
pub fn validate_secp256k1_secret_key(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 32 {
        return Err(KeystoreError::InvalidKeyLength {
            expected: 32,
            actual: bytes.len(),
        });
    }
    if bytes.iter().all(|&b| b == 0) {
        return Err(KeystoreError::CorruptedKeystore(
            "account".to_string(),
            "all-zero secp256k1 private key is invalid".to_string(),
        ));
    }
    if bytes >= &SECP256K1_ORDER[..] {
        return Err(KeystoreError::CorruptedKeystore(
            "account".to_string(),
            "secp256k1 private key is out of range (>= group order)".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a 32-byte secret key is a valid BLS12-381 scalar (canonical Fr and non-zero).
pub fn validate_bls12_381_secret_key(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 32 {
        return Err(KeystoreError::InvalidKeyLength {
            expected: 32,
            actual: bytes.len(),
        });
    }
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_serialize::CanonicalDeserialize;
    let fr = Fr::deserialize_compressed(bytes).map_err(|e| {
        KeystoreError::CorruptedKeystore(
            "bls12-381".to_string(),
            format!("invalid canonical BLS12-381 Fr field element: {e}"),
        )
    })?;
    if fr.is_zero() {
        return Err(KeystoreError::CorruptedKeystore(
            "bls12-381".to_string(),
            "all-zero BLS12-381 private key is invalid (identity scalar)".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a 32-byte secret key is a valid Ed25519 secret key.
///
/// Any non-zero 32-byte value is a usable Ed25519 seed; all-zero keys are
/// rejected as trivially weak.
pub fn validate_ed25519_secret_key(bytes: &[u8]) -> Result<()> {
    if bytes.len() != 32 {
        return Err(KeystoreError::InvalidKeyLength {
            expected: 32,
            actual: bytes.len(),
        });
    }
    if bytes.iter().all(|&b| b == 0) {
        return Err(KeystoreError::CorruptedKeystore(
            "ed25519".to_string(),
            "all-zero Ed25519 private key is invalid".to_string(),
        ));
    }
    Ok(())
}

/// Validate that a key type string is recognized.
pub fn validate_key_type(kind: &str) -> Result<()> {
    let valid = matches!(
        kind,
        KEY_TYPE_ED25519
            | KEY_TYPE_BLS
            | KEY_TYPE_ACCOUNT
            | KEY_TYPE_PROVING
            | KEY_TYPE_VERIFYING
            | KEY_TYPE_SRS
    ) || (!is_production() && matches!(kind, "test" | "unknown"));

    if !valid {
        return Err(KeystoreError::InvalidKeyType(format!(
            "unrecognized key type: {}",
            kind
        )));
    }
    Ok(())
}

/// Validate a key ID string to prevent path traversal and malformed identifiers.
pub fn validate_key_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_KEY_ID_LEN {
        return Err(KeystoreError::InvalidKeyId(format!(
            "invalid key id length: must be 1..={}",
            MAX_KEY_ID_LEN
        )));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(KeystoreError::InvalidKeyId(
            "invalid key id charset: must be alphanumeric, '.', '_', or '-'".to_string(),
        ));
    }
    if id.starts_with('.') || id.contains("..") {
        return Err(KeystoreError::PathTraversal(id.to_string()));
    }
    Ok(())
}

/// Key entry stored in the keystore with redacted Debug formatting.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct KeyEntry {
    #[zeroize(skip)]
    pub id: String,
    #[zeroize(skip)]
    pub kind: String,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyEntry")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("data", &format!("<redacted {} bytes>", self.data.len()))
            .finish()
    }
}

impl std::fmt::Display for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyEntry(id={}, kind={})", self.id, self.kind)
    }
}

impl KeyEntry {
    /// Create a new key entry with validation.
    pub fn new(id: String, kind: String, data: Vec<u8>) -> Result<Self> {
        validate_key_id(&id)?;
        validate_key_type(&kind)?;
        if data.len() > MAX_KEY_DATA_SIZE {
            return Err(KeystoreError::InvalidKeyLength {
                expected: MAX_KEY_DATA_SIZE,
                actual: data.len(),
            });
        }
        match kind.as_str() {
            KEY_TYPE_ED25519 => validate_ed25519_secret_key(&data)?,
            KEY_TYPE_BLS => validate_bls12_381_secret_key(&data)?,
            KEY_TYPE_ACCOUNT => validate_secp256k1_secret_key(&data)?,
            _ => {}
        }
        Ok(Self { id, kind, data })
    }
}

/// Pluggable asynchronous keystore trait.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a key entry into the keystore.
    async fn put(&self, key: KeyEntry) -> Result<()>;

    /// Retrieve a key entry by ID from the keystore.
    async fn get(&self, id: &str) -> Result<Option<KeyEntry>>;

    /// Delete a key entry by ID from the keystore.
    async fn delete(&self, id: &str) -> Result<()>;

    /// List all key IDs present in the keystore.
    async fn list(&self) -> Result<Vec<String>>;

    /// Check if a key ID exists in the keystore.
    async fn exists(&self, id: &str) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }
}

/// Extension trait providing typed key storage and retrieval methods.
#[async_trait]
pub trait KeyStoreExt: KeyStore {
    /// Store an Ed25519 private key.
    async fn put_ed25519_key(&self, id: &str, key: &Ed25519PrivateKey) -> Result<()> {
        validate_ed25519_secret_key(&key.0)?;
        let entry = KeyEntry::new(id.to_string(), KEY_TYPE_ED25519.to_string(), key.0.to_vec())?;
        self.put(entry).await
    }

    /// Retrieve an Ed25519 private key.
    async fn get_ed25519_key(&self, id: &str) -> Result<Option<Ed25519PrivateKey>> {
        match self.get(id).await? {
            Some(entry) => {
                if entry.kind != KEY_TYPE_ED25519 {
                    return Err(KeystoreError::InvalidKeyType(format!(
                        "key '{}' is of kind '{}', expected '{}'",
                        id, entry.kind, KEY_TYPE_ED25519
                    )));
                }
                validate_ed25519_secret_key(&entry.data)?;
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&entry.data);
                Ok(Some(Ed25519PrivateKey(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Store a BLS12-381 private key.
    async fn put_bls_key(&self, id: &str, key: &BlsPrivateKey) -> Result<()> {
        validate_bls12_381_secret_key(&key.0)?;
        let entry = KeyEntry::new(id.to_string(), KEY_TYPE_BLS.to_string(), key.0.clone())?;
        self.put(entry).await
    }

    /// Retrieve a BLS12-381 private key.
    async fn get_bls_key(&self, id: &str) -> Result<Option<BlsPrivateKey>> {
        match self.get(id).await? {
            Some(entry) => {
                if entry.kind != KEY_TYPE_BLS {
                    return Err(KeystoreError::InvalidKeyType(format!(
                        "key '{}' is of kind '{}', expected '{}'",
                        id, entry.kind, KEY_TYPE_BLS
                    )));
                }
                validate_bls12_381_secret_key(&entry.data)?;
                Ok(Some(BlsPrivateKey(entry.data.clone())))
            }
            None => Ok(None),
        }
    }

    /// Store an account private key by address.
    async fn put_account_key(&self, address: &Address, key_bytes: &[u8; 32]) -> Result<()> {
        validate_secp256k1_secret_key(key_bytes)?;
        let id = format!("account-{}", hex::encode(address.as_bytes()));
        let entry = KeyEntry::new(id, KEY_TYPE_ACCOUNT.to_string(), key_bytes.to_vec())?;
        self.put(entry).await
    }

    /// Retrieve an account private key by address.
    async fn get_account_key(&self, address: &Address) -> Result<Option<[u8; 32]>> {
        let id = format!("account-{}", hex::encode(address.as_bytes()));
        match self.get(&id).await? {
            Some(entry) => {
                validate_secp256k1_secret_key(&entry.data)?;
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&entry.data);
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

impl<T: KeyStore + ?Sized> KeyStoreExt for T {}
