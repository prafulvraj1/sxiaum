use thiserror::Error;

/// Keystore specific error types.
#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Decryption failed: invalid password or corrupted data")]
    InvalidPasswordOrCorruptData,

    #[error("Cryptographic MAC verification failed: invalid password")]
    MacMismatch,

    #[error("Key entry '{0}' not found")]
    KeyNotFound(String),

    #[error("Key entry '{0}' already exists")]
    KeyAlreadyExists(String),

    #[error("Corrupted keystore entry '{0}': {1}")]
    CorruptedKeystore(String, String),

    #[error("Unsupported keystore version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported KDF function: {0}")]
    UnsupportedKdf(String),

    #[error("Unsupported cipher algorithm: {0}")]
    UnsupportedCipher(String),

    #[error("Weak passphrase: {0}")]
    WeakPassword(String),

    #[error("Path traversal rejected for key ID: {0}")]
    PathTraversal(String),

    #[error("Invalid key ID: {0}")]
    InvalidKeyId(String),

    #[error("Invalid key type: {0}")]
    InvalidKeyType(String),

    #[error("Invalid key data length: expected {expected} bytes, got {actual} bytes")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Trivial or demo key blocked in production: {0}")]
    TrivialKeyBlocked(String),

    #[error("Plaintext keystore is forbidden when SXIAUM_ENV=production")]
    PlaintextForbiddenInProduction,

    #[error("Legacy v1 keystores are forbidden in production; migrate to v2 (Argon2id)")]
    LegacyFormatForbiddenInProduction,

    #[error("Vault error: {0}")]
    VaultError(String),

    #[error("BIP-39 mnemonic error: {0}")]
    MnemonicError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Generic keystore error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, KeystoreError>;
