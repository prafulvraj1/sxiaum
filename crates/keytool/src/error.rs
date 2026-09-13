//! Error types for the SXIAUM Keytool CLI and library.

use thiserror::Error;

/// Result alias for Keytool operations.
pub type Result<T> = std::result::Result<T, KeytoolError>;

#[derive(Error, Debug)]
pub enum KeytoolError {
    #[error("Keystore error: {0}")]
    Keystore(#[from] sxiaum_keystore::error::KeystoreError),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("Passphrase policy violation: {0}")]
    PassphrasePolicy(String),

    #[error("Passphrases do not match")]
    PassphraseMismatch,

    #[error("Operation aborted by user")]
    Aborted,

    #[error("Invalid key format or missing field: {0}")]
    InvalidFormat(String),

    #[error("Plaintext private key export is forbidden in production unless --allow-insecure-production-plaintext is set")]
    PlaintextInProductionForbidden,

    #[error("General error: {0}")]
    Other(String),
}
