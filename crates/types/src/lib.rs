use serde::{Deserialize, Serialize};
use thiserror::Error;
pub mod account;
pub mod address;
pub mod message;
pub mod serialization;
pub mod transaction;
pub mod validator;
pub mod vesting;
pub use crate::account::{compute_storage_root, Account, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT, MAX_STORAGE_ENTRIES};
pub use crate::address::{eip55_checksum, Address, AddressError};
pub use crate::message::{CanonicalMessage, NetworkMessage, CANONICAL_MESSAGE_VERSION, MAX_CANONICAL_MESSAGE_SIZE, MAX_HEADERS_PER_MESSAGE, MAX_SYNC_BLOCKS_PER_MESSAGE};
pub use crate::serialization::{serde_sig, Canonical};
pub use crate::transaction::{Log, Receipt, Transaction, MAX_LOG_DATA_SIZE, MAX_LOG_TOPICS, MAX_RECEIPT_LOGS, MAX_TX_DATA_SIZE, SECP256K1_N_DIV_2, SXIAUM_CHAIN_ID, SXIAUM_CHAIN_ID_HEX, SXIAUM_CHAIN_ID_STR};
pub use crate::validator::{Validator, ValidatorStatus, BLS_POP_LEN, BLS_PUBKEY_LEN, MAX_COMMISSION_BPS};
pub use crate::vesting::VestingSchedule;
pub type Amount = u128;
pub type Nonce = u64;
pub type Gas = u64;
pub type BlockHeight = u64;
pub type Timestamp = u64;
pub type Hash = [u8; 32];
pub type Signature = Vec<u8>;
pub type PublicKey = [u8; 32];
pub type BlsPublicKey = [u8; 48];
pub type BlsProofOfPossession = [u8; 96];
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ReservationId(pub u64);
#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum TxError {
    #[error("Invalid transaction signature")]
    InvalidSignature,
    #[error("Invalid transaction nonce. Expected {0}, got {1}")]
    InvalidNonce(u64, u64),
    #[error("Insufficient balance to execute transaction")]
    InsufficientBalance,
    #[error("Transaction signature is malleable (high S value)")]
    MalleableSignature,
    #[error("Invalid chain ID: expected {0}, got {1}")]
    InvalidChainId(u64, u64),
    #[error("Gas limit is zero or insufficient for intrinsic cost")]
    InvalidGasLimit,
}
#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum AccountError {
    #[error("Mathematical overflow during account state transition")]
    Overflow,
    #[error("Mathematical underflow during account state transition")]
    Underflow,
    #[error("Account nonce exhausted (reached u64::MAX)")]
    NonceExhausted,
    #[error("Account code hash is not a canonical commitment")]
    InvalidCodeHash,
    #[error("Account storage root is not a canonical commitment")]
    InvalidStorageRoot,
    #[error("Too many storage entries for account storage root")]
    TooManyStorageEntries,
    #[error("Duplicate storage slot in account storage root input")]
    DuplicateStorageSlot,
}
#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum ValidatorError {
    #[error("Insufficient stake to perform this consensus action")]
    InsufficientStake,
    #[error("Validator is jailed and cannot participate in consensus")]
    ValidatorJailed,
    #[error("Invalid BLS Proof-of-Possession signature")]
    InvalidProofOfPossession,
    #[error("Invalid Ed25519 public key")]
    InvalidPublicKey,
    #[error("Validator address does not match public key: expected {expected}, derived {derived}")]
    AddressMismatch { expected: String, derived: String },
    #[error("Commission {actual} bps exceeds maximum allowed {max} bps")]
    CommissionExceeded { actual: u16, max: u16 },
    #[error("Voting power mismatch: expected {expected}, got {actual}")]
    VotingPowerMismatch { expected: u64, actual: u64 },
    #[error("Invalid BLS public key length: expected {expected}, got {actual}")]
    InvalidBlsPublicKeyLength { expected: usize, actual: usize },
    #[error("Invalid BLS Proof-of-Possession length: expected {expected}, got {actual}")]
    InvalidBlsPopLength { expected: usize, actual: usize },
    #[error("Validator must provide both BLS public key and Proof-of-Possession, or neither")]
    IncompleteBlsCredentials,
    #[error("Active validator must have non-zero voting power")]
    ZeroVotingPower,
    #[error("Active validator must not carry a jailing window")]
    ActiveWithJailWindow,
}
#[derive(Error, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum VestingError {
    #[error("No tokens releasable at the current timestamp")]
    NoTokensReleasable,
    #[error("Released wei exceeds total wei")]
    ReleasedExceedsTotal,
    #[error("Cliff seconds exceeds duration seconds")]
    CliffExceedsDuration,
    #[error("Vesting total must be non-zero")]
    InvalidTotal,
    #[error("Vesting schedule parameters are invalid")]
    InvalidSchedule,
}
