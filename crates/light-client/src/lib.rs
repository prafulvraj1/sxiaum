//! Light client for the SXIAUM blockchain.
//!
//! This crate provides a lightweight client that verifies block headers
//! and maintains a trusted view of the chain without storing full state.
//!
//! # Mainnet Readiness
//!
//! The light client verifies:
//! - Block header linkage (parent hash, height, timestamp)
//! - Proposer Ed25519 signature
//! - BFT consensus quorum (2/3+ voting power)
//! - ZK state transition validity proof
//! - Chain ID (replay protection)
//! - Block version (protocol upgrade safety)
//!
//! All cryptographic verification uses domain-separated hashing to
//! prevent cross-protocol replay attacks.

pub mod client;
pub mod error;
pub mod header_sync;
pub mod proofs;
pub mod stateless;
pub mod verifier;

pub use crate::client::LightClient;
pub use crate::error::LightClientError;
pub use crate::header_sync::{validate_validator_set, HeaderSync, VerifiedHeaderEnvelope};
pub use crate::proofs::ProofVerifier;
pub use crate::stateless::StatelessVerifier;
pub use crate::verifier::HeaderVerifier;

// ---------------------------------------------------------------------------
// Mainnet light-client constants
// ---------------------------------------------------------------------------

/// Maximum number of headers that can be synced in a single batch.
/// Prevents memory exhaustion from a malicious peer sending huge header batches.
pub const MAX_HEADER_BATCH_SIZE: usize = 512;

/// Maximum acceptable timestamp drift (in seconds) for light client verification.
/// Headers with timestamps more than this many seconds in the future are rejected.
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

/// Maximum number of headers the light client retains in memory.
/// Older headers are pruned to prevent unbounded memory growth.
pub const MAX_RETAINED_HEADERS: usize = 1_024;
