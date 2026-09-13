//! Cryptographic primitives for the SXIAUM blockchain.
//!
//! This crate provides:
//! - BLS12-381 signatures (consensus voting, Proof-of-Possession)
//! - Ed25519 signatures (block/transaction signing)
//! - SHA-256 hashing with domain separation
//! - KZG polynomial commitments (state tree commitments)
//! - Merkle trees (transaction/receipt inclusion proofs)
//! - Remote signer support (HSM/Web3Signer integration)
//!
//! # Mainnet Readiness
//!
//! All cryptographic operations use domain-separated hashing to prevent
//! cross-protocol replay attacks.  BLS signatures use the IETF
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_` ciphersuite with a
//! dedicated Proof-of-Possession DST to prevent rogue-key attacks.
//!
//! The KZG SRS trust policy enforces ceremony-generated parameters
//! in production: the development trapdoor (tau=42) is rejected
//! by both compile-time and runtime checks.
//!
//! # Feature Flags
//!
//! - `remote-signer`: enables [`remote_signer`] (HSM/Web3Signer support).
//!   Pulls in `reqwest` + `tokio`. Off by default; enable only on binaries
//!   that actually delegate signing to a remote HSM.
//! - `fuzz-targets`: exposes `fuzz_target_*` entry points for cargo-fuzz or
//!   external harnesses. Never enabled in production builds.
//! - `dev-kzg-srs`: FORBIDDEN in release builds (compile_error in `kzg.rs`).

pub mod bls;
pub mod ceremony;
pub mod ed25519;
pub mod hash;
pub mod kzg;
pub mod merkle;
#[cfg(feature = "remote-signer")]
pub mod remote_signer;
pub mod signer;

pub use crate::bls::*;
pub use crate::ceremony::{
    ceremony_contribute, ceremony_init, ceremony_verify, verify_srs_structure,
    CeremonyContribution, CeremonyReport, CeremonyTranscript, MIN_CEREMONY_PARTICIPANTS,
};
pub use crate::ed25519::*;
pub use crate::hash::*;
pub use crate::kzg::{
    compute_kzg_commitment, compute_kzg_commitment_bytes, get_empty_commitment, get_empty_proof,
    open_kzg, precompute_kzg_basis, verify_batched_kzg_openings_multi_point,
    verify_batched_kzg_openings_single_point, verify_kzg_opening, SRS,
};
pub use crate::merkle::MerkleTree;
pub use crate::signer::*;

// ---------------------------------------------------------------------------
// Mainnet cryptographic constants
// ---------------------------------------------------------------------------

/// Cryptographic protocol version for the SXIAUM mainnet.
///
/// Increment when a cryptographic primitive is upgraded (e.g. BLS ciphersuite
/// change, hash function change).  Nodes reject blocks whose crypto version
/// they do not understand.
pub const CRYPTO_PROTOCOL_VERSION: u32 = 1;

/// Default timeout for remote signer requests (10 seconds).
pub const REMOTE_SIGNER_TIMEOUT_SECS: u64 = 10;

/// Maximum number of retry attempts for remote signer requests.
pub const REMOTE_SIGNER_MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff between remote signer retries.
pub const REMOTE_SIGNER_RETRY_BASE_MS: u64 = 500;

/// Domain separation tag for Merkle tree node hashing.
/// Prevents cross-protocol second-preimage attacks on Merkle proofs.
pub const DOMAIN_MERKLE_NODE: &str = "SXIAUM_MERKLE";

/// Domain separation tag for Ed25519 transaction signatures.
pub const DOMAIN_TX_SIGNATURE: &str = "SXIAUM_TX_SIG";

/// Domain separation tag for block header signatures.
pub const DOMAIN_BLOCK_SIGNATURE: &str = "SXIAUM_BLOCK_SIG";
