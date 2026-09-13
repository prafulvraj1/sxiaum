//! Hyper-Stateless Nano-Node (`sxiaum-nano`).
//!
//! Provides zero-disk, memory-bounded, sub-5ms cryptographic verification of the
//! SXIAUM L1 blockchain for smartphones (iOS/Android), smart electric vehicles (Tesla/EVs),
//! IoT sensors, and WebAssembly browser environments.
//!
//! # Architecture Profiles
//!
//! 1. **[`NanoLightClient`] (Profile 1: Zero-Execution Spot-Check Mode)**:
//!    - Verifies block header linkage, proposer Ed25519 signature, and HotStuff QC (>= 2f + 1 stake).
//!    - Spot-checks account balances and smart contract storage slots via constant-size KZG Verkle proofs.
//!    - **0 transaction re-execution**.
//!    - Resource budget: **~2.5 KB proof, ~1.5–2.5 ms, < 2 MB RAM, 0 MB disk**.
//!
//! 2. **[`NanoStatelessValidator`] (Profile 2: Full Stateless Re-execution Mode)**:
//!    - Verifies block header + BFT QC + batched KZG Verkle multiproof for all touched slots.
//!    - Re-executes block transactions against ephemeral in-memory state (`MemoryDatabaseBackend`).
//!    - Asserts computed post-state root equals block header state root.
//!    - Resource budget: **~15–50 KB witness, ~10–25 ms, < 25 MB RAM, 0 MB disk**.
//!
//! # Invariants
//!
//! - **Zero-Disk Invariant**: Performs 0 disk writes; all state and ring buffers reside purely in memory.
//! - **Quorum Strictness**: Strictly enforces $\ge \lfloor \frac{2 \cdot \text{TotalStake}}{3} \rfloor + 1$ active voting power.
//! - **Auditable Validator Rotation**: Tracks epoch boundary transitions via [`EpochHandoverCertificate`].
//! - **Mainnet Replay Protection**: Every header, block, handover certificate, and weak
//!   subjectivity checkpoint is validated against the canonical mainnet chain id
//!   ([`sxiaum_types::SXIAUM_CHAIN_ID`] = 13689) and the mainnet-strict rules of
//!   `sxiaum_block` (`BlockHeader::validate_mainnet` / `Block::validate_mainnet`):
//!   canonical protocol version, gas bounds, and the genesis timestamp floor.
//! - **No-Panic Guarantee**: All public functions return strongly-typed [`NanoError`] via Rust `Result`.

pub mod epoch_sync;
pub mod error;
pub mod ffi;
pub mod light_client;
pub mod validator;
pub mod wasm;

pub use crate::epoch_sync::{
    hotstuff_vote_digest, EpochHandoverCertificate, EpochSyncManager, ValidatorSignature,
    WeakSubjectivityCheckpoint, DEFAULT_MAX_UNBONDING_SECS, DOMAIN_VALIDATOR_SET,
};
pub use crate::error::NanoError;
pub use crate::light_client::{
    NanoLightClient, NanoLightConfig, DEFAULT_MAX_TIMESTAMP_DRIFT, DEFAULT_RING_BUFFER_CAPACITY,
};
pub use crate::validator::{NanoStatelessValidator, NanoValidatorConfig};
