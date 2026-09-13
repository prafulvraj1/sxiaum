//! SXIAUM blockchain node implementation.
//!
//! This crate provides the full node implementation that integrates:
//! - P2P networking (gossipsub, Kademlia DHT, request-response RPC)
//! - Consensus engine (HotStuff BFT with 3-phase commit)
//! - Transaction execution (EVM-compatible with parallel pipeline)
//! - Mempool (priority-ordered with MEV-protected commit-reveal)
//! - State management (Verkle tree with KZG commitments)
//! - RPC server (JSON-RPC with JWT authentication)
//! - Light client (header verification with ZK proofs)
//!
//! # Mainnet Readiness
//!
//! The node enforces 11 production preflight gates before startup:
//! 1. ZK proof policy (SP1 mode must be "production")
//! 2. KZG SRS (dev trapdoor tau=42 is rejected)
//! 3. JWT secret minimum entropy (32 bytes / 256-bit)
//! 4. TLS/transport security (cert or reverse proxy required)
//! 5. Validator key quality (no trivial repeated-byte keys)
//! 6. Mainnet genesis placeholders (no ceremony placeholders)
//! 7. Parallel OCC verification (cannot be disabled)
//! 8. No stray key files in deployment directory
//! 9. RPC write authentication (required for non-loopback)
//! 10. Bootnode placeholders (no template addresses)
//! 11. Genesis timestamp non-zero
//!
//! Any gate failure causes `std::process::exit(1)` before any subsystem starts.

pub mod config;
pub mod keys;
pub mod metrics;
pub mod node;
pub mod preflight;
pub mod recovery;
pub mod services;
pub mod shutdown;
pub mod startup;
pub mod state_sync;

pub use crate::config::{KzgConfig, NodeConfig, NodeMode, SyncMode, ZkConfig};
pub use crate::metrics::{MetricsService, NodeMetrics};
pub use crate::node::Node;
pub use crate::preflight::{collect_production_preflight_failures, run_production_preflight};
pub use crate::recovery::Recovery;
pub use crate::services::ServiceManager;
pub use crate::shutdown::Shutdown;
pub use crate::startup::Startup;

// ---------------------------------------------------------------------------
// Mainnet node constants
// ---------------------------------------------------------------------------

/// Consensus event loop tick interval in milliseconds (250ms).
/// Drives view timeouts and block proposal attempts.
pub const CONSENSUS_TICK_INTERVAL_MS: u64 = 250;

/// Maximum block proposal transaction count (256).
/// Limits the number of transactions included in a single block proposal.
pub const MAX_BLOCK_PROPOSAL_TXS: usize = 256;

/// P2P message poll interval in milliseconds (10ms).
/// How often the P2P listener checks for incoming gossip messages.
pub const P2P_MESSAGE_POLL_INTERVAL_MS: u64 = 10;

/// Default data directory for the node.
pub const DEFAULT_DATA_DIR: &str = ".sxiaum";

/// Default P2P listen address.
pub const DEFAULT_P2P_LISTEN_ADDR: &str = "0.0.0.0:9000";

/// Default RPC listen address (loopback only for security).
pub const DEFAULT_RPC_LISTEN_ADDR: &str = "127.0.0.1:8545";
