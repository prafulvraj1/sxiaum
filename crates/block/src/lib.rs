pub mod block;
pub mod body;
pub mod error;
pub mod header;

// ---------------------------------------------------------------------------
// Mainnet protocol constants
// ---------------------------------------------------------------------------

/// Canonical maximum serialized block size for the SXIAUM network (2 MB).
pub const MAX_BLOCK_SIZE_BYTES: usize = 2 * 1024 * 1024;

/// Canonical maximum transaction count allowed in a single block.
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;

/// Current block header version for the SXIAUM mainnet protocol.
///
/// Increment this when a hard fork introduces breaking changes to the
/// header layout or consensus rules. Old nodes reject blocks whose
/// version they do not understand.
pub const BLOCK_VERSION_CURRENT: u32 = 1;

/// Maximum block-level gas limit. Individual transactions may specify
/// their own `gas_limit`, but the aggregate `gas_used` in a block header
/// MUST NOT exceed this value.
pub const MAX_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Default block-level gas limit when the proposer does not set one
/// explicitly. This is the standard target on mainnet.
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 15_000_000;

/// Minimum viable block gas limit. Blocks specifying a gas limit below
/// this floor cannot execute even a single minimal transfer.
pub const MIN_BLOCK_GAS_LIMIT: u64 = 5_000;

/// Target block interval in seconds (2 seconds on mainnet).
pub const BLOCK_INTERVAL_SECS: u64 = 2;

/// Maximum acceptable clock drift for a block timestamp, in seconds.
/// A block whose timestamp is more than this many seconds in the future
/// (relative to the verifying node's local clock) is rejected.
pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 5;

/// Minimum allowed timestamp gap between consecutive blocks. A child
/// block's timestamp must be strictly greater than its parent's.
pub const MIN_TIMESTAMP_GAP: u64 = 1;

/// Canonical genesis timestamp for the SXIAUM mainnet (2024-01-01T00:00:00Z).
pub const GENESIS_TIMESTAMP: u64 = 1_704_067_200;

/// Maximum allowed size of the `extra_data` field in the block header (32 bytes).
pub const MAX_EXTRA_DATA_SIZE: usize = 32;

/// Maximum allowed size of an attached ZK validity proof, in bytes.
/// Prevents denial-of-service via unbounded proof blobs in headers.
pub const MAX_ZK_PROOF_SIZE: usize = 256 * 1024; // 256 KB

pub use crate::block::{Block, BlockBuilder};
pub use crate::body::BlockBody;
pub use crate::error::{BlockError, BodyError, HeaderError};
pub use crate::header::BlockHeader;
