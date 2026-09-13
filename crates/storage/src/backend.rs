//! Core storage trait definitions for the SXIAUM blockchain node.
//!
//! Defines the pluggable [`DatabaseBackend`] trait which allows abstracting over
//! persistent database engines (such as `redb` or `RocksDB`) and in-memory execution engines
//! for stateless clients and testing.

use anyhow::Result;

/// List of state updates to apply atomically.
/// `(key, Some(value))` represents an insertion/update,
/// while `(key, None)` represents a deletion.
pub type StateUpdates = Vec<(Vec<u8>, Option<Vec<u8>>)>;

/// A pluggable storage abstraction for the SXIAUM node.
///
/// Implemented by [`StorageEngine`](crate::StorageEngine) for durable disk storage
/// and [`MemoryDatabaseBackend`](crate::MemoryDatabaseBackend) for in-memory and stateless execution.
pub trait DatabaseBackend: Send + Sync {
    // ========================================================================
    // State Operations
    // ========================================================================

    /// Get the latest processed block height recorded in storage.
    fn latest_block_height(&self) -> Result<u64>;

    /// Read a single state value by its key.
    fn state_get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>>;

    /// Put a single key-value pair into the state.
    fn state_put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()>;

    /// Delete a single key from the state.
    fn state_delete(&self, key: Vec<u8>) -> Result<()>;

    /// Atomically commit a batch of state insertions, updates, and deletions.
    fn atomic_state_commit(&self, changes: StateUpdates) -> Result<()>;

    /// Asynchronously buffer a batch of state updates to be flushed later.
    fn atomic_state_commit_async(&self, changes: StateUpdates) -> Result<()>;

    /// Execute a point-in-time snapshot read for multiple state keys.
    fn state_snapshot_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>>;

    /// Execute parallel state reads across available thread pools.
    fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>>;

    /// Scan all state keys matching a given prefix.
    fn state_prefix_scan(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Scan state keys in lexicographical range `[start, end)` up to `limit` entries.
    fn state_range_scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Roll back a batch of state changes by applying an inverse undo diff.
    fn rollback_state_batch(&self, undo_changes: StateUpdates) -> Result<()> {
        let mut reversed = undo_changes;
        reversed.reverse();
        self.atomic_state_commit(reversed)
    }

    /// Flush all buffered write transactions and synchronization barriers to disk.
    fn flush_to_disk(&self) -> Result<()>;

    // ========================================================================
    // Verkle Tree Operations
    // ========================================================================

    /// Load a Verkle tree node by its commitment hash.
    fn load_verkle_node(&self, node_hash: [u8; 32]) -> Result<Option<Vec<u8>>>;

    /// Store a single Verkle tree node by its commitment hash.
    fn store_verkle_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) -> Result<()>;

    /// Batch store multiple Verkle tree nodes in a single atomic operation.
    fn batch_store_verkle_nodes(&self, nodes: &[([u8; 32], Vec<u8>)]) -> Result<()>;
}
