//! Persistent and in-memory storage engine for the SXIAUM blockchain node.
//!
//! Provides transactional key-value tables, block indexing, canonical chain tracking,
//! state caching, verkle trees, receipts, validator snapshots, and mempool persistence.

pub mod backend;
pub mod error;
pub mod memory;
pub mod redb_store;
pub mod schema;
pub(crate) mod tables;
mod util;

pub use crate::backend::{DatabaseBackend, StateUpdates};
pub use crate::error::{StorageError, StorageResult};
pub use crate::memory::MemoryDatabaseBackend;
pub use crate::redb_store::{StorageEngine, DB_VERSION};
pub use crate::schema::*;
pub use crate::tables::*;
