//! Storage recovery and state healing pipeline.
//!
//! Provides deterministic recovery mechanisms without silently discarding
//! or corrupting existing on-disk state.

use crate::node::Node;
use anyhow::{bail, Context, Result};
use std::path::Path;
use sxiaum_block::Block;
use tracing::info;

pub struct Recovery;

impl Recovery {
    /// Full recovery pipeline — runs all four steps in order.
    ///
    /// Call this during node startup if the storage path exists but may be
    /// stale or inconsistent (e.g. after a crash or ungraceful shutdown).
    pub async fn run(node: &mut Node, storage_path: &str) -> Result<()> {
        // Step 1: verify storage integrity (fails closed if corrupted).
        Self::detect_and_repair_storage(storage_path)?;

        // Step 2: restore from snapshot if one is available.
        let snapshot_path = format!("{}.snapshot", storage_path);
        if Path::new(&snapshot_path).exists() {
            Self::restore_from_snapshot(&snapshot_path, storage_path)?;
        }

        // Step 3: replay recent blocks to heal in-memory state.
        let from_height = node.storage.latest_block_height()?.saturating_sub(128);
        Self::replay_recent_blocks(node, from_height).await?;

        // Step 4: recover consensus state.
        Self::recover_consensus_state(node).await?;

        Ok(())
    }

    /// Step 1 — Detect corrupted storage.
    ///
    /// Verifies that the persistent database at `storage_path` is healthy.
    /// If opening or integrity checks fail, returns an error and fails closed.
    /// Never silently overwrites or re-initializes corrupted storage.
    pub fn detect_and_repair_storage(storage_path: &str) -> Result<()> {
        info!("Running storage integrity check for {}...", storage_path);
        let path = Path::new(storage_path);
        if !path.exists() {
            return Ok(()); // Fresh start — nothing to check.
        }

        let storage = sxiaum_storage::StorageEngine::new(storage_path)
            .with_context(|| format!("Failed to open storage engine at {}", storage_path))?;

        if !storage.check_integrity()? {
            bail!(
                "STORAGE CORRUPTION: Storage integrity check failed for {}. Manual intervention required.",
                storage_path
            );
        }

        info!("Storage integrity check passed for {}.", storage_path);
        Ok(())
    }

    /// Step 2 — Restore from snapshot.
    ///
    /// Copies a previously-taken storage snapshot over the active database
    /// path so the node starts from a known-good state.
    pub fn restore_from_snapshot(
        snapshot_path: impl AsRef<Path>,
        storage_path: impl AsRef<Path>,
    ) -> Result<()> {
        info!(
            "Restoring storage from snapshot {:?}...",
            snapshot_path.as_ref()
        );
        if !snapshot_path.as_ref().exists() {
            bail!("Snapshot file not found: {:?}", snapshot_path.as_ref());
        }

        sxiaum_storage::StorageEngine::restore_from_snapshot(snapshot_path, storage_path.as_ref())?;
        info!("Storage successfully restored from snapshot.");
        Ok(())
    }

    /// Step 3 — Replay recent blocks.
    ///
    /// Re-executes every stored block from `from_height` to the current chain
    /// tip against the in-memory state trie.
    ///
    /// Fails closed if any block in the contiguous sequence is missing or fails execution.
    pub async fn replay_recent_blocks(node: &mut Node, from_height: u64) -> Result<u64> {
        let latest_height = node.storage.latest_block_height()?;
        if latest_height == 0 {
            return Ok(0);
        }

        let effective_from_height = if from_height > 0 {
            let base_height = from_height - 1;
            if node.state.load_snapshot(base_height).is_ok() {
                info!(
                    "Loaded state snapshot at height {} as base for replay",
                    base_height
                );
                from_height
            } else {
                tracing::warn!(
                    "No state snapshot at height {} — starting block replay from genesis (height 0) to ensure continuous state transitions",
                    base_height
                );
                0
            }
        } else {
            0
        };

        info!(
            "Replaying blocks {} to {} for state healing...",
            effective_from_height, latest_height
        );

        let mut replayed = 0u64;
        let mut last_header_state_root = None;
        for height in effective_from_height..=latest_height {
            let header = node.storage.get_block_header(height)?.ok_or_else(|| {
                anyhow::anyhow!("Missing block header at height {} during replay", height)
            })?;
            let body = node.storage.get_block_body(height)?.ok_or_else(|| {
                anyhow::anyhow!("Missing block body at height {} during replay", height)
            })?;

            let block = Block::new(header.clone(), body);
            let computed_root = match node.execution.execute_block(block) {
                Ok(root) => root,
                Err(error) => {
                    let _ = node.state.rollback();
                    return Err(error)
                        .context(format!("Failed to execute block at height {}", height));
                }
            };

            if computed_root != header.state_root {
                let _ = node.state.rollback();
                bail!(
                    "State root mismatch during replay at height {}: computed=0x{}, header=0x{}",
                    height,
                    hex::encode(computed_root),
                    hex::encode(header.state_root)
                );
            }

            last_header_state_root = Some(header.state_root);
            replayed = replayed.saturating_add(1);
        }

        let final_root = node.state.commit()?;
        if let Some(expected) = last_header_state_root {
            if final_root != expected {
                let _ = node.state.rollback();
                bail!(
                    "Final state root mismatch after replay commit: committed=0x{}, expected=0x{}",
                    hex::encode(final_root),
                    hex::encode(expected)
                );
            }
        }

        info!(
            "Block replay complete: replayed={}, final_state_root=0x{}",
            replayed,
            hex::encode(final_root)
        );
        Ok(replayed)
    }

    /// Step 4 — Recover consensus state.
    ///
    /// Reloads the last persisted HotStuff view number and validator-set
    /// snapshot from storage so the consensus engine can resume round
    /// advancement without re-requesting a full validator-set sync from peers.
    pub async fn recover_consensus_state(node: &mut Node) -> Result<u64> {
        info!("Recovering HotStuff consensus state from persistent storage...");
        let view = node.consensus.write().await.start()?;
        info!("Consensus state recovered at view {}.", view);
        Ok(view)
    }
}
