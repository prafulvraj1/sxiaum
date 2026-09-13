use crate::node::VerkleNode;
use crate::verkle_tree::VerkleTree;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use sxiaum_crypto::hash::sha256;

/// Represents a contiguous chunk of state leaves.
#[derive(Clone, Debug, Default)]
pub struct StateChunk {
    pub items: Vec<([u8; 32], [u8; 32])>,
}

impl StateChunk {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.items.len() * 64);
        for (k, v) in &self.items {
            out.extend_from_slice(k);
            out.extend_from_slice(v);
        }
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        if !bytes.len().is_multiple_of(64) {
            return Err(anyhow!("Invalid chunk length: not a multiple of 64"));
        }
        let mut items = Vec::with_capacity(bytes.len() / 64);
        for chunk in bytes.chunks_exact(64) {
            let mut k = [0u8; 32];
            let mut v = [0u8; 32];
            k.copy_from_slice(&chunk[0..32]);
            v.copy_from_slice(&chunk[32..64]);
            items.push((k, v));
        }
        Ok(Self { items })
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.serialize())
    }
}

pub struct StateSnapshotGenerator {
    chunk_size: usize,
}

/// Magic + version header guarding the snapshot file format.
const SNAPSHOT_MAGIC: &[u8; 8] = b"SXSNAP01";

impl StateSnapshotGenerator {
    pub fn new(chunk_size: usize) -> Self {
        if chunk_size == 0 {
            panic!("snapshot chunk_size must be non-zero");
        }
        Self { chunk_size }
    }

    pub fn generate(&self, tree: &VerkleTree, path: impl AsRef<Path>) -> Result<()> {
        let mut chunks = Vec::new();
        let mut current_chunk = StateChunk::default();

        // 1. Collect all leaves
        let mut leaves = Vec::new();
        Self::collect_leaves(&tree.root, &mut Vec::new(), &mut leaves);

        // 2. Chunk them up
        for (k, v) in leaves {
            current_chunk.items.push((k, v));
            if current_chunk.items.len() >= self.chunk_size {
                chunks.push(std::mem::take(&mut current_chunk));
            }
        }
        if !current_chunk.items.is_empty() {
            chunks.push(current_chunk);
        }

        // 3. Write to disk
        // Format:
        // [8 bytes magic "SXSNAP01"]
        // [4 bytes num_chunks]
        // [32 bytes state_root]
        // For each chunk:
        // [4 bytes length] [32 bytes chunk hash] [chunk bytes]
        let mut file = File::create(path)?;
        file.write_all(SNAPSHOT_MAGIC)?;
        file.write_all(&(chunks.len() as u32).to_le_bytes())?;
        file.write_all(&tree.root_commitment())?;

        for chunk in &chunks {
            let bytes = chunk.serialize();
            file.write_all(&(bytes.len() as u32).to_le_bytes())?;
            file.write_all(&chunk.hash())?;
            file.write_all(&bytes)?;
        }
        file.flush()?;

        Ok(())
    }

    fn collect_leaves(
        node: &VerkleNode,
        current_path: &mut Vec<usize>,
        leaves: &mut Vec<([u8; 32], [u8; 32])>,
    ) {
        if node.is_leaf() {
            if let Some(val) = node.value {
                let mut key = [0u8; 32];
                for (i, &idx) in current_path.iter().enumerate() {
                    if i < 32 {
                        key[i] = idx as u8;
                    }
                }
                leaves.push((key, val));
            }
            return;
        }

        for (idx, child) in node.children.iter().enumerate() {
            if let Some(child_node) = child {
                current_path.push(idx);
                Self::collect_leaves(child_node, current_path, leaves);
                current_path.pop();
            }
        }
    }
}

pub struct StateSnapshotRestorer;

impl StateSnapshotRestorer {
    /// Maximum number of chunks allowed in a snapshot file (prevents OOM).
    const MAX_SNAPSHOT_CHUNKS: usize = 1_000_000;
    /// Maximum size of a single chunk in bytes (prevents OOM).
    const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024; // 64 MB

    pub fn restore(path: impl AsRef<Path>, expected_root: [u8; 32]) -> Result<VerkleTree> {
        let mut file = File::open(path)?;

        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)?;
        if &magic != SNAPSHOT_MAGIC {
            return Err(anyhow!(
                "not a SXIAUM state snapshot (bad magic header) — regenerate the snapshot \
                 with the current version"
            ));
        }

        let mut num_chunks_bytes = [0u8; 4];
        file.read_exact(&mut num_chunks_bytes)?;
        let num_chunks = u32::from_le_bytes(num_chunks_bytes) as usize;
        if num_chunks > Self::MAX_SNAPSHOT_CHUNKS {
            return Err(anyhow!(
                "snapshot chunk count {} exceeds maximum {}",
                num_chunks,
                Self::MAX_SNAPSHOT_CHUNKS
            ));
        }

        let mut root_bytes = [0u8; 32];
        file.read_exact(&mut root_bytes)?;
        if root_bytes != expected_root {
            return Err(anyhow!("Snapshot root does not match expected root"));
        }

        let mut tree = VerkleTree::new();

        for _ in 0..num_chunks {
            let mut len_bytes = [0u8; 4];
            file.read_exact(&mut len_bytes)?;
            let len = u32::from_le_bytes(len_bytes) as usize;
            if len > Self::MAX_CHUNK_SIZE {
                return Err(anyhow!(
                    "chunk size {} exceeds maximum {}",
                    len,
                    Self::MAX_CHUNK_SIZE
                ));
            }

            let mut chunk_hash = [0u8; 32];
            file.read_exact(&mut chunk_hash)?;

            let mut chunk_data = vec![0u8; len];
            file.read_exact(&mut chunk_data)?;

            // Integrity: every chunk is bound by its SHA-256 digest so silent
            // bit-rot or truncation inside a chunk cannot pass unnoticed even
            // before the final root check.
            let actual_hash = sha256(&chunk_data);
            if actual_hash != chunk_hash {
                return Err(anyhow!(
                    "snapshot chunk hash mismatch: expected 0x{}, got 0x{}",
                    hex::encode(chunk_hash),
                    hex::encode(actual_hash)
                ));
            }

            let chunk = StateChunk::deserialize(&chunk_data)?;
            for (k, v) in chunk.items {
                tree.insert(k, v)?;
            }
        }

        if tree.root_commitment() != expected_root {
            return Err(anyhow!(
                "Restored tree root does not match expected root after inserting all leaves"
            ));
        }

        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::{StateChunk, StateSnapshotGenerator, StateSnapshotRestorer};
    use crate::verkle_tree::VerkleTree;

    fn temp_snapshot_path(name: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-snapshot-{name}-{unique}.bin"))
    }

    fn sample_tree() -> VerkleTree {
        let mut tree = VerkleTree::new();
        for i in 0..5u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            let value = [i.wrapping_add(100); 32];
            tree.insert(key, value)
                .expect("sample tree insert should succeed");
        }
        tree
    }

    #[test]
    fn state_chunk_serialization_round_trip() {
        let chunk = StateChunk {
            items: vec![([1u8; 32], [2u8; 32]), ([3u8; 32], [4u8; 32])],
        };
        let bytes = chunk.serialize();
        assert_eq!(bytes.len(), 128);

        let decoded = StateChunk::deserialize(&bytes).expect("chunk decode should succeed");
        assert_eq!(decoded.items, chunk.items);
        // Truncated payloads (not a multiple of 64) must be rejected.
        assert!(StateChunk::deserialize(&bytes[..63]).is_err());
        assert!(StateChunk::deserialize(&bytes[..100]).is_err());
        assert!(StateChunk::deserialize(&[]).is_ok());
    }

    #[test]
    fn snapshot_generate_restore_round_trip() {
        let tree = sample_tree();
        let root = tree.root_commitment();
        let path = temp_snapshot_path("round-trip");

        StateSnapshotGenerator::new(2)
            .generate(&tree, &path)
            .expect("snapshot generation should succeed");

        let restored =
            StateSnapshotRestorer::restore(&path, root).expect("snapshot restore should succeed");

        assert_eq!(restored.root_commitment(), root);
        for i in 0..5u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            assert_eq!(
                restored.get(key).expect("restored read should succeed"),
                Some([i.wrapping_add(100); 32])
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restore_rejects_wrong_root() {
        let tree = sample_tree();
        let path = temp_snapshot_path("wrong-root");

        StateSnapshotGenerator::new(3)
            .generate(&tree, &path)
            .expect("snapshot generation should succeed");

        let wrong_root = [0xFFu8; 32];
        assert!(StateSnapshotRestorer::restore(&path, wrong_root).is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restore_rejects_bad_magic_and_corrupt_chunk() {
        let tree = sample_tree();
        let path = temp_snapshot_path("corrupt");

        StateSnapshotGenerator::new(4)
            .generate(&tree, &path)
            .expect("snapshot generation should succeed");
        let root = tree.root_commitment();

        // Bad magic header must be rejected.
        let bad_magic_path = temp_snapshot_path("bad-magic");
        std::fs::copy(&path, &bad_magic_path).expect("copy should succeed");
        let mut bytes = std::fs::read(&bad_magic_path).expect("read should succeed");
        bytes[0] = b'X';
        std::fs::write(&bad_magic_path, &bytes).expect("write should succeed");
        assert!(StateSnapshotRestorer::restore(&bad_magic_path, root).is_err());

        // A flipped byte inside a chunk payload must trip the chunk hash check.
        let mut bytes = std::fs::read(&path).expect("read should succeed");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).expect("write should succeed");
        assert!(StateSnapshotRestorer::restore(&path, root).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&bad_magic_path);
    }
}
