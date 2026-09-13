//! Shared storage helpers used by both the persistent `redb` engine and the
//! in-memory backend.
//!
//! Centralises canonical-chain invariant verification, canonical payload
//! decoding, mempool eviction ranking, and the peer-ban wire codec so the two
//! backends cannot drift apart behaviourally.

use crate::error::StorageError;
use anyhow::Result;
use sxiaum_block::{BlockBody, BlockHeader};
use sxiaum_types::{Canonical, Transaction};

/// Decode a canonically-serialized payload, falling back to legacy plain
/// bincode for rows written by older node versions.
pub(crate) fn decode_canonical<T: Canonical>(bytes: &[u8]) -> Result<T> {
    T::decode(bytes).or_else(|_| {
        if bytes.len() > 8 * 1024 * 1024 {
            anyhow::bail!("decode input exceeds maximum canonical size");
        }
        bincode::deserialize(bytes).map_err(Into::into)
    })
}

// ============================================================================
// Canonical chain invariant verification
// ============================================================================

/// One decoded canonical-chain row handed to [`verify_canonical_sequence`].
pub(crate) struct CanonicalRow {
    /// Block height (key of the canonical chain table).
    pub height: u64,
    /// Canonical block hash recorded for this height.
    pub hash: [u8; 32],
    /// Serialized block header.
    pub header_bytes: Vec<u8>,
    /// Serialized block body.
    pub body_bytes: Vec<u8>,
    /// Height recorded for `hash` in the block-hash index, if any.
    pub indexed_height: Option<u64>,
}

/// Verify relational and cryptographic integrity across an ordered sequence of
/// canonical chain entries: hash recomputation, height agreement, contiguous
/// heights, parent-link chaining, genesis rules, Merkle roots against bodies,
/// and hash-index consistency.
///
/// Rows MUST be supplied in ascending height order (`BTreeMap` iteration order
/// satisfies this for both backends).
pub(crate) fn verify_canonical_sequence(
    rows: impl IntoIterator<Item = CanonicalRow>,
) -> Result<()> {
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut expected_h = 0u64;

    for CanonicalRow {
        height,
        hash,
        header_bytes,
        body_bytes,
        indexed_height,
    } in rows
    {
        let header = decode_canonical::<BlockHeader>(&header_bytes).map_err(|e| {
            StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!("Failed to decode block header: {}", e),
            }
        })?;

        let computed_hash = header
            .try_hash()
            .map_err(|e| StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!("Failed to compute header hash: {}", e),
            })?;

        if computed_hash != hash {
            return Err(StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!(
                    "Header computed hash {:?} != canonical hash {:?}",
                    computed_hash, hash
                ),
            }
            .into());
        }

        if header.height != height {
            return Err(StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!(
                    "Header internal height {} != canonical table height {}",
                    header.height, height
                ),
            }
            .into());
        }

        match prev_hash {
            Some(p_hash) => {
                if height != expected_h {
                    return Err(StorageError::CorruptBlockIndex {
                        hash,
                        height,
                        reason: format!(
                            "Height gap in canonical chain: expected {}, got {}",
                            expected_h, height
                        ),
                    }
                    .into());
                }
                if header.parent_hash != p_hash {
                    return Err(StorageError::CorruptBlockIndex {
                        hash,
                        height,
                        reason: format!(
                            "Parent hash mismatch at height {}: expected {:?}, got {:?}",
                            height, p_hash, header.parent_hash
                        ),
                    }
                    .into());
                }
            }
            None => {
                if height == 0 && header.parent_hash != [0u8; 32] {
                    return Err(StorageError::CorruptBlockIndex {
                        hash,
                        height: 0,
                        reason: "Genesis block must have parent hash [0u8; 32]".to_string(),
                    }
                    .into());
                }
            }
        }

        let body = decode_canonical::<BlockBody>(&body_bytes).map_err(|e| {
            StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!("Failed to decode block body: {}", e),
            }
        })?;

        let tx_root = body
            .compute_tx_root()
            .map_err(|e| StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!("Failed to compute body tx_root: {}", e),
            })?;

        if header.tx_root != tx_root {
            return Err(StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!(
                    "Header tx_root {:?} != body tx_root {:?}",
                    header.tx_root, tx_root
                ),
            }
            .into());
        }

        let receipt_root =
            body.compute_receipt_root()
                .map_err(|e| StorageError::CorruptBlockIndex {
                    hash,
                    height,
                    reason: format!("Failed to compute body receipt_root: {}", e),
                })?;

        if header.receipts_root != receipt_root {
            return Err(StorageError::CorruptBlockIndex {
                hash,
                height,
                reason: format!(
                    "Header receipts_root {:?} != body receipt_root {:?}",
                    header.receipts_root, receipt_root
                ),
            }
            .into());
        }

        if indexed_height != Some(height) {
            return Err(StorageError::InvalidCanonicalMapping {
                height,
                expected: hash,
                actual: None,
            }
            .into());
        }

        prev_hash = Some(hash);
        expected_h = height + 1;
    }

    Ok(())
}

// ============================================================================
// Mempool priority eviction
// ============================================================================

/// Deterministically select the lowest-priority mempool entries to evict when
/// over capacity: cheapest gas price first, tie-broken by sender address and
/// nonce so every backend evicts identically.
pub(crate) fn select_lowest_priority_evictions(
    entries: Vec<([u8; 32], Transaction)>,
    max_entries: usize,
) -> Vec<[u8; 32]> {
    if entries.len() <= max_entries {
        return Vec::new();
    }

    let mut ranked = entries;
    ranked.sort_by(|left, right| {
        let left_priority = (left.1.gas_price, left.1.from, left.1.nonce);
        let right_priority = (right.1.gas_price, right.1.from, right.1.nonce);
        left_priority.cmp(&right_priority)
    });

    let overflow = ranked.len().saturating_sub(max_entries);
    ranked
        .into_iter()
        .take(overflow)
        .map(|(hash, _)| hash)
        .collect()
}

// ============================================================================
// Peer ban codec
// ============================================================================

/// Encode a peer ban as `<expiry_unix>:<reason>` bytes.
pub(crate) fn encode_peer_ban(expiry_unix: u64, reason: &str) -> Vec<u8> {
    format!("{}:{}", expiry_unix, reason).into_bytes()
}

/// Parse a peer-ban payload. Returns `None` for malformed or non-UTF-8 rows.
/// Reasons may themselves contain `:`; only the first separator is consumed.
pub(crate) fn parse_peer_ban(bytes: &[u8]) -> Option<(u64, String)> {
    let str_val = std::str::from_utf8(bytes).ok()?;
    let (exp_str, reason) = str_val.split_once(':')?;
    Some((exp_str.parse::<u64>().unwrap_or(0), reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sxiaum_block::{BlockBody, BlockHeader};

    #[test]
    fn peer_ban_codec_round_trips_reason_with_colons() {
        let encoded = encode_peer_ban(1750000000, "invalid block: bad proposal");
        assert_eq!(
            parse_peer_ban(&encoded),
            Some((1750000000, "invalid block: bad proposal".to_string()))
        );
        assert_eq!(parse_peer_ban(b"not-a-ban"), None);
        assert_eq!(parse_peer_ban(&[0xff, 0xfe]), None);
    }

    #[test]
    fn canonical_sequence_accepts_valid_chain() {
        let h0 = BlockHeader::new([0u8; 32], 0);
        let b0 = BlockBody::new();
        let h0_hash = h0.try_hash().unwrap();
        let h1 = BlockHeader::new(h0_hash, 1);
        let b1 = BlockBody::new();
        let h1_hash = h1.try_hash().unwrap();

        let rows = vec![
            CanonicalRow {
                height: 0,
                hash: h0_hash,
                header_bytes: h0.try_encode().unwrap(),
                body_bytes: b0.try_encode().unwrap(),
                indexed_height: Some(0),
            },
            CanonicalRow {
                height: 1,
                hash: h1_hash,
                header_bytes: h1.try_encode().unwrap(),
                body_bytes: b1.try_encode().unwrap(),
                indexed_height: Some(1),
            },
        ];
        assert!(verify_canonical_sequence(rows).is_ok());
    }

    #[test]
    fn canonical_sequence_rejects_parent_link_tamper() {
        let h0 = BlockHeader::new([0u8; 32], 0);
        let b0 = BlockBody::new();
        let h0_hash = h0.try_hash().unwrap();
        // Parent hash points nowhere near h0.
        let h1 = BlockHeader::new([0xAA; 32], 1);
        let b1 = BlockBody::new();
        let h1_hash = h1.try_hash().unwrap();

        let rows = vec![
            CanonicalRow {
                height: 0,
                hash: h0_hash,
                header_bytes: h0.try_encode().unwrap(),
                body_bytes: b0.try_encode().unwrap(),
                indexed_height: Some(0),
            },
            CanonicalRow {
                height: 1,
                hash: h1_hash,
                header_bytes: h1.try_encode().unwrap(),
                body_bytes: b1.try_encode().unwrap(),
                indexed_height: Some(1),
            },
        ];
        let err = verify_canonical_sequence(rows).expect_err("tampered parent must fail");
        assert!(
            err.to_string().contains("Parent hash mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn canonical_sequence_rejects_body_tx_root_mismatch() {
        let mut header = BlockHeader::new([0u8; 32], 0);
        // Empty body does not match a header claiming a non-empty tx root.
        header.tx_root = [0x77; 32];

        let err = verify_canonical_sequence(vec![CanonicalRow {
            height: 0,
            hash: header.try_hash().unwrap(),
            header_bytes: header.try_encode().unwrap(),
            body_bytes: BlockBody::new().try_encode().unwrap(),
            indexed_height: Some(0),
        }])
        .expect_err("tx root mismatch must fail");
        assert!(
            err.to_string().contains("tx_root"),
            "unexpected error: {err}"
        );
    }
}
