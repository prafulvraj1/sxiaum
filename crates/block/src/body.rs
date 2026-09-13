use crate::error::BodyError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use sxiaum_types::{Canonical, Hash, Receipt, Transaction, Validator};

/// Leaf prefix for the block Merkle tree.
///
/// Domain-separated leaf and internal nodes prevent the classic second-preimage
/// attack on naive Merkle trees (Bitcoin CVE-2012-2459) where an attacker could
/// craft a "leaf" that is actually the hash of two children and forge inclusion.
const TX_MERKLE_LEAF_PREFIX: u8 = 0x00;
/// Internal node prefix for the block Merkle tree.
const TX_MERKLE_NODE_PREFIX: u8 = 0x01;

/// Hash a single leaf with the leaf domain tag.
fn tx_merkle_leaf(leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([TX_MERKLE_LEAF_PREFIX]);
    hasher.update(leaf);
    hasher.finalize().into()
}

/// Hash two internal nodes with the node domain tag.
fn tx_merkle_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([TX_MERKLE_NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Constant node used to pad odd-sized Merkle levels up to an even length.
///
/// Padding with a FIXED constant (instead of duplicating the last node) makes
/// the root unambiguous over ordered leaf lists: `[A,B,C]` and `[A,B,C,C]`
/// produce DIFFERENT roots. Under last-node duplication both trees collapse
/// onto the same root, letting an equivocating proposer present two distinct
/// transaction bodies that satisfy one header commitment.
const MERKLE_PAD_NODE: Hash = [0u8; 32];

/// Pad a Merkle level to an even length using the fixed [`MERKLE_PAD_NODE`].
fn pad_level_to_even(level: &mut Vec<[u8; 32]>) {
    if !level.len().is_multiple_of(2) {
        level.push(MERKLE_PAD_NODE);
    }
}

/// Build the next level of internal nodes from a set of raw values.
///
/// `first` marks whether this is the first level (leaves → node): leaves are
/// hashed with the leaf prefix first, then pairs are hashed with the node prefix.
fn build_next_level(values: Vec<[u8; 32]>, first: bool) -> Vec<[u8; 32]> {
    let mut level: Vec<[u8; 32]> = values;
    if first {
        // Tag each leaf with the leaf domain prefix so leaves are
        // distinguishable from internal nodes (second-preimage protection).
        for v in level.iter_mut() {
            *v = tx_merkle_leaf(v);
        }
    }
    pad_level_to_even(&mut level);

    let mut next = Vec::with_capacity(level.len() / 2);
    for chunk in level.chunks_exact(2) {
        next.push(tx_merkle_pair(&chunk[0], &chunk[1]));
    }
    next
}

/// Generate a Merkle inclusion proof for the leaf at `index`.
fn generate_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Result<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return Err(BodyError::EmptyLeaves.into());
    }
    if index >= leaves.len() {
        return Err(BodyError::IndexOutOfBounds {
            index,
            total: leaves.len(),
        }
        .into());
    }

    let mut proof = Vec::new();
    let mut current_index = index;
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut first = true;

    while level.len() > 1 {
        if first {
            for v in level.iter_mut() {
                *v = tx_merkle_leaf(v);
            }
            first = false;
        }
        pad_level_to_even(&mut level);

        let mut next = Vec::with_capacity(level.len() / 2);
        for (chunk_index, chunk) in level.chunks_exact(2).enumerate() {
            let left_idx = chunk_index * 2;
            let right_idx = left_idx + 1;
            if left_idx == current_index || right_idx == current_index {
                let sib_idx = if left_idx == current_index {
                    right_idx
                } else {
                    left_idx
                };
                proof.push(level[sib_idx]);
                current_index /= 2;
            }
            next.push(tx_merkle_pair(&chunk[0], &chunk[1]));
        }
        level = next;
    }

    Ok(proof)
}

/// Verify a Merkle inclusion proof against `root`.
fn verify_merkle_proof(leaf: &[u8; 32], index: usize, proof: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut current = tx_merkle_leaf(leaf);
    let mut idx = index;

    for sibling in proof {
        if idx.is_multiple_of(2) {
            current = tx_merkle_pair(&current, sibling);
        } else {
            current = tx_merkle_pair(sibling, &current);
        }
        idx /= 2;
    }

    current == *root
}

/// Canonical block body containing transactions and execution receipts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BlockBody {
    /// Ordered list of state transition transactions included in this block.
    pub transactions: Vec<Transaction>,
    /// Corresponding execution receipts produced by executing the transactions in order.
    pub receipts: Vec<Receipt>,
}

impl BlockBody {
    /// Create a new empty block body.
    pub fn new() -> Self {
        Self {
            transactions: Vec::new(),
            receipts: Vec::new(),
        }
    }

    /// Create an empty block body for the genesis block.
    pub fn empty() -> Self {
        Self::new()
    }

    /// Add a single transaction to the block body.
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.transactions.push(tx);
    }

    /// Add multiple transactions to the block body.
    pub fn add_transactions(&mut self, txs: impl IntoIterator<Item = Transaction>) {
        self.transactions.extend(txs);
    }

    /// Add a single execution receipt to the block body.
    pub fn add_receipt(&mut self, receipt: Receipt) {
        self.receipts.push(receipt);
    }

    /// Add multiple execution receipts to the block body.
    pub fn add_receipts(&mut self, receipts: impl IntoIterator<Item = Receipt>) {
        self.receipts.extend(receipts);
    }

    /// Return the count of transactions in the block body.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Return the count of receipts in the block body.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Return true if both transactions and receipts are empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.receipts.is_empty()
    }

    /// Serialize the block body into its canonical deterministic binary format.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as Canonical>::try_encode(self)
    }

    /// Deserialize a block body from its canonical binary format.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Return the canonical binary size of the block body in bytes.
    pub fn size_bytes(&self) -> Result<usize> {
        self.try_encode().map(|b| b.len())
    }

    /// Return the Merkle tree root of all transactions (alias for [`compute_tx_root`]).
    pub fn tx_root(&self) -> Result<Hash> {
        self.compute_tx_root()
    }

    /// Return the Merkle tree root of all receipts (alias for [`compute_receipt_root`]).
    pub fn receipts_root(&self) -> Result<Hash> {
        self.compute_receipt_root()
    }

    /// Compute the Merkle tree root of all transactions in the block.
    pub fn compute_tx_root(&self) -> Result<Hash> {
        if self.transactions.is_empty() {
            return Ok([0u8; 32]);
        }
        let mut hashes = Vec::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            hashes.push(tx.try_hash()?);
        }
        Ok(Self::calculate_merkle_root(hashes))
    }

    /// Compute the Merkle tree root of all receipts in the block.
    pub fn compute_receipt_root(&self) -> Result<Hash> {
        if self.receipts.is_empty() {
            return Ok([0u8; 32]);
        }
        let mut hashes = Vec::with_capacity(self.receipts.len());
        for r in &self.receipts {
            hashes.push(r.try_hash()?);
        }
        Ok(Self::calculate_merkle_root(hashes))
    }

    /// Static helper for computing a validator set commitment root.
    pub fn compute_validator_root(validators: &[Validator]) -> Result<Hash> {
        if validators.is_empty() {
            return Ok([0u8; 32]);
        }
        let mut hashes = Vec::with_capacity(validators.len());
        for v in validators {
            hashes.push(v.try_hash()?);
        }
        Ok(Self::calculate_merkle_root(hashes))
    }

    /// Compute the canonical balanced binary Merkle tree root from an arbitrary list of leaf hashes.
    ///
    /// Leaves are prefixed with [`TX_MERKLE_LEAF_PREFIX`] and internal nodes with
    /// [`TX_MERKLE_NODE_PREFIX`] before hashing, preventing second-preimage attacks
    /// where a crafted 32-byte "leaf" could double as an internal node (the classic
    /// Bitcoin CVE-2012-2459 weakness). Odd levels are padded with the fixed
    /// [`MERKLE_PAD_NODE`], so every distinct ordered leaf list yields a distinct root.
    pub fn calculate_merkle_root(leaves: Vec<Hash>) -> Hash {
        if leaves.is_empty() {
            return [0u8; 32];
        }

        let mut level = leaves;
        let mut first = true;
        while level.len() > 1 {
            level = build_next_level(level, first);
            first = false;
        }

        if first {
            // Exactly one leaf was provided; tag it as a leaf.
            return tx_merkle_leaf(&level[0]);
        }
        level[0]
    }

    // --- Merkle Inclusion Proof Generation and Verification ---

    /// Generate a Merkle inclusion proof for a transaction at a specific index.
    pub fn generate_tx_merkle_proof(&self, index: usize) -> Result<Vec<Hash>> {
        if index >= self.transactions.len() {
            return Err(BodyError::IndexOutOfBounds {
                index,
                total: self.transactions.len(),
            }
            .into());
        }

        let mut leaves = Vec::with_capacity(self.transactions.len());
        for tx in &self.transactions {
            leaves.push(tx.try_hash()?);
        }
        let proof = generate_merkle_proof(&leaves, index)?;
        Ok(proof)
    }

    /// Verify a transaction's inclusion in a block using a Merkle proof against `tx_root`.
    pub fn verify_tx_merkle_proof(tx_hash: Hash, index: usize, proof: &[Hash], root: Hash) -> bool {
        verify_merkle_proof(&tx_hash, index, proof, &root)
    }

    /// Generate a Merkle inclusion proof for a receipt at a specific index.
    pub fn generate_receipt_merkle_proof(&self, index: usize) -> Result<Vec<Hash>> {
        if index >= self.receipts.len() {
            return Err(BodyError::IndexOutOfBounds {
                index,
                total: self.receipts.len(),
            }
            .into());
        }

        let mut leaves = Vec::with_capacity(self.receipts.len());
        for r in &self.receipts {
            leaves.push(r.try_hash()?);
        }
        let proof = generate_merkle_proof(&leaves, index)?;
        Ok(proof)
    }

    /// Verify a receipt's inclusion in a block using a Merkle proof against `receipts_root`.
    pub fn verify_receipt_merkle_proof(
        receipt_hash: Hash,
        index: usize,
        proof: &[Hash],
        root: Hash,
    ) -> bool {
        verify_merkle_proof(&receipt_hash, index, proof, &root)
    }

    /// Generate a Merkle inclusion proof for a validator at a specific index.
    pub fn generate_validator_merkle_proof(
        validators: &[Validator],
        index: usize,
    ) -> Result<Vec<Hash>> {
        if index >= validators.len() {
            return Err(BodyError::IndexOutOfBounds {
                index,
                total: validators.len(),
            }
            .into());
        }

        let mut leaves = Vec::with_capacity(validators.len());
        for v in validators {
            leaves.push(v.try_hash()?);
        }
        let proof = generate_merkle_proof(&leaves, index)?;
        Ok(proof)
    }

    /// Verify a validator's inclusion using a Merkle proof against `validator_root`.
    pub fn verify_validator_merkle_proof(
        validator_hash: Hash,
        index: usize,
        proof: &[Hash],
        root: Hash,
    ) -> bool {
        verify_merkle_proof(&validator_hash, index, proof, &root)
    }

    // --- Validation and Gas Methods ---

    /// Basic structural validation for transactions in the body.
    ///
    /// Validates:
    /// * Each transaction passes internal structural validation
    /// * Rejection of duplicate transaction hashes (double-spend protection within a block)
    /// * Total transaction count does not exceed [`crate::MAX_TRANSACTIONS_PER_BLOCK`]
    pub fn validate_transactions(&self) -> Result<()> {
        if self.transactions.len() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BodyError::TooManyTransactions {
                count: self.transactions.len(),
                max: crate::MAX_TRANSACTIONS_PER_BLOCK,
            }
            .into());
        }

        let mut seen = HashSet::with_capacity(self.transactions.len());
        for (i, tx) in self.transactions.iter().enumerate() {
            tx.validate_basic()
                .map_err(|e| BodyError::InvalidTransaction {
                    index: i,
                    error: e.to_string(),
                })?;

            let tx_hash = tx.try_hash()?;
            if !seen.insert(tx_hash) {
                return Err(BodyError::DuplicateTransaction(hex::encode(tx_hash)).into());
            }
        }
        Ok(())
    }

    /// Structural validation for receipts in the body.
    ///
    /// Validates:
    /// * Receipt count strictly matches transaction count
    /// * Each receipt's `tx_hash` matches the corresponding transaction's hash at the same index
    /// * Each receipt's `gas_used` does not exceed the transaction's declared `gas_limit`
    pub fn validate_receipts(&self) -> Result<()> {
        if self.receipts.len() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BodyError::TooManyReceipts {
                count: self.receipts.len(),
                max: crate::MAX_TRANSACTIONS_PER_BLOCK,
            }
            .into());
        }

        if self.receipts.len() != self.transactions.len() {
            return Err(BodyError::ReceiptCountMismatch {
                tx_count: self.transactions.len(),
                receipt_count: self.receipts.len(),
            }
            .into());
        }

        for (i, (tx, receipt)) in self
            .transactions
            .iter()
            .zip(self.receipts.iter())
            .enumerate()
        {
            let tx_hash = tx.try_hash()?;
            if receipt.tx_hash != tx_hash {
                return Err(BodyError::ReceiptTxHashMismatch {
                    index: i,
                    expected: hex::encode(tx_hash),
                    actual: hex::encode(receipt.tx_hash),
                }
                .into());
            }

            if receipt.gas_used > tx.gas_limit {
                return Err(BodyError::ReceiptGasExceedsTxLimit {
                    index: i,
                    gas_used: receipt.gas_used,
                    tx_gas_limit: tx.gas_limit,
                }
                .into());
            }
        }
        Ok(())
    }

    /// Compute the total gas consumed by all receipts in this block body.
    pub fn total_gas_used(&self) -> u64 {
        self.receipts.iter().fold(0u64, |total, receipt| {
            total.saturating_add(receipt.gas_used)
        })
    }

    /// Checked gas accumulation returning an error on integer overflow.
    pub fn total_gas_used_checked(&self) -> Result<u64> {
        self.receipts.iter().try_fold(0u64, |total, receipt| {
            total
                .checked_add(receipt.gas_used)
                .ok_or_else(|| BodyError::GasOverflow.into())
        })
    }

    /// Compute the total gas limit requested by all transactions in this block body.
    pub fn total_gas_limit(&self) -> u64 {
        self.transactions
            .iter()
            .fold(0u64, |total, tx| total.saturating_add(tx.gas_limit))
    }

    /// Checked gas limit accumulation returning an error on integer overflow.
    pub fn total_gas_limit_checked(&self) -> Result<u64> {
        self.transactions.iter().try_fold(0u64, |total, tx| {
            total
                .checked_add(tx.gas_limit)
                .ok_or_else(|| BodyError::GasOverflow.into())
        })
    }

    /// Validate that total gas consumed does not exceed the block gas limit.
    pub fn validate_gas_limit(&self, block_gas_limit: u64) -> Result<()> {
        let total = self.total_gas_used_checked()?;
        if total > block_gas_limit {
            return Err(BodyError::TotalGasUsedExceedsBlockLimit {
                total_gas_used: total,
                block_gas_limit,
            }
            .into());
        }
        Ok(())
    }

    /// Comprehensive mainnet validation of the block body.
    ///
    /// Validates:
    /// * All transactions pass basic validation without duplicates
    /// * All receipts match transactions 1-to-1 in order and hash
    /// * Individual receipt gas used <= transaction gas limit
    /// * Total gas used <= block gas limit
    /// * Total transaction gas limit <= block gas limit
    /// * Total transaction count <= [`crate::MAX_TRANSACTIONS_PER_BLOCK`]
    pub fn validate_mainnet(&self, block_gas_limit: u64) -> Result<()> {
        self.validate_transactions()?;
        self.validate_receipts()?;
        self.validate_gas_limit(block_gas_limit)?;

        let total_tx_gas_limit = self.total_gas_limit_checked()?;
        if total_tx_gas_limit > block_gas_limit {
            return Err(BodyError::TotalTxGasLimitExceedsBlockLimit {
                total_tx_gas_limit,
                block_gas_limit,
            }
            .into());
        }

        if self.transaction_count() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BodyError::TooManyTransactions {
                count: self.transaction_count(),
                max: crate::MAX_TRANSACTIONS_PER_BLOCK,
            }
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::BlockBody;
    use ed25519_dalek::SigningKey;
    use sxiaum_types::{Address, Receipt, Transaction, Validator};

    fn sample_transaction(nonce: u64) -> Transaction {
        let signing_key = SigningKey::from_bytes(&[0xA5u8; 32]);
        let sender = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(
            sender,
            Address([2u8; 32]),
            (10u64 + nonce).into(),
            nonce,
        );
        tx.sign(&signing_key)
            .expect("sample transaction must sign with its sender key");
        tx
    }

    fn sample_receipt(tx_hash: [u8; 32], gas_used: u64) -> Receipt {
        Receipt::new_success(tx_hash, gas_used, Some([9u8; 32]))
    }

    #[test]
    fn new_and_empty_bodies_start_without_entries() {
        let body = BlockBody::new();
        let empty = BlockBody::empty();

        assert_eq!(body.transaction_count(), 0);
        assert_eq!(body.receipt_count(), 0);
        assert!(body.is_empty());
        assert_eq!(empty, body);
    }

    #[test]
    fn add_transaction_and_receipt_updates_counts() {
        let tx = sample_transaction(1);
        let receipt = sample_receipt(tx.try_hash().unwrap(), 21_000);
        let mut body = BlockBody::new();

        body.add_transaction(tx);
        body.add_receipt(receipt);

        assert_eq!(body.transaction_count(), 1);
        assert_eq!(body.receipt_count(), 1);
        assert!(!body.is_empty());
    }

    #[test]
    fn batch_add_methods_work() {
        let tx1 = sample_transaction(1);
        let tx2 = sample_transaction(2);
        let r1 = sample_receipt(tx1.try_hash().unwrap(), 21_000);
        let r2 = sample_receipt(tx2.try_hash().unwrap(), 21_000);

        let mut body = BlockBody::new();
        body.add_transactions(vec![tx1, tx2]);
        body.add_receipts(vec![r1, r2]);

        assert_eq!(body.transaction_count(), 2);
        assert_eq!(body.receipt_count(), 2);
    }

    #[test]
    fn tx_and_receipt_roots_match_compute_aliases() {
        let tx_one = sample_transaction(1);
        let tx_two = sample_transaction(2);
        let receipt_one = sample_receipt(tx_one.try_hash().unwrap(), 21_000);
        let receipt_two = sample_receipt(tx_two.try_hash().unwrap(), 21_000);
        let mut body = BlockBody::new();

        body.add_transaction(tx_one);
        body.add_transaction(tx_two);
        body.add_receipt(receipt_one);
        body.add_receipt(receipt_two);

        assert_eq!(body.tx_root().unwrap(), body.compute_tx_root().unwrap());
        assert_eq!(
            body.receipts_root().unwrap(),
            body.compute_receipt_root().unwrap()
        );
        assert_ne!(body.tx_root().unwrap(), [0u8; 32]);
        assert_ne!(body.receipts_root().unwrap(), [0u8; 32]);
    }

    #[test]
    fn empty_body_returns_zero_roots() {
        let body = BlockBody::empty();
        assert_eq!(body.compute_tx_root().unwrap(), [0u8; 32]);
        assert_eq!(body.compute_receipt_root().unwrap(), [0u8; 32]);
        assert_eq!(BlockBody::compute_validator_root(&[]).unwrap(), [0u8; 32]);
    }

    #[test]
    fn merkle_roots_are_unambiguous_across_leaf_counts() {
        // SECURITY: with last-node duplication, [A,B,C] and [A,B,C,C] produced
        // the SAME root, allowing two distinct bodies to satisfy one header.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        let root_three = BlockBody::calculate_merkle_root(vec![a, b, c]);
        let root_four_dup = BlockBody::calculate_merkle_root(vec![a, b, c, c]);

        assert_ne!(
            root_three, root_four_dup,
            "distinct leaf lists must never share a Merkle root"
        );

        // A single leaf must not collide with any multi-leaf tree either
        // (leaf prefix vs node prefix separation).
        let root_single = BlockBody::calculate_merkle_root(vec![a]);
        let root_pair = BlockBody::calculate_merkle_root(vec![a, a]);
        assert_ne!(root_single, root_pair);
    }

    #[test]
    fn merkle_proofs_verify_for_odd_and_padded_levels() {
        let leaves: Vec<sxiaum_types::Hash> = (1u8..=7).map(|i| [i; 32]).collect();
        let root = BlockBody::calculate_merkle_root(leaves.clone());

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = super::generate_merkle_proof(&leaves, i).unwrap();
            assert!(
                BlockBody::verify_tx_merkle_proof(*leaf, i, &proof, root),
                "proof for index {i} must verify"
            );
            // Tampered leaf fails.
            assert!(!BlockBody::verify_tx_merkle_proof(
                [0xFF; 32], i, &proof, root
            ));
        }

        // Out-of-bounds index is rejected.
        assert!(super::generate_merkle_proof(&leaves, leaves.len()).is_err());
    }

    #[test]
    fn validator_root_computation_works() {
        let val1 = Validator::new(Address([1u8; 32]), [2u8; 32], 1000u64.into());
        let val2 = Validator::new(Address([3u8; 32]), [4u8; 32], 2000u64.into());

        let root = BlockBody::compute_validator_root(&[val1.clone(), val2.clone()]).unwrap();
        assert_ne!(root, [0u8; 32]);

        let proof = BlockBody::generate_validator_merkle_proof(&[val1.clone(), val2], 0).unwrap();
        assert!(BlockBody::verify_validator_merkle_proof(
            val1.try_hash().unwrap(),
            0,
            &proof,
            root
        ));
    }

    #[test]
    fn merkle_proof_generation_and_verification_works() {
        let mut body = BlockBody::new();
        let mut tx_hashes = Vec::new();
        let mut receipt_hashes = Vec::new();

        for i in 1..=5 {
            let tx = sample_transaction(i);
            let tx_h = tx.try_hash().unwrap();
            let receipt = sample_receipt(tx_h, 21_000);
            let r_h = receipt.try_hash().unwrap();

            tx_hashes.push(tx_h);
            receipt_hashes.push(r_h);
            body.add_transaction(tx);
            body.add_receipt(receipt);
        }

        let tx_root = body.compute_tx_root().unwrap();
        let receipt_root = body.compute_receipt_root().unwrap();

        for i in 0..5 {
            let tx_proof = body.generate_tx_merkle_proof(i).unwrap();
            assert!(BlockBody::verify_tx_merkle_proof(
                tx_hashes[i],
                i,
                &tx_proof,
                tx_root
            ));

            let receipt_proof = body.generate_receipt_merkle_proof(i).unwrap();
            assert!(BlockBody::verify_receipt_merkle_proof(
                receipt_hashes[i],
                i,
                &receipt_proof,
                receipt_root
            ));

            // Tampered leaf fails
            assert!(!BlockBody::verify_tx_merkle_proof(
                [0xFFu8; 32],
                i,
                &tx_proof,
                tx_root
            ));
        }

        assert!(body.generate_tx_merkle_proof(10).is_err());
        assert!(body.generate_receipt_merkle_proof(10).is_err());
    }

    #[test]
    fn validate_transactions_and_receipts_enforce_structure() {
        let tx = sample_transaction(3);
        let mut body = BlockBody::new();
        body.add_transaction(tx);

        assert!(body.validate_transactions().is_ok());
        assert!(body.validate_receipts().is_err());

        body.add_receipt(sample_receipt(
            body.transactions[0].try_hash().unwrap(),
            210, // tx.gas_limit for transfer is 210
        ));
        assert!(body.validate_receipts().is_ok());
    }

    #[test]
    fn encode_decode_and_size_bytes_are_consistent() {
        let tx = sample_transaction(4);
        let receipt = sample_receipt(tx.try_hash().unwrap(), 210);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(receipt);

        let encoded = body.try_encode().unwrap();
        let decoded = BlockBody::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded, body);
        assert_eq!(body.size_bytes().unwrap(), encoded.len());
    }

    #[test]
    fn total_gas_used_aggregates_receipt_gas() {
        let tx1 = sample_transaction(1);
        let tx2 = sample_transaction(2);
        let r1 = sample_receipt(tx1.try_hash().unwrap(), 210);
        let r2 = sample_receipt(tx2.try_hash().unwrap(), 210);
        let mut body = BlockBody::new();
        body.add_transaction(tx1);
        body.add_transaction(tx2);
        body.add_receipt(r1);
        body.add_receipt(r2);

        assert_eq!(body.total_gas_used(), 420);
        assert_eq!(body.total_gas_used_checked().unwrap(), 420);
    }

    #[test]
    fn total_gas_limit_aggregates_transaction_limits() {
        let tx1 = sample_transaction(1);
        let tx2 = sample_transaction(2);
        let mut body = BlockBody::new();
        body.add_transaction(tx1);
        body.add_transaction(tx2);

        assert_eq!(body.total_gas_limit(), 420); // 210 * 2
        assert_eq!(body.total_gas_limit_checked().unwrap(), 420);
    }

    #[test]
    fn validate_gas_limit_rejects_excess() {
        let tx = sample_transaction(1);
        let receipt = sample_receipt(tx.try_hash().unwrap(), 210);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(receipt);

        assert!(body.validate_gas_limit(210).is_ok());
        assert!(body.validate_gas_limit(200).is_err());
    }

    #[test]
    fn validate_mainnet_accepts_valid_body() {
        let tx = sample_transaction(1);
        let receipt = sample_receipt(tx.try_hash().unwrap(), 210);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(receipt);

        body.validate_mainnet(crate::DEFAULT_BLOCK_GAS_LIMIT)
            .expect("valid body should pass mainnet validation");
    }

    #[test]
    fn validate_mainnet_rejects_gas_limit_exceeded() {
        let tx = sample_transaction(1);
        let receipt = sample_receipt(tx.try_hash().unwrap(), 210);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(receipt);

        assert!(body.validate_mainnet(200).is_err());
    }

    #[test]
    fn validate_mainnet_rejects_receipt_count_mismatch() {
        let tx = sample_transaction(1);
        let mut body = BlockBody::new();
        body.add_transaction(tx);

        assert!(body
            .validate_mainnet(crate::DEFAULT_BLOCK_GAS_LIMIT)
            .is_err());
    }

    #[test]
    fn validate_transactions_rejects_duplicate_tx() {
        let tx = sample_transaction(1);
        let mut body = BlockBody::new();
        body.add_transaction(tx.clone());
        body.add_transaction(tx);

        assert!(body.validate_transactions().is_err());
    }

    #[test]
    fn validate_receipts_rejects_tx_hash_mismatch() {
        let tx = sample_transaction(1);
        let wrong_receipt = sample_receipt([0xFFu8; 32], 210);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(wrong_receipt);

        assert!(body.validate_receipts().is_err());
    }

    #[test]
    fn validate_receipts_rejects_receipt_gas_exceeding_tx_limit() {
        let tx = sample_transaction(1); // has gas_limit 210
        let receipt = sample_receipt(tx.try_hash().unwrap(), 500); // 500 > 210
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        body.add_receipt(receipt);

        assert!(body.validate_receipts().is_err());
    }
}
