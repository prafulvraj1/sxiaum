use crate::body::BlockBody;
use crate::error::BlockError;
use crate::header::BlockHeader;
use anyhow::Result;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sxiaum_types::{Address, BlockHeight, Canonical, Hash, Receipt, Timestamp, Transaction};

/// Canonical full block structure containing both header commitment and body payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    /// Consensus and state commitment header.
    pub header: BlockHeader,
    /// Transaction and execution receipt payload body.
    pub body: BlockBody,
}

impl Block {
    /// Create a new block with header and body components.
    pub fn new(header: BlockHeader, body: BlockBody) -> Self {
        Self { header, body }
    }

    /// Create the canonical genesis block (height 0) initialized with state root.
    pub fn genesis(genesis_state_root: Hash) -> Self {
        let mut header = BlockHeader::genesis();
        header.set_state_root(genesis_state_root);
        Self {
            header,
            body: BlockBody::empty(),
        }
    }

    // --- Accessor Methods ---

    /// Return the block's height.
    pub fn height(&self) -> BlockHeight {
        self.header.height
    }

    /// Return the parent block's hash.
    pub fn parent_hash(&self) -> Hash {
        self.header.parent_hash
    }

    /// Return the block's chain id for replay protection.
    pub fn chain_id(&self) -> u64 {
        self.header.chain_id
    }

    /// Return the block protocol version.
    pub fn version(&self) -> u32 {
        self.header.version
    }

    /// Return the block gas limit.
    pub fn gas_limit(&self) -> u64 {
        self.header.gas_limit
    }

    /// Return the actual gas used by all transactions in the block.
    pub fn gas_used(&self) -> u64 {
        self.header.gas_used
    }

    /// Return the block creation timestamp.
    pub fn timestamp(&self) -> Timestamp {
        self.header.timestamp
    }

    /// Return the block proposer's address.
    pub fn proposer(&self) -> Address {
        self.header.proposer
    }

    /// Return the state root commitment.
    pub fn state_root(&self) -> Hash {
        self.header.state_root
    }

    /// Return the transaction Merkle root commitment.
    pub fn tx_root(&self) -> Hash {
        self.header.tx_root
    }

    /// Return the receipt Merkle root commitment.
    pub fn receipts_root(&self) -> Hash {
        self.header.receipts_root
    }

    /// Return the validator set Merkle root commitment.
    pub fn validator_root(&self) -> Hash {
        self.header.validator_root
    }

    /// Return the randomness beacon seed.
    pub fn randomness_beacon(&self) -> Hash {
        self.header.randomness_beacon
    }

    /// Return the consensus extra data slice.
    pub fn extra_data(&self) -> &[u8] {
        &self.header.extra_data
    }

    /// Return the proposer signature if present.
    pub fn signature(&self) -> Option<[u8; 64]> {
        self.header.signature
    }

    /// Return true if this block is the genesis block (height 0).
    pub fn is_genesis(&self) -> bool {
        self.height() == 0
    }

    /// Return the number of transactions contained in the block.
    pub fn transaction_count(&self) -> usize {
        self.body.transaction_count()
    }

    /// Return the number of receipts contained in the block.
    pub fn receipt_count(&self) -> usize {
        self.body.receipt_count()
    }

    // --- Hashing and Serialization ---

    /// Return the block's canonical 32-byte header hash.
    pub fn try_hash(&self) -> Result<Hash> {
        self.header.try_hash()
    }

    /// Serialize the entire block (header + body) into canonical binary format.
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as Canonical>::try_encode(self)
    }

    /// Deserialize a full block from canonical binary format.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Return the full serialized binary size of the block in bytes.
    pub fn size_bytes(&self) -> Result<usize> {
        self.try_encode().map(|b| b.len())
    }

    // --- Merkle Root Management and Verification ---

    /// Compute and synchronize `tx_root`, `receipts_root`, and `gas_used` in the header from the body.
    pub fn try_compute_roots(&mut self) -> Result<()> {
        let tx_root = self.body.compute_tx_root()?;
        let receipt_root = self.body.compute_receipt_root()?;
        let gas_used = self.body.total_gas_used_checked()?;

        self.header.set_tx_root(tx_root);
        self.header.set_receipts_root(receipt_root);
        self.header.set_gas_used(gas_used);
        Ok(())
    }

    /// Verify that the header's Merkle commitments match the actual body contents.
    pub fn try_verify_merkle_roots(&self) -> Result<bool> {
        let tx_root = self.body.compute_tx_root()?;
        let receipt_root = self.body.compute_receipt_root()?;

        if self.header.tx_root != tx_root {
            return Ok(false);
        }
        if self.header.receipts_root != receipt_root {
            return Ok(false);
        }
        Ok(true)
    }

    /// Explicitly verify the transaction Merkle root against the block body.
    pub fn verify_tx_merkle_root(&self) -> Result<bool> {
        let tx_root = self.body.compute_tx_root()?;
        Ok(self.header.tx_root == tx_root)
    }

    /// Explicitly verify the receipt Merkle root against the block body.
    pub fn verify_receipt_merkle_root(&self) -> Result<bool> {
        let receipt_root = self.body.compute_receipt_root()?;
        Ok(self.header.receipts_root == receipt_root)
    }

    // --- Signature and Proposer Verification ---

    /// Verify the proposer's Ed25519 signature on the block header.
    pub fn verify_header_signature(&self, public_key_bytes: &[u8; 32]) -> Result<bool> {
        self.header.verify_signature(public_key_bytes)
    }

    /// Alias for [`verify_header_signature`].
    pub fn verify_proposer_signature(&self, public_key_bytes: &[u8; 32]) -> Result<bool> {
        self.header.verify_signature(public_key_bytes)
    }

    /// Verify that the block was proposed by the expected address.
    #[must_use]
    pub fn verify_proposer(&self, expected_proposer: Address) -> bool {
        self.header.proposer == expected_proposer
    }

    /// Verify the block's state root against an expected root.
    #[must_use]
    pub fn verify_state_root(&self, expected_root: Hash) -> bool {
        self.header.state_root == expected_root
    }

    /// Structural verification ensuring Merkle roots match body contents.
    #[must_use]
    pub fn verify_block_structure(&self) -> bool {
        self.try_verify_merkle_roots().unwrap_or(false)
    }

    /// Verify that the block size does not exceed the provided limit.
    #[must_use]
    pub fn verify_block_size_limit(&self, max_size: usize) -> bool {
        self.size_bytes().map(|s| s <= max_size).unwrap_or(false)
    }

    /// Verify that the block timestamp drift relative to local time is within acceptable tolerance.
    #[must_use]
    pub fn verify_block_timestamp_drift(&self, local_time: u64, max_drift: u64) -> bool {
        let diff = self.header.timestamp.abs_diff(local_time);
        diff <= max_drift
    }

    /// Full block cryptographic verification: proposer signature + Merkle roots.
    pub fn verify_full(&self, expected_proposer_pk: &[u8; 32]) -> Result<bool> {
        if !self.verify_header_signature(expected_proposer_pk)? {
            return Ok(false);
        }
        self.try_verify_merkle_roots()
    }

    /// Verify the block link sequence correctly points to the previous block.
    pub fn try_verify_parent_link(&self, previous_block: &Block) -> Result<bool> {
        let expected_height = match previous_block.height().checked_add(1) {
            Some(h) => h,
            None => return Ok(false),
        };
        Ok(self.header.verify_parent(previous_block.try_hash()?)
            && self.header.verify_height(expected_height))
    }

    // --- ZK Validity Proof Helpers ---

    #[must_use]
    pub fn has_zk_proof(&self) -> bool {
        self.header.zk_proof.is_some()
    }

    pub fn zk_proof_bytes(&self) -> Option<&[u8]> {
        self.header.zk_proof.as_deref()
    }

    pub fn attach_validity_proof(&mut self, proof: Vec<u8>) {
        self.header.set_zk_proof(proof);
    }

    // --- Validation Methods ---

    /// Basic structural validation of the block.
    pub fn validate_basic(&self) -> Result<()> {
        // 1. Cheap header structural checks
        self.header.validate_basic()?;

        // 2. Cheap bounds checks before expensive Merkle hashing or allocations
        if self.transaction_count() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BlockError::TooManyTransactions {
                count: self.transaction_count(),
                max: crate::MAX_TRANSACTIONS_PER_BLOCK,
            }
            .into());
        }

        if self.receipt_count() > crate::MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BlockError::TooManyReceipts {
                count: self.receipt_count(),
                max: crate::MAX_TRANSACTIONS_PER_BLOCK,
            }
            .into());
        }

        let size = self.size_bytes()?;
        if size > crate::MAX_BLOCK_SIZE_BYTES {
            return Err(BlockError::BlockSizeExceeded {
                size_bytes: size,
                max_bytes: crate::MAX_BLOCK_SIZE_BYTES,
            }
            .into());
        }

        // 3. Transaction and receipt internal validation
        self.body.validate_transactions()?;
        self.body.validate_receipts()?;

        // 4. Merkle root commitments
        let tx_root = self.body.compute_tx_root()?;
        if self.header.tx_root != tx_root {
            return Err(BlockError::MerkleRootMismatch {
                expected: hex::encode(self.header.tx_root),
                computed: hex::encode(tx_root),
            }
            .into());
        }

        let receipt_root = self.body.compute_receipt_root()?;
        if self.header.receipts_root != receipt_root {
            return Err(BlockError::MerkleRootMismatch {
                expected: hex::encode(self.header.receipts_root),
                computed: hex::encode(receipt_root),
            }
            .into());
        }

        Ok(())
    }

    /// Comprehensive mainnet validation of the block.
    ///
    /// Validates:
    /// * Structural integrity and basic validation
    /// * Header-level mainnet rules (version, chain ID, proposer, timestamp, gas)
    /// * Body-level mainnet rules (gas limit, transaction validation, receipt validation)
    /// * Genesis invariants (height 0 requires empty body and 0 gas used)
    /// * Gas consumed in header matches actual body gas consumed
    pub fn validate_mainnet(&self, local_time: Timestamp) -> Result<()> {
        self.validate_basic()?;
        self.header.validate_mainnet(local_time)?;
        self.body.validate_mainnet(self.header.gas_limit)?;

        if self.is_genesis() {
            if !self.body.is_empty() {
                return Err(BlockError::GenesisNonEmptyBody.into());
            }
            if self.header.gas_used != 0 {
                return Err(BlockError::GasUsedMismatch {
                    header_gas: self.header.gas_used,
                    body_gas: 0,
                }
                .into());
            }
        }

        let actual_gas_used = self.body.total_gas_used_checked()?;
        if self.header.gas_used != actual_gas_used {
            return Err(BlockError::GasUsedMismatch {
                header_gas: self.header.gas_used,
                body_gas: actual_gas_used,
            }
            .into());
        }

        Ok(())
    }

    /// Pairwise validation between this block and the previous parent block.
    pub fn validate_parent_child(
        &self,
        previous_block: &Block,
        local_time: Timestamp,
    ) -> Result<()> {
        self.validate_mainnet(local_time)?;
        self.header
            .validate_parent_child(&previous_block.header, local_time)?;
        Ok(())
    }

    /// Perform transaction-level validation within the block body.
    pub fn validate_transactions(&self) -> Result<()> {
        self.body.validate_transactions()
    }

    /// Perform receipt-level validation within the block body.
    pub fn validate_receipts(&self) -> Result<()> {
        self.body.validate_receipts()
    }

    // --- Consensus Support Methods ---

    /// Serialize the block into a canonical proposal message for consensus propagation.
    pub fn try_proposal_message(&self) -> Result<Vec<u8>> {
        self.try_encode()
    }

    /// Calculate the canonical hash used for consensus voting (the header hash).
    pub fn try_vote_hash(&self) -> Result<Hash> {
        self.try_hash()
    }

    /// Calculate a hash commitment for a Quorum Certificate (QC) covering this block.
    pub fn try_quorum_cert_hash(&self) -> Result<Hash> {
        let mut hasher = Sha256::new();
        hasher.update(b"SXIAUM_QC_HASH");
        hasher.update(self.height().to_le_bytes());
        hasher.update(self.try_hash()?);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        Ok(h)
    }

    // --- Networking Serialization Methods ---

    /// Encode the block for network transmission in gossip protocols.
    pub fn try_encode_network(&self) -> Result<Vec<u8>> {
        self.try_encode()
    }

    /// Decode a block from its canonical network payload representation.
    pub fn decode_network(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes)
    }

    /// Format the block as a gossip network message.
    pub fn try_into_gossip_message(&self) -> Result<sxiaum_types::NetworkMessage> {
        Ok(sxiaum_types::NetworkMessage::GossipProposedBlock(
            self.try_encode_network()?,
        ))
    }

    /// Format the block as a response for a sync-related block request.
    pub fn try_build_sync_response(&self) -> Result<sxiaum_types::NetworkMessage> {
        Ok(sxiaum_types::NetworkMessage::BlockHeaders(vec![self
            .header
            .try_encode()?]))
    }

    // --- Storage Interface Methods ---

    /// Encode the block into its canonical storage representation.
    pub fn try_encode_storage(&self) -> Result<Vec<u8>> {
        self.try_encode()
    }

    /// Decode a block from its canonical storage representation.
    pub fn decode_storage(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes)
    }

    /// Create a storage index entry mapping height to the block's current hash.
    pub fn try_height_index(&self) -> Result<(BlockHeight, Hash)> {
        Ok((self.height(), self.try_hash()?))
    }

    /// Return the lookup key used for hash-based retrieval in storage.
    pub fn try_hash_lookup_key(&self) -> Result<Hash> {
        self.try_hash()
    }
    /// Sign the block using an in-memory signing key.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        self.header.sign(signing_key)
    }

    /// Sign the block using an abstract signer (in-memory or remote HSM).
    pub fn sign_with_signer<S: sxiaum_crypto::Signer + ?Sized>(
        &mut self,
        signer: &S,
    ) -> Result<()> {
        self.header.sign_with_signer(signer)
    }
}

impl sxiaum_crypto::hash::Hashable for Block {
    fn try_hash(&self) -> Result<sxiaum_crypto::hash::Hash, anyhow::Error> {
        self.try_hash()
    }
}

/// High-level builder for assembling blocks during block proposal or execution.
pub struct BlockBuilder {
    pub header: BlockHeader,
    pub body: BlockBody,
}

impl BlockBuilder {
    /// Create a new block builder starting from a parent block header.
    pub fn try_new(parent_header: &BlockHeader) -> Result<Self> {
        let next_height = parent_header.height.checked_add(1).ok_or(
            crate::error::HeaderError::HeightOverflow {
                height: parent_header.height,
            },
        )?;
        let next_time = parent_header
            .timestamp
            .checked_add(crate::MIN_TIMESTAMP_GAP)
            .ok_or(crate::error::HeaderError::TimestampOverflow {
                timestamp: parent_header.timestamp,
            })?;

        let mut header = BlockHeader::new(parent_header.try_hash()?, next_height);
        header.set_timestamp(next_time);

        Ok(Self {
            header,
            body: BlockBody::new(),
        })
    }

    /// Create a new block builder for the genesis block.
    pub fn new_genesis(genesis_state_root: Hash) -> Self {
        let mut header = BlockHeader::genesis();
        header.set_state_root(genesis_state_root);

        Self {
            header,
            body: BlockBody::empty(),
        }
    }

    /// Add a single transaction to the block being built.
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.body.add_transaction(tx);
    }

    /// Add multiple transactions to the block being built.
    pub fn add_transactions(&mut self, txs: impl IntoIterator<Item = Transaction>) {
        self.body.add_transactions(txs);
    }

    /// Add a single execution receipt to the block being built.
    pub fn add_receipt(&mut self, receipt: Receipt) {
        self.body.add_receipt(receipt);
    }

    /// Add multiple execution receipts to the block being built.
    pub fn add_receipts(&mut self, receipts: impl IntoIterator<Item = Receipt>) {
        self.body.add_receipts(receipts);
    }

    /// Update the block timestamp.
    pub fn set_timestamp(&mut self, ts: Timestamp) {
        self.header.set_timestamp(ts);
    }

    /// Update the block proposer address.
    pub fn set_proposer(&mut self, proposer: Address) {
        self.header.set_proposer(proposer);
    }

    /// Update the block's state root commitment.
    pub fn set_state_root(&mut self, state_root: Hash) {
        self.header.set_state_root(state_root);
    }

    /// Update the block's validator set root commitment.
    pub fn set_validator_root(&mut self, validator_root: Hash) {
        self.header.set_validator_root(validator_root);
    }

    /// Update the randomness beacon seed.
    pub fn set_randomness_beacon(&mut self, beacon: Hash) {
        self.header.set_randomness_beacon(beacon);
    }

    /// Attach a ZK validity proof.
    pub fn set_zk_validity_proof(&mut self, proof: Vec<u8>) {
        self.header.set_zk_proof(proof);
    }

    /// Set the block-level gas limit.
    pub fn set_gas_limit(&mut self, gas_limit: u64) {
        self.header.set_gas_limit(gas_limit);
    }

    /// Set the block header version.
    pub fn set_version(&mut self, version: u32) {
        self.header.set_version(version);
    }

    /// Set the consensus-specific extra data.
    pub fn set_extra_data(&mut self, data: Vec<u8>) {
        self.header.set_extra_data(data);
    }

    /// Set the chain id for replay protection.
    pub fn set_chain_id(&mut self, chain_id: u64) {
        self.header.set_chain_id(chain_id);
    }

    /// Perform pre-build integrity and safety checks on the assembling block components.
    pub fn validate_before_commit(&self) -> Result<()> {
        self.header.validate_basic()?;
        self.body.validate_transactions()?;
        self.body.validate_receipts()?;
        self.body.validate_gas_limit(self.header.gas_limit)?;
        Ok(())
    }

    /// Build the finalized block, automatically computing all Merkle roots and gas totals.
    pub fn try_build(mut self) -> Result<Block> {
        let tx_root = self.body.compute_tx_root()?;
        let receipt_root = self.body.compute_receipt_root()?;
        let gas_used = self.body.total_gas_used_checked()?;

        self.header.set_tx_root(tx_root);
        self.header.set_receipts_root(receipt_root);
        self.header.set_gas_used(gas_used);

        Ok(Block {
            header: self.header,
            body: self.body,
        })
    }

    /// Sign the building block as proposer and return the finalized Block.
    pub fn try_sign_and_build(self, signing_key: &SigningKey) -> Result<Block> {
        let mut block = self.try_build()?;
        block.header.sign(signing_key)?;
        Ok(block)
    }

    /// Sign the building block using an abstract signer (in-memory or remote HSM) and return the finalized Block.
    pub fn try_sign_with_signer_and_build<S: sxiaum_crypto::Signer + ?Sized>(
        self,
        signer: &S,
    ) -> Result<Block> {
        let mut block = self.try_build()?;
        block.header.sign_with_signer(signer)?;
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::{BlockBody, BlockBuilder, BlockHeader};
    use ed25519_dalek::SigningKey;
    use sxiaum_types::{Address, Receipt, Transaction};

    fn sample_block() -> Block {
        let header = BlockHeader::new([1u8; 32], 2);
        let mut body = BlockBody::new();
        let signing_key = SigningKey::from_bytes(&[0xA5u8; 32]);
        let sender = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx =
            Transaction::new_transfer(sender, Address([3u8; 32]), 5u64.into(), 1);
        tx.sign(&signing_key)
            .expect("sample transaction must sign with its sender key");
        let receipt = Receipt::new_success(tx.try_hash().unwrap(), 210, Some([4u8; 32]));
        body.add_transaction(tx);
        body.add_receipt(receipt);

        let mut block = Block::new(header, body);
        block.try_compute_roots().unwrap();
        Block::new(block.header.clone(), block.body)
    }

    #[test]
    fn new_block_exposes_header_body_metadata() {
        let block = sample_block();

        assert_eq!(block.height(), 2);
        assert_eq!(block.parent_hash(), [1u8; 32]);
        assert_eq!(block.transaction_count(), 1);
        assert_eq!(block.receipt_count(), 1);
        assert_eq!(block.try_hash().unwrap(), block.header.try_hash().unwrap());
        assert!(!block.is_genesis());
        assert_eq!(block.version(), crate::BLOCK_VERSION_CURRENT);
        assert_eq!(block.chain_id(), sxiaum_types::SXIAUM_CHAIN_ID);
        assert_eq!(block.gas_limit(), crate::DEFAULT_BLOCK_GAS_LIMIT);
        assert_eq!(block.gas_used(), 210);
        assert!(block.timestamp() > 0);
        assert_eq!(block.state_root(), [0u8; 32]);
        assert_ne!(block.tx_root(), [0u8; 32]);
        assert_ne!(block.receipts_root(), [0u8; 32]);
        assert_eq!(block.validator_root(), [0u8; 32]);
        assert_eq!(block.randomness_beacon(), [0u8; 32]);
        assert!(block.extra_data().is_empty());
        assert_eq!(block.signature(), None);
    }

    #[test]
    fn compute_roots_and_verify_merkle_roots_match() {
        let mut block = sample_block();
        block.header.set_tx_root([0u8; 32]);
        block.header.set_receipts_root([0u8; 32]);

        assert!(!block.try_verify_merkle_roots().unwrap());
        assert!(!block.verify_block_structure());
        block.try_compute_roots().unwrap();
        assert!(block.try_verify_merkle_roots().unwrap());
        assert!(block.verify_block_structure());
        assert!(block.verify_tx_merkle_root().unwrap());
        assert!(block.verify_receipt_merkle_root().unwrap());
    }

    #[test]
    fn verify_parent_link_and_genesis_work() {
        let genesis = Block::genesis([9u8; 32]);
        let child = Block::new(
            BlockHeader::new(genesis.try_hash().unwrap(), 1),
            BlockBody::empty(),
        );

        assert!(genesis.is_genesis());
        assert!(child.try_verify_parent_link(&genesis).unwrap());
    }

    #[test]
    fn validate_basic_checks_roots_transactions_and_receipts() {
        let block = sample_block();
        block.validate_basic().expect("valid block should pass");
        block
            .validate_transactions()
            .expect("transactions should validate");
        block.validate_receipts().expect("receipts should validate");
        assert!(block.size_bytes().unwrap() > 0);
    }

    #[test]
    fn encode_decode_and_storage_network_helpers_round_trip() {
        let block = sample_block();
        let encoded = block.try_encode().unwrap();

        let decoded = Block::decode(&encoded).expect("decode should succeed");
        let storage_round_trip = Block::decode_storage(&block.try_encode_storage().unwrap())
            .expect("storage decode should succeed");
        let network_round_trip = Block::decode_network(&block.try_encode_network().unwrap())
            .expect("network decode should succeed");

        assert_eq!(decoded, block);
        assert_eq!(storage_round_trip, block);
        assert_eq!(network_round_trip, block);
        assert_eq!(
            block.try_height_index().unwrap(),
            (block.height(), block.try_hash().unwrap())
        );
        assert_eq!(
            block.try_hash_lookup_key().unwrap(),
            block.try_hash().unwrap()
        );
        assert!(block.try_into_gossip_message().is_ok());
        assert!(block.try_build_sync_response().is_ok());
        assert!(block.try_proposal_message().is_ok());
        assert_eq!(block.try_vote_hash().unwrap(), block.try_hash().unwrap());
        assert!(block.try_quorum_cert_hash().is_ok());
    }

    #[test]
    fn verify_header_signature_uses_header_signature_verification() {
        let signing_key = SigningKey::from_bytes(&[10u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&public_key);
        let mut block = sample_block();
        block.header.proposer = proposer;
        block
            .header
            .sign(&signing_key)
            .expect("signing should succeed");

        assert!(block
            .verify_header_signature(&public_key)
            .expect("verification should succeed"));
        assert!(block
            .verify_proposer_signature(&public_key)
            .expect("verification should succeed"));
        assert!(block
            .verify_full(&public_key)
            .expect("full verification should succeed"));
        assert!(block.verify_proposer(proposer));
        assert!(block.verify_state_root(block.state_root()));
        assert!(block.verify_block_size_limit(10_000));
        assert!(block.verify_block_timestamp_drift(block.timestamp(), 1));
    }

    #[test]
    fn try_compute_roots_updates_gas_used() {
        let header = BlockHeader::new([1u8; 32], 1);
        let mut body = BlockBody::new();
        let tx = Transaction::new_transfer(Address([2u8; 32]), Address([3u8; 32]), 5u64.into(), 1);
        let receipt = Receipt::new_success(tx.try_hash().unwrap(), 210, Some([4u8; 32]));
        body.add_transaction(tx);
        body.add_receipt(receipt);

        let mut block = Block::new(header, body);
        assert_eq!(block.gas_used(), 0);
        block.try_compute_roots().unwrap();
        assert_eq!(block.gas_used(), 210);
    }

    #[test]
    fn validate_mainnet_accepts_valid_block() {
        let mut block = sample_block();
        block.header.proposer = Address([1u8; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        block.header.set_timestamp(now);
        block
            .validate_mainnet(now)
            .expect("valid block should pass mainnet validation");
    }

    #[test]
    fn validate_mainnet_rejects_gas_used_mismatch() {
        let mut block = sample_block();
        block.header.proposer = Address([1u8; 32]);
        block.header.set_gas_used(999_999);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        block.header.set_timestamp(now);
        assert!(block.validate_mainnet(now).is_err());
    }

    #[test]
    fn validate_mainnet_rejects_gas_limit_exceeded_by_body() {
        let mut header = BlockHeader::new([1u8; 32], 1);
        header.proposer = Address([1u8; 32]);
        header.set_gas_limit(5_000);
        let mut body = BlockBody::new();
        let tx = Transaction::new_transfer(Address([2u8; 32]), Address([3u8; 32]), 5u64.into(), 1);
        let receipt = Receipt::new_success(tx.try_hash().unwrap(), 210, Some([4u8; 32]));
        body.add_transaction(tx);
        body.add_receipt(receipt);

        let mut block = Block::new(header, body);
        block.try_compute_roots().unwrap();
        block.header.set_gas_limit(100); // lower than gas_used (210)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        block.header.set_timestamp(now);
        assert!(block.validate_mainnet(now).is_err());
    }

    #[test]
    fn block_builder_sets_gas_used_on_build() {
        let parent = BlockHeader::new([1u8; 32], 1);
        let mut builder = BlockBuilder::try_new(&parent).unwrap();
        let tx = Transaction::new_transfer(Address([2u8; 32]), Address([3u8; 32]), 5u64.into(), 1);
        let receipt = Receipt::new_success(tx.try_hash().unwrap(), 210, Some([4u8; 32]));
        builder.add_transaction(tx);
        builder.add_receipt(receipt);

        let block = builder.try_build().unwrap();
        assert_eq!(block.gas_used(), 210);
    }

    #[test]
    fn block_builder_validate_before_commit_checks_gas_limit() {
        let parent = BlockHeader::new([1u8; 32], 1);
        let mut builder = BlockBuilder::try_new(&parent).unwrap();
        builder.set_gas_limit(100);

        let tx = Transaction::new_transfer(Address([2u8; 32]), Address([3u8; 32]), 5u64.into(), 1);
        let receipt = Receipt::new_success(tx.try_hash().unwrap(), 210, Some([4u8; 32]));
        builder.add_transaction(tx);
        builder.add_receipt(receipt);

        assert!(builder.validate_before_commit().is_err());
    }

    #[test]
    fn genesis_block_passes_mainnet_validation() {
        let block = Block::genesis([9u8; 32]);
        block
            .validate_mainnet(block.header.timestamp)
            .expect("genesis block should pass mainnet validation");
    }

    #[test]
    fn validate_parent_child_block_enforces_pairwise_integrity() {
        let genesis = Block::genesis([9u8; 32]);
        let signing_key = SigningKey::from_bytes(&[15u8; 32]);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());

        let mut builder = BlockBuilder::try_new(&genesis.header).unwrap();
        builder.set_proposer(proposer);
        let child = builder.try_sign_and_build(&signing_key).unwrap();

        child
            .validate_parent_child(&genesis, child.timestamp())
            .expect("valid parent-child blocks should pass validation");
    }

    #[test]
    fn zk_validity_proof_attachment_works() {
        let mut block = sample_block();
        assert!(!block.has_zk_proof());
        assert_eq!(block.zk_proof_bytes(), None);

        let proof = vec![0xDE, 0xAD, 0xBE, 0xEF];
        block.attach_validity_proof(proof.clone());
        assert!(block.has_zk_proof());
        assert_eq!(block.zk_proof_bytes(), Some(proof.as_slice()));
    }
}
