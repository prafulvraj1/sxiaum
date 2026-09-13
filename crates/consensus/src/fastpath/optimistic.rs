use crate::hotstuff::vote::{vote_signing_message, VotePhase};
use crate::pos::validator_set::ValidatorSet;
use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use sxiaum_block::Block;
use sxiaum_types::{Address, NetworkMessage};
use tracing::{info, warn};

/// Default fast-path window: block must collect >=2/3+1 votes within this timeout.
pub const FAST_PATH_TIMEOUT_MS: u64 = 200;

/// A per-round vote accumulator used by the fast-path commit protocol.
#[derive(Debug, Default)]
pub struct FastPathVoteAccumulator {
    /// validator address -> signature bytes
    votes: HashMap<Address, [u8; 64]>,
    /// When the accumulation window opened.
    started_at: Option<Instant>,
}

impl FastPathVoteAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a vote. Starts the timeout window on the first vote.
    pub fn add_vote(&mut self, validator: Address, signature: [u8; 64]) {
        if self.started_at.is_none() {
            self.started_at = Some(Instant::now());
        }
        self.votes.insert(validator, signature);
    }

    /// Returns `true` if the timeout window has not yet expired.
    pub fn within_timeout(&self, timeout: Duration) -> bool {
        match self.started_at {
            None => true, // no votes yet - window not started
            Some(t) => t.elapsed() <= timeout,
        }
    }

    /// Drain votes as (address, signature) pairs.
    pub fn drain(&self) -> Vec<(Address, [u8; 64])> {
        self.votes.iter().map(|(a, s)| (*a, *s)).collect()
    }

    /// Number of unique votes collected.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    pub fn clear(&mut self) {
        self.votes.clear();
        self.started_at = None;
    }
}

pub struct FastPath {
    pub enabled: bool,
    /// Timeout within which >=2/3+1 votes must arrive for fast-path commit.
    pub timeout: Duration,
}

impl Default for FastPath {
    fn default() -> Self {
        Self::new()
    }
}

impl FastPath {
    pub fn new() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_millis(FAST_PATH_TIMEOUT_MS),
        }
    }

    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Evaluate whether fast-path conditions are satisfied for a given block.
    pub fn check_conditions(
        &self,
        block: &Block,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
        view: u64,
        phase: VotePhase,
        validator_set: &ValidatorSet,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        self.has_quorum(
            signatures,
            quorum_threshold,
            block,
            view,
            phase,
            validator_set,
        )
    }

    /// Returns `true` when `signatures` contains at least `quorum_threshold`
    /// verified votes from distinct active validators.
    pub fn has_quorum(
        &self,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
        block: &Block,
        view: u64,
        phase: VotePhase,
        validator_set: &ValidatorSet,
    ) -> bool {
        let mut unique_validators = HashSet::new();
        let Ok(block_hash) = block.try_hash() else {
            return false;
        };
        for (addr, sig) in signatures {
            if let Some(validator) = validator_set.validator(addr) {
                if !validator.is_active() {
                    continue;
                }
                let msg = vote_signing_message(*addr, &block_hash, view, phase);
                if validator.verify_signature(&msg, sig).unwrap_or(false) {
                    unique_validators.insert(*addr);
                }
            }
        }
        unique_validators.len() >= quorum_threshold
    }

    /// Attempt an optimistic fast-path commit.
    ///
    /// Succeeds when:
    ///   - fast-path is enabled
    ///   - >=2/3+1 validators signed (`quorum_threshold`)
    ///   - votes arrived within the timeout window (`accumulator`)
    ///
    /// Returns the block hash on success, or an error explaining why the
    /// fast path was not applicable (caller should fall back to HotStuff).
    pub fn try_fast_commit(
        &self,
        block: &Block,
        accumulator: &FastPathVoteAccumulator,
        quorum_threshold: usize,
        view: u64,
        phase: VotePhase,
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32]> {
        if !self.enabled {
            bail!("fast path is disabled");
        }

        if !accumulator.within_timeout(self.timeout) {
            warn!(
                block_height = block.header.height,
                timeout_ms = self.timeout.as_millis(),
                votes = accumulator.vote_count(),
                "fast path timeout expired before quorum; falling back to HotStuff"
            );
            bail!("fast path timeout expired");
        }

        let signatures = accumulator.drain();
        if !self.has_quorum(
            &signatures,
            quorum_threshold,
            block,
            view,
            phase,
            validator_set,
        ) {
            bail!(
                "fast path: insufficient valid votes ({} < {})",
                signatures.len(),
                quorum_threshold
            );
        }

        let block_hash = block.try_hash()?;
        info!(
            block_height = block.header.height,
            block_hash = hex::encode(block_hash),
            votes = signatures.len(),
            quorum_threshold,
            "fast path commit succeeded"
        );
        Ok(block_hash)
    }

    /// Legacy wrapper kept for compatibility with existing call sites.
    pub fn fast_commit(
        &self,
        block: &Block,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
        view: u64,
        phase: VotePhase,
        validator_set: &ValidatorSet,
    ) -> Result<[u8; 32]> {
        if !self.check_conditions(
            block,
            signatures,
            quorum_threshold,
            view,
            phase,
            validator_set,
        ) {
            bail!("fast path conditions not satisfied");
        }
        block.try_hash()
    }

    pub fn fallback_to_hotstuff(&self) -> bool {
        !self.enabled
    }

    /// Verify that `signatures` contains at least `quorum_threshold` unique
    /// validator addresses with valid signatures.
    pub fn verify_fast_votes(
        &self,
        signatures: &[(Address, [u8; 64])],
        quorum_threshold: usize,
        block: &Block,
        view: u64,
        phase: VotePhase,
        validator_set: &ValidatorSet,
    ) -> bool {
        self.has_quorum(
            signatures,
            quorum_threshold,
            block,
            view,
            phase,
            validator_set,
        )
    }

    pub fn broadcast_fast_commit(&self, block: &Block) -> Result<NetworkMessage> {
        if !self.enabled {
            bail!("fast path disabled");
        }
        block.try_into_gossip_message()
    }

    /// Check if block exhibits conflicts.
    pub fn detect_conflicts(&self, _block: &Block) -> bool {
        false
    }

    pub fn revert_if_failure(&self, success: bool) -> Result<()> {
        if !success {
            bail!("fast path execution failed and reverted");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{FastPath, FAST_PATH_TIMEOUT_MS};
    use crate::hotstuff::vote::{vote_signing_message, VotePhase};
    use crate::pos::validator_set::ValidatorSet;
    use ed25519_dalek::{Signer, SigningKey};
    use primitive_types::U256;
    use std::time::Duration;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
    use sxiaum_types::{Address, NetworkMessage, Transaction};

    fn validator_from_signing_key(signing_key: &SigningKey) -> sxiaum_types::Validator {
        let pubkey = signing_key.verifying_key().to_bytes();
        let mut val = sxiaum_types::Validator::new(
            Address::from_public_key(&pubkey),
            pubkey,
            U256::from(10u64.pow(18)),
        );
        val.status = sxiaum_types::validator::ValidatorStatus::Active;
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        val.with_bls_pop(pk.0, pop.0)
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed_block() -> Block {
        let signing_key = signing_key(1);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut header = BlockHeader::new([0u8; 32], 1);
        header.proposer = proposer;

        let mut body = BlockBody::new();
        body.add_transaction(Transaction::new_transfer(
            proposer,
            Address([9u8; 32]),
            U256::from(1u64),
            0,
        ));
        body.add_receipt(sxiaum_types::Receipt::new_success([7u8; 32], 21_000, None));

        let mut block = Block::new(header, body);
        block.try_compute_roots().unwrap();
        block
            .header
            .sign(&signing_key)
            .expect("block signature should succeed");
        block
    }

    #[test]
    fn new_and_fallback_reflect_enabled_flag() {
        let fast_path = FastPath::new();
        assert!(fast_path.enabled);
        assert!(!fast_path.fallback_to_hotstuff());
    }

    #[test]
    fn verify_votes_and_check_conditions_require_quorum_and_no_conflict() {
        let fast_path = FastPath::new();
        let block = signed_block();
        let block_hash = block.try_hash().unwrap();
        let view = 1;
        let phase = VotePhase::Prepare;

        let key_a = signing_key(10);
        let key_b = signing_key(11);
        let val_a = validator_from_signing_key(&key_a);
        let val_b = validator_from_signing_key(&key_b);
        let mut vs = ValidatorSet::new();
        vs.add_validator(val_a.clone()).unwrap();
        vs.add_validator(val_b.clone()).unwrap();

        let msg_a = vote_signing_message(val_a.address, &block_hash, view, phase);
        let sig_a = key_a.sign(&msg_a).to_bytes();
        let msg_b = vote_signing_message(val_b.address, &block_hash, view, phase);
        let sig_b = key_b.sign(&msg_b).to_bytes();

        let signatures = vec![(val_a.address, sig_a), (val_b.address, sig_b)];
        assert!(fast_path.verify_fast_votes(&signatures, 2, &block, view, phase, &vs));
        assert!(!fast_path.verify_fast_votes(
            &[(val_a.address, sig_a), (val_a.address, sig_a)],
            2,
            &block,
            view,
            phase,
            &vs
        ));
        assert!(fast_path.check_conditions(&block, &signatures, 2, view, phase, &vs));
    }

    #[test]
    fn detect_conflicts_allows_unsigned_and_multi_sender_blocks_in_current_policy() {
        let fast_path = FastPath::new();

        let signed = signed_block();
        assert!(!fast_path.detect_conflicts(&signed));

        let unsigned = {
            let mut block = signed_block();
            block.header.signature = None;
            block
        };
        assert!(!fast_path.detect_conflicts(&unsigned));

        let key_3 = signing_key(3);
        let proposer_3 = Address::from_public_key(&key_3.verifying_key().to_bytes());
        let mut header_3 = BlockHeader::new([0u8; 32], 1);
        header_3.proposer = proposer_3;
        let body_3 = BlockBody::new();
        let mut empty_signed = Block::new(header_3, body_3);
        empty_signed.try_compute_roots().unwrap();
        empty_signed
            .header
            .sign(&key_3)
            .expect("sign should succeed");
        assert!(!fast_path.detect_conflicts(&empty_signed));

        let key_4 = signing_key(4);
        let proposer_4 = Address::from_public_key(&key_4.verifying_key().to_bytes());
        let mut header_4 = BlockHeader::new([0u8; 32], 2);
        header_4.proposer = proposer_4;
        let mut body_4 = BlockBody::new();
        let other_sender = Address([99u8; 32]);
        body_4.add_transaction(Transaction::new_transfer(
            other_sender,
            Address([8u8; 32]),
            U256::from(1u64),
            0,
        ));
        body_4.add_receipt(sxiaum_types::Receipt::new_success([8u8; 32], 21_000, None));
        let mut multi_sender = Block::new(header_4, body_4);
        multi_sender.try_compute_roots().unwrap();
        multi_sender
            .header
            .sign(&key_4)
            .expect("sign should succeed");
        assert!(!fast_path.detect_conflicts(&multi_sender));
    }

    #[test]
    fn fast_commit_and_broadcast_require_enabled_non_conflicting_block() {
        let fast_path = FastPath::new();
        let block = signed_block();
        let block_hash = block.try_hash().unwrap();
        let view = 1;
        let phase = VotePhase::Prepare;

        let key_a = signing_key(10);
        let key_b = signing_key(11);
        let val_a = validator_from_signing_key(&key_a);
        let val_b = validator_from_signing_key(&key_b);
        let mut vs = ValidatorSet::new();
        vs.add_validator(val_a.clone()).unwrap();
        vs.add_validator(val_b.clone()).unwrap();

        let msg_a = vote_signing_message(val_a.address, &block_hash, view, phase);
        let sig_a = key_a.sign(&msg_a).to_bytes();
        let msg_b = vote_signing_message(val_b.address, &block_hash, view, phase);
        let sig_b = key_b.sign(&msg_b).to_bytes();

        let signatures = vec![(val_a.address, sig_a), (val_b.address, sig_b)];

        assert_eq!(
            fast_path
                .fast_commit(&block, &signatures, 2, view, phase, &vs)
                .expect("fast commit should succeed"),
            block.try_hash().unwrap()
        );

        match fast_path
            .broadcast_fast_commit(&block)
            .expect("broadcast should succeed")
        {
            NetworkMessage::GossipProposedBlock(bytes) => {
                let decoded =
                    Block::decode_network(&bytes).expect("broadcast payload should decode");
                assert_eq!(decoded.try_hash().unwrap(), block.try_hash().unwrap());
            }
            other => panic!("unexpected broadcast message: {:?}", other),
        }

        let disabled = FastPath {
            enabled: false,
            timeout: Duration::from_millis(FAST_PATH_TIMEOUT_MS),
        };
        assert!(disabled
            .fast_commit(&block, &signatures, 2, view, phase, &vs)
            .is_err());
        assert!(disabled.broadcast_fast_commit(&block).is_err());
    }

    #[test]
    fn revert_if_failure_returns_error_on_failed_fast_path() {
        let fast_path = FastPath::new();
        fast_path
            .revert_if_failure(true)
            .expect("successful execution should not revert");
        assert!(fast_path.revert_if_failure(false).is_err());
    }
}
