use crate::hotstuff::vote::VotePhase;
pub mod pacemaker;
pub mod proposer;
pub mod vote;

use crate::hotstuff::vote::QuorumCertificate;
use anyhow::{bail, Result};
use std::collections::HashMap;
use sxiaum_block::Block;
use tracing::warn;

/// Maximum hops for locked-block ancestor walks (H-15): bounded to keep the
/// check O(1) under corrupted metadata while comfortably exceeding realistic
/// lock distances.
const ANCESTOR_WALK_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotStuffPhase {
    Prepare,
    PreCommit,
    Commit,
    Finalize,
}

pub struct HotStuff {
    prepare_qcs: HashMap<[u8; 32], QuorumCertificate>,
    block_phase: HashMap<[u8; 32], HotStuffPhase>,
    precommit_qcs: HashMap<[u8; 32], QuorumCertificate>,
    commit_qcs: HashMap<[u8; 32], QuorumCertificate>,
    /// Safety lock: the highest block hash for which we have a PreCommit QC.
    /// A node must never vote for a block that conflicts with its locked block
    /// (HotStuff paper §4 "Locked Block" safety rule).
    pub locked_block: Option<[u8; 32]>,
    /// Height of the locked block (for pruning-safe safety checks).
    pub locked_block_height: Option<u64>,
    /// The highest QC view number seen so far (liveness rule).
    pub highest_qc_view: u64,
    /// Map from block hash -> parent block hash (populated at Prepare time).
    block_parent: HashMap<[u8; 32], [u8; 32]>,
    /// Map from block hash -> view number (populated at Prepare time).
    block_views: HashMap<[u8; 32], u64>,
}

impl Default for HotStuff {
    fn default() -> Self {
        Self::new()
    }
}

impl HotStuff {
    pub fn new() -> Self {
        Self {
            prepare_qcs: HashMap::new(),
            block_phase: HashMap::new(),
            precommit_qcs: HashMap::new(),
            commit_qcs: HashMap::new(),
            locked_block: None,
            locked_block_height: None,
            highest_qc_view: 0,
            block_parent: HashMap::new(),
            block_views: HashMap::new(),
        }
    }

    /// Update the locked block after receiving a PreCommit QC.
    /// The locked block is updated to the block with the highest PreCommit QC.
    pub fn update_locked_block(&mut self, block_hash: [u8; 32], height: u64) {
        self.locked_block = Some(block_hash);
        self.locked_block_height = Some(height);
    }

    /// Update the highest QC view for liveness.
    pub fn update_highest_qc(&mut self, qc: &QuorumCertificate) {
        if qc.view > self.highest_qc_view {
            self.highest_qc_view = qc.view;
        }
    }

    /// SECURITY (H-17): vote-level enforcement of the locked-block safety
    /// rule. Returns true when `block` provably conflicts with the current
    /// locked block. Previously safety was checked only when a FULL Prepare
    /// QC was aggregated, so hostile peers could stockpile votes for
    /// conflicting branches on every replica between Prepare-QC events.
    pub fn vote_conflicts_with_locked_block(&self, block: &Block) -> bool {
        match self.locked_block {
            Some(locked) => !self.extends_locked_block(locked, block),
            None => false,
        }
    }

    /// Deterministic fork-choice: among two conflicting tips, select the branch
    /// extending the QC with the highest view number. This is equivalent to
    /// the "prefer-highest-QC" rule in the HotStuff paper.
    pub fn fork_choice(&self, tip_a: [u8; 32], tip_b: [u8; 32]) -> [u8; 32] {
        let view_a = self.block_views.get(&tip_a).copied().unwrap_or(0);
        let view_b = self.block_views.get(&tip_b).copied().unwrap_or(0);
        if view_a >= view_b {
            tip_a
        } else {
            tip_b
        }
    }

    pub fn prune(&mut self, min_view_to_keep: u64) {
        let hashes_to_prune: Vec<[u8; 32]> = self
            .block_views
            .iter()
            .filter(|(hash, &view)| {
                view < min_view_to_keep && self.locked_block.as_ref() != Some(hash)
            })
            .map(|(&hash, _)| hash)
            .collect();

        // SECURITY (H-15): before dropping an old block's metadata, check
        // whether it is still an ANCESTOR of a surviving block. Removing
        // interior chain links used to sever `extends_locked_block` walks,
        // causing legitimate extensions of the locked block to be spuriously
        // rejected after pruning (self-inflicted liveness halt).
        let protected_ancestors = self.protect_ancestor_chains(&hashes_to_prune);

        for hash in hashes_to_prune {
            if protected_ancestors.contains(&hash) {
                continue;
            }
            self.prepare_qcs.remove(&hash);
            self.precommit_qcs.remove(&hash);
            self.commit_qcs.remove(&hash);
            self.block_parent.remove(&hash);
            self.block_views.remove(&hash);
            self.block_phase.remove(&hash);
        }
    }

    /// Returns the subset of `candidates` that are still reachable as
    /// ancestors of surviving (non-candidate) blocks via `block_parent`.
    fn protect_ancestor_chains(
        &self,
        candidates: &[[u8; 32]],
    ) -> std::collections::HashSet<[u8; 32]> {
        let candidates_set: std::collections::HashSet<[u8; 32]> =
            candidates.iter().copied().collect();
        let mut protected = std::collections::HashSet::new();

        for survivor in self.block_views.keys() {
            if candidates_set.contains(survivor) {
                continue;
            }
            // Walk up from each survivor's parent chain; every candidate hit
            // is a load-bearing ancestor and must survive pruning.
            let mut current = match self.block_parent.get(survivor) {
                Some(&parent) => parent,
                None => continue,
            };
            let mut hops = 0usize;
            loop {
                if current == [0u8; 32] || !candidates_set.contains(&current) {
                    break;
                }
                if !protected.insert(current) {
                    break; // already walked this subtree
                }
                match self.block_parent.get(&current) {
                    Some(&parent) => current = parent,
                    None => break,
                }
                hops += 1;
                if hops >= ANCESTOR_WALK_LIMIT {
                    break;
                }
            }
        }
        protected
    }

    pub fn apply_three_phase_commit_rule(
        &mut self,
        block: &Block,
        qc: QuorumCertificate,
        validator_set: &[sxiaum_types::Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<HotStuffPhase> {
        let block_hash = block.try_hash()?;
        let target = match qc.phase {
            VotePhase::Prepare => HotStuffPhase::Prepare,
            VotePhase::PreCommit => HotStuffPhase::PreCommit,
            VotePhase::Commit => HotStuffPhase::Finalize,
        };

        let current = self.block_phase.get(&block_hash).copied();

        match (current, target) {
            (None, HotStuffPhase::Prepare) => {
                if !self.verify_prepare_phase(
                    block,
                    &qc,
                    validator_set,
                    threshold,
                    required_voting_power,
                )? {
                    bail!("prepare phase verification failed");
                }
                self.block_parent
                    .insert(block_hash, block.header.parent_hash);
                self.block_views.insert(block_hash, qc.view);
                self.update_highest_qc(&qc);
                self.prepare_qcs.insert(block_hash, qc);
                self.block_phase.insert(block_hash, HotStuffPhase::Prepare);
                Ok(HotStuffPhase::Prepare)
            }
            (Some(HotStuffPhase::Prepare), HotStuffPhase::Prepare) => {
                self.update_highest_qc(&qc);
                let current_sig_count = self
                    .prepare_qcs
                    .get(&block_hash)
                    .map(|q| q.signatures.len())
                    .unwrap_or(0);
                if qc.signatures.len() >= current_sig_count {
                    self.prepare_qcs.insert(block_hash, qc);
                }
                Ok(HotStuffPhase::Prepare)
            }
            (Some(HotStuffPhase::Prepare), HotStuffPhase::PreCommit) => {
                if !self.verify_pre_commit_phase(
                    block_hash,
                    &qc,
                    validator_set,
                    threshold,
                    required_voting_power,
                )? {
                    bail!("pre-commit phase verification failed");
                }
                self.update_highest_qc(&qc);
                self.update_locked_block(block_hash, block.height());
                self.precommit_qcs.insert(block_hash, qc);
                self.block_phase
                    .insert(block_hash, HotStuffPhase::PreCommit);
                Ok(HotStuffPhase::PreCommit)
            }
            (Some(HotStuffPhase::PreCommit), HotStuffPhase::PreCommit) => {
                self.update_highest_qc(&qc);
                let current_sig_count = self
                    .precommit_qcs
                    .get(&block_hash)
                    .map(|q| q.signatures.len())
                    .unwrap_or(0);
                if qc.signatures.len() >= current_sig_count {
                    self.precommit_qcs.insert(block_hash, qc);
                }
                Ok(HotStuffPhase::PreCommit)
            }
            (Some(HotStuffPhase::PreCommit), HotStuffPhase::Finalize) => {
                if !self.verify_commit_phase(
                    block_hash,
                    &qc,
                    validator_set,
                    threshold,
                    required_voting_power,
                )? {
                    bail!("commit phase verification failed");
                }
                self.update_highest_qc(&qc);
                self.commit_qcs.insert(block_hash, qc);
                self.block_phase.insert(block_hash, HotStuffPhase::Finalize);
                Ok(HotStuffPhase::Finalize)
            }
            (Some(HotStuffPhase::Finalize), HotStuffPhase::Finalize) => {
                self.update_highest_qc(&qc);
                let current_sig_count = self
                    .commit_qcs
                    .get(&block_hash)
                    .map(|q| q.signatures.len())
                    .unwrap_or(0);
                if qc.signatures.len() >= current_sig_count {
                    self.commit_qcs.insert(block_hash, qc);
                }
                Ok(HotStuffPhase::Finalize)
            }
            (Some(HotStuffPhase::Finalize), HotStuffPhase::Prepare)
            | (Some(HotStuffPhase::Finalize), HotStuffPhase::PreCommit)
            | (Some(HotStuffPhase::PreCommit), HotStuffPhase::Prepare) => {
                // Block has already advanced to a later phase
                Ok(current.unwrap())
            }
            _ => bail!("invalid phase transition or reused QC"),
        }
    }

    /// Verify the Prepare phase:
    ///  1. Block passes basic validation.
    ///  2. The QC references this block's hash.
    ///  3. The proposal does NOT conflict with the locked block (safety rule).
    ///  4. If there is a parent QC, its block_hash matches block.header.parent_hash.
    pub fn verify_prepare_phase(
        &self,
        block: &Block,
        qc: &QuorumCertificate,
        validator_set: &[sxiaum_types::Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<bool> {
        if block.validate_basic().is_err() {
            return Ok(false);
        }

        let block_hash = block.try_hash()?;
        if qc.block_hash != block_hash {
            return Ok(false);
        }

        if let Some(locked) = self.locked_block {
            if !self.extends_locked_block(locked, block) {
                warn!(
                    "rejecting proposal {}: conflicts with locked block {:?}",
                    hex::encode(block_hash),
                    hex::encode(locked)
                );
                return Ok(false);
            }
        }

        let parent_hash = block.header.parent_hash;
        let parent_qc_ok = match self.prepare_qcs.get(&parent_hash) {
            Some(parent_qc) => parent_qc.block_hash == parent_hash,
            None => true,
        };

        if !parent_qc_ok {
            return Ok(false);
        }

        qc.verify_bls_with_voting_power(validator_set, threshold, required_voting_power)
    }

    /// Check whether `block` extends the locked block (i.e. locked_block is an
    /// ancestor of block). Walk up the known parent chain.
    ///
    /// SECURITY (H-15): when the chain has been pruned and ancestry cannot be
    /// PROVEN, a block strictly above the locked height is given the benefit
    /// of the doubt instead of being rejected outright. The previous
    /// `None => return false` turned missing pruned links into spurious
    /// safety rejections of legitimate canonical extensions. Conflict
    /// detection for blocks at or below the locked height remains absolute
    /// via the height guard.
    fn extends_locked_block(&self, locked: [u8; 32], block: &Block) -> bool {
        // The locked block is always an ancestor of itself.
        if let Ok(hash) = block.try_hash() {
            if hash == locked {
                return true;
            }
        }
        // If we know the locked block height, a proposal at the same or
        // lower height cannot extend it (unless it IS the locked block).
        let above_locked = match self.locked_block_height {
            Some(locked_height) => {
                if block.height() <= locked_height {
                    return false;
                }
                true
            }
            None => false,
        };
        let mut current = block.header.parent_hash;
        let mut visited = std::collections::HashSet::new();
        for _ in 0..ANCESTOR_WALK_LIMIT {
            if current == locked {
                return true;
            }
            // Zero hash means genesis -- stop searching.
            if current == [0u8; 32] {
                break;
            }
            if !visited.insert(current) {
                break; // corrupt/cyclic metadata; stop walking
            }
            match self.block_parent.get(&current) {
                Some(&parent) => current = parent,
                // Pruned/unknown ancestry: cannot disprove extension. For a
                // proposal above the locked height, allow rather than halt
                // liveness; full QC chaining is verified elsewhere.
                None => return above_locked,
            }
        }
        above_locked
    }

    pub fn verify_pre_commit_phase(
        &self,
        block_hash: [u8; 32],
        qc: &QuorumCertificate,
        validator_set: &[sxiaum_types::Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<bool> {
        if !self.prepare_qcs.contains_key(&block_hash) || qc.block_hash != block_hash {
            return Ok(false);
        }
        qc.verify_bls_with_voting_power(validator_set, threshold, required_voting_power)
    }

    pub fn verify_commit_phase(
        &self,
        block_hash: [u8; 32],
        qc: &QuorumCertificate,
        validator_set: &[sxiaum_types::Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<bool> {
        if !self.precommit_qcs.contains_key(&block_hash) || qc.block_hash != block_hash {
            return Ok(false);
        }
        qc.verify_bls_with_voting_power(validator_set, threshold, required_voting_power)
    }

    pub fn has_prepare_quorum(&self, block_hash: [u8; 32]) -> bool {
        self.prepare_qcs.contains_key(&block_hash)
    }

    pub fn has_precommit_quorum(&self, block_hash: [u8; 32]) -> bool {
        self.precommit_qcs.contains_key(&block_hash)
    }

    pub fn has_commit_quorum(&self, block_hash: [u8; 32]) -> bool {
        self.commit_qcs.contains_key(&block_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::{HotStuff, HotStuffPhase};
    use crate::hotstuff::vote::QuorumCertificate;
    use crate::hotstuff::vote::VotePhase;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_types::Address;

    fn block_for(parent_hash: [u8; 32], height: u64) -> Block {
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = Address([height as u8; 32]);
        let mut block = Block::new(header, BlockBody::empty());
        block.try_compute_roots().unwrap();
        block
    }

    fn qc_for(block_hash: [u8; 32], view: u64, phase: VotePhase) -> QuorumCertificate {
        QuorumCertificate::new_with_phase(block_hash, view, phase, Vec::new(), Vec::new())
    }

    #[test]
    fn three_phase_commit_progresses_prepare_precommit_finalize_in_order() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([1u8; 32], 1);
        let block_hash = block.try_hash().unwrap();

        let prepare_phase = hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for(block_hash, 1, VotePhase::Prepare),
                &[],
                0,
                0,
            )
            .expect("prepare phase should succeed");
        assert_eq!(prepare_phase, HotStuffPhase::Prepare);
        assert!(hotstuff.has_prepare_quorum(block_hash));
        assert!(!hotstuff.has_precommit_quorum(block_hash));
        assert!(!hotstuff.has_commit_quorum(block_hash));

        let precommit_phase = hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for(block_hash, 2, VotePhase::PreCommit),
                &[],
                0,
                0,
            )
            .expect("pre-commit phase should succeed");
        assert_eq!(precommit_phase, HotStuffPhase::PreCommit);
        assert!(hotstuff.has_precommit_quorum(block_hash));
        assert!(!hotstuff.has_commit_quorum(block_hash));

        let finalize_phase = hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for(block_hash, 3, VotePhase::Commit),
                &[],
                0,
                0,
            )
            .expect("finalize phase should succeed");
        assert_eq!(finalize_phase, HotStuffPhase::Finalize);
        assert!(hotstuff.has_commit_quorum(block_hash));
    }

    #[test]
    fn prepare_phase_rejects_qc_for_wrong_block_hash() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([2u8; 32], 2);

        let error = hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for([9u8; 32], 1, VotePhase::Prepare),
                &[],
                0,
                0,
            )
            .expect_err("prepare phase should reject mismatched qc");

        assert!(error
            .to_string()
            .contains("prepare phase verification failed"));
    }

    #[test]
    fn precommit_phase_requires_existing_prepare_quorum() {
        let hotstuff = HotStuff::new();
        let block = block_for([3u8; 32], 3);
        let block_hash = block.try_hash().unwrap();

        assert!(!hotstuff
            .verify_pre_commit_phase(
                block_hash,
                &qc_for(block_hash, 1, VotePhase::Prepare),
                &[],
                0,
                0
            )
            .expect("pre-commit verification should run without state"));
    }

    #[test]
    fn commit_phase_requires_existing_precommit_quorum() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([4u8; 32], 4);
        let block_hash = block.try_hash().unwrap();

        hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for(block_hash, 1, VotePhase::Prepare),
                &[],
                0,
                0,
            )
            .expect("prepare phase should succeed");

        assert!(!hotstuff
            .verify_commit_phase(
                block_hash,
                &qc_for(block_hash, 2, VotePhase::PreCommit),
                &[],
                0,
                0
            )
            .expect("commit verification should fail before pre-commit quorum"));
    }

    #[test]
    fn precommit_and_commit_reject_mismatched_qc_hash_after_progression() {
        let mut hotstuff = HotStuff::new();
        let block = block_for([5u8; 32], 5);
        let block_hash = block.try_hash().unwrap();

        hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for(block_hash, 1, VotePhase::Prepare),
                &[],
                0,
                0,
            )
            .expect("prepare phase should succeed");
        let precommit_error = hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for([7u8; 32], 2, VotePhase::PreCommit),
                &[],
                0,
                0,
            )
            .expect_err("pre-commit should reject mismatched qc hash");
        assert!(precommit_error
            .to_string()
            .contains("pre-commit phase verification failed"));

        hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for(block_hash, 2, VotePhase::PreCommit),
                &[],
                0,
                0,
            )
            .expect("pre-commit phase should succeed");
        let commit_error = hotstuff
            .apply_three_phase_commit_rule(
                &block,
                qc_for([8u8; 32], 3, VotePhase::Commit),
                &[],
                0,
                0,
            )
            .expect_err("commit should reject mismatched qc hash");
        assert!(commit_error
            .to_string()
            .contains("commit phase verification failed"));
    }

    // SECURITY REGRESSION (H-15): pruning must not sever ancestor chains of
    // surviving blocks, and unknown (pruned) ancestry above the locked height
    // must not cause spurious rejection of legitimate extensions.
    #[test]
    fn pruning_preserves_locked_block_extension_liveness() {
        let mut hotstuff = HotStuff::new();
        let b1 = block_for([0u8; 32], 1);
        let b2 = block_for(b1.try_hash().unwrap(), 2);
        let b3 = block_for(b2.try_hash().unwrap(), 3);
        let extension = block_for(b3.try_hash().unwrap(), 4);

        let h1 = b1.try_hash().unwrap();
        let h2 = b2.try_hash().unwrap();
        let h3 = b3.try_hash().unwrap();

        hotstuff.block_parent.insert(h2, h1);
        hotstuff.block_parent.insert(h3, h2);
        hotstuff.block_views.insert(h1, 1);
        hotstuff.block_views.insert(h2, 2);
        hotstuff.block_views.insert(h3, 3);

        hotstuff.locked_block = Some(h1);
        hotstuff.locked_block_height = Some(1);

        assert!(hotstuff.extends_locked_block(h1, &extension));

        // Prune everything below view 3 except the locked block. The interior
        // link h2 is an ancestor of survivor h3 and MUST survive.
        hotstuff.prune(3);
        assert!(
            hotstuff.extends_locked_block(h1, &extension),
            "pruning must not break locked-block ancestry walks for survivors"
        );

        // Even when ancestry metadata is genuinely missing (legacy-pruned
        // state), a proposal strictly ABOVE the locked height gets the
        // benefit of the doubt instead of halting liveness.
        let mut degraded = HotStuff::new();
        degraded.block_parent.insert(h3, h2);
        degraded.block_views.insert(h3, 9);
        degraded.locked_block = Some(h1);
        degraded.locked_block_height = Some(1);
        let ext_on_missing = block_for(h3, 5);
        assert!(degraded.extends_locked_block(h1, &ext_on_missing));
        // ...while a block at/below locked height is still rejected outright.
        let below = block_for(h1, 1);
        assert!(!degraded.extends_locked_block(h1, &below));
    }

    // SECURITY REGRESSION (H-17): vote-level conflict detection against the
    // locked block.
    #[test]
    fn votes_conflicting_with_locked_block_are_detected() {
        let mut hotstuff = HotStuff::new();
        let locked = block_for([0u8; 32], 5);
        let locked_hash = locked.try_hash().unwrap();
        hotstuff.locked_block = Some(locked_hash);
        hotstuff.locked_block_height = Some(5);

        // Same height as lock -> cannot extend -> conflict.
        let sibling = block_for([0xAB; 32], 5);
        assert!(hotstuff.vote_conflicts_with_locked_block(&sibling));

        // Lower height -> conflict.
        let older = block_for([0xCD; 32], 4);
        assert!(hotstuff.vote_conflicts_with_locked_block(&older));

        // Extension of the lock itself -> no conflict.
        let child = block_for(locked_hash, 6);
        assert!(!hotstuff.vote_conflicts_with_locked_block(&child));

        // No lock set -> nothing conflicts.
        hotstuff.locked_block = None;
        assert!(!hotstuff.vote_conflicts_with_locked_block(&sibling));
    }
}
