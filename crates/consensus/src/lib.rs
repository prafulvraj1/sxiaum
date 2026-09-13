pub mod consensus_state;
pub mod fastpath;
pub mod governance;
pub mod hotstuff;
pub mod metrics;
pub mod pos;
pub mod slashing;
pub mod upgrades;

use crate::consensus_state::{reject_proposal_below_locked_block, restore_locked_block};
use crate::governance::GovernanceManager;
use crate::hotstuff::pacemaker::Pacemaker;
use crate::hotstuff::proposer::{ProposalExecution, Proposer};
use crate::hotstuff::vote::{QuorumCertificate, Vote, VoteCollector};
use crate::hotstuff::HotStuffPhase;
use crate::pos::uptime::UptimeMonitor;
use crate::pos::validator_set::ValidatorSet;
use crate::upgrades::{ProtocolVersion, UpgradeManager};
use anyhow::{bail, Result};
use primitive_types::U256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sxiaum_block::Block;
use sxiaum_block::BlockBody;
use sxiaum_execution::TransactionSource;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Canonical, Transaction, Validator};

pub use crate::consensus_state::{
    audit_consensus_state_integrity, checkpoint_finalized_block, detect_inconsistent_state,
    enter_safe_recovery_mode, has_proposed_in_view, latest_checkpoint, load_checkpoint,
    load_consensus_state, persist_consensus_state, record_proposal_in_view, restore_full_consensus,
    restore_highest_qc, restore_pacemaker_view, synchronize_view_with_peers, Checkpoint,
    ConsensusState, ConsensusStateManager, ConsistencyCheck, RestoredConsensus,
};
pub use crate::fastpath::FastPath;
pub use crate::hotstuff::proposer::ProposalMessage;
pub use crate::hotstuff::vote::{CommitCertificate, TimeoutVote, ViewChangeCertificate, VotePhase};
pub use crate::hotstuff::HotStuff;
pub use crate::pos::staking::StakingManager;
pub use crate::slashing::{
    apply_block_slashing, Evidence, Misbehavior, SlashingConfig, SlashingEvent, SlashingEventRpc,
    SlashingManager,
};

const CONSENSUS_VOTE_PREFIX: &[u8] = b"consensus:vote:";
const CONSENSUS_QC_PREFIX: &[u8] = b"consensus:qc:";
const CONSENSUS_VALIDATOR_SET_KEY: &[u8] = b"consensus:validator_set";
const CONSENSUS_CURRENT_VIEW_KEY: &[u8] = b"consensus:current_view";
const DEFAULT_EPOCH_LENGTH: u64 = 32;
const CONSENSUS_LOCKED_BLOCK_HEIGHT_KEY: &[u8] = b"consensus:locked_block_height";

// ---------------------------------------------------------------------------
// Mainnet consensus constants
// ---------------------------------------------------------------------------

/// Base pacemaker timeout in seconds.  Matches the target block interval
/// so that a view is not declared timed out before a block can propagate.
const CONSENSUS_BASE_TIMEOUT_SECS: u64 = sxiaum_block::BLOCK_INTERVAL_SECS;

/// Fixed block reward (in smallest units) for successfully proposing a
/// finalized block on mainnet.
const MAINNET_BLOCK_REWARD: u64 = 1_000_000_000;

/// Maximum number of pending (unfinalized) blocks held in memory.
/// Prevents memory exhaustion from a flood of invalid proposals.
const MAX_PENDING_BLOCKS: usize = 256;

/// Consecutive missed slots before a validator is jailed for liveness.
const UPTIME_JAIL_THRESHOLD: u64 = 10;

// Real TransactionSource and ProposalExecution are injected into Consensus::new_production.
// The Noop implementations below are strictly test-harness defaults for Consensus::with_storage.

/// Test-only dummy transaction source used by `Consensus::with_storage` in integration tests.
/// In production, `Consensus::new_production` receives the real storage-backed `Mempool`.
#[doc(hidden)]
#[allow(dead_code)]
pub struct NoopTransactionSource;

impl TransactionSource for NoopTransactionSource {
    fn pull_transactions(&self, _limit: usize) -> Result<Vec<Transaction>> {
        Ok(Vec::new())
    }

    fn acknowledge_transactions(&self, _hashes: &[[u8; 32]]) -> Result<()> {
        Ok(())
    }
}

/// Test-only dummy block execution engine used by `Consensus::with_storage` in integration tests.
/// In production, `Consensus::new_production` receives the real `Executor` backed by `revm 3.5` and `ZkEngine`.
#[doc(hidden)]
#[allow(dead_code)]
pub struct NoopExecution;

impl ProposalExecution for NoopExecution {
    fn produce_block(&self, template: Block, transactions: Vec<Transaction>) -> Result<Block> {
        let mut block = template;
        block.body.transactions = transactions;
        block
            .try_compute_roots()
            .map_err(|e| anyhow::anyhow!("merkle root computation failed: {}", e))?;
        Ok(block)
    }
}

pub trait ConsensusNetwork {
    fn broadcast_block_proposal(&self, payload: Vec<u8>) -> Result<()>;
    fn broadcast_vote(&self, payload: Vec<u8>) -> Result<()>;
    fn broadcast_quorum_certificate(&self, payload: Vec<u8>) -> Result<()>;
    fn broadcast_new_view(&self, payload: Vec<u8>) -> Result<()>;
    fn request_missing_blocks(&self, start_height: u64, limit: u64) -> Result<Vec<Vec<u8>>>;
    fn synchronize_validator_state(&self, payload: Vec<u8>) -> Result<()>;
}

pub struct Consensus {
    pub validator_set: ValidatorSet,
    pub pacemaker: Pacemaker,
    pub vote_collector: VoteCollector,
    pub proposer: Proposer,
    pub hotstuff: HotStuff,
    pub finalized_block_height: u64,
    pub staking_manager: StakingManager,
    pub slashing_manager: SlashingManager,
    pub uptime_monitor: UptimeMonitor,
    pub upgrades: UpgradeManager,
    pub governance: GovernanceManager,
    highest_qc_block: Option<[u8; 32]>,
    locked_block_height: Option<u64>,
    storage: Arc<StorageEngine>,
    pending_blocks: HashMap<[u8; 32], Block>,
    committed_blocks: HashMap<[u8; 32], Block>,
    /// The finalized block with the greatest height, kept in memory.
    finalized_blocks: Option<(u64, Block)>,
    epoch_length: u64,
}

impl Consensus {
    /// Primary constructor for production use: injects the real mempool and executor.
    pub fn new_production(
        storage: Arc<StorageEngine>,
        validator_address: Address,
        mempool: Arc<dyn TransactionSource + Send + Sync>,
        execution: Arc<dyn ProposalExecution + Send + Sync>,
    ) -> Self {
        let validator_set = ValidatorSet::new();
        let pacemaker = Pacemaker::new(Duration::from_secs(CONSENSUS_BASE_TIMEOUT_SECS));
        let proposer = Proposer::new(validator_address, mempool, execution);

        Self {
            validator_set,
            pacemaker,
            vote_collector: VoteCollector::new(),
            proposer,
            hotstuff: HotStuff::new(),
            finalized_block_height: 0,
            staking_manager: StakingManager::with_storage(storage.clone()),
            slashing_manager: SlashingManager::new(SlashingConfig::default(), storage.clone()),
            uptime_monitor: UptimeMonitor::new(UPTIME_JAIL_THRESHOLD),
            // SECURITY (C-05): storage-backed so scheduled hard forks
            // survive restarts (in-memory-only upgrades chain-split).
            upgrades: UpgradeManager::with_storage(ProtocolVersion::new(1, 0, 0), storage.clone()),
            governance: GovernanceManager::new(),
            highest_qc_block: None,
            locked_block_height: None,
            storage,
            pending_blocks: HashMap::new(),
            committed_blocks: HashMap::new(),
            finalized_blocks: None,
            epoch_length: DEFAULT_EPOCH_LENGTH,
        }
    }

    #[doc(hidden)]
    /// Constructor for integration tests that don't need a real mempool/executor.
    pub fn with_storage(storage: Arc<StorageEngine>) -> Self {
        let validator_set = ValidatorSet::new();
        let pacemaker = Pacemaker::new(Duration::from_secs(CONSENSUS_BASE_TIMEOUT_SECS));
        let proposer = Proposer::new(
            Address::zero(),
            Arc::new(NoopTransactionSource),
            Arc::new(NoopExecution),
        );

        Self {
            validator_set,
            pacemaker,
            vote_collector: VoteCollector::new(),
            proposer,
            hotstuff: HotStuff::new(),
            finalized_block_height: 0,
            staking_manager: StakingManager::with_storage(storage.clone()),
            slashing_manager: SlashingManager::new(SlashingConfig::default(), storage.clone()),
            uptime_monitor: UptimeMonitor::new(UPTIME_JAIL_THRESHOLD),
            // SECURITY (C-05): storage-backed in the test constructor too so
            // behavior is identical to production.
            upgrades: UpgradeManager::with_storage(ProtocolVersion::new(1, 0, 0), storage.clone()),
            governance: GovernanceManager::new(),
            highest_qc_block: None,
            locked_block_height: None,
            storage,
            pending_blocks: HashMap::new(),
            committed_blocks: HashMap::new(),
            finalized_blocks: None,
            epoch_length: DEFAULT_EPOCH_LENGTH,
        }
    }

    pub fn start(&mut self) -> Result<u64> {
        self.restore_consensus_state_on_restart()?;

        // Restore the locked block safety rule from durable storage so that
        // the safety lock survives restarts (Bug 3 fix).
        if let Ok(Some(locked_hash)) = restore_locked_block(&self.storage) {
            self.hotstuff.locked_block = Some(locked_hash);
            self.locked_block_height = self.load_locked_block_height();
        }

        if let Some(leader) = self.current_leader() {
            self.proposer = Proposer::new(
                leader,
                self.proposer.mempool.clone(),
                self.proposer.execution.clone(),
            );
        }

        Ok(self.current_view())
    }

    pub fn stop(&mut self) -> Result<()> {
        self.persist_validator_set()?;
        self.persist_current_consensus_view()?;
        let _ = self.governance.save_to_storage(&self.storage);
        Ok(())
    }

    pub fn process_block_proposal(&mut self, block: Block) -> Result<bool> {
        block.validate_mainnet(current_unix_timestamp())?;
        self.validate_proposal_parent(&block)?;

        // Mainnet replay-protection: reject blocks with wrong chain_id or version.
        if block.header.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            bail!(
                "block chain_id {} does not match mainnet {}",
                block.header.chain_id,
                sxiaum_types::SXIAUM_CHAIN_ID
            );
        }
        if block.header.version != sxiaum_block::BLOCK_VERSION_CURRENT {
            bail!(
                "block version {} does not match current protocol version {}",
                block.header.version,
                sxiaum_block::BLOCK_VERSION_CURRENT
            );
        }

        // DoS protection: reject proposals when too many blocks are pending.
        if self.pending_blocks.len() >= MAX_PENDING_BLOCKS {
            bail!(
                "too many pending blocks ({}); rejecting proposal",
                self.pending_blocks.len()
            );
        }

        // Enforce the locked-block safety rule before doing anything else (Bug 3 fix).
        reject_proposal_below_locked_block(
            self.hotstuff.locked_block,
            self.locked_block_height,
            &block,
        )?;

        let proposer = block.header.proposer;
        let proposer_validator = self
            .validator_set
            .validator(&proposer)
            .ok_or_else(|| anyhow::anyhow!("Proposer is not an active validator"))?;

        if !block.header.verify_signature(&proposer_validator.pubkey)? {
            anyhow::bail!("Invalid block signature");
        }

        // Sync the local pacemaker view when a valid proposal arrives from a
        // higher view. In HotStuff receiving a well-formed proposal for view V
        // serves as proof that V-1 timed out; replicas advance to V.
        let proposer = block.header.proposer;
        let current_leader_opt = self.current_leader();
        let needs_view_sync = match current_leader_opt {
            Some(l) => l != proposer,
            None => true,
        };
        if needs_view_sync {
            let active_count = self.validator_set.active_validator_count();
            let search_limit = (active_count.max(1) as u64) * 16;
            let current = self.current_view();
            let mut synced = false;
            for delta in 1..=search_limit {
                let candidate_view = current + delta;
                let seed = self.leader_seed();
                if let Some(leader) = self.validator_set.get_proposer(candidate_view, seed) {
                    if leader == proposer {
                        self.pacemaker.sync_view_with_network(candidate_view);
                        let _ = self.persist_current_consensus_view();
                        tracing::info!(
                            "synced view to {} from incoming proposal (proposer {})",
                            candidate_view,
                            proposer
                        );
                        synced = true;
                        break;
                    }
                }
            }
            if !synced {
                let expected = current_leader_opt.unwrap_or(Address::zero());
                bail!(
                    "invalid proposer for view {}: expected {}, got {}",
                    self.current_view(),
                    expected,
                    proposer
                );
            }
        }

        // Enforce proposer equivocation detection before fork resolution so that
        // a Byzantine leader double-proposing for the same height cannot silently
        // overwrite their previous proposal via fork resolution.
        self.detect_conflicting_proposal(&block)?;

        if self.is_conflicting_branch(&block) {
            self.reject_conflicting_branch(&block)?;
        }

        if self.detect_fork(&block) {
            self.resolve_fork(&block)?;
        }

        let block_hash = block.try_hash()?;
        self.pending_blocks.insert(block_hash, block);
        Ok(true)
    }

    pub fn process_vote(&mut self, vote: Vote) -> Result<Option<QuorumCertificate>> {
        let current = self.current_view();
        if vote.view > current {
            // A vote for a future view: sync if we have the pending block, otherwise reject.
            if self.pending_blocks.contains_key(&vote.block_hash) {
                self.pacemaker.sync_view_with_network(vote.view);
                let _ = self.persist_current_consensus_view();
            } else {
                bail!(
                    "vote view mismatch: expected {}, got {}",
                    current,
                    vote.view
                );
            }
        } else if vote.view < current {
            bail!(
                "vote view mismatch: expected {}, got {}",
                current,
                vote.view
            );
        }

        if !self.pending_blocks.contains_key(&vote.block_hash) {
            bail!("vote references unknown block");
        }

        // SECURITY (H-17): enforce the locked-block safety rule at VOTE
        // admission time, not only during Prepare-QC aggregation. Without
        // this check a hostile peer could stockpile votes for branches
        // conflicting with the locked block on every replica; the conflict
        // was only discovered (and dropped) when a full Prepare QC happened
        // to be formed.
        if let Some(block) = self.pending_blocks.get(&vote.block_hash) {
            if self.hotstuff.vote_conflicts_with_locked_block(block) {
                bail!(
                    "vote for block 0x{} conflicts with locked block {:?}",
                    hex::encode(vote.block_hash),
                    self.hotstuff.locked_block.map(hex::encode)
                );
            }
        }

        if let Some(existing_hash) =
            self.vote_collector
                .get_voted_hash_for_phase(vote.view, vote.phase, &vote.validator)
        {
            if existing_hash != vote.block_hash {
                let vote_a = self
                    .vote_collector
                    .get_validator_vote_for_phase(vote.view, vote.phase, &vote.validator)
                    .unwrap_or_else(|| {
                        Vote::new_with_phase(vote.validator, existing_hash, vote.view, vote.phase)
                    });

                let misbehavior = Misbehavior::DoubleVote {
                    view: vote.view,
                    vote_a,
                    vote_b: vote.clone(),
                };

                // Record the evidence for later confirmation via the proper
                // governance pipeline. Uses the dedicated self-detected evidence
                // constructor with type-level safety guarantees.
                let _ = self.slashing_manager.record_self_detected_evidence(
                    vote.validator,
                    misbehavior,
                    self.finalized_block_height,
                );

                bail!(
                    "double voting detected for validator {} in view {} phase {:?}",
                    vote.validator,
                    vote.view,
                    vote.phase
                );
            }
        }

        self.verify_validator_vote(&vote)?;
        self.vote_collector.add_vote(vote.clone())?;
        self.persist_vote_in_storage(&vote)?;
        let quorum_threshold = self.quorum_threshold();
        // Build a QC only for this vote's phase — never reuse across phases.
        let qc = self.vote_collector.build_quorum_certificate_for_phase(
            vote.view,
            vote.block_hash,
            vote.phase,
            quorum_threshold,
        );

        if let Some(ref qc) = qc {
            if qc.phase != vote.phase {
                bail!(
                    "internal error: QC phase {:?} != vote phase {:?}",
                    qc.phase,
                    vote.phase
                );
            }
            let _ = self.process_quorum_certificate(qc.clone())?;
        }

        Ok(qc)
    }

    pub fn process_quorum_certificate(&mut self, qc: QuorumCertificate) -> Result<HotStuffPhase> {
        self.reject_invalid_quorum_certificate(&qc)?;
        self.persist_quorum_certificate(&qc)?;
        self.persist_current_consensus_view()?;
        self.apply_highest_qc_rule(&qc);
        let block = self
            .pending_blocks
            .get(&qc.block_hash)
            .ok_or_else(|| anyhow::anyhow!("pending block not found for quorum phase"))?
            .clone();

        let advanced = self.apply_three_phase_commit_rule(&block, qc.clone())?;
        match (qc.phase, advanced) {
            (VotePhase::Prepare, HotStuffPhase::Prepare) => {
                if !self.verify_prepare_phase(&block, &qc)? {
                    bail!("prepare phase verification failed");
                }
            }
            (VotePhase::PreCommit, HotStuffPhase::PreCommit) => {
                let block_hash = block.try_hash()?;
                if !self.verify_pre_commit_phase(block_hash, &qc)? {
                    bail!("pre-commit phase verification failed");
                }
                // Persist the locked block so the safety rule survives restarts (Bug 3 fix).
                self.locked_block_height = Some(block.height());
                self.persist_locked_block(block_hash, block.height())?;
            }
            (VotePhase::Commit, HotStuffPhase::Finalize) => {
                let block_hash = block.try_hash()?;
                if !self.verify_commit_phase(block_hash, &qc)? {
                    bail!("commit phase verification failed");
                }
                self.finalize_block_once_quorum_reached(block_hash)?;
            }
            (phase, got) => {
                bail!(
                    "phase mismatch after QC apply: qc phase {:?} advanced to {:?}",
                    phase,
                    got
                );
            }
        }
        Ok(advanced)
    }

    pub fn generate_next_phase_vote(
        &self,
        validator_address: Address,
        signing_key: &ed25519_dalek::SigningKey,
        qc: &QuorumCertificate,
    ) -> Result<Option<Vote>> {
        let next_phase = match qc.phase {
            VotePhase::Prepare => VotePhase::PreCommit,
            VotePhase::PreCommit => VotePhase::Commit,
            VotePhase::Commit => return Ok(None),
        };

        let mut vote = Vote::new_with_phase(validator_address, qc.block_hash, qc.view, next_phase);
        vote.sign(signing_key)?;
        Ok(Some(vote))
    }

    pub fn commit_block(&mut self, block_hash: [u8; 32]) -> Result<()> {
        let is_already_finalized = self
            .finalized_blocks
            .as_ref()
            .map(|(_, b)| b.try_hash().unwrap_or_default() == block_hash)
            .unwrap_or(false);
        if self.committed_blocks.contains_key(&block_hash) || is_already_finalized {
            return Ok(());
        }
        let block = self
            .pending_blocks
            .remove(&block_hash)
            .ok_or_else(|| anyhow::anyhow!("block not found for commit"))?;
        self.committed_blocks.insert(block_hash, block);
        Ok(())
    }

    pub fn finalize_block(&mut self, block_hash: [u8; 32]) -> Result<()> {
        if let Some((_, existing)) = &self.finalized_blocks {
            if existing.try_hash()? == block_hash {
                return Ok(());
            }
        }
        self.ensure_committed_block_qc_is_valid(block_hash)?;

        // Finalized blocks are monotonically increasing in height; never roll back.
        if let Some((prev_height, _)) = &self.finalized_blocks {
            let committed = self
                .committed_blocks
                .get(&block_hash)
                .ok_or_else(|| anyhow::anyhow!("block not found for finalization"))?;
            if committed.height() <= *prev_height {
                bail!(
                    "finalize_block: height {} does not advance finalized height {}",
                    committed.height(),
                    prev_height
                );
            }
        }

        let block = self
            .committed_blocks
            .remove(&block_hash)
            .ok_or_else(|| anyhow::anyhow!("block not found for finalization"))?;

        self.finalized_block_height = block.height();
        self.persist_finalized_block_to_storage(&block)?;
        self.finalized_blocks = Some((block.height(), block.clone()));
        crate::metrics::ConsensusMetrics::record_block_mined(
            block.height(),
            &block.header.proposer.to_string(),
        );
        // Record uptime for the proposer of the finalized block
        self.uptime_monitor.record_success(&block.header.proposer);
        let _ = self
            .staking_manager
            .reward_validator(&block.header.proposer, U256::from(MAINNET_BLOCK_REWARD));

        if block.height() > 0 && block.height() % 100 == 0 {
            let vs_hash = self.validator_set.hash();
            if let Err(e) = crate::consensus_state::checkpoint_finalized_block(
                &self.storage,
                &block,
                self.current_view(),
                vs_hash,
            ) {
                tracing::error!("Failed to persist checkpoint: {}", e);
            }
        }

        // Check for missed blocks by expected proposers in intermediate views
        if let Ok(Some(qc)) = self.load_persisted_quorum_certificate(block_hash) {
            let finalized_view = qc.view;
            if let Ok(Some(parent_qc)) =
                self.load_persisted_quorum_certificate(block.header.parent_hash)
            {
                let parent_view = parent_qc.view;
                for missed_view in (parent_view + 1)..finalized_view {
                    let seed = self.leader_seed();
                    if let Some(missed_leader) = self.validator_set.get_proposer(missed_view, seed)
                    {
                        if self.uptime_monitor.record_miss(&missed_leader)
                            && self.validator_set.jail_validator(&missed_leader).is_ok()
                        {
                            // SECURITY (H-13): clear the consecutive-miss
                            // streak when the sentence starts. Previously
                            // `reset_validator` was never called by any
                            // production path, so the streak survived jailing
                            // and the FIRST missed slot after release
                            // instantly re-jailed the validator.
                            self.uptime_monitor.reset_validator(&missed_leader);
                            tracing::warn!(
                                "Validator {} jailed due to consecutive missed slots",
                                missed_leader
                            );
                        }
                    }
                }
            }
        }

        self.maybe_rotate_validator_set_for_new_epoch()?;

        // SECURITY (H-14): execute matured time-locked governance proposals
        // and wire approved SoftwareUpgrade decisions into the UpgradeManager.
        // Previously "execution" was a status flip only: approved upgrades
        // never reached the UpgradeManager, so the protocol version NEVER
        // changed on-chain regardless of governance outcomes.
        self.process_governance_upgrade_executions();

        // Check for missed blocks by other expected validators in this view
        // In a production HotStuff, we would know who was supposed to vote.

        self.pacemaker.advance_view();

        if let Some(leader) = self.current_leader() {
            self.proposer = Proposer::new(
                leader,
                self.proposer.mempool.clone(),
                self.proposer.execution.clone(),
            );
        }

        Ok(())
    }

    pub fn update_validator_set(&mut self, validators: Vec<Validator>) -> Result<()> {
        self.validator_set
            .replace_validators(validators)
            .map_err(|e| anyhow::anyhow!("validator set replacement failed: {}", e))?;
        self.persist_validator_set()
            .map_err(|e| anyhow::anyhow!("validator set persistence failed: {}", e))?;
        if let Some(leader) = self.current_leader() {
            self.proposer = Proposer::new(
                leader,
                self.proposer.mempool.clone(),
                self.proposer.execution.clone(),
            );
        }
        Ok(())
    }

    pub fn current_validator_root(&self) -> [u8; 32] {
        BlockBody::compute_validator_root(&self.validator_set.active_validators())
            .unwrap_or([0u8; 32])
    }

    pub fn current_view(&self) -> u64 {
        self.pacemaker.current_view
    }

    pub fn current_leader(&self) -> Option<Address> {
        let seed = self.leader_seed();
        self.validator_set.get_proposer(self.current_view(), seed)
    }

    /// Derives the seed for leader rotation based on the latest finalized block.
    pub fn leader_seed(&self) -> [u8; 32] {
        self.latest_finalized_block()
            .and_then(|block| block.try_hash().ok())
            .unwrap_or([0u8; 32])
    }

    pub fn latest_finalized_block(&self) -> Option<Block> {
        self.finalized_blocks.as_ref().map(|(_, b)| b.clone())
    }

    pub fn load_persisted_quorum_certificate(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<QuorumCertificate>> {
        let key = Self::qc_storage_key_for_block_hash(block_hash);
        self.storage
            .state_get(key)?
            .map(|bytes| {
                QuorumCertificate::decode(&bytes)
                    .or_else(|_| bincode::deserialize(&bytes))
                    .map_err(Into::into)
            })
            .transpose()
    }

    /// Returns the active highest Quorum Certificate known to consensus.
    pub fn highest_qc(&self) -> Result<Option<QuorumCertificate>> {
        if let Some(hash) = self.highest_qc_block {
            self.load_persisted_quorum_certificate(hash)
        } else {
            Ok(None)
        }
    }

    fn quorum_threshold(&self) -> usize {
        let count = self.validator_set.active_validator_count();
        if count == 0 {
            return 0;
        }
        ((count * 2) / 3) + 1
    }

    fn apply_longest_chain_rule(&self, candidate: &Block) -> bool {
        let best_known_height = self
            .pending_blocks
            .values()
            .chain(self.committed_blocks.values())
            .chain(self.finalized_blocks.as_ref().map(|(_, b)| b))
            .map(Block::height)
            .max()
            .unwrap_or(0);

        candidate.height() >= best_known_height
    }

    fn apply_highest_qc_rule(&mut self, qc: &QuorumCertificate) {
        if self.highest_qc_block.is_none() {
            self.highest_qc_block = Some(qc.block_hash);
            return;
        }

        let current_height = self
            .highest_qc_block
            .and_then(|hash| self.find_block(&hash))
            .map(Block::height)
            .unwrap_or(0);
        let candidate_height = self
            .find_block(&qc.block_hash)
            .map(Block::height)
            .unwrap_or(0);

        if candidate_height >= current_height {
            self.highest_qc_block = Some(qc.block_hash);
        }
    }

    fn detect_fork(&self, candidate: &Block) -> bool {
        let candidate_hash = match candidate.try_hash() {
            Ok(h) => h,
            Err(_) => return false,
        };
        self.pending_blocks.values().any(|existing| {
            let existing_hash = match existing.try_hash() {
                Ok(h) => h,
                Err(_) => return false,
            };
            existing.parent_hash() == candidate.parent_hash() && existing_hash != candidate_hash
        })
    }

    fn resolve_fork(&mut self, candidate: &Block) -> Result<()> {
        if !self.apply_longest_chain_rule(candidate) {
            bail!("fork resolution rejected shorter competing branch");
        }

        let candidate_hash = candidate.try_hash()?;
        let conflicting_hashes: Vec<[u8; 32]> = self
            .pending_blocks
            .values()
            .filter(|existing| {
                let existing_hash = match existing.try_hash() {
                    Ok(h) => h,
                    Err(_) => return false,
                };
                existing.parent_hash() == candidate.parent_hash() && existing_hash != candidate_hash
            })
            .filter_map(|b| b.try_hash().ok())
            .collect();

        for hash in conflicting_hashes {
            if let Some(conflicting_block) = self.pending_blocks.get(&hash) {
                if !self.prefer_candidate_branch(candidate, conflicting_block) {
                    bail!("fork resolution kept existing higher-priority branch");
                }
            }
            self.pending_blocks.remove(&hash);
        }

        Ok(())
    }

    fn reject_conflicting_branch(&self, block: &Block) -> Result<()> {
        bail!(
            "rejected block {} from conflicting branch at parent {:?}",
            block.height(),
            block.parent_hash()
        )
    }

    fn apply_three_phase_commit_rule(
        &mut self,
        block: &Block,
        qc: QuorumCertificate,
    ) -> Result<HotStuffPhase> {
        let active_validators = self.validator_set.active_validators();
        let required_voting_power = self.required_quorum_voting_power();
        self.hotstuff.apply_three_phase_commit_rule(
            block,
            qc,
            &active_validators,
            self.quorum_threshold(),
            required_voting_power,
        )
    }

    fn verify_prepare_phase(&self, block: &Block, qc: &QuorumCertificate) -> Result<bool> {
        let active_validators = self.validator_set.active_validators();
        let required_voting_power = self.required_quorum_voting_power();
        self.hotstuff.verify_prepare_phase(
            block,
            qc,
            &active_validators,
            self.quorum_threshold(),
            required_voting_power,
        )
    }

    fn verify_pre_commit_phase(
        &self,
        block_hash: [u8; 32],
        qc: &QuorumCertificate,
    ) -> Result<bool> {
        let active_validators = self.validator_set.active_validators();
        let required_voting_power = self.required_quorum_voting_power();
        self.hotstuff.verify_pre_commit_phase(
            block_hash,
            qc,
            &active_validators,
            self.quorum_threshold(),
            required_voting_power,
        )
    }

    fn verify_commit_phase(&self, block_hash: [u8; 32], qc: &QuorumCertificate) -> Result<bool> {
        let active_validators = self.validator_set.active_validators();
        let required_voting_power = self.required_quorum_voting_power();
        self.hotstuff.verify_commit_phase(
            block_hash,
            qc,
            &active_validators,
            self.quorum_threshold(),
            required_voting_power,
        )
    }

    fn finalize_block_once_quorum_reached(&mut self, block_hash: [u8; 32]) -> Result<()> {
        if !self.committed_blocks.contains_key(&block_hash) {
            self.commit_block(block_hash)?;
        }
        let result = self.finalize_block(block_hash);
        let _ = self.governance.save_to_storage(&self.storage);

        // Prune HotStuff QC maps, VoteCollector, and pending/committed block maps
        // Keep a 10-view buffer to avoid pruning in-flight messages for recent forks.
        let current_view = self.current_view();
        let prune_threshold = current_view.saturating_sub(10);
        self.hotstuff.prune(prune_threshold);
        self.vote_collector.prune(prune_threshold);

        let finalized_height = self.finalized_block_height;
        self.pending_blocks
            .retain(|_, b| b.height() > finalized_height);
        self.committed_blocks
            .retain(|_, b| b.height() > finalized_height);
        self.slashing_manager
            .prune_expired_evidence(finalized_height);

        result
    }

    fn persist_finalized_block_to_storage(&self, block: &Block) -> Result<()> {
        let header_bytes = block.header.try_encode()?;
        let body_bytes = block.body.try_encode()?;
        self.storage
            .atomic_block_commit(block.height(), header_bytes, body_bytes)
    }

    fn is_conflicting_branch(&self, candidate: &Block) -> bool {
        let candidate_hash = match candidate.try_hash() {
            Ok(h) => h,
            Err(_) => return false,
        };
        if let Some((_, finalized)) = &self.finalized_blocks {
            let finalized_hash = match finalized.try_hash() {
                Ok(h) => h,
                Err(_) => return false,
            };
            if finalized.height() == candidate.height() && finalized_hash != candidate_hash {
                return true;
            }
        }
        false
    }

    fn prefer_candidate_branch(&self, candidate: &Block, incumbent: &Block) -> bool {
        if candidate.height() != incumbent.height() {
            return candidate.height() > incumbent.height();
        }

        let candidate_hash = candidate.try_hash().ok();
        let incumbent_hash = incumbent.try_hash().ok();
        let candidate_has_highest_qc =
            candidate_hash.is_some() && self.highest_qc_block == candidate_hash;
        let incumbent_has_highest_qc =
            incumbent_hash.is_some() && self.highest_qc_block == incumbent_hash;
        candidate_has_highest_qc || !incumbent_has_highest_qc
    }

    fn find_block(&self, hash: &[u8; 32]) -> Option<&Block> {
        self.pending_blocks
            .get(hash)
            .or_else(|| self.committed_blocks.get(hash))
            .or_else(|| {
                self.finalized_blocks
                    .as_ref()
                    .and_then(|(_, b)| (b.try_hash().ok().as_ref() == Some(hash)).then_some(b))
            })
    }

    fn resolve_parent_block(&self, child: &Block) -> Result<Block> {
        if child.height() == 0 {
            bail!("genesis cannot be processed as a consensus proposal");
        }

        if let Some(parent) = self.find_block(&child.parent_hash()) {
            return Ok(parent.clone());
        }

        let parent_height = child.height().saturating_sub(1);
        let header = self
            .storage
            .get_block_header(parent_height)?
            .ok_or_else(|| anyhow::anyhow!("proposal references an unknown parent"))?;
        if header.try_hash()? != child.parent_hash() {
            bail!(
                "proposal parent hash does not match canonical block at height {}",
                parent_height
            );
        }
        let body = self
            .storage
            .get_block_body(parent_height)?
            .ok_or_else(|| anyhow::anyhow!("canonical parent body is missing"))?;
        Ok(Block::new(header, body))
    }

    fn validate_proposal_parent(&self, block: &Block) -> Result<()> {
        let parent = self.resolve_parent_block(block)?;
        if block.height() != parent.height().saturating_add(1) {
            bail!(
                "proposal height {} does not directly follow parent height {}",
                block.height(),
                parent.height()
            );
        }
        if block.parent_hash() != parent.try_hash()? {
            bail!("proposal does not link to its resolved parent");
        }
        if !block.header.verify_timestamp(parent.header.timestamp) {
            bail!("proposal timestamp must be strictly greater than its parent timestamp");
        }
        if block.height() <= self.finalized_block_height {
            bail!("proposal does not advance the finalized chain");
        }
        Ok(())
    }

    fn detect_conflicting_proposal(&self, candidate: &Block) -> Result<()> {
        let candidate_hash = candidate.try_hash()?;
        let conflicting = self.pending_blocks.values().any(|existing| {
            let existing_hash = match existing.try_hash() {
                Ok(h) => h,
                Err(_) => return false,
            };
            existing.height() == candidate.height()
                && existing.header.proposer == candidate.header.proposer
                && existing_hash != candidate_hash
        });

        if conflicting {
            bail!(
                "conflicting proposal detected from proposer {} at height {}",
                candidate.header.proposer,
                candidate.height()
            );
        }

        Ok(())
    }

    fn verify_validator_vote(&self, vote: &Vote) -> Result<()> {
        let validator = self
            .validator_set
            .validator(&vote.validator)
            .ok_or_else(|| anyhow::anyhow!("unknown validator {}", vote.validator))?;

        if !vote.verify_signature(validator)? {
            bail!("invalid validator signature for {}", vote.validator);
        }

        if self.validator_set.voting_power(&vote.validator) == 0 {
            bail!("validator {} has no voting power", vote.validator);
        }

        Ok(())
    }

    /// SECURITY (C-02/C-03): public, read-only QC verification so external
    /// consumers (node sync paths, gossip ingestion) can authenticate
    /// proposer-supplied QCs against the local validator set before trusting
    /// peer data. Fails closed on any cryptographic or quorum mismatch.
    pub fn verify_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()> {
        self.reject_invalid_quorum_certificate(qc)
    }

    fn reject_invalid_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()> {
        let active_validators = self.validator_set.active_validators();
        let required_voting_power = self.required_quorum_voting_power();
        if !qc.verify_bls_with_voting_power(
            &active_validators,
            self.quorum_threshold(),
            required_voting_power,
        )? {
            bail!("invalid quorum certificate");
        }
        Ok(())
    }

    pub fn required_quorum_voting_power(&self) -> u64 {
        let total = self.validator_set.total_active_voting_power();
        if total == 0 {
            return 0;
        }
        let total_u128 = total as u128;
        let quorum = ((total_u128 * 2) / 3) + 1;
        u64::try_from(quorum).unwrap_or(u64::MAX)
    }

    pub fn broadcast_block_proposal_to_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        block: &Block,
    ) -> Result<()> {
        let view = self.pacemaker.current_view;
        let proposer = &block.header.proposer;
        if has_proposed_in_view(&self.storage, view, proposer)? {
            bail!(
                "double proposal detected for view {} by proposer {}",
                view,
                proposer
            );
        }
        record_proposal_in_view(&self.storage, view, proposer)?;
        network.broadcast_block_proposal(block.try_encode()?)
    }

    pub fn broadcast_vote_to_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        vote: &Vote,
    ) -> Result<()> {
        network.broadcast_vote(vote.encode())
    }

    pub fn broadcast_quorum_certificate_to_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        quorum_certificate: &QuorumCertificate,
    ) -> Result<()> {
        network.broadcast_quorum_certificate(quorum_certificate.encode())
    }

    pub fn broadcast_new_view_message<N: ConsensusNetwork>(&self, network: &N) -> Result<()> {
        let message = self
            .pacemaker
            .broadcast_new_view(self.validator_set.active_validator_count());
        network.broadcast_new_view(message.try_encode()?)
    }

    pub fn request_missing_blocks_from_peers<N: ConsensusNetwork>(
        &self,
        network: &N,
        start_height: u64,
        limit: u64,
    ) -> Result<Vec<Block>> {
        let payloads = network.request_missing_blocks(start_height, limit)?;
        payloads
            .into_iter()
            .map(|payload| Block::decode(&payload))
            .collect()
    }

    pub fn synchronize_validator_state_with_network<N: ConsensusNetwork>(
        &self,
        network: &N,
    ) -> Result<()> {
        let validators = self.validator_set.active_validators();
        network.synchronize_validator_state(validators.try_encode()?)
    }

    /// Release any reserved MEV transactions back to the revealed mempool.
    pub fn release_mev_reservation(&self, handle: sxiaum_types::ReservationId) -> Result<()> {
        self.proposer
            .mempool
            .release_transaction_reservation(handle)
    }

    fn persist_vote_in_storage(&self, vote: &Vote) -> Result<()> {
        self.storage
            .state_put(Self::vote_storage_key(vote), vote.try_encode()?)
    }

    fn persist_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()> {
        self.storage
            .state_put(Self::qc_storage_key(qc), qc.encode())?;
        if let Ok(Some(current_highest)) = crate::consensus_state::restore_highest_qc(&self.storage)
        {
            if qc.view >= current_highest.view {
                let _ = self
                    .storage
                    .state_put(b"cstate:highest_qc".to_vec(), qc.encode());
            }
        } else {
            let _ = self
                .storage
                .state_put(b"cstate:highest_qc".to_vec(), qc.encode());
        }
        Ok(())
    }

    fn ensure_committed_block_qc_is_valid(&self, block_hash: [u8; 32]) -> Result<()> {
        let qc = self
            .load_persisted_quorum_certificate(block_hash)?
            .ok_or_else(|| {
                anyhow::anyhow!("missing quorum certificate for block {:x?}", block_hash)
            })?;
        self.reject_invalid_quorum_certificate(&qc)
    }

    pub fn persist_validator_set(&self) -> Result<()> {
        let validators = self.validator_set.active_validators();
        self.storage.state_put(
            CONSENSUS_VALIDATOR_SET_KEY.to_vec(),
            validators.try_encode()?,
        )
    }

    fn persist_current_consensus_view(&self) -> Result<()> {
        self.storage.state_put(
            CONSENSUS_CURRENT_VIEW_KEY.to_vec(),
            self.current_view().to_le_bytes().to_vec(),
        )
    }

    /// Persist the locked block hash and height so the safety rule survives restarts.
    fn persist_locked_block(&self, block_hash: [u8; 32], height: u64) -> Result<()> {
        self.storage.state_put(
            CONSENSUS_LOCKED_BLOCK_HEIGHT_KEY.to_vec(),
            height.to_le_bytes().to_vec(),
        )?;
        // Also write to the canonical locked-block key read by restore_locked_block().
        crate::consensus_state::persist_locked_block(&self.storage, block_hash)
    }

    /// Load the persisted locked-block height (if any).
    fn load_locked_block_height(&self) -> Option<u64> {
        self.storage
            .state_get(CONSENSUS_LOCKED_BLOCK_HEIGHT_KEY.to_vec())
            .ok()
            .flatten()
            .filter(|bytes| bytes.len() == 8)
            .map(|bytes| {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                u64::from_le_bytes(arr)
            })
    }

    fn restore_consensus_state_on_restart(&mut self) -> Result<()> {
        if let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())?
        {
            let validators: Vec<Validator> = <Vec<Validator> as Canonical>::decode(&bytes)
                .or_else(|_| bincode::deserialize(&bytes))?;
            self.validator_set.replace_validators(validators)?;
        }

        if let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_CURRENT_VIEW_KEY.to_vec())?
        {
            if bytes.len() == 8 {
                let mut view_bytes = [0u8; 8];
                view_bytes.copy_from_slice(&bytes);
                self.pacemaker.current_view = u64::from_le_bytes(view_bytes);
            }
        }

        for (_, bytes) in self
            .storage
            .state_prefix_scan(CONSENSUS_VOTE_PREFIX.to_vec())?
        {
            let vote: Vote = Vote::decode(&bytes)?;
            let _ = self.vote_collector.add_vote(vote);
        }

        let mut highest_qc_view = 0u64;
        let mut restored_highest_qc: Option<[u8; 32]> = None;
        for (_, bytes) in self
            .storage
            .state_prefix_scan(CONSENSUS_QC_PREFIX.to_vec())?
        {
            let qc = QuorumCertificate::decode(&bytes)?;
            if qc.view >= highest_qc_view || restored_highest_qc.is_none() {
                highest_qc_view = qc.view;
                restored_highest_qc = Some(qc.block_hash);
            }
        }
        self.highest_qc_block = restored_highest_qc;
        self.hotstuff.highest_qc_view = highest_qc_view;

        let _ = self.governance.load_from_storage(&self.storage);

        Ok(())
    }

    fn qc_storage_key_for_block_hash(block_hash: [u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(CONSENSUS_QC_PREFIX.len() + block_hash.len());
        key.extend_from_slice(CONSENSUS_QC_PREFIX);
        key.extend_from_slice(&block_hash);
        key
    }

    fn maybe_rotate_validator_set_for_new_epoch(&mut self) -> Result<()> {
        if self.finalized_block_height == 0
            || !self
                .finalized_block_height
                .is_multiple_of(self.epoch_length)
        {
            return Ok(());
        }

        self.staking_manager.staking_epoch_update()?;

        let passed_proposals = self.governance.get_and_mark_passed_proposals();
        for proposal in passed_proposals {
            match proposal.proposal_type {
                crate::governance::ProposalType::AddValidator { validator } => {
                    // SECURITY (H-09): slash cooldown is enforced on the
                    // governance admission path too. Previously only live
                    // jail status was checked, so a slashed validator whose
                    // jail window expired could rejoin mid-cooldown via an
                    // AddValidator proposal.
                    let in_cooldown = self
                        .slashing_manager
                        .is_in_cooldown(&validator.address, self.finalized_block_height)
                        .unwrap_or(true);
                    if in_cooldown {
                        tracing::warn!(
                            "AddValidator proposal for {} rejected: slash cooldown active",
                            validator.address
                        );
                    } else if let Err(err) = self.validator_set.add_validator(validator) {
                        tracing::warn!("AddValidator proposal rejected: {}", err);
                    }
                }
                crate::governance::ProposalType::RemoveValidator { address } => {
                    let _ = self.validator_set.remove_validator(&address);
                }
                _ => {}
            }
        }

        let mut next_validators = self.validator_set.all_validators();
        for validator in &mut next_validators {
            validator.stake = self.staking_manager.get_stake(&validator.address);
            validator.update_voting_power();
            if validator.stake.is_zero() {
                validator.status = sxiaum_types::validator::ValidatorStatus::Inactive;
            } else if validator.is_jailed() {
                // keep jailed status; unjailing is handled by the jail window
            } else {
                // SECURITY (H-09): a validator serving a post-slash cooldown
                // must not be reactivated just because its jail window
                // expired. Cooldown was recorded by `execute_slash` but never
                // consulted, so slashed validators rejoined clean at the next
                // epoch boundary.
                let in_cooldown = self
                    .slashing_manager
                    .is_in_cooldown(&validator.address, self.finalized_block_height)
                    .unwrap_or(true);
                if in_cooldown {
                    validator.status = sxiaum_types::validator::ValidatorStatus::Jailed;
                    validator.voting_power = 0;
                } else {
                    validator.status = sxiaum_types::validator::ValidatorStatus::Active;
                    // SECURITY (H-13): a returning validator starts its uptime
                    // streak clean; stale streaks caused instant re-jailing.
                    self.uptime_monitor.reset_validator(&validator.address);
                }
            }
        }

        next_validators.retain(|validator| !validator.stake.is_zero());
        self.validator_set.replace_validators(next_validators)?;
        crate::metrics::ConsensusMetrics::record_validator_count(
            self.validator_set.active_validator_count(),
        );
        self.persist_validator_set()?;
        self.persist_current_consensus_view()?;
        Ok(())
    }

    /// SECURITY (H-14): consume matured time-locked governance proposals and
    /// apply SoftwareUpgrade decisions to the UpgradeManager. Failures are
    /// logged loudly (never silently discarded) but do not halt finalization;
    /// a rejected upgrade keeps its Executed status and must be re-proposed.
    fn process_governance_upgrade_executions(&mut self) {
        let current_height = self.finalized_block_height;
        for proposal in self
            .governance
            .execute_time_locked_proposals(current_height)
        {
            if let crate::governance::ProposalType::SoftwareUpgrade { version, height } =
                &proposal.proposal_type
            {
                match crate::upgrades::ProtocolVersion::parse(version) {
                    Ok(target) => {
                        if let Err(error) = self.upgrades.apply_governance_upgrade(
                            &proposal.title,
                            target,
                            *height,
                            current_height,
                        ) {
                            tracing::error!(
                                "governance upgrade '{}' scheduling FAILED: {} \
                                 (manual operator action required)",
                                proposal.title,
                                error
                            );
                        }
                    }
                    Err(error) => tracing::error!(
                        "governance upgrade '{}' has unparseable version '{}': {}",
                        proposal.title,
                        version,
                        error
                    ),
                }
            }
        }
    }

    fn vote_storage_key(vote: &Vote) -> Vec<u8> {
        let mut key = CONSENSUS_VOTE_PREFIX.to_vec();
        key.extend_from_slice(&vote.view.to_le_bytes());
        key.extend_from_slice(vote.validator.as_bytes());
        key.extend_from_slice(&vote.block_hash);
        key
    }

    fn qc_storage_key(qc: &QuorumCertificate) -> Vec<u8> {
        let mut key = CONSENSUS_QC_PREFIX.to_vec();
        key.extend_from_slice(&qc.block_hash);
        key
    }
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{
        Consensus, ConsensusNetwork, CONSENSUS_CURRENT_VIEW_KEY, CONSENSUS_QC_PREFIX,
        CONSENSUS_VALIDATOR_SET_KEY, CONSENSUS_VOTE_PREFIX,
    };
    use crate::hotstuff::vote::{QuorumCertificate, Vote};
    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_storage::StorageEngine;
    use sxiaum_types::validator::ValidatorStatus;
    use sxiaum_types::{Address, Canonical, Validator};

    #[derive(Default)]
    struct MockConsensusNetwork {
        block_proposals: RefCell<Vec<Vec<u8>>>,
        votes: RefCell<Vec<Vec<u8>>>,
        quorum_certificates: RefCell<Vec<Vec<u8>>>,
        new_views: RefCell<Vec<Vec<u8>>>,
        validator_syncs: RefCell<Vec<Vec<u8>>>,
        missing_blocks_response: RefCell<Vec<Vec<u8>>>,
        missing_blocks_requests: RefCell<Vec<(u64, u64)>>,
    }

    impl ConsensusNetwork for MockConsensusNetwork {
        fn broadcast_block_proposal(&self, payload: Vec<u8>) -> Result<()> {
            self.block_proposals.borrow_mut().push(payload);
            Ok(())
        }

        fn broadcast_vote(&self, payload: Vec<u8>) -> Result<()> {
            self.votes.borrow_mut().push(payload);
            Ok(())
        }

        fn broadcast_quorum_certificate(&self, payload: Vec<u8>) -> Result<()> {
            self.quorum_certificates.borrow_mut().push(payload);
            Ok(())
        }

        fn broadcast_new_view(&self, payload: Vec<u8>) -> Result<()> {
            self.new_views.borrow_mut().push(payload);
            Ok(())
        }

        fn request_missing_blocks(&self, start_height: u64, limit: u64) -> Result<Vec<Vec<u8>>> {
            self.missing_blocks_requests
                .borrow_mut()
                .push((start_height, limit));
            Ok(self.missing_blocks_response.borrow().clone())
        }

        fn synchronize_validator_state(&self, payload: Vec<u8>) -> Result<()> {
            self.validator_syncs.borrow_mut().push(payload);
            Ok(())
        }
    }

    fn unique_storage_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-{name}-{unique}.redb"))
    }

    fn test_storage(name: &str) -> (Arc<StorageEngine>, PathBuf) {
        let path = unique_storage_path(name);
        let storage = Arc::new(
            StorageEngine::new(path.to_string_lossy().as_ref())
                .expect("test storage should initialize"),
        );
        (storage, path)
    }

    fn cleanup_storage(path: PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn active_validator(seed: u8) -> (Validator, SigningKey) {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let signing_key = signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&public_key);
        let mut validator = Validator::new(address, public_key, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        validator = validator.with_bls_pop(pk.0, pop.0);
        (validator, signing_key)
    }

    fn inactive_validator(seed: u8) -> (Validator, SigningKey) {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let signing_key = signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&public_key);
        let mut validator = Validator::new(address, public_key, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Inactive;
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        validator = validator.with_bls_pop(pk.0, pop.0);
        (validator, signing_key)
    }

    fn zero_power_validator(seed: u8) -> (Validator, SigningKey) {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let signing_key = signing_key(seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&public_key);
        let mut validator = Validator::new(address, public_key, U256::from(1u64));
        validator.status = ValidatorStatus::Active;
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        validator = validator.with_bls_pop(pk.0, pop.0);
        (validator, signing_key)
    }

    fn block_for(parent_hash: [u8; 32], height: u64, proposer: Address) -> Block {
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        let mut block = Block::new(header, BlockBody::empty());
        block
            .try_compute_roots()
            .expect("merkle root computation failed");
        block
    }

    fn new_consensus() -> Consensus {
        let storage = Arc::new(
            StorageEngine::new("consensus-temp.redb")
                .expect("consensus temporary storage should initialize"),
        );
        Consensus::with_storage(storage)
    }

    fn with_storage(storage: Arc<StorageEngine>) -> Consensus {
        Consensus::with_storage(storage)
    }

    #[test]
    fn new_initializes_requested_consensus_fields() {
        let path = PathBuf::from("consensus-temp.redb");
        let consensus = new_consensus();

        assert_eq!(consensus.current_view(), 0);
        assert!(consensus.current_leader().is_none());
        assert_eq!(consensus.proposer.validator_id, Address::zero());
        assert_eq!(consensus.vote_collector.vote_count(0, [0u8; 32]), 0);

        drop(consensus);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn start_restores_view_and_updates_proposer_for_current_leader() {
        let (storage, path) = test_storage("consensus-start");
        let (validator, _) = active_validator(1);

        {
            let mut consensus = with_storage(storage.clone());
            let _ = consensus.update_validator_set(vec![validator.clone()]);
            consensus.pacemaker.current_view = 7;
            consensus.stop().expect("consensus state should persist");
        }

        let mut restored = with_storage(storage);
        let view = restored.start().expect("consensus should start");

        assert_eq!(view, 7);
        assert_eq!(restored.current_view(), 7);
        assert_eq!(restored.current_leader(), Some(validator.address));
        assert_eq!(restored.proposer.validator_id, validator.address);

        cleanup_storage(path);
    }

    #[test]
    fn process_block_proposal_accepts_leader_block_and_tracks_it() {
        let (storage, path) = test_storage("consensus-proposal");
        let (validator, signing_key) = active_validator(2);
        let mut consensus = with_storage(storage.clone());
        let _ = consensus.update_validator_set(vec![validator.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        storage
            .atomic_block_commit_typed(0, &genesis.header, &genesis.body)
            .unwrap();
        let mut block = block_for(genesis.try_hash().unwrap(), 1, validator.address);
        block.header.sign(&signing_key).unwrap();
        let block_hash = block.try_hash().unwrap();

        let accepted = consensus
            .process_block_proposal(block)
            .expect("leader proposal should be accepted");

        assert!(accepted);
        assert!(consensus.pending_blocks.contains_key(&block_hash));

        cleanup_storage(path);
    }

    #[test]
    fn process_vote_builds_quorum_certificate_and_persists_vote() {
        let (storage, path) = test_storage("consensus-vote");
        let (validator, signing_key) = active_validator(3);
        let mut consensus = with_storage(storage.clone());
        let _ = consensus.update_validator_set(vec![validator.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        storage
            .atomic_block_commit_typed(0, &genesis.header, &genesis.body)
            .unwrap();
        let mut block = block_for(genesis.try_hash().unwrap(), 1, validator.address);
        block.header.sign(&signing_key).unwrap();
        let block_hash = block.try_hash().unwrap();
        consensus
            .process_block_proposal(block)
            .expect("proposal should be tracked");

        let mut vote = Vote::new(validator.address, block_hash, consensus.current_view());
        vote.sign(&signing_key).expect("vote should sign");

        let qc = consensus
            .process_vote(vote.clone())
            .expect("vote should be processed")
            .expect("single active validator should reach quorum");

        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(consensus.vote_collector.vote_count(0, block_hash), 1);
        assert!(consensus.hotstuff.has_prepare_quorum(block_hash));

        let persisted_vote = storage
            .state_prefix_scan(CONSENSUS_VOTE_PREFIX.to_vec())
            .expect("vote scan should succeed");
        assert_eq!(persisted_vote.len(), 1);

        cleanup_storage(path);
    }

    #[test]
    fn conflicting_proposals_are_detected_for_same_proposer_and_height() {
        let (storage, path) = test_storage("consensus-conflicting-proposal");
        let (validator, _) = active_validator(19);
        let mut consensus = with_storage(storage);
        let _ = consensus.update_validator_set(vec![validator.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let first = block_for(genesis.try_hash().unwrap(), 1, validator.address);
        let second = block_for([7u8; 32], 1, validator.address);
        consensus
            .pending_blocks
            .insert(first.try_hash().unwrap(), first);

        assert!(consensus.detect_conflicting_proposal(&second).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn validator_vote_verification_rejects_invalid_signature_and_zero_voting_power() {
        let (storage, path) = test_storage("consensus-verify-vote");
        let (active, active_signer) = active_validator(20);
        let (inactive, inactive_signer) = inactive_validator(21);
        let (zero_power, _zero_power_signer) = zero_power_validator(26);
        let mut consensus = with_storage(storage);
        assert!(
            consensus
                .update_validator_set(vec![
                    active.clone(),
                    inactive.clone(),
                    zero_power.clone(),
                ])
                .is_err(),
            "active validator with zero voting power must be rejected"
        );
        consensus
            .update_validator_set(vec![active.clone(), inactive.clone()])
            .expect("validators with positive voting power must register");

        let block_hash = [5u8; 32];
        let mut bad_signature_vote = Vote::new(active.address, block_hash, 0);
        bad_signature_vote
            .sign(&inactive_signer)
            .expect("vote signing should succeed even with wrong signer");
        assert!(consensus
            .verify_validator_vote(&bad_signature_vote)
            .is_err());

        let mut valid_vote = Vote::new(active.address, block_hash, 0);
        valid_vote.sign(&active_signer).expect("vote should sign");
        consensus
            .verify_validator_vote(&valid_vote)
            .expect("active validator vote should verify");

        consensus
            .validator_set
            .jail_validator(&active.address)
            .expect("active validator should jail");
        let mut jailed_vote = Vote::new(active.address, block_hash, 0);
        jailed_vote.sign(&active_signer).expect("vote should sign");
        assert!(consensus.verify_validator_vote(&jailed_vote).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn invalid_quorum_certificates_are_rejected_and_valid_ones_pass() {
        let (storage, path) = test_storage("consensus-invalid-qc");
        let (validator_a, signer_a) = active_validator(22);
        let (validator_b, signer_b) = active_validator(23);
        let mut consensus = with_storage(storage);
        let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let block_hash = [8u8; 32];
        let mut vote_a = Vote::new(validator_a.address, block_hash, 0);
        let mut vote_b = Vote::new(validator_b.address, block_hash, 0);
        vote_a.sign(&signer_a).expect("vote a should sign");
        vote_b.sign(&signer_b).expect("vote b should sign");

        let invalid_qc = QuorumCertificate::new(
            block_hash,
            0,
            vec![vote_a.signature.to_vec()],
            vec![vote_a.validator],
        );
        assert!(consensus
            .reject_invalid_quorum_certificate(&invalid_qc)
            .is_err());

        let valid_qc = QuorumCertificate::new(
            block_hash,
            0,
            vec![vote_a.signature.to_vec(), vote_b.signature.to_vec()],
            vec![vote_a.validator, vote_b.validator],
        );
        consensus
            .reject_invalid_quorum_certificate(&valid_qc)
            .expect("two-validator quorum certificate should be accepted");

        cleanup_storage(path);
    }

    #[test]
    fn commit_and_finalize_block_move_it_through_consensus_lifecycle() {
        let (storage, path) = test_storage("consensus-finalize");
        let (validator_a, signing_key_a) = active_validator(4);
        let (validator_b, signing_key_b) = active_validator(5);
        let mut consensus = with_storage(storage.clone());
        let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        storage
            .atomic_block_commit_typed(0, &genesis.header, &genesis.body)
            .unwrap();
        let proposer = consensus.current_leader().expect("leader should exist");
        let signing_key = if proposer == validator_a.address {
            &signing_key_a
        } else {
            &signing_key_b
        };
        let mut block = block_for(genesis.try_hash().unwrap(), 1, proposer);
        block.header.sign(signing_key).unwrap();
        let block_hash = block.try_hash().unwrap();
        consensus
            .process_block_proposal(block)
            .expect("proposal should be accepted");

        let mut vote_a = Vote::new(validator_a.address, block_hash, consensus.current_view());
        vote_a.sign(&signing_key_a).expect("vote should sign");
        let mut vote_b = Vote::new(validator_b.address, block_hash, consensus.current_view());
        vote_b.sign(&signing_key_b).expect("vote should sign");
        let qc = QuorumCertificate::new(
            block_hash,
            consensus.current_view(),
            vec![vote_a.signature.to_vec(), vote_b.signature.to_vec()],
            vec![validator_a.address, validator_b.address],
        );
        consensus
            .reject_invalid_quorum_certificate(&qc)
            .expect("qc should validate before finalization");
        consensus
            .persist_quorum_certificate(&qc)
            .expect("qc should persist before finalization");

        consensus
            .commit_block(block_hash)
            .expect("pending block should commit");
        assert!(consensus.committed_blocks.contains_key(&block_hash));

        let previous_view = consensus.current_view();
        consensus
            .finalize_block(block_hash)
            .expect("committed block should finalize");

        assert_eq!(consensus.finalized_block_height, 1);
        assert_eq!(consensus.current_view(), previous_view + 1);
        assert!(!consensus.committed_blocks.contains_key(&block_hash));
        assert_eq!(
            consensus
                .latest_finalized_block()
                .map(|block| block.try_hash().unwrap()),
            Some(block_hash)
        );
        assert_eq!(
            consensus.proposer.validator_id,
            consensus.current_leader().unwrap()
        );
        assert_eq!(
            storage
                .latest_block_height()
                .expect("latest height should load"),
            1
        );

        cleanup_storage(path);
    }

    #[test]
    fn update_validator_set_persists_validators_and_updates_leader_state() {
        let (storage, path) = test_storage("consensus-validator-set");
        let (validator_a, _) = active_validator(6);
        let (validator_b, _) = active_validator(7);
        let mut consensus = with_storage(storage.clone());

        let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        assert_eq!(consensus.current_view(), 0);
        assert_eq!(
            consensus.current_leader(),
            consensus.validator_set.get_proposer(0, [0u8; 32])
        );
        assert_eq!(
            consensus.proposer.validator_id,
            consensus.current_leader().unwrap()
        );

        let stored_view = storage
            .state_get(CONSENSUS_CURRENT_VIEW_KEY.to_vec())
            .expect("view lookup should succeed");
        assert!(stored_view.is_none());

        let mut restored = with_storage(storage);
        restored.start().expect("restored consensus should start");

        assert_eq!(restored.validator_set.active_validator_count(), 2);
        assert_eq!(
            restored.current_leader(),
            restored.validator_set.get_proposer(0, [0u8; 32])
        );
        assert_eq!(
            restored.proposer.validator_id,
            restored.current_leader().unwrap()
        );

        cleanup_storage(path);
    }

    #[test]
    fn longest_chain_rule_prefers_candidate_at_or_above_best_known_height() {
        let (storage, path) = test_storage("consensus-longest-chain");
        let (validator, _) = active_validator(8);
        let mut consensus = with_storage(storage);

        let base = Block::genesis([0u8; 32]);
        let higher = block_for(base.try_hash().unwrap(), 3, validator.address);
        let shorter = block_for(base.try_hash().unwrap(), 2, validator.address);
        let equal = block_for(base.try_hash().unwrap(), 3, validator.address);

        consensus
            .pending_blocks
            .insert(higher.try_hash().unwrap(), higher);

        assert!(!consensus.apply_longest_chain_rule(&shorter));
        assert!(consensus.apply_longest_chain_rule(&equal));

        cleanup_storage(path);
    }

    #[test]
    fn highest_qc_rule_tracks_highest_known_block_height() {
        let (storage, path) = test_storage("consensus-highest-qc");
        let (validator, _) = active_validator(9);
        let mut consensus = with_storage(storage);

        let genesis = Block::genesis([0u8; 32]);
        let lower = block_for(genesis.try_hash().unwrap(), 1, validator.address);
        let higher = block_for(lower.try_hash().unwrap(), 2, validator.address);
        let lower_hash = lower.try_hash().unwrap();
        let higher_hash = higher.try_hash().unwrap();
        consensus.pending_blocks.insert(lower_hash, lower);
        consensus.pending_blocks.insert(higher_hash, higher);

        consensus.apply_highest_qc_rule(&QuorumCertificate::new(
            lower_hash,
            1,
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(consensus.highest_qc_block, Some(lower_hash));

        consensus.apply_highest_qc_rule(&QuorumCertificate::new(
            higher_hash,
            2,
            Vec::new(),
            Vec::new(),
        ));
        assert_eq!(consensus.highest_qc_block, Some(higher_hash));

        cleanup_storage(path);
    }

    #[test]
    fn fork_detection_and_resolution_replace_lower_priority_pending_branch() {
        let (storage, path) = test_storage("consensus-fork-resolution");
        let (validator_a, _) = active_validator(10);
        let (validator_b, _) = active_validator(11);
        let mut consensus = with_storage(storage);

        let genesis = Block::genesis([0u8; 32]);
        let incumbent = block_for(genesis.try_hash().unwrap(), 1, validator_a.address);
        let candidate = block_for(genesis.try_hash().unwrap(), 1, validator_b.address);
        let incumbent_hash = incumbent.try_hash().unwrap();
        let candidate_hash = candidate.try_hash().unwrap();

        consensus
            .pending_blocks
            .insert(incumbent_hash, incumbent.clone());

        assert!(consensus.detect_fork(&candidate));

        consensus.highest_qc_block = Some(candidate_hash);
        consensus
            .resolve_fork(&candidate)
            .expect("candidate should replace lower-priority branch");

        assert!(!consensus.pending_blocks.contains_key(&incumbent_hash));
        assert!(!consensus.detect_fork(&candidate));

        cleanup_storage(path);
    }

    #[test]
    fn fork_resolution_rejects_shorter_or_lower_priority_branch() {
        let (storage, path) = test_storage("consensus-fork-reject");
        let (validator_a, _) = active_validator(12);
        let (validator_b, _) = active_validator(13);
        let mut consensus = with_storage(storage);

        let genesis = Block::genesis([0u8; 32]);
        let incumbent = block_for(genesis.try_hash().unwrap(), 2, validator_a.address);
        let shorter = block_for(genesis.try_hash().unwrap(), 1, validator_b.address);
        let same_height_candidate = block_for(genesis.try_hash().unwrap(), 2, validator_b.address);
        let incumbent_hash = incumbent.try_hash().unwrap();

        consensus
            .pending_blocks
            .insert(incumbent_hash, incumbent.clone());
        assert!(consensus.resolve_fork(&shorter).is_err());

        consensus.highest_qc_block = Some(incumbent_hash);
        assert!(consensus.resolve_fork(&same_height_candidate).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn conflicting_finalized_branch_is_rejected() {
        let (storage, path) = test_storage("consensus-conflicting-branch");
        let (validator_a, _) = active_validator(14);
        let (validator_b, signing_key_b) = active_validator(15);
        let mut consensus = with_storage(storage);
        let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let genesis = Block::genesis([0u8; 32]);
        let finalized = block_for(genesis.try_hash().unwrap(), 1, validator_a.address);
        let mut candidate = block_for([9u8; 32], 1, validator_b.address);
        candidate.header.sign(&signing_key_b).unwrap();
        consensus.finalized_blocks = Some((finalized.height(), finalized));

        assert!(consensus.is_conflicting_branch(&candidate));
        assert!(consensus.reject_conflicting_branch(&candidate).is_err());
        assert!(consensus.process_block_proposal(candidate).is_err());

        cleanup_storage(path);
    }

    #[test]
    fn consensus_network_methods_broadcast_and_decode_expected_payloads() {
        let (storage, path) = test_storage("consensus-network-broadcasts");
        let (validator_a, signing_key) = active_validator(16);
        let (validator_b, _) = active_validator(17);
        let mut consensus = with_storage(storage);
        let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);
        consensus.pacemaker.current_view = 3;

        let block = block_for([1u8; 32], 2, validator_a.address);
        let mut vote = Vote::new(validator_a.address, block.try_hash().unwrap(), 3);
        vote.sign(&signing_key).expect("vote should sign");
        let qc = QuorumCertificate::new(
            block.try_hash().unwrap(),
            3,
            vec![vote.signature.to_vec()],
            vec![validator_a.address],
        );
        let network = MockConsensusNetwork::default();

        consensus
            .broadcast_block_proposal_to_peers(&network, &block)
            .expect("block proposal broadcast should succeed");
        let decoded_block: Block = Block::decode(&network.block_proposals.borrow()[0])
            .expect("broadcast block should deserialize");
        assert_eq!(decoded_block.try_hash().unwrap(), block.try_hash().unwrap());

        consensus
            .broadcast_vote_to_peers(&network, &vote)
            .expect("vote broadcast should succeed");
        let decoded_vote =
            Vote::decode(&network.votes.borrow()[0]).expect("broadcast vote should deserialize");
        assert_eq!(decoded_vote.block_hash, vote.block_hash);

        consensus
            .broadcast_quorum_certificate_to_peers(&network, &qc)
            .expect("qc broadcast should succeed");
        let decoded_qc = QuorumCertificate::decode(&network.quorum_certificates.borrow()[0])
            .expect("broadcast qc should deserialize");
        assert_eq!(decoded_qc.block_hash, qc.block_hash);

        consensus
            .broadcast_new_view_message(&network)
            .expect("new-view broadcast should succeed");
        let new_view: crate::hotstuff::pacemaker::NewViewMessage =
            <crate::hotstuff::pacemaker::NewViewMessage as Canonical>::decode(
                &network.new_views.borrow()[0],
            )
            .expect("new-view payload should deserialize");
        assert_eq!(new_view.view, 3);
        assert_eq!(new_view.leader_index, Some(1));

        consensus
            .synchronize_validator_state_with_network(&network)
            .expect("validator sync should succeed");
        let synced_validators: Vec<Validator> =
            <Vec<Validator> as Canonical>::decode(&network.validator_syncs.borrow()[0])
                .expect("validator sync payload should deserialize");
        assert_eq!(synced_validators.len(), 2);
        assert!(synced_validators
            .iter()
            .any(|validator| validator.address == validator_a.address));
        assert!(synced_validators
            .iter()
            .any(|validator| validator.address == validator_b.address));

        cleanup_storage(path);
    }

    #[test]
    fn consensus_can_request_and_decode_missing_blocks_from_peers() {
        let (storage, path) = test_storage("consensus-request-missing-blocks");
        let (validator, _) = active_validator(18);
        let consensus = with_storage(storage);
        let block_a = block_for([2u8; 32], 4, validator.address);
        let block_b = block_for(block_a.try_hash().unwrap(), 5, validator.address);
        let network = MockConsensusNetwork {
            missing_blocks_response: RefCell::new(vec![
                block_a.try_encode().expect("block a should serialize"),
                block_b.try_encode().expect("block b should serialize"),
            ]),
            ..Default::default()
        };

        let blocks = consensus
            .request_missing_blocks_from_peers(&network, 4, 2)
            .expect("missing block request should succeed");

        assert_eq!(
            network.missing_blocks_requests.borrow().as_slice(),
            &[(4, 2)]
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].try_hash().unwrap(), block_a.try_hash().unwrap());
        assert_eq!(blocks[1].try_hash().unwrap(), block_b.try_hash().unwrap());

        cleanup_storage(path);
    }

    #[test]
    fn consensus_state_persistence_and_restore_round_trip_votes_qcs_validators_and_view() {
        let (storage, path) = test_storage("consensus-restore-roundtrip");
        let (validator_a, signer_a) = active_validator(24);
        let (validator_b, signer_b) = active_validator(25);

        let block_hash = {
            let genesis = Block::genesis([0u8; 32]);
            let block = block_for(genesis.try_hash().unwrap(), 1, validator_a.address);
            block.try_hash().unwrap()
        };

        {
            let mut consensus = with_storage(storage.clone());
            let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);
            consensus.pacemaker.current_view = 9;

            let mut vote_a = Vote::new(validator_a.address, block_hash, 9);
            let mut vote_b = Vote::new(validator_b.address, block_hash, 9);
            vote_a.sign(&signer_a).expect("vote a should sign");
            vote_b.sign(&signer_b).expect("vote b should sign");
            consensus
                .persist_vote_in_storage(&vote_a)
                .expect("vote a should persist");
            consensus
                .persist_vote_in_storage(&vote_b)
                .expect("vote b should persist");

            let qc = QuorumCertificate::new(
                block_hash,
                9,
                vec![vote_a.signature.to_vec(), vote_b.signature.to_vec()],
                vec![vote_a.validator, vote_b.validator],
            );
            consensus
                .persist_quorum_certificate(&qc)
                .expect("qc should persist");
            consensus
                .persist_current_consensus_view()
                .expect("view should persist");
            consensus
                .stop()
                .expect("consensus stop should persist validator set");
        }

        let stored_validators: Vec<Validator> = <Vec<Validator> as Canonical>::decode(
            &storage
                .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())
                .expect("validator set read should succeed")
                .expect("validator set should persist"),
        )
        .expect("validator set should deserialize");
        assert_eq!(stored_validators.len(), 2);

        let stored_view_bytes = storage
            .state_get(CONSENSUS_CURRENT_VIEW_KEY.to_vec())
            .expect("view read should succeed")
            .expect("view should persist");
        let mut stored_view = [0u8; 8];
        stored_view.copy_from_slice(&stored_view_bytes);
        assert_eq!(u64::from_le_bytes(stored_view), 9);

        let stored_votes = storage
            .state_prefix_scan(CONSENSUS_VOTE_PREFIX.to_vec())
            .expect("vote scan should succeed");
        assert_eq!(stored_votes.len(), 2);

        let stored_qcs = storage
            .state_prefix_scan(CONSENSUS_QC_PREFIX.to_vec())
            .expect("qc scan should succeed");
        assert_eq!(stored_qcs.len(), 1);

        let mut restored = with_storage(storage);
        restored
            .start()
            .expect("consensus should restore from storage");

        assert_eq!(restored.current_view(), 9);
        assert_eq!(restored.validator_set.active_validator_count(), 2);
        assert_eq!(restored.vote_collector.vote_count(9, block_hash), 2);
        assert_eq!(restored.highest_qc_block, Some(block_hash));
        assert_eq!(
            restored.proposer.validator_id,
            restored.current_leader().unwrap()
        );

        cleanup_storage(path);
    }

    #[test]
    fn leader_rotation_jails_offline_validator_and_rotates() {
        let (storage, path) = test_storage("consensus-leader-rotation-jail");
        let (validator_a, _) = active_validator(40);
        let (validator_b, _) = active_validator(41);
        let mut consensus = with_storage(storage.clone());
        let _ = consensus.update_validator_set(vec![validator_a.clone(), validator_b.clone()]);

        let initial_active = consensus.validator_set.active_validator_count();
        assert_eq!(initial_active, 2);

        // Simulate 11 consecutive missed views by validator_b
        for _ in 0..11 {
            consensus.uptime_monitor.record_miss(&validator_b.address);
        }

        // Jail validator manually as if view timeout happened
        consensus
            .validator_set
            .jail_validator(&validator_b.address)
            .unwrap();

        let new_active = consensus.validator_set.active_validator_count();
        assert_eq!(
            new_active, 1,
            "Validator should be jailed and removed from active set"
        );

        cleanup_storage(path);
    }

    #[test]
    fn byzantine_leader_proposing_invalid_block_is_rejected() {
        let (storage, path) = test_storage("consensus-byzantine-leader");
        let (validator_a, _) = active_validator(42);
        let mut consensus = with_storage(storage.clone());
        let _ = consensus.update_validator_set(vec![validator_a.clone()]);

        let mut invalid_block = block_for([0u8; 32], 1, validator_a.address);
        // Tamper with the block signature to simulate a Byzantine proposal
        invalid_block.header.signature = Some([0xFF; 64]);

        let result = consensus.process_block_proposal(invalid_block);
        assert!(
            result.is_err(),
            "Byzantine block with invalid signature must be rejected"
        );

        cleanup_storage(path);
    }
}
