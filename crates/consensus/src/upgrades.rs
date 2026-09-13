use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, BlockHeight};
use tracing::info;

/// Represents a distinct protocol version for the SXIAUM network.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ProtocolVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns the current mainnet protocol version.
    pub fn mainnet() -> Self {
        Self::new(1, 0, 0)
    }

    /// Parse a `major.minor.patch` version string.
    pub fn parse(version: &str) -> Result<Self> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            bail!(
                "invalid protocol version '{}': expected 'major.minor.patch'",
                version
            );
        }
        let major = parts[0]
            .trim()
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("invalid major version '{}': {}", parts[0], e))?;
        let minor = parts[1]
            .trim()
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("invalid minor version '{}': {}", parts[1], e))?;
        let patch = parts[2]
            .trim()
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("invalid patch version '{}': {}", parts[2], e))?;
        Ok(Self::new(major, minor, patch))
    }
}

/// Maximum number of blocks that an unscheduled upgrade proposal can be
/// pending before it expires. Prevents stale proposals from accumulating
/// indefinitely. SCHEDULED upgrades never expire (see `prune_expired_proposals`).
pub const MAX_UPGRADE_PROPOSAL_AGE: u64 = 1_000_000;

/// Storage key under which the upgrade manager state is persisted.
const UPGRADES_STATE_KEY: &[u8] = b"consensus:upgrade_manager";

/// A formal proposal for a network-wide protocol upgrade (hard fork).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpgradeProposal {
    pub name: String,
    pub target_version: ProtocolVersion,
    pub activation_height: BlockHeight,
    pub description: String,
    pub votes: u64,
    /// Block height at which the proposal was submitted.
    pub submitted_at_height: BlockHeight,
    /// Whether the upgrade reached quorum and has been formally scheduled.
    #[serde(default)]
    pub scheduled: bool,
    /// Identities of validators that have voted. SECURITY (C-05): votes are
    /// per-validator and deduplicated — one address may vote at most once.
    #[serde(default)]
    pub voters: Vec<[u8; 32]>,
}

/// Manages the governance and scheduling of network upgrades.
///
/// SECURITY (C-05): the full proposal state is persisted to storage on every
/// mutation and restored on construction, so a node restart can never drop a
/// scheduled hard fork (which would split the chain between restarted and
/// non-restarted nodes).
pub struct UpgradeManager {
    current_version: ProtocolVersion,
    pending_upgrades: Vec<UpgradeProposal>,
    /// Backing store for crash-safe persistence. `None` only in tests.
    storage: Option<Arc<StorageEngine>>,
}

impl UpgradeManager {
    pub fn new(initial_version: ProtocolVersion) -> Self {
        Self {
            current_version: initial_version,
            pending_upgrades: Vec::new(),
            storage: None,
        }
    }

    /// Storage-backed constructor: restores persisted proposals so scheduled
    /// upgrades survive restarts. Fail-closed: a corrupt upgrade record
    /// aborts startup rather than silently continuing without the fork.
    pub fn with_storage(initial_version: ProtocolVersion, storage: Arc<StorageEngine>) -> Self {
        let mut manager = Self::new(initial_version);
        manager.storage = Some(storage);
        if let Err(error) = manager.reload_from_storage() {
            // A corrupt upgrade record is consensus-critical: proceeding
            // without a scheduled fork risks a permanent chain split.
            panic!("failed to restore upgrade manager state: {}", error);
        }
        manager
    }

    /// Re-read persisted proposals from storage into memory.
    fn reload_from_storage(&mut self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let Some(bytes) = storage.state_get(UPGRADES_STATE_KEY.to_vec())? else {
            return Ok(()); // nothing persisted yet
        };
        self.pending_upgrades = bincode::deserialize(&bytes)
            .map_err(|error| anyhow::anyhow!("corrupt persisted upgrade state: {}", error))?;
        Ok(())
    }

    /// Persist the full proposal set. Called after EVERY mutation.
    fn persist(&self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let bytes = bincode::serialize(&self.pending_upgrades)?;
        storage.state_put(UPGRADES_STATE_KEY.to_vec(), bytes)?;
        Ok(())
    }

    /// Submit a new upgrade proposal for validator voting.
    ///
    /// The activation height must be strictly greater than the current
    /// height to ensure nodes have time to upgrade before the fork activates.
    pub fn submit_proposal(
        &mut self,
        proposal: UpgradeProposal,
        current_height: BlockHeight,
    ) -> Result<()> {
        if proposal.activation_height <= current_height {
            bail!(
                "activation height {} must be greater than current height {}",
                proposal.activation_height,
                current_height
            );
        }

        if proposal.target_version <= self.current_version {
            bail!(
                "target version {:?} must be greater than current version {:?}",
                proposal.target_version,
                self.current_version
            );
        }

        // Reject duplicate names.
        if self
            .pending_upgrades
            .iter()
            .any(|p| p.name == proposal.name)
        {
            bail!(
                "upgrade proposal with name '{}' already exists",
                proposal.name
            );
        }

        let mut proposal = proposal;
        proposal.submitted_at_height = current_height;
        proposal.scheduled = false;
        proposal.voters.clear();
        proposal.votes = 0;
        self.pending_upgrades.push(proposal);
        self.persist()?;
        Ok(())
    }

    /// Record a validator's vote for a specific proposal.
    ///
    /// SECURITY (C-05): votes are attributed to a validator identity and
    /// deduplicated — a validator address can vote at most once per
    /// proposal. Anonymous additive voting allowed any caller to inflate
    /// the tally arbitrarily.
    pub fn record_vote(&mut self, proposal_name: &str, voter: Address, weight: u64) -> Result<()> {
        let proposal = self
            .pending_upgrades
            .iter_mut()
            .find(|p| p.name == proposal_name)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_name))?;

        if proposal.voters.contains(&voter.0) {
            bail!(
                "validator 0x{} has already voted on proposal '{}'",
                hex::encode(voter.0),
                proposal_name
            );
        }

        proposal.voters.push(voter.0);
        proposal.votes = proposal.votes.saturating_add(weight);
        self.persist()?;
        Ok(())
    }

    /// Checks if a protocol version change is active at the given height.
    /// Only scheduled/approved proposals can activate.
    pub fn get_active_version(&self, height: BlockHeight) -> ProtocolVersion {
        let mut version = self.current_version;
        for p in &self.pending_upgrades {
            if p.scheduled && height >= p.activation_height && p.target_version > version {
                version = p.target_version;
            }
        }
        version
    }

    /// Schedules an upgrade height once quorum is reached.
    ///
    /// SECURITY (C-05): the scheduled height must be strictly in the future
    /// relative to `current_height`; retroactive activation heights would
    /// make the fork boundary depend on when a node learned of the upgrade.
    pub fn schedule_upgrade(
        &mut self,
        proposal_name: &str,
        height: BlockHeight,
        quorum_threshold: u64,
        current_height: BlockHeight,
    ) -> Result<()> {
        if height <= current_height {
            bail!(
                "scheduled activation height {} must be greater than current height {}",
                height,
                current_height
            );
        }

        let proposal = self
            .pending_upgrades
            .iter_mut()
            .find(|p| p.name == proposal_name)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_name))?;

        if proposal.votes < quorum_threshold {
            bail!(
                "Proposal has not reached the required quorum threshold (votes: {}, threshold: {})",
                proposal.votes,
                quorum_threshold
            );
        }

        proposal.activation_height = height;
        proposal.scheduled = true;
        self.persist()?;
        Ok(())
    }

    /// SECURITY (H-14): apply a SoftwareUpgrade decision that has ALREADY
    /// passed the on-chain governance tally and time-lock.
    ///
    /// Previously governance "execution" was a status flip only — approved
    /// SoftwareUpgrade proposals never reached this manager, leaving two
    /// disconnected vote ledgers and no activation hook. Governance voting,
    /// quorum, and the time-lock are authoritative here; this method only
    /// re-validates the consensus-critical invariants (future activation
    /// height, strictly increasing version, no duplicate name) before marking
    /// the upgrade scheduled so `get_active_version` flips at the fork block.
    pub fn apply_governance_upgrade(
        &mut self,
        proposal_name: &str,
        target_version: ProtocolVersion,
        activation_height: BlockHeight,
        current_height: BlockHeight,
    ) -> Result<()> {
        if activation_height <= current_height {
            bail!(
                "governance upgrade '{}' activation height {} must be greater than current height {}",
                proposal_name,
                activation_height,
                current_height
            );
        }

        if target_version <= self.current_version {
            bail!(
                "governance upgrade '{}' target version {:?} must be greater than current version {:?}",
                proposal_name,
                target_version,
                self.current_version
            );
        }

        if self
            .pending_upgrades
            .iter()
            .any(|p| p.name == proposal_name)
        {
            bail!(
                "upgrade proposal with name '{}' already exists",
                proposal_name
            );
        }

        self.pending_upgrades.push(UpgradeProposal {
            name: proposal_name.to_string(),
            target_version,
            activation_height,
            description: "approved via on-chain governance".to_string(),
            votes: 0,
            submitted_at_height: current_height,
            scheduled: true,
            voters: Vec::new(),
        });
        self.persist()?;
        info!(
            "governance-approved upgrade '{}' to version {:?} scheduled for height {}",
            proposal_name, target_version, activation_height
        );
        Ok(())
    }

    /// Remove expired proposals that have exceeded the maximum pending age.
    ///
    /// SECURITY (C-05): SCHEDULED upgrades are never pruned. Dropping a
    /// scheduled hard fork on age would make restarted nodes disagree with
    /// non-restarted nodes about the active protocol version — a permanent
    /// chain split at the activation height.
    pub fn prune_expired_proposals(&mut self, current_height: BlockHeight) {
        self.pending_upgrades.retain(|p| {
            p.scheduled
                || current_height.saturating_sub(p.submitted_at_height) <= MAX_UPGRADE_PROPOSAL_AGE
        });
        // Retention-only change; persistence is best-effort here (a crash
        // before the next real mutation just re-prunes identically).
        let _ = self.persist();
    }

    /// Returns the current protocol version.
    pub fn current_version(&self) -> ProtocolVersion {
        self.current_version
    }

    /// Returns all pending upgrade proposals.
    pub fn pending_proposals(&self) -> &[UpgradeProposal] {
        &self.pending_upgrades
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(name: &str, activation: u64) -> UpgradeProposal {
        UpgradeProposal {
            name: name.into(),
            target_version: ProtocolVersion::new(2, 0, 0),
            activation_height: activation,
            description: "test".into(),
            votes: 0,
            submitted_at_height: 1_000,
            scheduled: false,
            voters: Vec::new(),
        }
    }

    #[test]
    fn upgrade_manager_proposal_and_activation() {
        let mut manager = UpgradeManager::new(ProtocolVersion::mainnet());
        manager
            .submit_proposal(proposal("v2-hardfork", 50_000), 1_000)
            .unwrap();
        assert_eq!(manager.pending_proposals().len(), 1);

        // Before reaching quorum and scheduling, reaching height must NOT activate
        assert_eq!(
            manager.get_active_version(50_000),
            ProtocolVersion::new(1, 0, 0)
        );

        manager
            .record_vote("v2-hardfork", Address([1u8; 32]), 75)
            .unwrap();
        manager
            .schedule_upgrade("v2-hardfork", 50_000, 67, 1_000)
            .unwrap();

        assert_eq!(
            manager.get_active_version(49_999),
            ProtocolVersion::new(1, 0, 0)
        );
        assert_eq!(
            manager.get_active_version(50_000),
            ProtocolVersion::new(2, 0, 0)
        );
        assert_eq!(
            manager.get_active_version(50_001),
            ProtocolVersion::new(2, 0, 0)
        );
    }

    #[test]
    fn unscheduled_proposal_does_not_activate() {
        let mut manager = UpgradeManager::new(ProtocolVersion::mainnet());
        manager
            .submit_proposal(proposal("malicious-fork", 2_000), 1_000)
            .unwrap();
        // Height passes activation_height, but proposal is not scheduled
        assert_eq!(
            manager.get_active_version(2_500),
            ProtocolVersion::new(1, 0, 0)
        );
    }

    #[test]
    fn double_voting_is_rejected() {
        let mut manager = UpgradeManager::new(ProtocolVersion::mainnet());
        manager
            .submit_proposal(proposal("v2", 50_000), 1_000)
            .unwrap();
        let voter = Address([4u8; 32]);
        manager.record_vote("v2", voter, 10).unwrap();
        assert!(manager.record_vote("v2", voter, 10).is_err());
        // Votes must not have been double-counted.
        assert_eq!(manager.pending_proposals()[0].votes, 10);
    }

    #[test]
    fn past_schedule_height_is_rejected() {
        let mut manager = UpgradeManager::new(ProtocolVersion::mainnet());
        manager
            .submit_proposal(proposal("v2", 50_000), 1_000)
            .unwrap();
        manager.record_vote("v2", Address([5u8; 32]), 100).unwrap();
        assert!(manager.schedule_upgrade("v2", 500, 67, 1_000).is_err());
        assert!(manager.schedule_upgrade("v2", 1_000, 67, 1_000).is_err());
        assert!(manager.schedule_upgrade("v2", 5_000, 67, 1_000).is_ok());
    }

    #[test]
    fn pruning_never_drops_scheduled_upgrades() {
        let mut manager = UpgradeManager::new(ProtocolVersion::mainnet());
        manager
            .submit_proposal(proposal("v2", 50_000), 1_000)
            .unwrap();
        manager.record_vote("v2", Address([6u8; 32]), 100).unwrap();
        manager.schedule_upgrade("v2", 50_000, 67, 1_000).unwrap();

        // Age far beyond MAX_UPGRADE_PROPOSAL_AGE.
        manager.prune_expired_proposals(1_000 + MAX_UPGRADE_PROPOSAL_AGE + 1);
        assert_eq!(
            manager.pending_proposals().len(),
            1,
            "scheduled upgrade must survive pruning"
        );
        assert_eq!(
            manager.get_active_version(50_000),
            ProtocolVersion::new(2, 0, 0)
        );
    }
}
