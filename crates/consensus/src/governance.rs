use anyhow::{bail, Result};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sxiaum_types::{Address, BlockHeight};

/// Minimum deposit (in smallest units) required to submit a governance
/// proposal on mainnet.  This prevents spam proposals.
pub const MIN_PROPOSAL_DEPOSIT: u64 = 1_000_000_000;

/// Time-lock duration in blocks for parameter changes and software upgrades.
/// At a 2-second block interval, this is approximately 24 hours.
pub const GOVERNANCE_TIME_LOCK_BLOCKS: u64 = 43_200;

/// Types of governance proposals supported by SXIAUM.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalType {
    ParameterChange {
        key: String,
        value: String,
    },
    TextProposal {
        description: String,
    },
    SoftwareUpgrade {
        version: String,
        height: BlockHeight,
    },
    CommunityFundSpend {
        recipient: Address,
        amount: U256,
    },
    AddValidator {
        validator: sxiaum_types::Validator,
    },
    RemoveValidator {
        address: Address,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, std::hash::Hash)]
pub enum VoteOption {
    Yes,
    No,
    Abstain,
    NoWithVeto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proposal {
    pub id: u64,
    pub title: String,
    pub proposal_type: ProposalType,
    pub status: ProposalStatus,
    pub submit_time: u64,
    pub voting_start_height: BlockHeight,
    pub voting_end_height: BlockHeight,
    pub total_votes: HashMap<VoteOption, U256>,
    pub execution_height: Option<BlockHeight>,
    /// Deposit locked when the proposal was submitted.
    pub deposit: U256,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    DepositPeriod,
    VotingPeriod,
    Passed,
    TimeLocked,
    Rejected,
    Failed,
    Executed,
}

pub struct GovernanceManager {
    proposals: HashMap<u64, Proposal>,
    votes: HashMap<(u64, Address), (VoteOption, U256)>,
    next_id: u64,
}

#[derive(Serialize, Deserialize)]
struct GovernanceState {
    proposals: HashMap<u64, Proposal>,
    votes: Vec<((u64, Address), (VoteOption, U256))>,
    next_id: u64,
}

impl Default for GovernanceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceManager {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            votes: HashMap::new(),
            next_id: 1,
        }
    }

    /// Submit a new governance proposal to the network.
    ///
    /// Uses the minimum mainnet deposit; see [`Self::submit_proposal_with_deposit`].
    pub fn submit_proposal(
        &mut self,
        title: String,
        p_type: ProposalType,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<u64> {
        self.submit_proposal_with_deposit(
            title,
            p_type,
            start,
            end,
            U256::from(MIN_PROPOSAL_DEPOSIT),
        )
    }

    /// Submit a governance proposal with a custom deposit amount.
    /// The deposit must meet the minimum requirement.
    pub fn submit_proposal_with_deposit(
        &mut self,
        title: String,
        p_type: ProposalType,
        start: BlockHeight,
        end: BlockHeight,
        deposit: U256,
    ) -> Result<u64> {
        if end <= start {
            bail!(
                "voting end height {} must be greater than start height {}",
                end,
                start
            );
        }
        if deposit < U256::from(MIN_PROPOSAL_DEPOSIT) {
            bail!(
                "proposal deposit {} below minimum {}",
                deposit,
                MIN_PROPOSAL_DEPOSIT
            );
        }

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let proposal = Proposal {
            id,
            title,
            proposal_type: p_type,
            status: ProposalStatus::VotingPeriod,
            submit_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            voting_start_height: start,
            voting_end_height: end,
            total_votes: HashMap::new(),
            execution_height: None,
            deposit,
        };

        self.proposals.insert(id, proposal);
        Ok(id)
    }

    /// Cast a vote on an active proposal at the given chain height.
    ///
    /// `current_height` must fall inside the proposal's voting window
    /// (`voting_start_height <= current_height <= voting_end_height`); votes
    /// outside the window are rejected so tallies cannot be manipulated by
    /// late or premature vote injection.
    ///
    /// voting_power should be calculated by the caller (via StakingManager).
    pub fn cast_vote(
        &mut self,
        proposal_id: u64,
        voter: Address,
        option: VoteOption,
        power: U256,
        current_height: BlockHeight,
    ) -> Result<()> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

        if proposal.status != ProposalStatus::VotingPeriod {
            bail!("Proposal is not in voting period");
        }

        if current_height < proposal.voting_start_height
            || current_height > proposal.voting_end_height
        {
            bail!(
                "voting window closed for proposal {}: active between heights {} and {} (current {})",
                proposal_id,
                proposal.voting_start_height,
                proposal.voting_end_height,
                current_height
            );
        }

        // Handle double voting by removing previous weight if any.
        if let Some((previous_option, previous_power)) = self.votes.get(&(proposal_id, voter)) {
            let weight = proposal
                .total_votes
                .entry(previous_option.clone())
                .or_insert(U256::zero());
            *weight = weight.saturating_sub(*previous_power);
        }

        self.votes
            .insert((proposal_id, voter), (option.clone(), power));
        let weight = proposal.total_votes.entry(option).or_insert(U256::zero());
        *weight = weight.saturating_add(power);

        Ok(())
    }

    /// Tally the votes and determine the outcome of a proposal using floating-point threshold.
    /// Delegates to `tally_proposal_bps` to ensure deterministic integer math across nodes.
    pub fn tally_proposal(
        &mut self,
        proposal_id: u64,
        quorum: U256,
        pass_threshold: f64,
        current_height: BlockHeight,
    ) -> Result<ProposalStatus> {
        let pass_threshold_bps = if pass_threshold <= 0.0 {
            0u64
        } else if pass_threshold >= 1.0 {
            10_000u64
        } else {
            (pass_threshold * 10_000.0).round() as u64
        };
        self.tally_proposal_bps(proposal_id, quorum, pass_threshold_bps, current_height)
    }

    /// Deterministic tally calculation using basis points (10_000 bps = 100%) and pure U256 arithmetic.
    pub fn tally_proposal_bps(
        &mut self,
        proposal_id: u64,
        quorum: U256,
        pass_threshold_bps: u64,
        current_height: BlockHeight,
    ) -> Result<ProposalStatus> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| anyhow::anyhow!("Proposal not found: {}", proposal_id))?;

        let total_power = proposal
            .total_votes
            .values()
            .fold(U256::zero(), |acc, x| acc.saturating_add(*x));
        if total_power < quorum || total_power.is_zero() {
            proposal.status = ProposalStatus::Failed;
            return Ok(ProposalStatus::Failed);
        }

        let yes_votes = proposal
            .total_votes
            .get(&VoteOption::Yes)
            .cloned()
            .unwrap_or(U256::zero());

        // Deterministic integer cross-multiplication: yes_votes * 10_000 >= total_power * pass_threshold_bps
        let passed = yes_votes.saturating_mul(U256::from(10_000))
            >= total_power.saturating_mul(U256::from(pass_threshold_bps));

        if passed {
            // Apply time-lock for execution using mainnet block interval constant.
            match proposal.proposal_type {
                ProposalType::ParameterChange { .. } | ProposalType::SoftwareUpgrade { .. } => {
                    proposal.status = ProposalStatus::TimeLocked;
                    proposal.execution_height =
                        Some(current_height.saturating_add(GOVERNANCE_TIME_LOCK_BLOCKS));
                }
                _ => {
                    proposal.status = ProposalStatus::Passed;
                }
            }
        } else {
            proposal.status = ProposalStatus::Rejected;
        }

        Ok(proposal.status)
    }

    /// Execute time-locked proposals that have reached their execution height.
    pub fn execute_time_locked_proposals(&mut self, current_height: BlockHeight) -> Vec<Proposal> {
        let mut executed = Vec::new();
        for proposal in self.proposals.values_mut() {
            if proposal.status == ProposalStatus::TimeLocked {
                if let Some(exec_height) = proposal.execution_height {
                    if current_height >= exec_height {
                        proposal.status = ProposalStatus::Executed;
                        executed.push(proposal.clone());
                    }
                }
            }
        }
        executed
    }

    /// Returns the current state of a proposal for explorer and RPC.
    pub fn get_proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    pub fn get_and_mark_passed_proposals(&mut self) -> Vec<Proposal> {
        let mut passed = Vec::new();
        for proposal in self.proposals.values_mut() {
            if proposal.status == ProposalStatus::Passed {
                proposal.status = ProposalStatus::Executed;
                passed.push(proposal.clone());
            }
        }
        passed
    }

    /// Load the governance state from persistent storage.
    pub fn load_from_storage(&mut self, storage: &sxiaum_storage::StorageEngine) -> Result<()> {
        if let Some(bytes) = storage.get_metadata("governance_state")? {
            let state: GovernanceState =
                <GovernanceState as sxiaum_types::Canonical>::decode(&bytes)
                    .or_else(|_| bincode::deserialize(&bytes))?;
            self.proposals = state.proposals;
            self.votes = state.votes.into_iter().collect();
            self.next_id = state.next_id;
            tracing::info!(
                "Loaded governance state: {} proposals, {} votes",
                self.proposals.len(),
                self.votes.len()
            );
        }
        Ok(())
    }

    /// Save the current governance state to persistent storage.
    pub fn save_to_storage(&self, storage: &sxiaum_storage::StorageEngine) -> Result<()> {
        let state = GovernanceState {
            proposals: self.proposals.clone(),
            votes: self.votes.clone().into_iter().collect(),
            next_id: self.next_id,
        };
        let bytes = <GovernanceState as sxiaum_types::Canonical>::try_encode(&state)?;
        storage.put_metadata("governance_state", &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sxiaum_types::Address;

    #[test]
    fn governance_lifecycle_and_time_lock() {
        let mut gov = GovernanceManager::new();
        let id = gov
            .submit_proposal(
                "Upgrade".into(),
                ProposalType::SoftwareUpgrade {
                    version: "2.0.0".into(),
                    height: 100_000,
                },
                1,
                100,
            )
            .unwrap();

        let voter1 = Address([1u8; 32]);
        gov.cast_vote(id, voter1, VoteOption::Yes, U256::from(100_000), 50)
            .unwrap();

        // Votes outside the voting window must be rejected.
        assert!(gov
            .cast_vote(id, Address([9u8; 32]), VoteOption::No, U256::from(1), 101)
            .is_err());
        assert!(gov
            .cast_vote(id, Address([9u8; 32]), VoteOption::No, U256::from(1), 0)
            .is_err());

        let status = gov
            .tally_proposal(id, U256::from(50_000), 0.5, 100)
            .unwrap();
        assert_eq!(status, ProposalStatus::TimeLocked);

        let proposal = gov.get_proposal(id).unwrap();
        assert_eq!(
            proposal.execution_height,
            Some(100 + GOVERNANCE_TIME_LOCK_BLOCKS)
        );

        // Before execution height
        assert!(gov.execute_time_locked_proposals(100).is_empty());

        // At execution height
        let executed = gov.execute_time_locked_proposals(100 + GOVERNANCE_TIME_LOCK_BLOCKS);
        assert_eq!(executed.len(), 1);
        assert_eq!(executed[0].id, id);
        assert_eq!(executed[0].status, ProposalStatus::Executed);
    }

    #[test]
    fn deterministic_tally_with_large_u256_power() {
        let mut gov = GovernanceManager::new();
        let id = gov
            .submit_proposal_with_deposit(
                "BigStake".into(),
                ProposalType::TextProposal {
                    description: "test".into(),
                },
                10,
                50,
                U256::from(MIN_PROPOSAL_DEPOSIT),
            )
            .unwrap();

        // 10^30 power (> u128::MAX)
        let huge_power = U256::from(10u64.pow(18)) * U256::from(10u64.pow(18));
        let voter = Address([2u8; 32]);
        gov.cast_vote(id, voter, VoteOption::Yes, huge_power, 20)
            .unwrap();

        let status = gov
            .tally_proposal_bps(id, huge_power / 2, 6000, 50)
            .unwrap();
        assert_eq!(status, ProposalStatus::Passed);

        // Invalid height ordering is rejected
        assert!(gov
            .submit_proposal_with_deposit(
                "BadOrder".into(),
                ProposalType::TextProposal {
                    description: "test".into(),
                },
                100,
                50,
                U256::from(MIN_PROPOSAL_DEPOSIT),
            )
            .is_err());
    }

    #[test]
    fn vote_change_with_decreased_power_preserves_exact_tally() {
        let mut gov = GovernanceManager::new();
        let id = gov
            .submit_proposal(
                "VoteChange".into(),
                ProposalType::TextProposal {
                    description: "test".into(),
                },
                1,
                100,
            )
            .unwrap();

        let voter = Address([7u8; 32]);
        // Initial vote: 200 power for Yes
        gov.cast_vote(id, voter, VoteOption::Yes, U256::from(200), 10)
            .unwrap();

        let proposal = gov.get_proposal(id).unwrap();
        assert_eq!(
            *proposal.total_votes.get(&VoteOption::Yes).unwrap(),
            U256::from(200)
        );

        // Voter changes vote to No after partially unstaking (power now 50)
        gov.cast_vote(id, voter, VoteOption::No, U256::from(50), 20)
            .unwrap();

        let proposal = gov.get_proposal(id).unwrap();
        // Yes must have exactly 0, not orphan residual 150
        assert_eq!(
            *proposal.total_votes.get(&VoteOption::Yes).unwrap(),
            U256::zero()
        );
        assert_eq!(
            *proposal.total_votes.get(&VoteOption::No).unwrap(),
            U256::from(50)
        );
    }
}
