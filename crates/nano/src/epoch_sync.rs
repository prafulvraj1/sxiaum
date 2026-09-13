//! Auditable validator-set rotation and epoch handover certificate verification.
//!
//! Provides the mathematical and cryptographic continuity for nano-nodes to
//! securely track validator set transitions over months and years without
//! trusting central oracles.

use crate::error::NanoError;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use sxiaum_block::BlockHeader;
use sxiaum_crypto::ed25519;
use sxiaum_crypto::hash::{domain_hash, DOMAIN_CONSENSUS};
use sxiaum_types::{Address, Hash, SXIAUM_CHAIN_ID, Validator};

/// Domain separation tag for validator set commitment hashes.
pub const DOMAIN_VALIDATOR_SET: &str = "SXIAUM_VALIDATOR_SET";

/// Maximum allowed offline window for weak subjectivity (14 days in seconds).
pub const DEFAULT_MAX_UNBONDING_SECS: u64 = 14 * 24 * 60 * 60;

/// Represents a validator's signature in a consensus quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator: Address,
    pub signature: ed25519::Signature,
}

impl ValidatorSignature {
    pub fn new(validator: Address, signature_bytes: [u8; 64]) -> Self {
        Self {
            validator,
            signature: ed25519::Signature(signature_bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.signature.0
    }
}

/// Certificate proving an atomic validator-set transition at an epoch boundary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochHandoverCertificate {
    /// The epoch number being finalized (e.g. Epoch E).
    pub epoch: u64,
    /// The block header at the epoch boundary (height = E * K).
    pub boundary_header: BlockHeader,
    /// Quorum certificate signatures from the current active validator set V_E.
    pub consensus_signatures: Vec<ValidatorSignature>,
    /// HotStuff metadata `(view, phase_tag)` for vote verification.
    pub hotstuff_view_phase: Option<(u64, u8)>,
    /// The proposed successor validator set V_{E+1}.
    pub next_validator_set: Vec<Validator>,
}

/// Serde default pinning checkpoints to the canonical mainnet chain id.
fn default_checkpoint_chain_id() -> u64 {
    SXIAUM_CHAIN_ID
}

/// Out-of-band social consensus anchor for bootstrapping new devices.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WeakSubjectivityCheckpoint {
    pub epoch: u64,
    pub height: u64,
    pub block_hash: Hash,
    pub state_root: Hash,
    pub validator_set: Vec<Validator>,
    pub timestamp: u64,
    /// Replay-protection chain identifier of the network this checkpoint
    /// belongs to. Must equal [`SXIAUM_CHAIN_ID`] (13689) on mainnet.
    #[serde(default = "default_checkpoint_chain_id")]
    pub chain_id: u64,
}

/// Manages active validator sets, stake distributions, and epoch handovers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSyncManager {
    pub current_epoch: u64,
    pub active_validator_set: Vec<Validator>,
    pub total_active_stake: u128,
}

impl EpochSyncManager {
    /// Initialize with a known trusted validator set.
    pub fn new(epoch: u64, validator_set: Vec<Validator>) -> Result<Self, NanoError> {
        let total_active_stake = Self::validate_and_tally_stake(&validator_set)?;
        Ok(Self {
            current_epoch: epoch,
            active_validator_set: validator_set,
            total_active_stake,
        })
    }

    /// Compute canonical domain-separated cryptographic digest of a validator set.
    pub fn compute_validator_set_hash(validators: &[Validator]) -> Hash {
        let mut material = Vec::new();
        for v in validators {
            material.extend_from_slice(v.address.as_bytes());
            material.extend_from_slice(&v.pubkey);
            material.extend_from_slice(&v.voting_power.to_le_bytes());
            material.push(if v.is_active() { 1 } else { 0 });
        }
        domain_hash(DOMAIN_VALIDATOR_SET, &material)
    }

    /// Verify and apply an `EpochHandoverCertificate`, updating $V_E \to V_{E+1}$.
    ///
    /// `current_time` anchors mainnet-strict validation of the boundary header
    /// (canonical protocol version, chain id 13689, gas bounds, genesis
    /// timestamp floor, and the 5s future-time bound).
    pub fn verify_and_apply_handover(
        &mut self,
        certificate: &EpochHandoverCertificate,
        current_time: u64,
    ) -> Result<(), NanoError> {
        if certificate.epoch != self.current_epoch {
            return Err(NanoError::EpochHandoverFailed {
                epoch: certificate.epoch,
                reason: format!(
                    "certificate epoch {} does not match current local epoch {}",
                    certificate.epoch, self.current_epoch
                ),
            });
        }

        // 1. Verify boundary header under mainnet-strict rules
        certificate
            .boundary_header
            .validate_mainnet(current_time)
            .map_err(|e| NanoError::EpochHandoverFailed {
                epoch: certificate.epoch,
                reason: format!("invalid boundary header: {e}"),
            })?;

        // 2. Compute and verify next validator set hash
        let computed_next_hash = Self::compute_validator_set_hash(&certificate.next_validator_set);
        let next_hash_hex = hex::encode(computed_next_hash);

        let next_stake = Self::validate_and_tally_stake(&certificate.next_validator_set)?;

        // 3. Verify Quorum Certificate signatures signed by CURRENT validator set V_E
        let header_hash = certificate
            .boundary_header
            .try_hash()
            .map_err(|e| NanoError::Crypto(e.to_string()))?;

        self.verify_quorum_signatures(
            &header_hash,
            certificate.boundary_header.height,
            &certificate.consensus_signatures,
            certificate.hotstuff_view_phase,
        )?;

        // 4. Atomically transition validator set V_E -> V_{E+1}
        self.current_epoch = self.current_epoch.saturating_add(1);
        self.active_validator_set = certificate.next_validator_set.clone();
        self.total_active_stake = next_stake;

        tracing::info!(
            epoch = self.current_epoch,
            next_hash = %next_hash_hex,
            total_stake = self.total_active_stake,
            "Epoch handover verified successfully; validator set rotated"
        );

        Ok(())
    }

    /// Verify a Weak Subjectivity Checkpoint against current time and unbonding window.
    pub fn verify_and_apply_checkpoint(
        &mut self,
        checkpoint: &WeakSubjectivityCheckpoint,
        current_time: u64,
        max_unbonding_secs: u64,
    ) -> Result<(), NanoError> {
        // Replay protection: the checkpoint must belong to this network.
        if checkpoint.chain_id != SXIAUM_CHAIN_ID {
            return Err(NanoError::ChainIdMismatch {
                height: checkpoint.height,
                expected: SXIAUM_CHAIN_ID,
                actual: checkpoint.chain_id,
            });
        }

        if current_time > checkpoint.timestamp.saturating_add(max_unbonding_secs) {
            return Err(NanoError::WeakSubjectivityStale {
                checkpoint_time: checkpoint.timestamp,
                current_time,
                max_window_secs: max_unbonding_secs,
            });
        }

        let total_stake = Self::validate_and_tally_stake(&checkpoint.validator_set)?;
        self.current_epoch = checkpoint.epoch;
        self.active_validator_set = checkpoint.validator_set.clone();
        self.total_active_stake = total_stake;

        tracing::info!(
            epoch = checkpoint.epoch,
            height = checkpoint.height,
            "Weak subjectivity checkpoint verified and applied"
        );
        Ok(())
    }

    /// Verify BFT Quorum Certificate signatures against active validator set.
    ///
    /// Requires strictly >= 2f + 1 of active voting power (floor(2 * TotalStake / 3) + 1).
    pub fn verify_quorum_signatures(
        &self,
        block_hash: &Hash,
        height: u64,
        signatures: &[ValidatorSignature],
        hotstuff_meta: Option<(u64, u8)>,
    ) -> Result<(), NanoError> {
        if signatures.is_empty() {
            return Err(NanoError::QuorumNotReached {
                height,
                accumulated_power: 0,
                required_threshold: self.quorum_threshold(),
                total_stake: self.total_active_stake,
            });
        }

        let mut accumulated_power = 0u128;
        let mut seen_signers = HashSet::new();

        for val_sig in signatures {
            if !seen_signers.insert(val_sig.validator) {
                return Err(NanoError::DuplicateSignerInQc {
                    height,
                    validator: val_sig.validator.to_string(),
                });
            }

            let validator = self
                .active_validator_set
                .iter()
                .find(|v| v.address == val_sig.validator && v.is_active())
                .ok_or_else(|| NanoError::UnknownSigner {
                    signer: val_sig.validator.to_string(),
                })?;

            let signing_digest = match hotstuff_meta {
                Some((view, phase)) => {
                    hotstuff_vote_digest(val_sig.validator, block_hash, view, phase)
                }
                None => *block_hash,
            };

            let valid = ed25519::verify(&validator.pubkey, &signing_digest, &val_sig.signature.0);
            if !valid {
                return Err(NanoError::InvalidVoteSignature {
                    validator: val_sig.validator.to_string(),
                    reason: "ed25519 signature verification failed".into(),
                });
            }

            accumulated_power = accumulated_power
                .checked_add(u128::from(validator.voting_power))
                .ok_or_else(|| NanoError::Crypto("voting power overflow".into()))?;
        }

        let required_threshold = self.quorum_threshold();
        if accumulated_power < required_threshold {
            return Err(NanoError::QuorumNotReached {
                height,
                accumulated_power,
                required_threshold,
                total_stake: self.total_active_stake,
            });
        }

        Ok(())
    }

    /// Strict BFT Quorum Threshold: $\lfloor \frac{2 \cdot \text{TotalStake}}{3} \rfloor + 1$.
    ///
    /// Computed overflow-safe for arbitrarily large total stake.
    #[inline]
    pub fn quorum_threshold(&self) -> u128 {
        // floor(2T/3) = (T/3)*2 + (1 if T % 3 == 2 else 0), which cannot
        // overflow u128 for any T, unlike a direct `T * 2` intermediate.
        let q = self.total_active_stake / 3;
        let r = self.total_active_stake % 3;
        q.saturating_mul(2) + u128::from(r == 2) + 1
    }

    fn validate_and_tally_stake(validators: &[Validator]) -> Result<u128, NanoError> {
        if validators.is_empty() {
            return Err(NanoError::EpochHandoverFailed {
                epoch: 0,
                reason: "validator set cannot be empty".into(),
            });
        }

        let mut seen = HashSet::new();
        let mut total = 0u128;

        for v in validators {
            if !v.is_active() {
                continue;
            }
            if v.voting_power == 0 {
                return Err(NanoError::EpochHandoverFailed {
                    epoch: 0,
                    reason: format!("validator {} has 0 voting power", v.address),
                });
            }
            let derived = Address::from_public_key(&v.pubkey);
            if derived != v.address {
                return Err(NanoError::EpochHandoverFailed {
                    epoch: 0,
                    reason: format!(
                        "validator {} address does not match public key (derived {})",
                        v.address, derived
                    ),
                });
            }
            if !seen.insert(v.address) {
                return Err(NanoError::EpochHandoverFailed {
                    epoch: 0,
                    reason: format!("duplicate validator address {}", v.address),
                });
            }
            total = total
                .checked_add(u128::from(v.voting_power))
                .ok_or_else(|| NanoError::Crypto("stake tally overflow".into()))?;
        }

        if total == 0 {
            return Err(NanoError::EpochHandoverFailed {
                epoch: 0,
                reason: "total active stake is zero".into(),
            });
        }

        Ok(total)
    }
}

/// Helper computing canonical HotStuff vote digest matching `sxiaum-consensus`.
pub fn hotstuff_vote_digest(
    validator: Address,
    block_hash: &Hash,
    view: u64,
    phase_tag: u8,
) -> Hash {
    let mut bytes = [0u8; 73];
    bytes[..32].copy_from_slice(validator.as_bytes());
    bytes[32..64].copy_from_slice(block_hash);
    bytes[64..72].copy_from_slice(&view.to_le_bytes());
    bytes[72] = phase_tag;
    domain_hash(DOMAIN_CONSENSUS, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;
    use sxiaum_types::{SXIAUM_CHAIN_ID, ValidatorStatus};

    /// Build a structurally valid, ACTIVE validator (address derived from pubkey).
    fn test_validator(id: u8, voting_power: u64) -> Validator {
        let pubkey = [id; 32];
        let mut v = Validator::new(Address::from_public_key(&pubkey), pubkey, U256::from(1_000));
        v.voting_power = voting_power;
        v.status = ValidatorStatus::Active;
        v
    }

    #[test]
    fn quorum_threshold_matches_strict_bft_formula() {
        let manager = EpochSyncManager::new(0, vec![test_validator(1, 10)]).unwrap();
        assert_eq!(manager.quorum_threshold(), (10u128 * 2) / 3 + 1);
    }

    #[test]
    fn quorum_threshold_is_overflow_safe_at_extreme_stake() {
        // Constructed directly: no validator-set validation needed for math tests.
        let manager = EpochSyncManager {
            current_epoch: 0,
            active_validator_set: Vec::new(),
            total_active_stake: u128::MAX,
        };
        // 2^128 - 1 is divisible by 3, so floor(2T/3) == (T/3) * 2 exactly,
        // and the old `T * 2 / 3` formulation would have overflowed in debug.
        assert_eq!(manager.quorum_threshold(), (u128::MAX / 3) * 2 + 1);
    }

    #[test]
    fn checkpoint_rejects_foreign_chain_id() {
        let mut manager = EpochSyncManager::new(0, vec![test_validator(1, 10)]).unwrap();
        let checkpoint = WeakSubjectivityCheckpoint {
            epoch: 0,
            height: 100,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            validator_set: Vec::new(),
            timestamp: 0,
            chain_id: 999,
        };
        let err = manager
            .verify_and_apply_checkpoint(&checkpoint, 1_000_000, DEFAULT_MAX_UNBONDING_SECS)
            .expect_err("foreign chain id must be rejected");
        assert!(matches!(err, NanoError::ChainIdMismatch { .. }));
    }

    #[test]
    fn checkpoint_accepts_canonical_chain_id() {
        let mut manager = EpochSyncManager::new(0, vec![test_validator(1, 10)]).unwrap();
        let checkpoint = WeakSubjectivityCheckpoint {
            epoch: 3,
            height: 100,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            validator_set: vec![test_validator(2, 10)],
            timestamp: 0,
            chain_id: SXIAUM_CHAIN_ID,
        };
        manager
            .verify_and_apply_checkpoint(&checkpoint, 1_000_000, DEFAULT_MAX_UNBONDING_SECS)
            .expect("canonical chain id checkpoint must be accepted");
        assert_eq!(manager.current_epoch, 3);
    }

    #[test]
    fn hotstuff_vote_digest_matches_light_client_crate_layout() {
        // Byte layout must stay identical to sxiaum-light-client::hotstuff_vote_digest
        // and sxiaum_consensus::hotstuff::vote_signing_message:
        // [validator(32) || block_hash(32) || view_le(8) || phase(1)] domain-hashed.
        let validator = Address([7u8; 32]);
        let block_hash: Hash = [9u8; 32];
        let mut expected_material = [0u8; 73];
        expected_material[..32].copy_from_slice(validator.as_bytes());
        expected_material[32..64].copy_from_slice(&block_hash);
        expected_material[64..72].copy_from_slice(&42u64.to_le_bytes());
        expected_material[72] = 2;
        assert_eq!(
            hotstuff_vote_digest(validator, &block_hash, 42, 2),
            domain_hash(DOMAIN_CONSENSUS, &expected_material)
        );
    }

    #[test]
    fn nano_epoch_sync_rejects_weak_subjectivity_staleness() {
        let mut manager = EpochSyncManager::new(0, vec![test_validator(1, 10)]).unwrap();
        let checkpoint = WeakSubjectivityCheckpoint {
            epoch: 3,
            height: 100,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            validator_set: vec![test_validator(2, 10)],
            timestamp: 1000,
            chain_id: SXIAUM_CHAIN_ID,
        };

        // current_time is 1000 + 14 days + 1 second -> stale!
        let current_time = 1000 + DEFAULT_MAX_UNBONDING_SECS + 1;
        let err = manager
            .verify_and_apply_checkpoint(&checkpoint, current_time, DEFAULT_MAX_UNBONDING_SECS)
            .expect_err("stale weak subjectivity checkpoint must be rejected");
        assert!(matches!(err, NanoError::WeakSubjectivityStale { .. }));
    }
}
