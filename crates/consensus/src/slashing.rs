use crate::governance::GovernanceManager;
use crate::hotstuff::vote::Vote;
use crate::pos::staking::StakingManager;
use crate::pos::validator_set::ValidatorSet;
use anyhow::{anyhow, bail, Result};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Canonical, Validator};
use tracing::{info, warn};

// - custom serde for [u8; 64] -

mod serde_sig64 {
    use serde::{de::Error, Deserializer, Serializer};
    pub fn serialize<S>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(sig.as_slice())
    }
    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        v.try_into().map_err(|_| Error::custom("expected 64 bytes"))
    }
}

// - storage keys -

const SLASHING_EVENT_PREFIX: &[u8] = b"slashing:event:";
const SLASHING_HISTORY_PREFIX: &[u8] = b"slashing:history:";
const COOLDOWN_PREFIX: &[u8] = b"slashing:cooldown:";
const EVIDENCE_EXECUTED_PREFIX: &[u8] = b"slashing:executed:";

/// Maximum age (in blocks) of evidence before it expires and cannot be
/// used for slashing. Prevents indefinite accumulation of stale evidence.
pub const EVIDENCE_EXPIRY_BLOCKS: u64 = 10_000;

// - item 1: Misbehavior enum -

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Misbehavior {
    /// item 2: validator signed two different blocks in the same view and phase.
    DoubleVote {
        view: u64,
        vote_a: Vote,
        vote_b: Vote,
    },
    /// item 3: validator proposed two different blocks in the same view.
    DoubleProposal {
        view: u64,
        proposer: Address,
        proposal_a: Vec<u8>,
        proposal_b: Vec<u8>,
    },
    /// item 4: validator submitted a vote with an invalid signature.
    InvalidSignature { vote: Vote, reason: String },
}

impl Misbehavior {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DoubleVote { .. } => "DoubleVote",
            Self::DoubleProposal { .. } => "DoubleProposal",
            Self::InvalidSignature { .. } => "InvalidSignature",
        }
    }

    pub fn validator(&self) -> &Address {
        match self {
            Self::DoubleVote { vote_a, .. } => &vote_a.validator,
            Self::DoubleProposal { proposer, .. } => proposer,
            Self::InvalidSignature { vote, .. } => &vote.validator,
        }
    }

    /// SECURITY (H-08): cryptographic identity of the OFFENSE itself.
    ///
    /// Evidence IDs must bind the full offense payload (the equivocated
    /// votes/proposals), not just metadata. Previously IDs hashed
    /// (validator, kind, height, reporter), so two reporters filing the SAME
    /// double-vote produced two distinct IDs and `execute_slash` fired twice
    /// (2x stake extraction for one crime). The content hash uses
    /// length-framed canonical encodings so identical offenses always yield
    /// the same ID regardless of who reports it or when.
    pub fn content_hash(&self) -> [u8; 32] {
        fn framed(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"sxiaum:misbehavior:v1:");
        hasher.update(self.kind().as_bytes());
        match self {
            Misbehavior::DoubleVote {
                view,
                vote_a,
                vote_b,
            } => {
                hasher.update(view.to_le_bytes());
                framed(&mut hasher, &vote_a.encode());
                framed(&mut hasher, &vote_b.encode());
            }
            Misbehavior::DoubleProposal {
                view,
                proposal_a,
                proposal_b,
                ..
            } => {
                hasher.update(view.to_le_bytes());
                framed(&mut hasher, proposal_a);
                framed(&mut hasher, proposal_b);
            }
            Misbehavior::InvalidSignature { vote, reason } => {
                framed(&mut hasher, &vote.encode());
                framed(&mut hasher, reason.as_bytes());
            }
        }
        hasher.finalize().into()
    }
}

// - item 5: Evidence records -

#[derive(Clone, Debug)]
pub struct SelfDetectedEvidence {
    pub id: [u8; 32],
    pub validator: Address,
    pub misbehavior: Misbehavior,
    pub detected_at_height: u64,
}

impl SelfDetectedEvidence {
    pub(crate) fn new(
        validator: Address,
        misbehavior: Misbehavior,
        detected_at_height: u64,
    ) -> Self {
        let mut e = Self {
            id: [0u8; 32],
            validator,
            misbehavior,
            detected_at_height,
        };
        e.id = e.compute_id();
        e
    }

    fn compute_id(&self) -> [u8; 32] {
        // SECURITY (H-08): identity is the offense content only. Binding the
        // detection height here would let a replayed offense (re-detected
        // after a restart) mint a fresh ID and bypass the executed-evidence
        // replay guard.
        let mut hasher = Sha256::new();
        hasher.update(b"sxiaum:evidence:self-detected:v1:");
        hasher.update(self.misbehavior.content_hash());
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportedEvidence {
    pub id: [u8; 32],
    pub validator: Address,
    pub misbehavior: Misbehavior,
    pub reported_at_height: u64,
    pub reporter: Address,
    /// Reporter's signature over the evidence id.
    #[serde(with = "serde_sig64")]
    pub reporter_signature: [u8; 64],
}

impl ReportedEvidence {
    pub fn new(
        validator: Address,
        misbehavior: Misbehavior,
        reported_at_height: u64,
        reporter: Address,
        reporter_signature: [u8; 64],
    ) -> Result<Self> {
        if reporter == Address::zero() {
            bail!("reported evidence cannot have sentinel zero address as reporter");
        }
        let mut e = Self {
            id: [0u8; 32],
            validator,
            misbehavior,
            reported_at_height,
            reporter,
            reporter_signature,
        };
        e.id = e.compute_id();
        Ok(e)
    }

    fn compute_id(&self) -> [u8; 32] {
        // SECURITY (H-08): identity is the offense content only. Reporter and
        // reporting height are excluded so that N reporters filing the SAME
        // offense all derive the SAME evidence ID; the executed-evidence
        // replay guard in `execute_slash` then rejects every report after the
        // first instead of slashing once per reporter.
        let mut hasher = Sha256::new();
        hasher.update(b"sxiaum:evidence:reported:v1:");
        hasher.update(self.misbehavior.content_hash());
        hasher.finalize().into()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        <Self as Canonical>::try_encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let ev = <Self as Canonical>::decode(bytes).or_else(|_| bincode::deserialize(bytes))?;
        if ev.reporter == Address::zero() {
            bail!("decoded reported evidence has invalid zero reporter address");
        }
        Ok(ev)
    }
}

#[derive(Clone, Debug)]
pub enum EvidenceSource {
    SelfDetected(SelfDetectedEvidence),
    Reported(ReportedEvidence),
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub verified: bool,
}

impl Evidence {
    pub fn new(
        validator: Address,
        misbehavior: Misbehavior,
        reported_at_height: u64,
        reporter: Address,
        reporter_signature: [u8; 64],
    ) -> Result<Self> {
        Self::new_reported(
            validator,
            misbehavior,
            reported_at_height,
            reporter,
            reporter_signature,
        )
    }

    pub fn new_self_detected(
        validator: Address,
        misbehavior: Misbehavior,
        detected_at_height: u64,
    ) -> Self {
        Self {
            source: EvidenceSource::SelfDetected(SelfDetectedEvidence::new(
                validator,
                misbehavior,
                detected_at_height,
            )),
            verified: false,
        }
    }

    pub fn new_reported(
        validator: Address,
        misbehavior: Misbehavior,
        reported_at_height: u64,
        reporter: Address,
        reporter_signature: [u8; 64],
    ) -> Result<Self> {
        let reported = ReportedEvidence::new(
            validator,
            misbehavior,
            reported_at_height,
            reporter,
            reporter_signature,
        )?;
        Ok(Self {
            source: EvidenceSource::Reported(reported),
            verified: false,
        })
    }

    pub fn id(&self) -> [u8; 32] {
        match &self.source {
            EvidenceSource::SelfDetected(e) => e.id,
            EvidenceSource::Reported(e) => e.id,
        }
    }

    pub fn validator(&self) -> Address {
        match &self.source {
            EvidenceSource::SelfDetected(e) => e.validator,
            EvidenceSource::Reported(e) => e.validator,
        }
    }

    pub fn misbehavior(&self) -> &Misbehavior {
        match &self.source {
            EvidenceSource::SelfDetected(e) => &e.misbehavior,
            EvidenceSource::Reported(e) => &e.misbehavior,
        }
    }

    pub fn reported_at_height(&self) -> u64 {
        match &self.source {
            EvidenceSource::SelfDetected(e) => e.detected_at_height,
            EvidenceSource::Reported(e) => e.reported_at_height,
        }
    }

    pub fn reporter(&self) -> Option<Address> {
        match &self.source {
            EvidenceSource::SelfDetected(_) => None,
            EvidenceSource::Reported(e) => Some(e.reporter),
        }
    }
}

// - item 13 / 18: SlashingEvent (log + history) -

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub id: [u8; 32],
    pub validator: Address,
    pub misbehavior_kind: String,
    pub slash_amount: U256,
    pub burned_amount: U256,
    pub height: u64,
    pub timestamp: u64,
    pub evidence_id: [u8; 32],
}

impl SlashingEvent {
    fn new(evidence: &Evidence, slash_amount: U256, burned_amount: U256, height: u64) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut hasher = Sha256::new();
        hasher.update(evidence.id());
        hasher.update(height.to_le_bytes());
        let id: [u8; 32] = hasher.finalize().into();
        Self {
            id,
            validator: evidence.validator(),
            misbehavior_kind: evidence.misbehavior().kind().to_string(),
            slash_amount,
            burned_amount,
            height,
            timestamp: ts,
            evidence_id: evidence.id(),
        }
    }
}

// - Slashing config -

#[derive(Clone, Debug)]
pub struct SlashingConfig {
    /// Fraction of stake to slash on double-vote (in basis points, 10_000 = 100%).
    pub double_vote_slash_bps: u64,
    /// Fraction of stake to slash on double-proposal.
    pub double_proposal_slash_bps: u64,
    /// Fraction of stake to slash on invalid signature.
    pub invalid_sig_slash_bps: u64,
    /// Fraction of the slashed amount that is burned (rest may go to reporter).
    pub burn_fraction_bps: u64,
    /// Cooldown in blocks before a jailed validator may rejoin (item 17).
    pub cooldown_blocks: u64,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            double_vote_slash_bps: 500,     // 5%
            double_proposal_slash_bps: 200, // 2%
            invalid_sig_slash_bps: 100,     // 1%
            burn_fraction_bps: 8_000,       // 80% burned
            cooldown_blocks: 1_000,
        }
    }
}

// - RPC types (item 19) -

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEventRpc {
    pub id: String,
    pub validator: String,
    pub misbehavior: String,
    pub slash_amount: String,
    pub burned_amount: String,
    pub height: u64,
    pub timestamp: u64,
}

impl From<&SlashingEvent> for SlashingEventRpc {
    fn from(e: &SlashingEvent) -> Self {
        Self {
            id: hex::encode(e.id),
            validator: e.validator.to_string(),
            misbehavior: e.misbehavior_kind.clone(),
            slash_amount: e.slash_amount.to_string(),
            burned_amount: e.burned_amount.to_string(),
            height: e.height,
            timestamp: e.timestamp,
        }
    }
}

// - SlashingManager -

pub struct SlashingManager {
    pub config: SlashingConfig,
    storage: Arc<StorageEngine>,
    /// In-memory pending evidence pool (item 5).
    pub pending_evidence: HashMap<[u8; 32], Evidence>,
}

impl SlashingManager {
    pub fn new(config: SlashingConfig, storage: Arc<StorageEngine>) -> Self {
        Self {
            config,
            storage,
            pending_evidence: HashMap::new(),
        }
    }

    // - item 2: detect double vote -

    pub fn detect_double_vote(&self, existing: &Vote, incoming: &Vote) -> Option<Misbehavior> {
        if existing.view == incoming.view
            && existing.phase == incoming.phase
            && existing.validator == incoming.validator
            && existing.block_hash != incoming.block_hash
        {
            Some(Misbehavior::DoubleVote {
                view: existing.view,
                vote_a: existing.clone(),
                vote_b: incoming.clone(),
            })
        } else {
            None
        }
    }

    // - item 3: detect double proposal -

    pub fn detect_double_proposal(
        &self,
        view: u64,
        proposer: Address,
        existing_bytes: Vec<u8>,
        incoming_bytes: Vec<u8>,
    ) -> Option<Misbehavior> {
        // Different raw bytes at the same view = conflicting proposals.
        if existing_bytes != incoming_bytes {
            Some(Misbehavior::DoubleProposal {
                view,
                proposer,
                proposal_a: existing_bytes,
                proposal_b: incoming_bytes,
            })
        } else {
            None
        }
    }

    // - item 4: detect invalid signature -

    pub fn detect_invalid_signature(
        &self,
        vote: &Vote,
        validator: &Validator,
    ) -> Option<Misbehavior> {
        match vote.verify_signature(validator) {
            Ok(true) => None,
            Ok(false) => Some(Misbehavior::InvalidSignature {
                vote: vote.clone(),
                reason: "signature verification returned false".to_string(),
            }),
            Err(e) => Some(Misbehavior::InvalidSignature {
                vote: vote.clone(),
                reason: e.to_string(),
            }),
        }
    }

    // - item 5: record evidence -

    pub fn record_self_detected_evidence(
        &mut self,
        validator: Address,
        misbehavior: Misbehavior,
        detected_at_height: u64,
    ) -> Result<[u8; 32]> {
        let evidence = Evidence::new_self_detected(validator, misbehavior, detected_at_height);
        let id = evidence.id();
        self.pending_evidence.insert(id, evidence);
        Ok(id)
    }

    pub fn record_reported_evidence(&mut self, evidence: ReportedEvidence) -> Result<[u8; 32]> {
        let id = evidence.id;
        self.pending_evidence.insert(
            id,
            Evidence {
                source: EvidenceSource::Reported(evidence),
                verified: false,
            },
        );
        Ok(id)
    }

    pub fn record_evidence(
        &mut self,
        validator: Address,
        misbehavior: Misbehavior,
        reported_at_height: u64,
        reporter: Address,
        reporter_signature: [u8; 64],
    ) -> Result<[u8; 32]> {
        let evidence = Evidence::new_reported(
            validator,
            misbehavior,
            reported_at_height,
            reporter,
            reporter_signature,
        )?;
        let id = evidence.id();
        self.pending_evidence.insert(id, evidence);
        Ok(id)
    }

    // - item 6: broadcast slashing evidence (returns serialized payload) -

    pub fn broadcast_slashing_evidence(&self, evidence_id: &[u8; 32]) -> Result<Vec<u8>> {
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;
        match &evidence.source {
            EvidenceSource::Reported(reported) => reported.encode(),
            EvidenceSource::SelfDetected(_) => {
                bail!("self-detected evidence cannot be broadcast as reported evidence without a reporter signature")
            }
        }
    }

    // - item 7: verify evidence signatures -

    pub fn verify_evidence_signatures(
        &self,
        evidence: &Evidence,
        reporter_validator: &Validator,
    ) -> Result<bool> {
        match &evidence.source {
            EvidenceSource::Reported(reported) => {
                if reported.reporter != reporter_validator.address {
                    return Ok(false);
                }
                reporter_validator.verify_signature(&reported.id, &reported.reporter_signature)
            }
            EvidenceSource::SelfDetected(_) => {
                // Self-detected evidence is internal and verified via payload
                Ok(true)
            }
        }
    }

    /// Cryptographically verify the inner misbehavior against the accused validator.
    pub fn verify_misbehavior_payload(
        misbehavior: &Misbehavior,
        accused_validator: &Validator,
    ) -> Result<bool> {
        if *misbehavior.validator() != accused_validator.address {
            return Ok(false);
        }

        match misbehavior {
            Misbehavior::DoubleVote {
                view,
                vote_a,
                vote_b,
            } => {
                if vote_a.validator != accused_validator.address
                    || vote_b.validator != accused_validator.address
                {
                    return Ok(false);
                }
                if vote_a.view != *view || vote_b.view != *view {
                    return Ok(false);
                }
                if vote_a.phase != vote_b.phase {
                    return Ok(false);
                }
                if vote_a.block_hash == vote_b.block_hash {
                    return Ok(false);
                }
                // Both conflicting votes must carry valid cryptographic signatures by the accused validator
                let sig_a_ok = vote_a.verify_signature(accused_validator).unwrap_or(false);
                let sig_b_ok = vote_b.verify_signature(accused_validator).unwrap_or(false);
                Ok(sig_a_ok && sig_b_ok)
            }
            Misbehavior::DoubleProposal {
                view: _,
                proposer,
                proposal_a,
                proposal_b,
            } => {
                if *proposer != accused_validator.address {
                    return Ok(false);
                }
                if proposal_a == proposal_b {
                    return Ok(false);
                }
                let Ok(block_a) = sxiaum_block::Block::decode(proposal_a) else {
                    return Ok(false);
                };
                let Ok(block_b) = sxiaum_block::Block::decode(proposal_b) else {
                    return Ok(false);
                };
                if block_a.header.proposer != accused_validator.address
                    || block_b.header.proposer != accused_validator.address
                {
                    return Ok(false);
                }
                if block_a.height() != block_b.height() {
                    return Ok(false);
                }
                let Ok(hash_a) = block_a.try_hash() else {
                    return Ok(false);
                };
                let Ok(hash_b) = block_b.try_hash() else {
                    return Ok(false);
                };
                if hash_a == hash_b {
                    return Ok(false);
                }
                let sig_a = block_a
                    .verify_header_signature(&accused_validator.pubkey)
                    .unwrap_or(false);
                let sig_b = block_b
                    .verify_header_signature(&accused_validator.pubkey)
                    .unwrap_or(false);
                Ok(sig_a && sig_b)
            }
            Misbehavior::InvalidSignature { .. } => {
                // Third-party unauthenticated votes cannot be used to slash the forged victim address.
                // Invalid network messages are penalized at the P2P transport layer.
                Ok(false)
            }
        }
    }

    // - item 8: confirm validator misbehavior -

    pub fn confirm_misbehavior(
        &mut self,
        evidence_id: &[u8; 32],
        reporter_validator: &Validator,
    ) -> Result<()> {
        // Clone evidence to avoid simultaneous mut + immut borrow of self.
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;

        if !self.verify_evidence_signatures(&evidence, reporter_validator)? {
            bail!(
                "evidence signature verification failed for {:?}",
                evidence_id
            );
        }
        self.pending_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| anyhow!("evidence {:?} disappeared", evidence_id))?
            .verified = true;
        Ok(())
    }

    pub fn confirm_self_detected_misbehavior(
        &mut self,
        evidence_id: &[u8; 32],
        accused_validator: &Validator,
    ) -> Result<()> {
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;

        match &evidence.source {
            EvidenceSource::SelfDetected(_) => {}
            EvidenceSource::Reported(_) => {
                bail!("reported evidence must be confirmed with reporter validator signature");
            }
        }

        if !Self::verify_misbehavior_payload(evidence.misbehavior(), accused_validator)? {
            bail!(
                "misbehavior payload verification failed for self-detected evidence {:?}",
                evidence_id
            );
        }

        self.pending_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| anyhow!("evidence {:?} disappeared", evidence_id))?
            .verified = true;
        Ok(())
    }

    pub fn confirm_misbehavior_with_accused(
        &mut self,
        evidence_id: &[u8; 32],
        reporter_validator: &Validator,
        accused_validator: &Validator,
    ) -> Result<()> {
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;

        if !self.verify_evidence_signatures(&evidence, reporter_validator)? {
            bail!(
                "evidence signature verification failed for {:?}",
                evidence_id
            );
        }

        if !Self::verify_misbehavior_payload(evidence.misbehavior(), accused_validator)? {
            bail!(
                "misbehavior payload verification failed for {:?}",
                evidence_id
            );
        }

        self.pending_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| anyhow!("evidence {:?} disappeared", evidence_id))?
            .verified = true;
        Ok(())
    }

    /// Check whether a given evidence ID has already been executed.
    pub fn is_evidence_executed(&self, evidence_id: &[u8; 32]) -> Result<bool> {
        let key = evidence_executed_key(evidence_id);
        Ok(self.storage.state_get(key)?.is_some())
    }

    /// Prune expired evidence from the in-memory pool to protect memory.
    pub fn prune_expired_evidence(&mut self, current_height: u64) {
        self.pending_evidence.retain(|_, evidence| {
            current_height.saturating_sub(evidence.reported_at_height()) <= EVIDENCE_EXPIRY_BLOCKS
        });
    }

    // - items 9-12, 13-17: full slash pipeline -

    pub fn execute_slash(
        &mut self,
        evidence_id: &[u8; 32],
        current_height: u64,
        validator_set: &mut ValidatorSet,
        staking: &mut StakingManager,
        governance: &mut GovernanceManager,
    ) -> Result<SlashingEvent> {
        let evidence = self
            .pending_evidence
            .get(evidence_id)
            .cloned()
            .ok_or_else(|| anyhow!("evidence {:?} not found", evidence_id))?;

        if !evidence.verified {
            bail!("evidence {:?} not yet confirmed", evidence_id);
        }

        // Enforce evidence expiry window
        if current_height.saturating_sub(evidence.reported_at_height()) > EVIDENCE_EXPIRY_BLOCKS {
            bail!(
                "evidence {:?} has expired: reported at height {}, current height {}, max age {}",
                evidence_id,
                evidence.reported_at_height(),
                current_height,
                EVIDENCE_EXPIRY_BLOCKS
            );
        }

        // Prevent double-slashing replay
        if self.is_evidence_executed(evidence_id)? {
            bail!("evidence {:?} has already been executed", evidence_id);
        }

        let validator_addr = evidence.validator();
        let accused_validator = validator_set
            .validator(&validator_addr)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "accused validator {} not found in validator set",
                    validator_addr
                )
            })?;

        if !Self::verify_misbehavior_payload(evidence.misbehavior(), &accused_validator)? {
            bail!(
                "misbehavior payload verification failed for accused validator {}",
                validator_addr
            );
        }

        // Determine slash amount based on misbehavior type (item 9)
        let current_stake = staking.get_stake(&validator_addr);

        let slash_bps = match evidence.misbehavior() {
            Misbehavior::DoubleVote { .. } => self.config.double_vote_slash_bps,
            Misbehavior::DoubleProposal { .. } => self.config.double_proposal_slash_bps,
            Misbehavior::InvalidSignature { .. } => self.config.invalid_sig_slash_bps,
        };

        let slash_amount = current_stake * U256::from(slash_bps) / U256::from(10_000u64);

        // SECURITY: consume the evidence BEFORE applying any penalty writes.
        // Marking execution first guarantees a crash mid-way can never replay
        // the same offense and extract stake twice; the worst case of a
        // partial failure is a missed slash, never a double slash.
        let exec_key = evidence_executed_key(evidence_id);
        self.storage.state_put(exec_key, vec![1u8])?;

        // item 9: reduce validator stake
        let slash_result = staking.slash_validator(&validator_addr, slash_amount);
        if let Err(error) = &slash_result {
            tracing::error!(
                "slashing stake deduction FAILED for validator {} (evidence consumed): {}",
                validator_addr,
                error
            );
        }
        slash_result?;
        crate::metrics::ConsensusMetrics::record_slashing_event(evidence.misbehavior().kind());

        // item 10: burn slashed tokens (track burned portion)
        let burned_amount =
            slash_amount * U256::from(self.config.burn_fraction_bps) / U256::from(10_000u64);

        // item 11: jail and slash validator in validator set
        let _ = validator_set.slash_validator(&validator_addr, slash_amount);

        // item 17: record cooldown so the validator cannot rejoin immediately
        self.set_cooldown(validator_addr, current_height)?;

        // Build event
        let event = SlashingEvent::new(&evidence, slash_amount, burned_amount, current_height);

        // item 13: persist slashing event
        self.persist_slashing_event(&event)?;

        // item 18: store slashing history entry per validator
        self.store_slashing_history(&validator_addr, &event)?;

        // item 14: update validator reputation (re-use evidence log entry)
        info!(
            "validator {} reputation updated: slashed {} at height {} for {}",
            validator_addr,
            slash_amount,
            current_height,
            evidence.misbehavior().kind()
        );

        // item 15: emit slashing event log
        warn!(
            "[SLASHING EVENT] validator={} kind={} slash={} burned={} height={}",
            validator_addr, event.misbehavior_kind, slash_amount, burned_amount, current_height
        );

        // item 16: notify governance module
        self.notify_governance(governance, &event)?;

        // Remove from pending pool
        self.pending_evidence.remove(evidence_id);

        Ok(event)
    }

    // - item 17: cooldown enforcement -

    fn set_cooldown(&self, validator: Address, current_height: u64) -> Result<()> {
        let release_at = current_height.saturating_add(self.config.cooldown_blocks);
        let key = cooldown_key(&validator);
        self.storage
            .state_put(key, release_at.to_le_bytes().to_vec())
    }

    pub fn is_in_cooldown(&self, validator: &Address, current_height: u64) -> Result<bool> {
        let key = cooldown_key(validator);
        let Some(bytes) = self.storage.state_get(key)? else {
            return Ok(false);
        };
        if bytes.len() != 8 {
            return Ok(false);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(current_height < u64::from_le_bytes(arr))
    }

    pub fn cooldown_release_height(&self, validator: &Address) -> Result<Option<u64>> {
        let key = cooldown_key(validator);
        let Some(bytes) = self.storage.state_get(key)? else {
            return Ok(None);
        };
        if bytes.len() != 8 {
            return Ok(None);
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(Some(u64::from_le_bytes(arr)))
    }

    // - item 13: persist slashing event -

    fn persist_slashing_event(&self, event: &SlashingEvent) -> Result<()> {
        let key = slashing_event_key(&event.id);
        let bytes = event.try_encode()?;
        self.storage.state_put(key, bytes)
    }

    pub fn load_slashing_event(&self, event_id: &[u8; 32]) -> Result<Option<SlashingEvent>> {
        let key = slashing_event_key(event_id);
        let Some(bytes) = self.storage.state_get(key)? else {
            return Ok(None);
        };
        let event: SlashingEvent = SlashingEvent::decode(&bytes)?;
        Ok(Some(event))
    }

    // - item 18: slashing history per validator -

    fn store_slashing_history(&self, validator: &Address, event: &SlashingEvent) -> Result<()> {
        let key = slashing_history_key(validator, event.height);
        let bytes = event.try_encode()?;
        self.storage.state_put(key, bytes)
    }

    pub fn slashing_history(&self, validator: &Address) -> Result<Vec<SlashingEvent>> {
        let prefix = slashing_history_prefix(validator);
        let rows = self.storage.state_prefix_scan(prefix)?;
        let mut events = Vec::with_capacity(rows.len());
        for (_k, v) in rows {
            let event: SlashingEvent = SlashingEvent::decode(&v)?;
            events.push(event);
        }
        Ok(events)
    }

    // - item 16: notify governance module -

    fn notify_governance(
        &self,
        governance: &mut GovernanceManager,
        event: &SlashingEvent,
    ) -> Result<()> {
        let desc = format!(
            "Validator {} was slashed {} tokens at height {} for {}",
            event.validator, event.slash_amount, event.height, event.misbehavior_kind
        );
        if let Err(error) = governance.submit_proposal(
            format!("Slashing Incident Report - {}", event.validator),
            crate::governance::ProposalType::TextProposal { description: desc },
            event.height,
            event.height + 10_000,
        ) {
            warn!(
                "failed to record slashing incident as governance proposal: {}",
                error
            );
        }
        Ok(())
    }

    // - item 19: RPC querying helpers -

    pub fn get_slashing_event_rpc(&self, event_id: &[u8; 32]) -> Result<Option<SlashingEventRpc>> {
        let opt = self.load_slashing_event(event_id)?;
        Ok(opt.as_ref().map(SlashingEventRpc::from))
    }

    pub fn get_slashing_history_rpc(&self, validator: &Address) -> Result<Vec<SlashingEventRpc>> {
        let list = self.slashing_history(validator)?;
        Ok(list.iter().map(SlashingEventRpc::from).collect())
    }
}

/// Helper function to apply slashing for a block's included evidence items.
pub fn apply_block_slashing(
    slashing_manager: &mut SlashingManager,
    evidence_ids: &[[u8; 32]],
    current_height: u64,
    validator_set: &mut ValidatorSet,
    staking: &mut StakingManager,
    governance: &mut GovernanceManager,
) -> Result<Vec<SlashingEvent>> {
    let mut events = Vec::with_capacity(evidence_ids.len());
    for id in evidence_ids {
        match slashing_manager.execute_slash(id, current_height, validator_set, staking, governance)
        {
            Ok(event) => events.push(event),
            Err(error) => tracing::warn!("block slashing skipped evidence {:?}: {}", id, error),
        }
    }
    Ok(events)
}

// - storage key helpers -

fn slashing_event_key(event_id: &[u8; 32]) -> Vec<u8> {
    let mut key = SLASHING_EVENT_PREFIX.to_vec();
    key.extend_from_slice(event_id);
    key
}

fn slashing_history_prefix(validator: &Address) -> Vec<u8> {
    let mut key = SLASHING_HISTORY_PREFIX.to_vec();
    key.extend_from_slice(validator.as_bytes());
    key.push(b':');
    key
}

fn slashing_history_key(validator: &Address, height: u64) -> Vec<u8> {
    let mut key = slashing_history_prefix(validator);
    key.extend_from_slice(&height.to_be_bytes()); // big-endian for scan order
    key
}

fn cooldown_key(validator: &Address) -> Vec<u8> {
    let mut key = COOLDOWN_PREFIX.to_vec();
    key.extend_from_slice(validator.as_bytes());
    key
}

fn evidence_executed_key(evidence_id: &[u8; 32]) -> Vec<u8> {
    let mut key = EVIDENCE_EXECUTED_PREFIX.to_vec();
    key.extend_from_slice(evidence_id);
    key
}

// - tests -

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::GovernanceManager;
    use crate::pos::staking::StakingManager;
    use crate::pos::validator_set::ValidatorSet;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_storage::StorageEngine;
    use sxiaum_types::{Address, Validator};

    fn unique_db(name: &str) -> (PathBuf, Arc<StorageEngine>) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("target/tmp/slashing_test_{name}_{ts}.redb"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let storage = Arc::new(StorageEngine::new(&path).unwrap());
        (path, storage)
    }

    fn make_validator(seed: u8) -> (SigningKey, Validator) {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let addr = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut validator = Validator::new(
            addr,
            sk.verifying_key().to_bytes(),
            U256::from(1_000_000u64),
        );
        let (bls_sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&bls_sk, &pk).unwrap();
        validator = validator.with_bls_pop(pk.0, pop.0);
        (sk, validator)
    }

    fn make_vote(sk: &SigningKey, block_hash: [u8; 32], view: u64) -> Vote {
        let addr = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut vote = Vote::new(addr, block_hash, view);
        vote.sign(sk).expect("sign");
        vote
    }

    fn default_manager(storage: Arc<StorageEngine>) -> SlashingManager {
        SlashingManager::new(SlashingConfig::default(), storage)
    }

    #[test]
    fn detect_double_vote_same_view_different_blocks() {
        let (path, storage) = unique_db("dv");
        let (sk, _) = make_validator(1);
        let mgr = default_manager(storage.clone());

        let vote_a = make_vote(&sk, [1u8; 32], 5);
        let vote_b = make_vote(&sk, [2u8; 32], 5);
        let same_block = make_vote(&sk, [1u8; 32], 5);

        assert!(mgr.detect_double_vote(&vote_a, &vote_b).is_some());
        assert!(mgr.detect_double_vote(&vote_a, &same_block).is_none());
        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn detect_double_proposal_different_bytes() {
        let (path, storage) = unique_db("dp");
        let mgr = default_manager(storage.clone());
        let proposer = Address([1u8; 32]);
        let mb = mgr
            .detect_double_proposal(3, proposer, vec![1, 2], vec![3, 4])
            .unwrap();
        assert_eq!(mb.validator(), &proposer);
        assert!(mgr
            .detect_double_proposal(3, proposer, vec![1, 2], vec![1, 2])
            .is_none());
        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn detect_invalid_signature_bad_vote() {
        let (path, storage) = unique_db("sig");
        let (sk, validator) = make_validator(2);
        let mgr = default_manager(storage.clone());

        // Valid vote should not trigger
        let valid = make_vote(&sk, [1u8; 32], 1);
        assert!(mgr.detect_invalid_signature(&valid, &validator).is_none());

        // Vote with zero signature should trigger
        let mut bad = valid.clone();
        bad.signature = [0u8; 64];
        assert!(mgr.detect_invalid_signature(&bad, &validator).is_some());
        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn record_evidence_assigns_deterministic_id() {
        let (path, storage) = unique_db("rec");
        let (sk, _) = make_validator(3);
        let addr = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut mgr = default_manager(storage.clone());
        let vote_a = make_vote(&sk, [1u8; 32], 1);
        let vote_b = make_vote(&sk, [2u8; 32], 1);
        let mb = Misbehavior::DoubleVote {
            view: 1,
            vote_a,
            vote_b,
        };

        let id1 = mgr
            .record_evidence(addr, mb.clone(), 10, addr, [0u8; 64])
            .unwrap();
        // Same inputs -> same id
        let id2 = mgr.record_evidence(addr, mb, 10, addr, [0u8; 64]).unwrap();
        assert_eq!(id1, id2);
        drop(storage);
        let _ = fs::remove_file(&path);
    }

    // SECURITY REGRESSION (H-08): two DIFFERENT reporters filing the SAME
    // offense (even at different heights) must derive the SAME evidence ID so
    // the executed-evidence replay guard rejects the duplicate instead of
    // slashing twice for one crime.
    #[test]
    fn duplicate_reports_of_same_offense_share_one_evidence_id() {
        let (path, storage) = unique_db("dup-report");
        let (sk, _) = make_validator(7);
        let accused = Address::from_public_key(&sk.verifying_key().to_bytes());
        let reporter_b = Address([0xB0; 32]);
        let mut mgr = default_manager(storage.clone());

        let mb = Misbehavior::DoubleVote {
            view: 4,
            vote_a: make_vote(&sk, [0xAA; 32], 4),
            vote_b: make_vote(&sk, [0xBB; 32], 4),
        };

        let id_reporter_a = mgr
            .record_evidence(accused, mb.clone(), 100, accused, [0u8; 64])
            .unwrap();
        let id_reporter_b_later_height = mgr
            .record_evidence(accused, mb, 5555, reporter_b, [0u8; 64])
            .unwrap();

        assert_eq!(
            id_reporter_a, id_reporter_b_later_height,
            "same offense must map to one evidence ID regardless of reporter/height"
        );
        drop(storage);
        let _ = fs::remove_file(&path);
    }

    // SECURITY REGRESSION (H-08): distinct offenses must NOT collide.
    #[test]
    fn distinct_offenses_get_distinct_evidence_ids() {
        let (path, storage) = unique_db("distinct");
        let (sk, _) = make_validator(8);
        let accused = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut mgr = default_manager(storage.clone());

        let mb_one = Misbehavior::DoubleVote {
            view: 1,
            vote_a: make_vote(&sk, [1u8; 32], 1),
            vote_b: make_vote(&sk, [2u8; 32], 1),
        };
        let mb_two = Misbehavior::DoubleVote {
            view: 2,
            vote_a: make_vote(&sk, [3u8; 32], 2),
            vote_b: make_vote(&sk, [4u8; 32], 2),
        };

        let id_one = mgr
            .record_evidence(accused, mb_one, 10, accused, [0u8; 64])
            .unwrap();
        let id_two = mgr
            .record_evidence(accused, mb_two, 10, accused, [0u8; 64])
            .unwrap();
        assert_ne!(id_one, id_two);
        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn full_slash_pipeline_reduces_stake_and_jails_validator() {
        let (path, storage) = unique_db("slash");
        let (sk, validator) = make_validator(4);
        let addr = validator.address;

        let mut mgr = default_manager(storage.clone());
        let mut vs = ValidatorSet::new();
        let mut staking = StakingManager::with_storage(storage.clone());
        let mut governance = GovernanceManager::new();

        vs.add_validator(validator.clone()).unwrap();
        staking
            .stake_tokens(addr, U256::from(1_000_000u64))
            .unwrap();

        let vote_a = make_vote(&sk, [1u8; 32], 2);
        let vote_b = make_vote(&sk, [2u8; 32], 2);
        let mb = Misbehavior::DoubleVote {
            view: 2,
            vote_a: vote_a.clone(),
            vote_b: vote_b.clone(),
        };

        let evidence = Evidence::new(addr, mb.clone(), 100, addr, [0u8; 64]).unwrap();
        let id = evidence.id();

        let mut verified = evidence;
        verified.verified = true;
        mgr.pending_evidence.insert(id, verified);

        let event = mgr
            .execute_slash(&id, 100, &mut vs, &mut staking, &mut governance)
            .unwrap();

        assert!(event.slash_amount > U256::zero());
        assert!(event.burned_amount > U256::zero());
        assert!(event.burned_amount <= event.slash_amount);

        // Validator should be jailed
        let active = vs.active_validators();
        assert!(!active.iter().any(|v| v.address == addr));

        // Slashing history should be stored
        let history = mgr.slashing_history(&addr).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].validator, addr);

        // Cooldown should be active
        assert!(mgr.is_in_cooldown(&addr, 100).unwrap());
        assert!(!mgr
            .is_in_cooldown(&addr, 100 + mgr.config.cooldown_blocks + 1)
            .unwrap());

        // Attempting to re-execute the same evidence is rejected
        let mut replay_evidence = Evidence::new(addr, mb, 100, addr, [0u8; 64]).unwrap();
        replay_evidence.verified = true;
        mgr.pending_evidence.insert(id, replay_evidence);
        assert!(mgr
            .execute_slash(&id, 100, &mut vs, &mut staking, &mut governance)
            .is_err());

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn expired_evidence_is_rejected_and_pruned() {
        let (path, storage) = unique_db("expired");
        let (sk, validator) = make_validator(6);
        let addr = validator.address;

        let mut mgr = default_manager(storage.clone());
        let mut vs = ValidatorSet::new();
        let mut staking = StakingManager::with_storage(storage.clone());
        let mut governance = GovernanceManager::new();

        vs.add_validator(validator.clone()).unwrap();
        staking
            .stake_tokens(addr, U256::from(1_000_000u64))
            .unwrap();

        let vote_a = make_vote(&sk, [1u8; 32], 1);
        let vote_b = make_vote(&sk, [2u8; 32], 1);
        let mb = Misbehavior::DoubleVote {
            view: 1,
            vote_a,
            vote_b,
        };

        // Evidence reported at height 10
        let mut evidence = Evidence::new(addr, mb, 10, addr, [0u8; 64]).unwrap();
        evidence.verified = true;
        let id = evidence.id();
        mgr.pending_evidence.insert(id, evidence);

        // Attempt execution at height 10 + EVIDENCE_EXPIRY_BLOCKS + 1
        let expired_height = 10 + EVIDENCE_EXPIRY_BLOCKS + 1;
        assert!(mgr
            .execute_slash(&id, expired_height, &mut vs, &mut staking, &mut governance)
            .is_err());

        // Pruning removes it
        assert_eq!(mgr.pending_evidence.len(), 1);
        mgr.prune_expired_evidence(expired_height);
        assert_eq!(mgr.pending_evidence.len(), 0);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rpc_getters_return_correct_data() {
        let (path, storage) = unique_db("rpc");
        let (sk, validator) = make_validator(5);
        let addr = validator.address;
        let mut mgr = default_manager(storage.clone());
        let mut vs = ValidatorSet::new();
        let mut staking = StakingManager::with_storage(storage.clone());
        let mut governance = GovernanceManager::new();
        vs.add_validator(validator.clone()).unwrap();
        staking.stake_tokens(addr, U256::from(500_000u64)).unwrap();

        let vote_a = make_vote(&sk, [1u8; 32], 5);
        let vote_b = make_vote(&sk, [2u8; 32], 5);
        let evidence = {
            let mb = Misbehavior::DoubleVote {
                view: 5,
                vote_a,
                vote_b,
            };
            let mut e = Evidence::new(addr, mb, 200, addr, [0u8; 64]).unwrap();
            e.verified = true;
            e
        };
        let id = evidence.id();
        mgr.pending_evidence.insert(id, evidence);

        let event = mgr
            .execute_slash(&id, 200, &mut vs, &mut staking, &mut governance)
            .unwrap();

        let rpc_event = mgr.get_slashing_event_rpc(&event.id).unwrap();
        assert!(rpc_event.is_some());

        let history = mgr.get_slashing_history_rpc(&addr).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].misbehavior, "DoubleVote");

        drop(storage);
        let _ = fs::remove_file(&path);
    }
}
