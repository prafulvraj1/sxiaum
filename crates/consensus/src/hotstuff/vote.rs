use anyhow::{bail, Result};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use sxiaum_crypto::bls::{
    aggregate_public_keys, aggregate_votes, verify_quorum_certificate, BlsPublicKey, BlsSignature,
};
use sxiaum_crypto::hash::{domain_hash, DOMAIN_CONSENSUS};
use sxiaum_types::{Address, Canonical, Validator};

mod serde_sig {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig.as_slice())
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| Error::custom("expected 64 bytes"))
    }
}

/// HotStuff vote / QC phase tag.
///
/// Each phase requires its **own** quorum certificate. A Prepare QC must not
/// be reused to advance PreCommit or Commit/Finalize.
#[derive(
    Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum VotePhase {
    #[default]
    Prepare = 0,
    PreCommit = 1,
    /// Third-phase votes; forming a QC for this phase finalizes the block.
    Commit = 2,
}

impl VotePhase {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn next(self) -> Option<Self> {
        match self {
            Self::Prepare => Some(Self::PreCommit),
            Self::PreCommit => Some(Self::Commit),
            Self::Commit => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub validator: Address,
    pub block_hash: [u8; 32],
    pub view: u64,
    /// Consensus phase this vote applies to (Prepare / PreCommit / Commit).
    #[serde(default)]
    pub phase: VotePhase,
    #[serde(default)]
    pub entropy_commit: [u8; 32],
    #[serde(default)]
    pub entropy_reveal: Option<[u8; 32]>,
    #[serde(with = "serde_sig")]
    pub signature: [u8; 64],
}

impl Vote {
    /// Create an unsigned Prepare-phase vote (legacy default).
    pub fn new(validator: Address, block_hash: [u8; 32], view: u64) -> Self {
        Self::new_with_phase(validator, block_hash, view, VotePhase::Prepare)
    }

    pub fn new_with_phase(
        validator: Address,
        block_hash: [u8; 32],
        view: u64,
        phase: VotePhase,
    ) -> Self {
        Self {
            validator,
            block_hash,
            view,
            phase,
            entropy_commit: [0u8; 32],
            entropy_reveal: None,
            signature: [0u8; 64],
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let message = self.signing_message();
        self.signature = signing_key.sign(&message).to_bytes();
        Ok(())
    }

    pub fn verify_signature(&self, validator: &Validator) -> Result<bool> {
        validator.verify_signature(&self.signing_message(), &self.signature)
    }

    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as Canonical>::try_encode(self)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.try_encode().unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Domain-separated vote digest: includes phase so QCs cannot be cross-applied.
    pub fn signing_message(&self) -> [u8; 32] {
        vote_signing_message(self.validator, &self.block_hash, self.view, self.phase)
    }
}

/// Canonical vote signing message shared by `Vote` and `QuorumCertificate` verify.
pub fn vote_signing_message(
    validator: Address,
    block_hash: &[u8; 32],
    view: u64,
    phase: VotePhase,
) -> [u8; 32] {
    let mut bytes = [0u8; 73];
    bytes[..32].copy_from_slice(validator.as_bytes());
    bytes[32..64].copy_from_slice(block_hash);
    bytes[64..72].copy_from_slice(&view.to_le_bytes());
    bytes[72] = phase.as_byte();
    domain_hash(DOMAIN_CONSENSUS, &bytes)
}

/// Canonical message signed by validators for BLS aggregate QC verification.
/// Binds block hash, view number, and consensus phase to prevent cross-view
/// and cross-phase replay of aggregated certificates.
pub fn bls_qc_signing_message(block_hash: &[u8; 32], view: u64, phase: VotePhase) -> [u8; 41] {
    let mut msg = [0u8; 41];
    msg[..32].copy_from_slice(block_hash);
    msg[32..40].copy_from_slice(&view.to_le_bytes());
    msg[40] = phase.as_byte();
    msg
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub block_hash: [u8; 32],
    pub view: u64,
    /// Phase this QC certifies. Must match the votes that formed it.
    #[serde(default)]
    pub phase: VotePhase,
    #[serde(default)]
    pub aggregated_entropy: [u8; 32],
    pub signatures: Vec<Vec<u8>>,
    pub validators: Vec<Address>,
}

impl QuorumCertificate {
    pub fn new(
        block_hash: [u8; 32],
        view: u64,
        signatures: Vec<Vec<u8>>,
        validators: Vec<Address>,
    ) -> Self {
        Self::new_with_phase(block_hash, view, VotePhase::Prepare, signatures, validators)
    }

    pub fn new_with_phase(
        block_hash: [u8; 32],
        view: u64,
        phase: VotePhase,
        signatures: Vec<Vec<u8>>,
        validators: Vec<Address>,
    ) -> Self {
        Self {
            block_hash,
            view,
            phase,
            aggregated_entropy: [0u8; 32],
            signatures,
            validators,
        }
    }

    pub fn verify(&self, validator_set: &[Validator], threshold: usize) -> Result<bool> {
        if self.signatures.len() != self.validators.len() {
            return Ok(false);
        }
        if self.validators.len() < threshold {
            return Ok(false);
        }

        let mut seen_validators = HashSet::with_capacity(self.validators.len());

        for (address, signature) in self.validators.iter().zip(self.signatures.iter()) {
            if !seen_validators.insert(*address) {
                return Ok(false);
            }

            let Some(validator) = validator_set
                .iter()
                .find(|validator| validator.address == *address)
            else {
                return Ok(false);
            };

            if signature.len() != 64 {
                return Ok(false);
            }

            let mut sig = [0u8; 64];
            sig.copy_from_slice(signature);
            // In 3-phase HotStuff, vote signatures commit to the common tuple
            // (validator, block_hash, view, phase). Individual vote entropy reveals
            // are accumulated into `aggregated_entropy` upon receipt by the leader.
            // When re-verifying a QC, we verify each validator's signature over the
            // canonical vote signing message. Cryptographic mismatches or invalid
            // signatures return Ok(false) rather than aborting consensus with Err.
            let msg = vote_signing_message(*address, &self.block_hash, self.view, self.phase);
            match validator.verify_signature(&msg, &sig) {
                Ok(true) => {}
                Ok(false) | Err(_) => return Ok(false),
            }
        }

        Ok(true)
    }

    pub fn verify_with_voting_power(
        &self,
        validator_set: &[Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<bool> {
        if !self.verify(validator_set, threshold)? {
            return Ok(false);
        }

        let mut total_voting_power = 0u64;
        for address in &self.validators {
            let Some(validator) = validator_set
                .iter()
                .find(|validator| validator.address == *address)
            else {
                return Ok(false);
            };
            total_voting_power = total_voting_power.saturating_add(validator.voting_power);
        }

        Ok(total_voting_power >= required_voting_power)
    }

    pub fn verify_bls_with_voting_power(
        &self,
        validator_set: &[Validator],
        threshold: usize,
        required_voting_power: u64,
    ) -> Result<bool> {
        // Fallback to Ed25519 for tests or legacy QCs that use 64-byte signatures or empty signatures
        if self.signatures.is_empty() || self.signatures.first().is_some_and(|sig| sig.len() == 64)
        {
            return self.verify_with_voting_power(validator_set, threshold, required_voting_power);
        }

        // Align length/duplicate checks with verify() before aggregation (Bug 5 fix).
        if self.signatures.len() != self.validators.len() {
            return Ok(false);
        }

        let mut seen_validators = HashSet::with_capacity(self.validators.len());
        for address in &self.validators {
            if !seen_validators.insert(*address) {
                return Ok(false);
            }
        }

        let mut total_voting_power = 0u64;
        let mut public_keys = Vec::with_capacity(self.validators.len());

        for address in &self.validators {
            let Some(validator) = validator_set
                .iter()
                .find(|validator| validator.address == *address)
            else {
                return Ok(false);
            };

            total_voting_power = total_voting_power.saturating_add(validator.voting_power);

            // Extract BLS public key if available
            if let Some(ref pk_bytes) = validator.bls_pubkey {
                public_keys.push(sxiaum_crypto::bls::BlsPublicKey(pk_bytes.clone()));
            } else {
                return self.verify_with_voting_power(
                    validator_set,
                    threshold,
                    required_voting_power,
                );
            }
        }

        if total_voting_power < required_voting_power || self.validators.len() < threshold {
            return Ok(false);
        }

        if public_keys.is_empty() {
            return Ok(self.is_genesis());
        }

        self.verify_bls_aggregate_signature(&public_keys)
    }

    pub fn aggregate_bls_signatures(&self) -> Result<Vec<u8>> {
        Ok(self.aggregate_bls_signature()?.0)
    }

    pub fn aggregate_bls_signature(&self) -> Result<BlsSignature> {
        let signatures: Result<Vec<_>> = self
            .signatures
            .iter()
            .map(|signature| Ok(BlsSignature(signature.clone())))
            .collect();
        aggregate_votes(&signatures?)
    }

    pub fn verify_bls_aggregate_signature(&self, public_keys: &[BlsPublicKey]) -> Result<bool> {
        if public_keys.len() != self.validators.len() {
            return Ok(false);
        }

        let mut seen_validators = HashSet::with_capacity(self.validators.len());
        for address in &self.validators {
            if !seen_validators.insert(*address) {
                return Ok(false);
            }
        }

        if self.signatures.len() != self.validators.len() {
            return Ok(false);
        }

        let aggregate_public_key = aggregate_public_keys(public_keys)?;
        let aggregate_signature = self.aggregate_bls_signature()?;
        // Bind block_hash, view, and phase into the BLS message for cross-view and cross-phase replay protection.
        let msg = bls_qc_signing_message(&self.block_hash, self.view, self.phase);
        Ok(verify_quorum_certificate(
            &aggregate_public_key,
            &msg,
            &aggregate_signature,
        ))
    }

    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as Canonical>::try_encode(self)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.try_encode().unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    /// Compact participant bitmap: bit `i` is set when validator index `i`
    /// signed this QC. One bit per entry of `self.validators`, packed
    /// little-endian into `ceil(n / 8)` bytes.
    pub fn validator_bitmap(&self) -> Vec<u8> {
        let n = self.validators.len();
        let mut bitmap = vec![0u8; n.div_ceil(8)];
        for (i, _) in self.validators.iter().enumerate() {
            bitmap[i / 8] |= 1 << (i % 8);
        }
        bitmap
    }

    pub fn is_genesis(&self) -> bool {
        self.block_hash == [0u8; 32] && self.view == 0 && self.validators.is_empty()
    }
}

/// A CommitCertificate is a QuorumCertificate for the Commit phase.
/// It represents finality for a block at a given view.
pub type CommitCertificate = QuorumCertificate;

/// A ViewChangeCertificate aggregates timeout votes from validators
/// to justify advancing to a new view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewChangeCertificate {
    pub view: u64,
    pub new_view: u64,
    pub timeout_votes: Vec<TimeoutVote>,
    pub aggregated_signature: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub validator: Address,
    pub view: u64,
    pub highest_qc: Option<QuorumCertificate>,
    #[serde(with = "serde_sig")]
    pub signature: [u8; 64],
}

impl TimeoutVote {
    pub fn new(validator: Address, view: u64, highest_qc: Option<QuorumCertificate>) -> Self {
        Self {
            validator,
            view,
            highest_qc,
            signature: [0u8; 64],
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let message = self.signing_message();
        self.signature = signing_key.sign(&message).to_bytes();
        Ok(())
    }

    pub fn signing_message(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.validator.as_bytes());
        bytes.extend_from_slice(&self.view.to_le_bytes());
        if let Some(ref qc) = self.highest_qc {
            bytes.extend_from_slice(&qc.block_hash);
            bytes.extend_from_slice(&qc.view.to_le_bytes());
        }
        domain_hash(DOMAIN_CONSENSUS, &bytes)
    }

    pub fn verify_signature(&self, validator: &Validator) -> Result<bool> {
        validator.verify_signature(&self.signing_message(), &self.signature)
    }
}

impl ViewChangeCertificate {
    pub fn new(view: u64, new_view: u64) -> Self {
        Self {
            view,
            new_view,
            timeout_votes: Vec::new(),
            aggregated_signature: None,
        }
    }

    pub fn add_timeout_vote(&mut self, vote: TimeoutVote) {
        self.timeout_votes.push(vote);
    }

    pub fn has_quorum(&self, threshold: usize) -> bool {
        self.timeout_votes.len() >= threshold
    }

    pub fn verify(&self, validator_set: &[Validator], threshold: usize) -> Result<bool> {
        if self.timeout_votes.len() < threshold {
            return Ok(false);
        }

        let mut seen = HashSet::new();
        for vote in &self.timeout_votes {
            if !seen.insert(vote.validator) {
                return Ok(false);
            }
            let Some(validator) = validator_set.iter().find(|v| v.address == vote.validator) else {
                return Ok(false);
            };
            if !vote.verify_signature(validator)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Select the proposer for the new view based on the highest QC
    /// among all timeout votes (deterministic leader election).
    pub fn select_proposer(&self, validator_set: &[Validator]) -> Option<Address> {
        let active: Vec<_> = validator_set.iter().filter(|v| v.is_active()).collect();
        if active.is_empty() {
            return None;
        }

        // Find the highest QC view among all timeout votes
        let max_qc_view = self
            .timeout_votes
            .iter()
            .filter_map(|v| v.highest_qc.as_ref().map(|qc| qc.view))
            .max()
            .unwrap_or(0);

        // Use the highest QC view as seed for deterministic selection
        let mut hasher = Sha256::new();
        hasher.update(max_qc_view.to_le_bytes());
        hasher.update(self.new_view.to_le_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let index = (u64::from_le_bytes(bytes) as usize) % active.len();
        Some(active[index].address)
    }
}

#[derive(Clone, Debug, Default)]
pub struct VoteCollector {
    /// Votes keyed by (view, block_hash, phase).
    votes: HashMap<(u64, [u8; 32], VotePhase), Vec<Vote>>,
    /// Per-validator last vote target for (view, phase) — double-vote detection.
    validator_votes: HashMap<(u64, VotePhase, Address), [u8; 32]>,
}

impl VoteCollector {
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            validator_votes: HashMap::new(),
        }
    }

    pub fn add_vote(&mut self, vote: Vote) -> Result<()> {
        let validator = vote.validator;
        let block_hash = vote.block_hash;
        let view = vote.view;
        let phase = vote.phase;

        if let Some(previous_block_hash) =
            self.validator_votes
                .get(&(vote.view, vote.phase, vote.validator))
        {
            if previous_block_hash != &vote.block_hash {
                bail!(
                    "double voting detected for validator {} in view {} phase {:?}",
                    vote.validator,
                    vote.view,
                    vote.phase
                );
            }
        }

        // Commit-Reveal Check
        //
        // SECURITY (H-16): enforcement now depends on LOCAL availability of
        // the validator's Prepare commitment. Previously, a PreCommit vote
        // carrying a reveal with NO locally-known Prepare vote was rejected
        // ("entropy reveal provided without prior commit"). After a restart
        // or prune the collector's Prepare votes are gone, so every honest
        // validator's reveal was bounced and the commit-reveal pipeline lost
        // quorum permanently. When the commitment IS known, checks stay
        // strict; when it is unknown, the vote is accepted provisionally and
        // its Ed25519 signature is still verified downstream.
        if phase != VotePhase::Prepare {
            if let Some(prep) =
                self.get_validator_vote_for_phase(view, VotePhase::Prepare, &validator)
            {
                if prep.entropy_commit == [0u8; 32] {
                    if vote.entropy_reveal.is_some() {
                        bail!("entropy reveal provided without prior commit");
                    }
                } else if let Some(reveal) = vote.entropy_reveal {
                    let hashed_reveal = sxiaum_crypto::hash::sha256(&reveal);
                    if hashed_reveal != prep.entropy_commit {
                        bail!("entropy reveal does not match commit");
                    }
                } else {
                    bail!("missing entropy reveal");
                }
            }
        }

        let entry = self
            .votes
            .entry((vote.view, vote.block_hash, vote.phase))
            .or_default();
        if !entry
            .iter()
            .any(|existing| existing.validator == vote.validator)
        {
            entry.push(vote);
        }
        self.validator_votes
            .insert((view, phase, validator), block_hash);
        Ok(())
    }

    pub fn vote_count(&self, view: u64, block_hash: [u8; 32]) -> usize {
        self.vote_count_for_phase(view, block_hash, VotePhase::Prepare)
    }

    pub fn vote_count_for_phase(&self, view: u64, block_hash: [u8; 32], phase: VotePhase) -> usize {
        self.votes
            .get(&(view, block_hash, phase))
            .map(|votes| votes.len())
            .unwrap_or(0)
    }

    pub fn get_validator_vote(&self, view: u64, validator: &Address) -> Option<Vote> {
        self.get_validator_vote_for_phase(view, VotePhase::Prepare, validator)
    }

    pub fn get_validator_vote_for_phase(
        &self,
        view: u64,
        phase: VotePhase,
        validator: &Address,
    ) -> Option<Vote> {
        if let Some(hash) = self.validator_votes.get(&(view, phase, *validator)) {
            if let Some(list) = self.votes.get(&(view, *hash, phase)) {
                return list.iter().find(|v| v.validator == *validator).cloned();
            }
        }
        None
    }

    pub fn get_voted_hash(&self, view: u64, validator: &Address) -> Option<[u8; 32]> {
        self.get_voted_hash_for_phase(view, VotePhase::Prepare, validator)
    }

    pub fn get_voted_hash_for_phase(
        &self,
        view: u64,
        phase: VotePhase,
        validator: &Address,
    ) -> Option<[u8; 32]> {
        self.validator_votes
            .get(&(view, phase, *validator))
            .cloned()
    }

    pub fn has_quorum(&self, view: u64, block_hash: [u8; 32], threshold: usize) -> bool {
        self.has_quorum_for_phase(view, block_hash, VotePhase::Prepare, threshold)
    }

    pub fn has_quorum_for_phase(
        &self,
        view: u64,
        block_hash: [u8; 32],
        phase: VotePhase,
        threshold: usize,
    ) -> bool {
        self.vote_count_for_phase(view, block_hash, phase) >= threshold
    }

    pub fn aggregate_signatures(
        &self,
        view: u64,
        block_hash: [u8; 32],
    ) -> Vec<(Address, [u8; 64])> {
        self.aggregate_signatures_for_phase(view, block_hash, VotePhase::Prepare)
    }

    pub fn aggregate_signatures_for_phase(
        &self,
        view: u64,
        block_hash: [u8; 32],
        phase: VotePhase,
    ) -> Vec<(Address, [u8; 64])> {
        self.votes
            .get(&(view, block_hash, phase))
            .map(|votes| {
                votes
                    .iter()
                    .map(|vote| (vote.validator, vote.signature))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn build_quorum_certificate(
        &self,
        view: u64,
        block_hash: [u8; 32],
        threshold: usize,
    ) -> Option<QuorumCertificate> {
        self.build_quorum_certificate_for_phase(view, block_hash, VotePhase::Prepare, threshold)
    }

    pub fn build_quorum_certificate_for_phase(
        &self,
        view: u64,
        block_hash: [u8; 32],
        phase: VotePhase,
        threshold: usize,
    ) -> Option<QuorumCertificate> {
        if !self.has_quorum_for_phase(view, block_hash, phase, threshold) {
            return None;
        }

        let votes = self.votes.get(&(view, block_hash, phase))?;
        let mut aggregated_entropy = [0u8; 32];

        // Aggregate reveals (e.g. XOR)
        for vote in votes {
            if let Some(reveal) = vote.entropy_reveal {
                for i in 0..32 {
                    aggregated_entropy[i] ^= reveal[i];
                }
            }
        }

        // Fallback: If no reveals were present, aggregated_entropy remains [0u8; 32] as a sentinel.
        // We do not fabricate randomness from deterministic input (Bug 6 fix).

        let (validators, signatures): (Vec<_>, Vec<_>) = votes
            .iter()
            .map(|vote| (vote.validator, vote.signature.to_vec()))
            .unzip();

        Some(QuorumCertificate {
            block_hash,
            view,
            phase,
            aggregated_entropy,
            signatures,
            validators,
        })
    }

    /// Prune all votes and double-vote tracking data older than `min_view`.
    pub fn prune(&mut self, min_view: u64) {
        self.votes.retain(|(view, _, _), _| *view >= min_view);
        self.validator_votes
            .retain(|(view, _, _), _| *view >= min_view);
    }
}

#[cfg(test)]
mod tests {
    use super::{bls_qc_signing_message, QuorumCertificate, Vote, VoteCollector, VotePhase};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use sxiaum_crypto::bls::{bls_generate_keypair, validator_vote_signature};
    use sxiaum_types::{Address, Validator};

    fn validator_from_signing_key(signing_key: &SigningKey) -> Validator {
        let pubkey = signing_key.verifying_key().to_bytes();
        Validator::new(
            Address::from_public_key(&pubkey),
            pubkey,
            U256::from(10u64.pow(18)),
        )
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn quorum_certificate_new_encode_decode_and_bitmap_work() {
        let qc = QuorumCertificate::new(
            [4u8; 32],
            12,
            vec![vec![1u8; 64], vec![2u8; 64]],
            vec![Address([1u8; 32]), Address([2u8; 32])],
        );

        assert_eq!(qc.block_hash, [4u8; 32]);
        assert_eq!(qc.view, 12);
        assert_eq!(qc.phase, VotePhase::Prepare);
        assert_eq!(qc.signatures.len(), 2);
        assert_eq!(qc.validators.len(), 2);
        // Compact bitmap: 2 participants -> one byte with bits 0 and 1 set.
        assert_eq!(qc.validator_bitmap(), vec![0b0000_0011u8]);

        let encoded = qc.encode();
        let decoded = QuorumCertificate::decode(&encoded)
            .expect("quorum certificate decoding should succeed");

        assert_eq!(decoded.block_hash, qc.block_hash);
        assert_eq!(decoded.view, qc.view);
        assert_eq!(decoded.phase, qc.phase);
        assert_eq!(decoded.signatures, qc.signatures);
        assert_eq!(decoded.validators, qc.validators);
    }

    #[test]
    fn quorum_certificate_verify_rejects_threshold_mismatch_and_unknown_validator() {
        let signer = signing_key(6);
        let validator = validator_from_signing_key(&signer);
        let mut vote = Vote::new(validator.address, [6u8; 32], 1);
        vote.sign(&signer).expect("vote signing should succeed");

        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );

        assert!(!qc
            .verify(std::slice::from_ref(&validator), 2)
            .expect("threshold check should run"));

        let other_validator = validator_from_signing_key(&signing_key(7));
        assert!(!qc
            .verify(&[other_validator], 1)
            .expect("validator lookup should run"));
    }

    #[test]
    fn vote_new_sign_verify_and_codec_round_trip() {
        let signing_key = signing_key(0);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new_with_phase(validator.address, [3u8; 32], 9, VotePhase::PreCommit);

        assert_eq!(vote.validator, validator.address);
        assert_eq!(vote.block_hash, [3u8; 32]);
        assert_eq!(vote.view, 9);
        assert_eq!(vote.phase, VotePhase::PreCommit);
        assert_eq!(vote.signature, [0u8; 64]);

        vote.sign(&signing_key)
            .expect("vote signing should succeed");
        assert!(vote
            .verify_signature(&validator)
            .expect("vote verification should succeed"));

        let encoded = vote.encode();
        let decoded = Vote::decode(&encoded).expect("vote decoding should succeed");

        assert_eq!(decoded.validator, vote.validator);
        assert_eq!(decoded.block_hash, vote.block_hash);
        assert_eq!(decoded.view, vote.view);
        assert_eq!(decoded.phase, vote.phase);
        assert_eq!(decoded.signature, vote.signature);
    }

    #[test]
    fn vote_collector_add_vote_counts_quorum_and_aggregates_signatures() {
        let signing_key = signing_key(4);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [8u8; 32], 6);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let mut collector = VoteCollector::new();
        collector
            .add_vote(vote.clone())
            .expect("vote insert should succeed");
        collector
            .add_vote(vote.clone())
            .expect("duplicate vote for same block should be ignored");

        assert_eq!(collector.vote_count(6, [8u8; 32]), 1);
        assert!(collector.has_quorum(6, [8u8; 32], 1));
        assert!(!collector.has_quorum(6, [8u8; 32], 2));

        let aggregated = collector.aggregate_signatures(6, [8u8; 32]);
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].0, validator.address);
        assert_eq!(aggregated[0].1, vote.signature);

        let qc = collector
            .build_quorum_certificate(6, [8u8; 32], 1)
            .expect("qc should be built at quorum");
        assert_eq!(qc.block_hash, [8u8; 32]);
        assert_eq!(qc.view, 6);
        assert_eq!(qc.phase, VotePhase::Prepare);
        assert_eq!(qc.validators, vec![validator.address]);
        assert_eq!(qc.signatures, vec![vote.signature.to_vec()]);

        assert!(collector
            .build_quorum_certificate(6, [8u8; 32], 2)
            .is_none());
    }

    #[test]
    fn vote_collector_rejects_double_vote_for_different_block_in_same_view_phase() {
        let signing_key = signing_key(5);
        let validator = validator_from_signing_key(&signing_key);
        let mut first_vote = Vote::new(validator.address, [1u8; 32], 2);
        first_vote
            .sign(&signing_key)
            .expect("first vote signing should succeed");
        let mut second_vote = Vote::new(validator.address, [2u8; 32], 2);
        second_vote
            .sign(&signing_key)
            .expect("second vote signing should succeed");

        let mut collector = VoteCollector::new();
        collector
            .add_vote(first_vote)
            .expect("first vote insert should succeed");

        assert!(collector.add_vote(second_vote).is_err());
    }

    #[test]
    fn vote_collector_allows_same_block_across_phases() {
        let signing_key = signing_key(8);
        let validator = validator_from_signing_key(&signing_key);
        let hash = [42u8; 32];
        let reveal = [1u8; 32];
        let commit = sxiaum_crypto::hash::sha256(&reveal);

        let mut prepare = Vote::new_with_phase(validator.address, hash, 1, VotePhase::Prepare);
        prepare.entropy_commit = commit;
        let mut precommit = Vote::new_with_phase(validator.address, hash, 1, VotePhase::PreCommit);
        precommit.entropy_reveal = Some(reveal);

        prepare.sign(&signing_key).unwrap();
        precommit.sign(&signing_key).unwrap();

        let mut collector = VoteCollector::new();
        collector.add_vote(prepare).unwrap();
        collector.add_vote(precommit).unwrap();
        assert_eq!(
            collector.vote_count_for_phase(1, hash, VotePhase::Prepare),
            1
        );
        assert_eq!(
            collector.vote_count_for_phase(1, hash, VotePhase::PreCommit),
            1
        );
    }

    #[test]
    fn phase_bound_into_signature_prevents_qc_reuse() {
        let signing_key = signing_key(1);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new_with_phase(validator.address, [7u8; 32], 4, VotePhase::Prepare);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let good = QuorumCertificate::new_with_phase(
            vote.block_hash,
            vote.view,
            VotePhase::Prepare,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );
        assert!(good.verify(std::slice::from_ref(&validator), 1).unwrap());

        // Same signatures claimed under PreCommit must fail.
        let bad = QuorumCertificate::new_with_phase(
            vote.block_hash,
            vote.view,
            VotePhase::PreCommit,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );
        assert!(!bad.verify(&[validator], 1).unwrap());
    }

    #[test]
    fn quorum_certificate_verifies_signed_votes_using_view_message() {
        let signing_key = signing_key(1);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [7u8; 32], 4);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );

        assert!(qc
            .verify(&[validator], 1)
            .expect("qc verification should succeed"));
    }

    #[test]
    fn quorum_certificate_rejects_duplicate_validator_entries() {
        let signing_key = signing_key(2);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [9u8; 32], 2);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec(), vote.signature.to_vec()],
            vec![vote.validator, vote.validator],
        );

        assert!(!qc
            .verify(std::slice::from_ref(&validator), 2)
            .expect("qc verification should succeed"));
        assert!(!qc
            .verify_with_voting_power(&[validator], 2, 2)
            .expect("voting power verification should succeed"));
    }

    #[test]
    fn quorum_certificate_bls_helper_verifies_aggregated_signature() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let block_hash = [11u8; 32];
        let view = 3;
        let phase = VotePhase::Prepare;
        let msg = bls_qc_signing_message(&block_hash, view, phase);
        let sig1 = validator_vote_signature(&sk1, &msg).expect("vote signature should succeed");
        let sig2 = validator_vote_signature(&sk2, &msg).expect("vote signature should succeed");
        let mut qc = QuorumCertificate::new(
            block_hash,
            view,
            vec![sig1.0, sig2.0],
            vec![Address([1u8; 32]), Address([2u8; 32])],
        );
        qc.phase = phase;

        assert!(qc
            .verify_bls_aggregate_signature(&[pk1, pk2])
            .expect("bls aggregate verification should succeed"));
        assert!(!qc
            .aggregate_bls_signatures()
            .expect("bls aggregation should succeed")
            .is_empty());
    }

    #[test]
    fn vote_collector_builds_qc_with_view() {
        let signing_key = signing_key(3);
        let validator = validator_from_signing_key(&signing_key);
        let mut vote = Vote::new(validator.address, [5u8; 32], 8);
        vote.sign(&signing_key)
            .expect("vote signing should succeed");

        let mut collector = VoteCollector::new();
        collector
            .add_vote(vote)
            .expect("vote insert should succeed");
        let qc = collector
            .build_quorum_certificate(8, [5u8; 32], 1)
            .expect("qc should be built");

        assert_eq!(qc.view, 8);
    }

    #[test]
    fn vote_collector_prune_removes_old_views() {
        let signing_key = signing_key(4);
        let validator = validator_from_signing_key(&signing_key);
        let mut collector = VoteCollector::new();

        let mut old_vote = Vote::new(validator.address, [1u8; 32], 5);
        old_vote.sign(&signing_key).unwrap();
        collector.add_vote(old_vote).unwrap();

        let mut new_vote = Vote::new(validator.address, [2u8; 32], 15);
        new_vote.sign(&signing_key).unwrap();
        collector.add_vote(new_vote).unwrap();

        assert_eq!(collector.vote_count(5, [1u8; 32]), 1);
        assert_eq!(collector.vote_count(15, [2u8; 32]), 1);

        collector.prune(10);
        assert_eq!(collector.vote_count(5, [1u8; 32]), 0);
        assert_eq!(collector.vote_count(15, [2u8; 32]), 1);
    }
}
