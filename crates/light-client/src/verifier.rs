use anyhow::{bail, Result};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use sxiaum_block::BlockHeader;
use sxiaum_crypto::ed25519;
use sxiaum_crypto::hash::{domain_hash, DOMAIN_CONSENSUS};
use sxiaum_types::{Address, Hash, Validator};
use tracing::debug;

use crate::error::LightClientError;

/// Compute the canonical HotStuff vote signing message digest.
///
/// Byte layout and domain separation MUST stay identical to
/// `sxiaum_consensus::hotstuff::vote_signing_message`:
/// `[validator(32) || block_hash(32) || view_le(8) || phase_tag(1)]`,
/// hashed with `domain_hash(DOMAIN_CONSENSUS, ...)`. A cross-crate
/// known-answer test in this crate pins the two implementations together.
pub fn hotstuff_vote_digest(
    validator: Address,
    block_hash: &[u8; 32],
    view: u64,
    phase_tag: u8,
) -> [u8; 32] {
    let mut bytes = [0u8; 73];
    bytes[..32].copy_from_slice(validator.as_bytes());
    bytes[32..64].copy_from_slice(block_hash);
    bytes[64..72].copy_from_slice(&view.to_le_bytes());
    bytes[72] = phase_tag;
    domain_hash(DOMAIN_CONSENSUS, &bytes)
}

/// A specialized verifier for the SXIAUM light client to ensure headers are cryptographically secure.
pub struct HeaderVerifier;

impl HeaderVerifier {
    /// Verify that a candidate header properly extends a known parent.
    pub fn verify_linkage(header: &BlockHeader, parent: &BlockHeader) -> Result<()> {
        // Enforce basic structural constraints on candidate header.
        header
            .validate_basic()
            .map_err(|e| LightClientError::HeaderValidation(e.to_string()))?;

        let expected_height = parent.height.checked_add(1).ok_or_else(|| {
            LightClientError::HeaderLinkage(format!(
                "Height arithmetic overflow at parent height {}",
                parent.height
            ))
        })?;

        if header.height != expected_height {
            return Err(LightClientError::HeightMismatch {
                expected: expected_height,
                actual: header.height,
            }
            .into());
        }

        let parent_hash = parent.try_hash()?;
        if !header.verify_parent(parent_hash) {
            return Err(LightClientError::ParentHashMismatch {
                height: header.height,
                expected: hex::encode(parent_hash),
                actual: hex::encode(header.parent_hash),
            }
            .into());
        }

        if !header.verify_timestamp(parent.timestamp) {
            return Err(LightClientError::TimestampRegression {
                height: header.height,
                header_time: header.timestamp,
                parent_time: parent.timestamp,
            }
            .into());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if header.timestamp > now.saturating_add(crate::MAX_TIMESTAMP_DRIFT_SECS) {
            return Err(LightClientError::FutureTimestamp {
                height: header.height,
                timestamp: header.timestamp,
                now,
                max_drift: crate::MAX_TIMESTAMP_DRIFT_SECS,
            }
            .into());
        }

        Ok(())
    }

    /// Verify the canonical proposer's signature on the header.
    pub fn verify_proposer_signature(
        header: &BlockHeader,
        public_key_bytes: &[u8; 32],
    ) -> Result<bool> {
        if public_key_bytes.iter().all(|&b| b == 0) {
            return Err(LightClientError::ZeroProposerPublicKey.into());
        }

        let derived_proposer = Address::from_public_key(public_key_bytes);
        if header.proposer != derived_proposer {
            return Err(LightClientError::ProposerAddressMismatch {
                header_proposer: header.proposer,
                derived_proposer,
            }
            .into());
        }

        header.verify_signature(public_key_bytes).map_err(|e| {
            LightClientError::InvalidProposerSignature {
                height: header.height,
                reason: e.to_string(),
            }
            .into()
        })
    }

    /// Verify a quorum of consensus signatures for BFT finality verification using voting power.
    ///
    /// Each signature is accepted in exactly one of two modes:
    /// 1. **Direct mode** — signature over the canonical header hash.
    /// 2. **HotStuff vote mode** — signature over the canonical HotStuff vote
    ///    digest for `(view, phase)` supplied by the caller via
    ///    `hotstuff_view_phase`. When no metadata is supplied, only direct
    ///    signatures are accepted: the light client never guesses view/phase
    ///    values (a brute-force fallback would both amplify DoS cost ~100x per
    ///    bogus signature and accept non-canonical vote messages).
    pub fn verify_consensus_signatures(
        header_hash: Hash,
        signatures: &[(Address, [u8; 64])],
        validator_set: &[Validator],
        height: sxiaum_types::BlockHeight,
        hotstuff_view_phase: Option<(u64, u8)>,
    ) -> Result<bool> {
        if validator_set.is_empty() {
            return Err(LightClientError::InvalidValidatorSet(
                "trusted validator set is empty".into(),
            )
            .into());
        }

        if signatures.is_empty() {
            return Err(LightClientError::MissingConsensusSignatures { height }.into());
        }

        if signatures.len() > validator_set.len() {
            bail!(
                "signature count ({}) exceeds trusted validator set size ({})",
                signatures.len(),
                validator_set.len()
            );
        }

        // Validate phase_tag up-front when provided (canonical phases 0..=2).
        if let Some((_, phase)) = hotstuff_view_phase {
            if phase > 2 {
                bail!("invalid HotStuff phase tag {phase} (expected 0, 1, or 2)");
            }
        }

        // 1. Calculate the total voting power of the active validator set and validate keys.
        let mut validator_addresses = HashSet::new();
        let mut total_active_power = 0u128;

        for validator in validator_set {
            if !validator.is_active() {
                continue;
            }

            if validator.voting_power == 0 {
                return Err(LightClientError::InvalidValidatorSet(format!(
                    "active validator {} has zero voting power",
                    validator.address
                ))
                .into());
            }

            let derived_addr = Address::from_public_key(&validator.pubkey);
            if derived_addr != validator.address {
                return Err(LightClientError::InvalidValidatorSet(format!(
                    "validator address mismatch for {}: derived {} from public key",
                    validator.address, derived_addr
                ))
                .into());
            }

            ed25519::PublicKey(validator.pubkey)
                .validate()
                .map_err(|e| {
                    LightClientError::InvalidValidatorSet(format!(
                        "validator {} public key is invalid curve point: {:?}",
                        validator.address, e
                    ))
                })?;

            if !validator_addresses.insert(validator.address) {
                return Err(LightClientError::InvalidValidatorSet(format!(
                    "duplicate validator address in trusted validator set: {}",
                    validator.address
                ))
                .into());
            }

            total_active_power = total_active_power
                .checked_add(u128::from(validator.voting_power))
                .ok_or_else(|| {
                    LightClientError::InvalidValidatorSet(
                        "validator voting power arithmetic overflow".into(),
                    )
                })?;
        }

        if total_active_power == 0 {
            return Err(LightClientError::InvalidValidatorSet(
                "total active voting power in validator set is zero".into(),
            )
            .into());
        }

        let quorum_threshold = (total_active_power
            .checked_mul(2)
            .ok_or_else(|| anyhow::anyhow!("quorum multiplication overflow"))?
            / 3)
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("quorum addition overflow"))?;

        let mut verified_voting_power = 0u128;
        let mut seen_signers = HashSet::new();
        let active_validator_map: std::collections::HashMap<Address, &Validator> = validator_set
            .iter()
            .filter(|v| v.is_active() && v.voting_power > 0)
            .map(|v| (v.address, v))
            .collect();

        // 2. Cryptographically verify each signature and accumulate voting power.
        for (address, sig_bytes) in signatures {
            if !seen_signers.insert(*address) {
                return Err(LightClientError::DuplicateConsensusSignature(*address).into());
            }

            let validator = active_validator_map
                .get(address)
                .ok_or_else(|| LightClientError::UnknownOrInactiveValidator(*address))?;

            // Mode 1: direct signature over the header hash.
            let mut valid = ed25519::verify(&validator.pubkey, &header_hash, sig_bytes);

            // Mode 2: canonical HotStuff vote digest for the explicitly
            // supplied (view, phase) — verified once, never guessed.
            if !valid {
                if let Some((view, phase)) = hotstuff_view_phase {
                    let digest = hotstuff_vote_digest(*address, &header_hash, view, phase);
                    valid = ed25519::verify(&validator.pubkey, &digest, sig_bytes);
                }
            }

            if !valid {
                return Err(LightClientError::InvalidConsensusSignature {
                    validator: *address,
                    header_hash: hex::encode(header_hash),
                }
                .into());
            }

            verified_voting_power = verified_voting_power
                .checked_add(u128::from(validator.voting_power))
                .ok_or_else(|| anyhow::anyhow!("verified voting power overflow"))?;
        }

        // 3. Ensure the cryptographic quorum reflects more than 2/3 of the total active voting power.
        if verified_voting_power < quorum_threshold {
            return Err(LightClientError::ConsensusQuorumFailed {
                weight: verified_voting_power,
                required: quorum_threshold,
                total: total_active_power,
            }
            .into());
        }

        debug!(
            "Cryptographic quorum reached: power={}/{} for header 0x{}",
            verified_voting_power,
            total_active_power,
            hex::encode(header_hash)
        );
        Ok(true)
    }

    /// Load the official ZK verification key for the SXIAUM block STF.
    pub fn load_zk_verification_key() -> Result<Vec<u8>> {
        let env_key = std::env::var("SXIAUM_SP1_VERIFICATION_KEY")
            .or_else(|_| std::env::var("SP1_VERIFICATION_KEY"));

        match env_key {
            Ok(encoded) => {
                let key = hex::decode(encoded.trim_start_matches("0x"))?;
                if key.is_empty() || key.iter().all(|byte| *byte == 0) {
                    return Err(LightClientError::InvalidZkVerificationKey.into());
                }
                Ok(key)
            }
            Err(_) => {
                if sxiaum_zk::is_production() {
                    bail!("SXIAUM_SP1_VERIFICATION_KEY is required in production mode");
                }
                // Canonical development / test verification key
                Ok(sxiaum_zk::canonical_sp1_program_vk())
            }
        }
    }

    /// LC Step 2+3 - Retrieve the ZK proof from the header and verify it using the verifier key.
    pub fn verify_zk_validity_proof(header: &BlockHeader, verification_key: &[u8]) -> Result<bool> {
        if verification_key.is_empty() || verification_key.iter().all(|byte| *byte == 0) {
            return Err(LightClientError::InvalidZkVerificationKey.into());
        }

        if sxiaum_zk::is_placeholder_vk_hash(&hex::encode(verification_key)) {
            return Err(LightClientError::InvalidZkVerificationKey.into());
        }

        let proof_bytes = header
            .zk_proof
            .as_ref()
            .ok_or_else(|| LightClientError::MissingZkProof(header.height))?;

        if proof_bytes.is_empty() {
            return Err(LightClientError::EmptyZkProof(header.height).into());
        }

        if proof_bytes.len() > sxiaum_block::MAX_ZK_PROOF_SIZE {
            return Err(LightClientError::ZkProofTooLarge {
                size: proof_bytes.len(),
                max: sxiaum_block::MAX_ZK_PROOF_SIZE,
            }
            .into());
        }

        let mut header_commitment = header.clone();
        header_commitment.zk_proof = None;
        let header_hash = header_commitment.try_hash()?;

        let verifier = if sxiaum_zk::is_production() {
            sxiaum_zk::Sp1Verifier::new_mainnet(verification_key.to_owned())
        } else {
            sxiaum_zk::Sp1Verifier::new(verification_key.to_owned())
        };

        if let Ok(sp1_proof) = bincode::deserialize::<sxiaum_zk::Sp1Proof>(proof_bytes) {
            match sxiaum_zk::ZkPublicInputs::decode(&sp1_proof.public_inputs) {
                Ok(pi) => {
                    if pi.chain_id != header.chain_id {
                        return Err(LightClientError::ChainIdMismatch {
                            expected: header.chain_id,
                            actual: pi.chain_id,
                        }
                        .into());
                    }
                    if sxiaum_zk::is_production() && pi.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
                        return Err(LightClientError::ChainIdMismatch {
                            expected: sxiaum_types::SXIAUM_CHAIN_ID,
                            actual: pi.chain_id,
                        }
                        .into());
                    }
                    if pi.protocol_version != header.version {
                        return Err(LightClientError::VersionMismatch {
                            expected: header.version,
                            actual: pi.protocol_version,
                        }
                        .into());
                    }
                    if pi.circuit_version != sxiaum_zk::STF_CIRCUIT_VERSION {
                        bail!(
                            "proof circuit_version {} != supported {}",
                            pi.circuit_version,
                            sxiaum_zk::STF_CIRCUIT_VERSION
                        );
                    }
                    if pi.block_height != header.height {
                        bail!(
                            "proof block_height {} != header height {}",
                            pi.block_height,
                            header.height
                        );
                    }
                    if pi.parent_hash != header.parent_hash {
                        bail!("proof parent_hash != header parent_hash");
                    }
                    if pi.state_root_after != header.state_root {
                        bail!("proof state_root_after != header state_root");
                    }
                    if pi.tx_root != header.tx_root {
                        bail!("proof tx_root != header tx_root");
                    }
                    if pi.receipts_root != header.receipts_root {
                        bail!("proof receipts_root != header receipts_root");
                    }
                    if pi.beacon_randomness != header.randomness_beacon {
                        bail!("proof beacon_randomness != header randomness_beacon");
                    }
                }
                Err(e) => {
                    if sxiaum_zk::is_production() {
                        return Err(LightClientError::ZkVerificationFailed {
                            height: header.height,
                            reason: format!(
                                "failed to decode canonical ZkPublicInputs in production: {}",
                                e
                            ),
                        }
                        .into());
                    }
                    // Non-production fallback for simulated 32-byte header hashes
                    if sp1_proof.public_inputs != header_hash {
                        bail!("simulated proof public_inputs != header hash");
                    }
                }
            }

            verifier.validate_proof_structure(&sp1_proof).map_err(|e| {
                LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                }
            })?;

            verifier
                .verify_execution_trace_commitments(&sp1_proof, &sp1_proof.public_inputs)
                .map_err(|e| LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                })?;

            verifier
                .verify_polynomial_constraints(&sp1_proof, &sp1_proof.public_inputs)
                .map_err(|e| LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                })?;

            verifier
                .verify_final_proof_validity(&sp1_proof, &sp1_proof.public_inputs)
                .map_err(|e| LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                })?;
        } else {
            if sxiaum_zk::is_production() {
                return Err(LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: "invalid serialized Sp1Proof in production mode".into(),
                }
                .into());
            }
            let sp1_proof = sxiaum_zk::Sp1Proof {
                proof_bytes: proof_bytes.to_vec(),
                public_inputs: header_hash.to_vec(),
                compressed: false,
                proof_system: sxiaum_zk::Sp1ProofSystem::SimulatedSha256,
                verkle_proofs: vec![],
                vk_hash: None,
            };

            verifier.validate_proof_structure(&sp1_proof).map_err(|e| {
                LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                }
            })?;

            verifier
                .verify_execution_trace_commitments(&sp1_proof, &header_hash)
                .map_err(|e| LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                })?;

            verifier
                .verify_polynomial_constraints(&sp1_proof, &header_hash)
                .map_err(|e| LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                })?;

            verifier
                .verify_final_proof_validity(&sp1_proof, &header_hash)
                .map_err(|e| LightClientError::ZkVerificationFailed {
                    height: header.height,
                    reason: e.to_string(),
                })?;
        }

        Ok(true)
    }

    /// High-level entry point for confirming that a block header represents a valid state transition via ZK.
    pub fn confirm_state_transition_validity(
        header: &BlockHeader,
        verification_key: &[u8],
    ) -> Result<bool> {
        Self::verify_zk_validity_proof(header, verification_key)
    }

    /// Perform a full structural and cryptographic validation of a header.
    pub fn validate_header_full(
        header: &BlockHeader,
        parent: &BlockHeader,
        proposer_public_key: &[u8; 32],
        zk_verification_key: &[u8],
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Comprehensive canonical mainnet validation (gas bounds, versions, chain ID, sizes)
        header.validate_mainnet(now)?;

        // 2. Non-genesis proposer cannot be zero
        if header.height > 0 && header.proposer.is_zero() {
            bail!(
                "non-genesis header at height {} has zero proposer address",
                header.height
            );
        }

        // 3. Header linkage to parent
        Self::verify_linkage(header, parent)?;

        // 4. Proposer cryptographic signature
        if !Self::verify_proposer_signature(header, proposer_public_key)? {
            return Err(LightClientError::InvalidProposerSignature {
                height: header.height,
                reason: "proposer signature check failed".into(),
            }
            .into());
        }

        // 5. ZK state transition validity proof
        if !Self::confirm_state_transition_validity(header, zk_verification_key)? {
            return Err(LightClientError::ZkVerificationFailed {
                height: header.height,
                reason: "ZK STF proof invalid".into(),
            }
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use sxiaum_types::validator::ValidatorStatus;

    fn single_validator(sk_byte: u8, power: u64) -> (ed25519_dalek::SigningKey, Vec<Validator>) {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[sk_byte; 32]);
        let pk = signer.verifying_key().to_bytes();
        let address = Address::from_public_key(&pk);
        let mut v = Validator::new(address, pk, power.into());
        v.status = ValidatorStatus::Active;
        v.voting_power = power;
        (signer, vec![v])
    }

    /// Cross-crate known-answer test: the light client's HotStuff vote digest
    /// MUST be byte-identical to the consensus engine's canonical
    /// `vote_signing_message` for every (view, phase) combination.
    #[test]
    fn hotstuff_digest_matches_consensus_engine() {
        use sxiaum_consensus::hotstuff::vote::{vote_signing_message, VotePhase};

        let validator = Address([7u8; 32]);
        let block_hash = [0xabu8; 32];

        for view in [0u64, 1, 17, 4_242, u64::MAX] {
            for (phase_tag, phase) in [
                (0u8, VotePhase::Prepare),
                (1u8, VotePhase::PreCommit),
                (2u8, VotePhase::Commit),
            ] {
                assert_eq!(
                    hotstuff_vote_digest(validator, &block_hash, view, phase_tag),
                    vote_signing_message(validator, &block_hash, view, phase),
                    "digest mismatch at view={view} phase={phase_tag}"
                );
            }
        }
    }

    #[test]
    fn hotstuff_qc_signature_verifies_with_metadata() {
        let (signer, validator_set) = single_validator(42, 10);
        let pk = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&pk);
        let header_hash: Hash = [0xcd; 32];

        // Sign exactly like the consensus engine would.
        let digest = hotstuff_vote_digest(proposer, &header_hash, 5, 2);
        let sig = signer.sign(&digest).to_bytes();

        // With explicit (view, phase) metadata the QC must verify...
        let ok = HeaderVerifier::verify_consensus_signatures(
            header_hash,
            &[(proposer, sig)],
            &validator_set,
            7,
            Some((5, 2)),
        );
        assert!(ok.expect("hotstuff qc should verify"));

        // ...and WITHOUT metadata it must fail (no view/phase guessing).
        let direct_only = HeaderVerifier::verify_consensus_signatures(
            header_hash,
            &[(proposer, sig)],
            &validator_set,
            7,
            None,
        );
        assert!(
            direct_only.is_err(),
            "hotstuff signature must not verify without explicit metadata"
        );
    }

    #[test]
    fn rejects_invalid_phase_and_duplicate_signers() {
        let (signer, validator_set) = single_validator(43, 10);
        let pk = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&pk);
        let header_hash: Hash = [0x11u8; 32];
        let sig = signer.sign(&header_hash).to_bytes();

        // Phase tag > 2 is rejected up-front.
        let bad_phase = HeaderVerifier::verify_consensus_signatures(
            header_hash,
            &[(proposer, sig)],
            &validator_set,
            3,
            Some((0, 9)),
        );
        assert!(bad_phase.is_err());

        // Duplicate signer is rejected.
        let dup = HeaderVerifier::verify_consensus_signatures(
            header_hash,
            &[(proposer, sig), (proposer, sig)],
            &validator_set,
            3,
            None,
        );
        assert!(dup.is_err());

        // Empty signatures report the real height in the error.
        let empty =
            HeaderVerifier::verify_consensus_signatures(header_hash, &[], &validator_set, 77, None)
                .unwrap_err();
        assert!(empty.to_string().contains("77"), "got: {empty}");
    }
}
