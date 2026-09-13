use crate::error::LightClientError;
use crate::verifier::HeaderVerifier;
use anyhow::Result;
use libp2p::PeerId;
use std::collections::HashSet;
use sxiaum_block::BlockBody;
use sxiaum_block::BlockHeader;
use sxiaum_crypto::ed25519;
use sxiaum_types::{Address, BlockHeight, Hash, Validator};
use tracing::{info, warn};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHeaderEnvelope {
    pub header: BlockHeader,
    pub consensus_signatures: Vec<(Address, [u8; 64])>,
    /// Optional HotStuff `(view, phase_tag)` metadata shared by every
    /// signature in this envelope. A QC is formed within a single view and
    /// phase, so one pair covers the whole certificate. When `None`, all
    /// signatures are verified directly against the header hash.
    pub hotstuff_view_phase: Option<(u64, u8)>,
}

impl VerifiedHeaderEnvelope {
    /// Direct-hash envelope: signatures over the canonical header hash.
    pub fn direct(header: BlockHeader, consensus_signatures: Vec<(Address, [u8; 64])>) -> Self {
        Self {
            header,
            consensus_signatures,
            hotstuff_view_phase: None,
        }
    }

    /// HotStuff vote envelope: signatures over the canonical vote digest for
    /// the given `(view, phase_tag)` (phase: Prepare=0, PreCommit=1, Commit=2).
    pub fn hotstuff(
        header: BlockHeader,
        consensus_signatures: Vec<(Address, [u8; 64])>,
        view: u64,
        phase_tag: u8,
    ) -> Result<Self> {
        if phase_tag > 2 {
            return Err(LightClientError::HeaderValidation(format!(
                "invalid HotStuff phase tag {phase_tag}"
            ))
            .into());
        }
        Ok(Self {
            header,
            consensus_signatures,
            hotstuff_view_phase: Some((view, phase_tag)),
        })
    }
}

/// Helper to rigorously validate the integrity of a trusted or transition validator set.
pub fn validate_validator_set(validator_set: &[Validator]) -> Result<()> {
    if validator_set.is_empty() {
        return Err(LightClientError::InvalidValidatorSet(
            "validator set must not be empty".into(),
        )
        .into());
    }

    let mut seen_addresses = HashSet::new();
    let mut total_active_power = 0u128;

    for v in validator_set {
        if !v.is_active() {
            continue;
        }

        if v.voting_power == 0 {
            return Err(LightClientError::InvalidValidatorSet(format!(
                "active validator {} has zero voting power",
                v.address
            ))
            .into());
        }

        let derived = Address::from_public_key(&v.pubkey);
        if derived != v.address {
            return Err(LightClientError::InvalidValidatorSet(format!(
                "validator {} address does not match public key (derived {})",
                v.address, derived
            ))
            .into());
        }

        ed25519::PublicKey(v.pubkey).validate().map_err(|e| {
            LightClientError::InvalidValidatorSet(format!(
                "validator {} public key is invalid curve point: {:?}",
                v.address, e
            ))
        })?;

        if !seen_addresses.insert(v.address) {
            return Err(LightClientError::InvalidValidatorSet(format!(
                "duplicate validator address in validator set: {}",
                v.address
            ))
            .into());
        }

        total_active_power = total_active_power
            .checked_add(u128::from(v.voting_power))
            .ok_or_else(|| {
                LightClientError::InvalidValidatorSet("validator set voting power overflow".into())
            })?;
    }

    if total_active_power == 0 {
        return Err(LightClientError::InvalidValidatorSet(
            "total active voting power in validator set is zero".into(),
        )
        .into());
    }

    Ok(())
}

/// Orchestrates the verification and retention of block headers for the local light client.
pub struct HeaderSync {
    /// The libp2p PeerId of the full node providing headers.
    pub peer: PeerId,
    /// The current height of the local verified chain.
    pub current_height: BlockHeight,
    /// The store of headers that have passed all cryptographic checks (bounded).
    pub verified_headers: Vec<BlockHeader>,
    /// Cached ZK verification key for block state transitions.
    pub zk_verification_key: Vec<u8>,
    /// Active validator set used for aggregated signature checks.
    pub validator_set: Vec<Validator>,
}

impl HeaderSync {
    /// Creates a new synchronization instance starting from a trusted checkpoint header.
    pub fn new(peer: PeerId, trusted_header: BlockHeader) -> Result<Self> {
        Self::new_with_validator_set(peer, trusted_header, Vec::new())
    }

    pub fn new_with_validator_set(
        peer: PeerId,
        trusted_header: BlockHeader,
        validator_set: Vec<Validator>,
    ) -> Result<Self> {
        let zk_verification_key = HeaderVerifier::load_zk_verification_key()?;
        Self::new_trusted(peer, trusted_header, validator_set, zk_verification_key)
    }

    pub fn new_trusted(
        peer: PeerId,
        trusted_header: BlockHeader,
        validator_set: Vec<Validator>,
        zk_verification_key: Vec<u8>,
    ) -> Result<Self> {
        // Validate trusted header basic structure
        trusted_header.validate_basic().map_err(|e| {
            LightClientError::HeaderValidation(format!(
                "trusted checkpoint header failed basic validation: {:?}",
                e
            ))
        })?;

        if trusted_header.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            return Err(LightClientError::ChainIdMismatch {
                expected: sxiaum_types::SXIAUM_CHAIN_ID,
                actual: trusted_header.chain_id,
            }
            .into());
        }

        if trusted_header.version != sxiaum_block::BLOCK_VERSION_CURRENT {
            return Err(LightClientError::VersionMismatch {
                expected: sxiaum_block::BLOCK_VERSION_CURRENT,
                actual: trusted_header.version,
            }
            .into());
        }

        // Validate validator set integrity
        validate_validator_set(&validator_set)?;

        // Validate ZK verification key
        if zk_verification_key.is_empty() || zk_verification_key.iter().all(|byte| *byte == 0) {
            return Err(LightClientError::InvalidZkVerificationKey.into());
        }

        // Validate validator root linkage if non-zero
        if trusted_header.validator_root != [0u8; 32] {
            let expected_root = BlockBody::compute_validator_root(&validator_set)?;
            if trusted_header.validator_root != expected_root {
                return Err(LightClientError::ValidatorRootMismatch {
                    height: trusted_header.height,
                    header_root: hex::encode(trusted_header.validator_root),
                    computed_root: hex::encode(expected_root),
                }
                .into());
            }
        }

        let current_height = trusted_header.height;
        Ok(Self {
            peer,
            current_height,
            verified_headers: vec![trusted_header],
            zk_verification_key,
            validator_set,
        })
    }

    /// Receive and process a batch of verified header envelopes from network.
    pub fn receive_verified_headers(&mut self, headers: Vec<VerifiedHeaderEnvelope>) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        if headers.len() > crate::MAX_HEADER_BATCH_SIZE {
            return Err(LightClientError::BatchSizeExceeded {
                size: headers.len(),
                max: crate::MAX_HEADER_BATCH_SIZE,
            }
            .into());
        }

        info!(
            "Received batch of {} headers from peer {}.",
            headers.len(),
            self.peer
        );

        let mut sorted_headers = headers;
        sorted_headers.sort_by_key(|h| h.header.height);

        self.process_verified_batch(sorted_headers)?;
        Ok(())
    }

    /// Atomic batch verification:
    /// All headers in the batch must pass cryptographic verification against the chain
    /// before any state is mutated. If any header fails, the entire batch is rejected
    /// leaving local trusted state uncorrupted.
    fn process_verified_batch(&mut self, batch: Vec<VerifiedHeaderEnvelope>) -> Result<()> {
        validate_validator_set(&self.validator_set)?;

        let expected_validator_root = BlockBody::compute_validator_root(&self.validator_set)?;
        let mut simulated_height = self.current_height;
        let mut last_parent = self.verified_headers.last().cloned().ok_or_else(|| {
            LightClientError::HeaderLinkage("missing parent header in verified history".into())
        })?;

        let mut verified_staged = Vec::with_capacity(batch.len());

        for envelope in batch {
            let header = envelope.header;
            let expected_height = simulated_height.checked_add(1).ok_or_else(|| {
                LightClientError::HeaderLinkage(format!(
                    "Height sequence overflow at height {}",
                    simulated_height
                ))
            })?;

            if header.height != expected_height {
                warn!(
                    "Received invalid header sequence: height={}, expected={}",
                    header.height, expected_height
                );
                return Err(LightClientError::HeightMismatch {
                    expected: expected_height,
                    actual: header.height,
                }
                .into());
            }

            let proposer_pk = self
                .validator_set
                .iter()
                .find(|validator| validator.address == header.proposer && validator.is_active())
                .map(|validator| validator.pubkey)
                .ok_or_else(|| LightClientError::UnknownOrInactiveValidator(header.proposer))?;

            // 1. Full header cryptographic validation (linkage, proposer sig, ZK STF proof)
            HeaderVerifier::validate_header_full(
                &header,
                &last_parent,
                &proposer_pk,
                &self.zk_verification_key,
            )?;

            // 2. Validator root match against active validator set
            if header.validator_root != expected_validator_root {
                return Err(LightClientError::ValidatorRootMismatch {
                    height: header.height,
                    header_root: hex::encode(header.validator_root),
                    computed_root: hex::encode(expected_validator_root),
                }
                .into());
            }

            // 3. Consensus 2/3+ quorum signatures
            let header_hash = header.try_hash()?;
            HeaderVerifier::verify_consensus_signatures(
                header_hash,
                &envelope.consensus_signatures,
                &self.validator_set,
                header.height,
                envelope.hotstuff_view_phase,
            )?;

            simulated_height = header.height;
            last_parent = header.clone();
            verified_staged.push(header);
        }

        // All checks succeeded: atomically commit batch to local trusted state
        for header in verified_staged {
            self.current_height = header.height;
            self.verified_headers.push(header);
        }

        // Bounded memory retention: prune oldest headers if exceeding cap
        if self.verified_headers.len() > crate::MAX_RETAINED_HEADERS {
            let excess = self.verified_headers.len() - crate::MAX_RETAINED_HEADERS;
            self.verified_headers.drain(0..excess);
        }

        info!(
            "Header sync progress: successfully verified up to height {}.",
            self.current_height
        );
        Ok(())
    }

    /// Authenticated validator set transition:
    /// Updates the trusted validator set ONLY if the new validator set's root
    /// matches the `validator_root` committed in the latest verified block header.
    pub fn transition_validator_set(&mut self, new_validator_set: Vec<Validator>) -> Result<()> {
        validate_validator_set(&new_validator_set)?;

        let latest_header = self
            .latest_verified_header()
            .ok_or_else(|| LightClientError::NoVerifiedHeader)?;

        let new_root = BlockBody::compute_validator_root(&new_validator_set)?;
        if latest_header.validator_root != new_root {
            return Err(LightClientError::ValidatorSetTransitionRejected {
                height: latest_header.height,
                new_root: hex::encode(new_root),
                header_root: hex::encode(latest_header.validator_root),
            }
            .into());
        }

        info!(
            "Validator set transitioned successfully at height {}: {} active validators (root: 0x{})",
            latest_header.height,
            new_validator_set.len(),
            hex::encode(new_root)
        );
        self.validator_set = new_validator_set;
        Ok(())
    }

    pub fn update_peer(&mut self, peer: PeerId) {
        self.peer = peer;
    }

    /// Returns the current trusted tip of the light client's synced chain.
    pub fn current_chain_tip(&self) -> (BlockHeight, Option<Hash>) {
        let last_header = self.latest_verified_header();
        (
            self.current_height,
            last_header.and_then(|h| h.try_hash().ok()),
        )
    }

    /// Retrieve the current verified head of the synced header chain.
    pub fn latest_verified_header(&self) -> Option<&BlockHeader> {
        self.verified_headers.last()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use primitive_types::U256;
    use sha2::{Digest, Sha256};
    use sxiaum_types::{validator::ValidatorStatus, Address};

    fn mock_sp1_commitment(public_inputs: &[u8], verification_key: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(verification_key);
        hasher.update(public_inputs);
        let execution_trace = hasher.finalize_reset();

        hasher.update(b"sp1:pk");
        hasher.update(verification_key);
        let proving_key = hasher.finalize_reset();

        hasher.update(proving_key);
        hasher.update(execution_trace);
        hasher.update(public_inputs);
        hasher.finalize().to_vec()
    }

    #[test]
    fn test_header_sync_batch_processing_and_validation() {
        let signer = SigningKey::from_bytes(&[10u8; 32]);
        let pk = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&pk);
        let zk_vk = vec![0x22; 128];

        let mut v = Validator::new(proposer, pk, U256::from(100));
        v.voting_power = 1;
        v.status = ValidatorStatus::Active;
        let validator_set = vec![v];

        let genesis = BlockHeader::genesis();
        let peer = PeerId::random();
        let mut sync =
            HeaderSync::new_trusted(peer, genesis.clone(), validator_set.clone(), zk_vk.clone())
                .unwrap();

        let mut h1 = BlockHeader::new(genesis.try_hash().unwrap(), 1);
        h1.proposer = proposer;
        h1.timestamp = genesis.timestamp + 1;
        h1.validator_root = BlockBody::compute_validator_root(&validator_set).unwrap();
        let unsigned1 = h1.try_hash().unwrap();
        h1.zk_proof = Some(mock_sp1_commitment(&unsigned1, &zk_vk));
        let hash1 = h1.try_hash().unwrap();
        h1.signature = Some(signer.sign(&hash1).to_bytes());

        let envelope1 = VerifiedHeaderEnvelope::direct(
            h1.clone(),
            vec![(proposer, signer.sign(&hash1).to_bytes())],
        );

        // Sync batch with h1
        sync.receive_verified_headers(vec![envelope1]).unwrap();
        assert_eq!(sync.current_height, 1);
        assert_eq!(sync.current_chain_tip().0, 1);
        assert_eq!(sync.current_chain_tip().1, Some(hash1));

        // Out-of-order header (height 3 instead of 2) -> rejected
        let mut h3 = BlockHeader::new(hash1, 3);
        h3.proposer = proposer;
        h3.timestamp = h1.timestamp + 2;
        h3.validator_root = BlockBody::compute_validator_root(&validator_set).unwrap();
        let unsigned3 = h3.try_hash().unwrap();
        h3.zk_proof = Some(mock_sp1_commitment(&unsigned3, &zk_vk));
        let hash3 = h3.try_hash().unwrap();
        h3.signature = Some(signer.sign(&hash3).to_bytes());

        let envelope3 =
            VerifiedHeaderEnvelope::direct(h3, vec![(proposer, signer.sign(&hash3).to_bytes())]);
        assert!(sync.receive_verified_headers(vec![envelope3]).is_err());
        // Stays at height 1 (atomic)
        assert_eq!(sync.current_height, 1);
    }

    #[test]
    fn test_rejects_empty_or_zero_trusted_params() {
        let genesis = BlockHeader::genesis();
        let peer = PeerId::random();

        // Empty validator set
        let err1 = HeaderSync::new_trusted(peer, genesis.clone(), vec![], vec![1u8; 128]);
        assert!(err1.is_err());

        // Zeroed ZK VK
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let addr = Address::from_public_key(&pk);
        let mut v = Validator::new(addr, pk, U256::from(1));
        v.voting_power = 1;
        let err2 = HeaderSync::new_trusted(peer, genesis, vec![v], vec![0u8; 128]);
        assert!(err2.is_err());
    }

    #[test]
    fn test_atomic_batch_rollback_on_failure() {
        let signer = SigningKey::from_bytes(&[20u8; 32]);
        let pk = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&pk);
        let zk_vk = vec![0x33; 128];

        let mut v = Validator::new(proposer, pk, U256::from(100));
        v.voting_power = 1;
        v.status = ValidatorStatus::Active;
        let validator_set = vec![v];

        let genesis = BlockHeader::genesis();
        let peer = PeerId::random();
        let mut sync =
            HeaderSync::new_trusted(peer, genesis.clone(), validator_set.clone(), zk_vk.clone())
                .unwrap();

        // Build valid header 1
        let mut h1 = BlockHeader::new(genesis.try_hash().unwrap(), 1);
        h1.proposer = proposer;
        h1.timestamp = genesis.timestamp + 1;
        h1.validator_root = BlockBody::compute_validator_root(&validator_set).unwrap();
        let unsigned1 = h1.try_hash().unwrap();
        h1.zk_proof = Some(mock_sp1_commitment(&unsigned1, &zk_vk));
        let hash1 = h1.try_hash().unwrap();
        h1.signature = Some(signer.sign(&hash1).to_bytes());

        let env1 = VerifiedHeaderEnvelope::direct(
            h1.clone(),
            vec![(proposer, signer.sign(&hash1).to_bytes())],
        );

        // Build invalid header 2 (bad signature)
        let mut h2 = BlockHeader::new(hash1, 2);
        h2.proposer = proposer;
        h2.timestamp = h1.timestamp + 1;
        h2.validator_root = BlockBody::compute_validator_root(&validator_set).unwrap();
        let unsigned2 = h2.try_hash().unwrap();
        h2.zk_proof = Some(mock_sp1_commitment(&unsigned2, &zk_vk));
        let hash2 = h2.try_hash().unwrap();
        h2.signature = Some(signer.sign(&hash2).to_bytes());

        let env2_bad = VerifiedHeaderEnvelope::direct(h2, vec![(proposer, [0xff; 64])]); // Bad signature

        // Batch of [env1, env2_bad] must fail completely and not advance height
        let res = sync.receive_verified_headers(vec![env1, env2_bad]);
        assert!(res.is_err());
        assert_eq!(sync.current_height, 0);
        assert_eq!(sync.verified_headers.len(), 1);
    }
}
