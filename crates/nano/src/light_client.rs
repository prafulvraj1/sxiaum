//! Profile 1: `NanoLightClient` (Zero-Execution Edge Client).
//!
//! Designed for smartphones (iOS/Android), IoT telemetry devices, smartwatches,
//! and WebAssembly browser dApps. Verifies block headers, BFT quorums, and
//! spot-checks account state and smart contract storage in memory with **0 MB disk**.

use crate::epoch_sync::{
    EpochHandoverCertificate, EpochSyncManager, ValidatorSignature, WeakSubjectivityCheckpoint,
};
use crate::error::NanoError;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use sxiaum_block::BlockHeader;
use sxiaum_state::{storage_proof_key, VerkleProof};
use sxiaum_types::{Account, Address, Hash, Validator};

/// Maximum allowable future timestamp drift for edge verification.
///
/// Defaults to the canonical mainnet bound enforced by
/// [`sxiaum_block::MAX_FUTURE_BLOCK_TIME_SECS`] (5 seconds), so nano devices
/// apply exactly the same clock-skew rule as full mainnet validators. Note
/// that `sxiaum_block::BlockHeader::validate_mainnet` (invoked on every
/// verified header) always enforces the canonical 5-second bound regardless
/// of this setting; a *lower* configured value here adds extra strictness.
pub const DEFAULT_MAX_TIMESTAMP_DRIFT: u64 = sxiaum_block::MAX_FUTURE_BLOCK_TIME_SECS;
/// Default size of in-memory FIFO header buffer.
pub const DEFAULT_RING_BUFFER_CAPACITY: usize = 128;

/// Serde default pinning nano configs to the canonical mainnet chain id.
fn default_config_chain_id() -> u64 {
    sxiaum_types::SXIAUM_CHAIN_ID
}

/// Configuration for initializing a `NanoLightClient`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NanoLightConfig {
    pub genesis_state_root: Hash,
    pub initial_validator_set: Vec<Validator>,
    pub ring_buffer_capacity: usize,
    pub max_timestamp_drift_secs: u64,
    /// Replay-protection chain identifier. Must equal the canonical
    /// [`sxiaum_types::SXIAUM_CHAIN_ID`] (13689) on mainnet; constructors
    /// reject any other value.
    #[serde(default = "default_config_chain_id")]
    pub chain_id: u64,
}

impl Default for NanoLightConfig {
    fn default() -> Self {
        Self {
            genesis_state_root: [0u8; 32],
            initial_validator_set: Vec::new(),
            ring_buffer_capacity: DEFAULT_RING_BUFFER_CAPACITY,
            max_timestamp_drift_secs: DEFAULT_MAX_TIMESTAMP_DRIFT,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
        }
    }
}

/// Zero-Disk, memory-bounded light client verifying consensus and Verkle state proofs.
#[derive(Clone, Debug)]
pub struct NanoLightClient {
    pub epoch_manager: EpochSyncManager,
    pub header_buffer: VecDeque<BlockHeader>,
    pub latest_verified_header: Option<BlockHeader>,
    pub config: NanoLightConfig,
}

impl NanoLightClient {
    /// Create a new `NanoLightClient` at genesis with the initial trusted validator set.
    ///
    /// Mainnet-ready: rejects configurations pinning a chain id other than the
    /// canonical [`sxiaum_types::SXIAUM_CHAIN_ID`].
    pub fn new(config: NanoLightConfig) -> Result<Self, NanoError> {
        if config.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            return Err(NanoError::UnsupportedChainId {
                configured: config.chain_id,
                canonical: sxiaum_types::SXIAUM_CHAIN_ID,
            });
        }
        let epoch_manager = EpochSyncManager::new(0, config.initial_validator_set.clone())?;
        Ok(Self {
            epoch_manager,
            header_buffer: VecDeque::with_capacity(config.ring_buffer_capacity),
            latest_verified_header: None,
            config,
        })
    }

    /// Bootstrap from an out-of-band Weak Subjectivity Checkpoint.
    pub fn from_checkpoint(
        checkpoint: WeakSubjectivityCheckpoint,
        config: NanoLightConfig,
        current_time: u64,
        max_unbonding_secs: u64,
    ) -> Result<Self, NanoError> {
        let mut epoch_manager =
            EpochSyncManager::new(checkpoint.epoch, checkpoint.validator_set.clone())?;
        epoch_manager.verify_and_apply_checkpoint(
            &checkpoint,
            current_time,
            max_unbonding_secs,
        )?;

        Ok(Self {
            epoch_manager,
            header_buffer: VecDeque::with_capacity(config.ring_buffer_capacity),
            latest_verified_header: None,
            config,
        })
    }

    /// Verify a candidate block header against parent linkage, proposer Ed25519 signature,
    /// and BFT Quorum Certificate signatures, appending it to the in-memory ring buffer.
    pub fn verify_and_append_header(
        &mut self,
        header: BlockHeader,
        signatures: &[ValidatorSignature],
        hotstuff_meta: Option<(u64, u8)>,
        current_time: u64,
    ) -> Result<Hash, NanoError> {
        // 1. Mainnet-strict structural validation: canonical protocol version,
        //    replay-protection chain id, gas bounds, genesis timestamp floor,
        //    proposer presence, and the canonical 5s future-time bound.
        header
            .validate_mainnet(current_time)
            .map_err(|e| NanoError::ValidationFailed {
                height: header.height,
                reason: e.to_string(),
            })?;

        // 1b. Explicit chain-id replay protection (defense in depth).
        if header.chain_id != self.config.chain_id {
            return Err(NanoError::ChainIdMismatch {
                height: header.height,
                expected: self.config.chain_id,
                actual: header.chain_id,
            });
        }

        // 2. Linkage validation against latest verified parent (if present)
        if let Some(parent) = &self.latest_verified_header {
            let expected_height = parent.height.saturating_add(1);
            if header.height != expected_height {
                return Err(NanoError::HeightMismatch {
                    expected: expected_height,
                    actual: header.height,
                });
            }

            let parent_hash = parent
                .try_hash()
                .map_err(|e| NanoError::Crypto(e.to_string()))?;
            if !header.verify_parent(parent_hash) {
                return Err(NanoError::ParentHashMismatch {
                    height: header.height,
                    expected: hex::encode(parent_hash),
                    actual: hex::encode(header.parent_hash),
                });
            }

            if !header.verify_timestamp(parent.timestamp) {
                return Err(NanoError::TimestampRegression {
                    height: header.height,
                    header_time: header.timestamp,
                    parent_time: parent.timestamp,
                });
            }
        }

        // 3. Check future timestamp bounds
        if header.timestamp
            > current_time.saturating_add(self.config.max_timestamp_drift_secs)
        {
            return Err(NanoError::FutureTimestamp {
                height: header.height,
                timestamp: header.timestamp,
                now: current_time,
                max_drift: self.config.max_timestamp_drift_secs,
            });
        }

        // 4. Verify proposer Ed25519 signature
        let proposer_val = self
            .epoch_manager
            .active_validator_set
            .iter()
            .find(|v| v.address == header.proposer && v.is_active())
            .ok_or_else(|| NanoError::UnknownSigner {
                signer: header.proposer.to_string(),
            })?;

        let derived = Address::from_public_key(&proposer_val.pubkey);
        if derived != header.proposer {
            return Err(NanoError::ProposerMismatch {
                header_proposer: header.proposer.to_string(),
                derived: derived.to_string(),
            });
        }

        header
            .verify_signature(&proposer_val.pubkey)
            .map_err(|e| NanoError::InvalidProposerSignature {
                height: header.height,
                reason: e.to_string(),
            })?;

        // 5. Verify BFT Quorum Certificate signatures (>= 2f + 1)
        let block_hash = header
            .try_hash()
            .map_err(|e| NanoError::Crypto(e.to_string()))?;
        self.epoch_manager.verify_quorum_signatures(
            &block_hash,
            header.height,
            signatures,
            hotstuff_meta,
        )?;

        // 6. Push to bounded in-memory ring buffer (0 MB disk)
        if self.header_buffer.len() >= self.config.ring_buffer_capacity {
            self.header_buffer.pop_front();
        }
        self.header_buffer.push_back(header.clone());
        self.latest_verified_header = Some(header);

        Ok(block_hash)
    }

    /// Overload accepting raw address and signature slice tuples.
    pub fn verify_and_append_header_raw(
        &mut self,
        header: BlockHeader,
        signatures: &[(Address, [u8; 64])],
        hotstuff_meta: Option<(u64, u8)>,
        current_time: u64,
    ) -> Result<Hash, NanoError> {
        let sigs: Vec<ValidatorSignature> = signatures
            .iter()
            .map(|(addr, s)| ValidatorSignature::new(*addr, *s))
            .collect();
        self.verify_and_append_header(header, &sigs, hotstuff_meta, current_time)
    }

    /// Spot-check an account state (balance, nonce, code_hash) against a verified state root
    /// using a constant-size KZG Verkle proof (~2.5 KB) via the batched multi-point opening path (one pairing check).
    pub fn verify_account_balance(
        &self,
        address: &Address,
        expected_account: &Account,
        root: Hash,
        proof: &VerkleProof,
    ) -> Result<bool, NanoError> {
        proof
            .verify_account_proof_batched(address, expected_account, root)
            .map_err(|e| NanoError::KzgVerificationFailed(e.to_string()))
    }

    /// Spot-check a smart contract storage slot value against a verified state root
    /// using a constant-size KZG Verkle proof via the batched multi-point opening path (one pairing check).
    pub fn verify_storage_slot(
        &self,
        address: &Address,
        slot_key: Hash,
        expected_value: Hash,
        root: Hash,
        proof: &VerkleProof,
    ) -> Result<bool, NanoError> {
        let key = storage_proof_key(address, &slot_key);
        proof
            .verify_proof_batched(key, expected_value, root)
            .map_err(|e| NanoError::KzgVerificationFailed(e.to_string()))
    }

    /// Dual-Path Gap Recovery:
    ///
    /// The BFT handover chain is enforced as the **primary trust anchor** for validator-set
    /// rotations and header linkage. An optional ZK proof statement (target state root,
    /// block hash, and height) provides defense-in-depth cryptographic verification and MUST
    /// strictly corroborate the handover chain's boundary header.
    ///
    /// If the ZK proof disagrees with the handover chain or is uncorroborated, gap sync is rejected.
    pub fn handle_gap_sync(
        &mut self,
        handover_chain: &[EpochHandoverCertificate],
        zk_proof_meta: Option<(Hash, Hash, u64)>,
        current_time: u64,
    ) -> Result<(), NanoError> {
        if handover_chain.is_empty() {
            return Err(NanoError::GapRecovery(
                "handover chain cannot be empty; handover corroboration is mandatory".into(),
            ));
        }

        // 1. Corroborate optional ZK proof against the final boundary header BEFORE mutating state
        if let Some((zk_target_root, zk_block_hash, zk_height)) = zk_proof_meta {
            let last_cert = handover_chain
                .last()
                .expect("handover chain checked non-empty");
            let boundary_hash = last_cert
                .boundary_header
                .try_hash()
                .map_err(|e| NanoError::Crypto(e.to_string()))?;

            if last_cert.boundary_header.height != zk_height {
                return Err(NanoError::GapRecovery(format!(
                    "ZK proof height {} does not corroborate handover boundary height {}",
                    zk_height, last_cert.boundary_header.height
                )));
            }
            if last_cert.boundary_header.state_root != zk_target_root {
                return Err(NanoError::GapRecovery(format!(
                    "ZK proof target root 0x{} does not corroborate handover state root 0x{}",
                    hex::encode(zk_target_root),
                    hex::encode(last_cert.boundary_header.state_root)
                )));
            }
            if boundary_hash != zk_block_hash {
                return Err(NanoError::GapRecovery(format!(
                    "ZK proof block hash 0x{} does not corroborate handover header hash 0x{}",
                    hex::encode(zk_block_hash),
                    hex::encode(boundary_hash)
                )));
            }
        }

        // 2. Process and verify the full BFT handover chain (primary trust anchor)
        for cert in handover_chain {
            self.epoch_manager
                .verify_and_apply_handover(cert, current_time)?;
            self.latest_verified_header = Some(cert.boundary_header.clone());
            if self.header_buffer.len() >= self.config.ring_buffer_capacity {
                self.header_buffer.pop_front();
            }
            self.header_buffer.push_back(cert.boundary_header.clone());
        }

        Ok(())
    }

    /// Fast epoch gap recovery using handover certificates only.
    pub fn handle_gap_sync_handover(
        &mut self,
        handover_chain: &[EpochHandoverCertificate],
        current_time: u64,
    ) -> Result<(), NanoError> {
        self.handle_gap_sync(handover_chain, None, current_time)
    }

    /// Returns the latest verified block header.
    pub fn latest_header(&self) -> Option<&BlockHeader> {
        self.latest_verified_header.as_ref()
    }

    /// Returns current verified chain height.
    pub fn current_height(&self) -> u64 {
        self.latest_verified_header
            .as_ref()
            .map(|h| h.height)
            .unwrap_or(0)
    }

    /// Returns the current active validator set.
    pub fn active_validators(&self) -> &[Validator] {
        &self.epoch_manager.active_validator_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use sxiaum_state::proof::{storage_proof_key, VerkleProof};
    use sxiaum_state::VerkleTree;
    use sxiaum_types::{SXIAUM_CHAIN_ID, ValidatorStatus};

    /// Build an ed25519 signing key and derived validator.
    fn test_keypair(seed_byte: u8) -> (SigningKey, [u8; 32], Address) {
        let seed = [seed_byte; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pubkey = sk.verifying_key().to_bytes();
        let address = Address::from_public_key(&pubkey);
        (sk, pubkey, address)
    }

    fn test_validator(sk: &SigningKey, voting_power: u64) -> Validator {
        let pubkey = sk.verifying_key().to_bytes();
        let address = Address::from_public_key(&pubkey);
        let mut v = Validator::new(address, pubkey, U256::from(1_000));
        v.voting_power = voting_power;
        v.status = ValidatorStatus::Active;
        v
    }

    fn sign_header_and_qc(
        h: &mut BlockHeader,
        sk: &SigningKey,
        val: &Validator,
        view: u64,
        phase: u8,
    ) -> (Hash, Vec<crate::epoch_sync::ValidatorSignature>, Option<(u64, u8)>) {
        h.proposer = val.address;
        h.sign(sk).expect("sign header");
        let hash = h.try_hash().expect("header hash");
        let digest = crate::epoch_sync::hotstuff_vote_digest(val.address, &hash, view, phase);
        let sig = sxiaum_crypto::ed25519::sign(sk.as_bytes(), &digest);
        let vs = crate::epoch_sync::ValidatorSignature::new(val.address, sig.0);
        (hash, vec![vs], Some((view, phase)))
    }

    const TEST_BASE_TIME: u64 = 1_704_068_000;

    #[test]
    fn default_light_config_is_mainnet_pinned() {
        let config = NanoLightConfig::default();
        assert_eq!(config.chain_id, SXIAUM_CHAIN_ID);
        assert_eq!(config.max_timestamp_drift_secs, super::DEFAULT_MAX_TIMESTAMP_DRIFT);
    }

    #[test]
    fn light_client_rejects_non_mainnet_chain_id() {
        let (sk, _, _) = test_keypair(1);
        let config = NanoLightConfig {
            initial_validator_set: vec![test_validator(&sk, 10)],
            chain_id: 1,
            ..Default::default()
        };
        assert!(matches!(
            NanoLightClient::new(config),
            Err(NanoError::UnsupportedChainId { .. })
        ));
    }

    #[test]
    fn verify_header_rejects_foreign_chain_id() {
        let (sk, _, _) = test_keypair(1);
        let val = test_validator(&sk, 10);
        let config = NanoLightConfig {
            initial_validator_set: vec![val.clone()],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("client with canonical chain id");

        let mut header = BlockHeader::new([1u8; 32], 1);
        header.chain_id = 999;
        header.timestamp = TEST_BASE_TIME;
        let (_, qc, meta) = sign_header_and_qc(&mut header, &sk, &val, 1, 0);

        let now = TEST_BASE_TIME;
        let err = client
            .verify_and_append_header(header, &qc, meta, now)
            .expect_err("foreign chain id must be rejected");
        assert!(matches!(
            err,
            NanoError::ValidationFailed { .. } | NanoError::ChainIdMismatch { .. }
        ));
    }

    #[test]
    fn nano_light_client_rejects_forged_proposer_signature() {
        let (sk_val, _, _) = test_keypair(1);
        let (sk_forger, _, _) = test_keypair(99);

        let config = NanoLightConfig {
            initial_validator_set: vec![test_validator(&sk_val, 100)],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut header = BlockHeader::new([1u8; 32], 1);
        header.timestamp = TEST_BASE_TIME;
        header.proposer = test_validator(&sk_val, 100).address;
        // Sign with a forged key directly into header.signature
        header.sign(&sk_val).expect("sign");
        let hash = header.try_hash().expect("hash");
        let forged_sig = sxiaum_crypto::ed25519::sign(sk_forger.as_bytes(), &hash);
        header.signature = Some(forged_sig.0);

        let now = TEST_BASE_TIME;
        let err = client
            .verify_and_append_header(header, &[], None, now)
            .expect_err("forged proposer signature must fail");
        assert!(matches!(
            err,
            NanoError::InvalidProposerSignature { .. }
                | NanoError::ValidationFailed { .. }
                | NanoError::ProposerMismatch { .. }
        ));
    }

    #[test]
    fn nano_light_client_rejects_duplicate_signer_in_qc() {
        let (sk, _, _) = test_keypair(1);
        let val = test_validator(&sk, 100);

        let config = NanoLightConfig {
            initial_validator_set: vec![val.clone()],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut header = BlockHeader::new([1u8; 32], 1);
        header.timestamp = TEST_BASE_TIME;
        header.proposer = val.address;
        header.sign(&sk).expect("sign");

        let header_hash = header.try_hash().expect("hash");
        let digest = crate::epoch_sync::hotstuff_vote_digest(val.address, &header_hash, 1, 0);
        let sig = sxiaum_crypto::ed25519::sign(sk.as_bytes(), &digest);
        let vs = crate::epoch_sync::ValidatorSignature::new(val.address, sig.0);
        let sigs = vec![vs, vs]; // Duplicate!

        let now = TEST_BASE_TIME;
        let err = client
            .verify_and_append_header(header, &sigs, Some((1, 0)), now)
            .expect_err("duplicate signer in QC must fail");
        assert!(matches!(err, NanoError::DuplicateSignerInQc { .. }));
    }

    #[test]
    fn nano_light_client_rejects_unknown_signer() {
        let (sk_val, _, _) = test_keypair(1);
        let (sk_unknown, _, addr_unknown) = test_keypair(2);

        let config = NanoLightConfig {
            initial_validator_set: vec![test_validator(&sk_val, 100)],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut header = BlockHeader::new([1u8; 32], 1);
        header.timestamp = TEST_BASE_TIME;
        header.proposer = test_validator(&sk_val, 100).address;
        header.sign(&sk_val).expect("sign");

        let header_hash = header.try_hash().expect("hash");
        let digest = crate::epoch_sync::hotstuff_vote_digest(addr_unknown, &header_hash, 1, 0);
        let sig = sxiaum_crypto::ed25519::sign(sk_unknown.as_bytes(), &digest);
        let vs = crate::epoch_sync::ValidatorSignature::new(addr_unknown, sig.0);

        let now = TEST_BASE_TIME;
        let err = client
            .verify_and_append_header(header, &[vs], Some((1, 0)), now)
            .expect_err("unknown signer in QC must fail");
        assert!(matches!(err, NanoError::UnknownSigner { .. }));
    }

    #[test]
    fn nano_light_client_rejects_height_and_parent_hash_mismatch() {
        let (sk, _, _) = test_keypair(1);
        let val = test_validator(&sk, 100);

        let config = NanoLightConfig {
            initial_validator_set: vec![val.clone()],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut h1 = BlockHeader::new([1u8; 32], 1);
        h1.timestamp = TEST_BASE_TIME;
        let (h1_hash, qc1, meta1) = sign_header_and_qc(&mut h1, &sk, &val, 1, 0);

        client
            .verify_and_append_header(h1, &qc1, meta1, TEST_BASE_TIME)
            .expect("append h1");

        // Try height jump (height 3 directly instead of 2)
        let mut h3 = BlockHeader::new(h1_hash, 3);
        h3.timestamp = TEST_BASE_TIME + 2;
        let (_, qc3, meta3) = sign_header_and_qc(&mut h3, &sk, &val, 3, 0);
        let err = client
            .verify_and_append_header(h3, &qc3, meta3, TEST_BASE_TIME + 2)
            .expect_err("height mismatch must fail");
        assert!(matches!(err, NanoError::HeightMismatch { .. }));

        // Try wrong parent hash for height 2
        let mut h2 = BlockHeader::new([0xDE; 32], 2);
        h2.timestamp = TEST_BASE_TIME + 2;
        let (_, qc2, meta2) = sign_header_and_qc(&mut h2, &sk, &val, 2, 0);
        let err = client
            .verify_and_append_header(h2, &qc2, meta2, TEST_BASE_TIME + 2)
            .expect_err("parent hash mismatch must fail");
        assert!(matches!(err, NanoError::ParentHashMismatch { .. }));
    }

    #[test]
    fn nano_light_client_rejects_timestamp_regression_and_future_drift() {
        let (sk, _, _) = test_keypair(1);
        let val = test_validator(&sk, 100);

        let config = NanoLightConfig {
            initial_validator_set: vec![val.clone()],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut h1 = BlockHeader::new([1u8; 32], 1);
        h1.timestamp = TEST_BASE_TIME;
        let (h1_hash, qc1, meta1) = sign_header_and_qc(&mut h1, &sk, &val, 1, 0);

        client
            .verify_and_append_header(h1, &qc1, meta1, TEST_BASE_TIME)
            .expect("append h1");

        // Timestamp regression: header time <= parent time
        let mut h2_regress = BlockHeader::new(h1_hash, 2);
        h2_regress.timestamp = TEST_BASE_TIME; // Equal to parent -> regression!
        let (_, qc_reg, meta_reg) = sign_header_and_qc(&mut h2_regress, &sk, &val, 2, 0);
        let err = client
            .verify_and_append_header(h2_regress, &qc_reg, meta_reg, TEST_BASE_TIME + 2)
            .expect_err("timestamp regression must fail");
        assert!(matches!(
            err,
            NanoError::TimestampRegression { .. } | NanoError::ValidationFailed { .. }
        ));

        // Future drift: header time > now + 5s (canonical bound)
        let mut h2_future = BlockHeader::new(h1_hash, 2);
        h2_future.timestamp = TEST_BASE_TIME + 10; // now is TEST_BASE_TIME + 2, 10 > 2 + 5
        let (_, qc_fut, meta_fut) = sign_header_and_qc(&mut h2_future, &sk, &val, 2, 0);
        let err = client
            .verify_and_append_header(h2_future, &qc_fut, meta_fut, TEST_BASE_TIME + 2)
            .expect_err("future drift >5s must fail");
        assert!(matches!(
            err,
            NanoError::FutureTimestamp { .. } | NanoError::ValidationFailed { .. }
        ));
    }

    #[test]
    fn nano_light_client_verifies_account_and_storage_proofs_and_rejects_forged() {
        std::env::set_var("SXIAUM_SRS_MODE", "dev");
        let (sk, _, _) = test_keypair(1);
        let config = NanoLightConfig {
            initial_validator_set: vec![test_validator(&sk, 100)],
            ..Default::default()
        };
        let client = NanoLightClient::new(config).expect("init client");

        let mut tree = VerkleTree::new();
        let target_address = Address([0x42; 32]);
        let mut account = Account::new(target_address);
        account.balance = U256::from(1_000_000);
        account.nonce = 1;
        let account_hash = account.try_hash().unwrap();
        tree.insert(*target_address.as_bytes(), account_hash)
            .expect("insert account");

        let slot = [42u8; 32];
        let value = [99u8; 32];
        let proof_key = storage_proof_key(&target_address, &slot);
        tree.insert(proof_key, value).expect("insert storage");

        let root = tree.root_commitment();
        let account_proof = VerkleProof::generate_account_proof(&tree, &target_address).expect("account proof");
        let storage_proof = VerkleProof::generate_storage_proof(&tree, &target_address, slot).expect("storage proof");

        // Genuine verification
        let ok = client
            .verify_account_balance(&target_address, &account, root, &account_proof)
            .expect("verify account balance");
        assert!(ok, "genuine account proof must verify");

        let ok = client
            .verify_storage_slot(&target_address, slot, value, root, &storage_proof)
            .expect("verify storage proof");
        assert!(ok, "genuine storage proof must verify");

        // Forged balance rejected
        let mut forged_account = Account::new(target_address);
        forged_account.balance = U256::from(999_999_999);
        forged_account.nonce = 1;
        let ok = client
            .verify_account_balance(&target_address, &forged_account, root, &account_proof)
            .expect("verify forged balance");
        assert!(!ok, "forged balance must return false");

        // Forged storage value rejected
        let forged_value = [88u8; 32];
        let ok = client
            .verify_storage_slot(&target_address, slot, forged_value, root, &storage_proof)
            .expect("verify forged storage");
        assert!(!ok, "forged storage value must return false");
    }

    #[test]
    fn nano_gap_sync_dual_path_requires_handover_corroboration() {
        use crate::epoch_sync::{hotstuff_vote_digest, EpochHandoverCertificate, ValidatorSignature};

        let (sk_v0, _, _) = test_keypair(1);
        let (sk_v1, _, _) = test_keypair(2);
        let v0 = test_validator(&sk_v0, 100);
        let v1 = test_validator(&sk_v1, 100);

        let config = NanoLightConfig {
            initial_validator_set: vec![v0.clone()],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut boundary = BlockHeader::new([1u8; 32], 100);
        boundary.timestamp = TEST_BASE_TIME;
        boundary.state_root = [0x55; 32];
        boundary.proposer = v0.address;
        boundary.sign(&sk_v0).expect("sign");
        let boundary_hash = boundary.try_hash().expect("hash");

        let next_set = vec![v1.clone()];

        let mut cert = EpochHandoverCertificate {
            epoch: 0,
            boundary_header: boundary.clone(),
            consensus_signatures: Vec::new(),
            hotstuff_view_phase: Some((1, 0)),
            next_validator_set: next_set,
        };
        let digest = hotstuff_vote_digest(v0.address, &boundary_hash, 1, 0);
        let sig = sxiaum_crypto::ed25519::sign(sk_v0.as_bytes(), &digest);
        cert.consensus_signatures.push(ValidatorSignature::new(v0.address, sig.0));

        // Dual-path gap sync: handover chain + matching ZK proof metadata
        let zk_meta = Some((boundary.state_root, boundary_hash, boundary.height));
        client
            .handle_gap_sync(&[cert], zk_meta, TEST_BASE_TIME)
            .expect("gap sync must succeed when corroborated");

        assert_eq!(client.current_height(), 100);
        assert_eq!(client.active_validators(), &[v1]);
    }

    #[test]
    fn nano_gap_sync_rejects_unconstrained_or_mismatched_zk_proof() {
        use crate::epoch_sync::{hotstuff_vote_digest, EpochHandoverCertificate, ValidatorSignature};

        let (sk_v0, _, _) = test_keypair(1);
        let (sk_v1, _, _) = test_keypair(2);
        let v0 = test_validator(&sk_v0, 100);
        let v1 = test_validator(&sk_v1, 100);

        let config = NanoLightConfig {
            initial_validator_set: vec![v0.clone()],
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut boundary = BlockHeader::new([1u8; 32], 100);
        boundary.timestamp = TEST_BASE_TIME;
        boundary.state_root = [0x55; 32];
        boundary.proposer = v0.address;
        boundary.sign(&sk_v0).expect("sign");
        let boundary_hash = boundary.try_hash().expect("hash");

        let next_set = vec![v1.clone()];

        let mut cert = EpochHandoverCertificate {
            epoch: 0,
            boundary_header: boundary,
            consensus_signatures: Vec::new(),
            hotstuff_view_phase: Some((1, 0)),
            next_validator_set: next_set,
        };
        let digest = hotstuff_vote_digest(v0.address, &boundary_hash, 1, 0);
        let sig = sxiaum_crypto::ed25519::sign(sk_v0.as_bytes(), &digest);
        cert.consensus_signatures.push(ValidatorSignature::new(v0.address, sig.0));

        // Mismatched state root in ZK proof
        let bad_zk_root = Some(([0xEE; 32], boundary_hash, 100));
        let err = client
            .handle_gap_sync(&[cert.clone()], bad_zk_root, TEST_BASE_TIME)
            .expect_err("mismatched ZK root must fail");
        assert!(matches!(err, NanoError::GapRecovery(..)));

        // Mismatched height in ZK proof
        let bad_zk_height = Some(([0x55; 32], boundary_hash, 999));
        let err = client
            .handle_gap_sync(&[cert], bad_zk_height, TEST_BASE_TIME)
            .expect_err("mismatched ZK height must fail");
        assert!(matches!(err, NanoError::GapRecovery(..)));
    }

    #[test]
    fn nano_memory_footprint_bounds() {
        let (sk, _, _) = test_keypair(1);
        let val = test_validator(&sk, 100);

        let ring_cap = 16;
        let config = NanoLightConfig {
            initial_validator_set: vec![val.clone()],
            ring_buffer_capacity: ring_cap,
            ..Default::default()
        };
        let mut client = NanoLightClient::new(config).expect("init client");

        let mut prev_hash = [1u8; 32];
        for i in 1..=50 {
            let mut h = BlockHeader::new(prev_hash, i);
            h.timestamp = TEST_BASE_TIME + i;
            let (hash, qc, meta) = sign_header_and_qc(&mut h, &sk, &val, i, 0);
            prev_hash = hash;
            client
                .verify_and_append_header(h, &qc, meta, TEST_BASE_TIME + i)
                .expect("append header");
        }

        assert_eq!(client.header_buffer.len(), ring_cap);
        assert_eq!(client.current_height(), 50);
    }
}
