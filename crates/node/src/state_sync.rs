//! Snapshot-based state-sync engine.
//!
//! # Protocol
//!
//! 1. **Server side** (`StateSyncEngine::create_snapshot`): compresses all
//!    canonical-prefix state entries from the storage engine into a
//!    length-prefixed, zstd-compressed binary chunk and stores it alongside
//!    the canonical `state_root` and `block_height` at which it was taken.
//!
//! 2. **Client side** (`StateSyncEngine::apply_snapshot`): authenticates the
//!    manifest, decompresses the chunk, replays every key/value pair into the
//!    local storage backend, and verifies the resulting state root matches
//!    the one advertised in the snapshot manifest.
//!
//! # Security (C-04)
//!
//! Snapshots arrive from untrusted peers, so `apply_snapshot` enforces:
//!
//! 1. **Manifest authentication** — the manifest must carry an Ed25519
//!    signature from an ACTIVE validator in the locally persisted validator
//!    set. Checksums are integrity-only and prove nothing about origin.
//! 2. **Key-prefix allowlist** — only canonical state prefixes may be
//!    written; snapshots can never touch `metadata:*`, consensus state,
//!    bans, or any other storage namespace.
//! 3. **Rollback guard** — a snapshot at or below the local chain height is
//!    rejected (no regressive overwrites from lagging peers).
//!
//! Snapshots are gossiped on `TOPIC_STATE_SYNC` (see `networking::gossip`).

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use sxiaum_types::Address;
use tracing::info;

/// Wire-format manifest that accompanies a compressed state chunk.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Block height at which the snapshot was taken.
    pub height: u64,
    /// State root (Verkle / SMT root) at `height`.
    pub state_root: [u8; 32],
    /// Canonical block header hash H_N at `height` (spec §2.1). Bound into
    /// the recursive certificate as its target block hash so the proof
    /// certifies the exact finalized head — not just an arbitrary root.
    #[serde(default)]
    pub block_hash: [u8; 32],
    /// Number of key/value pairs in the snapshot.
    pub entry_count: u64,
    /// SHA-256 checksum of the raw (uncompressed) payload.
    pub payload_checksum: [u8; 32],
    /// Address of the validator that produced (and signed) this manifest.
    #[serde(default)]
    pub proposer: [u8; 32],
    /// Optional Groth16 recursive proof certificate (539 bytes MNT6 / 256 bytes BLS12-381) certifying historical progression from genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Vec<u8>>,
    /// Ed25519 signature over [`SnapshotManifest::signing_payload`].
    #[serde(with = "serde_sig64", default = "default_manifest_signature")]
    pub signature: [u8; 64],
}

fn default_manifest_signature() -> [u8; 64] {
    [0u8; 64]
}

/// Serde support for fixed 64-byte signatures (byte-sequence wire format).
mod serde_sig64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
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
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| Error::custom("expected 64 bytes"))
    }
}

impl SnapshotManifest {
    /// Canonical byte sequence committed to by `signature`. Every
    /// security-relevant manifest field is covered; the signature itself is
    /// excluded (it cannot sign itself).
    pub fn signing_payload(&self) -> Vec<u8> {
        const DOMAIN: &[u8] = b"sxiaum:state-sync:manifest:v1";
        let mut payload = Vec::with_capacity(
            DOMAIN.len() + 8 + 32 + 8 + 32 + 32 + self.proof.as_ref().map_or(0, |p| p.len() + 8),
        );
        payload.extend_from_slice(DOMAIN);
        payload.extend_from_slice(&self.height.to_be_bytes());
        payload.extend_from_slice(&self.state_root);
        payload.extend_from_slice(&self.block_hash);
        payload.extend_from_slice(&self.entry_count.to_be_bytes());
        payload.extend_from_slice(&self.payload_checksum);
        payload.extend_from_slice(&self.proposer);
        if let Some(proof_bytes) = &self.proof {
            payload.extend_from_slice(b":proof:");
            payload.extend_from_slice(proof_bytes);
        }
        payload
    }
}

/// A snapshot that can be transmitted over the gossip layer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub manifest: SnapshotManifest,
    /// zstd-compressed, bincode-encoded `Vec<(Vec<u8>, Vec<u8>)>` of key/value pairs.
    pub compressed_payload: Vec<u8>,
}

/// Prefixes used for all persistent state entries in the storage engine.
const STATE_PREFIXES: &[&[u8]] = &[b"account:", b"storage:", b"contract:code:", b"vesting:"];

/// Storage key under which the active validator set is persisted. Used to
/// authenticate inbound snapshot manifests.
const CONSENSUS_VALIDATOR_SET_KEY: &[u8] = b"consensus:validator_set";

pub const MAX_DECOMPRESSED_PAYLOAD_BYTES: usize = 64 * 1024 * 1024; // 64 MB
pub const MAX_SNAPSHOT_ENTRY_COUNT: u64 = 1_000_000;

pub struct StateSyncEngine {
    storage: Arc<StorageEngine>,
    state: Arc<StateDB>,
    /// Validator signing key used to sign outbound snapshot manifests.
    signer: Option<SigningKey>,
    /// Optional ZK engine for verifying recursive state sync proofs.
    zk: Option<Arc<sxiaum_zk::ZkEngine>>,
    /// Hardcoded or configured genesis state root.
    genesis_state_root: Option<[u8; 32]>,
}

impl StateSyncEngine {
    pub fn new(storage: Arc<StorageEngine>, state: Arc<StateDB>) -> Self {
        Self {
            storage,
            state,
            signer: None,
            zk: None,
            genesis_state_root: None,
        }
    }

    /// Configure the validator signing key used to sign outbound manifests.
    pub fn with_signer(mut self, signer: SigningKey) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Configure the ZK engine and genesis root for recursive proof validation.
    pub fn with_zk_engine(
        mut self,
        zk: Arc<sxiaum_zk::ZkEngine>,
        genesis_state_root: [u8; 32],
    ) -> Self {
        self.zk = Some(zk);
        self.genesis_state_root = Some(genesis_state_root);
        self
    }

    /// Create a compressed snapshot of all state at the current head.
    /// The snapshot includes all account, storage, contract code, and vesting keys.
    pub fn create_snapshot(&self, height: u64) -> Result<StateSnapshot> {
        info!("Creating state snapshot at height {}", height);

        // SECURITY (C-04): snapshots are authenticated statements about chain
        // state. Refuse to produce an unsigned snapshot — it would be
        // rejected by every secure peer on arrival.
        let signer = self.signer.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "cannot create state snapshot: no validator signing key configured \
                 (snapshots must be signed to be acceptable)"
            )
        })?;

        // 1. Collect all state entries across all canonical prefixes.
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for prefix in STATE_PREFIXES {
            let scanned = self
                .storage
                .state_prefix_scan(prefix.to_vec())
                .with_context(|| {
                    format!(
                        "failed to scan state for prefix {:?}",
                        String::from_utf8_lossy(prefix)
                    )
                })?;
            entries.extend(scanned);
        }

        let entry_count = entries.len() as u64;
        info!("Snapshot contains {} total state entries", entry_count);

        // 2. Serialize and compute checksum of the raw payload.
        let raw_payload =
            bincode::serialize(&entries).context("failed to serialize snapshot entries")?;

        let payload_checksum = checksum(&raw_payload);

        // 3. Compress with zstd (level 3 - fast, good ratio).
        let compressed_payload =
            zstd::encode_all(raw_payload.as_slice(), 3).context("zstd compression failed")?;

        // 4. Fetch the current state root.
        let state_root = self
            .storage
            .state_get_bytes(b"metadata:state_root")
            .context("failed to read state root from storage")?
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0u8; 32]);

        // 4b. Resolve the canonical block header hash H_N at `height`
        //     (spec §2.1). On mainnet this is mandatory: the recursive
        //     certificate must certify the exact finalized head.
        let block_hash = match self.storage.get_block_header(height)? {
            Some(header) => {
                let header_hash = header
                    .try_hash()
                    .context("failed to hash canonical block header")?;
                if header.state_root != state_root {
                    bail!(
                        "canonical header at height {} disagrees with the committed state root \
                         (header 0x{}, storage 0x{}) — refusing to certify inconsistent state",
                        height,
                        hex::encode(header.state_root),
                        hex::encode(state_root)
                    );
                }
                header_hash
            }
            None if sxiaum_zk::is_production() => {
                bail!(
                    "cannot create state snapshot at height {}: no canonical block header \
                     (mainnet certificates must bind a real header hash)",
                    height
                );
            }
            // Development only: no canonical head exists yet (genesis-anchored
            // testnets/devnets). The zero hash is still signed and bound into
            // the certificate, so this can never be mistaken for a real head.
            None => [0u8; 32],
        };

        // 5. Sign the manifest so receivers can authenticate its origin.
        let proposer = Address::from_public_key(&signer.verifying_key().to_bytes());
        let mut manifest = SnapshotManifest {
            height,
            state_root,
            block_hash,
            entry_count,
            payload_checksum,
            proposer: proposer.0,
            proof: None,
            signature: [0u8; 64],
        };

        // If ZK engine is available and has prover initialized, generate and attach proof
        if let (Some(zk), Some(genesis_root)) = (&self.zk, self.genesis_state_root) {
            if zk.fold_stack.is_some() {
                if let Ok(rec_proof) = zk.generate_recursive_state_sync_proof(
                    genesis_root,
                    state_root,
                    block_hash,
                    height,
                    [0u8; 32],
                ) {
                    manifest.proof = Some(rec_proof.proof.bytes);
                }
            } else if zk.groth16_prover.is_some() {
                if let Ok(zk_proof) = zk.generate_state_transition_proof(
                    genesis_root,
                    block_hash,
                    state_root,
                ) {
                    manifest.proof = Some(zk_proof.bytes);
                }
            }
        }

        let signature =
            sxiaum_crypto::ed25519::sign(&signer.to_bytes(), &manifest.signing_payload());
        manifest.signature = signature.0;

        Ok(StateSnapshot {
            manifest,
            compressed_payload,
        })
    }

    /// Apply a received snapshot to the local node's storage and verify the
    /// resulting state root matches the manifest.
    ///
    /// SECURITY (C-04): the manifest is authenticated against the local
    /// validator set, only canonical state prefixes may be written, and
    /// regressive (stale) snapshots are rejected outright.
    pub fn apply_snapshot(&self, snapshot: StateSnapshot) -> Result<()> {
        info!(
            "Applying state snapshot: height={}, entries={}",
            snapshot.manifest.height, snapshot.manifest.entry_count
        );

        // 0. Authenticate the manifest BEFORE trusting any of its content.
        self.verify_manifest_authenticity(&snapshot.manifest)?;

        // 0b. Rollback guard: never accept a snapshot that would move local
        // state backwards. A lagging/malicious peer must not be able to
        // rewind a node by replaying an old snapshot.
        let local_height = self.storage.latest_block_height().unwrap_or(0);
        if local_height > 0 && snapshot.manifest.height <= local_height {
            bail!(
                "snapshot height {} is not ahead of local height {} (rollback rejected)",
                snapshot.manifest.height,
                local_height
            );
        }

        if snapshot.manifest.entry_count > MAX_SNAPSHOT_ENTRY_COUNT {
            bail!(
                "snapshot entry count {} exceeds maximum allowed limit ({})",
                snapshot.manifest.entry_count,
                MAX_SNAPSHOT_ENTRY_COUNT
            );
        }

        // 0c. Cryptographic Proof Check (Invention 4: Recursive Proof-Carrying State):
        // If a ZK proof is attached, verify the Groth16 recursive certificate
        // against genesis and the canonical header hash H_N.
        if let Some(proof_bytes) = &snapshot.manifest.proof {
            if let (Some(zk), Some(genesis_root)) = (&self.zk, self.genesis_state_root) {
                // Consistency cross-check: if this node already stores the
                // canonical header at the manifest height, its hash must match.
                if let Ok(Some(local_header)) =
                    self.storage.get_block_header(snapshot.manifest.height)
                {
                    let local_hash = local_header
                        .try_hash()
                        .context("failed to hash local canonical block header")?;
                    if local_hash != snapshot.manifest.block_hash {
                        bail!(
                            "snapshot block hash 0x{} does not match the local canonical header 0x{} at height {}",
                            hex::encode(snapshot.manifest.block_hash),
                            hex::encode(local_hash),
                            snapshot.manifest.height
                        );
                    }
                }

                let zk_proof = sxiaum_zk::ZkProof {
                    bytes: proof_bytes.clone(),
                };
                let valid = if zk.fold_stack.is_some() {
                    zk.verify_recursive_state_sync_proof(
                        genesis_root,
                        snapshot.manifest.state_root,
                        snapshot.manifest.block_hash,
                        snapshot.manifest.height,
                        [0u8; 32],
                        &zk_proof,
                    )
                    .context("recursive state sync proof verification failed")?
                } else if zk.groth16_verifier.is_some() {
                    let public_inputs = sxiaum_zk::encode_state_transition_public_inputs(
                        genesis_root,
                        snapshot.manifest.block_hash,
                        snapshot.manifest.state_root,
                    );
                    zk.verify_groth16_proof(&zk_proof, &public_inputs)
                        .context("recursive state sync proof verification failed")?
                } else {
                    false
                };
                if !valid {
                    bail!("recursive state sync proof rejected: invalid mathematical proof of provenance from genesis");
                }
                info!(
                    "Cryptographic recursive proof verified successfully: certified genesis -> height {}",
                    snapshot.manifest.height
                );
            }
        }

        // 1. Decompress with maximum size limit (prevents decompression bombs).
        use std::io::Read;
        let decoder = zstd::Decoder::new(snapshot.compressed_payload.as_slice())
            .context("failed to create zstd decoder")?;
        let mut raw_payload = Vec::new();
        decoder
            .take((MAX_DECOMPRESSED_PAYLOAD_BYTES + 1) as u64)
            .read_to_end(&mut raw_payload)
            .context("zstd decompression failed")?;

        if raw_payload.len() > MAX_DECOMPRESSED_PAYLOAD_BYTES {
            bail!(
                "snapshot decompressed payload size ({} bytes) exceeds maximum allowed ({} bytes)",
                raw_payload.len(),
                MAX_DECOMPRESSED_PAYLOAD_BYTES
            );
        }

        // 2. Verify payload checksum.
        let actual_checksum = checksum(&raw_payload);
        if actual_checksum != snapshot.manifest.payload_checksum {
            bail!(
                "snapshot payload checksum mismatch: expected {:?}, got {:?}",
                snapshot.manifest.payload_checksum,
                actual_checksum
            );
        }

        // 3. Deserialize entries.
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            bincode::deserialize(&raw_payload).context("failed to deserialize snapshot entries")?;

        if entries.len() as u64 != snapshot.manifest.entry_count {
            bail!(
                "snapshot entry count mismatch: expected {}, got {}",
                snapshot.manifest.entry_count,
                entries.len()
            );
        }

        // 3b. SECURITY (C-04): key-prefix allowlist. Snapshot entries may
        // only write canonical state namespaces. Anything else (metadata:*,
        // consensus:*, bans, mempool state, ...) is rejected — otherwise a
        // snapshot could overwrite validator sets, chain metadata, or peer
        // bans and compromise the whole node.
        for (key, _) in &entries {
            if !is_canonical_state_key(key) {
                bail!(
                    "snapshot entry key 0x{} is outside the canonical state prefixes (rejected)",
                    hex::encode(key)
                );
            }
        }

        // 4. Replay all entries into local storage.
        for (key, value) in entries {
            self.storage
                .state_put(key, value)
                .context("failed to write snapshot entry to storage")?;
        }

        info!(
            "State snapshot applied: {} entries written",
            snapshot.manifest.entry_count
        );

        // Rebuild the in-memory state trie from the newly populated storage before committing
        self.state
            .rebuild_tree_from_storage()
            .context("failed to rebuild state tree from storage after snapshot")?;

        // 5. Commit and verify state root after replay.
        let computed_root = self
            .state
            .commit()
            .context("state commit after snapshot failed")?;

        if computed_root != snapshot.manifest.state_root {
            bail!(
                "state root mismatch after snapshot replay: expected 0x{}, got 0x{}",
                hex::encode(snapshot.manifest.state_root),
                hex::encode(computed_root)
            );
        }

        // Persist the verified state root.
        self.storage
            .state_put(b"metadata:state_root".to_vec(), computed_root.to_vec())?;

        info!(
            "State root verified: 0x{}",
            hex::encode(snapshot.manifest.state_root)
        );

        Ok(())
    }

    /// SECURITY (C-04): verify that the manifest is signed by an ACTIVE
    /// validator in the locally persisted validator set.
    ///
    /// A payload checksum is integrity-only (attacker-controlled in ↔
    /// attacker-controlled out); only a validator signature binds the
    /// manifest to the chain's authorized set.
    fn verify_manifest_authenticity(&self, manifest: &SnapshotManifest) -> Result<()> {
        let Some(bytes) = self
            .storage
            .state_get(CONSENSUS_VALIDATOR_SET_KEY.to_vec())?
        else {
            // Bootstrap mode: no persisted validator set yet. There is no
            // trust anchor available, so accepting the snapshot would be a
            // total-state-compromise vector. Fail closed.
            bail!("snapshot rejected: no local validator set available to authenticate manifest");
        };
        let validators: Vec<sxiaum_types::Validator> = bincode::deserialize(&bytes)
            .context("failed to deserialize local validator set for snapshot auth")?;

        if validators.is_empty() {
            bail!("snapshot rejected: local validator set is empty (cannot authenticate manifest)");
        }

        let proposer = Address(manifest.proposer);
        let payload = manifest.signing_payload();
        for validator in &validators {
            if !validator.is_active() || validator.address != proposer {
                continue;
            }
            if sxiaum_crypto::ed25519::verify(&validator.pubkey, &payload, &manifest.signature) {
                return Ok(());
            }
            // Signature present but invalid for this validator — keep
            // scanning in case of key rotation duplicates, then fail.
        }

        bail!(
            "snapshot rejected: manifest signature from proposer 0x{} is not a valid active-validator signature",
            hex::encode(manifest.proposer)
        );
    }

    /// Encode a `StateSnapshot` for transmission via gossip.
    pub fn encode_for_gossip(snapshot: &StateSnapshot) -> Result<Vec<u8>> {
        bincode::serialize(snapshot).context("failed to encode state snapshot for gossip")
    }

    /// Decode a `StateSnapshot` received from gossip.
    pub fn decode_from_gossip(payload: &[u8]) -> Result<StateSnapshot> {
        bincode::deserialize(payload).context("failed to decode state snapshot from gossip")
    }
}

/// True when `key` belongs to a canonical state namespace that snapshots are
/// allowed to write.
fn is_canonical_state_key(key: &[u8]) -> bool {
    STATE_PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

/// SHA-256 checksum helper.
fn checksum(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sxiaum_types::{Account, Validator};

    fn validator_with_key(signing_key: &SigningKey) -> Validator {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pubkey);
        let mut validator = Validator::new(address, pubkey, 1_000_000.into());
        validator.status = sxiaum_types::ValidatorStatus::Active;
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        validator.with_bls_pop(pk.0, pop.0)
    }

    fn engine_with_validator_set(
        signing_key: &SigningKey,
    ) -> (Arc<StorageEngine>, Arc<StateDB>, std::path::PathBuf) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sxiaum-state-sync-{unique}.redb"));
        let storage = Arc::new(StorageEngine::new(path.to_string_lossy().as_ref()).unwrap());
        let state = Arc::new(StateDB::new(storage.clone()));
        let validator = validator_with_key(signing_key);
        storage
            .state_put(
                CONSENSUS_VALIDATOR_SET_KEY.to_vec(),
                bincode::serialize(&vec![validator]).unwrap(),
            )
            .unwrap();
        (storage, state, path)
    }

    #[test]
    fn signed_snapshot_roundtrip_is_accepted() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);
        let engine =
            StateSyncEngine::new(storage.clone(), state.clone()).with_signer(signing_key.clone());

        let account = Account::new(Address([9u8; 32]));
        state
            .update_account(&account.address, &account)
            .expect("account write must succeed");

        let reloaded = state
            .get_account(&account.address)
            .expect("account read must succeed")
            .expect("written account must be readable");
        assert_eq!(reloaded, account);

        let rebuilt_root = state
            .rebuild_tree_from_storage()
            .expect("tree rebuild must succeed");
        let root = state.commit().expect("commit must succeed");
        assert_eq!(
            rebuilt_root, root,
            "tree rebuild must reproduce the committed root"
        );
        storage
            .state_put(b"metadata:state_root".to_vec(), root.to_vec())
            .unwrap();

        let snapshot = engine.create_snapshot(10).expect("snapshot should build");
        assert_ne!(snapshot.manifest.signature, [0u8; 64]);
        engine
            .apply_snapshot(snapshot)
            .expect("signed snapshot should apply");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unsigned_or_forged_manifest_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let attacker_key = SigningKey::from_bytes(&[99u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);

        // Attacker engine: not the registered validator.
        let attacker_engine =
            StateSyncEngine::new(storage.clone(), state.clone()).with_signer(attacker_key);
        let snapshot = attacker_engine
            .create_snapshot(10)
            .expect("snapshot should build");
        let verifier = StateSyncEngine::new(storage.clone(), state.clone());
        assert!(verifier.apply_snapshot(snapshot).is_err());

        // Unsigned manifest (zero signature) must also fail.
        let mut snapshot = attacker_engine.create_snapshot(11).unwrap();
        snapshot.manifest.signature = [0u8; 64];
        assert!(verifier.apply_snapshot(snapshot).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn non_canonical_keys_are_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);
        let engine =
            StateSyncEngine::new(storage.clone(), state.clone()).with_signer(signing_key.clone());

        let mut snapshot = engine.create_snapshot(10).expect("snapshot should build");

        // Tamper: swap payload for one containing a metadata key, fixing the
        // checksum + signature so ONLY the allowlist can catch it.
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            vec![(b"metadata:state_root".to_vec(), vec![0u8; 32])];
        let raw = bincode::serialize(&entries).unwrap();
        snapshot.manifest.payload_checksum = checksum(&raw);
        snapshot.manifest.entry_count = entries.len() as u64;
        snapshot.compressed_payload = zstd::encode_all(raw.as_slice(), 3).unwrap();
        let sig = sxiaum_crypto::ed25519::sign(
            &signing_key.to_bytes(),
            &snapshot.manifest.signing_payload(),
        );
        snapshot.manifest.signature = sig.0;

        let err = engine
            .apply_snapshot(snapshot)
            .expect_err("metadata keys must be rejected");
        assert!(
            err.to_string().contains("canonical state prefixes"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_snapshot_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);
        let engine = StateSyncEngine::new(storage.clone(), state.clone()).with_signer(signing_key);

        // Put local chain head at height 5 so a height-5 snapshot is stale.
        let mut header = sxiaum_block::BlockHeader::new([1u8; 32], 5);
        header.state_root = [2u8; 32];
        let body = sxiaum_block::BlockBody::empty();
        storage
            .atomic_block_commit_typed(5, &header, &body)
            .expect("block should store");
        // Keep the committed-state-root metadata consistent with the header
        // (mainnet snapshots refuse to certify inconsistent state).
        storage
            .state_put(b"metadata:state_root".to_vec(), vec![2u8; 32])
            .expect("state root metadata should store");

        let snapshot = engine.create_snapshot(5).expect("snapshot should build");
        let err = engine
            .apply_snapshot(snapshot)
            .expect_err("stale snapshot must be rejected");
        assert!(err.to_string().contains("rollback"), "unexpected: {err}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unsigned_creation_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);
        let engine = StateSyncEngine::new(storage, state);
        assert!(engine.create_snapshot(1).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn state_sync_with_recursive_zk_proof_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);

        let (pk, vk) =
            sxiaum_zk::Groth16Prover::generate_recursive_sync_setup_parameters().unwrap();
        let vk_bytes = sxiaum_zk::serialize_verifying_key(&vk).unwrap();
        let verifier = sxiaum_zk::Groth16Verifier::from_verifying_key_bytes(&vk_bytes).unwrap();

        let mut zk_engine = sxiaum_zk::ZkEngine::new();
        zk_engine.groth16_prover = Some(sxiaum_zk::Groth16Prover::new(pk));
        zk_engine.groth16_verifier = Some(verifier);
        let zk_arc = Arc::new(zk_engine);

        let genesis_state_root = [42u8; 32];
        let engine = StateSyncEngine::new(storage.clone(), state.clone())
            .with_signer(signing_key.clone())
            .with_zk_engine(zk_arc.clone(), genesis_state_root);

        let account = Account::new(Address([15u8; 32]));
        state
            .update_account(&account.address, &account)
            .expect("account write must succeed");

        let rebuilt_root = state
            .rebuild_tree_from_storage()
            .expect("tree rebuild must succeed");
        let root = state.commit().expect("commit must succeed");
        assert_eq!(
            rebuilt_root, root,
            "tree rebuild must reproduce the committed root"
        );
        storage
            .state_put(b"metadata:state_root".to_vec(), root.to_vec())
            .unwrap();

        let snapshot = engine
            .create_snapshot(100)
            .expect("snapshot should build with ZK proof");
        assert!(
            snapshot.manifest.proof.is_some(),
            "snapshot must carry recursive ZK proof"
        );

        let receiving_engine = StateSyncEngine::new(storage.clone(), state.clone())
            .with_zk_engine(zk_arc, genesis_state_root);
        receiving_engine
            .apply_snapshot(snapshot)
            .expect("valid recursive proof snapshot must apply cleanly");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn state_sync_with_invalid_recursive_zk_proof_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let (storage, state, path) = engine_with_validator_set(&signing_key);

        let (pk, vk) =
            sxiaum_zk::Groth16Prover::generate_recursive_sync_setup_parameters().unwrap();
        let vk_bytes = sxiaum_zk::serialize_verifying_key(&vk).unwrap();
        let verifier = sxiaum_zk::Groth16Verifier::from_verifying_key_bytes(&vk_bytes).unwrap();

        let mut zk_engine = sxiaum_zk::ZkEngine::new();
        zk_engine.groth16_prover = Some(sxiaum_zk::Groth16Prover::new(pk));
        zk_engine.groth16_verifier = Some(verifier);
        let zk_arc = Arc::new(zk_engine);

        let genesis_state_root = [42u8; 32];
        let engine = StateSyncEngine::new(storage.clone(), state.clone())
            .with_signer(signing_key.clone())
            .with_zk_engine(zk_arc.clone(), genesis_state_root);

        state.rebuild_tree_from_storage().unwrap();
        let root = state.commit().unwrap();
        storage
            .state_put(b"metadata:state_root".to_vec(), root.to_vec())
            .unwrap();

        let mut snapshot = engine.create_snapshot(100).expect("snapshot should build");
        assert!(snapshot.manifest.proof.is_some());

        // Tamper with proof bytes
        if let Some(ref mut proof_bytes) = snapshot.manifest.proof {
            proof_bytes[0] ^= 0xff;
        }

        // Re-sign manifest with corrupted proof
        let sig = sxiaum_crypto::ed25519::sign(
            &signing_key.to_bytes(),
            &snapshot.manifest.signing_payload(),
        );
        snapshot.manifest.signature = sig.0;

        let receiving_engine = StateSyncEngine::new(storage.clone(), state.clone())
            .with_zk_engine(zk_arc, genesis_state_root);
        let err = receiving_engine
            .apply_snapshot(snapshot)
            .expect_err("corrupted recursive ZK proof must be rejected");
        assert!(
            err.to_string().contains("recursive state sync proof"),
            "unexpected err: {err}"
        );

        let _ = std::fs::remove_file(path);
    }
}
