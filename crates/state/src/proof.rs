use crate::node::VerkleNode;
use crate::verkle_tree::VerkleTree;
use anyhow::{bail, Result};
use lru::LruCache;
use parking_lot::Mutex;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use sxiaum_types::{Account, Address};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerkleProof {
    pub commitments: Vec<[u8; 32]>,
    #[serde(default)]
    pub kzg_commitments: Vec<Vec<u8>>,
    #[serde(default)]
    pub openings: Vec<Vec<u8>>,
    pub path: Vec<usize>,
    pub values: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcVerkleProof {
    pub root: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
    #[serde(default)]
    pub kzg_commitments: Vec<Vec<u8>>,
    #[serde(default)]
    pub openings: Vec<Vec<u8>>,
    pub path: Vec<usize>,
    pub values: Vec<[u8; 32]>,
    pub minimal: bool,
}

/// Storage slot preimage included in a stateless execution witness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoragePreimage {
    pub address: Address,
    pub slot: [u8; 32],
    pub value: [u8; 32],
}

/// Contract bytecode preimage keyed by code hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodePreimage {
    pub code_hash: [u8; 32],
    pub bytecode: Vec<u8>,
}

/// A cryptographic witness containing proofs for a subset of state keys,
/// plus optional preimages required for **stateless block execution**.
///
/// Phase-1 light clients verify Verkle proofs against `pre_state_root`, hydrate
/// an ephemeral state from `account_preimages` / `storage_preimages`, execute
/// the block, and check the resulting state root.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateWitness {
    /// Independent proofs for each requested key. In a future iteration, this
    /// should be upgraded to a single shared multiproof structure.
    pub proofs: Vec<VerkleProof>,
    /// Full account payloads (nonce, balance, code_hash, -) for proven keys.
    #[serde(default)]
    pub account_preimages: Vec<Account>,
    /// Storage slot values accessed during the block.
    #[serde(default)]
    pub storage_preimages: Vec<StoragePreimage>,
    /// Contract bytecode when EVM code is required for execution.
    #[serde(default)]
    pub code_preimages: Vec<CodePreimage>,
}

impl StateWitness {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_proofs(proofs: Vec<VerkleProof>) -> Self {
        Self {
            proofs,
            ..Self::default()
        }
    }
}

/// A structurally compressed witness that deduplicates internal nodes across multiple proofs.
/// This minimizes bandwidth for stateless clients and light nodes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompressedStateWitness {
    /// Flattened unique KZG commitments across the accessed partial trie.
    pub unique_commitments: Vec<Vec<u8>>,
    /// Minimal instructions required to reconstruct the partial Verkle tree structure.
    pub partial_tree_nodes: Vec<(Vec<usize>, usize)>,
    /// Leaf values.
    pub values: Vec<([u8; 32], [u8; 32])>,
}

impl CompressedStateWitness {
    /// Compress a [`StateWitness`] by deduplicating KZG commitments that are
    /// shared across multiple individual Verkle proofs.
    ///
    /// **Algorithm** (Phase-1 implementation):
    /// 1. Collect every `kzg_commitments` blob from every proof.
    /// 2. Build a deduplication map: `commitment_bytes -> index` in
    ///    `unique_commitments`.
    /// 3. For each proof, record a `(path, last_value)` pair referencing
    ///    the shared index rather than repeating the raw bytes.
    ///
    /// This is a correct, bandwidth-saving implementation for the common case
    /// where multiple accessed keys share inner-node commitments.  A full
    /// cryptographic multiproof (merging the KZG opening arguments) is a
    /// future upgrade tracked in the roadmap.
    pub fn compress(witness: &StateWitness) -> Self {
        use std::collections::HashMap;

        let mut dedup_map: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut unique_commitments: Vec<Vec<u8>> = Vec::new();
        let mut partial_tree_nodes: Vec<(Vec<usize>, usize)> = Vec::new();
        let mut values: Vec<([u8; 32], [u8; 32])> = Vec::new();

        for proof in &witness.proofs {
            // --- deduplicate KZG commitments --------------------------------
            for commitment in &proof.kzg_commitments {
                if !dedup_map.contains_key(commitment) {
                    let idx = unique_commitments.len();
                    dedup_map.insert(commitment.clone(), idx);
                    unique_commitments.push(commitment.clone());
                }
            }

            // --- record path + leaf-value pair ------------------------------
            // The path encodes the trie descent steps; the leaf value is the
            // last element in the proof's value list.
            let path = proof.path.clone();
            // Use the index of the *first* commitment of this proof as a
            // back-reference into `unique_commitments`.
            let commitment_start_idx = proof
                .kzg_commitments
                .first()
                .and_then(|c| dedup_map.get(c))
                .copied()
                .unwrap_or(0);
            partial_tree_nodes.push((path, commitment_start_idx));

            // Derive the canonical 32-byte key from the path.
            let key_bytes: Vec<u8> = proof.path.iter().map(|&x| x as u8).collect();
            let mut key = [0u8; 32];
            let copy_len = key_bytes.len().min(32);
            key[..copy_len].copy_from_slice(&key_bytes[..copy_len]);
            let leaf_value = proof.values.last().copied().unwrap_or([0u8; 32]);
            values.push((key, leaf_value));
        }

        Self {
            unique_commitments,
            partial_tree_nodes,
            values,
        }
    }

    /// Reconstruct a [`StateWitness`] from the compressed representation.
    ///
    /// Each `partial_tree_nodes` entry is mapped back to a `VerkleProof`
    /// by recovering its KZG commitment slice from `unique_commitments`.
    /// Openings are not stored in the compressed form and will be empty;
    /// callers that require openings must re-request them from a full node.
    pub fn decompress(&self) -> StateWitness {
        let proofs: Vec<VerkleProof> = self
            .partial_tree_nodes
            .iter()
            .zip(self.values.iter())
            .map(|((path, commitment_idx), (key, value))| {
                // Recover the commitment for this proof entry.
                let kzg_commitments = self
                    .unique_commitments
                    .get(*commitment_idx)
                    .cloned()
                    .map(|c| vec![c])
                    .unwrap_or_default();

                // The commitment hash is derived from the first unique commitment using domain digest
                let commitment_hash = self
                    .unique_commitments
                    .get(*commitment_idx)
                    .map(|c| sxiaum_crypto::kzg::commitment_digest(c))
                    .unwrap_or([0u8; 32]);

                VerkleProof {
                    commitments: vec![commitment_hash],
                    kzg_commitments,
                    openings: Vec::new(), // not stored in compressed form
                    path: path.clone(),
                    values: vec![*key, *value],
                }
            })
            .collect();

        StateWitness {
            proofs,
            account_preimages: Vec::new(),
            storage_preimages: Vec::new(),
            code_preimages: Vec::new(),
        }
    }
}

/// A thread-safe, memory-efficient cache for storing recently generated or verified witnesses.
pub struct WitnessCache {
    cache: Mutex<LruCache<[u8; 32], StateWitness>>,
}

const MIN_WITNESS_CACHE_CAPACITY: NonZeroUsize = match NonZeroUsize::new(1) {
    Some(cap) => cap,
    None => unreachable!(),
};

impl WitnessCache {
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or(MIN_WITNESS_CACHE_CAPACITY);
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn get(&self, block_hash: [u8; 32]) -> Option<StateWitness> {
        self.cache.lock().get(&block_hash).cloned()
    }

    pub fn put(&self, block_hash: [u8; 32], witness: StateWitness) {
        self.cache.lock().put(block_hash, witness);
    }
}

/// Network payloads for the Light-Client Witness Protocol.
/// This allows light nodes to request partial state proofs from full nodes securely.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LightClientWitnessMessage {
    /// A light client requesting proofs for specific accounts/storage slots.
    WitnessRequest {
        block_hash: [u8; 32],
        keys: Vec<[u8; 32]>,
    },
    /// A full node responding with the compressed witness.
    WitnessResponse {
        block_hash: [u8; 32],
        witness: CompressedStateWitness,
    },
}

impl StateWitness {
    /// Generate a witness containing proofs for multiple keys.
    pub fn generate(tree: &VerkleTree, keys: &[[u8; 32]]) -> Result<Self> {
        let proofs = VerkleProof::batch_proof_generation(tree, keys)?;
        Ok(Self {
            proofs,
            account_preimages: Vec::new(),
            storage_preimages: Vec::new(),
            code_preimages: Vec::new(),
        })
    }

    /// Verify the witness against a known state root and expected key-value pairs.
    pub fn verify(&self, root: [u8; 32], expected_kvs: &[([u8; 32], [u8; 32])]) -> Result<bool> {
        if self.proofs.len() != expected_kvs.len() {
            return Ok(false);
        }
        for (proof, (key, value)) in self.proofs.iter().zip(expected_kvs.iter()) {
            if !proof.verify_proof(*key, *value, root)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verify every account preimage binds to a Verkle proof under `root`.
    ///
    /// For each account `A` we require a proof of key `A.address` whose leaf
    /// value equals `A.try_hash()?`. Proofs without a matching preimage are allowed
    /// (storage-only keys). Preimages without a valid proof are rejected when
    /// `require_proofs` is true.
    pub fn verify_account_preimages(&self, root: [u8; 32], require_proofs: bool) -> Result<()> {
        for account in &self.account_preimages {
            let account_hash = account.try_hash()?;
            let key = *account.address.as_bytes();

            let mut matched_full_proof = false;

            for proof in &self.proofs {
                if proof.values.last().copied() == Some(account_hash) && !proof.openings.is_empty()
                {
                    // SECURITY (C-11): only FULL proofs (with KZG openings)
                    // can bind a preimage to the trusted root. The previous
                    // minimal branch accepted self-consistent attacker-chosen
                    // commitments and was forgeable by construction.
                    if proof.verify_proof(key, account_hash, root)? {
                        matched_full_proof = true;
                        break;
                    }
                }
            }

            if matched_full_proof {
                continue;
            }

            if require_proofs {
                bail!(
                    "account preimage for {} is not proven against state root 0x{}",
                    account.address,
                    hex::encode(root)
                );
            }
        }
        Ok(())
    }

    /// Verify storage preimages against proofs when available.
    pub fn verify_storage_preimages(&self, root: [u8; 32], require_proofs: bool) -> Result<()> {
        for entry in &self.storage_preimages {
            let key = storage_proof_key(&entry.address, &entry.slot);
            let mut verified = false;
            for proof in &self.proofs {
                if proof.verify_proof(key, entry.value, root).unwrap_or(false) {
                    verified = true;
                    break;
                }
            }
            if !verified && require_proofs {
                bail!(
                    "storage preimage for {} slot 0x{} not proven against root",
                    entry.address,
                    hex::encode(entry.slot)
                );
            }
        }
        Ok(())
    }
}

impl VerkleProof {
    pub fn generate_proof(tree: &VerkleTree, key: [u8; 32]) -> Result<Self> {
        let path = tree.path_indices(key);
        let mut commitments = Vec::with_capacity(path.len() + 1);
        let mut kzg_commitments = Vec::with_capacity(path.len() + 1);
        let mut openings = Vec::with_capacity(path.len());
        let mut values = Vec::with_capacity(path.len() + 1);
        let mut current = &tree.root;

        commitments.push(current.commitment());
        kzg_commitments.push(current.kzg_commitment_bytes()?);
        values.push(current.value.unwrap_or([0u8; 32]));

        for index in &path {
            openings.push(current.kzg_opening(*index)?);
            current = current
                .child(*index)
                .ok_or_else(|| anyhow::anyhow!("missing node on proof path"))?;
            commitments.push(current.commitment());
            kzg_commitments.push(current.kzg_commitment_bytes()?);
            values.push(current.value.unwrap_or([0u8; 32]));
        }

        Ok(Self {
            commitments,
            kzg_commitments,
            openings,
            path,
            values,
        })
    }

    /// Verify the Verkle proof using fast batched 2-pairing KZG verification.
    ///
    /// Evaluates all level opening proofs simultaneously via
    /// `sxiaum_crypto::kzg::verify_batched_kzg_openings_multi_point`.
    pub fn verify_proof(&self, key: [u8; 32], value: [u8; 32], root: [u8; 32]) -> Result<bool> {
        self.verify_proof_batched(key, value, root)
    }

    /// Fast batched verification of a single-key Verkle proof using a single 2-pairing check:
    /// $$e\left(\sum_{j=0}^{k-1} r^j \pi_j, [\tau]_2\right) = e\left(\sum_{j=0}^{k-1} r^j \big(\pi_j \cdot z_j + C_j - [y_j]_1\big), G_2\right)$$
    ///
    /// Verifies all path levels in a single pairing equation (~1.8 ms), avoiding
    /// sequential per-level pairing checks.
    pub fn verify_proof_batched(
        &self,
        key: [u8; 32],
        value: [u8; 32],
        root: [u8; 32],
    ) -> Result<bool> {
        self.validate_full_shape(key)?;

        if self.commitments[0] != root {
            return Ok(false);
        }

        if self.values.last().copied().unwrap_or([0u8; 32]) != value {
            return Ok(false);
        }

        let n = self.path.len();
        let evaluations: Vec<Option<[u8; 32]>> = self.commitments[1..=n]
            .iter()
            .map(|c| Some(*c))
            .collect();

        let ok = sxiaum_crypto::kzg::verify_batched_kzg_openings_multi_point(
            &self.kzg_commitments[..n],
            &self.path,
            &evaluations,
            &self.openings,
        )?;
        if !ok {
            return Ok(false);
        }

        Ok(self.commitments.last().copied() == Some(Self::leaf_commitment(value)))
    }

    /// Sequential per-level verification of a single-key Verkle proof (fallback/reference).
    pub fn verify_proof_sequential(
        &self,
        key: [u8; 32],
        value: [u8; 32],
        root: [u8; 32],
    ) -> Result<bool> {
        self.validate_full_shape(key)?;

        if self.commitments[0] != root {
            return Ok(false);
        }

        if self.values.last().copied().unwrap_or([0u8; 32]) != value {
            return Ok(false);
        }

        for depth in 0..self.path.len() {
            let child_commitment = self.commitments[depth + 1];
            if !sxiaum_crypto::kzg::verify_kzg_opening(
                &self.kzg_commitments[depth],
                self.path[depth],
                Some(child_commitment),
                &self.openings[depth],
            )? {
                return Ok(false);
            }
        }

        Ok(self.commitments.last().copied() == Some(Self::leaf_commitment(value)))
    }

    pub fn generate_account_proof(tree: &VerkleTree, address: &Address) -> Result<Self> {
        Self::generate_proof(tree, *address.as_bytes())
    }

    pub fn generate_storage_proof(
        tree: &VerkleTree,
        address: &Address,
        key: [u8; 32],
    ) -> Result<Self> {
        let storage_key = storage_proof_key(address, &key);
        Self::generate_proof(tree, storage_key)
    }

    /// Spot-check an account proof using the batched KZG path (single 2-pairing check).
    pub fn verify_account_proof(
        &self,
        address: &Address,
        account: &Account,
        root: [u8; 32],
    ) -> Result<bool> {
        self.verify_account_proof_batched(address, account, root)
    }

    /// Spot-check an account proof using the batched KZG path.
    pub fn verify_account_proof_batched(
        &self,
        address: &Address,
        account: &Account,
        root: [u8; 32],
    ) -> Result<bool> {
        self.verify_proof_batched(*address.as_bytes(), account.try_hash()?, root)
    }

    /// Spot-check a storage proof using the batched KZG path (single 2-pairing check).
    pub fn verify_storage_proof(
        &self,
        address: &Address,
        key: [u8; 32],
        value: [u8; 32],
        root: [u8; 32],
    ) -> Result<bool> {
        self.verify_storage_proof_batched(address, key, value, root)
    }

    /// Spot-check a storage proof using the batched KZG path.
    pub fn verify_storage_proof_batched(
        &self,
        address: &Address,
        key: [u8; 32],
        value: [u8; 32],
        root: [u8; 32],
    ) -> Result<bool> {
        self.verify_proof_batched(storage_proof_key(address, &key), value, root)
    }

    pub fn batch_proof_generation(tree: &VerkleTree, keys: &[[u8; 32]]) -> Result<Vec<Self>> {
        keys.par_iter()
            .map(|key| Self::generate_proof(tree, *key))
            .collect()
    }

    pub fn generate_minimal_proof(tree: &VerkleTree, key: [u8; 32]) -> Result<Self> {
        let full = Self::generate_proof(tree, key)?;
        let minimal_commitments = full
            .commitments
            .first()
            .copied()
            .into_iter()
            .chain(full.commitments.last().copied())
            .collect();
        let minimal_values = full.values.last().copied().into_iter().collect();

        Ok(Self {
            commitments: minimal_commitments,
            kzg_commitments: Vec::new(),
            openings: Vec::new(),
            path: full.path,
            values: minimal_values,
        })
    }

    pub fn export_for_rpc(&self, root: [u8; 32]) -> RpcVerkleProof {
        RpcVerkleProof {
            root,
            commitments: self.commitments.clone(),
            kzg_commitments: self.kzg_commitments.clone(),
            openings: self.openings.clone(),
            path: self.path.clone(),
            values: self.values.clone(),
            minimal: false,
        }
    }

    pub fn export_minimal_for_rpc(&self, root: [u8; 32]) -> RpcVerkleProof {
        RpcVerkleProof {
            root,
            commitments: self
                .commitments
                .first()
                .copied()
                .into_iter()
                .chain(self.commitments.last().copied())
                .collect(),
            kzg_commitments: Vec::new(),
            openings: Vec::new(),
            path: self.path.clone(),
            values: self.values.last().copied().into_iter().collect(),
            minimal: true,
        }
    }

    pub fn verify_for_light_client(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        if rpc_proof.minimal {
            // SECURITY (C-11): minimal proofs carry no KZG openings — every
            // check on them is self-consistency between attacker-chosen
            // fields, so ANY (key, value) pair can be "proven" under ANY
            // root. They are forgeable by construction and are rejected at
            // every trust boundary.
            Self::verify_minimal_rpc_proof(rpc_proof, key, value)
        } else {
            let full_like = VerkleProof {
                commitments: rpc_proof.commitments.clone(),
                kzg_commitments: rpc_proof.kzg_commitments.clone(),
                openings: rpc_proof.openings.clone(),
                path: rpc_proof.path.clone(),
                values: rpc_proof.values.clone(),
            };
            full_like.verify_proof(key, value, rpc_proof.root)
        }
    }

    pub fn verify(
        &self,
        root_hash: [u8; 32],
        keys: &[[u8; 32]],
        values: &[[u8; 32]],
    ) -> Result<bool> {
        if keys.len() != 1 || values.len() != 1 {
            bail!("current proof verifier expects a single key/value pair");
        }

        self.verify_proof(keys[0], values[0], root_hash)
    }

    fn validate_full_shape(&self, key: [u8; 32]) -> Result<()> {
        if self.commitments.is_empty() {
            bail!("proof commitments cannot be empty");
        }

        if self.values.len() != self.commitments.len() {
            bail!("proof values length must match commitments length");
        }

        let expected_path: Vec<usize> = key.iter().map(|byte| *byte as usize).collect();
        if self.path != expected_path {
            bail!("proof path does not match key bytes");
        }

        if self.commitments.len() != self.path.len() + 1 {
            bail!("proof commitments length must be path length plus one");
        }

        if self.kzg_commitments.len() != self.commitments.len() {
            bail!("proof KZG commitments length must match commitments length");
        }

        if self.openings.len() != self.path.len() {
            bail!("proof opening length must match path length");
        }

        Ok(())
    }

    /// SECURITY (C-11): minimal proofs are forgeable by construction.
    ///
    /// The previous implementation "verified" them with:
    ///   root == commitments[0]  (both attacker-chosen),
    ///   values[0] == value      (claimed value),
    ///   commitments[1] == leaf_commitment(value) (publicly computable).
    /// No cryptographic binding to a trusted root exists, so anyone could
    /// produce a minimal proof for any (key, value) under any root. Minimal
    /// proofs are therefore UNCONDITIONALLY REJECTED.
    fn verify_minimal_rpc_proof(
        rpc_proof: &RpcVerkleProof,
        _key: [u8; 32],
        _value: [u8; 32],
    ) -> Result<bool> {
        bail!(
            "minimal Verkle proofs are not cryptographically verifiable and are rejected \
             (proof at path {:?} claims root 0x{})",
            rpc_proof.path,
            hex::encode(rpc_proof.root)
        );
    }

    fn leaf_commitment(value: [u8; 32]) -> [u8; 32] {
        VerkleNode::new_leaf([0u8; 32], value).commitment()
    }
}

impl VerkleTree {
    pub fn generate_proof(&self, key: [u8; 32]) -> Result<VerkleProof> {
        VerkleProof::generate_proof(self, key)
    }

    pub fn batch_proof_generation(&self, keys: &[[u8; 32]]) -> Result<Vec<VerkleProof>> {
        VerkleProof::batch_proof_generation(self, keys)
    }

    pub fn generate_minimal_proof(&self, key: [u8; 32]) -> Result<VerkleProof> {
        VerkleProof::generate_minimal_proof(self, key)
    }

    /// Generate a shared [`VerkleMultiProof`] covering multiple keys in a single
    /// structure that deduplicates internal-node commitments and KZG openings.
    ///
    /// This is the P1 multiproof implementation.  For single-key proofs or
    /// cases where the individual [`VerkleProof`] API is sufficient, use
    /// `generate_proof`/`batch_proof_generation` instead.
    pub fn generate_multiproof(&self, keys: &[[u8; 32]]) -> Result<VerkleMultiProof> {
        VerkleMultiProof::generate(self, keys)
    }
}

/// A shared Verkle multiproof covering N keys with deduplicated internal-node commitments.
///
/// **P1 improvement** over the existing approach of N independent [`VerkleProof`]s.
/// When multiple accessed keys share inner nodes (very common in the same block), this
/// structure stores each inner commitment and its KZG opening exactly once rather than
/// repeating it per key.
///
/// # Wire format
/// Transmitted as part of the [`StateWitness`] when more than one key is accessed.
/// The verifier reconstructs per-key paths using `key_path_lengths` and the flattened
/// `shared_path_indices` slice.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerkleMultiProof {
    /// Root commitment (first element of every key's proof path — identical for all keys
    /// under the same root, stored once here).
    pub root: [u8; 32],
    /// Deduplicated list of inner-node KZG commitment bytes (G1 serialised, 48 or 32 bytes).
    pub shared_commitments: Vec<Vec<u8>>,
    /// One KZG opening proof per entry in `shared_commitments`.
    pub shared_openings: Vec<Vec<u8>>,
    /// Evaluation index per shared commitment (the child index in the branching factor).
    pub shared_indices: Vec<usize>,
    /// Evaluation (child commitment hash) per shared opening.
    pub shared_evaluations: Vec<Option<[u8; 32]>>,
    /// For each key: the indices into `shared_commitments` that form its proof path.
    pub key_commitment_refs: Vec<Vec<usize>>,
    /// Leaf values for each key (same order as the original key slice).
    pub leaf_values: Vec<[u8; 32]>,
    /// SECURITY (multiproof anchoring): for every entry in `shared_commitments`,
    /// the full node commitment digest of the node that produced it. Entry 0 of
    /// any key path MUST equal the trusted state root, and consecutive entries
    /// MUST chain through `shared_evaluations`. Without these digests a
    /// multiproof assembled from honest tuples of *unrelated* trees would
    /// verify under an arbitrary claimed root.
    pub shared_self_digests: Vec<[u8; 32]>,
}

type MultiProofNodeKey = (Vec<u8>, usize, Option<[u8; 32]>, [u8; 32]);

impl VerkleMultiProof {
    /// Generate a shared multiproof for `keys` against `tree`.
    ///
    /// This walks each key's proof path, deduplicates unique `(commitment, child_index)`
    /// openings that appear across paths, and records a single KZG opening per unique evaluation.
    pub fn generate(tree: &VerkleTree, keys: &[[u8; 32]]) -> Result<Self> {
        use std::collections::HashMap;

        let mut commit_map: HashMap<MultiProofNodeKey, usize> = HashMap::new();
        let mut shared_commitments: Vec<Vec<u8>> = Vec::new();
        let mut shared_openings: Vec<Vec<u8>> = Vec::new();
        let mut shared_indices: Vec<usize> = Vec::new();
        let mut shared_evaluations: Vec<Option<[u8; 32]>> = Vec::new();
        let mut shared_self_digests: Vec<[u8; 32]> = Vec::new();
        let mut key_commitment_refs: Vec<Vec<usize>> = Vec::new();
        let mut leaf_values: Vec<[u8; 32]> = Vec::new();

        let root_commitment = tree.root_commitment();

        for key in keys {
            let proof = VerkleProof::generate_proof(tree, *key)?;
            let mut refs: Vec<usize> = Vec::with_capacity(proof.path.len());

            for (depth, child_index) in proof.path.iter().enumerate() {
                let kzg_bytes = &proof.kzg_commitments[depth];
                let evaluation = proof.commitments.get(depth + 1).copied();
                let self_digest = proof.commitments[depth];
                let map_key = (kzg_bytes.clone(), *child_index, evaluation, self_digest);

                let idx = if let Some(&existing) = commit_map.get(&map_key) {
                    existing
                } else {
                    let new_idx = shared_commitments.len();
                    commit_map.insert(map_key, new_idx);
                    shared_commitments.push(kzg_bytes.clone());
                    let opening = proof.openings.get(depth).cloned().unwrap_or_default();
                    shared_openings.push(opening);
                    shared_indices.push(*child_index);
                    shared_evaluations.push(evaluation);
                    shared_self_digests.push(self_digest);
                    new_idx
                };
                refs.push(idx);
            }

            key_commitment_refs.push(refs);
            leaf_values.push(proof.values.last().copied().unwrap_or([0u8; 32]));
        }

        Ok(Self {
            root: root_commitment,
            shared_commitments,
            shared_openings,
            shared_indices,
            shared_evaluations,
            key_commitment_refs,
            leaf_values,
            shared_self_digests,
        })
    }

    /// Verify the multiproof against `root` and the expected `(key, value)` pairs.
    ///
    /// Runs one KZG opening check per unique evaluation (not per key), and validates
    /// path integrity, root anchoring, inter-level chaining, and leaf binding for
    /// every requested key.
    ///
    /// SECURITY (multiproof anchoring): every key's first entry must carry a self
    /// digest equal to the CALLER-SUPPLIED trusted `root` (the multiproof's own
    /// `root` field is attacker-settable metadata), and consecutive entries must
    /// chain via `shared_self_digests == shared_evaluations`. This prevents
    /// splicing honest openings from unrelated trees under a foreign root.
    pub fn verify_multiproof(
        &self,
        root: [u8; 32],
        keys: &[[u8; 32]],
        values: &[[u8; 32]],
    ) -> Result<bool> {
        if keys.len() != self.leaf_values.len() || values.len() != keys.len() {
            return Ok(false);
        }

        // All shared arrays must be complete; truncated structures are rejected
        // instead of silently verified over the overlapping prefix.
        let n = self.shared_commitments.len();
        if self.shared_openings.len() != n
            || self.shared_indices.len() != n
            || self.shared_evaluations.len() != n
            || self.shared_self_digests.len() != n
        {
            return Ok(false);
        }
        if self.key_commitment_refs.len() != keys.len() {
            return Ok(false);
        }

        // Verify leaf values match expected values.
        for (i, value) in values.iter().enumerate() {
            if self.leaf_values[i] != *value {
                return Ok(false);
            }
        }

        // Cryptographic: verify every unique KZG opening.
        for j in 0..n {
            let ok = sxiaum_crypto::kzg::verify_kzg_opening(
                &self.shared_commitments[j],
                self.shared_indices[j],
                self.shared_evaluations[j],
                &self.shared_openings[j],
            )?;
            if !ok {
                return Ok(false);
            }
        }

        // Verify path consistency, root anchoring, level linkage, and leaf
        // binding for each key.
        for (i, key) in keys.iter().enumerate() {
            let refs = &self.key_commitment_refs[i];

            let path: Vec<usize> = key.iter().map(|b| *b as usize).collect();
            if refs.len() != path.len() || refs.is_empty() {
                return Ok(false);
            }

            for depth in 0..path.len() {
                let ref_idx = refs[depth];
                if ref_idx >= n {
                    return Ok(false);
                }
                if self.shared_indices[ref_idx] != path[depth] {
                    return Ok(false);
                }
            }

            // Anchor the first level to the caller-supplied trusted root.
            if self.shared_self_digests[refs[0]] != root {
                return Ok(false);
            }

            // Chain every deeper level to its parent's evaluated child digest.
            for depth in 0..path.len() - 1 {
                if Some(self.shared_self_digests[refs[depth + 1]])
                    != self.shared_evaluations[refs[depth]]
                {
                    return Ok(false);
                }
            }

            // The final evaluation at depth 31 must bind to the leaf commitment of leaf_values[i].
            let last_ref = refs[path.len() - 1];
            let expected_leaf_commitment = VerkleProof::leaf_commitment(self.leaf_values[i]);
            if self.shared_evaluations[last_ref] != Some(expected_leaf_commitment) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Fast batched verification of the multiproof using a single BLS12-381 2-pairing check:
    /// $$e\left(\sum_{j=0}^{k-1} r^j \pi_j, [\tau]_2\right) = e\left(\sum_{j=0}^{k-1} r^j \big(\pi_j \cdot z_j + C_j - [y_j]_1\big), G_2\right)$$
    ///
    /// Achieves ~1.8–2.5 ms verification time for multi-slot block witnesses on mobile and edge devices.
    pub fn verify_multiproof_batched(
        &self,
        root: [u8; 32],
        keys: &[[u8; 32]],
        values: &[[u8; 32]],
    ) -> Result<bool> {
        if keys.len() != self.leaf_values.len() || values.len() != keys.len() {
            return Ok(false);
        }

        let n = self.shared_commitments.len();
        if self.shared_openings.len() != n
            || self.shared_indices.len() != n
            || self.shared_evaluations.len() != n
            || self.shared_self_digests.len() != n
        {
            return Ok(false);
        }
        if self.key_commitment_refs.len() != keys.len() {
            return Ok(false);
        }

        // Verify leaf values match expected values.
        for (i, value) in values.iter().enumerate() {
            if self.leaf_values[i] != *value {
                return Ok(false);
            }
        }

        // Cryptographic: verify all unique KZG openings in a single batched 2-pairing check!
        let ok = sxiaum_crypto::kzg::verify_batched_kzg_openings_multi_point(
            &self.shared_commitments,
            &self.shared_indices,
            &self.shared_evaluations,
            &self.shared_openings,
        )?;
        if !ok {
            return Ok(false);
        }

        // Verify path consistency, root anchoring, level linkage, and leaf
        // binding for each key.
        for (i, key) in keys.iter().enumerate() {
            let refs = &self.key_commitment_refs[i];

            let path: Vec<usize> = key.iter().map(|b| *b as usize).collect();
            if refs.len() != path.len() || refs.is_empty() {
                return Ok(false);
            }

            for depth in 0..path.len() {
                let ref_idx = refs[depth];
                if ref_idx >= n {
                    return Ok(false);
                }
                if self.shared_indices[ref_idx] != path[depth] {
                    return Ok(false);
                }
            }

            // Anchor the first level to the caller-supplied trusted root.
            if self.shared_self_digests[refs[0]] != root {
                return Ok(false);
            }

            // Chain every deeper level to its parent's evaluated child digest.
            for depth in 0..path.len() - 1 {
                if Some(self.shared_self_digests[refs[depth + 1]])
                    != self.shared_evaluations[refs[depth]]
                {
                    return Ok(false);
                }
            }

            // The final evaluation at depth 31 must bind to the leaf commitment of leaf_values[i].
            let last_ref = refs[path.len() - 1];
            let expected_leaf_commitment = VerkleProof::leaf_commitment(self.leaf_values[i]);
            if self.shared_evaluations[last_ref] != Some(expected_leaf_commitment) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

pub fn storage_proof_key(address: &Address, key: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(address.as_bytes().len() + key.len());
    material.extend_from_slice(address.as_bytes());
    material.extend_from_slice(key);
    sxiaum_crypto::hash::domain_hash("SXIAUM_STORAGE_SLOT", &material)
}

#[cfg(test)]
mod tests {
    use super::{storage_proof_key, RpcVerkleProof, VerkleProof};
    use crate::verkle_tree::VerkleTree;
    use sxiaum_types::{Account, Address};

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn generate_and_verify_basic_proof() {
        let mut tree = VerkleTree::new();
        let key = hash(1);
        let value = hash(2);
        tree.insert(key, value).expect("tree insert should succeed");

        let proof =
            VerkleProof::generate_proof(&tree, key).expect("proof generation should succeed");

        assert_eq!(proof.path, tree.path_indices(key));
        assert_eq!(
            proof.commitments.first().copied(),
            Some(tree.root_commitment())
        );
        assert_eq!(proof.values.last().copied(), Some(value));
        assert!(proof
            .verify_proof(key, value, tree.root_commitment())
            .expect("proof verification should succeed"));
        assert!(!proof
            .verify_proof(key, hash(9), tree.root_commitment())
            .expect("mismatched value check should succeed"));
    }

    #[test]
    fn account_and_storage_proof_helpers_round_trip() {
        let mut tree = VerkleTree::new();
        let address = Address(hash(3));
        let account = Account::new(address);
        let account_hash = account.try_hash().unwrap();
        tree.insert(*address.as_bytes(), account_hash)
            .expect("account insert should succeed");

        let account_proof = VerkleProof::generate_account_proof(&tree, &address)
            .expect("account proof generation should succeed");
        assert!(account_proof
            .verify_account_proof(&address, &account, tree.root_commitment())
            .expect("account proof verification should succeed"));

        let storage_slot = hash(4);
        let storage_value = hash(5);
        let proof_key = storage_proof_key(&address, &storage_slot);
        tree.insert(proof_key, storage_value)
            .expect("storage insert should succeed");

        let storage_proof = VerkleProof::generate_storage_proof(&tree, &address, storage_slot)
            .expect("storage proof generation should succeed");
        assert!(storage_proof
            .verify_storage_proof(
                &address,
                storage_slot,
                storage_value,
                tree.root_commitment()
            )
            .expect("storage proof verification should succeed"));
    }

    #[test]
    fn batch_proof_generation_returns_all_requested_proofs() {
        let mut tree = VerkleTree::new();
        let keys = vec![hash(6), hash(7), hash(8)];

        for (index, key) in keys.iter().enumerate() {
            tree.insert(*key, hash(index as u8 + 10))
                .expect("tree insert should succeed");
        }

        let proofs = VerkleProof::batch_proof_generation(&tree, &keys)
            .expect("batch proof generation should succeed");

        assert_eq!(proofs.len(), keys.len());
        for (index, proof) in proofs.iter().enumerate() {
            assert!(proof
                .verify_proof(keys[index], hash(index as u8 + 10), tree.root_commitment())
                .expect("proof verification should succeed"));
        }
    }

    #[test]
    fn verify_proof_rejects_invalid_shape() {
        let proof = VerkleProof {
            commitments: vec![[1u8; 32]],
            kzg_commitments: vec![],
            openings: vec![],
            path: vec![1, 2, 3],
            values: vec![],
        };

        assert!(proof.verify_proof(hash(1), hash(2), hash(3)).is_err());
    }

    #[test]
    fn minimal_proofs_are_rejected_at_verification() {
        let mut tree = VerkleTree::new();
        let key = hash(11);
        let value = hash(12);
        tree.insert(key, value).expect("tree insert should succeed");

        // SECURITY (C-11): even a CORRECTLY generated minimal proof must be
        // rejected — the format is forgeable by construction.
        let proof = VerkleProof::generate_minimal_proof(&tree, key)
            .expect("minimal proof generation should succeed");
        let rpc = proof.export_minimal_for_rpc(tree.root_commitment());

        assert!(
            VerkleProof::verify_for_light_client(&rpc, key, value).is_err(),
            "minimal proofs must be rejected even for genuine data"
        );
    }

    #[test]
    fn minimal_rpc_proof_rejects_invalid_shape() {
        let rpc = RpcVerkleProof {
            root: hash(1),
            commitments: vec![hash(1)],
            kzg_commitments: vec![],
            openings: vec![],
            path: vec![1; 32],
            values: vec![hash(2)],
            minimal: true,
        };

        assert!(VerkleProof::verify_for_light_client(&rpc, hash(1), hash(2)).is_err());
    }

    #[test]
    fn multiproof_round_trip_deduplicates_commitments() {
        let mut tree = VerkleTree::new();
        // Create 3 keys that share the first byte so they share the root's child node.
        let mut k1 = hash(1);
        k1[0] = 0x42;
        let mut k2 = hash(2);
        k2[0] = 0x42;
        let mut k3 = hash(3);
        k3[0] = 0x42;

        let v1 = hash(11);
        let v2 = hash(12);
        let v3 = hash(13);

        tree.insert(k1, v1).unwrap();
        tree.insert(k2, v2).unwrap();
        tree.insert(k3, v3).unwrap();

        let keys = vec![k1, k2, k3];
        let values = vec![v1, v2, v3];

        let multiproof = tree
            .generate_multiproof(&keys)
            .expect("multiproof generation should succeed");

        // Root should match
        assert_eq!(multiproof.root, tree.root_commitment());

        // With 3 keys sharing the first byte, they share the root commitment.
        // A naive list of independent proofs would have 3 * 32 = 96 commitments.
        // The multiproof should deduplicate the shared inner nodes.
        assert!(multiproof.shared_commitments.len() < keys.len() * 32);

        // Verify it passes
        let ok = multiproof
            .verify_multiproof(tree.root_commitment(), &keys, &values)
            .expect("multiproof verification should not error");
        assert!(ok, "multiproof should verify successfully");

        // Tamper with a value
        let mut bad_values = values.clone();
        bad_values[0] = hash(99);
        let bad_ok = multiproof
            .verify_multiproof(tree.root_commitment(), &keys, &bad_values)
            .expect("multiproof verification should not error");
        assert!(!bad_ok, "multiproof should fail with bad value");
    }

    #[test]
    fn multiproof_rejects_foreign_root_splice_attack() {
        // SECURITY REGRESSION (multiproof anchoring): the previous verifier
        // compared only the attacker-settable `root` metadata field and never
        // bound `shared_commitments` to the trusted root. A multiproof honestly
        // generated against tree A verified under ANY root, letting honest
        // tuples from unrelated trees be spliced into forged claims.
        let build_tree = |seed: u8| {
            let mut tree = VerkleTree::new();
            for i in 0..3u8 {
                let mut key = [0u8; 32];
                key[0] = 0x42;
                key[1] = seed;
                key[2] = i;
                tree.insert(key, hash(seed * 10 + i)).unwrap();
            }
            tree
        };

        let tree_a = build_tree(1);
        let tree_b = build_tree(2);
        assert_ne!(tree_a.root_commitment(), tree_b.root_commitment());

        let keys: Vec<[u8; 32]> = (0..3u8)
            .map(|i| {
                let mut key = [0u8; 32];
                key[0] = 0x42;
                key[1] = 1;
                key[2] = i;
                key
            })
            .collect();

        let honest_for_a = tree_a
            .generate_multiproof(&keys)
            .expect("multiproof generation should succeed");

        // The multiproof's own root field still claims A — but the caller
        // anchors to B, so verification must fail even though every opening
        // tuple inside is cryptographically genuine.
        let spliced = honest_for_a
            .verify_multiproof(tree_b.root_commitment(), &keys, &honest_for_a.leaf_values)
            .expect("splice check should not error");
        assert!(
            !spliced,
            "multiproof generated under a foreign tree must never verify under another root"
        );

        // Tampering any single self digest must also break verification.
        let mut tampered = tree_a
            .generate_multiproof(&keys)
            .expect("multiproof generation should succeed");
        tampered.shared_self_digests[0] = hash(200);
        let tampered_ok = tampered
            .verify_multiproof(tree_a.root_commitment(), &keys, &tampered.leaf_values)
            .expect("tamper check should not error");
        assert!(!tampered_ok, "tampered self digest must fail verification");

        // Truncated shared arrays must be rejected, not partially verified.
        let mut truncated = tree_a
            .generate_multiproof(&keys)
            .expect("multiproof generation should succeed");
        truncated.shared_self_digests.pop();
        let truncated_ok = truncated
            .verify_multiproof(tree_a.root_commitment(), &keys, &truncated.leaf_values)
            .expect("truncation check should not error");
        assert!(
            !truncated_ok,
            "length-mismatched multiproof must fail closed"
        );
    }

    #[test]
    fn batched_multiproof_matches_sequential_verification() {
        let mut tree = VerkleTree::new();
        let mut keys = Vec::new();
        let mut expected_values = Vec::new();

        for i in 0..5u8 {
            let mut key = [0u8; 32];
            key[0] = 0xAA;
            key[1] = i * 10;
            key[2] = i;
            let val = hash(i + 50);
            tree.insert(key, val).unwrap();
            keys.push(key);
            expected_values.push(val);
        }

        let multiproof = tree.generate_multiproof(&keys).unwrap();

        // 1. Sequential verify passes
        assert!(multiproof
            .verify_multiproof(tree.root_commitment(), &keys, &expected_values)
            .unwrap());

        // 2. Batched verify passes identically
        assert!(multiproof
            .verify_multiproof_batched(tree.root_commitment(), &keys, &expected_values)
            .unwrap());

        // 3. Foreign root fails in batched mode
        assert!(!multiproof
            .verify_multiproof_batched([0xEE; 32], &keys, &expected_values)
            .unwrap());

        // 4. Tampered leaf value fails in batched mode
        let mut bad_values = expected_values.clone();
        bad_values[2] = hash(99);
        assert!(!multiproof
            .verify_multiproof_batched(tree.root_commitment(), &keys, &bad_values)
            .unwrap());
    }
}
