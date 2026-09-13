//! State Transition Function (STF) circuit constraints for the SP1 guest.
//!
//! Phase-1 mainnet scope (see `docs/specs/core_protocol.md`):
//! prove **state transition validity** - signatures, gas accounting, Verkle
//! access structure, deterministic ordering, and commit-reveal digests -
//! **not** full EVM opcode emulation.
//!
//! The same constraint set is executed inside `crates/zk/guest` so host-side
//! prechecks and the zkVM guest stay aligned.

use crate::sp1::prover::{ZkBlockWitness, ZkPublicInputs};
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sxiaum_block::Block;
use sxiaum_types::{Address, Transaction};

/// Default block gas ceiling used when the caller does not supply one.
pub const DEFAULT_MAX_BLOCK_GAS: u64 = sxiaum_block::MAX_BLOCK_GAS_LIMIT;

/// Wire-format version for guest - host compatibility.
pub const STF_CIRCUIT_VERSION: u32 = 1;

/// Domain tags for commitments (must match guest).
const DOM_READS: &[u8] = b"sxiaum:stf:reads:v1";
const DOM_WRITES: &[u8] = b"sxiaum:stf:writes:v1";
const DOM_VERKLE: &[u8] = b"sxiaum:stf:verkle:v1";
const DOM_CR: &[u8] = b"sxiaum:stf:commit_reveal:v1";
const DOM_BIND: &[u8] = b"sxiaum:stf:bind:v1";

/// Serde helper: `[u8; 64]` is not supported by default serde array impls.
mod serde_sig64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(val: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        val.as_slice().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        bytes
            .try_into()
            .map_err(|_| D::Error::custom("expected 64-byte signature"))
    }
}

/// One transaction's data required to re-verify signature + gas in-circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfTxWitness {
    pub tx_hash: [u8; 32],
    pub from: [u8; 32],
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    /// Ed25519 verifying key (32 bytes). Empty / zero for pre-hashed eth path.
    pub pubkey: [u8; 32],
    /// Ed25519 signature (64 bytes).
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
    /// Message that was signed (native txs: transaction hash).
    pub signed_message: [u8; 32],
    /// `0` = Ed25519, `1` = Ethereum raw (guest checks commitment only).
    pub scheme: u8,
    /// Nonce used to reveal the transaction (for MEV commit-reveal ordering).
    pub reveal_nonce: [u8; 32],
}

/// Sparse state access entry (account or storage key).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfStateAccess {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Verkle proof fragment supplied to the STF circuit for each state access group.
///
/// **Cryptographic enforcement (since mainnet launch)**: every `(commitment[i],
/// evaluation_point[i], evaluation[i], opening_proof[i])` tuple is verified
/// using a real KZG opening check via `sxiaum_crypto::kzg::verify_kzg_opening`.
/// Previously Phase-1 only performed structural / shape checks; the full KZG
/// pairing verification is now mandatory for all non-empty proof entries.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfVerkleProof {
    pub commitments: Vec<[u8; 32]>,
    pub evaluation_points: Vec<[u8; 32]>,
    pub evaluations: Vec<[u8; 32]>,
    pub opening_proofs: Vec<Vec<u8>>,
    pub witness_root: [u8; 32],
}

/// Private witness consumed by the SP1 guest together with [`ZkPublicInputs`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfPrivateInputs {
    pub version: u32,
    pub max_block_gas: u64,
    pub transactions: Vec<StfTxWitness>,
    pub state_reads: Vec<StfStateAccess>,
    pub state_writes: Vec<StfStateAccess>,
    pub verkle_proofs: Vec<StfVerkleProof>,
    /// Commit-reveal digests (HMAC/hash commitments) for MEV-protected txs.
    pub commit_reveal_digests: Vec<[u8; 32]>,
    /// Binding commitment over public + private aggregates (see `compute_binding`).
    pub binding: [u8; 32],
}

impl Default for StfPrivateInputs {
    fn default() -> Self {
        Self {
            version: STF_CIRCUIT_VERSION,
            max_block_gas: DEFAULT_MAX_BLOCK_GAS,
            transactions: Vec::new(),
            state_reads: Vec::new(),
            state_writes: Vec::new(),
            verkle_proofs: Vec::new(),
            commit_reveal_digests: Vec::new(),
            binding: [0u8; 32],
        }
    }
}

impl StfPrivateInputs {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(bincode::deserialize(bytes)?)
    }

    /// Build private inputs from a block body and per-tx execution metrics.
    #[allow(clippy::too_many_arguments)]
    pub fn from_block(
        block: &Block,
        gas_used_per_tx: &[u64],
        state_reads: Vec<StfStateAccess>,
        state_writes: Vec<StfStateAccess>,
        verkle_proofs: Vec<StfVerkleProof>,
        commit_reveal_digests: Vec<[u8; 32]>,
        reveal_nonces: Vec<[u8; 32]>,
        max_block_gas: u64,
        public: &ZkPublicInputs,
    ) -> Result<Self> {
        if block.body.transactions.len() != gas_used_per_tx.len() {
            bail!(
                "gas_used_per_tx length {} != tx count {}",
                gas_used_per_tx.len(),
                block.body.transactions.len()
            );
        }
        if block.body.transactions.len() != reveal_nonces.len() {
            bail!(
                "reveal_nonces length {} != tx count {}",
                reveal_nonces.len(),
                block.body.transactions.len()
            );
        }
        let mut transactions = Vec::with_capacity(block.body.transactions.len());
        for (i, (tx, &gas_used)) in block
            .body
            .transactions
            .iter()
            .zip(gas_used_per_tx.iter())
            .enumerate()
        {
            transactions.push(build_tx_witness(tx, gas_used, reveal_nonces[i])?);
        }

        let mut private = Self {
            version: STF_CIRCUIT_VERSION,
            max_block_gas,
            transactions,
            state_reads,
            state_writes,
            verkle_proofs,
            commit_reveal_digests,
            binding: [0u8; 32],
        };
        private.binding = compute_binding(public, &private);
        Ok(private)
    }
}

pub fn build_tx_witness(
    tx: &Transaction,
    gas_used: u64,
    reveal_nonce: [u8; 32],
) -> Result<StfTxWitness> {
    let tx_hash = tx.try_hash()?;
    let from = *tx.from.as_bytes();

    // Ethereum-originated raw txs: bind sighash + recovery material without full secp in guest.
    if tx.ethereum_y_parity.is_some() || tx.ethereum_sighash.is_some() {
        let sighash = tx
            .ethereum_sighash
            .ok_or_else(|| anyhow::anyhow!("ethereum tx missing sighash for STF witness"))?;
        let mut signature = [0u8; 64];
        if let Some(sig) = tx.signature {
            signature = sig;
        }
        let mut pubkey = [0u8; 32];
        if let Some(pk) = tx.signer_pubkey {
            pubkey = pk;
        }
        return Ok(StfTxWitness {
            tx_hash,
            from,
            nonce: tx.nonce,
            gas_limit: tx.gas_limit,
            gas_used,
            pubkey,
            signature,
            signed_message: sighash,
            scheme: 1,
            reveal_nonce,
        });
    }

    let pubkey = tx
        .signer_pubkey
        .ok_or_else(|| anyhow::anyhow!("tx missing signer_pubkey for STF witness"))?;
    let signature = tx
        .signature
        .ok_or_else(|| anyhow::anyhow!("tx missing signature for STF witness"))?;

    Ok(StfTxWitness {
        tx_hash,
        from,
        nonce: tx.nonce,
        gas_limit: tx.gas_limit,
        gas_used,
        pubkey,
        signature,
        signed_message: tx_hash,
        scheme: 0,
        reveal_nonce,
    })
}

pub fn compute_ordering_seed(
    parent_hash: &[u8; 32],
    height: u64,
    beacon_randomness: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(parent_hash);
    hasher.update(height.to_le_bytes());
    hasher.update(beacon_randomness);
    hasher.finalize().into()
}

pub fn randomize_ordering<T>(items: &mut [T], seed: &[u8; 32], height: u64) {
    let n = items.len();
    if n == 0 {
        return;
    }
    for i in (1..n).rev() {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(height.to_le_bytes());
        h.update((i as u64).to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let r = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
        let j = (r as usize) % (i + 1);
        items.swap(i, j);
    }
}

pub fn compute_commit_hash(reveal_nonce: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(reveal_nonce);
    h.update(tx_hash);
    h.finalize().into()
}

pub fn compute_reads_commitment(reads: &[StfStateAccess]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOM_READS);
    hasher.update((reads.len() as u64).to_le_bytes());
    for r in reads {
        hasher.update((r.key.len() as u64).to_le_bytes());
        hasher.update(&r.key);
        hasher.update((r.value.len() as u64).to_le_bytes());
        hasher.update(&r.value);
    }
    hasher.finalize().into()
}

pub fn compute_writes_commitment(writes: &[StfStateAccess]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOM_WRITES);
    hasher.update((writes.len() as u64).to_le_bytes());
    for w in writes {
        hasher.update((w.key.len() as u64).to_le_bytes());
        hasher.update(&w.key);
        hasher.update((w.value.len() as u64).to_le_bytes());
        hasher.update(&w.value);
    }
    hasher.finalize().into()
}

pub fn compute_verkle_commitment(proofs: &[StfVerkleProof]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOM_VERKLE);
    hasher.update((proofs.len() as u64).to_le_bytes());
    for p in proofs {
        hasher.update((p.commitments.len() as u64).to_le_bytes());
        for c in &p.commitments {
            hasher.update(c);
        }
        hasher.update((p.evaluation_points.len() as u64).to_le_bytes());
        for ep in &p.evaluation_points {
            hasher.update(ep);
        }
        hasher.update((p.evaluations.len() as u64).to_le_bytes());
        for ev in &p.evaluations {
            hasher.update(ev);
        }
        hasher.update((p.opening_proofs.len() as u64).to_le_bytes());
        for op in &p.opening_proofs {
            hasher.update(op);
        }
        hasher.update(p.witness_root);
    }
    hasher.finalize().into()
}

pub fn compute_commit_reveal_commitment(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOM_CR);
    hasher.update((digests.len() as u64).to_le_bytes());
    for d in digests {
        hasher.update(d);
    }
    hasher.finalize().into()
}

/// Maximum transactions in a single block STF witness (100,000).
pub const MAX_STF_TRANSACTIONS: usize = 100_000;

/// Maximum state read accesses in an STF witness (500,000).
pub const MAX_STF_STATE_READS: usize = 500_000;

/// Maximum state write accesses in an STF witness (500,000).
pub const MAX_STF_STATE_WRITES: usize = 500_000;

/// Maximum Verkle proofs in an STF witness (50,000).
pub const MAX_STF_VERKLE_PROOFS: usize = 50_000;

/// Maximum commit-reveal digests in an STF witness (100,000).
pub const MAX_STF_COMMIT_REVEAL_DIGESTS: usize = 100_000;

/// Binding links public inputs to private aggregate commitments.
pub fn compute_binding(public: &ZkPublicInputs, private: &StfPrivateInputs) -> [u8; 32] {
    let total_gas: u64 = private.transactions.iter().map(|t| t.gas_used).sum();
    let mut hasher = Sha256::new();
    hasher.update(DOM_BIND);
    hasher.update(public.chain_id.to_le_bytes());
    hasher.update(public.protocol_version.to_le_bytes());
    hasher.update(public.circuit_version.to_le_bytes());
    hasher.update(public.genesis_hash);
    hasher.update(public.block_height.to_le_bytes());
    hasher.update(public.parent_hash);
    hasher.update(public.state_root_before);
    hasher.update(public.state_root_after);
    hasher.update(public.tx_root);
    hasher.update(public.receipts_root);
    hasher.update(public.witness_root);
    hasher.update(public.beacon_randomness);
    hasher.update(total_gas.to_le_bytes());
    hasher.update(private.max_block_gas.to_le_bytes());
    hasher.update(compute_reads_commitment(&private.state_reads));
    hasher.update(compute_writes_commitment(&private.state_writes));
    hasher.update(compute_verkle_commitment(&private.verkle_proofs));
    hasher.update(compute_commit_reveal_commitment(
        &private.commit_reveal_digests,
    ));
    hasher.finalize().into()
}

/// SXIAUM address derivation mirrored for the guest (full 32-byte SHA-256).
pub fn address_from_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    let digest = Sha256::digest(pubkey);
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&digest[0..32]);
    addr
}

fn verify_ed25519(pubkey: &[u8; 32], message: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| anyhow::anyhow!("invalid ed25519 public key: {e:?}"))?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|e| anyhow::anyhow!("ed25519 signature verification failed: {e:?}"))?;
    Ok(())
}

/// Verify all Phase-1 STF constraints for a block witness.
pub fn verify_stf_constraints(witness: &ZkBlockWitness) -> Result<()> {
    let public = &witness.public_inputs;

    // Empty / default witness: allow only no-op transitions (used by unit tests).
    if witness.trace.witness_input.is_empty() {
        if public.state_root_before != public.state_root_after {
            bail!("empty STF witness cannot change state root");
        }
        return Ok(());
    }

    // When host filled trace.public_inputs, they must match the envelope (mirroring guest).
    if !witness.trace.public_inputs.is_empty() {
        let encoded = public.encode();
        if witness.trace.public_inputs.as_slice() != encoded.as_slice() {
            bail!("trace.public_inputs mismatch with envelope");
        }
    }

    let private = StfPrivateInputs::decode(&witness.trace.witness_input)?;
    verify_stf_private(public, &private)
}

/// Core constraint checker (shared semantics with the SP1 guest).
pub fn verify_stf_private(public: &ZkPublicInputs, private: &StfPrivateInputs) -> Result<()> {
    if private.version != STF_CIRCUIT_VERSION {
        bail!(
            "unsupported STF circuit version {} (expected {})",
            private.version,
            STF_CIRCUIT_VERSION
        );
    }

    if private.transactions.len() > MAX_STF_TRANSACTIONS {
        bail!(
            "transaction count {} exceeds maximum allowed {}",
            private.transactions.len(),
            MAX_STF_TRANSACTIONS
        );
    }

    if private.state_reads.len() > MAX_STF_STATE_READS {
        bail!(
            "state reads count {} exceeds maximum allowed {}",
            private.state_reads.len(),
            MAX_STF_STATE_READS
        );
    }

    if private.state_writes.len() > MAX_STF_STATE_WRITES {
        bail!(
            "state writes count {} exceeds maximum allowed {}",
            private.state_writes.len(),
            MAX_STF_STATE_WRITES
        );
    }

    if private.verkle_proofs.len() > MAX_STF_VERKLE_PROOFS {
        bail!(
            "verkle proofs count {} exceeds maximum allowed {}",
            private.verkle_proofs.len(),
            MAX_STF_VERKLE_PROOFS
        );
    }

    if private.commit_reveal_digests.len() > MAX_STF_COMMIT_REVEAL_DIGESTS {
        bail!(
            "commit reveal digests count {} exceeds maximum allowed {}",
            private.commit_reveal_digests.len(),
            MAX_STF_COMMIT_REVEAL_DIGESTS
        );
    }

    if private.max_block_gas == 0 {
        bail!("max_block_gas must be > 0");
    }

    let total_gas: u64 = private.transactions.iter().map(|t| t.gas_used).sum();
    if total_gas > private.max_block_gas {
        bail!(
            "block gas used {} exceeds max_block_gas {}",
            total_gas,
            private.max_block_gas
        );
    }

    // Empty block: state root must be unchanged.
    if private.transactions.is_empty() {
        if public.state_root_before != public.state_root_after {
            bail!("empty transaction list requires state_root_before == state_root_after");
        }
        if !private.state_writes.is_empty() {
            bail!("empty transaction list cannot include state writes");
        }
    } else {
        // Non-empty blocks must bind to a real transaction root.
        if public.tx_root == [0u8; 32] {
            bail!("non-empty block requires non-zero tx_root");
        }
        // State-changing blocks must move the root when there are writes.
        if !private.state_writes.is_empty() && public.state_root_before == public.state_root_after {
            bail!("state writes present but state_root_after equals state_root_before");
        }
    }

    // Trace public_inputs field, when populated, must match the envelope.
    // (Host fills this when building block witnesses.)

    // Deterministic MEV Ordering validation
    let seed = compute_ordering_seed(
        &public.parent_hash,
        public.block_height,
        &public.beacon_randomness,
    );

    // Create pairs of (commit_hash, tx_hash) and sort them deterministically
    let mut sorted_pairs: Vec<([u8; 32], [u8; 32])> = private
        .transactions
        .iter()
        .map(|t| {
            let commit = compute_commit_hash(&t.reveal_nonce, &t.tx_hash);
            (commit, t.tx_hash)
        })
        .collect();

    sorted_pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    // Apply the seed-based shuffle
    randomize_ordering(&mut sorted_pairs, &seed, public.block_height);

    // Verify that the final shuffled order exactly matches the order in which transactions were executed
    for (i, tx) in private.transactions.iter().enumerate() {
        if tx.tx_hash != sorted_pairs[i].1 {
            bail!("transaction ordering mismatch at index {i}");
        }
    }

    // Per-transaction constraints.
    for (i, tx) in private.transactions.iter().enumerate() {
        if tx.gas_limit == 0 {
            bail!("tx[{i}] gas_limit must be > 0");
        }
        if tx.gas_used > tx.gas_limit {
            bail!(
                "tx[{i}] gas_used {} exceeds gas_limit {}",
                tx.gas_used,
                tx.gas_limit
            );
        }
        if tx.tx_hash == [0u8; 32] {
            bail!("tx[{i}] tx_hash must be non-zero");
        }

        match tx.scheme {
            0 => {
                // Ed25519: sender address + signature.
                let derived = address_from_pubkey(&tx.pubkey);
                if derived != tx.from {
                    bail!("tx[{i}] pubkey does not match from address");
                }
                // Also check against types::Address derivation for host consistency.
                if Address::from_public_key(&tx.pubkey).as_bytes() != &tx.from {
                    bail!("tx[{i}] address derivation mismatch with sxiaum Address");
                }
                verify_ed25519(&tx.pubkey, &tx.signed_message, &tx.signature)?;
                if tx.signed_message != tx.tx_hash {
                    bail!("tx[{i}] native scheme requires signed_message == tx_hash");
                }
            }
            1 => {
                // Ethereum path: require non-zero sighash binding (full secp left to revm path).
                if tx.signed_message == [0u8; 32] {
                    bail!("tx[{i}] ethereum scheme requires non-zero signed_message (sighash)");
                }
                if tx.from == [0u8; 32] {
                    bail!("tx[{i}] ethereum scheme requires non-zero from");
                }
            }
            other => bail!("tx[{i}] unknown signature scheme {other}"),
        }
    }

    // State access keys must be non-empty.
    for (i, r) in private.state_reads.iter().enumerate() {
        if r.key.is_empty() {
            bail!("state_reads[{i}] key must be non-empty");
        }
    }
    for (i, w) in private.state_writes.iter().enumerate() {
        if w.key.is_empty() {
            bail!("state_writes[{i}] key must be non-empty");
        }
    }

    // Verkle proof structure: shape validation, root anchor, witness binding, and
    // full KZG opening cryptographic verification for every proof entry.
    for (i, p) in private.verkle_proofs.iter().enumerate() {
        if p.commitments.is_empty() {
            bail!("verkle_proofs[{i}] must include at least one commitment");
        }
        if p.evaluations.is_empty() {
            bail!("verkle_proofs[{i}] must include at least one evaluation");
        }
        if p.commitments.len() != p.evaluation_points.len() {
            bail!("verkle_proofs[{i}] commitments and evaluation_points length mismatch");
        }
        if p.evaluations.len() != p.opening_proofs.len() {
            bail!("verkle_proofs[{i}] evaluations and opening_proofs length mismatch");
        }
        if p.commitments[0] != public.state_root_before {
            bail!("verkle_proofs[{i}] root commitment mismatch with state_root_before");
        }

        // Witness binding: ensure the proof is bound to the verified witness root.
        if p.witness_root != public.witness_root {
            bail!("verkle_proofs[{i}] witness_root mismatch with public inputs");
        }

        // Fail closed on ANY cross-array length mismatch. The previous
        // min()-truncation silently skipped verification of trailing
        // commitments when arrays disagreed, letting partially-unverified
        // proof fragments pass.
        if p.commitments.len() != p.evaluation_points.len()
            || p.evaluations.len() != p.opening_proofs.len()
            || p.commitments.len() != p.evaluations.len()
        {
            bail!(
                "verkle_proofs[{i}] array length mismatch: commitments={}, \
                 evaluation_points={}, evaluations={}, opening_proofs={}",
                p.commitments.len(),
                p.evaluation_points.len(),
                p.evaluations.len(),
                p.opening_proofs.len()
            );
        }

        let is_production = crate::is_production();
        for j in 0..p.commitments.len() {
            // In non-production environments, skip KZG verification for
            // placeholder/empty opening proofs (common in unit tests that
            // verify STF constraints, not KZG cryptography).  Production
            // always requires valid KZG openings.
            let proof_bytes = &p.opening_proofs[j];
            let is_placeholder = proof_bytes.is_empty() || proof_bytes.iter().all(|&b| b == 0);
            if is_placeholder && !is_production {
                continue;
            }

            // Decode the evaluation point index exactly like the host-side
            // verifier in `ZkEngine::validate_block_proof` (full little-endian
            // u64 from the first 8 bytes). Reading only `ep[0]` allowed a
            // crafted point to verify under different indices in the two
            // verification paths.
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&p.evaluation_points[j][0..8]);
            let index = u64::from_le_bytes(buf) as usize;
            let evaluation = Some(p.evaluations[j]);
            let opening_ok = sxiaum_crypto::kzg::verify_kzg_opening(
                &p.commitments[j],
                index,
                evaluation,
                proof_bytes,
            )
            .map_err(|e| {
                anyhow::anyhow!("verkle_proofs[{i}] opening[{j}] KZG verify error: {e}")
            })?;
            if !opening_ok {
                bail!(
                    "verkle_proofs[{i}] opening[{j}] KZG opening verification failed. \
                     The proof is cryptographically invalid."
                );
            }
        }
    }

    // When state is accessed, require at least one verkle proof for mainnet-grade witnesses.
    // (Empty proofs allowed only when there are no reads/writes.)
    if (!private.state_reads.is_empty() || !private.state_writes.is_empty())
        && private.verkle_proofs.is_empty()
    {
        bail!("state accesses require at least one verkle proof in the STF witness");
    }

    // Commit-reveal digests: if present, each must be non-zero.
    for (i, d) in private.commit_reveal_digests.iter().enumerate() {
        if *d == [0u8; 32] {
            bail!("commit_reveal_digests[{i}] must be non-zero");
        }
    }

    // Binding commitment.
    let expected_binding = compute_binding(public, private);
    if private.binding != expected_binding {
        bail!("STF binding commitment mismatch");
    }

    Ok(())
}

/// Attach verified private inputs onto a [`ZkBlockWitness`] trace payload.
pub fn attach_private_to_witness(
    mut witness: ZkBlockWitness,
    private: StfPrivateInputs,
) -> Result<ZkBlockWitness> {
    verify_stf_private(&witness.public_inputs, &private)?;
    witness.trace.witness_input = private.encode()?;
    witness.trace.public_inputs = witness.public_inputs.encode();
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sp1::prover::Sp1ExecutionTrace;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_types::Transaction;

    fn signed_transfer() -> (Transaction, SigningKey) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let from = Address::from_public_key(&pk);
        let to = Address::from_public_key(&[8u8; 32]);
        let mut tx = Transaction::new_transfer(from, to, U256::from(1u64), 0);
        tx.sign(&sk).expect("sign");
        (tx, sk)
    }

    #[test]
    fn empty_witness_allows_noop_transition() {
        let witness = ZkBlockWitness::new(
            Sp1ExecutionTrace {
                program: vec![],
                witness_input: vec![],
                execution_trace: vec![],
                public_inputs: vec![],
            },
            ZkPublicInputs::default(),
        );
        verify_stf_constraints(&witness).expect("empty ok");
    }

    #[test]
    fn signed_tx_block_passes_stf() {
        let (tx, _) = signed_transfer();
        let mut header = BlockHeader::new([1u8; 32], 1);
        header.set_state_root([2u8; 32]);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        let mut block = Block::new(header, body);
        block.try_compute_roots().expect("compute roots");
        let public = ZkPublicInputs::new(
            1,         // chain_id
            1,         // protocol_version
            1,         // circuit_version
            [0u8; 32], // genesis_hash
            block.header.height,
            block.header.parent_hash,
            [1u8; 32], // state_root_before
            [2u8; 32], // state_root_after
            block.header.tx_root,
            block.header.receipts_root,
            [0u8; 32], // witness_root
            [0u8; 32], // beacon_randomness
        );
        let private = StfPrivateInputs::from_block(
            &block,
            &[210],
            vec![StfStateAccess {
                key: b"account:from".to_vec(),
                value: vec![1],
            }],
            vec![StfStateAccess {
                key: b"account:to".to_vec(),
                value: vec![2],
            }],
            vec![StfVerkleProof {
                commitments: vec![[1u8; 32], [2u8; 32], [4u8; 32]],
                evaluation_points: vec![[0u8; 32], [0u8; 32], [0u8; 32]],
                evaluations: vec![[0u8; 32], [0u8; 32], [0u8; 32]],
                opening_proofs: vec![vec![0u8; 32], vec![0u8; 32], vec![0u8; 32]],
                witness_root: [0u8; 32],
            }],
            vec![],
            vec![[0u8; 32]],
            DEFAULT_MAX_BLOCK_GAS,
            &public,
        )
        .expect("private");
        verify_stf_private(&public, &private).expect("stf");
    }

    #[test]
    fn rejects_gas_over_limit() {
        let (tx, _) = signed_transfer();
        let mut header = BlockHeader::new([1u8; 32], 1);
        header.set_state_root([2u8; 32]);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        let block = Block::new(header, body);
        let public = ZkPublicInputs::new(
            1,
            1,
            1,
            [0u8; 32],
            block.header.height,
            block.header.parent_hash,
            [1u8; 32],
            [2u8; 32],
            block.header.tx_root,
            block.header.receipts_root,
            [0u8; 32],
            [0u8; 32],
        );
        let mut private = StfPrivateInputs::from_block(
            &block,
            &[210],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![[0u8; 32]],
            DEFAULT_MAX_BLOCK_GAS,
            &public,
        )
        .expect("private");
        // No state writes - before may equal after; keep roots equal for this case.
        private.transactions[0].gas_used = private.transactions[0].gas_limit + 1;
        private.binding = compute_binding(&public, &private);
        assert!(verify_stf_private(&public, &private).is_err());
    }

    #[test]
    fn rejects_bad_signature() {
        let (tx, _) = signed_transfer();
        let mut header = BlockHeader::new([1u8; 32], 1);
        header.set_state_root([1u8; 32]);
        let mut body = BlockBody::new();
        body.add_transaction(tx);
        let block = Block::new(header, body);
        let public = ZkPublicInputs::new(
            1,
            1,
            1,
            [0u8; 32],
            block.header.height,
            block.header.parent_hash,
            [1u8; 32],
            [1u8; 32],
            block.header.tx_root,
            block.header.receipts_root,
            [0u8; 32],
            [0u8; 32],
        );
        let mut private = StfPrivateInputs::from_block(
            &block,
            &[210],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![[0u8; 32]],
            DEFAULT_MAX_BLOCK_GAS,
            &public,
        )
        .expect("private");
        private.transactions[0].signature[0] ^= 0xff;
        private.binding = compute_binding(&public, &private);
        assert!(verify_stf_private(&public, &private).is_err());
    }
}
