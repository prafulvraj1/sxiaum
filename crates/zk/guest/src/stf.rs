//! Guest-side STF constraints - keep in sync with `sxiaum_zk::sp1::stf`.
//!
//! This module is intentionally self-contained (no host crate deps) so it can
//! compile inside the SP1 RISC-V guest.

extern crate alloc;

use alloc::vec::Vec;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STF_CIRCUIT_VERSION: u32 = 1;

pub const MAX_STF_TRANSACTIONS: usize = 100_000;
pub const MAX_STF_STATE_READS: usize = 500_000;
pub const MAX_STF_STATE_WRITES: usize = 500_000;
pub const MAX_STF_VERKLE_PROOFS: usize = 50_000;
pub const MAX_STF_COMMIT_REVEAL_DIGESTS: usize = 100_000;

const DOM_READS: &[u8] = b"sxiaum:stf:reads:v1";
const DOM_WRITES: &[u8] = b"sxiaum:stf:writes:v1";
const DOM_VERKLE: &[u8] = b"sxiaum:stf:verkle:v1";
const DOM_CR: &[u8] = b"sxiaum:stf:commit_reveal:v1";
const DOM_BIND: &[u8] = b"sxiaum:stf:bind:v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkPublicInputs {
    pub chain_id: u64,
    pub protocol_version: u32,
    pub circuit_version: u32,
    pub genesis_hash: [u8; 32],
    pub block_height: u64,
    pub parent_hash: [u8; 32],
    pub state_root_before: [u8; 32],
    pub state_root_after: [u8; 32],
    pub tx_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub witness_root: [u8; 32],
    pub beacon_randomness: [u8; 32],
}

impl ZkPublicInputs {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(280);
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        bytes.extend_from_slice(&self.circuit_version.to_le_bytes());
        bytes.extend_from_slice(&self.genesis_hash);
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.state_root_before);
        bytes.extend_from_slice(&self.state_root_after);
        bytes.extend_from_slice(&self.tx_root);
        bytes.extend_from_slice(&self.receipts_root);
        bytes.extend_from_slice(&self.witness_root);
        bytes.extend_from_slice(&self.beacon_randomness);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StfError> {
        if bytes.len() != 280 {
            return Err("ZkPublicInputs decode: expected 280 bytes");
        }
        let chain_id = u64::from_le_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| "invalid chain_id slice")?,
        );
        let protocol_version = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| "invalid protocol_version slice")?,
        );
        let circuit_version = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| "invalid circuit_version slice")?,
        );
        let genesis_hash = bytes[16..48]
            .try_into()
            .map_err(|_| "invalid genesis_hash slice")?;
        let block_height = u64::from_le_bytes(
            bytes[48..56]
                .try_into()
                .map_err(|_| "invalid block_height slice")?,
        );
        let parent_hash = bytes[56..88]
            .try_into()
            .map_err(|_| "invalid parent_hash slice")?;
        let state_root_before = bytes[88..120]
            .try_into()
            .map_err(|_| "invalid state_root_before slice")?;
        let state_root_after = bytes[120..152]
            .try_into()
            .map_err(|_| "invalid state_root_after slice")?;
        let tx_root = bytes[152..184]
            .try_into()
            .map_err(|_| "invalid tx_root slice")?;
        let receipts_root = bytes[184..216]
            .try_into()
            .map_err(|_| "invalid receipts_root slice")?;
        let witness_root = bytes[216..248]
            .try_into()
            .map_err(|_| "invalid witness_root slice")?;
        let beacon_randomness = bytes[248..280]
            .try_into()
            .map_err(|_| "invalid beacon_randomness slice")?;
        Ok(Self {
            chain_id,
            protocol_version,
            circuit_version,
            genesis_hash,
            block_height,
            parent_hash,
            state_root_before,
            state_root_after,
            tx_root,
            receipts_root,
            witness_root,
            beacon_randomness,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1ExecutionTrace {
    pub program: Vec<u8>,
    pub witness_input: Vec<u8>,
    pub execution_trace: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkBlockWitness {
    pub trace: Sp1ExecutionTrace,
    pub public_inputs: ZkPublicInputs,
}

mod serde_sig64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Vec;

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfTxWitness {
    pub tx_hash: [u8; 32],
    pub from: [u8; 32],
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub pubkey: [u8; 32],
    #[serde(with = "serde_sig64")]
    pub signature: [u8; 64],
    pub signed_message: [u8; 32],
    pub scheme: u8,
    pub reveal_nonce: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfStateAccess {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfVerkleProof {
    pub commitments: Vec<[u8; 32]>,
    pub evaluation_points: Vec<[u8; 32]>,
    pub evaluations: Vec<[u8; 32]>,
    pub opening_proofs: Vec<Vec<u8>>,
    pub witness_root: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StfPrivateInputs {
    pub version: u32,
    pub max_block_gas: u64,
    pub transactions: Vec<StfTxWitness>,
    pub state_reads: Vec<StfStateAccess>,
    pub state_writes: Vec<StfStateAccess>,
    pub verkle_proofs: Vec<StfVerkleProof>,
    pub commit_reveal_digests: Vec<[u8; 32]>,
    pub binding: [u8; 32],
}

pub type StfError = &'static str;

fn compute_ordering_seed(
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

fn randomize_ordering<T>(
    items: &mut [T],
    seed: &[u8; 32],
    height: u64,
) {
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

fn compute_commit_hash(reveal_nonce: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(reveal_nonce);
    h.update(tx_hash);
    h.finalize().into()
}

fn compute_reads_commitment(reads: &[StfStateAccess]) -> [u8; 32] {
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

fn compute_writes_commitment(writes: &[StfStateAccess]) -> [u8; 32] {
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

fn compute_verkle_commitment(proofs: &[StfVerkleProof]) -> [u8; 32] {
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

fn compute_commit_reveal_commitment(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOM_CR);
    hasher.update((digests.len() as u64).to_le_bytes());
    for d in digests {
        hasher.update(d);
    }
    hasher.finalize().into()
}

fn compute_binding(public: &ZkPublicInputs, private: &StfPrivateInputs) -> [u8; 32] {
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
    hasher.update(compute_commit_reveal_commitment(&private.commit_reveal_digests));
    hasher.finalize().into()
}

fn address_from_pubkey(pubkey: &[u8; 32]) -> [u8; 32] {
    let digest = Sha256::digest(pubkey);
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&digest[0..32]);
    addr
}

fn verify_ed25519(
    pubkey: &[u8; 32],
    message: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), StfError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| "invalid ed25519 public key")?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|_| "ed25519 signature verification failed")?;
    Ok(())
}

/// Verify Phase-1 STF constraints. Returns `Err` static reason on failure.
pub fn verify_stf_private(
    public: &ZkPublicInputs,
    private: &StfPrivateInputs,
) -> Result<(), StfError> {
    if private.version != STF_CIRCUIT_VERSION {
        return Err("unsupported STF circuit version");
    }
    if private.transactions.len() > MAX_STF_TRANSACTIONS {
        return Err("transaction count exceeds maximum allowed");
    }
    if private.state_reads.len() > MAX_STF_STATE_READS {
        return Err("state reads count exceeds maximum allowed");
    }
    if private.state_writes.len() > MAX_STF_STATE_WRITES {
        return Err("state writes count exceeds maximum allowed");
    }
    if private.verkle_proofs.len() > MAX_STF_VERKLE_PROOFS {
        return Err("verkle proofs count exceeds maximum allowed");
    }
    if private.commit_reveal_digests.len() > MAX_STF_COMMIT_REVEAL_DIGESTS {
        return Err("commit reveal digests count exceeds maximum allowed");
    }
    if private.max_block_gas == 0 {
        return Err("max_block_gas must be > 0");
    }

    let total_gas: u64 = private.transactions.iter().map(|t| t.gas_used).sum();
    if total_gas > private.max_block_gas {
        return Err("block gas used exceeds max_block_gas");
    }

    if private.transactions.is_empty() {
        if public.state_root_before != public.state_root_after {
            return Err("empty transaction list requires unchanged state root");
        }
        if !private.state_writes.is_empty() {
            return Err("empty transaction list cannot include state writes");
        }
    } else {
        if public.tx_root == [0u8; 32] {
            return Err("non-empty block requires non-zero tx_root");
        }
        if !private.state_writes.is_empty() && public.state_root_before == public.state_root_after {
            return Err("state writes present but state root unchanged");
        }
    }

    let seed = compute_ordering_seed(
        &public.parent_hash,
        public.block_height,
        &public.beacon_randomness,
    );
    
    let mut sorted_pairs: Vec<([u8; 32], [u8; 32])> = private.transactions.iter().map(|t| {
        let commit = compute_commit_hash(&t.reveal_nonce, &t.tx_hash);
        (commit, t.tx_hash)
    }).collect();
    
    sorted_pairs.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    randomize_ordering(&mut sorted_pairs, &seed, public.block_height);
    
    for (i, tx) in private.transactions.iter().enumerate() {
        if tx.tx_hash != sorted_pairs[i].1 {
            return Err("transaction ordering mismatch at index");
        }
    }

    for tx in &private.transactions {
        if tx.gas_limit == 0 {
            return Err("tx gas_limit must be > 0");
        }
        if tx.gas_used > tx.gas_limit {
            return Err("tx gas_used exceeds gas_limit");
        }
        if tx.tx_hash == [0u8; 32] {
            return Err("tx_hash must be non-zero");
        }
        match tx.scheme {
            0 => {
                if address_from_pubkey(&tx.pubkey) != tx.from {
                    return Err("pubkey does not match from address");
                }
                verify_ed25519(&tx.pubkey, &tx.signed_message, &tx.signature)?;
                if tx.signed_message != tx.tx_hash {
                    return Err("native scheme requires signed_message == tx_hash");
                }
            }
            1 => {
                if tx.signed_message == [0u8; 32] {
                    return Err("ethereum scheme requires non-zero sighash");
                }
                if tx.from == [0u8; 32] {
                    return Err("ethereum scheme requires non-zero from");
                }
            }
            _ => return Err("unknown signature scheme"),
        }
    }

    for r in &private.state_reads {
        if r.key.is_empty() {
            return Err("state read key must be non-empty");
        }
    }
    for w in &private.state_writes {
        if w.key.is_empty() {
            return Err("state write key must be non-empty");
        }
    }

    for p in &private.verkle_proofs {
        if p.commitments.is_empty() {
            return Err("verkle proof missing commitments");
        }
        if p.evaluations.is_empty() {
            return Err("verkle proof missing evaluations");
        }
        if p.commitments.len() != p.evaluation_points.len() {
            return Err("verkle proof commitments and evaluation_points length mismatch");
        }
        if p.evaluations.len() != p.opening_proofs.len() {
            return Err("verkle proof evaluations and opening_proofs length mismatch");
        }
        if p.commitments[0] != public.state_root_before {
            return Err("verkle proof root commitment mismatch with state_root_before");
        }
        if p.witness_root != public.witness_root {
            return Err("verkle proof witness_root mismatch with public inputs");
        }
    }

    for d in &private.commit_reveal_digests {
        if *d == [0u8; 32] {
            return Err("commit-reveal digest must be non-zero");
        }
    }

    if private.binding != compute_binding(public, private) {
        return Err("STF binding commitment mismatch");
    }

    Ok(())
}

pub fn verify_block_witness(witness: &ZkBlockWitness) -> Result<(), StfError> {
    let public = &witness.public_inputs;

    if witness.trace.witness_input.is_empty() {
        if public.state_root_before != public.state_root_after {
            return Err("empty STF witness cannot change state root");
        }
        return Ok(());
    }

    let private: StfPrivateInputs = bincode::deserialize(&witness.trace.witness_input)
        .map_err(|_| "failed to decode StfPrivateInputs")?;

    // When host filled trace.public_inputs, they must match the envelope.
    if !witness.trace.public_inputs.is_empty() {
        let encoded = public.encode();
        if witness.trace.public_inputs.as_slice() != encoded.as_slice() {
            return Err("trace.public_inputs mismatch with envelope");
        }
    }

    verify_stf_private(public, &private)
}
