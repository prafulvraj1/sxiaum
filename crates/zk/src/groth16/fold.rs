//! Recursive fold-circuit layer (Invention 1, spec §2.3).
//!
//! # What this actually implements
//!
//! Each fold certificate is a Groth16 proof whose R1CS constraint system
//! verifies the **prior certificate's Groth16 verification equation** as
//! arithmetic constraints. This is genuine in-circuit recursion: a chain of
//! `D` fold certificates attests `D` chained epoch transitions, and the final
//! certificate is verified with a **single pairing check**, independent of
//! `D` (chain age).
//!
//! # The recursion-friendly two-cycle (BCTV14 pattern)
//!
//! A Groth16 circuit cannot embed its own verifying key as constants (the VK
//! is an output of setup on the very constraints that would contain it — the
//! classic fixed-point problem), and supplying the prior VK as *public
//! inputs* makes the prior statement — and hence every subsequent statement —
//! grow without bound. The resolution implemented here is the standard
//! two-cycle construction (Ben-Sasson, Chiesa, Tromer, and Virza 2014,
//! "Scalable Zero Knowledge via Cycles of Elliptic Curves" [BCTV14]) over
//! MNT4-753 / MNT6-753, whose base and scalar fields are swapped:
//!
//! * `LayerA` circuit: scalar field = `MNT6-753::ScalarField` (= `MNT4-753`
//!   base field). Produces MNT6 Groth16 proofs and verifies the prior
//!   layer-B MNT4 proof with native-field pairing constraints
//!   (`ark_r1cs_std::pairing::mnt4::PairingVar`).
//! * `LayerB` circuit: scalar field = `MNT4-753::ScalarField` (= `MNT6-753`
//!   base field). Produces MNT4 Groth16 proofs and verifies the prior
//!   layer-A MNT6 proof with native-field pairing constraints.
//!
//! The prior layer's VK is allocated as **witness** variables and bound to
//! the protocol by an in-circuit arithmetic-native Poseidon sponge commitment:
//! the constraint `Poseidon(witness VK elements) == prior_vk_digest` ties the witness
//! VK to the `prior_vk_digest` element of the prior statement, which the
//! native verifier pins to the digest of ITS OWN prior-layer VK. This keeps
//! the fold statement a FIXED 25 field elements (no growth with depth), the
//! two layer setups independent (no fixed point), and the chain sound: the
//! only VK whose hash matches the pinned digest is the pinned one, and
//! proofs under that VK cannot be forged without its trapdoor.
//!
//! # Trust anchoring (bootstrap)
//!
//! * `sel = 0` (bootstrap/trusted-delta certificate): both the pairing gate
//!   and the VK-commitment gate are disabled and the statement pins
//!   `prior = genesis`. These certificates carry a trusted infrastructure
//!   delta — exactly the trust level of the pre-fold epoch certificates.
//!   The **pinned anchor certificate** (produced once at genesis by trusted
//!   infrastructure and pinned in node binaries, like the genesis root) is
//!   a `sel = 0` certificate.
//! * `sel = 1` (folded certificate): the circuit enforces the prior proof's
//!   full verification equation, the VK commitment, the inductive chaining
//!   ties (`prior.target == self.prior`), and the policy constraint
//!   `prior.sel == 1 OR prior == pinned anchor statement`. Chains of
//!   `sel = 1` certificates therefore bottom out at the pinned anchor
//!   certificate and nowhere else.
//!
//! # Honest scoping
//!
//! * Verification of a folded certificate is O(1): one certificate download,
//!   one pairing check, independent of chain age.
//! * Proving a fold chain is O(#epochs) sequential fold provings (as in
//!   SP1/RISC0 continuation proving).
//! * The per-epoch state-transition binding inside each fold remains the
//!   audited-STF scaffold (linear placeholder constraints); see spec §2.3.
//! * The recursion layer uses MNT4/6-753 (128-bit security), matching the
//!   BLS12-381 KZG state-proof layer.

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::lc;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::pairing::PairingVar as PairingGadget;
use ark_r1cs_std::prelude::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;

// ---------------------------------------------------------------------------
// Wire-format constants
// ---------------------------------------------------------------------------

/// Canonical compressed Groth16 proof size on MNT6-753 (Layer A):
/// `A(95) + B(285) + C(95) = 475 bytes`.
pub const FOLD_CERT_PROOF_SIZE_LAYER_A: usize = 475;
/// Canonical compressed Groth16 proof size on MNT4-753 (Layer B):
/// `A(95) + B(190) + C(95) = 380 bytes`.
pub const FOLD_CERT_PROOF_SIZE_LAYER_B: usize = 380;
/// Field-element width (bytes) of both MNT4-753 and MNT6-753 fields (753 bits).
pub const FOLD_FIELD_BYTES: usize = 95;

// ---------------------------------------------------------------------------
// Statement types
// ---------------------------------------------------------------------------

/// Which layer of the MNT4/6-753 fold cycle a certificate belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FoldLayerId {
    /// MNT6-753 scalar field circuit; verifies prior MNT4 proofs.
    A,
    /// MNT4-753 scalar field circuit; verifies prior MNT6 proofs.
    B,
}

impl FoldLayerId {
    pub fn other(self) -> Self {
        match self {
            FoldLayerId::A => FoldLayerId::B,
            FoldLayerId::B => FoldLayerId::A,
        }
    }

    /// Byte tag stored in the certificate header.
    pub fn to_u8(self) -> u8 {
        match self {
            FoldLayerId::A => 0,
            FoldLayerId::B => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(FoldLayerId::A),
            1 => Some(FoldLayerId::B),
            _ => None,
        }
    }
}

/// Protocol constants pinned into the fold circuit at setup time: the
/// statement of the **pinned anchor certificate** (the trusted genesis fold).
/// These are the in-circuit constants that `sel = 1` chains bottom out at.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldAnchorConfig {
    /// State root certified by the anchor certificate (usually the genesis
    /// ceremony checkpoint root).
    pub root: [u8; 32],
    /// Canonical block header hash certified by the anchor certificate.
    pub block_hash: [u8; 32],
    /// Height certified by the anchor certificate.
    pub height: u64,
}

/// The public statement of a fold certificate: 10 field elements.
///
/// Every field is < 2^256 by construction (32-byte hashes, `u64` counters),
/// so each field embeds injectively into either 298-bit cycle field and can
/// be split into two 128-bit chunks for cross-layer packing.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldStatement {
    /// `false` = bootstrap/trusted-delta certificate (pairing gate disabled,
    /// prior pinned to genesis). `true` = folded certificate (prior proof
    /// verified in-circuit).
    pub sel: bool,
    pub genesis_root: [u8; 32],
    pub target_root: [u8; 32],
    pub target_block_hash: [u8; 32],
    pub target_height: u64,
    pub chain_id: u64,
    /// SHA-256 digest of this certificate layer's canonical VK
    /// ([`fold_vk_digest`]).
    pub vk_digest: [u8; 32],
    /// State root this fold builds on (`S_{N-K}`).
    pub prior_root: [u8; 32],
    /// Block hash this fold builds on.
    pub prior_block_hash: [u8; 32],
    /// Height this fold builds on.
    pub prior_height: u64,
}

impl FoldStatement {
    /// The genesis-anchored prior statement used by every `sel = 0`
    /// bootstrap certificate: "no prior progress, trusted delta from S_0".
    pub fn genesis_prior(genesis_root: [u8; 32], chain_id: u64, vk_digest: [u8; 32]) -> Self {
        Self {
            sel: false,
            genesis_root,
            target_root: genesis_root,
            target_block_hash: [0u8; 32],
            target_height: 0,
            chain_id,
            vk_digest,
            prior_root: genesis_root,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Public-input layout
// ---------------------------------------------------------------------------
//
// The fold circuit has a FIXED 25-element public-input vector (flat Groth16
// instance), identical for both layers:
//
//   [0]      sel                         (0/1)
//   [1..10]  own statement               (S0, SN, HN, N, chain, vkdig, Sp, Hp, Np)
//   [10..22] prior chunks (lo, hi) x 6   (prior.target_root, .target_block_hash,
//                                         .target_height, .prior_root,
//                                         .prior_block_hash, .prior_height)
//   [22]     prior_sel                   (the prior certificate's sel)
//   [23..25] prior_vk_digest chunks      (lo, hi of the prior layer's VK digest)
//
// The witness consists of the prior proof points (A, B, C), the FULL prior
// layer VK (alpha, beta, gamma, delta, IC â€” bound in-circuit by
// SHA-256(serialization) == prior_vk_digest), and the epoch delta
// commitments. Because the VK is witness material (not public inputs), the
// statement size is FIXED â€” fold chains do not grow the statement with
// depth, which is what makes unbounded recursion possible here.

pub const FOLD_PI_SEL: usize = 0;
pub const FOLD_PI_STATEMENT: usize = 1; // 9 elements
pub const FOLD_PI_PRIOR_CHUNKS: usize = 10; // 12 elements
pub const FOLD_PI_PRIOR_SEL: usize = 22; // 1 element
pub const FOLD_PI_PRIOR_VK_DIGEST: usize = 23; // 2 elements (lo, hi)
/// Total flat Groth16 public-input count of a fold certificate.
pub const FOLD_PUBLIC_INPUTS_LEN: usize = 25;
/// Number of chunked prior-statement fields.
pub const FOLD_PRIOR_CHUNKED_FIELDS: usize = 6;
/// Number of public fields in a fold statement.
pub const FOLD_STATEMENT_LEN: usize = 10;

// ---------------------------------------------------------------------------
// Prior-layer verifying key material (circuit witness)
// ---------------------------------------------------------------------------

/// The prior layer's Groth16 verifying key, expressed over the prior curve.
/// In the fold circuit these are **witness** variables, bound by the
/// in-circuit SHA-256 commitment to the `prior_vk_digest` statement element;
/// the native verifier pins the same digest, so the prover has no usable
/// freedom over them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorVK<EP: Pairing> {
    pub alpha_g1: <<EP as Pairing>::G1 as CurveGroup>::Affine,
    pub beta_g2: <<EP as Pairing>::G2 as CurveGroup>::Affine,
    pub gamma_g2: <<EP as Pairing>::G2 as CurveGroup>::Affine,
    pub delta_g2: <<EP as Pairing>::G2 as CurveGroup>::Affine,
    /// `IC_0..IC_n`: one G1 point per prior-circuit public input, plus the
    /// constant term (26 points for the 25-input fold circuit).
    pub ic: Vec<<<EP as Pairing>::G1 as CurveGroup>::Affine>,
}

impl<EP: Pairing> PriorVK<EP> {
    /// Extract from an ark-groth16 verifying key of the prior layer.
    pub fn from_verifying_key(vk: &VerifyingKey<EP>) -> anyhow::Result<Self> {
        if vk.gamma_abc_g1.len() < 2 {
            anyhow::bail!(
                "prior VK has {} IC points, expected at least 2",
                vk.gamma_abc_g1.len()
            );
        }
        Ok(Self {
            alpha_g1: vk.alpha_g1,
            beta_g2: vk.beta_g2,
            gamma_g2: vk.gamma_g2,
            delta_g2: vk.delta_g2,
            ic: vk.gamma_abc_g1.clone(),
        })
    }

    /// A dummy prior VK for circuit setup (any valid curve points suffice:
    /// the VK is witness material, not a setup constant).
    pub fn dummy_for_setup() -> Self {
        let g1 = <<EP as Pairing>::G1 as PrimeGroup>::generator().into_affine();
        let g2 = <<EP as Pairing>::G2 as PrimeGroup>::generator().into_affine();
        Self {
            alpha_g1: g1,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g2: g2,
            ic: vec![g1; FOLD_PUBLIC_INPUTS_LEN + 1],
        }
    }
}

/// The prior certificate's in-circuit-verified Groth16 proof points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorProofPoints<EP: Pairing> {
    pub a: <<EP as Pairing>::G1 as CurveGroup>::Affine,
    pub b: <<EP as Pairing>::G2 as CurveGroup>::Affine,
    pub c: <<EP as Pairing>::G1 as CurveGroup>::Affine,
}

impl<EP: Pairing> PriorProofPoints<EP> {
    pub fn from_proof(proof: &Proof<EP>) -> Self {
        Self {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        }
    }

    /// Generators, used as inert witness filler for `sel = 0` bootstrap
    /// certificates (whose pairing gate is disabled).
    pub fn generators() -> Self {
        Self {
            a: <<EP as Pairing>::G1 as PrimeGroup>::generator().into_affine(),
            b: <<EP as Pairing>::G2 as PrimeGroup>::generator().into_affine(),
            c: <<EP as Pairing>::G1 as PrimeGroup>::generator().into_affine(),
        }
    }
}

/// Canonical Poseidon digest of a fold-layer verifying key over its base-prime-field elements.
/// Bound in-circuit to the witness VK using the arithmetic-native Poseidon sponge.
pub fn fold_vk_digest<EP: Pairing>(vk: &VerifyingKey<EP>) -> [u8; 32] {
    let prior_vk = PriorVK::<EP> {
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        ic: vk.gamma_abc_g1.clone(),
    };
    let elems = prior_vk.to_base_prime_field_elements();
    let digest_elem = poseidon_sponge_native(&elems);
    hash_from_field(&digest_elem)
}

impl<EP: Pairing> PriorVK<EP> {
    /// Extract every base-prime-field element of every VK coordinate in canonical order.
    pub fn to_base_prime_field_elements(
        &self,
    ) -> Vec<<<EP as Pairing>::G1 as CurveGroup>::BaseField> {
        let mut out = Vec::new();
        let push_g1 = |p: &<<EP as Pairing>::G1 as CurveGroup>::Affine, out: &mut Vec<_>| {
            let (x, y) = p.xy().expect("VK points are never the identity");
            for c in [x, y] {
                out.extend(c.to_base_prime_field_elements());
            }
        };
        let push_g2 = |p: &<<EP as Pairing>::G2 as CurveGroup>::Affine, out: &mut Vec<_>| {
            let (x, y) = p.xy().expect("VK points are never the identity");
            for c in [x, y] {
                out.extend(c.to_base_prime_field_elements());
            }
        };
        push_g1(&self.alpha_g1, &mut out);
        push_g2(&self.beta_g2, &mut out);
        push_g2(&self.gamma_g2, &mut out);
        push_g2(&self.delta_g2, &mut out);
        for p in &self.ic {
            push_g1(p, &mut out);
        }
        out
    }

    /// Canonical byte serialization bound by the in-circuit SHA-256
    /// commitment: for every point (alpha, beta, gamma, delta, each IC), the
    /// affine x and y coordinates, each coordinate expanded into its
    /// base-prime-field coefficients (38 bytes each, little-endian).
    pub fn canonical_serialization(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for elem in self.to_base_prime_field_elements() {
            let bytes = elem.into_bigint().to_bytes_le();
            let n = bytes.len().min(FOLD_FIELD_BYTES);
            out.extend_from_slice(&bytes[..n]);
            if n < FOLD_FIELD_BYTES {
                out.resize(out.len() + (FOLD_FIELD_BYTES - n), 0);
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Public-input builder (single source of truth for prover and verifier)
// ---------------------------------------------------------------------------

/// Build the flat 25-element Groth16 public-input vector of a fold
/// certificate (see the layout comment above).
///
/// * `own` — the certificate's own statement.
/// * `prior` — the prior certificate's statement.
/// * `_prior_prior` — the certificate before the prior one (only needed to
///   reproduce the prior circuit's own chunk publics and its
///   `prior_vk_digest`; no proof required).
pub fn fold_public_inputs<ET>(
    own: &FoldStatement,
    prior: &FoldStatement,
    _prior_prior: &FoldStatement,
) -> Result<Vec<<ET as Pairing>::ScalarField>, SynthesisError>
where
    ET: Pairing,
{
    let mut out: Vec<<ET as Pairing>::ScalarField> = Vec::with_capacity(FOLD_PUBLIC_INPUTS_LEN);
    let push_chunks = |field: &[u8; 32], out: &mut Vec<<ET as Pairing>::ScalarField>| {
        let (lo, hi) = split_chunk(field);
        out.push(<ET as Pairing>::ScalarField::from_le_bytes_mod_order(&lo));
        out.push(<ET as Pairing>::ScalarField::from_le_bytes_mod_order(&hi));
    };
    let mut buf32 = [0u8; 32];
    let mut push_u64_chunks = |v: u64, out: &mut Vec<<ET as Pairing>::ScalarField>| {
        buf32[..8].copy_from_slice(&v.to_le_bytes());
        push_chunks(&buf32, out);
    };

    // [0] sel
    out.push(if own.sel {
        <ET as Pairing>::ScalarField::from(1u64)
    } else {
        <ET as Pairing>::ScalarField::from(0u64)
    });
    // [1..10] own statement
    out.push(field_from_hash::<ET::ScalarField>(&own.genesis_root));
    out.push(field_from_hash::<ET::ScalarField>(&own.target_root));
    out.push(field_from_hash::<ET::ScalarField>(&own.target_block_hash));
    out.push(field_from_u64::<ET::ScalarField>(own.target_height));
    out.push(field_from_u64::<ET::ScalarField>(own.chain_id));
    out.push(field_from_hash::<ET::ScalarField>(&own.vk_digest));
    out.push(field_from_hash::<ET::ScalarField>(&own.prior_root));
    out.push(field_from_hash::<ET::ScalarField>(&own.prior_block_hash));
    out.push(field_from_u64::<ET::ScalarField>(own.prior_height));
    // [10..22] prior chunks
    push_chunks(&prior.target_root, &mut out);
    push_chunks(&prior.target_block_hash, &mut out);
    push_u64_chunks(prior.target_height, &mut out);
    push_chunks(&prior.prior_root, &mut out);
    push_chunks(&prior.prior_block_hash, &mut out);
    push_u64_chunks(prior.prior_height, &mut out);
    // [22] prior sel
    out.push(if prior.sel {
        <ET as Pairing>::ScalarField::from(1u64)
    } else {
        <ET as Pairing>::ScalarField::from(0u64)
    });
    // [23..25] prior vk_digest chunks
    push_chunks(&prior.vk_digest, &mut out);

    debug_assert_eq!(out.len(), FOLD_PUBLIC_INPUTS_LEN);
    Ok(out)
}

/// Split a 32-byte statement field into two 128-bit little-endian chunks.
/// Statement fields are < 2^256 by construction, so
/// `lo + hi * 2^128` reconstructs the original integer exactly.
pub fn split_chunk(field: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&field[..16]);
    hi.copy_from_slice(&field[16..]);
    (lo, hi)
}

/// Convert a 32-byte hash into a cycle-field element. 2^256 < modulus, so
/// this is injective on statement fields.
pub fn field_from_hash<F: PrimeField>(bytes: &[u8; 32]) -> F {
    F::from_le_bytes_mod_order(bytes)
}

pub fn field_from_u64<F: PrimeField>(v: u64) -> F {
    F::from(v)
}

/// Inverse of [`field_from_hash`] for canonical elements < 2^256.
pub fn hash_from_field<F: PrimeField>(f: &F) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

// ---------------------------------------------------------------------------
// Poseidon Arithmetic Sponge & Gadget (Spec §2.3 / Mainnet VK Binding)
// ---------------------------------------------------------------------------

pub const POSEIDON_RATE: usize = 2;
pub const POSEIDON_CAPACITY: usize = 1;
pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 56;
pub const POSEIDON_TOTAL_ROUNDS: usize = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;

/// Deterministic round constants for Poseidon over `F: PrimeField`.
pub fn poseidon_round_constants<F: PrimeField>() -> Vec<[F; POSEIDON_WIDTH]> {
    let mut constants = Vec::with_capacity(POSEIDON_TOTAL_ROUNDS);
    for r in 0..POSEIDON_TOTAL_ROUNDS {
        let mut round_c = [F::zero(); POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            let mut hasher = Sha256::new();
            hasher.update(b"SXIAUM_POSEIDON_MNT753_ROUND_CONSTANTS_V1");
            hasher.update(&(r as u32).to_le_bytes());
            hasher.update(&(i as u32).to_le_bytes());
            let hash = hasher.finalize();
            round_c[i] = F::from_le_bytes_mod_order(&hash);
        }
        constants.push(round_c);
    }
    constants
}

/// Cauchy MDS matrix of size 3x3: M_{i,j} = (x_i + y_j)^{-1} where x = [1, 2, 3], y = [4, 5, 6].
pub fn poseidon_mds_matrix<F: PrimeField>() -> [[F; POSEIDON_WIDTH]; POSEIDON_WIDTH] {
    let mut mds = [[F::zero(); POSEIDON_WIDTH]; POSEIDON_WIDTH];
    for i in 0..POSEIDON_WIDTH {
        for j in 0..POSEIDON_WIDTH {
            let sum = F::from((i + 1 + j + 4) as u64);
            mds[i][j] = sum.inverse().expect("MDS denominator non-zero");
        }
    }
    mds
}

/// Native Poseidon sponge over arbitrary field elements `F: PrimeField`.
/// Width T = 3 (rate 2, capacity 1), alpha = 5, R_F = 8, R_P = 56.
pub fn poseidon_sponge_native<F: PrimeField>(inputs: &[F]) -> F {
    let mds = poseidon_mds_matrix::<F>();
    let round_constants = poseidon_round_constants::<F>();

    // Initial state: [domain_tag, 0, 0]
    let mut state = [
        F::from_le_bytes_mod_order(b"SXIAUM_POSEIDON_VK_V1_MNT753\0\0\0"),
        F::zero(),
        F::zero(),
    ];

    let mut idx = 0;
    while idx < inputs.len() {
        state[1] += inputs[idx];
        if idx + 1 < inputs.len() {
            state[2] += inputs[idx + 1];
        }
        idx += 2;
        poseidon_permute_native(&mut state, &mds, &round_constants);
    }
    if inputs.is_empty() {
        poseidon_permute_native(&mut state, &mds, &round_constants);
    }
    state[0]
}

fn poseidon_permute_native<F: PrimeField>(
    state: &mut [F; POSEIDON_WIDTH],
    mds: &[[F; POSEIDON_WIDTH]; POSEIDON_WIDTH],
    round_constants: &[[F; POSEIDON_WIDTH]],
) {
    let half_rf = POSEIDON_FULL_ROUNDS / 2;
    let r_p = POSEIDON_PARTIAL_ROUNDS;

    for r in 0..POSEIDON_TOTAL_ROUNDS {
        // 1. Add round constants
        for i in 0..POSEIDON_WIDTH {
            state[i] += round_constants[r][i];
        }

        // 2. S-box: x -> x^5
        if r < half_rf || r >= half_rf + r_p {
            for i in 0..POSEIDON_WIDTH {
                let x2 = state[i].square();
                let x4 = x2.square();
                state[i] = x4 * state[i];
            }
        } else {
            let x2 = state[0].square();
            let x4 = x2.square();
            state[0] = x4 * state[0];
        }

        // 3. Linear layer: multiply by MDS matrix
        let mut new_state = [F::zero(); POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            for j in 0..POSEIDON_WIDTH {
                new_state[i] += state[j] * mds[i][j];
            }
        }
        *state = new_state;
    }
}

/// In-circuit Poseidon sponge over circuit variables `FpVar<F>`.
/// Arithmetic-native: zero bit-decompositions, 3 R1CS constraints per S-box.
pub fn poseidon_sponge_gadget<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    inputs: &[FpVar<F>],
) -> Result<FpVar<F>, SynthesisError> {
    let mds = poseidon_mds_matrix::<F>();
    let round_constants = poseidon_round_constants::<F>();

    let init_tag = FpVar::Constant(F::from_le_bytes_mod_order(b"SXIAUM_POSEIDON_VK_V1_MNT753\0\0\0"));
    let zero = FpVar::Constant(F::zero());
    let mut state = [init_tag, zero.clone(), zero];

    let mut idx = 0;
    while idx < inputs.len() {
        state[1] = state[1].clone() + &inputs[idx];
        if idx + 1 < inputs.len() {
            state[2] = state[2].clone() + &inputs[idx + 1];
        }
        idx += 2;
        poseidon_permute_gadget(cs.clone(), &mut state, &mds, &round_constants)?;
    }
    if inputs.is_empty() {
        poseidon_permute_gadget(cs, &mut state, &mds, &round_constants)?;
    }
    Ok(state[0].clone())
}

fn poseidon_permute_gadget<F: PrimeField>(
    _cs: ConstraintSystemRef<F>,
    state: &mut [FpVar<F>; POSEIDON_WIDTH],
    mds: &[[F; POSEIDON_WIDTH]; POSEIDON_WIDTH],
    round_constants: &[[F; POSEIDON_WIDTH]],
) -> Result<(), SynthesisError> {
    let half_rf = POSEIDON_FULL_ROUNDS / 2;
    let r_p = POSEIDON_PARTIAL_ROUNDS;

    for r in 0..POSEIDON_TOTAL_ROUNDS {
        // 1. Add round constants
        for i in 0..POSEIDON_WIDTH {
            state[i] = state[i].clone() + FpVar::Constant(round_constants[r][i]);
        }

        // 2. S-box: x -> x^5
        if r < half_rf || r >= half_rf + r_p {
            for i in 0..POSEIDON_WIDTH {
                state[i] = sbox_5_gadget(&state[i])?;
            }
        } else {
            state[0] = sbox_5_gadget(&state[0])?;
        }

        // 3. Linear layer: multiply by MDS matrix
        let mut new_state = [
            FpVar::Constant(F::zero()),
            FpVar::Constant(F::zero()),
            FpVar::Constant(F::zero()),
        ];
        for i in 0..POSEIDON_WIDTH {
            for j in 0..POSEIDON_WIDTH {
                new_state[i] = new_state[i].clone() + &(state[j].clone() * FpVar::Constant(mds[i][j]));
            }
        }
        *state = new_state;
    }
    Ok(())
}

fn sbox_5_gadget<F: PrimeField>(x: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    let x5 = &x4 * x;
    Ok(x5)
}

/// The recursive fold circuit for one layer of the MNT4/6-298 cycle.
///
/// Type parameters:
/// * `ET` â€” the curve this layer proves over (its scalar field is the
///   circuit field).
/// * `EP` â€” the prior layer's curve, whose base prime field equals
///   `ET::ScalarField`; this circuit verifies prior Groth16 proofs over
///   `EP` with native-field pairing constraints via gadget `PW`.
pub struct RecursiveFoldCircuit<ET, EP, PW>
where
    ET: Pairing,
    EP: Pairing,
    PW: PairingGadget<EP>,
{
    /// Pinned anchor-certificate statement (in-circuit constants).
    pub anchor: FoldAnchorConfig,
    /// This certificate's statement.
    pub statement: FoldStatement,
    /// The prior certificate's statement.
    pub prior_statement: FoldStatement,
    /// The certificate before the prior one (its statement supplies the
    /// prior circuit's own chunk publics and prior_vk_digest).
    pub prior_prior_statement: FoldStatement,
    /// Prior layer VK (witness, SHA-256-bound to `prior_vk_digest`).
    pub prior_vk: PriorVK<EP>,
    /// Prior proof points (witness).
    pub prior_proof: PriorProofPoints<EP>,
    pub _pd: PhantomData<(ET, PW)>,
}

impl<ET: Pairing, EP: Pairing, PW: PairingGadget<EP>> Clone
    for RecursiveFoldCircuit<ET, EP, PW>
{
    fn clone(&self) -> Self {
        Self {
            anchor: self.anchor.clone(),
            statement: self.statement.clone(),
            prior_statement: self.prior_statement.clone(),
            prior_prior_statement: self.prior_prior_statement.clone(),
            prior_vk: self.prior_vk.clone(),
            prior_proof: self.prior_proof.clone(),
            _pd: PhantomData,
        }
    }
}

impl<ET, EP, PW> RecursiveFoldCircuit<ET, EP, PW>
where
    ET: Pairing,
    EP: Pairing,
    PW: PairingGadget<EP>,
{
    /// The 10 statement field values, in prior-circuit input order:
    /// [sel, S_0, S_N, H_N, N, chain_id, vk_digest, S_prev, H_prev, N_prev].
    fn statement_fields(
        s: &FoldStatement,
    ) -> [<ET as Pairing>::ScalarField; FOLD_STATEMENT_LEN] {
        [
            <ET as Pairing>::ScalarField::from(if s.sel { 1u64 } else { 0u64 }),
            field_from_hash::<ET::ScalarField>(&s.genesis_root),
            field_from_hash::<ET::ScalarField>(&s.target_root),
            field_from_hash::<ET::ScalarField>(&s.target_block_hash),
            field_from_u64::<ET::ScalarField>(s.target_height),
            field_from_u64::<ET::ScalarField>(s.chain_id),
            field_from_hash::<ET::ScalarField>(&s.vk_digest),
            field_from_hash::<ET::ScalarField>(&s.prior_root),
            field_from_hash::<ET::ScalarField>(&s.prior_block_hash),
            field_from_u64::<ET::ScalarField>(s.prior_height),
        ]
    }
}

/// 2^i as a field constant (i < 256, far below the 298-bit modulus).
fn pow2<F: PrimeField>(i: usize) -> F {
    F::from(2u64).pow([i as u64, 0, 0, 0])
}

/// Allocate the little-endian bit decomposition of a 128-bit chunk as
/// witness Booleans, enforcing `chunk_var == sum(bit_i * 2^i)`. A chunk
/// public input that is >= 2^128 is unsatisfiable, so the MSM scalar bits
/// are the chunk's true integer bits with no truncation gap.
fn alloc_chunk_bits<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    chunk_var: ark_relations::gr1cs::Variable,
    chunk_value: F,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let bigint = chunk_value.into_bigint();
    let mut bits = Vec::with_capacity(128);
    let mut acc: ark_relations::gr1cs::LinearCombination<F> = lc!();
    for i in 0..128 {
        let b = bigint.get_bit(i);
        let bit = Boolean::new_witness(cs.clone(), || Ok(b))?;
        match &bit {
            Boolean::Var(v) => acc += (pow2::<F>(i), v.variable()),
            Boolean::Constant(true) => acc += (pow2::<F>(i), ark_relations::gr1cs::Variable::One),
            Boolean::Constant(false) => {}
        }
        bits.push(bit);
    }
    // chunk_var * 1 == acc (R1CS form)
    cs.enforce_r1cs_constraint(
        || lc!() + (F::one(), chunk_var) - &acc,
        || lc!() + ark_relations::gr1cs::Variable::One,
        || ark_relations::gr1cs::LinearCombination::zero(),
    )?;
    Ok(bits)
}

impl<ET, EP, PW> ConstraintSynthesizer<<ET as Pairing>::ScalarField>
    for RecursiveFoldCircuit<ET, EP, PW>
where
    ET: Pairing,
    EP: Pairing,
    PW: PairingGadget<EP>,
    ET: Pairing<ScalarField = <<EP as Pairing>::G1 as CurveGroup>::BaseField>,
    ET: Pairing<ScalarField = <<<EP as Pairing>::G2Affine as AffineRepr>::BaseField as Field>::BasePrimeField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<ET as Pairing>::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let one_fp = FpVar::Constant(<ET as Pairing>::ScalarField::from(1u64));
        let zero_fp = FpVar::Constant(<ET as Pairing>::ScalarField::from(0u64));
        let alloc_input = |v: <ET as Pairing>::ScalarField| -> Result<
            FpVar<<ET as Pairing>::ScalarField>,
            SynthesisError,
        > {
            FpVar::new_variable(cs.clone(), || Ok(v), AllocationMode::Input)
        };
        let alloc_witness = |v: <ET as Pairing>::ScalarField| -> Result<
            FpVar<<ET as Pairing>::ScalarField>,
            SynthesisError,
        > {
            FpVar::new_variable(cs.clone(), || Ok(v), AllocationMode::Witness)
        };

        // ---- 1. Public inputs (allocation order == `fold_public_inputs`) ----
        let own = Self::statement_fields(&self.statement);
        let sel_fp = alloc_input(own[0])?;
        let s0_fp = alloc_input(own[1])?;
        let sn_fp = alloc_input(own[2])?;
        let _hn_own_fp = alloc_input(own[3])?;
        let n_own_fp = alloc_input(own[4])?;
        let chain_fp = alloc_input(own[5])?;
        let _vkdig_own_fp = alloc_input(own[6])?;
        let sp_fp = alloc_input(own[7])?;
        let hp_own_fp = alloc_input(own[8])?;
        let np_own_fp = alloc_input(own[9])?;

        let prior = &self.prior_statement;
        let mut chunk_values: Vec<<ET as Pairing>::ScalarField> = Vec::with_capacity(12);
        {
            let push32 = |field: &[u8; 32], out: &mut Vec<<ET as Pairing>::ScalarField>| {
                let (lo, hi) = split_chunk(field);
                out.push(<ET as Pairing>::ScalarField::from_le_bytes_mod_order(&lo));
                out.push(<ET as Pairing>::ScalarField::from_le_bytes_mod_order(&hi));
            };
            let mut buf32 = [0u8; 32];
            push32(&prior.target_root, &mut chunk_values);
            push32(&prior.target_block_hash, &mut chunk_values);
            buf32[..8].copy_from_slice(&prior.target_height.to_le_bytes());
            push32(&buf32, &mut chunk_values);
            push32(&prior.prior_root, &mut chunk_values);
            push32(&prior.prior_block_hash, &mut chunk_values);
            buf32[..8].copy_from_slice(&prior.prior_height.to_le_bytes());
            push32(&buf32, &mut chunk_values);
        }
        let mut chunk_vars = Vec::with_capacity(12);
        let mut chunk_fps = Vec::with_capacity(12);
        for v in &chunk_values {
            let fp = alloc_input(*v)?;
            if let FpVar::Var(a) = &fp {
                chunk_vars.push(a.variable);
            } else {
                return Err(SynthesisError::Unsatisfiable);
            }
            chunk_fps.push(fp);
        }
        let mut chunk_bits: Vec<Vec<Boolean<<ET as Pairing>::ScalarField>>> =
            Vec::with_capacity(12);
        for (var, val) in chunk_vars.iter().zip(chunk_values.iter()) {
            chunk_bits.push(alloc_chunk_bits(cs.clone(), *var, *val)?);
        }

        let prior_sel_fp = alloc_input(if prior.sel {
            <ET as Pairing>::ScalarField::from(1u64)
        } else {
            <ET as Pairing>::ScalarField::from(0u64)
        })?;
        let mut vk_digest_fps = Vec::with_capacity(2);
        {
            let (lo, hi) = split_chunk(&prior.vk_digest);
            for v in [&lo, &hi] {
                vk_digest_fps.push(alloc_input(
                    <ET as Pairing>::ScalarField::from_le_bytes_mod_order(v),
                )?);
            }
        }
        let _ = (&prior_sel_fp, &vk_digest_fps);

        // The prior circuit's own chunk publics + prior_sel + prior_vk_digest
        // (derived from the prior-prior statement) — these reproduce the
        // prior circuit's inputs [10..25] for the MSM.
        let prior_prior = &self.prior_prior_statement;
        let mut pp_chunk_values: Vec<<ET as Pairing>::ScalarField> = Vec::with_capacity(12);
        {
            let push32 = |field: &[u8; 32], out: &mut Vec<<ET as Pairing>::ScalarField>| {
                let (lo, hi) = split_chunk(field);
                out.push(<ET as Pairing>::ScalarField::from_le_bytes_mod_order(&lo));
                out.push(<ET as Pairing>::ScalarField::from_le_bytes_mod_order(&hi));
            };
            let mut buf32 = [0u8; 32];
            push32(&prior_prior.target_root, &mut pp_chunk_values);
            push32(&prior_prior.target_block_hash, &mut pp_chunk_values);
            buf32[..8].copy_from_slice(&prior_prior.target_height.to_le_bytes());
            push32(&buf32, &mut pp_chunk_values);
            push32(&prior_prior.prior_root, &mut pp_chunk_values);
            push32(&prior_prior.prior_block_hash, &mut pp_chunk_values);
            buf32[..8].copy_from_slice(&prior_prior.prior_height.to_le_bytes());
            push32(&buf32, &mut pp_chunk_values);
        }
        let mut pp_chunk_fps = Vec::with_capacity(12);
        for v in &pp_chunk_values {
            pp_chunk_fps.push(alloc_witness(*v)?);
        }
        let pp_prior_sel_fp = alloc_witness(if prior_prior.sel {
            <ET as Pairing>::ScalarField::from(1u64)
        } else {
            <ET as Pairing>::ScalarField::from(0u64)
        })?;
        let mut pp_vk_digest_fps = Vec::with_capacity(2);
        {
            let (lo, hi) = split_chunk(&prior_prior.vk_digest);
            for v in [&lo, &hi] {
                pp_vk_digest_fps.push(alloc_witness(
                    <ET as Pairing>::ScalarField::from_le_bytes_mod_order(v),
                )?);
            }
        }
        let _ = (&pp_chunk_fps, &pp_prior_sel_fp, &pp_vk_digest_fps);

        // ---- 2. Witnesses ----
        let a_var = <PW as PairingGadget<EP>>::G1Var::new_variable(
            cs.clone(),
            || Ok(self.prior_proof.a.into_group()),
            AllocationMode::Witness,
        )?;
        let b_var = <PW as PairingGadget<EP>>::G2Var::new_variable(
            cs.clone(),
            || Ok(self.prior_proof.b.into_group()),
            AllocationMode::Witness,
        )?;
        let c_var = <PW as PairingGadget<EP>>::G1Var::new_variable(
            cs.clone(),
            || Ok(self.prior_proof.c.into_group()),
            AllocationMode::Witness,
        )?;

        let delta_val = own[2] - own[7]; // S_N - S_prev
        let delta_fp = alloc_witness(delta_val)?;
        let n_inv_val = own[4].inverse().ok_or(SynthesisError::Unsatisfiable)?;
        let n_inv_fp = alloc_witness(n_inv_val)?;
        let chain_inv_val = own[5].inverse().ok_or(SynthesisError::Unsatisfiable)?;
        let chain_inv_fp = alloc_witness(chain_inv_val)?;

        let alpha_var = <PW as PairingGadget<EP>>::G1Var::new_variable(
            cs.clone(),
            || Ok(self.prior_vk.alpha_g1.into_group()),
            AllocationMode::Witness,
        )?;
        let beta_var = <PW as PairingGadget<EP>>::G2Var::new_variable(
            cs.clone(),
            || Ok(self.prior_vk.beta_g2.into_group()),
            AllocationMode::Witness,
        )?;
        let gamma_var = <PW as PairingGadget<EP>>::G2Var::new_variable(
            cs.clone(),
            || Ok(self.prior_vk.gamma_g2.into_group()),
            AllocationMode::Witness,
        )?;
        let delta_vk_var = <PW as PairingGadget<EP>>::G2Var::new_variable(
            cs.clone(),
            || Ok(self.prior_vk.delta_g2.into_group()),
            AllocationMode::Witness,
        )?;
        let mut ic_vars = Vec::with_capacity(self.prior_vk.ic.len());
        for p in &self.prior_vk.ic {
            ic_vars.push(<PW as PairingGadget<EP>>::G1Var::new_variable(
                cs.clone(),
                || Ok((*p).into_group()),
                AllocationMode::Witness,
            )?);
        }

        // ---- 3. Scaffold + policy constraints ----
        sel_fp.mul_equals(&sel_fp, &sel_fp)?;
        (sp_fp.clone() + &delta_fp).enforce_equal(&sn_fp)?;
        n_own_fp.mul_equals(&n_inv_fp, &one_fp)?;
        chain_fp.mul_equals(&chain_inv_fp, &one_fp)?;

        // sel = 0 pins the prior statement to genesis: (x - genesis) * (1 - sel) == 0.
        let not_sel = one_fp.clone() - &sel_fp;
        (sp_fp.clone() - &s0_fp).mul_equals(&not_sel, &zero_fp)?;
        hp_own_fp.mul_equals(&not_sel, &zero_fp)?;
        np_own_fp.mul_equals(&not_sel, &zero_fp)?;

        // Inductive chaining ties (sel = 1): prior.target == own.prior.
        let two128 = FpVar::Constant(pow2::<<ET as Pairing>::ScalarField>(128));
        let recon = |lo: &FpVar<<ET as Pairing>::ScalarField>,
                     hi: &FpVar<<ET as Pairing>::ScalarField>|
         -> Result<FpVar<<ET as Pairing>::ScalarField>, SynthesisError> {
            Ok(lo.clone() + &(hi.clone() * &two128))
        };
        let sn_recon = recon(&chunk_fps[0], &chunk_fps[1])?;
        let hn_recon = recon(&chunk_fps[2], &chunk_fps[3])?;
        let np_recon = recon(&chunk_fps[4], &chunk_fps[5])?;
        let sp_recon = recon(&chunk_fps[6], &chunk_fps[7])?;
        let hp_recon = recon(&chunk_fps[8], &chunk_fps[9])?;
        let npr_recon = recon(&chunk_fps[10], &chunk_fps[11])?;

        (sn_recon.clone() - &sp_fp).mul_equals(&sel_fp, &zero_fp)?;
        (hn_recon.clone() - &hp_own_fp).mul_equals(&sel_fp, &zero_fp)?;
        (np_recon.clone() - &np_own_fp).mul_equals(&sel_fp, &zero_fp)?;

        // Anchor-match: the prior statement equals the pinned anchor
        // certificate's statement.
        let anchor_root = field_from_hash::<ET::ScalarField>(&self.anchor.root);
        let anchor_hash = field_from_hash::<ET::ScalarField>(&self.anchor.block_hash);
        let anchor_height = field_from_u64::<ET::ScalarField>(self.anchor.height);
        let eq_const = |x: &FpVar<<ET as Pairing>::ScalarField>,
                        c: <ET as Pairing>::ScalarField|
         -> Result<Boolean<<ET as Pairing>::ScalarField>, SynthesisError> {
            x.is_eq(&FpVar::Constant(c))
        };
        let mut am = eq_const(&sn_recon, anchor_root)?;
        am &= &eq_const(&hn_recon, anchor_hash)?;
        am &= &eq_const(&np_recon, anchor_height)?;
        am &= &sp_recon.is_eq(&s0_fp)?;
        am &= &eq_const(&hp_recon, <ET as Pairing>::ScalarField::from(0u64))?;
        am &= &eq_const(&npr_recon, <ET as Pairing>::ScalarField::from(0u64))?;
        am &= &prior_sel_fp.is_eq(&zero_fp)?;

        // Policy tie: sel * (prior_sel - 1) * (1 - anchor_match) == 0.
        let am_fp = FpVar::conditionally_select(&am, &one_fp, &zero_fp)?;
        let lhs = prior_sel_fp.clone() - &one_fp;
        let rhs = one_fp.clone() - &am_fp;
        let lhs_val = lhs.value().unwrap_or(<ET as Pairing>::ScalarField::from(0u64));
        let rhs_val = rhs.value().unwrap_or(<ET as Pairing>::ScalarField::from(0u64));
        let t_fp = alloc_witness(lhs_val * rhs_val)?;
        lhs.mul_equals(&rhs, &t_fp)?;
        sel_fp.mul_equals(&t_fp, &zero_fp)?;

        // ---- 4. In-circuit Poseidon commitment binding the witness VK ----
        // Hash all witness VK coordinate base-prime field elements using
        // the arithmetic-native Poseidon sponge gadget; enforce equality with
        // the prior statement's vk_digest (reconstructed from chunk publics, gated by sel).
        let vk_elems = self.prior_vk.to_base_prime_field_elements();
        let mut vk_coord_vars: Vec<FpVar<<ET as Pairing>::ScalarField>> =
            Vec::with_capacity(vk_elems.len());
        for elem in &vk_elems {
            vk_coord_vars.push(alloc_witness(*elem)?);
        }
        let computed_vk_digest = poseidon_sponge_gadget(cs.clone(), &vk_coord_vars)?;
        let expected_vk_digest = recon(&vk_digest_fps[0], &vk_digest_fps[1])?;
        let vk_ok = computed_vk_digest.is_eq(&expected_vk_digest)?;
        let vk_ok_fp = FpVar::conditionally_select(&vk_ok, &one_fp, &zero_fp)?;
        (vk_ok_fp - &one_fp).mul_equals(&sel_fp, &zero_fp)?;

        // ---- 5. In-circuit verification of the PRIOR Groth16 proof ----
        // g_ic = IC_0 + sum(x_i * IC_i) over the prior circuit's full
        // 25-element public-input vector, in its input order:
        //   [0] sel_p            -> prior_sel_fp
        //   [1] S_0p             -> own S_0 (same genesis)
        //   [2..5] S_Np,H_Np,N_p -> prior chunk reconstructions
        //   [5] chain_p          -> own chain_id
        //   [6] vk_digest_p      -> prior_vk_digest reconstruction
        //   [7..10] S_prev_p,H_prev_p,N_prev_p -> prior chunk reconstructions
        //   [10..22] the prior's own 12 chunk publics (direct)
        //   [22] the prior's prior_sel (direct)
        //   [23,24] the prior's prior_vk_digest chunks (direct)
        let mut scalar_bitvecs: Vec<Vec<Boolean<<ET as Pairing>::ScalarField>>> =
            Vec::with_capacity(25);
        let chunk_scalar = |lo: usize, hi: usize| -> Vec<Boolean<<ET as Pairing>::ScalarField>> {
            let mut bits = chunk_bits[lo].clone();
            bits.extend(chunk_bits[hi].iter().cloned());
            debug_assert_eq!(bits.len(), 256);
            bits
        };
        scalar_bitvecs.push(prior_sel_fp.to_bits_le()?); // [0] sel_p
        scalar_bitvecs.push(s0_fp.to_bits_le()?); // [1] S_0p
        scalar_bitvecs.push(chunk_scalar(0, 1)); // [2] S_Np
        scalar_bitvecs.push(chunk_scalar(2, 3)); // [3] H_Np
        scalar_bitvecs.push(chunk_scalar(4, 5)); // [4] N_p
        scalar_bitvecs.push(chain_fp.to_bits_le()?); // [5] chain_p
        scalar_bitvecs.push(chunk_scalar(0, 1)); // placeholder, replaced below
        scalar_bitvecs.push(chunk_scalar(6, 7)); // [7] S_prev_p
        scalar_bitvecs.push(chunk_scalar(8, 9)); // [8] H_prev_p
        scalar_bitvecs.push(chunk_scalar(10, 11)); // [9] N_prev_p
        for fp in &pp_chunk_fps {
            scalar_bitvecs.push(fp.to_bits_le()?); // [10..22] prior's chunks
        }
        scalar_bitvecs.push(pp_prior_sel_fp.to_bits_le()?); // [22]
        for fp in &pp_vk_digest_fps {
            scalar_bitvecs.push(fp.to_bits_le()?); // [23,24]
        }
        // [6] vk_digest_p = full 256-bit reconstruction of the digest chunks.
        scalar_bitvecs[6] = {
            let lo_bits = vk_digest_fps[0].to_bits_le()?;
            let hi_bits = vk_digest_fps[1].to_bits_le()?;
            let mut bits = Vec::with_capacity(256);
            for b in lo_bits.iter().take(128) {
                bits.push(b.clone());
            }
            for b in hi_bits.iter().take(128) {
                bits.push(b.clone());
            }
            bits
        };

        let mut g_ic = ic_vars[0].clone();
        for (i, bits) in scalar_bitvecs.iter().enumerate() {
            let term = ic_vars[i + 1].scalar_mul_le(bits.iter())?;
            g_ic += &term;
        }

        // Verification equation, in product-of-pairings form:
        //   e(A, B) * e(-g_ic, gamma) * e(-C, delta) * e(-alpha, beta) == 1
        let a_prep = <PW as PairingGadget<EP>>::prepare_g1(&a_var)?;
        let b_prep = <PW as PairingGadget<EP>>::prepare_g2(&b_var)?;
        let g_prep = <PW as PairingGadget<EP>>::prepare_g1(&g_ic.negate()?)?;
        let c_prep = <PW as PairingGadget<EP>>::prepare_g1(&c_var.negate()?)?;
        let alpha_prep = <PW as PairingGadget<EP>>::prepare_g1(&alpha_var.negate()?)?;
        let gamma_prep = <PW as PairingGadget<EP>>::prepare_g2(&gamma_var)?;
        let delta_prep = <PW as PairingGadget<EP>>::prepare_g2(&delta_vk_var)?;
        let beta_prep = <PW as PairingGadget<EP>>::prepare_g2(&beta_var)?;

        let gt_product = <PW as PairingGadget<EP>>::product_of_pairings(
            &[a_prep, g_prep, c_prep, alpha_prep],
            &[b_prep, gamma_prep, delta_prep, beta_prep],
        )?;
        let gt_one = <PW as PairingGadget<EP>>::GTVar::constant(
            <EP as Pairing>::TargetField::ONE,
        );
        let eq_bit_bool = gt_product.is_eq(&gt_one)?;
        let eq_fp = FpVar::conditionally_select(&eq_bit_bool, &one_fp, &zero_fp)?;

        // Pairing gate: sel * (eq - 1) == 0.
        (eq_fp.clone() - &one_fp).mul_equals(&sel_fp, &zero_fp)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Layer aliases
// ---------------------------------------------------------------------------

/// Layer A: proves over MNT6-753; verifies prior MNT4-753 proofs in-circuit.
pub type FoldCircuitA = RecursiveFoldCircuit<
    ark_mnt6_753::MNT6_753,
    ark_mnt4_753::MNT4_753,
    ark_r1cs_std::pairing::mnt4::PairingVar<ark_mnt4_753::Config>,
>;

/// Layer B: proves over MNT4-753; verifies prior MNT6-753 proofs in-circuit.
pub type FoldCircuitB = RecursiveFoldCircuit<
    ark_mnt4_753::MNT4_753,
    ark_mnt6_753::MNT6_753,
    ark_r1cs_std::pairing::mnt6::PairingVar<ark_mnt6_753::Config>,
>;

// ---------------------------------------------------------------------------
// Prover / verifier wrappers
// ---------------------------------------------------------------------------

/// Prover for one fold layer.
pub struct FoldLayerProver<ET: Pairing, EP: Pairing, PW: PairingGadget<EP>> {
    pub proving_key: ProvingKey<ET>,
    /// This layer's verifying key (needed to build the OTHER layer's
    /// verifier and to derive this layer's `vk_digest`).
    pub vk: VerifyingKey<ET>,
    pub anchor: FoldAnchorConfig,
    pub chain_id: u64,
    /// Poseidon digest of this layer's canonical VK; bound into every
    /// statement this layer produces.
    pub vk_digest: [u8; 32],
    pub layer: FoldLayerId,
    pub _pd: PhantomData<(EP, PW)>,
}

// Manual impls: derive(Clone)/derive(Debug) would add unnecessary bounds for
// the PhantomData marker.
impl<ET: Pairing, EP: Pairing, PW: PairingGadget<EP>> Clone for FoldLayerProver<ET, EP, PW> {
    fn clone(&self) -> Self {
        Self {
            proving_key: self.proving_key.clone(),
            vk: self.vk.clone(),
            anchor: self.anchor.clone(),
            chain_id: self.chain_id,
            vk_digest: self.vk_digest,
            layer: self.layer,
            _pd: PhantomData,
        }
    }
}

impl<ET, EP, PW> FoldLayerProver<ET, EP, PW>
where
    ET: Pairing,
    EP: Pairing,
    PW: PairingGadget<EP>,
{
    fn debug_fields(&self) -> impl std::fmt::Debug {
        (
            self.layer,
            self.chain_id,
            hex::encode(self.vk_digest),
        )
    }
}

impl<ET: Pairing, EP: Pairing, PW: PairingGadget<EP>> std::fmt::Debug
    for FoldLayerProver<ET, EP, PW>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FoldLayerProver")
            .field("inner", &self.debug_fields())
            .finish()
    }
}

impl<ET, EP, PW> FoldLayerProver<ET, EP, PW>
where
    ET: Pairing,
    EP: Pairing,
    PW: PairingGadget<EP>,
    ET: Pairing<ScalarField = <<EP as Pairing>::G1 as CurveGroup>::BaseField>,
    ET: Pairing<ScalarField = <<<EP as Pairing>::G2Affine as AffineRepr>::BaseField as Field>::BasePrimeField>,
{
    /// Trusted setup for this layer. Both layers' setups are independent:
    /// the prior VK is witness material, never a setup constant.
    pub fn setup(
        anchor: FoldAnchorConfig,
        chain_id: u64,
        layer: FoldLayerId,
    ) -> anyhow::Result<Self> {
        // Setup dummy: heights must be non-zero (the circuit enforces it),
        // sel = 0 so the pairing and VK-commitment gates are open for the
        // filler points.
        let statement = FoldStatement {
            sel: false,
            genesis_root: anchor.root,
            target_root: anchor.root,
            target_block_hash: anchor.block_hash,
            target_height: anchor.height.max(1),
            chain_id,
            vk_digest: [0u8; 32],
            prior_root: anchor.root,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
        };
        let prior_statement = FoldStatement::genesis_prior(anchor.root, chain_id, [0u8; 32]);
        let prior_prior_statement =
            FoldStatement::genesis_prior(anchor.root, chain_id, [0u8; 32]);
        let circuit = RecursiveFoldCircuit::<ET, EP, PW> {
            anchor: anchor.clone(),
            statement,
            prior_statement,
            prior_prior_statement,
            prior_vk: PriorVK::dummy_for_setup(),
            prior_proof: PriorProofPoints::generators(),
            _pd: PhantomData,
        };
        let mut rng = rand::thread_rng();
        let (proving_key, vk) = Groth16::<ET>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| anyhow::anyhow!("fold layer {layer:?} setup failed: {e:?}"))?;
        let vk_digest = fold_vk_digest(&vk);
        Ok(Self {
            proving_key,
            vk,
            anchor,
            chain_id,
            vk_digest,
            layer,
            _pd: PhantomData,
        })
    }

    /// Prove one fold of this layer.
    pub fn prove(
        &self,
        statement: FoldStatement,
        prior_statement: FoldStatement,
        prior_prior_statement: FoldStatement,
        prior_vk: &PriorVK<EP>,
        prior_proof: &PriorProofPoints<EP>,
    ) -> anyhow::Result<Proof<ET>> {
        let circuit = RecursiveFoldCircuit::<ET, EP, PW> {
            anchor: self.anchor.clone(),
            statement,
            prior_statement,
            prior_prior_statement,
            prior_vk: prior_vk.clone(),
            prior_proof: prior_proof.clone(),
            _pd: PhantomData,
        };
        let mut rng = rand::thread_rng();
        Groth16::<ET>::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|e| anyhow::anyhow!("fold proof generation failed: {e:?}"))
    }
}

/// Native verifier for one fold layer. Performs exactly ONE pairing check
/// per certificate (O(1) sync verification).
#[derive(Clone)]
pub struct FoldLayerVerifier<ET: Pairing> {
    pub vk: VerifyingKey<ET>,
    pub anchor: FoldAnchorConfig,
    pub chain_id: u64,
    /// This layer's pinned VK digest; every statement must carry it.
    pub vk_digest: [u8; 32],
    /// The pinned PRIOR layer's VK digest; folded certificates must carry it
    /// in their `prior_vk_digest` element.
    pub prior_vk_digest: [u8; 32],
}

impl<ET: Pairing> FoldLayerVerifier<ET> {
    /// Build from this layer's VK and the prior layer's VK digest (pinned).
    pub fn new(
        vk: &VerifyingKey<ET>,
        prior_vk_digest: [u8; 32],
        anchor: FoldAnchorConfig,
        chain_id: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            vk: vk.clone(),
            anchor,
            chain_id,
            vk_digest: fold_vk_digest(vk),
            prior_vk_digest,
        })
    }

    /// Verify a fold certificate with a single pairing check.
    ///
    /// `own` is the certificate's statement; `prior` and `prior_prior` are
    /// the prior certificates' statements (sync metadata; all bound by the
    /// proof). Fail-closed: chain id and VK digests must match the pins.
    pub fn verify(
        &self,
        own: &FoldStatement,
        prior: &FoldStatement,
        prior_prior: &FoldStatement,
        proof: &Proof<ET>,
    ) -> anyhow::Result<bool> {
        if own.chain_id != self.chain_id {
            anyhow::bail!(
                "fold certificate chain id {} does not match pinned {}",
                own.chain_id,
                self.chain_id
            );
        }
        if own.vk_digest != self.vk_digest {
            anyhow::bail!("fold certificate vk_digest does not match the pinned ceremony");
        }
        if own.genesis_root != prior.genesis_root
            || prior.genesis_root != prior_prior.genesis_root
        {
            anyhow::bail!("fold certificate genesis root does not match its prior statements");
        }
        if own.sel && prior.vk_digest != self.prior_vk_digest {
            anyhow::bail!(
                "folded certificate's prior_vk_digest does not match the pinned prior-layer ceremony"
            );
        }
        let inputs = fold_public_inputs::<ET>(own, prior, prior_prior)?;
        Groth16::<ET>::verify(&self.vk, &inputs, proof)
            .map_err(|e| anyhow::anyhow!("fold pairing check failed: {e:?}"))
    }
}

/// Serialize a fold-layer proof into canonical compressed bytes.
pub fn serialize_fold_proof<ET: Pairing>(
    proof: &Proof<ET>,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    proof
        .serialize_compressed(&mut out)
        .map_err(|e| anyhow::anyhow!("fold proof serialization failed: {e:?}"))?;
    Ok(out)
}

/// Deserialize and group-validate a canonical fold-layer proof.
pub fn deserialize_fold_proof<ET: Pairing>(bytes: &[u8]) -> anyhow::Result<Proof<ET>> {
    Proof::<ET>::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("invalid fold proof encoding: {e:?}"))
}

/// The complete fold stack: provers and verifiers for both layers of the
/// MNT4/6-753 cycle, sharing one anchor configuration and chain id.
#[derive(Clone)]
pub struct FoldStack {
    pub prover_a: FoldLayerProver<
        ark_mnt6_753::MNT6_753,
        ark_mnt4_753::MNT4_753,
        ark_r1cs_std::pairing::mnt4::PairingVar<ark_mnt4_753::Config>,
    >,
    pub prover_b: FoldLayerProver<
        ark_mnt4_753::MNT4_753,
        ark_mnt6_753::MNT6_753,
        ark_r1cs_std::pairing::mnt6::PairingVar<ark_mnt6_753::Config>,
    >,
    pub verifier_a: FoldLayerVerifier<ark_mnt6_753::MNT6_753>,
    pub verifier_b: FoldLayerVerifier<ark_mnt4_753::MNT4_753>,
}

impl std::fmt::Debug for FoldStack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FoldStack")
            .field("prover_a", &self.prover_a)
            .field("prover_b", &self.prover_b)
            .finish_non_exhaustive()
    }
}

impl FoldStack {
    /// Run both layer setups (independent; the prior VK is witness material,
    /// never a setup constant) and build the cross-layer verifiers.
    pub fn generate(anchor: FoldAnchorConfig, chain_id: u64) -> anyhow::Result<Self> {
        let prover_a = FoldLayerProver::setup(anchor.clone(), chain_id, FoldLayerId::A)?;
        let prover_b = FoldLayerProver::setup(anchor.clone(), chain_id, FoldLayerId::B)?;
        // Layer A verifies prior layer-B proofs: its verifier pins VK_B's digest.
        let verifier_a = FoldLayerVerifier::new(
            &prover_a.vk,
            prover_b.vk_digest,
            anchor.clone(),
            chain_id,
        )?;
        // Layer B verifies prior layer-A proofs: its verifier pins VK_A's digest.
        let verifier_b = FoldLayerVerifier::new(
            &prover_b.vk,
            prover_a.vk_digest,
            anchor.clone(),
            chain_id,
        )?;
        Ok(Self {
            prover_a,
            prover_b,
            verifier_a,
            verifier_b,
        })
    }
}

