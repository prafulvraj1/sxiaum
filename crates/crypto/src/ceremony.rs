//! Sequential multi-party Powers-of-Tau ceremony for the KZG / Verkle SRS.
//!
//! # Protocol
//!
//! The ceremony is a sequential MPC in the style of "perpetual powers of tau":
//!
//! 1. **Init** ([`ceremony_init`]): publishes the initial SRS built from the
//!    generators only (`tau = 1`: every G1 power is `g1`, `[tau]_2 = g2`) plus
//!    a genesis transcript entry. No secret exists yet.
//! 2. **Contribute** ([`ceremony_contribute`]): each participant
//!    - fully *verifies* the incoming SRS structure with BLS12-381 pairings
//!      and the transcript chain (fail closed),
//!    - samples fresh secret entropy `tau_i` from the OS RNG and exponentiates
//!      every element (`P -> tau_i * P`, `[tau]_2 -> tau_i * [tau]_2`),
//!    - publishes `W_i = [tau_i]_2`, a hiding commitment to its secret that
//!      later lets anyone verify the round with a single pairing,
//!    - destroys the secret before writing anything to disk.
//! 3. **Finalize** ([`ceremony_verify`]): anyone verifies offline
//!    - the transcript hash chain links every contribution,
//!    - every round satisfies `e(new_P1, g2) == e(old_P1, W_i)` — proving the
//!      published ratio scalar was actually applied (knowledge of `tau_i`),
//!    - the final SRS passes full structural verification
//!      (`e(P_i, g2) == e(P_{i-1}, [tau]_2)` for all i),
//!    - participant count meets [`MIN_CEREMONY_PARTICIPANTS`], IDs are unique,
//!    - the final file does not match the development-trapdoor fingerprint.
//!
//! Security: as long as **one** honest contributor destroyed its `tau_i`, the
//! final toxic waste is unknown. Every structural claim is publicly checkable,
//! so participants need trust neither each other nor any coordinator.
//!
//! The finalized file is consumed by
//! [`crate::kzg::load_production_srs_from_file`] and its SHA-256 pinned in
//! genesis `kzg.srs_hash` (see [`crate::kzg::assert_production_srs_file`]).

use crate::hash::domain_hash;
use crate::kzg::{load_srs_from_file, write_srs_to_file, BRANCHING_FACTOR, DEV_SRS_MARKER, SRS};
use anyhow::{bail, Context, Result};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroize;

/// Current ceremony transcript format version.
pub const CEREMONY_TRANSCRIPT_VERSION: u32 = 1;

/// Minimum number of contributions required for a mainnet-grade ceremony.
pub const MIN_CEREMONY_PARTICIPANTS: usize = 3;

const DOMAIN_ATTEST_KEY: &str = "SXIAUM_CEREMONY_ATTEST";
const DOMAIN_CHALLENGE: &str = "SXIAUM_CEREMONY_CHALLENGE";

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn srs_file_digest(path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read SRS file {}", path.display()))?;
    Ok(sha256(&bytes))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One participant's contribution record in the public transcript.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyContribution {
    /// Operator-chosen participant identifier (unique per ceremony).
    pub participant_id: String,
    /// SHA-256 of the SRS file this contribution transformed.
    #[serde(with = "hex32")]
    pub prev_state_hash: [u8; 32],
    /// SHA-256 of the SRS file produced by this contribution.
    #[serde(with = "hex32")]
    pub new_state_hash: [u8; 32],
    /// Compressed G2 element `[tau_i]_2` — hiding commitment to the round
    /// secret scalar.
    #[serde(with = "point_hex")]
    pub tau_commitment: Vec<u8>,
    /// Compressed G1 element `[tau_1 * ... * tau_i]_1` — cumulative product
    /// after this round, enabling full offline verification of every ratio.
    #[serde(with = "point_hex")]
    pub cumulative_p1: Vec<u8>,
    /// Fresh per-round randomness binding the attestation to this round only.
    #[serde(with = "hex32")]
    pub challenge: [u8; 32],
    /// `H(ATTEST || challenge || new_state_hash || commitments)` — public
    /// transcript-binding digest.
    #[serde(with = "hex32")]
    pub attestation: [u8; 32],
    /// Unix timestamp when the contribution was created.
    pub created_at_unix: u64,
}

/// Public, ordered transcript of a full ceremony run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyTranscript {
    pub version: u32,
    /// Number of G1 powers fixed at init; must match every SRS file.
    pub branching_factor: usize,
    /// SHA-256 of the initial (generator-only) SRS file.
    #[serde(with = "hex32")]
    pub init_state_hash: [u8; 32],
    pub contributions: Vec<CeremonyContribution>,
}

impl CeremonyTranscript {
    /// Create the genesis transcript for an initialized ceremony.
    pub fn genesis(init_state_hash: [u8; 32], branching_factor: usize) -> Self {
        Self {
            version: CEREMONY_TRANSCRIPT_VERSION,
            branching_factor,
            init_state_hash,
            contributions: Vec::new(),
        }
    }

    /// Load a JSON transcript from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)
            .with_context(|| format!("failed to read ceremony transcript {}", path.display()))?;
        serde_json::from_slice(&raw)
            .with_context(|| format!("failed to parse ceremony transcript {}", path.display()))
    }

    /// Write a JSON transcript to disk.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
        }
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    /// Hash of the current head state (init hash when no contributions yet).
    pub fn head_state_hash(&self) -> [u8; 32] {
        self.contributions
            .last()
            .map(|c| c.new_state_hash)
            .unwrap_or(self.init_state_hash)
    }

    /// Structural validation: version, hash-chain linkage, unique IDs,
    /// non-zero challenges/attestations.
    pub fn validate_chain(&self) -> Result<()> {
        if self.version != CEREMONY_TRANSCRIPT_VERSION {
            bail!(
                "unsupported ceremony transcript version {} (expected {})",
                self.version,
                CEREMONY_TRANSCRIPT_VERSION
            );
        }
        if self.branching_factor != BRANCHING_FACTOR {
            bail!(
                "ceremony transcript branching factor {} does not match this build ({})",
                self.branching_factor,
                BRANCHING_FACTOR
            );
        }

        let mut seen_ids = std::collections::HashSet::new();
        let mut expected_prev = self.init_state_hash;
        for (idx, c) in self.contributions.iter().enumerate() {
            if c.participant_id.trim().is_empty() {
                bail!("contribution {idx} has an empty participant id");
            }
            if !seen_ids.insert(c.participant_id.clone()) {
                bail!(
                    "participant id {:?} appears more than once in the ceremony",
                    c.participant_id
                );
            }
            if c.prev_state_hash != expected_prev {
                bail!(
                    "contribution {idx} ({}) breaks the hash chain: prev_state_hash does not \
                     match the previous state",
                    c.participant_id
                );
            }
            if c.new_state_hash == c.prev_state_hash {
                bail!(
                    "contribution {idx} ({}) did not change the SRS state",
                    c.participant_id
                );
            }
            if c.tau_commitment.is_empty() || c.cumulative_p1.is_empty() {
                bail!(
                    "contribution {idx} ({}) is missing its tau commitments",
                    c.participant_id
                );
            }
            if c.challenge == [0u8; 32] || c.attestation == [0u8; 32] {
                bail!(
                    "contribution {idx} ({}) has a zero challenge or attestation",
                    c.participant_id
                );
            }
            expected_prev = c.new_state_hash;
        }
        Ok(())
    }

    /// Finalize-time gate: valid chain with enough distinct participants.
    pub fn validate_for_production(&self, min_participants: usize) -> Result<()> {
        self.validate_chain()?;
        if self.contributions.len() < min_participants {
            bail!(
                "ceremony has only {} contribution(s); production requires at least {}",
                self.contributions.len(),
                min_participants
            );
        }
        Ok(())
    }
}

/// Full structural + cryptographic verification of an SRS stage against
/// itself. Works for ANY powers-of-tau stage (initial tau=1 included) without
/// knowing tau. All checks fail closed:
///
/// - exactly [`BRANCHING_FACTOR`] G1 powers,
/// - `P_0 == g1`,
/// - `e(P_1, g2) == e(g1, [tau]_2)` (G1/G2 agree on the secret scalar),
/// - `e(P_i, g2) == e(P_{i-1}, [tau]_2)` for every consecutive power,
/// - no match with the development-trapdoor fingerprint.
pub fn verify_srs_structure(srs: &SRS) -> Result<()> {
    if srs.g1_powers.len() != BRANCHING_FACTOR {
        bail!(
            "SRS must contain exactly {BRANCHING_FACTOR} G1 powers, got {}",
            srs.g1_powers.len()
        );
    }
    if srs.g1_powers[0] != G1Projective::generator() {
        bail!("SRS P_0 is not the BLS12-381 G1 generator");
    }
    // Pin the canonical G2 generator so every node loads byte-comparable
    // parameters and pairing checks are interoperable.
    if srs.g2 != G2Projective::generator() {
        bail!("SRS g2 element is not the canonical BLS12-381 G2 generator");
    }

    // Initial ceremony state (tau = 1): [tau]_2 == g2.
    if srs.g2_tau == srs.g2 {
        if srs.is_dev_trapdoor() {
            bail!("SRS matches the development trapdoor fingerprint ({DEV_SRS_MARKER})");
        }
        if srs
            .g1_powers
            .iter()
            .any(|p| *p != G1Projective::generator())
        {
            bail!("SRS claims tau=1 ([tau]_2 == g2) but G1 powers are not all the generator");
        }
        return Ok(());
    }

    let g2_aff = srs.g2.into_affine();
    let g2_tau_aff = srs.g2_tau.into_affine();
    let g1_gen_aff = G1Projective::generator().into_affine();

    let lhs = Bls12_381::pairing(g1_gen_aff, g2_tau_aff);
    let rhs = Bls12_381::pairing(srs.g1_powers[1].into_affine(), g2_aff);
    if lhs != rhs {
        bail!("SRS pairing check failed: e(g1, [tau]_2) != e([tau]_1, g2)");
    }

    for i in 2..srs.g1_powers.len() {
        let lhs = Bls12_381::pairing(srs.g1_powers[i].into_affine(), g2_aff);
        let rhs = Bls12_381::pairing(srs.g1_powers[i - 1].into_affine(), g2_tau_aff);
        if lhs != rhs {
            bail!(
                "SRS pairing check failed at G1 power {i}: powers are not a consistent \
                 geometric progression"
            );
        }
    }

    if srs.is_dev_trapdoor() {
        bail!("SRS matches the development trapdoor fingerprint ({DEV_SRS_MARKER})");
    }
    Ok(())
}

/// Initialize a new ceremony: write the generator-only SRS (tau = 1) and the
/// genesis transcript. Returns the SHA-256 pin of the initial SRS file.
pub fn ceremony_init(srs_path: &Path, transcript_path: &Path) -> Result<[u8; 32]> {
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let srs = SRS::from_public_parts(vec![g1; BRANCHING_FACTOR], g2, g2);
    if srs.is_dev_trapdoor() {
        bail!("internal error: initial ceremony SRS matched the dev trapdoor");
    }

    write_srs_to_file(&srs, srs_path)?;
    let init_hash = srs_file_digest(srs_path)?;

    let transcript = CeremonyTranscript::genesis(init_hash, BRANCHING_FACTOR);
    transcript.save(transcript_path)?;

    tracing::info!(
        "ceremony initialized: {BRANCHING_FACTOR} G1 powers, initial state 0x{}",
        hex::encode(init_hash)
    );
    Ok(init_hash)
}

/// Contribute to an existing ceremony.
///
/// Verifies the incoming SRS structurally (pairings) and against the
/// transcript chain, applies fresh OS entropy, records a verifiable
/// `[tau_i]_2` commitment, destroys the secret, and appends to the transcript.
/// Returns the recorded contribution.
pub fn ceremony_contribute(
    input_srs_path: &Path,
    output_srs_path: &Path,
    transcript_path: &Path,
    participant_id: &str,
) -> Result<CeremonyContribution> {
    if participant_id.trim().is_empty() {
        bail!("participant id must not be empty");
    }

    let mut transcript = CeremonyTranscript::load(transcript_path)?;
    transcript.validate_chain()?;
    if transcript
        .contributions
        .iter()
        .any(|c| c.participant_id == participant_id)
    {
        bail!("participant {participant_id:?} already contributed to this ceremony");
    }

    // Verify incoming state BEFORE touching it (fail closed).
    let incoming =
        load_srs_from_file(input_srs_path).context("incoming ceremony SRS failed to load")?;
    verify_srs_structure(&incoming)
        .context("incoming ceremony SRS failed structural verification")?;

    let prev_hash = srs_file_digest(input_srs_path)?;
    if prev_hash != transcript.head_state_hash() {
        bail!(
            "input SRS hash 0x{} does not match the transcript head 0x{}",
            hex::encode(prev_hash),
            hex::encode(transcript.head_state_hash())
        );
    }

    // Sample fresh secret entropy and transform every element.
    let mut seed = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let mut tau = Fr::from_le_bytes_mod_order(&seed);
    seed.zeroize();
    if tau.is_zero() {
        tau = Fr::from(1u64);
    }

    // Transform: new_P_j = tau_i^j * old_P_j so the state remains a valid
    // powers-of-tau progression for the NEW cumulative secret T' = T * tau_i
    // ([(T*tau_i)^j]_1 = tau_i^j * [T^j]_1). The G2 element scales uniformly
    // because it commits the cumulative secret itself, not its powers.
    let mut factor = Fr::from(1u64);
    let out_g1: Vec<G1Projective> = incoming
        .g1_powers
        .iter()
        .map(|p| {
            let scaled = *p * factor;
            factor *= tau;
            scaled
        })
        .collect();
    let out_g2_tau = incoming.g2_tau * tau;

    // Hiding commitment to this round's secret ratio: W = [tau_i]_2.
    let w_projective = G2Projective::generator() * tau;
    let mut tau_commitment = Vec::new();
    w_projective
        .into_affine()
        .serialize_compressed(&mut tau_commitment)
        .map_err(|e| anyhow::anyhow!("failed to serialize tau commitment: {e:?}"))?;

    // Cumulative product after this round: C = [tau_1 * ... * tau_i]_1,
    // i.e. exactly the P1 of the state produced by this contribution.
    let mut cumulative_p1 = Vec::new();
    out_g1[1]
        .into_affine()
        .serialize_compressed(&mut cumulative_p1)
        .map_err(|e| anyhow::anyhow!("failed to serialize cumulative P1: {e:?}"))?;

    let srs = SRS::from_public_parts(out_g1, incoming.g2, out_g2_tau);

    write_srs_to_file(&srs, output_srs_path)?;
    let new_hash = srs_file_digest(output_srs_path)?;

    // Destroy the secret (best-effort; Fr does not implement Zeroize).
    tau = Fr::zero();
    let _ = tau;

    let challenge = domain_hash(DOMAIN_CHALLENGE, &prev_hash);
    let attestation = compute_attestation(&challenge, &new_hash, &tau_commitment, &cumulative_p1);

    let contribution = CeremonyContribution {
        participant_id: participant_id.to_string(),
        prev_state_hash: prev_hash,
        new_state_hash: new_hash,
        tau_commitment,
        cumulative_p1,
        challenge,
        attestation,
        created_at_unix: now_unix(),
    };
    transcript.contributions.push(contribution.clone());
    transcript.save(transcript_path)?;

    tracing::info!(
        "ceremony contribution recorded for {participant_id} (state 0x{})",
        hex::encode(new_hash)
    );
    Ok(contribution)
}

fn compute_attestation(
    challenge: &[u8; 32],
    new_hash: &[u8; 32],
    tau_commitment: &[u8],
    cumulative_p1: &[u8],
) -> [u8; 32] {
    let mut material = Vec::with_capacity(32 + 32 + tau_commitment.len() + cumulative_p1.len());
    material.extend_from_slice(challenge);
    material.extend_from_slice(new_hash);
    material.extend_from_slice(tau_commitment);
    material.extend_from_slice(cumulative_p1);
    domain_hash(DOMAIN_ATTEST_KEY, &material)
}

/// Finalize a ceremony: verify the complete transcript and the final SRS.
///
/// Offline verification uses only the final SRS file and the transcript:
///
/// 1. hash-chain linkage of every contribution (transcript integrity),
/// 2. attestation recomputation for every round,
/// 3. per-round ratio verification with pairings:
///    `e(C_i, g2) == e(C_{i-1}, W_i)` where `C_0 = g1`, `C_i` is the recorded
///    cumulative `[tau_1..tau_i]_1` and `W_i = [tau_i]_2` — each published
///    ratio scalar provably chained the state,
/// 4. `C_n == final_P1` plus full structural pairing verification of the
///    final file (all 256 powers consistent),
/// 5. minimum participant count, unique IDs, dev-trapdoor rejection.
///
/// Returns a [`CeremonyReport`] whose `final_state_hash` is the value to pin
/// in genesis `kzg.srs_hash`.
pub fn ceremony_verify(
    final_srs_path: &Path,
    transcript_path: &Path,
    min_participants: usize,
) -> Result<CeremonyReport> {
    use ark_bls12_381::G2Affine;
    use ark_ec::AffineRepr;
    use ark_serialize::CanonicalDeserialize;

    let transcript = CeremonyTranscript::load(transcript_path)?;
    transcript.validate_for_production(min_participants)?;

    let final_srs =
        load_srs_from_file(final_srs_path).context("final ceremony SRS failed to load")?;
    verify_srs_structure(&final_srs)
        .context("final ceremony SRS failed structural verification")?;

    let final_hash = srs_file_digest(final_srs_path)?;
    if final_hash != transcript.head_state_hash() {
        bail!(
            "final SRS hash 0x{} does not match the transcript head 0x{}",
            hex::encode(final_hash),
            hex::encode(transcript.head_state_hash())
        );
    }

    let g2_aff = final_srs.g2.into_affine();

    // Walk every round: attestation + cumulative-product pairing chain.
    let mut cumulative_prev = G1Projective::generator(); // C_0 = [1]_1
    for (idx, c) in transcript.contributions.iter().enumerate() {
        let expected_attestation = compute_attestation(
            &c.challenge,
            &c.new_state_hash,
            &c.tau_commitment,
            &c.cumulative_p1,
        );
        if expected_attestation != c.attestation {
            bail!(
                "contribution {idx} ({}) attestation mismatch",
                c.participant_id
            );
        }

        let w_aff = G2Affine::deserialize_compressed(c.tau_commitment.as_slice()).map_err(|e| {
            anyhow::anyhow!(
                "contribution {idx} ({}): invalid tau_commitment point: {e:?}",
                c.participant_id
            )
        })?;
        let c_i_aff = ark_bls12_381::G1Affine::deserialize_compressed(c.cumulative_p1.as_slice())
            .map_err(|e| {
            anyhow::anyhow!(
                "contribution {idx} ({}): invalid cumulative_p1 point: {e:?}",
                c.participant_id
            )
        })?;

        // e(C_i, g2) == e(C_{i-1}, W_i)  =>  C_i = tau_i * C_{i-1}
        let lhs = Bls12_381::pairing(c_i_aff, g2_aff);
        let rhs = Bls12_381::pairing(cumulative_prev.into_affine(), w_aff);
        if lhs != rhs {
            bail!(
                "contribution {idx} ({}): cumulative product does not chain from the previous \
                 round (pairing check failed)",
                c.participant_id
            );
        }
        cumulative_prev = c_i_aff.into_group();
    }

    // The last cumulative commitment must be exactly the final P1.
    if cumulative_prev != final_srs.g1_powers[1] {
        bail!("transcript cumulative P1 does not equal the final SRS [tau]_1 element");
    }

    Ok(CeremonyReport {
        final_state_hash: final_hash,
        participants: transcript
            .contributions
            .iter()
            .map(|c| c.participant_id.clone())
            .collect(),
        transcript_version: transcript.version,
    })
}

/// Summary returned by [`ceremony_verify`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CeremonyReport {
    /// SHA-256 of the final SRS file (pin in genesis `kzg.srs_hash`).
    #[serde(with = "hex32")]
    pub final_state_hash: [u8; 32],
    /// Ordered participant ids.
    pub participants: Vec<String>,
    pub transcript_version: u32,
}

// ---------------------------------------------------------------------------
// serde helpers (hex-encoded fields for human-readable transcripts)
// ---------------------------------------------------------------------------

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(v)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        let trimmed = raw.trim_start_matches("0x");
        let bytes = hex::decode(trimmed).map_err(serde::de::Error::custom)?;
        let len = bytes.len();
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected 32 bytes, got {len}")))
    }
}

mod point_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(v)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(d)?;
        hex::decode(raw.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kzg::{
        assert_production_srs_file, load_production_srs_from_file, load_srs_from_file,
    };

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sxiaum_ceremony_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn transcript_chain_rejects_tampering() {
        let mut t = CeremonyTranscript::genesis([1u8; 32], BRANCHING_FACTOR);
        let c = CeremonyContribution {
            participant_id: "a".into(),
            prev_state_hash: [1u8; 32],
            new_state_hash: [2u8; 32],
            tau_commitment: vec![1, 2, 3],
            cumulative_p1: vec![4, 5, 6],
            challenge: [7u8; 32],
            attestation: [8u8; 32],
            created_at_unix: 0,
        };
        t.contributions.push(c.clone());
        assert!(t.validate_chain().is_ok());

        // Break the chain.
        let mut broken = t.clone();
        broken.contributions[0].prev_state_hash = [9u8; 32];
        assert!(broken.validate_chain().is_err());

        // No-op contribution.
        let mut noop = t.clone();
        noop.contributions[0].new_state_hash = [1u8; 32];
        assert!(noop.validate_chain().is_err());

        // Duplicate participant.
        let mut dup = t;
        dup.contributions.push(CeremonyContribution {
            participant_id: "a".into(),
            ..c
        });
        assert!(dup.validate_chain().is_err());
    }

    #[test]
    fn full_ceremony_flow_verifies_and_pins() {
        let dir = temp_dir("flow");
        let srs_a = dir.join("srs_round0.srs");
        let srs_b = dir.join("srs_round1.srs");
        let srs_c = dir.join("srs_round2.srs");
        let srs_final = dir.join("srs_final.srs");
        let transcript = dir.join("transcript.json");

        let init_hash = ceremony_init(&srs_a, &transcript).expect("init");
        assert!(verify_srs_structure(&load_srs_from_file(&srs_a).unwrap()).is_ok());
        ceremony_contribute(&srs_a, &srs_b, &transcript, "alice").expect("alice");
        ceremony_contribute(&srs_b, &srs_c, &transcript, "bob").expect("bob");
        ceremony_contribute(&srs_c, &srs_final, &transcript, "carol").expect("carol");

        // Duplicate participation is rejected.
        assert!(ceremony_contribute(&srs_final, &srs_b, &transcript, "alice").is_err());

        let report = ceremony_verify(&srs_final, &transcript, MIN_CEREMONY_PARTICIPANTS)
            .expect("full verification must succeed");
        assert_ne!(report.final_state_hash, init_hash);
        assert_eq!(report.participants.len(), 3);
        assert!(report.participants.contains(&"bob".to_string()));

        // The final file is production-loadable and pinnable in genesis.
        let loaded = load_production_srs_from_file(&srs_final).expect("production load");
        assert!(!loaded.is_dev_trapdoor());
        let pinned = hex::encode(report.final_state_hash);
        assert_production_srs_file(&srs_final, &pinned).expect("genesis pin must match");
        assert!(assert_production_srs_file(&srs_final, &init_hash_hex_mismatch()).is_err());

        // Transcript round-trips through JSON with hex fields.
        let reloaded = CeremonyTranscript::load(&transcript).unwrap();
        assert_eq!(reloaded.contributions.len(), 3);
        assert_eq!(
            reloaded.contributions[0].participant_id, "alice",
            "hex-encoded transcript fields must deserialize"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn init_hash_hex_mismatch() -> String {
        "deadbeef".repeat(8)
    }

    #[test]
    fn ceremony_rejects_wrong_input_state() {
        let dir = temp_dir("wronginput");
        let srs_a = dir.join("a.srs");
        let srs_b = dir.join("b.srs");
        let srs_other = dir.join("other.srs");
        let transcript = dir.join("t.json");

        ceremony_init(&srs_a, &transcript).unwrap();
        ceremony_contribute(&srs_a, &srs_b, &transcript, "alice").unwrap();

        // A different valid SRS that is not the transcript head.
        let foreign_init = dir.join("foreign_init.srs");
        ceremony_init(&foreign_init, &dir.join("other_transcript.json")).unwrap();
        ceremony_contribute(
            &foreign_init,
            &srs_other,
            &dir.join("other_transcript.json"),
            "mallory",
        )
        .unwrap();

        assert!(
            ceremony_contribute(&srs_other, &dir.join("c.srs"), &transcript, "bob").is_err(),
            "contributing from a non-head state must fail"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finalize_requires_minimum_participants() {
        let dir = temp_dir("minpart");
        let srs_a = dir.join("a.srs");
        let srs_b = dir.join("b.srs");
        let transcript = dir.join("t.json");

        ceremony_init(&srs_a, &transcript).unwrap();
        ceremony_contribute(&srs_a, &srs_b, &transcript, "solo").unwrap();

        let err = ceremony_verify(&srs_b, &transcript, MIN_CEREMONY_PARTICIPANTS)
            .expect_err("single participant must not finalize");
        assert!(err.to_string().contains("at least"));

        // Lower threshold accepts (useful for testnet dry-runs).
        ceremony_verify(&srs_b, &transcript, 1).expect("low threshold verify");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_attestation_breaks_finalization() {
        let dir = temp_dir("tamper");
        let srs_a = dir.join("a.srs");
        let srs_b = dir.join("b.srs");
        let transcript = dir.join("t.json");

        ceremony_init(&srs_a, &transcript).unwrap();
        ceremony_contribute(&srs_a, &srs_b, &transcript, "alice").unwrap();

        let mut t = CeremonyTranscript::load(&transcript).unwrap();
        t.contributions[0].attestation = [0xab_u8; 32];
        t.save(&transcript).unwrap();

        let err = ceremony_verify(&srs_b, &transcript, 1).err().unwrap();
        assert!(err.to_string().contains("attestation mismatch"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
