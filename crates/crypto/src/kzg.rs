// C1: Development KZG SRS trapdoor (tau = 42) must never ship in release.
#[cfg(all(not(debug_assertions), feature = "dev-kzg-srs"))]
compile_error!("dev-kzg-srs feature must not be enabled in release builds");

use crate::hash::domain_hash;
use anyhow::{bail, Context, Result};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::sync::OnceLock;

/// Verkle branching factor: number of G1 powers in the SRS and slots per
/// KZG commitment vector. Public so ceremony tooling can pin the same size.
pub const BRANCHING_FACTOR: usize = 256;
const DOMAIN_KZG_COMMITMENT: &str = "SXIAUM_KZG_COMMITMENT";

/// Publicly known development trapdoor. Anyone who knows this scalar can forge
/// KZG/Verkle openings for the entire state tree.
///
/// This value is only permitted in-process when the `dev-kzg-srs` feature is
/// enabled (debug builds) or inside unit tests. It must never appear in a file
/// loaded under production / mainnet policy.
pub const DEV_TRAPDOOR_TAU: u64 = 42;

/// Human-readable marker used in error messages and CI greps.
pub const DEV_SRS_MARKER: &str = "dev_tau42";

/// Minimum byte size for a ceremony-style SRS file (256 G1 + 2 G2 compressed).
pub const MIN_PRODUCTION_SRS_BYTES: u64 = 1024;

pub struct SRS {
    pub g1_powers: Vec<G1Projective>,
    pub g2: G2Projective,
    pub g2_tau: G2Projective,
    /// Present only for the in-memory development SRS. Ceremony / file-loaded
    /// SRS always set this to `None` (toxic waste discarded).
    tau: Option<Fr>,
}

impl std::fmt::Debug for SRS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SRS")
            .field("g1_powers_len", &self.g1_powers.len())
            .field("has_trapdoor_in_memory", &self.tau.is_some())
            .field("is_dev_trapdoor", &self.is_dev_trapdoor())
            .finish()
    }
}

impl SRS {
    /// True when this SRS was built from the known development trapdoor.
    pub fn is_dev_trapdoor(&self) -> bool {
        if self.tau == Some(Fr::from(DEV_TRAPDOOR_TAU)) {
            return true;
        }
        matches_dev_trapdoor_powers(&self.g1_powers, self.g2, self.g2_tau)
    }

    /// Assemble an SRS from public curve elements only (no trapdoor).
    ///
    /// Used by the ceremony module to construct init/contribution states
    /// without ever holding toxic waste.
    pub fn from_public_parts(
        g1_powers: Vec<G1Projective>,
        g2: G2Projective,
        g2_tau: G2Projective,
    ) -> Self {
        Self {
            g1_powers,
            g2,
            g2_tau,
            tau: None,
        }
    }
}

/// Returns true when the process must use a ceremony SRS file (never tau=42).
///
/// Forced by any of:
/// - `SXIAUM_SRS_MODE=production`
/// - `SXIAUM_ENV=production`
/// - `SXIAUM_NETWORK=mainnet`
pub fn requires_production_srs() -> bool {
    let srs_mode = env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    let env_mode = env::var("SXIAUM_ENV").unwrap_or_default();
    let network = env::var("SXIAUM_NETWORK").unwrap_or_default();
    srs_mode.eq_ignore_ascii_case("production")
        || env_mode.eq_ignore_ascii_case("production")
        || network.eq_ignore_ascii_case("mainnet")
}

/// True if a genesis / config SRS hash is an unset ceremony placeholder.
pub fn is_placeholder_srs_hash(hash: &str) -> bool {
    let h = hash
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if h.is_empty() {
        return true;
    }
    let lower = h.to_ascii_lowercase();
    if lower.contains("placeholder") || lower == "replace" || lower.starts_with("replace_") {
        return true;
    }
    // All-zero digests are not a real ceremony pin.
    h.chars().all(|c| c == '0')
}

/// SHA-256 (hex, no 0x prefix) of an SRS file on disk.
pub fn srs_file_sha256_hex(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read SRS file for hashing: {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn matches_dev_trapdoor_powers(
    g1_powers: &[G1Projective],
    g2: G2Projective,
    g2_tau: G2Projective,
) -> bool {
    if g1_powers.len() < 3 {
        return false;
    }
    let g1 = G1Projective::generator();
    let tau = Fr::from(DEV_TRAPDOOR_TAU);
    let power1 = g1 * tau;
    let power2 = g1 * (tau * tau);
    // power-0 is always the generator for monic powers-of-tau; match 1 and 2
    // plus g2_tau to reduce accidental false positives on partial files.
    g1_powers[0] == g1 && g1_powers[1] == power1 && g1_powers[2] == power2 && g2_tau == g2 * tau
}

fn build_powers_of_tau(tau: Fr) -> SRS {
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let mut g1_powers = Vec::with_capacity(BRANCHING_FACTOR);
    let mut current_power = Fr::from(1u64);
    for _ in 0..BRANCHING_FACTOR {
        g1_powers.push(g1 * current_power);
        current_power *= tau;
    }
    SRS {
        g1_powers,
        g2,
        g2_tau: g2 * tau,
        tau: Some(tau),
    }
}

/// Build the development SRS from the publicly known trapdoor (tau = 42).
///
/// This function is always compiled in so that integration tests in downstream
/// crates (e.g. `sxiaum-node`) can exercise the KZG commitment path without
/// requiring the `dev-kzg-srs` feature flag.
///
/// **Security:** This function is only called from [`get_srs`] when
/// [`requires_production_srs`] returns `false` AND [`allows_dev_srs`] permits
/// the dev trapdoor (tests, debug builds, or explicit `SXIAUM_SRS_MODE=dev`).
/// Unconfigured release builds fail closed instead. The production path always
/// loads a ceremony SRS from file.
fn build_dev_srs() -> SRS {
    build_powers_of_tau(Fr::from(DEV_TRAPDOOR_TAU))
}

/// Build an SRS from a secret tau and **discard** the trapdoor (`tau = None`).
///
/// Suitable for:
/// - local integration tests of the production file path
/// - operator dry-runs before a real multi-party ceremony
///
/// **Not** a substitute for a multi-party Powers-of-Tau ceremony for mainnet:
/// a single-party generated file is still trusted-setup risk if the generator
/// retains tau. Mainnet must use a ceremony (or imported verified PoT) where
/// toxic waste is destroyed by participants.
pub fn generate_discarded_trapdoor_srs() -> Result<SRS> {
    use rand::rngs::OsRng;
    use zeroize::Zeroize;

    // Sample a non-dev field element from OS entropy.
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    let mut tau = Fr::from_le_bytes_mod_order(&bytes);
    bytes.zeroize();

    // Never accidentally produce the public dev trapdoor.
    if tau == Fr::from(DEV_TRAPDOOR_TAU) || tau.is_zero() {
        tau = Fr::from(DEV_TRAPDOOR_TAU.wrapping_add(1));
    }
    let mut srs = build_powers_of_tau(tau);
    // Discard toxic waste from the in-memory structure before return.
    srs.tau = None;
    // Best-effort: overwrite local tau (Fr may not implement Zeroize; reassign).
    tau = Fr::from(0u64);
    let _ = tau;
    if srs.is_dev_trapdoor() {
        bail!("internal error: generated SRS matched development trapdoor footprint");
    }
    Ok(srs)
}

/// Write an SRS to disk in the canonical length-prefixed compressed format.
///
/// Refuses to write any SRS that matches the development trapdoor footprint.
pub fn write_srs_to_file(srs: &SRS, path: &Path) -> Result<()> {
    if srs.is_dev_trapdoor() {
        bail!(
            "Refusing to save development SRS ({} / tau={}). \
             Ceremony or discarded-trapdoor SRS only.",
            DEV_SRS_MARKER,
            DEV_TRAPDOOR_TAU
        );
    }
    if srs.g1_powers.len() != BRANCHING_FACTOR {
        bail!(
            "SRS must contain exactly {} G1 powers, got {}",
            BRANCHING_FACTOR,
            srs.g1_powers.len()
        );
    }

    let mut f = File::create(path)
        .with_context(|| format!("failed to create SRS file: {}", path.display()))?;

    for g1 in &srs.g1_powers {
        let mut buf = Vec::new();
        g1.into_affine()
            .serialize_compressed(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to serialize g1: {:?}", e))?;
        let len = (buf.len() as u32).to_le_bytes();
        f.write_all(&len)?;
        f.write_all(&buf)?;
    }

    for g2 in [&srs.g2, &srs.g2_tau] {
        let mut buf = Vec::new();
        g2.into_affine()
            .serialize_compressed(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to serialize g2: {:?}", e))?;
        let len = (buf.len() as u32).to_le_bytes();
        f.write_all(&len)?;
        f.write_all(&buf)?;
    }

    Ok(())
}

/// SECURITY (C-15): explicit opt-in for the insecure development trapdoor SRS.
///
/// The dev SRS (tau = 42) may only be used when the operator asked for it:
/// - inside unit tests (`cfg!(test)`), or
/// - in debug builds (`cfg!(debug_assertions)`), or
/// - via an explicit `SXIAUM_SRS_MODE=dev|development` setting.
///
/// A **release** binary with no environment configuration must never silently
/// fall back to the publicly-known trapdoor; it fails closed instead.
pub fn allows_dev_srs() -> bool {
    if cfg!(test) || cfg!(debug_assertions) {
        return true;
    }
    let mode = env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    mode.eq_ignore_ascii_case("dev") || mode.eq_ignore_ascii_case("development")
}

pub fn get_srs() -> &'static SRS {
    static SRS_INSTANCE: OnceLock<SRS> = OnceLock::new();
    SRS_INSTANCE.get_or_init(|| {
        // Production / mainnet: ceremony file only. Never fall back to tau=42.
        if requires_production_srs() {
            let path = env::var("SXIAUM_KZG_SRS_PATH").unwrap_or_else(|_| {
                panic!(
                    "SXIAUM_KZG_SRS_PATH must be set when production/mainnet SRS policy is active \
                     (SXIAUM_SRS_MODE=production, SXIAUM_ENV=production, or SXIAUM_NETWORK=mainnet)"
                )
            });
            match load_production_srs_from_file(Path::new(&path)) {
                Ok(s) => s,
                Err(e) => panic!(
                    "failed to load production SRS from {}: {:#}",
                    path, e
                ),
            }
        } else if allows_dev_srs() {
            // ------------------------------------------------------------
            // DEVELOPMENT SRS (tau = 42) — explicit opt-in / test / debug only
            // ------------------------------------------------------------
            // Safe for devnet/testnet because no real value is at stake, and
            // only reachable when the operator explicitly opted in (or under
            // test/debug builds). Release builds with no configuration fail
            // closed below instead of silently using the known trapdoor.
            //
            // The `dev-kzg-srs` feature remains as an explicit CI assertion
            // hook (`cfg!(feature = ...)`).
            #[cfg(not(test))]
            tracing::warn!(
                "DEVELOPMENT SRS ({} / tau={}) is active — known trapdoor; state commitments \
                 are NOT sound. Set SXIAUM_SRS_MODE=production + SXIAUM_KZG_SRS_PATH before going live.",
                DEV_SRS_MARKER,
                DEV_TRAPDOOR_TAU
            );
            build_dev_srs()
        } else {
            // SECURITY (C-15): fail closed. An unconfigured release binary
            // must not run on the publicly-known dev trapdoor.
            panic!(
                "KZG SRS policy is fail-closed: no SRS configured. \
                 For production/mainnet set SXIAUM_SRS_MODE=production and SXIAUM_KZG_SRS_PATH \
                 to a ceremony-generated SRS. To explicitly accept the insecure development \
                 trapdoor (dev/testnet only) set SXIAUM_SRS_MODE=dev."
            )
        }
    })
}

// Read an SRS file written by `write_srs_to_file`. Format is a simple
// length-prefixed sequence of compressed affine points:
//   [u32 len][g1_affine_bytes] * BRANCHING_FACTOR, [u32 len][g2_bytes], [u32 len][g2_tau_bytes]
pub fn load_srs_from_file(path: &Path) -> Result<SRS> {
    let f =
        File::open(path).with_context(|| format!("failed to open SRS file: {}", path.display()))?;
    let mut rdr = BufReader::new(f);

    let mut g1_powers = Vec::with_capacity(BRANCHING_FACTOR);
    for i in 0..BRANCHING_FACTOR {
        let mut len_buf = [0u8; 4];
        rdr.read_exact(&mut len_buf)
            .with_context(|| format!("failed to read G1[{i}] length prefix"))?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 256 {
            bail!("invalid G1[{i}] length prefix: {len}");
        }
        let mut buf = vec![0u8; len];
        rdr.read_exact(&mut buf)
            .with_context(|| format!("failed to read G1[{i}] bytes"))?;
        let affine = G1Affine::deserialize_compressed(&buf[..])
            .map_err(|e| anyhow::anyhow!("failed to deserialize G1[{i}] affine: {:?}", e))?;
        g1_powers.push(affine.into_group());
    }

    let mut len_buf = [0u8; 4];
    rdr.read_exact(&mut len_buf)
        .context("failed to read g2 length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    rdr.read_exact(&mut buf)
        .context("failed to read g2 bytes")?;
    let g2_affine = ark_bls12_381::G2Affine::deserialize_compressed(&buf[..])
        .map_err(|e| anyhow::anyhow!("failed to deserialize G2 affine: {:?}", e))?;
    let g2 = g2_affine.into_group();

    let mut len_buf2 = [0u8; 4];
    rdr.read_exact(&mut len_buf2)
        .context("failed to read g2_tau length")?;
    let len2 = u32::from_le_bytes(len_buf2) as usize;
    let mut buf2 = vec![0u8; len2];
    rdr.read_exact(&mut buf2)
        .context("failed to read g2_tau bytes")?;
    let g2_tau_affine = ark_bls12_381::G2Affine::deserialize_compressed(&buf2[..])
        .map_err(|e| anyhow::anyhow!("failed to deserialize G2 tau affine: {:?}", e))?;
    let g2_tau = g2_tau_affine.into_group();

    let srs = SRS {
        g1_powers,
        g2,
        g2_tau,
        tau: None,
    };

    // C1: Never accept a file that matches the public development trapdoor.
    // Dev mode uses the in-memory path only; files are for ceremony / prod.
    if srs.is_dev_trapdoor() {
        bail!(
            "The SRS file at {} is the DEVELOPMENT SRS ({} / tau={}). \
             It has a publicly known trapdoor and MUST NOT be loaded. \
             Provide a ceremony-generated SRS file.",
            path.display(),
            DEV_SRS_MARKER,
            DEV_TRAPDOOR_TAU
        );
    }

    Ok(srs)
}

/// Load an SRS for production use: size sanity + dev-trapdoor rejection.
pub fn load_production_srs_from_file(path: &Path) -> Result<SRS> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot stat SRS file {}", path.display()))?;
    if meta.len() < MIN_PRODUCTION_SRS_BYTES {
        bail!(
            "SXIAUM_KZG_SRS_PATH={} is only {} bytes — too small for a real ceremony SRS \
             (expected at least {} bytes)",
            path.display(),
            meta.len(),
            MIN_PRODUCTION_SRS_BYTES
        );
    }
    // load_srs_from_file already rejects dev_tau42 footprint.
    load_srs_from_file(path)
}

/// Full production gate used by preflight: not-dev, non-placeholder pin, hash match.
pub fn assert_production_srs_file(path: &Path, expected_genesis_hash_hex: &str) -> Result<()> {
    if is_placeholder_srs_hash(expected_genesis_hash_hex) {
        bail!(
            "genesis kzg.srs_hash is a placeholder ({:?}). \
             Pin the SHA-256 of the ceremony SRS before production/mainnet.",
            expected_genesis_hash_hex
        );
    }

    // Reject before load so operators get a clear message.
    validate_srs_is_not_dev(path)?;
    let _srs = load_production_srs_from_file(path)?;

    let actual = srs_file_sha256_hex(path)?;
    let expected = expected_genesis_hash_hex
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase();
    if actual != expected {
        bail!(
            "SRS hash mismatch for {}. Genesis: {}, File: {}",
            path.display(),
            expected,
            actual
        );
    }
    Ok(())
}

/// Save the currently loaded global SRS to disk.
///
/// Refuses the development trapdoor SRS so operators cannot accidentally
/// distribute `dev_tau42` as a “production” artifact.
pub fn save_srs_to_file(path: &Path) -> Result<()> {
    let srs = get_srs();
    if srs.is_dev_trapdoor() {
        bail!(
            "Refusing to save development SRS ({} / tau={}) to file for distribution",
            DEV_SRS_MARKER,
            DEV_TRAPDOOR_TAU
        );
    }
    write_srs_to_file(srs, path)
}

/// Validate that an SRS file is not the development SRS built from tau = 42.
///
/// Checks G1 powers 0..=2 and g2_tau against the known trapdoor footprint.
/// Called by production preflight and by [`load_srs_from_file`].
pub fn validate_srs_is_not_dev(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot open SRS file for validation: {}", path.display()))?;
    if meta.len() < 32 {
        bail!(
            "SRS file {} is too small ({} bytes) to be a valid ceremony SRS",
            path.display(),
            meta.len()
        );
    }

    // Fast path: raw magic string some older tests / tooling used.
    // Bounded read (4 KiB) so a huge or adversarial file cannot force a
    // full in-memory scan just to reach the structural checks below.
    if let Ok(mut f) = File::open(path) {
        let mut prefix = vec![0u8; 4096];
        let mut filled = 0;
        while filled < prefix.len() {
            match f.read(&mut prefix[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => break,
            }
        }
        prefix.truncate(filled);
        if prefix.starts_with(DEV_SRS_MARKER.as_bytes())
            || prefix
                .windows(DEV_SRS_MARKER.len())
                .any(|w| w == DEV_SRS_MARKER.as_bytes())
        {
            bail!(
                "{} SRS detected at {}. Development trapdoor files must not be used in production.",
                DEV_SRS_MARKER,
                path.display()
            );
        }
    }

    // Structural check: parse enough points to detect tau=42 powers.
    let f = File::open(path)
        .with_context(|| format!("cannot open SRS file for validation: {}", path.display()))?;
    let mut rdr = BufReader::new(f);

    let mut g1_check: Vec<G1Projective> = Vec::with_capacity(3);
    for i in 0..3 {
        let mut len_buf = [0u8; 4];
        if rdr.read_exact(&mut len_buf).is_err() {
            bail!("SRS validation read error at G1[{i}] — file is truncated or not an SXIAUM SRS");
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > 256 {
            bail!("SRS validation: invalid G1[{i}] length {len}");
        }
        let mut buf = vec![0u8; len];
        rdr.read_exact(&mut buf)
            .with_context(|| format!("SRS validation read error (G1[{i}] bytes)"))?;
        let affine = G1Affine::deserialize_compressed(&buf[..]).map_err(|e| {
            anyhow::anyhow!("SRS validation: failed to deserialize G1[{i}]: {:?}", e)
        })?;
        g1_check.push(affine.into_group());
    }

    // Skip remaining G1 powers to reach G2.
    for i in 3..BRANCHING_FACTOR {
        let mut len_buf = [0u8; 4];
        rdr.read_exact(&mut len_buf)
            .with_context(|| format!("SRS validation skip G1[{i}] length"))?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        rdr.read_exact(&mut buf)
            .with_context(|| format!("SRS validation skip G1[{i}] bytes"))?;
    }

    let mut read_g2 = || -> Result<G2Projective> {
        let mut len_buf = [0u8; 4];
        rdr.read_exact(&mut len_buf)
            .context("SRS validation: g2 length")?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        rdr.read_exact(&mut buf)
            .context("SRS validation: g2 bytes")?;
        let affine = ark_bls12_381::G2Affine::deserialize_compressed(&buf[..])
            .map_err(|e| anyhow::anyhow!("SRS validation: deserialize g2: {:?}", e))?;
        Ok(affine.into_group())
    };
    let g2 = read_g2()?;
    let g2_tau = read_g2()?;

    // Pad to length expected by matcher (only first 3 powers matter).
    let mut powers = g1_check;
    while powers.len() < 3 {
        powers.push(G1Projective::generator());
    }

    if matches_dev_trapdoor_powers(&powers, g2, g2_tau) {
        bail!(
            "The SRS file at {} appears to be the DEVELOPMENT SRS ({} / tau={}). \
             It has a publicly known trapdoor and MUST NOT be used in production. \
             Provide a ceremony-generated SRS file.",
            path.display(),
            DEV_SRS_MARKER,
            DEV_TRAPDOOR_TAU
        );
    }

    Ok(())
}

static EMPTY_COMMITMENT: OnceLock<[u8; 32]> = OnceLock::new();
static EMPTY_PROOF: OnceLock<Vec<u8>> = OnceLock::new();

pub fn get_empty_commitment() -> [u8; 32] {
    *EMPTY_COMMITMENT.get_or_init(|| {
        let zero = G1Projective::zero().into_affine();
        let mut compressed = Vec::new();
        zero.serialize_compressed(&mut compressed).unwrap();

        let mut material = Vec::with_capacity(compressed.len() + (BRANCHING_FACTOR * 33));
        material.extend_from_slice(&compressed);
        material.resize(material.len() + BRANCHING_FACTOR, 0);
        commitment_digest(&material)
    })
}

pub fn get_empty_proof() -> Vec<u8> {
    EMPTY_PROOF
        .get_or_init(|| {
            let proof = G1Projective::zero();
            let mut compressed = Vec::new();
            proof
                .into_affine()
                .serialize_compressed(&mut compressed)
                .unwrap();
            compressed
        })
        .clone()
}

pub fn precompute_kzg_basis() {
    tracing::info!("Precomputing KZG / Lagrange commitment basis...");
    let start = std::time::Instant::now();

    let _ = get_empty_commitment();
    let _ = get_empty_proof();
    let _ = get_srs();

    tracing::info!("Initializing polynomial interpolation basis (Lagrange basis)...");
    let _ = lagrange_basis();

    tracing::info!("Initializing G1 Lagrange basis points (256 elements)...");
    for index in 0..BRANCHING_FACTOR {
        let _ = lagrange_commitment_basis_point(index).expect("failed to precompute basis point");
    }

    tracing::info!(
        "KZG / Lagrange basis precomputed successfully in {:?}",
        start.elapsed()
    );
}

pub fn compute_kzg_commitment(values: &[Option<[u8; 32]>]) -> [u8; 32] {
    let is_empty = values.iter().all(|val| val.is_none_or(|v| v == [0u8; 32]));
    if is_empty {
        return get_empty_commitment();
    }

    let compressed = compute_kzg_commitment_bytes(values)
        .expect("KZG commitment serialization should succeed for valid inputs");

    // Bind both the serialized KZG point and its evaluation vector into the
    // digest used by upper layers (state roots, node commitments). This avoids
    // digest collisions when different sparse vectors produce equal serialized
    // points under development/testing SRS edge cases.
    let mut material = Vec::with_capacity(compressed.len() + (BRANCHING_FACTOR * 33));
    material.extend_from_slice(&compressed);
    for index in 0..BRANCHING_FACTOR {
        match values.get(index).and_then(|value| *value) {
            Some(bytes) => {
                material.push(1);
                material.extend_from_slice(&bytes);
            }
            None => material.push(0),
        }
    }

    commitment_digest(&material)
}

pub fn commitment_digest(compressed_commitment: &[u8]) -> [u8; 32] {
    domain_hash(DOMAIN_KZG_COMMITMENT, compressed_commitment)
}

pub fn compute_kzg_commitment_bytes(values: &[Option<[u8; 32]>]) -> Result<Vec<u8>> {
    let commitment = compute_kzg_commitment_point(values)?;
    let mut compressed = Vec::new();
    commitment
        .into_affine()
        .serialize_compressed(&mut compressed)
        .map_err(|e| anyhow::anyhow!("failed to serialize KZG commitment: {:?}", e))?;
    Ok(compressed)
}

pub fn open_kzg(values: &[Option<[u8; 32]>], index: usize) -> Result<Vec<u8>> {
    if index >= BRANCHING_FACTOR {
        bail!("KZG opening index out of bounds");
    }

    let is_empty = values.iter().all(|val| val.is_none_or(|v| v == [0u8; 32]));
    if is_empty {
        return Ok(get_empty_proof());
    }

    let z = Fr::from(index as u64);
    let y = field_value(values.get(index).and_then(|value| *value));
    let coefficients = coefficients(values);
    let quotient = quotient_coefficients(&coefficients, z, y);
    let proof = commit_coefficients(&quotient)?;

    let mut compressed = Vec::new();
    proof
        .into_affine()
        .serialize_compressed(&mut compressed)
        .map_err(|e| anyhow::anyhow!("failed to serialize KZG proof: {:?}", e))?;
    Ok(compressed)
}

pub fn verify_kzg_opening(
    commitment_bytes: &[u8],
    index: usize,
    value: Option<[u8; 32]>,
    proof_bytes: &[u8],
) -> Result<bool> {
    if index >= BRANCHING_FACTOR {
        bail!("KZG opening index out of bounds");
    }

    let commitment = deserialize_g1(commitment_bytes)?;
    let proof = deserialize_g1(proof_bytes)?;
    let z = Fr::from(index as u64);
    let y = field_value(value);

    let lhs_g1 = commitment.into_group() - (G1Projective::generator() * y);
    let rhs_g2 = get_srs().g2_tau - (get_srs().g2 * z);

    Ok(
        Bls12_381::pairing(lhs_g1.into_affine(), get_srs().g2.into_affine())
            == Bls12_381::pairing(proof, rhs_g2.into_affine()),
    )
}

/// Verify a batch of KZG openings all evaluated at the SAME index `z`.
///
/// Reduces $k$ individual pairing checks to a single BLS12-381 pairing check:
/// $$e\left(\pi_{\text{agg}}, [\tau]_2 - [z]_2\right) = e\left(C_{\text{agg}} - [y_{\text{agg}}]_1, G_2\right)$$
/// where:
/// $$C_{\text{agg}} = \sum_{j=0}^{k-1} r^j C_j, \quad y_{\text{agg}} = \sum_{j=0}^{k-1} r^j y_j, \quad \pi_{\text{agg}} = \sum_{j=0}^{k-1} r^j \pi_j$$
/// and $r \in \mathbb{F}_q$ is a Fiat-Shamir challenge derived over the input transcript.
pub fn verify_batched_kzg_openings_single_point(
    commitments_bytes: &[Vec<u8>],
    index: usize,
    values: &[Option<[u8; 32]>],
    proofs_bytes: &[Vec<u8>],
) -> Result<bool> {
    let k = commitments_bytes.len();
    if k == 0 {
        return Ok(true);
    }
    if values.len() != k || proofs_bytes.len() != k {
        bail!(
            "mismatched batch input lengths: {} commitments, {} values, {} proofs",
            k,
            values.len(),
            proofs_bytes.len()
        );
    }
    if index >= BRANCHING_FACTOR {
        bail!("KZG opening index out of bounds");
    }

    if k == 1 {
        return verify_kzg_opening(&commitments_bytes[0], index, values[0], &proofs_bytes[0]);
    }

    let r = compute_batching_challenge(commitments_bytes, &[index], values, proofs_bytes);
    let mut current_r = Fr::from(1u64);

    let mut c_agg = G1Projective::zero();
    let mut y_agg = Fr::zero();
    let mut pi_agg = G1Projective::zero();

    for j in 0..k {
        let commitment = deserialize_g1(&commitments_bytes[j])?;
        let proof = deserialize_g1(&proofs_bytes[j])?;
        let y = field_value(values[j]);

        c_agg += commitment * current_r;
        y_agg += y * current_r;
        pi_agg += proof * current_r;

        current_r *= r;
    }

    let z = Fr::from(index as u64);
    let lhs_g1 = c_agg - (G1Projective::generator() * y_agg);
    let rhs_g2 = get_srs().g2_tau - (get_srs().g2 * z);

    Ok(
        Bls12_381::pairing(lhs_g1.into_affine(), get_srs().g2.into_affine())
            == Bls12_381::pairing(pi_agg.into_affine(), rhs_g2.into_affine()),
    )
}

/// Verify a batch of KZG openings evaluated at ARBITRARY distinct indices $z_0, \dots, z_{k-1}$.
///
/// Reduces $k$ individual opening proofs into a single 2-pairing check:
/// $$e\left(\sum_{j=0}^{k-1} r^j \pi_j, [\tau]_2\right) = e\left(\sum_{j=0}^{k-1} r^j \big(\pi_j \cdot z_j + C_j - [y_j]_1\big), G_2\right)$$
/// where $r \in \mathbb{F}_q$ is a Fiat-Shamir challenge derived over the transcript.
pub fn verify_batched_kzg_openings_multi_point(
    commitments_bytes: &[Vec<u8>],
    indices: &[usize],
    values: &[Option<[u8; 32]>],
    proofs_bytes: &[Vec<u8>],
) -> Result<bool> {
    let k = commitments_bytes.len();
    if k == 0 {
        return Ok(true);
    }
    if indices.len() != k || values.len() != k || proofs_bytes.len() != k {
        bail!(
            "mismatched batch input lengths: {} commitments, {} indices, {} values, {} proofs",
            k,
            indices.len(),
            values.len(),
            proofs_bytes.len()
        );
    }

    for &idx in indices {
        if idx >= BRANCHING_FACTOR {
            bail!("KZG opening index out of bounds: {}", idx);
        }
    }

    if k == 1 {
        return verify_kzg_opening(
            &commitments_bytes[0],
            indices[0],
            values[0],
            &proofs_bytes[0],
        );
    }

    let r = compute_batching_challenge(commitments_bytes, indices, values, proofs_bytes);
    let mut current_r = Fr::from(1u64);

    let mut p1 = G1Projective::zero();
    let mut p2 = G1Projective::zero();
    let g1_gen = G1Projective::generator();

    for j in 0..k {
        let commitment = deserialize_g1(&commitments_bytes[j])?;
        let proof = deserialize_g1(&proofs_bytes[j])?;
        let z = Fr::from(indices[j] as u64);
        let y = field_value(values[j]);

        p1 += proof * current_r;

        let term = (proof * z) + commitment - (g1_gen * y);
        p2 += term * current_r;

        current_r *= r;
    }

    Ok(
        Bls12_381::pairing(p1.into_affine(), get_srs().g2_tau.into_affine())
            == Bls12_381::pairing(p2.into_affine(), get_srs().g2.into_affine()),
    )
}

fn compute_batching_challenge(
    commitments_bytes: &[Vec<u8>],
    indices: &[usize],
    values: &[Option<[u8; 32]>],
    proofs_bytes: &[Vec<u8>],
) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(b"SXIAUM_KZG_BATCH_CHALLENGE_V1");
    for c in commitments_bytes {
        hasher.update((c.len() as u32).to_le_bytes());
        hasher.update(c);
    }
    for idx in indices {
        hasher.update((*idx as u64).to_le_bytes());
    }
    for v in values {
        match v {
            Some(val) => {
                hasher.update([1u8]);
                hasher.update(val);
            }
            None => {
                hasher.update([0u8; 33]);
            }
        }
    }
    for p in proofs_bytes {
        hasher.update((p.len() as u32).to_le_bytes());
        hasher.update(p);
    }
    let digest = hasher.finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

fn compute_kzg_commitment_point(values: &[Option<[u8; 32]>]) -> Result<G1Projective> {
    let mut commitment = G1Projective::zero();
    for index in 0..BRANCHING_FACTOR {
        let value = field_value(values.get(index).and_then(|value| *value));
        if !value.is_zero() {
            commitment += lagrange_commitment_basis_point(index)? * value;
        }
    }
    Ok(commitment)
}

fn commit_coefficients(coefficients: &[Fr]) -> Result<G1Projective> {
    let srs = get_srs();
    let mut commitment = G1Projective::zero();

    for (i, coeff) in coefficients.iter().enumerate() {
        if i >= srs.g1_powers.len() {
            break;
        }
        commitment += srs.g1_powers[i] * coeff;
    }

    Ok(commitment)
}

fn coefficients(values: &[Option<[u8; 32]>]) -> Vec<Fr> {
    let evaluations: Vec<Fr> = (0..BRANCHING_FACTOR)
        .map(|index| field_value(values.get(index).and_then(|value| *value)))
        .collect();
    interpolate_evaluations(&evaluations)
}

fn interpolate_evaluations(evaluations: &[Fr]) -> Vec<Fr> {
    let basis = lagrange_basis();
    let mut polynomial = vec![Fr::zero(); evaluations.len()];

    for (i, y) in evaluations.iter().enumerate() {
        if y.is_zero() {
            continue;
        }

        for (degree, coeff) in basis[i].iter().enumerate() {
            polynomial[degree] += *coeff * y;
        }
    }

    polynomial
}

fn lagrange_basis() -> &'static Vec<Vec<Fr>> {
    static BASIS: OnceLock<Vec<Vec<Fr>>> = OnceLock::new();
    BASIS.get_or_init(|| {
        let mut all = Vec::with_capacity(BRANCHING_FACTOR);

        for i in 0..BRANCHING_FACTOR {
            let xi = Fr::from(i as u64);
            let mut basis = vec![Fr::from(1u64)];
            let mut denominator = Fr::from(1u64);

            for j in 0..BRANCHING_FACTOR {
                if i == j {
                    continue;
                }

                let xj = Fr::from(j as u64);
                let mut next = vec![Fr::zero(); basis.len() + 1];
                for (degree, coeff) in basis.iter().enumerate() {
                    next[degree] -= *coeff * xj;
                    next[degree + 1] += coeff;
                }
                basis = next;
                denominator *= xi - xj;
            }

            let denominator_inverse = denominator
                .inverse()
                .expect("distinct interpolation domain points have non-zero denominator");
            for coeff in &mut basis {
                *coeff *= denominator_inverse;
            }
            all.push(basis);
        }

        all
    })
}

fn lagrange_commitment_basis_point(index: usize) -> Result<G1Projective> {
    if index >= BRANCHING_FACTOR {
        bail!("Lagrange commitment basis index out of bounds");
    }

    static BASIS: OnceLock<Vec<OnceLock<G1Projective>>> = OnceLock::new();
    let basis = BASIS.get_or_init(|| {
        (0..BRANCHING_FACTOR)
            .map(|_| OnceLock::new())
            .collect::<Vec<_>>()
    });

    Ok(*basis[index].get_or_init(|| {
        compute_lagrange_commitment_basis_point(index)
            .expect("Lagrange commitment basis point should build")
    }))
}

fn compute_lagrange_commitment_basis_point(index: usize) -> Result<G1Projective> {
    if let Some(tau) = get_srs().tau {
        return Ok(G1Projective::generator() * lagrange_evaluation(index, tau)?);
    }

    let coefficients = lagrange_basis_coefficients(index)?;
    commit_coefficients(&coefficients)
}

fn lagrange_evaluation(index: usize, point: Fr) -> Result<Fr> {
    if index >= BRANCHING_FACTOR {
        bail!("Lagrange evaluation index out of bounds");
    }

    let xi = Fr::from(index as u64);
    let mut numerator = Fr::from(1u64);
    let mut denominator = Fr::from(1u64);

    for j in 0..BRANCHING_FACTOR {
        if j == index {
            continue;
        }

        let xj = Fr::from(j as u64);
        numerator *= point - xj;
        denominator *= xi - xj;
    }

    Ok(numerator
        * denominator
            .inverse()
            .expect("distinct interpolation domain points have non-zero denominator"))
}

fn lagrange_basis_coefficients(index: usize) -> Result<Vec<Fr>> {
    if index >= BRANCHING_FACTOR {
        bail!("Lagrange basis index out of bounds");
    }

    let xi = Fr::from(index as u64);
    let mut basis = divide_by_linear(interpolation_domain_vanishing_polynomial(), xi);
    let denominator = evaluate_polynomial(&basis, xi);
    let denominator_inverse = denominator
        .inverse()
        .expect("distinct interpolation domain points have non-zero denominator");

    for coeff in &mut basis {
        *coeff *= denominator_inverse;
    }

    Ok(basis)
}

fn interpolation_domain_vanishing_polynomial() -> &'static Vec<Fr> {
    static VANISHING: OnceLock<Vec<Fr>> = OnceLock::new();
    VANISHING.get_or_init(|| {
        let mut polynomial = vec![Fr::from(1u64)];

        for i in 0..BRANCHING_FACTOR {
            let xi = Fr::from(i as u64);
            let mut next = vec![Fr::zero(); polynomial.len() + 1];
            for (degree, coeff) in polynomial.iter().enumerate() {
                next[degree] -= *coeff * xi;
                next[degree + 1] += coeff;
            }
            polynomial = next;
        }

        polynomial
    })
}

fn divide_by_linear(coefficients: &[Fr], root: Fr) -> Vec<Fr> {
    let mut quotient = vec![Fr::zero(); coefficients.len().saturating_sub(1)];
    let mut carry = *coefficients.last().unwrap_or(&Fr::zero());
    for index in (0..quotient.len()).rev() {
        quotient[index] = carry;
        carry = coefficients[index] + (carry * root);
    }
    quotient
}

fn evaluate_polynomial(coefficients: &[Fr], x: Fr) -> Fr {
    coefficients
        .iter()
        .rev()
        .fold(Fr::zero(), |acc, coeff| (acc * x) + coeff)
}

fn quotient_coefficients(coefficients: &[Fr], z: Fr, y: Fr) -> Vec<Fr> {
    let mut adjusted = coefficients.to_vec();
    if let Some(constant) = adjusted.first_mut() {
        *constant -= y;
    }

    let mut quotient = vec![Fr::zero(); adjusted.len().saturating_sub(1)];
    let mut carry = *adjusted.last().unwrap_or(&Fr::zero());
    for index in (1..adjusted.len()).rev() {
        quotient[index - 1] = carry;
        carry = adjusted[index - 1] + (carry * z);
    }
    quotient
}

#[cfg(test)]
fn evaluate(coefficients: &[Fr], x: Fr) -> Fr {
    coefficients
        .iter()
        .rev()
        .fold(Fr::zero(), |acc, coeff| (acc * x) + coeff)
}

fn field_value(value: Option<[u8; 32]>) -> Fr {
    Fr::from_be_bytes_mod_order(&value.unwrap_or([0u8; 32]))
}

fn deserialize_g1(bytes: &[u8]) -> Result<G1Affine> {
    let point = G1Affine::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("failed to deserialize KZG point: {:?}", e))?;
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn value(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn write_raw_dev_srs_for_test(path: &Path) {
        // Bypass write_srs_to_file (which refuses dev) to simulate a leaked file.
        let srs = build_dev_srs();
        let mut f = File::create(path).unwrap();
        for g1 in &srs.g1_powers {
            let mut buf = Vec::new();
            g1.into_affine().serialize_compressed(&mut buf).unwrap();
            let len = (buf.len() as u32).to_le_bytes();
            f.write_all(&len).unwrap();
            f.write_all(&buf).unwrap();
        }
        for g2 in [&srs.g2, &srs.g2_tau] {
            let mut buf = Vec::new();
            g2.into_affine().serialize_compressed(&mut buf).unwrap();
            let len = (buf.len() as u32).to_le_bytes();
            f.write_all(&len).unwrap();
            f.write_all(&buf).unwrap();
        }
    }

    #[test]
    fn placeholder_srs_hash_detection() {
        assert!(is_placeholder_srs_hash(""));
        assert!(is_placeholder_srs_hash("0x"));
        assert!(is_placeholder_srs_hash(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_placeholder_srs_hash("0xplaceholder"));
        assert!(is_placeholder_srs_hash("REPLACE_ME"));
        assert!(!is_placeholder_srs_hash(
            "fbb3cfc234a66a15aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn generate_discarded_trapdoor_srs_is_not_dev() {
        let srs = generate_discarded_trapdoor_srs().expect("generate");
        assert!(!srs.is_dev_trapdoor());
        assert!(srs.tau.is_none());
    }

    #[test]
    fn write_and_load_ceremony_style_srs_roundtrip() {
        let dir = std::env::temp_dir().join(format!("sxiaum_srs_rt_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ceremony_style.srs");

        let srs = generate_discarded_trapdoor_srs().unwrap();
        write_srs_to_file(&srs, &path).unwrap();

        validate_srs_is_not_dev(&path).expect("must accept non-dev");
        let loaded = load_srs_from_file(&path).unwrap();
        assert!(!loaded.is_dev_trapdoor());
        assert_eq!(loaded.g1_powers.len(), BRANCHING_FACTOR);

        let hash = srs_file_sha256_hex(&path).unwrap();
        assert_production_srs_file(&path, &hash).unwrap();
        assert!(assert_production_srs_file(&path, "0".repeat(64).as_str()).is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn validate_and_load_reject_dev_tau42_file() {
        let dir = std::env::temp_dir().join(format!("sxiaum_srs_dev_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("dev_tau42.srs");
        write_raw_dev_srs_for_test(&path);

        let v = validate_srs_is_not_dev(&path);
        assert!(v.is_err(), "expected reject");
        let msg = v.unwrap_err().to_string();
        assert!(
            msg.contains(DEV_SRS_MARKER) || msg.contains("DEVELOPMENT SRS"),
            "msg={msg}"
        );

        let load = load_srs_from_file(&path);
        assert!(load.is_err(), "dev SRS file must not load");
        let load_msg = match load {
            Err(e) => e.to_string(),
            Ok(_) => unreachable!(),
        };
        assert!(
            load_msg.contains(DEV_SRS_MARKER) || load_msg.contains("DEVELOPMENT"),
            "msg={load_msg}"
        );

        // Magic-string form used by older tooling / tests
        let magic_path = dir.join("magic.srs");
        let mut fake = DEV_SRS_MARKER.as_bytes().to_vec();
        fake.resize(128, 0);
        std::fs::write(&magic_path, &fake).unwrap();
        let magic = validate_srs_is_not_dev(&magic_path);
        assert!(magic.is_err());
        assert!(magic.unwrap_err().to_string().contains(DEV_SRS_MARKER));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_srs_refuses_dev_trapdoor() {
        let srs = build_dev_srs();
        let path = std::env::temp_dir().join("should_fail_dev.srs");
        let res = write_srs_to_file(&srs, &path);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Refusing to save"));
    }

    #[test]
    fn kzg_opening_verifies_for_sparse_vector_slots() {
        let mut values = vec![None; BRANCHING_FACTOR];
        values[1] = Some(value(7));
        values[3] = Some(value(9));
        assert_eq!(
            super::evaluate(&super::lagrange_basis()[3], ark_bls12_381::Fr::from(3u64)),
            ark_bls12_381::Fr::from(1u64)
        );
        let coefficients = super::coefficients(&values);

        assert_eq!(
            super::evaluate(&coefficients, ark_bls12_381::Fr::from(3u64)),
            super::field_value(Some(value(9)))
        );

        let commitment =
            compute_kzg_commitment_bytes(&values).expect("commitment should serialize");
        let proof = open_kzg(&values, 3).expect("opening should serialize");

        assert!(verify_kzg_opening(&commitment, 3, Some(value(9)), &proof)
            .expect("opening verification should run"));
        assert!(!verify_kzg_opening(&commitment, 3, Some(value(8)), &proof)
            .expect("mismatched opening verification should run"));
    }

    #[test]
    fn save_srs_to_file_rejects_dev_srs() {
        let path = std::env::temp_dir().join("should_fail.srs");
        let res = super::save_srs_to_file(&path);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("Refusing to save development SRS"));
    }

    #[test]
    fn batched_kzg_opening_single_point_verifies() {
        // Build two distinct polynomials with evaluations at index 5
        let mut values1 = vec![None; BRANCHING_FACTOR];
        values1[5] = Some(value(42));
        values1[10] = Some(value(99));

        let mut values2 = vec![None; BRANCHING_FACTOR];
        values2[5] = Some(value(77));
        values2[20] = Some(value(11));

        let c1 = compute_kzg_commitment_bytes(&values1).unwrap();
        let c2 = compute_kzg_commitment_bytes(&values2).unwrap();

        let pi1 = open_kzg(&values1, 5).unwrap();
        let pi2 = open_kzg(&values2, 5).unwrap();

        let commitments = vec![c1, c2];
        let vals = vec![Some(value(42)), Some(value(77))];
        let proofs = vec![pi1, pi2];

        // Valid batch check
        assert!(
            verify_batched_kzg_openings_single_point(&commitments, 5, &vals, &proofs).unwrap()
        );

        // Corrupted value check
        let bad_vals = vec![Some(value(43)), Some(value(77))];
        assert!(
            !verify_batched_kzg_openings_single_point(&commitments, 5, &bad_vals, &proofs).unwrap()
        );

        // Wrong index check
        assert!(
            !verify_batched_kzg_openings_single_point(&commitments, 6, &vals, &proofs).unwrap()
        );
    }

    #[test]
    fn batched_kzg_opening_multi_point_verifies() {
        let mut values1 = vec![None; BRANCHING_FACTOR];
        values1[3] = Some(value(12));
        values1[7] = Some(value(34));

        let mut values2 = vec![None; BRANCHING_FACTOR];
        values2[11] = Some(value(56));
        values2[15] = Some(value(78));

        let mut values3 = vec![None; BRANCHING_FACTOR];
        values3[200] = Some(value(90));

        let c1 = compute_kzg_commitment_bytes(&values1).unwrap();
        let c2 = compute_kzg_commitment_bytes(&values2).unwrap();
        let c3 = compute_kzg_commitment_bytes(&values3).unwrap();

        let pi1 = open_kzg(&values1, 3).unwrap();
        let pi2 = open_kzg(&values2, 11).unwrap();
        let pi3 = open_kzg(&values3, 200).unwrap();

        let commitments = vec![c1, c2, c3];
        let indices = vec![3, 11, 200];
        let vals = vec![Some(value(12)), Some(value(56)), Some(value(90))];
        let proofs = vec![pi1, pi2, pi3];

        // Valid multi-point batch
        assert!(
            verify_batched_kzg_openings_multi_point(&commitments, &indices, &vals, &proofs)
                .unwrap()
        );

        // Tampered value in position 2
        let mut tampered_vals = vals.clone();
        tampered_vals[1] = Some(value(57));
        assert!(
            !verify_batched_kzg_openings_multi_point(
                &commitments,
                &indices,
                &tampered_vals,
                &proofs
            )
            .unwrap()
        );

        // Tampered index
        let mut tampered_indices = indices.clone();
        tampered_indices[0] = 4;
        assert!(
            !verify_batched_kzg_openings_multi_point(
                &commitments,
                &tampered_indices,
                &vals,
                &proofs
            )
            .unwrap()
        );
    }
}
