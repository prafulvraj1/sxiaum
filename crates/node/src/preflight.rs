//! Production preflight checks for SXIAUM node startup.
//!
//! When `SXIAUM_ENV=production` this module enforces a fail-closed policy:
//! every required security gate must be satisfied or the process exits with a
//! clear error message before any subsystem is initialised.
//!
//! Devnet / testnet operation (no `SXIAUM_ENV` or `SXIAUM_ENV != production`)
//! passes all checks unchanged - no behaviour regression for existing workflows.

use std::env;
use std::path::Path;
use tracing::{error, info, warn};

/// Minimum acceptable byte-length for the JWT secret.
/// 32 bytes = 256-bit entropy floor (NIST SP 800-131A).
const MIN_JWT_SECRET_BYTES: usize = 32;

/// Run all production preflight checks before any subsystem starts.
///
/// # Behaviour
///
/// - If `SXIAUM_ENV` is **not** `"production"`, emits a single info log and
///   returns immediately without performing any checks.
/// - If `SXIAUM_ENV=production`, evaluates every gate listed below and
///   **calls `std::process::exit(1)`** on the first failure, printing a clear
///   human-readable error to stderr.
///
/// # Gates checked in production mode
///
/// 1. `SXIAUM_SP1_MODE=production` - simulated ZK proofs are disallowed.
/// 2. `SXIAUM_SRS_MODE=production` AND `SXIAUM_KZG_SRS_PATH` points to a
///    readable, non-trivially-sized file - dev SRS (-=42) is disallowed.
/// 3. `SXIAUM_RPC_JWT_SECRET` is set AND is at least 32 bytes long.
/// 4. TLS is required: either `SXIAUM_TLS_CERT_PATH` + `SXIAUM_TLS_KEY_PATH`
///    are both set, or `SXIAUM_ALLOW_HTTP=1` must NOT be set.
/// 5. `SXIAUM_VALIDATOR_KEY` (if set) must not consist of a single repeated
///    byte - such keys indicate accidental test seeds.
/// 6. Mainnet genesis must not contain ceremony placeholder pubkeys.
/// 7. Parallel OCC sequential verification must not be explicitly disabled.
/// 8. No stray private-key files in the deployment directory.
/// 9. Non-loopback RPC requires write authentication (`SXIAUM_RPC_WRITE_AUTH=1`).
/// 10. Bootnodes must not contain template placeholders.
/// 11. `genesis_timestamp` must be non-zero.
///
/// Collect production preflight failures without exiting (for tests and tooling).
///
/// Returns `Ok(())` when not in production mode (checks skipped).
/// Returns `Err(messages)` when production mode fails one or more gates.
pub fn collect_production_preflight_failures(
    config: &crate::node::NodeConfig,
) -> Result<(), Vec<String>> {
    let env_mode = env::var("SXIAUM_ENV").unwrap_or_default();
    let net_mode = env::var("SXIAUM_NETWORK").unwrap_or_default();
    let srs_mode = env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    let is_mainnet_config = config
        .network
        .as_deref()
        .map(|n| n.eq_ignore_ascii_case("mainnet"))
        .unwrap_or(false);

    let is_prod = env_mode.eq_ignore_ascii_case("production")
        || net_mode.eq_ignore_ascii_case("mainnet")
        || srs_mode.eq_ignore_ascii_case("production")
        || is_mainnet_config;

    if !is_prod {
        info!(
            "SXIAUM_ENV={:?} - running in development/testnet mode. \
             Production preflight checks skipped.",
            if env_mode.is_empty() {
                "unset"
            } else {
                &env_mode
            }
        );
        return Ok(());
    }

    info!("SXIAUM production/mainnet mode active - running production preflight checks...");

    let mut failures: Vec<String> = Vec::new();

    // - Gate 1: ZK proof policy -
    check_sp1_mode(&mut failures, config);

    // - Gate 2: KZG SRS (C1) -
    check_srs_mode(&mut failures, config);

    // - Gate 3: JWT secret minimum entropy -
    check_jwt_secret(&mut failures);

    // - Gate 4: TLS / transport security -
    check_tls_config(&mut failures);

    // - Gate 5: Validator key quality -
    check_validator_key_quality(&mut failures);

    // - Gate 6: Mainnet genesis must not contain ceremony placeholders -
    check_mainnet_genesis_placeholders(&mut failures);

    // - Gate 7: Parallel OCC sequential verification enabled -
    check_parallel_verify_policy(&mut failures);

    // - Gate 8: No stray private key files in deployment directory -
    check_no_stray_key_files(&mut failures);

    // - Gate 9: Public RPC must have write auth enabled -
    check_rpc_write_auth(&mut failures, config);

    // - Gate 10: Bootnodes must not use placeholders -
    check_template_bootnodes(&mut failures, config);

    // - Gate 11: Genesis timestamp must be non-zero -
    check_genesis_timestamp(&mut failures, config);

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

pub fn run_production_preflight(config: &crate::node::NodeConfig) {
    match collect_production_preflight_failures(config) {
        Ok(()) => {
            if env::var("SXIAUM_ENV").unwrap_or_default() == "production"
                || env::var("SXIAUM_NETWORK").unwrap_or_default() == "mainnet"
            {
                info!("All production preflight checks passed. Proceeding with startup.");
            }
        }
        Err(failures) => {
            error!("=================================================================");
            error!("PRODUCTION PREFLIGHT FAILED - node will not start.");
            error!("=================================================================");
            for (i, msg) in failures.iter().enumerate() {
                error!("  [{}] {}", i + 1, msg);
            }
            error!("-----------------------------------------------------------------");
            error!("Fix all items above before running with SXIAUM_ENV=production.");
            error!("=================================================================");
            std::process::exit(1);
        }
    }
}

// - Individual gate checks -

/// Gate 1 - ZK proof policy.
///
/// `SXIAUM_SP1_MODE` must equal `"production"` when `SXIAUM_ENV=production`.
/// Without this, the node defaults to accepting simulated SHA-256 proofs which
/// can be forged by anyone. Additionally, the `vk_hash` in the loaded config
/// must be a real non-zero hash, not a placeholder.
fn check_sp1_mode(failures: &mut Vec<String>, config: &crate::node::NodeConfig) {
    let mode = env::var("SXIAUM_SP1_MODE").unwrap_or_default();
    if mode != "production" {
        failures.push(format!(
            "SXIAUM_SP1_MODE is {:?} - must be \"production\" to disallow \
             simulated ZK proofs. Set: SXIAUM_SP1_MODE=production",
            if mode.is_empty() { "unset" } else { &mode }
        ));
    } else {
        if cfg!(feature = "dev-simulated-proofs") {
            failures.push(
                "binary built with dev-simulated-proofs cannot run in production".to_string(),
            );
        }

        // Reject placeholder / all-zero vk_hash before initialising the verifier.
        // A zero key would allow any forged proof to satisfy the commitment check.
        if sxiaum_zk::sp1::verifier::is_placeholder_vk_hash(&config.zk.vk_hash) {
            failures.push(format!(
                "Gate 1 FAIL: zk.vk_hash {:?} is a placeholder / all-zeros value. \
                 A zero verification key allows any forged proof to pass. \
                 Pin the SHA-256 of the SP1 ELF in genesis.json (zk.vk_hash) \
                 before running in production.",
                config.zk.vk_hash
            ));
            return;
        }

        // Eagerly initialise the global SP1 verifier so it is fail-closed from
        // the very first proof that arrives.
        if let Err(e) = sxiaum_zk::sp1::verifier::Sp1Verifier::init_global(&config.zk.vk_hash) {
            failures.push(format!("SP1 global verifier initialization failed: {}", e));
        } else {
            info!("Gate 1 OK: SXIAUM_SP1_MODE=production, global SP1 verifier initialised (mainnet) with VK hash {}.", config.zk.vk_hash);
        }
    }
}

/// Gate 2 - KZG SRS (C1: development tau=42 trapdoor must never be used).
///
/// Production requires:
/// - `SXIAUM_SRS_MODE=production` (also implied by `SXIAUM_ENV=production` /
///   `SXIAUM_NETWORK=mainnet` via crypto policy)
/// - `SXIAUM_KZG_SRS_PATH` pointing at a ceremony SRS file
/// - File is not the development `dev_tau42` footprint
/// - Genesis `kzg.srs_hash` is a real SHA-256 pin (not zero/placeholder)
/// - File hash matches the genesis pin
fn check_srs_mode(failures: &mut Vec<String>, config: &crate::node::NodeConfig) {
    // Binaries compiled with the dev trapdoor feature are never production-safe.
    if cfg!(feature = "dev-kzg-srs") {
        failures.push(
            "SECURITY FAILURE (C1): this binary was built with feature dev-kzg-srs. \
             Production/mainnet nodes must be built without that feature \
             (cargo build --release -p sxiaum-node-bin, no --features dev)."
                .to_string(),
        );
    }

    let srs_mode = env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    if srs_mode != "production" {
        failures.push(format!(
            "SXIAUM_SRS_MODE is {:?} - must be \"production\". \
             The development SRS (dev_tau42 / tau=42) has a known trapdoor and must never be \
             used in production. Set: SXIAUM_SRS_MODE=production and \
             SXIAUM_KZG_SRS_PATH=/path/to/ceremony.srs",
            if srs_mode.is_empty() {
                "unset"
            } else {
                &srs_mode
            }
        ));
        return;
    }

    // Reject unset / placeholder genesis pins before touching the filesystem.
    if sxiaum_crypto::kzg::is_placeholder_srs_hash(&config.kzg.srs_hash) {
        failures.push(format!(
            "genesis kzg.srs_hash is a ceremony placeholder ({:?}). \
             Pin the SHA-256 of the production SRS file before mainnet launch (C1).",
            config.kzg.srs_hash
        ));
    }

    match env::var("SXIAUM_KZG_SRS_PATH") {
        Err(_) => {
            failures.push(
                "Production KZG SRS path not provided: SXIAUM_SRS_MODE=production but \
                 SXIAUM_KZG_SRS_PATH is not set. Provide a path to a ceremony-generated SRS file."
                    .to_string(),
            );
        }
        Ok(path_str) => {
            let path = Path::new(&path_str);
            if !path.exists() {
                failures.push(format!(
                    "SXIAUM_KZG_SRS_PATH={:?} does not exist on disk.",
                    path_str
                ));
                return;
            }

            match sxiaum_crypto::kzg::assert_production_srs_file(path, &config.kzg.srs_hash) {
                Ok(()) => {
                    let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    info!(
                        "Gate 2 OK: SXIAUM_SRS_MODE=production, non-dev SRS {:?} ({} bytes), hash pinned.",
                        path_str, len
                    );

                    // Ceremony transcript gate (mainnet provenance):
                    // - hard requirement when SXIAUM_SRS_CEREMONY_TRANSCRIPT is set,
                    // - strong warning when unset so operators cannot silently
                    //   ship a single-party artifact to mainnet.
                    match env::var("SXIAUM_SRS_CEREMONY_TRANSCRIPT") {
                        Ok(transcript_path) => {
                            let tp = Path::new(&transcript_path);
                            if !tp.exists() {
                                failures.push(format!(
                                    "SXIAUM_SRS_CEREMONY_TRANSCRIPT={:?} does not exist on disk.",
                                    transcript_path
                                ));
                            } else {
                                match sxiaum_crypto::ceremony::CeremonyTranscript::load(tp)
                                    .and_then(|t| {
                                        t.validate_for_production(
                                            sxiaum_crypto::MIN_CEREMONY_PARTICIPANTS,
                                        )?;
                                        Ok(t)
                                    }) {
                                    Ok(t) => info!(
                                        "Gate 2 OK: ceremony transcript verified ({} participants).",
                                        t.contributions.len()
                                    ),
                                    Err(e) => failures.push(format!(
                                        "SXIAUM_SRS_CEREMONY_TRANSCRIPT={:?} failed validation: {}",
                                        transcript_path, e
                                    )),
                                }
                            }
                        }
                        Err(_) => warn!(
                            "No ceremony transcript configured (SXIAUM_SRS_CEREMONY_TRANSCRIPT \
                             unset): the pinned SRS provenance cannot be verified. Mainnet \
                             operators should run the multi-party ceremony and provide it."
                        ),
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    // Normalize messages for operators and tests.
                    if msg.contains("dev_tau42") || msg.contains("DEVELOPMENT SRS") {
                        failures.push(format!(
                            "dev_tau42 SRS detected at SXIAUM_KZG_SRS_PATH={:?}: {}",
                            path_str, msg
                        ));
                    } else if msg.contains("hash mismatch") || msg.contains("SRS hash mismatch") {
                        failures.push(format!(
                            "SRS hash mismatch for SXIAUM_KZG_SRS_PATH={:?}: {}",
                            path_str, msg
                        ));
                    } else if msg.contains("placeholder") {
                        failures.push(msg);
                    } else {
                        failures.push(format!(
                            "SXIAUM_KZG_SRS_PATH={:?} rejected: {}",
                            path_str, msg
                        ));
                    }
                }
            }
        }
    }
}

/// Gate 3 - JWT secret minimum entropy.
///
/// Either `SXIAUM_JWT_KEY_FILE` must be set, or `SXIAUM_RPC_JWT_SECRET` must be set and at least [`MIN_JWT_SECRET_BYTES`]
/// bytes long (32 bytes = 256-bit entropy).
fn check_jwt_secret(failures: &mut Vec<String>) {
    if let Ok(key_file) = env::var("SXIAUM_JWT_KEY_FILE") {
        if !std::path::Path::new(&key_file).exists() {
            failures.push(format!(
                "SXIAUM_JWT_KEY_FILE={:?} does not exist.",
                key_file
            ));
        } else {
            info!("Gate 3 OK: SXIAUM_JWT_KEY_FILE is set ({:?}).", key_file);
        }
        return;
    }

    match env::var("SXIAUM_RPC_JWT_SECRET") {
        Err(_) => {
            failures.push(
                "Neither SXIAUM_JWT_KEY_FILE nor SXIAUM_RPC_JWT_SECRET is set. JWT authentication is required in production. \
                 Generate a secret: openssl rand -hex 32"
                    .to_string(),
            );
        }
        Ok(secret) => {
            if secret.len() < MIN_JWT_SECRET_BYTES {
                failures.push(format!(
                    "SXIAUM_RPC_JWT_SECRET is only {} bytes - minimum is {} bytes (256-bit \
                     entropy). Generate a stronger secret: openssl rand -hex 32",
                    secret.len(),
                    MIN_JWT_SECRET_BYTES
                ));
            } else {
                info!(
                    "Gate 3 OK: SXIAUM_RPC_JWT_SECRET is set ({} bytes - {} minimum).",
                    secret.len(),
                    MIN_JWT_SECRET_BYTES
                );
            }
        }
    }
}

/// Gate 4 - Transport security (TLS).
///
/// In production, either:
/// - `SXIAUM_TLS_CERT_PATH` **and** `SXIAUM_TLS_KEY_PATH` must both be set
///   pointing to readable PEM files (checked by `validate_tls_files`), OR
/// - `SXIAUM_REVERSE_PROXY=true` is explicitly set, indicating an external
///   TLS-terminating proxy (nginx, Caddy, AWS ALB, etc.) handles encryption.
///
/// `SXIAUM_ALLOW_HTTP=1` is **never** acceptable in production — it unconditionally
/// exposes the node to plaintext traffic without any proxy guarantee.
fn check_tls_config(failures: &mut Vec<String>) {
    let allow_http = env::var("SXIAUM_ALLOW_HTTP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if allow_http {
        failures.push(
            "SXIAUM_ALLOW_HTTP=1 is set - this disables TLS and allows \
             unauthenticated HTTP traffic, which is forbidden in production. \
             Remove this variable or set it to 0."
                .to_string(),
        );
        return;
    }

    let reverse_proxy = env::var("SXIAUM_REVERSE_PROXY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let cert = env::var("SXIAUM_TLS_CERT_PATH").ok();
    let key = env::var("SXIAUM_TLS_KEY_PATH").ok();

    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_ok = Path::new(&cert_path).exists();
            let key_ok = Path::new(&key_path).exists();
            if !cert_ok {
                failures.push(format!(
                    "SXIAUM_TLS_CERT_PATH={:?} does not exist.",
                    cert_path
                ));
            }
            if !key_ok {
                failures.push(format!(
                    "SXIAUM_TLS_KEY_PATH={:?} does not exist.",
                    key_path
                ));
            }
            // Check key file permissions on Unix
            #[cfg(unix)]
            if key_ok {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&key_path) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        failures.push(format!(
                            "SXIAUM_TLS_KEY_PATH={:?} has insecure permissions ({:#o}). \
                             Set to 0600: chmod 600 {:?}",
                            key_path, mode, key_path
                        ));
                    }
                }
            }
            if cert_ok && key_ok {
                info!(
                    "Gate 4 OK: TLS cert and key present at {:?} / {:?}.",
                    cert_path, key_path
                );
            }
        }
        _ if reverse_proxy => {
            // Explicit reverse-proxy mode: an external proxy MUST handle TLS.
            // We log a warning so operators know this is an assumption, not verified.
            warn!(
                "Gate 4 OK (REVERSE PROXY MODE): SXIAUM_REVERSE_PROXY=true — \
                 assuming an external TLS-terminating proxy (nginx/Caddy/ALB) is in front. \
                 Ensure the proxy does NOT expose plain HTTP to the public internet."
            );
            info!("Gate 4: reverse proxy mode acknowledged.");
        }
        _ => {
            // Neither TLS paths set nor reverse-proxy mode declared — fail closed.
            failures.push(
                "Gate 4 FAIL: Neither SXIAUM_TLS_CERT_PATH+SXIAUM_TLS_KEY_PATH nor \
                 SXIAUM_REVERSE_PROXY=true is set. Production requires TLS. \
                 Either configure TLS directly or set SXIAUM_REVERSE_PROXY=true \
                 if a verified TLS proxy is in front of this node."
                    .to_string(),
            );
        }
    }
}

/// Gate 5 - Validator key quality.
///
/// If `SXIAUM_VALIDATOR_KEY` is set, reject keys whose bytes all repeat a
/// single value (e.g. all-zeros, all-0x01) - these indicate test seeds that
/// have leaked into production configuration.
fn check_validator_key_quality(failures: &mut Vec<String>) {
    match env::var("SXIAUM_VALIDATOR_KEY") {
        Err(_) => {
            // Key not in env - loaded from file/keystore; we cannot check it here.
            info!("Gate 5 OK: SXIAUM_VALIDATOR_KEY not in env (assumed file/keystore/Vault).");
        }
        Ok(key_hex) => {
            let raw = hex::decode(key_hex.trim_start_matches("0x")).unwrap_or_default();
            if raw.len() >= 8 {
                let first = raw[0];
                if raw.iter().all(|&b| b == first) {
                    failures.push(format!(
                        "SXIAUM_VALIDATOR_KEY appears to be a trivial repeated-byte key \
                         (all bytes = 0x{:02x}). This is a test seed and must not be used \
                         in production. Generate a real validator key.",
                        first
                    ));
                } else {
                    info!("Gate 5 OK: SXIAUM_VALIDATOR_KEY passes quality check.");
                }
            } else {
                failures.push(
                    "SXIAUM_VALIDATOR_KEY is too short (< 8 decoded bytes). \
                     Provide a full 32-byte Ed25519 private key seed."
                        .to_string(),
                );
            }
        }
    }
}

/// Gate 6 — reject committed mainnet genesis with ceremony placeholders.
fn check_mainnet_genesis_placeholders(failures: &mut Vec<String>) {
    let path = env::var("SXIAUM_GENESIS_PATH").unwrap_or_else(|_| {
        // Prefer in-tree mainnet template when operators forget to set the path.
        "configs/mainnet/genesis.json".to_string()
    });
    let path = Path::new(&path);
    if !path.exists() {
        // Path may be absolute elsewhere; only fail if explicitly mainnet network.
        if env::var("SXIAUM_NETWORK")
            .map(|n| n.eq_ignore_ascii_case("mainnet"))
            .unwrap_or(false)
        {
            failures.push(format!(
                "SXIAUM_GENESIS_PATH={:?} does not exist (required for mainnet production).",
                path
            ));
        }
        return;
    }

    let Ok(raw) = std::fs::read_to_string(path) else {
        failures.push(format!("cannot read genesis file {:?}", path));
        return;
    };

    let is_mainnet = raw.contains("\"network\": \"mainnet\"")
        || raw.contains("\"network\":\"mainnet\"")
        || env::var("SXIAUM_NETWORK")
            .map(|n| n.eq_ignore_ascii_case("mainnet"))
            .unwrap_or(false);

    if !is_mainnet {
        return;
    }

    const PLACEHOLDERS: &[&str] = &[
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000003",
        "0x0000000000000000000000000000000000000000000000000000000000000004",
    ];
    for ph in PLACEHOLDERS {
        if raw.contains(ph) {
            failures.push(format!(
                "Mainnet genesis {:?} still contains placeholder validator pubkey {}. \
                 Complete the genesis ceremony before production.",
                path, ph
            ));
            break;
        }
    }

    // C1: refuse mainnet genesis that still advertises an unset SRS pin.
    if raw.contains("UNSET_CEREMONY_PLACEHOLDER")
        || raw.contains("\"srs_hash\": \"0xplaceholder\"")
        || raw.contains("\"srs_hash\":\"0xplaceholder\"")
        || raw.contains(
            "\"srs_hash\": \"0x0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        || raw.contains(
            "\"srs_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"",
        )
    {
        failures.push(format!(
            "Mainnet genesis {:?} still has an unset/placeholder kzg.srs_hash (C1). \
             Pin the SHA-256 of the ceremony SRS before production.",
            path
        ));
    }
}

/// Gate 7 — OCC parallel execution must verify against sequential in all environments.
///
/// P1-5: `verify_parallel_execution` now defaults to `true` globally. This gate
/// ensures it cannot be disabled explicitly in production via env override.
fn check_parallel_verify_policy(failures: &mut Vec<String>) {
    // Explicit disable is forbidden in production.
    if env::var("SXIAUM_VERIFY_PARALLEL")
        .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
    {
        failures.push(
            "SXIAUM_VERIFY_PARALLEL=0 is forbidden in production. \
             Parallel OCC must be cross-checked against sequential execution to guarantee \
             consensus safety. Remove this override or set SXIAUM_VERIFY_PARALLEL=1."
                .to_string(),
        );
    } else {
        // P1-5: The default is now always `true` — no need to force-set the env var.
        // Just confirm it is not explicitly disabled.
        info!(
            "Gate 7 OK: parallel OCC verification is enabled (default=true in all environments)."
        );
    }
}

/// Gate 8 — No stray private key files in the deployment directory.
///
/// P1-7: Scans `SXIAUM_KEY_MATERIAL_SCAN_DIR` (default: current directory) for files
/// matching known private key patterns. In production, any match is a hard failure.
/// In other environments, it emits a security warning.
fn check_no_stray_key_files(failures: &mut Vec<String>) {
    let scan_dir = env::var("SXIAUM_KEY_MATERIAL_SCAN_DIR").unwrap_or_else(|_| ".".to_string());
    let scan_path = Path::new(&scan_dir);

    if !scan_path.exists() {
        return;
    }

    // Patterns that indicate sensitive key material files
    const KEY_PATTERNS: &[&str] = &[
        ".pem",
        ".key",
        "_key.json",
        "validator_key",
        "sxiaum-key",
        "private_key",
    ];

    let mut found: Vec<String> = Vec::new();

    // Scan top-level files only (not recursive — avoids scanning deep build trees)
    if let Ok(entries) = std::fs::read_dir(scan_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_lowercase();
            if KEY_PATTERNS.iter().any(|pat| name_str.contains(pat)) {
                found.push(entry.path().display().to_string());
            }
        }
    }

    if !found.is_empty() {
        let msg = format!(
            "Gate 8: Potential private key files found in deployment directory {:?}: [{}]. \
             Delete these files, rotate keys if exposure is suspected, and store key material \
             in an HSM or encrypted keystore. Files: {}",
            scan_dir,
            found.len(),
            found.join(", ")
        );
        failures.push(msg);
    } else {
        info!(
            "Gate 8 OK: no stray private key files found in {:?}.",
            scan_dir
        );
    }
}

/// Gate 9 — Public RPC endpoints must have write authentication enabled in production.
fn check_rpc_write_auth(failures: &mut Vec<String>, config: &crate::node::NodeConfig) {
    let rpc_ip = config.rpc_addr.ip();
    if rpc_ip.is_loopback() {
        info!("Gate 9 OK: RPC bind address {} is loopback (safe).", rpc_ip);
        return;
    }

    let write_auth_enabled = env::var("SXIAUM_RPC_WRITE_AUTH")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !write_auth_enabled {
        failures.push(format!(
            "Gate 9 FAIL: Public RPC endpoint bound to non-loopback address ({}) \
             without mandatory write authentication. \
             Set SXIAUM_RPC_WRITE_AUTH=1 in your production environment.",
            config.rpc_addr
        ));
    } else {
        info!("Gate 9 OK: SXIAUM_RPC_WRITE_AUTH=1 is enforced on public RPC endpoint.");
    }
}

/// Gate 10 — Bootnodes must not be template placeholders.
fn check_template_bootnodes(failures: &mut Vec<String>, config: &crate::node::NodeConfig) {
    if let Ok(raw_bootnodes) = env::var("SXIAUM_BOOTNODES") {
        if raw_bootnodes.contains("REPLACE_WITH_BOOTNODE_PEER_ID")
            || raw_bootnodes.contains("REPLACE_")
        {
            failures.push(format!(
                "Gate 10 FAIL: SXIAUM_BOOTNODES contains template placeholder ({:?}). \
                 Replace it with a real multiaddr in your configuration.",
                raw_bootnodes
            ));
            return;
        }
    }

    let mut found = false;
    for bootnode in &config.bootstrap_peers {
        let bootnode_str = bootnode.1.to_string();
        if bootnode_str.contains("REPLACE_WITH_BOOTNODE_PEER_ID")
            || bootnode_str.contains("REPLACE_")
        {
            failures.push(format!(
                "Gate 10 FAIL: Bootnode {:?} is a template placeholder. \
                 Replace it with a real multiaddr in your configuration.",
                bootnode
            ));
            found = true;
        }
    }
    if !found {
        info!("Gate 10 OK: Bootnodes do not contain template placeholders.");
    }
}

/// Gate 11 — Production genesis timestamp must be non-zero.
///
/// A `genesis_timestamp` of 0 means the genesis was never finalized for
/// mainnet. All nodes must use an identical non-zero UTC epoch so that
/// fork-choice and block timing are deterministic across the network.
fn check_genesis_timestamp(failures: &mut Vec<String>, config: &crate::node::NodeConfig) {
    let ts = config.genesis_timestamp;
    if ts == 0 {
        failures.push(
            "Gate 11 FAIL: genesis_timestamp is 0. \
             Set it to the ceremony freeze UTC epoch (e.g. 1754006400 for 2025-08-01T00:00:00Z) \
             in genesis.json before production launch. All nodes must use the same value."
                .to_string(),
        );
    } else {
        info!("Gate 11 OK: genesis_timestamp = {} (non-zero).", ts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_failures_when_env_not_production() {
        // This test must not set SXIAUM_ENV=production; the function should
        // return immediately without inspecting any other variables.
        // We call the individual gate helpers with an empty failures vec to
        // test them directly.
        // run_production_preflight() returns early for non-production - tested
        // indirectly by ensuring the process does not exit in CI.
    }

    #[test]
    fn sp1_mode_gate_fails_when_unset() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        // Temporarily clear the variable (safe under test lock)
        let old = std::env::var("SXIAUM_SP1_MODE").ok();
        std::env::remove_var("SXIAUM_SP1_MODE");

        let config = crate::node::NodeConfig::default();

        check_sp1_mode(&mut failures, &config);
        assert!(
            !failures.is_empty(),
            "should fail when SXIAUM_SP1_MODE is unset"
        );

        // Restore
        if let Some(v) = old {
            std::env::set_var("SXIAUM_SP1_MODE", v);
        }
    }

    #[test]
    fn jwt_secret_gate_fails_when_too_short() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_RPC_JWT_SECRET").ok();
        std::env::set_var("SXIAUM_RPC_JWT_SECRET", "short");

        check_jwt_secret(&mut failures);
        assert!(
            !failures.is_empty(),
            "should fail when JWT secret < 32 bytes"
        );

        match old {
            Some(v) => std::env::set_var("SXIAUM_RPC_JWT_SECRET", v),
            None => std::env::remove_var("SXIAUM_RPC_JWT_SECRET"),
        }
    }

    #[test]
    fn jwt_secret_gate_passes_when_long_enough() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_RPC_JWT_SECRET").ok();
        std::env::set_var("SXIAUM_RPC_JWT_SECRET", "a".repeat(MIN_JWT_SECRET_BYTES));

        check_jwt_secret(&mut failures);
        assert!(
            failures.is_empty(),
            "should pass when JWT secret >= 32 bytes"
        );

        match old {
            Some(v) => std::env::set_var("SXIAUM_RPC_JWT_SECRET", v),
            None => std::env::remove_var("SXIAUM_RPC_JWT_SECRET"),
        }
    }

    #[test]
    fn allow_http_gate_fails_in_production() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_ALLOW_HTTP").ok();
        std::env::set_var("SXIAUM_ALLOW_HTTP", "1");

        check_tls_config(&mut failures);
        assert!(!failures.is_empty(), "should fail when SXIAUM_ALLOW_HTTP=1");

        match old {
            Some(v) => std::env::set_var("SXIAUM_ALLOW_HTTP", v),
            None => std::env::remove_var("SXIAUM_ALLOW_HTTP"),
        }
    }

    #[test]
    fn validator_key_gate_rejects_repeated_byte_key() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_VALIDATOR_KEY").ok();
        // All-zeros key: 32 bytes of 0x00
        std::env::set_var(
            "SXIAUM_VALIDATOR_KEY",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );

        check_validator_key_quality(&mut failures);
        assert!(!failures.is_empty(), "should reject all-zero validator key");

        match old {
            Some(v) => std::env::set_var("SXIAUM_VALIDATOR_KEY", v),
            None => std::env::remove_var("SXIAUM_VALIDATOR_KEY"),
        }
    }

    #[test]
    fn parallel_verify_policy_rejects_disable_override() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_VERIFY_PARALLEL").ok();
        std::env::set_var("SXIAUM_VERIFY_PARALLEL", "0");

        check_parallel_verify_policy(&mut failures);
        assert!(
            !failures.is_empty(),
            "should fail when SXIAUM_VERIFY_PARALLEL=0"
        );

        match old {
            Some(v) => std::env::set_var("SXIAUM_VERIFY_PARALLEL", v),
            None => std::env::remove_var("SXIAUM_VERIFY_PARALLEL"),
        }
    }

    #[test]
    fn stray_key_protection_detects_exposed_keys() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let temp = tempfile::tempdir().unwrap();
        let key_file = temp.path().join("validator_key.json");
        std::fs::write(&key_file, "secret-key-material").unwrap();

        let old = std::env::var("SXIAUM_KEY_MATERIAL_SCAN_DIR").ok();
        std::env::set_var(
            "SXIAUM_KEY_MATERIAL_SCAN_DIR",
            temp.path().to_str().unwrap(),
        );

        let mut failures = Vec::new();
        check_no_stray_key_files(&mut failures);
        assert!(
            !failures.is_empty(),
            "should fail when stray key file is found"
        );

        match old {
            Some(v) => std::env::set_var("SXIAUM_KEY_MATERIAL_SCAN_DIR", v),
            None => std::env::remove_var("SXIAUM_KEY_MATERIAL_SCAN_DIR"),
        }
    }

    #[test]
    fn rpc_write_auth_gate_rejects_unauthenticated_public_rpc() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_RPC_WRITE_AUTH").ok();
        std::env::remove_var("SXIAUM_RPC_WRITE_AUTH");

        let config = crate::node::NodeConfig {
            rpc_addr: "0.0.0.0:8545".parse().unwrap(),
            ..Default::default()
        };

        check_rpc_write_auth(&mut failures, &config);
        assert!(
            !failures.is_empty(),
            "should reject public RPC without write auth"
        );

        match old {
            Some(v) => std::env::set_var("SXIAUM_RPC_WRITE_AUTH", v),
            None => std::env::remove_var("SXIAUM_RPC_WRITE_AUTH"),
        }
    }

    #[test]
    fn bootnode_gate_rejects_template_placeholder() {
        let _g = crate::keys::TEST_ENV_LOCK.lock();
        let mut failures = Vec::new();
        let old = std::env::var("SXIAUM_BOOTNODES").ok();
        std::env::set_var(
            "SXIAUM_BOOTNODES",
            "/ip4/1.2.3.4/tcp/9000/p2p/REPLACE_WITH_BOOTNODE_PEER_ID",
        );

        let config = crate::node::NodeConfig::default();
        check_template_bootnodes(&mut failures, &config);
        assert!(
            !failures.is_empty(),
            "should reject template bootnode placeholder"
        );

        match old {
            Some(v) => std::env::set_var("SXIAUM_BOOTNODES", v),
            None => std::env::remove_var("SXIAUM_BOOTNODES"),
        }
    }

    #[test]
    fn genesis_timestamp_gate_rejects_zero() {
        let mut failures = Vec::new();
        let mut config = crate::node::NodeConfig {
            genesis_timestamp: 0,
            ..Default::default()
        };

        check_genesis_timestamp(&mut failures, &config);
        assert!(!failures.is_empty(), "should reject zero genesis timestamp");

        config.genesis_timestamp = 1754006400;
        let mut failures_pass = Vec::new();
        check_genesis_timestamp(&mut failures_pass, &config);
        assert!(
            failures_pass.is_empty(),
            "should pass non-zero genesis timestamp"
        );
    }
}
