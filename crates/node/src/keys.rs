//! Advanced validator / P2P key loading.
//!
//! Private keys are **never** taken from committed JSON configs. Resolution
//! order (first match wins):
//!
//! 1. `SXIAUM_VALIDATOR_KEY` - 32-byte hex in the environment  
//! 2. `SXIAUM_VALIDATOR_KEY_FILE` - path to a file containing 32-byte hex  
//! 3. Encrypted filesystem keystore:
//!    - `SXIAUM_VALIDATOR_KEYSTORE` (directory)
//!    - `SXIAUM_VALIDATOR_KEY_ID` (entry id, default `validator`)
//!    - `SXIAUM_VALIDATOR_KEYSTORE_PASSWORD` or `SXIAUM_VALIDATOR_KEYSTORE_PASSWORD_FILE`
//! 4. HashiCorp Vault (optional):
//!    - `SXIAUM_VAULT_ADDR`, `SXIAUM_VAULT_TOKEN`, `SXIAUM_VAULT_KEY_PATH`
//! 5. Config field `validator_key_env` - name of another env var holding the hex key  
//! 6. Config field `validator_key_file` - path string in JSON (not the key material)  
//! 7. Config field `validator_keystore` + `validator_key_id` (+ password env as above)
//!
//! Production (`SXIAUM_ENV=production`) rejects trivial/repeated-byte keys.

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::{info, warn};
use zeroize::Zeroize;

/// Resolved 32-byte ed25519 seed (zeroized on drop).
#[derive(Clone)]
pub struct SecretSeed([u8; 32]);

impl SecretSeed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_array(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for SecretSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.write_str("SecretSeed([REDACTED])")
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn is_production() -> bool {
    let env = std::env::var("SXIAUM_ENV").unwrap_or_default();
    let srs = std::env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    env.eq_ignore_ascii_case("production") || srs.eq_ignore_ascii_case("production")
}

fn parse_hex32(hex_str: &str) -> Result<[u8; 32]> {
    let cleaned = hex_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let decoded = hex::decode(cleaned).context("invalid hex for private key")?;
    if decoded.len() != 32 {
        bail!(
            "private key must be exactly 32 bytes, got {}",
            decoded.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

const DEMO_SEEDS: &[[u8; 32]] = &[
    [0x01; 32],
    [0x02; 32],
    [0x03; 32],
    [0x04; 32],
    // "0000000000000000000000000000000000000000000000000000000000000001"
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ],
];

fn is_trivial_key(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|&b| b == bytes[0]) || DEMO_SEEDS.contains(bytes)
}

fn reject_if_trivial(bytes: &[u8; 32], source: &str) -> Result<()> {
    if is_trivial_key(bytes) {
        if is_production() {
            bail!(
                "SECURITY ERROR: trivial/repeated-byte key or known demo seed from {source} is blocked in production"
            );
        }
        warn!(
            "SECURITY: trivial/repeated-byte key or demo seed loaded from {source} - devnet only, never mainnet"
        );
    }
    Ok(())
}

fn read_hex_file(path: &Path) -> Result<[u8; 32]> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read key file {}", path.display()))?;

    // P1-7: After reading the file, restrict permissions to 0600 on Unix
    // so that other processes on the same host cannot read the key material.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .with_context(|| format!("cannot stat key file {}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o177 != 0 {
            // Attempt to tighten permissions; log if we cannot.
            let secure_perms = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(path, secure_perms) {
                warn!(
                    "Cannot restrict permissions on key file {} (current: {:#o}): {}. \
                     Manually run: chmod 600 {}",
                    path.display(),
                    mode,
                    e,
                    path.display()
                );
            } else {
                info!(
                    "Restricted key file {} permissions from {:#o} to 0600.",
                    path.display(),
                    mode
                );
            }
        }
    }

    info!("Loaded validator key from file: {}", path.display());

    // Allow optional trailing newline / comments: first non-empty, non-# line.
    let line = raw
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("key file {} is empty", path.display()))?;
    parse_hex32(line)
}

fn password_from_env() -> Option<String> {
    if let Ok(p) = std::env::var("SXIAUM_VALIDATOR_KEYSTORE_PASSWORD") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    if let Ok(path) = std::env::var("SXIAUM_VALIDATOR_KEYSTORE_PASSWORD_FILE") {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let p = contents.trim().to_string();
            if !p.is_empty() {
                return Some(p);
            }
        }
    }
    None
}

fn load_from_keystore(dir: &Path, key_id: &str, password: Option<String>) -> Result<[u8; 32]> {
    // Reject path-traversal or malformed key ids before touching the filesystem.
    sxiaum_keystore::validate_key_id(key_id)
        .map_err(|e| anyhow::anyhow!("invalid keystore key id '{}': {}", key_id, e))?;

    let path = dir.join(key_id);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read keystore entry {}", path.display()))?;

    let pw = password.as_deref().unwrap_or("");
    let entry = sxiaum_keystore::format::detect_and_decrypt(&bytes, pw, key_id).map_err(|e| {
        anyhow::anyhow!(
            "failed to decrypt or load keystore entry '{}': {}",
            key_id,
            e
        )
    })?;

    if entry.data.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&entry.data);
        return Ok(out);
    }
    if entry.data.len() == 64 || entry.data.starts_with(b"0x") {
        let s = String::from_utf8_lossy(&entry.data);
        return parse_hex32(&s);
    }
    bail!(
        "keystore entry '{}' data must be 32 raw bytes or hex (got {} bytes)",
        key_id,
        entry.data.len()
    );
}

fn load_from_vault() -> Result<Option<[u8; 32]>> {
    let addr = match std::env::var("SXIAUM_VAULT_ADDR") {
        Ok(a) if !a.is_empty() => a,
        _ => return Ok(None),
    };
    let token = std::env::var("SXIAUM_VAULT_TOKEN").unwrap_or_default();
    let path = match std::env::var("SXIAUM_VAULT_KEY_PATH") {
        Ok(p) if !p.is_empty() => p,
        _ => return Ok(None),
    };
    if is_production() {
        if token.is_empty() {
            bail!("SXIAUM_VAULT_TOKEN is required when SXIAUM_VAULT_ADDR is set in production");
        }
        if !addr.starts_with("https://") {
            bail!("Vault address must use HTTPS in production");
        }
        if addr.contains("169.254.169.254")
            || addr.contains("127.0.0.1")
            || addr.contains("localhost")
            || addr.contains("::1")
        {
            bail!("Vault address must not be a loopback or metadata service IP in production");
        }
    }
    if path.contains("..") {
        bail!("Path traversal detected in Vault key path");
    }

    // Blocking HTTP GET of KV secret - path is operator-defined.
    // Expected secret value: field `hex` or `key` or `value` containing 32-byte hex.
    let url = format!(
        "{}/v1/{}",
        addr.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to build Vault HTTP client")?;
    let mut req = client.get(&url);
    if !token.is_empty() {
        req = req.bearer_auth(&token);
    }
    let resp = req.send().context("Vault request failed")?;
    if !resp.status().is_success() {
        bail!("Vault returned HTTP {}", resp.status());
    }
    let body: Value = resp.json().context("Vault response is not JSON")?;
    // KV v2: data.data.*; KV v1: data.*
    let data = body
        .pointer("/data/data")
        .or_else(|| body.get("data"))
        .cloned()
        .unwrap_or(body);
    let hex_val = data
        .get("hex")
        .or_else(|| data.get("key"))
        .or_else(|| data.get("value"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Vault secret missing hex/key/value field at {path}"))?;
    Ok(Some(parse_hex32(hex_val)?))
}

/// Resolve the validator signing seed using the advanced source chain.
pub fn resolve_validator_seed(config_json: Option<&Value>) -> Result<SecretSeed> {
    // Reject legacy inline private keys even if still present in old config files.
    if let Some(v) = config_json {
        if v.get("proposer_private_key").is_some() || v.get("validator_key").is_some() {
            bail!(
                "SECURITY FAILURE: `proposer_private_key` or `validator_key` in JSON is no longer supported. \
                 Remove it and use SXIAUM_VALIDATOR_KEY, SXIAUM_VALIDATOR_KEY_FILE, \
                 encrypted keystore, or Vault (see docs/KEY_MANAGEMENT.md)."
            );
        }
    }

    // 1) Direct env hex
    if let Ok(hex_key) = std::env::var("SXIAUM_VALIDATOR_KEY") {
        if !hex_key.is_empty() {
            let bytes = parse_hex32(&hex_key)?;
            reject_if_trivial(&bytes, "SXIAUM_VALIDATOR_KEY")?;
            info!("Validator key loaded from SXIAUM_VALIDATOR_KEY");
            return Ok(SecretSeed::from_bytes(bytes));
        }
    }

    // 2) Env path to hex file
    if let Ok(path) = std::env::var("SXIAUM_VALIDATOR_KEY_FILE") {
        if !path.is_empty() {
            let bytes = read_hex_file(Path::new(&path))?;
            reject_if_trivial(&bytes, "SXIAUM_VALIDATOR_KEY_FILE")?;
            info!(path = %path, "Validator key loaded from key file");
            return Ok(SecretSeed::from_bytes(bytes));
        }
    }

    // 3) Encrypted FS keystore via env
    if let Ok(dir) = std::env::var("SXIAUM_VALIDATOR_KEYSTORE") {
        if !dir.is_empty() {
            let key_id =
                std::env::var("SXIAUM_VALIDATOR_KEY_ID").unwrap_or_else(|_| "validator".into());
            let bytes = load_from_keystore(Path::new(&dir), &key_id, password_from_env())?;
            reject_if_trivial(&bytes, "SXIAUM_VALIDATOR_KEYSTORE")?;
            info!(%dir, %key_id, "Validator key loaded from encrypted keystore");
            return Ok(SecretSeed::from_bytes(bytes));
        }
    }

    // 4) Vault
    if let Some(bytes) = load_from_vault()? {
        reject_if_trivial(&bytes, "Vault")?;
        info!("Validator key loaded from HashiCorp Vault");
        return Ok(SecretSeed::from_bytes(bytes));
    }

    // 5-7) Config indirection (env name / file path / keystore path - never raw key)
    if let Some(v) = config_json {
        if let Some(env_name) = v.get("validator_key_env").and_then(|x| x.as_str()) {
            let hex_key = std::env::var(env_name).with_context(|| {
                format!(
                    "config validator_key_env={env_name} is set but environment variable is missing"
                )
            })?;
            let bytes = parse_hex32(&hex_key)?;
            reject_if_trivial(&bytes, env_name)?;
            info!(%env_name, "Validator key loaded via config validator_key_env");
            return Ok(SecretSeed::from_bytes(bytes));
        }
        if let Some(path) = v.get("validator_key_file").and_then(|x| x.as_str()) {
            let bytes = read_hex_file(Path::new(path))?;
            reject_if_trivial(&bytes, "validator_key_file")?;
            info!(%path, "Validator key loaded via config validator_key_file");
            return Ok(SecretSeed::from_bytes(bytes));
        }
        if let Some(dir) = v.get("validator_keystore").and_then(|x| x.as_str()) {
            let key_id = v
                .get("validator_key_id")
                .and_then(|x| x.as_str())
                .unwrap_or("validator");
            let bytes = load_from_keystore(Path::new(dir), key_id, password_from_env())?;
            reject_if_trivial(&bytes, "validator_keystore")?;
            info!(%dir, %key_id, "Validator key loaded via config validator_keystore");
            return Ok(SecretSeed::from_bytes(bytes));
        }
    }

    bail!(
        "No validator private key source configured. Use one of:\n\
         - SXIAUM_VALIDATOR_KEY=<32-byte hex>\n\
         - SXIAUM_VALIDATOR_KEY_FILE=/path/to/key.hex\n\
         - SXIAUM_VALIDATOR_KEYSTORE + SXIAUM_VALIDATOR_KEY_ID + password\n\
         - SXIAUM_VAULT_ADDR + SXIAUM_VAULT_TOKEN + SXIAUM_VAULT_KEY_PATH\n\
         - config validator_key_env / validator_key_file / validator_keystore\n\
         See docs/KEY_MANAGEMENT.md"
    )
}

/// Resolve optional P2P node identity seed (stable PeerId across restarts).
pub fn resolve_p2p_seed(
    config_json: Option<&Value>,
    validator_seed: Option<&[u8; 32]>,
) -> Result<Option<[u8; 32]>> {
    if let Ok(hex_key) = std::env::var("SXIAUM_P2P_NODE_KEY") {
        if !hex_key.is_empty() {
            return Ok(Some(parse_hex32(&hex_key)?));
        }
    }
    if let Ok(path) = std::env::var("SXIAUM_P2P_NODE_KEY_FILE") {
        if !path.is_empty() {
            return Ok(Some(read_hex_file(Path::new(&path))?));
        }
    }
    if let Some(v) = config_json {
        if v.get("p2p_node_key_seed").is_some() {
            bail!(
                "SECURITY FAILURE: `p2p_node_key_seed` in JSON is no longer supported. \
                 Use SXIAUM_P2P_NODE_KEY / SXIAUM_P2P_NODE_KEY_FILE or omit to derive from validator key."
            );
        }
        if let Some(env_name) = v.get("p2p_node_key_env").and_then(|x| x.as_str()) {
            let hex_key = std::env::var(env_name)
                .with_context(|| format!("p2p_node_key_env={env_name} not set"))?;
            return Ok(Some(parse_hex32(&hex_key)?));
        }
        if let Some(path) = v.get("p2p_node_key_file").and_then(|x| x.as_str()) {
            return Ok(Some(read_hex_file(Path::new(path))?));
        }
    }
    // Default: derive a domain-separated seed from the validator key so PeerId is stable
    // without a second secret.
    if let Some(seed) = validator_seed {
        if is_production() {
            bail!(
                "SECURITY ERROR: deriving P2P node key from validator seed is forbidden in production. \
                 Configure a separate P2P key via SXIAUM_P2P_NODE_KEY or SXIAUM_P2P_NODE_KEY_FILE."
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(b"sxiaum:p2p-node-key:v1");
        hasher.update(seed);
        return Ok(Some(hasher.finalize().into()));
    }
    Ok(None)
}

pub fn signing_key_from_seed(seed: &SecretSeed) -> SigningKey {
    SigningKey::from_bytes(seed.as_bytes())
}

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inline_json_private_key() {
        let _g = TEST_ENV_LOCK.lock();
        std::env::remove_var("SXIAUM_VALIDATOR_KEY");
        std::env::remove_var("SXIAUM_VALIDATOR_KEY_FILE");
        std::env::remove_var("SXIAUM_VALIDATOR_KEYSTORE");
        std::env::remove_var("SXIAUM_VAULT_ADDR");
        let v = serde_json::json!({
            "proposer_private_key": "0x0101010101010101010101010101010101010101010101010101010101010101"
        });
        let err = resolve_validator_seed(Some(&v)).unwrap_err();
        assert!(err.to_string().contains("no longer supported"));
    }

    #[test]
    fn loads_from_env_hex() {
        let _g = TEST_ENV_LOCK.lock();
        std::env::set_var(
            "SXIAUM_VALIDATOR_KEY",
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        std::env::remove_var("SXIAUM_VALIDATOR_KEY_FILE");
        std::env::remove_var("SXIAUM_VALIDATOR_KEYSTORE");
        std::env::remove_var("SXIAUM_VAULT_ADDR");
        let seed = resolve_validator_seed(None).expect("env key");
        assert_eq!(seed.as_bytes()[0], 0xaa);
        std::env::remove_var("SXIAUM_VALIDATOR_KEY");
    }

    #[test]
    fn loads_from_named_env_via_config() {
        let _g = TEST_ENV_LOCK.lock();
        std::env::remove_var("SXIAUM_VALIDATOR_KEY");
        std::env::remove_var("SXIAUM_VALIDATOR_KEY_FILE");
        std::env::remove_var("SXIAUM_VALIDATOR_KEYSTORE");
        std::env::remove_var("SXIAUM_VAULT_ADDR");
        std::env::set_var(
            "SXIAUM_VALIDATOR_KEY_1",
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        );
        let v = serde_json::json!({ "validator_key_env": "SXIAUM_VALIDATOR_KEY_1" });
        let seed = resolve_validator_seed(Some(&v)).expect("named env");
        assert_eq!(seed.as_bytes()[0], 0xbb);
        std::env::remove_var("SXIAUM_VALIDATOR_KEY_1");
    }
}
