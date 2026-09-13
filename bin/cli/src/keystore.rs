//! SXIAUM Wallet Security Engine
//!
//! Encryption stack (delegates to the shared `sxiaum-keystore` primitives):
//!   Key derivation  : Argon2id via [sxiaum_keystore::kdf] (m=65536 KiB, t=3, p=1)
//!   Cipher          : AES-256-GCM via [sxiaum_keystore::cipher] (256-bit key, 96-bit nonce)
//!   Storage format  : JSON keystore (version 2) — identical layout to prior releases
//!
//! The keystore file stores NO plaintext private keys.
//! The password is never persisted - only held in memory during the operation.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use sxiaum_keystore::cipher::{decrypt_aes256_gcm, encrypt_aes256_gcm};
use sxiaum_keystore::kdf::{derive_argon2id, Argon2Params as KdfArgon2Params};
use zeroize::Zeroize;

// - Constants -

/// Argon2id parameters (OWASP recommended interactive profile).
const ARGON2_MEMORY_KIB: u32 = 65_536; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const SALT_BYTES: usize = 32;
const NONCE_BYTES: usize = 12; // 96-bit GCM nonce

// - On-disk keystore format -

#[derive(Serialize, Deserialize, Clone)]
pub struct KeystoreV2 {
    /// Format version - always 2 for AES-256-GCM/Argon2id.
    pub version: u8,

    pub kdf: String,              // "argon2id"
    pub kdf_params: Argon2Params, // serialisable subset of argon2 params
    pub cipher: String,           // "aes-256-gcm"

    /// Base64-encoded random 12-byte nonce used for AES-GCM.
    pub nonce: String,

    /// Base64-encoded AES-GCM ciphertext (includes the 16-byte auth tag).
    pub ciphertext: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// Base64-encoded 32-byte random salt.
    pub salt: String,
}

impl Argon2Params {
    fn to_kdf_params(&self) -> KdfArgon2Params {
        KdfArgon2Params {
            memory_kib: self.m_cost,
            time_cost: self.t_cost,
            parallelism: self.p_cost,
        }
    }
}

fn decode_salt(salt_b64: &str) -> anyhow::Result<Vec<u8>> {
    let salt = BASE64
        .decode(salt_b64)
        .map_err(|_| anyhow::anyhow!("Corrupt keystore: invalid salt encoding"))?;
    if salt.len() < 16 || salt.len() > 64 {
        return Err(anyhow::anyhow!(
            "Corrupt keystore: invalid salt length {}",
            salt.len()
        ));
    }
    Ok(salt)
}

// - Plaintext wallet payload -

/// The decrypted in-memory wallet payload.
/// All fields implement Zeroize so the keys are wiped when dropped.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct WalletPayload {
    /// alias - private key hex (64 chars, no 0x prefix)
    pub keys: HashMap<String, String>,
}

impl Drop for WalletPayload {
    fn drop(&mut self) {
        for v in self.keys.values_mut() {
            v.zeroize();
        }
    }
}

// - Encrypt -

/// Encrypt the wallet payload with a new random salt + nonce.
/// Returns a ready-to-serialise KeystoreV2 struct.
pub fn encrypt_wallet(payload: &WalletPayload, password: &str) -> anyhow::Result<KeystoreV2> {
    use rand::RngCore;

    // Generate fresh random salt and nonce from the OS CSPRNG.
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let params = KdfArgon2Params {
        memory_kib: ARGON2_MEMORY_KIB,
        time_cost: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
    };
    let derived = derive_argon2id(password, &salt, &params)?;

    let plaintext = serde_json::to_vec(payload)?;
    let ciphertext = encrypt_aes256_gcm(&derived, &nonce_bytes, &plaintext)?;

    Ok(KeystoreV2 {
        version: 2,
        kdf: "argon2id".to_string(),
        kdf_params: Argon2Params {
            m_cost: ARGON2_MEMORY_KIB,
            t_cost: ARGON2_ITERATIONS,
            p_cost: ARGON2_PARALLELISM,
            salt: BASE64.encode(salt),
        },
        cipher: "aes-256-gcm".to_string(),
        nonce: BASE64.encode(nonce_bytes),
        ciphertext: BASE64.encode(&ciphertext),
    })
}

// - Decrypt -

/// Decrypt a KeystoreV2 with the given password.
/// Returns `Err` with a generic message on wrong password (no oracle leak).
pub fn decrypt_wallet(ks: &KeystoreV2, password: &str) -> anyhow::Result<WalletPayload> {
    if ks.version != 2 {
        anyhow::bail!("Unsupported keystore version {}", ks.version);
    }
    if ks.kdf != "argon2id" {
        anyhow::bail!("Unsupported kdf {}", ks.kdf);
    }
    if ks.cipher != "aes-256-gcm" {
        anyhow::bail!("Unsupported cipher {}", ks.cipher);
    }

    let salt = decode_salt(&ks.kdf_params.salt)?;
    if salt.len() != SALT_BYTES {
        return Err(anyhow::anyhow!(
            "Corrupt keystore: invalid salt length {}",
            salt.len()
        ));
    }
    let nonce_raw = BASE64
        .decode(&ks.nonce)
        .map_err(|_| anyhow::anyhow!("Corrupt keystore: invalid nonce encoding"))?;
    if nonce_raw.len() != NONCE_BYTES {
        return Err(anyhow::anyhow!("Corrupt keystore: invalid nonce length"));
    }
    let ciphertext = BASE64
        .decode(&ks.ciphertext)
        .map_err(|_| anyhow::anyhow!("Corrupt keystore: invalid ciphertext encoding"))?;
    if ciphertext.is_empty() {
        return Err(anyhow::anyhow!("Corrupt keystore: empty ciphertext"));
    }

    let derived = derive_argon2id(password, &salt, &ks.kdf_params.to_kdf_params())
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {e}"))?;

    let mut nonce_arr = [0u8; NONCE_BYTES];
    nonce_arr.copy_from_slice(&nonce_raw);

    let plaintext = decrypt_aes256_gcm(&derived, &nonce_arr, &ciphertext)
        .map_err(|_| anyhow::anyhow!("- Wrong password or corrupted wallet file"))?;

    let payload: WalletPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| anyhow::anyhow!("Corrupt keystore: decrypted payload is not valid JSON"))?;

    Ok(payload)
}

// - Address book (plaintext - addresses are public) -

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AddressBook {
    /// label - address (0x-prefixed)
    pub entries: HashMap<String, String>,
}

impl AddressBook {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let data = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Resolve a user-supplied address or label to a 0x-prefixed address string.
    pub fn resolve<'a>(&'a self, input: &'a str) -> &'a str {
        self.entries.get(input).map(|s| s.as_str()).unwrap_or(input)
    }
}
