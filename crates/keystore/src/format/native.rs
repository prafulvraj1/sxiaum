use crate::cipher::{decrypt_aes256_gcm, encrypt_aes256_gcm};
use crate::error::{KeystoreError, Result};
use crate::kdf::{derive_argon2id, derive_pbkdf2_sha256, Argon2Params};
use crate::KeyEntry;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Native encrypted keystore wrapper matching SXIAUM v2 on-disk representation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NativeKeystoreWrapper {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default = "default_kdf")]
    pub kdf: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

fn default_version() -> u8 {
    crate::KEYSTORE_VERSION
}

fn default_kdf() -> String {
    "argon2id".to_string()
}

impl NativeKeystoreWrapper {
    /// Encrypt a `KeyEntry` using Argon2id + AES-256-GCM.
    pub fn encrypt(entry: &KeyEntry, password: &str) -> Result<Self> {
        let mut salt = vec![0u8; 32];
        let mut nonce = vec![0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let params = Argon2Params::default();
        let key = derive_argon2id(password, &salt, &params)?;

        let plaintext = Zeroizing::new(serde_json::to_vec(entry)?);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&nonce);

        let ciphertext = encrypt_aes256_gcm(&key, &nonce_arr, &plaintext)?;

        // Compute MAC over ciphertext using SHA-256: SHA256(key[16..32] || ciphertext)
        let mut hasher = Sha256::new();
        hasher.update(&key[16..32]);
        hasher.update(&ciphertext);
        let mac_bytes: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            version: crate::KEYSTORE_VERSION,
            kdf: "argon2id".to_string(),
            salt,
            nonce,
            ciphertext,
            mac: Some(hex::encode(mac_bytes)),
        })
    }

    /// Decrypt a `NativeKeystoreWrapper` into a `KeyEntry`.
    pub fn decrypt(&self, password: &str) -> Result<KeyEntry> {
        if self.salt.len() < 16 || self.salt.len() > 64 {
            return Err(KeystoreError::CorruptedKeystore(
                "native".to_string(),
                format!("invalid salt length: {}", self.salt.len()),
            ));
        }

        if self.nonce.len() != 12 {
            return Err(KeystoreError::CorruptedKeystore(
                "native".to_string(),
                format!("invalid nonce length: {}", self.nonce.len()),
            ));
        }

        if self.ciphertext.is_empty() {
            return Err(KeystoreError::CorruptedKeystore(
                "native".to_string(),
                "ciphertext cannot be empty".to_string(),
            ));
        }

        if self.ciphertext.len() > crate::MAX_KEY_DATA_SIZE {
            return Err(KeystoreError::InvalidKeyLength {
                expected: crate::MAX_KEY_DATA_SIZE,
                actual: self.ciphertext.len(),
            });
        }

        if self.version == 0 || self.version > crate::KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }

        let is_legacy = self.version < 2 || self.kdf != "argon2id";

        if is_legacy && crate::password::is_production() {
            return Err(KeystoreError::LegacyFormatForbiddenInProduction);
        }

        let key = if is_legacy {
            derive_pbkdf2_sha256(password, &self.salt, crate::PBKDF2_ITERATIONS)?
        } else {
            let params = Argon2Params::default();
            derive_argon2id(password, &self.salt, &params)?
        };

        // If MAC is present, perform strict constant-time pre-validation
        if let Some(mac_hex) = &self.mac {
            let expected_mac = hex::decode(mac_hex).map_err(|e| {
                KeystoreError::CorruptedKeystore(
                    "native".to_string(),
                    format!("invalid MAC hex encoding: {e}"),
                )
            })?;
            if expected_mac.len() != 32 {
                return Err(KeystoreError::CorruptedKeystore(
                    "native".to_string(),
                    format!(
                        "invalid MAC length: expected 32 bytes, got {}",
                        expected_mac.len()
                    ),
                ));
            }
            let mut hasher = Sha256::new();
            hasher.update(&key[16..32]);
            hasher.update(&self.ciphertext);
            let computed_mac: [u8; 32] = hasher.finalize().into();
            let mut exp_arr = [0u8; 32];
            exp_arr.copy_from_slice(&expected_mac);
            if !crate::cipher::constant_time_eq_32(&computed_mac, &exp_arr) {
                return Err(KeystoreError::InvalidPasswordOrCorruptData);
            }
        }

        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&self.nonce);

        let decrypted = decrypt_aes256_gcm(&key, &nonce_arr, &self.ciphertext)?;
        let entry: KeyEntry = serde_json::from_slice(&decrypted)?;
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_keystore_encrypt_decrypt_roundtrip() {
        let entry =
            KeyEntry::new("val-1".to_string(), "ed25519".to_string(), vec![0x42; 32]).unwrap();

        let wrapper = NativeKeystoreWrapper::encrypt(&entry, "SuperSecret123!").unwrap();
        assert_eq!(wrapper.version, 2);
        assert_eq!(wrapper.kdf, "argon2id");
        assert!(wrapper.mac.is_some());

        let decrypted = wrapper.decrypt("SuperSecret123!").unwrap();
        assert_eq!(decrypted, entry);

        // Wrong password fails
        assert!(wrapper.decrypt("WrongPassword123!").is_err());
    }

    #[test]
    fn native_keystore_tampered_mac_is_rejected() {
        let entry =
            KeyEntry::new("val-1".to_string(), "ed25519".to_string(), vec![0x42; 32]).unwrap();

        let mut wrapper = NativeKeystoreWrapper::encrypt(&entry, "SuperSecret123!").unwrap();
        wrapper.mac = Some("deadbeef".to_string()); // invalid length
        assert!(wrapper.decrypt("SuperSecret123!").is_err());

        wrapper.mac = Some("00".repeat(32)); // wrong MAC
        assert!(wrapper.decrypt("SuperSecret123!").is_err());
    }
}
