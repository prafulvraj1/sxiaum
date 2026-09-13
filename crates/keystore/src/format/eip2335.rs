use crate::cipher::{apply_aes128_ctr, compute_eip2335_checksum, verify_eip2335_checksum};
use crate::error::{KeystoreError, Result};
use crate::kdf::derive_pbkdf2_sha256;
use crate::{validate_bls12_381_secret_key, KeyEntry};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// EIP-2335 v4 standard keystore container for BLS12-381 validator keys.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335Keystore {
    pub crypto: Eip2335Crypto,
    pub description: String,
    pub pubkey: String,
    pub path: String,
    pub uuid: String,
    pub version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335Crypto {
    pub kdf: Eip2335Kdf,
    pub checksum: Eip2335Checksum,
    pub cipher: Eip2335Cipher,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335Kdf {
    pub function: String,
    pub params: Eip2335KdfParams,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335KdfParams {
    pub dklen: u32,
    pub c: u32,
    pub prf: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335Checksum {
    pub function: String,
    pub params: serde_json::Value,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335Cipher {
    pub function: String,
    pub params: Eip2335CipherParams,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Eip2335CipherParams {
    pub iv: String,
}

impl Eip2335Keystore {
    /// Encrypt a BLS12-381 private key (32 bytes) according to EIP-2335 specification.
    pub fn encrypt(
        secret_key_bytes: &[u8; 32],
        public_key_hex: &str,
        password: &str,
        path: Option<&str>,
        description: Option<&str>,
    ) -> Result<Self> {
        validate_bls12_381_secret_key(secret_key_bytes)?;

        let mut salt_bytes = [0u8; 32];
        let mut iv_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        OsRng.fill_bytes(&mut iv_bytes);

        // Standard EIP-2335 PBKDF2 count (matches the Lighthouse / eth2 reference).
        let iterations = 262_144;
        let dk = derive_pbkdf2_sha256(password, &salt_bytes, iterations)?;

        let mut enc_key = [0u8; 16];
        let mut mac_key = [0u8; 16];
        enc_key.copy_from_slice(&dk[0..16]);
        mac_key.copy_from_slice(&dk[16..32]);

        let ciphertext = apply_aes128_ctr(&enc_key, &iv_bytes, secret_key_bytes)?;
        let checksum_bytes = compute_eip2335_checksum(&mac_key, &ciphertext);

        Ok(Self {
            crypto: Eip2335Crypto {
                kdf: Eip2335Kdf {
                    function: "pbkdf2".to_string(),
                    params: Eip2335KdfParams {
                        dklen: 32,
                        c: iterations,
                        prf: "hmac-sha256".to_string(),
                        salt: hex::encode(salt_bytes),
                    },
                    message: String::new(),
                },
                checksum: Eip2335Checksum {
                    function: "sha256".to_string(),
                    params: serde_json::json!({}),
                    message: hex::encode(checksum_bytes),
                },
                cipher: Eip2335Cipher {
                    function: "aes-128-ctr".to_string(),
                    params: Eip2335CipherParams {
                        iv: hex::encode(iv_bytes),
                    },
                    message: hex::encode(&*ciphertext),
                },
            },
            description: description
                .unwrap_or("SXIAUM BLS12-381 Validator Key")
                .to_string(),
            pubkey: public_key_hex.trim_start_matches("0x").to_string(),
            path: path.unwrap_or("m/12381/3600/0/0/0").to_string(),
            uuid: super::generate_uuid_v4(),
            version: 4,
        })
    }

    /// Decrypt the EIP-2335 keystore and recover the 32-byte private key.
    pub fn decrypt(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        if self.version != 4 {
            return Err(KeystoreError::UnsupportedVersion(self.version as u8));
        }

        if self.crypto.kdf.function != "pbkdf2" {
            return Err(KeystoreError::UnsupportedKdf(
                self.crypto.kdf.function.clone(),
            ));
        }

        if self.crypto.kdf.params.dklen != 32 {
            return Err(KeystoreError::CorruptedKeystore(
                "eip2335".into(),
                format!(
                    "invalid dklen {} (must be 32)",
                    self.crypto.kdf.params.dklen
                ),
            ));
        }

        if self.crypto.kdf.params.prf != "hmac-sha256" {
            return Err(KeystoreError::CorruptedKeystore(
                "eip2335".into(),
                format!("unsupported PRF {}", self.crypto.kdf.params.prf),
            ));
        }

        if self.crypto.cipher.function != "aes-128-ctr" {
            return Err(KeystoreError::UnsupportedCipher(
                self.crypto.cipher.function.clone(),
            ));
        }

        let salt = hex::decode(&self.crypto.kdf.params.salt).map_err(|e| {
            KeystoreError::CorruptedKeystore("eip2335".into(), format!("bad salt: {e}"))
        })?;

        let dk = derive_pbkdf2_sha256(password, &salt, self.crypto.kdf.params.c)?;

        let mut enc_key = [0u8; 16];
        let mut mac_key = [0u8; 16];
        enc_key.copy_from_slice(&dk[0..16]);
        mac_key.copy_from_slice(&dk[16..32]);

        let ciphertext = hex::decode(&self.crypto.cipher.message).map_err(|e| {
            KeystoreError::CorruptedKeystore("eip2335".into(), format!("bad ciphertext: {e}"))
        })?;

        let expected_checksum = hex::decode(&self.crypto.checksum.message).map_err(|e| {
            KeystoreError::CorruptedKeystore("eip2335".into(), format!("bad checksum: {e}"))
        })?;

        if expected_checksum.len() != 32 {
            return Err(KeystoreError::CorruptedKeystore(
                "eip2335".into(),
                "invalid checksum length".into(),
            ));
        }

        let mut checksum_arr = [0u8; 32];
        checksum_arr.copy_from_slice(&expected_checksum);

        // Fast constant-time checksum verification before decrypting
        if !verify_eip2335_checksum(&mac_key, &ciphertext, &checksum_arr) {
            return Err(KeystoreError::InvalidPasswordOrCorruptData);
        }

        let iv = hex::decode(&self.crypto.cipher.params.iv).map_err(|e| {
            KeystoreError::CorruptedKeystore("eip2335".into(), format!("bad iv: {e}"))
        })?;

        if iv.len() != 16 {
            return Err(KeystoreError::CorruptedKeystore(
                "eip2335".into(),
                "invalid iv length".into(),
            ));
        }

        let mut iv_arr = [0u8; 16];
        iv_arr.copy_from_slice(&iv);

        let plaintext = apply_aes128_ctr(&enc_key, &iv_arr, &ciphertext)?;
        if plaintext.len() != 32 {
            return Err(KeystoreError::InvalidKeyLength {
                expected: 32,
                actual: plaintext.len(),
            });
        }

        validate_bls12_381_secret_key(&plaintext)?;

        let mut secret_key = Zeroizing::new([0u8; 32]);
        secret_key.copy_from_slice(&plaintext[0..32]);
        Ok(secret_key)
    }

    /// Convert into standard SXIAUM `KeyEntry`.
    pub fn to_key_entry(&self, password: &str, id: &str) -> Result<KeyEntry> {
        let secret = self.decrypt(password)?;
        KeyEntry::new(
            id.to_string(),
            crate::KEY_TYPE_BLS.to_string(),
            secret.to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip2335_encrypt_decrypt_roundtrip() {
        // Valid BLS scalar (1)
        let mut secret_key = [0u8; 32];
        secret_key[0] = 1;
        let pubkey_hex = "b22f281e05ddbcba278dfaeefcfbca0dd80e2fc5230c1d1a8e2ee2a106822c9bfa0fb0e3b97b0a701460980d9ab18765";
        let password = "TestValidatorPassword!123";

        let keystore = Eip2335Keystore::encrypt(
            &secret_key,
            pubkey_hex,
            password,
            Some("m/12381/3600/0/0/0"),
            Some("Validator 0"),
        )
        .unwrap();

        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "pbkdf2");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");

        let decrypted = keystore.decrypt(password).unwrap();
        assert_eq!(*decrypted, secret_key);

        // Wrong password must fail
        assert!(keystore.decrypt("WrongPassword").is_err());
    }

    #[test]
    fn eip2335_rejects_bad_dklen_and_kdf() {
        let mut secret_key = [0u8; 32];
        secret_key[0] = 2;
        let keystore =
            Eip2335Keystore::encrypt(&secret_key, "aa00", "TestValidatorPassword!123", None, None)
                .unwrap();

        // Hostile/foreign dklen must be rejected before any KDF work.
        let mut bad_dklen = keystore.clone();
        bad_dklen.crypto.kdf.params.dklen = 64;
        assert!(matches!(
            bad_dklen.decrypt("TestValidatorPassword!123"),
            Err(KeystoreError::CorruptedKeystore(_, _))
        ));

        // scrypt keystores are rejected upfront with UnsupportedKdf.
        let mut scrypt_ks = keystore.clone();
        scrypt_ks.crypto.kdf.function = "scrypt".to_string();
        assert!(matches!(
            scrypt_ks.decrypt("TestValidatorPassword!123"),
            Err(KeystoreError::UnsupportedKdf(_))
        ));

        // Non-standard version is rejected.
        let mut bad_version = keystore;
        bad_version.version = 5;
        assert!(matches!(
            bad_version.decrypt("TestValidatorPassword!123"),
            Err(KeystoreError::UnsupportedVersion(5))
        ));
    }

    #[test]
    fn eip2335_uuid_is_valid_v4() {
        let mut secret_key = [0u8; 32];
        secret_key[0] = 3;
        let keystore =
            Eip2335Keystore::encrypt(&secret_key, "bb01", "TestValidatorPassword!123", None, None)
                .unwrap();
        assert_eq!(keystore.uuid.len(), 36);
        assert!(keystore
            .uuid
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-'));
    }
}
