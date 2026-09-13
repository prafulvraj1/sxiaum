use crate::cipher::{apply_aes128_ctr, compute_web3_mac, verify_web3_mac};
use crate::error::{KeystoreError, Result};
use crate::kdf::derive_pbkdf2_sha256;
use crate::{validate_secp256k1_secret_key, KeyEntry};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Web3 Secret Storage Definition v3 JSON container for Ethereum/SXIAUM account keys.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Web3Keystore {
    pub address: String,
    pub crypto: Web3Crypto,
    pub id: String,
    pub version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Web3Crypto {
    pub cipher: String,
    pub cipherparams: Web3CipherParams,
    pub ciphertext: String,
    pub kdf: String,
    pub kdfparams: Web3KdfParams,
    pub mac: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Web3CipherParams {
    pub iv: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Web3KdfParams {
    pub c: u32,
    pub dklen: u32,
    pub prf: String,
    pub salt: String,
}

impl Web3Keystore {
    /// Encrypt a 32-byte account private key according to Web3 Secret Storage v3 specification.
    pub fn encrypt(secret_key_bytes: &[u8; 32], address_hex: &str, password: &str) -> Result<Self> {
        validate_secp256k1_secret_key(secret_key_bytes)?;

        let mut salt_bytes = [0u8; 32];
        let mut iv_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        OsRng.fill_bytes(&mut iv_bytes);

        // Matches the go-ethereum default PBKDF2 round count.
        let iterations = 100_000;
        let dk = derive_pbkdf2_sha256(password, &salt_bytes, iterations)?;

        let mut enc_key = [0u8; 16];
        let mut mac_key = [0u8; 16];
        enc_key.copy_from_slice(&dk[0..16]);
        mac_key.copy_from_slice(&dk[16..32]);

        let ciphertext = apply_aes128_ctr(&enc_key, &iv_bytes, secret_key_bytes)?;
        let mac_bytes = compute_web3_mac(&mac_key, &ciphertext);

        Ok(Self {
            address: address_hex.trim_start_matches("0x").to_ascii_lowercase(),
            crypto: Web3Crypto {
                cipher: "aes-128-ctr".to_string(),
                cipherparams: Web3CipherParams {
                    iv: hex::encode(iv_bytes),
                },
                ciphertext: hex::encode(&*ciphertext),
                kdf: "pbkdf2".to_string(),
                kdfparams: Web3KdfParams {
                    c: iterations,
                    dklen: 32,
                    prf: "hmac-sha256".to_string(),
                    salt: hex::encode(salt_bytes),
                },
                mac: hex::encode(mac_bytes),
            },
            id: super::generate_uuid_v4(),
            version: 3,
        })
    }

    /// Decrypt the Web3 v3 keystore and recover the 32-byte private key.
    pub fn decrypt(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        if self.version != 3 {
            return Err(KeystoreError::UnsupportedVersion(self.version as u8));
        }

        if self.crypto.kdf != "pbkdf2" {
            return Err(KeystoreError::UnsupportedKdf(self.crypto.kdf.clone()));
        }

        if self.crypto.kdfparams.dklen != 32 {
            return Err(KeystoreError::CorruptedKeystore(
                "web3_v3".into(),
                format!("invalid dklen {} (must be 32)", self.crypto.kdfparams.dklen),
            ));
        }

        if self.crypto.kdfparams.prf != "hmac-sha256" {
            return Err(KeystoreError::CorruptedKeystore(
                "web3_v3".into(),
                format!("unsupported PRF {}", self.crypto.kdfparams.prf),
            ));
        }

        if self.crypto.cipher != "aes-128-ctr" {
            return Err(KeystoreError::UnsupportedCipher(self.crypto.cipher.clone()));
        }

        let salt = hex::decode(&self.crypto.kdfparams.salt).map_err(|e| {
            KeystoreError::CorruptedKeystore("web3_v3".into(), format!("bad salt: {e}"))
        })?;

        let dk = derive_pbkdf2_sha256(password, &salt, self.crypto.kdfparams.c)?;

        let mut enc_key = [0u8; 16];
        let mut mac_key = [0u8; 16];
        enc_key.copy_from_slice(&dk[0..16]);
        mac_key.copy_from_slice(&dk[16..32]);

        let ciphertext = hex::decode(&self.crypto.ciphertext).map_err(|e| {
            KeystoreError::CorruptedKeystore("web3_v3".into(), format!("bad ciphertext: {e}"))
        })?;

        let expected_mac = hex::decode(&self.crypto.mac).map_err(|e| {
            KeystoreError::CorruptedKeystore("web3_v3".into(), format!("bad mac: {e}"))
        })?;

        if expected_mac.len() != 32 {
            return Err(KeystoreError::CorruptedKeystore(
                "web3_v3".into(),
                "invalid mac length".into(),
            ));
        }

        let mut mac_arr = [0u8; 32];
        mac_arr.copy_from_slice(&expected_mac);

        // Fast constant-time MAC check before CTR decrypt
        if !verify_web3_mac(&mac_key, &ciphertext, &mac_arr) {
            return Err(KeystoreError::InvalidPasswordOrCorruptData);
        }

        let iv = hex::decode(&self.crypto.cipherparams.iv).map_err(|e| {
            KeystoreError::CorruptedKeystore("web3_v3".into(), format!("bad iv: {e}"))
        })?;

        if iv.len() != 16 {
            return Err(KeystoreError::CorruptedKeystore(
                "web3_v3".into(),
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

        validate_secp256k1_secret_key(&plaintext)?;

        let mut secret_key = Zeroizing::new([0u8; 32]);
        secret_key.copy_from_slice(&plaintext[0..32]);
        Ok(secret_key)
    }

    /// Convert into standard SXIAUM `KeyEntry`.
    pub fn to_key_entry(&self, password: &str) -> Result<KeyEntry> {
        let secret = self.decrypt(password)?;
        let id = format!("account-{}", self.address);
        KeyEntry::new(id, crate::KEY_TYPE_ACCOUNT.to_string(), secret.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web3_v3_encrypt_decrypt_roundtrip() {
        let mut secret_key = [0u8; 32];
        secret_key[31] = 0x88;
        let address = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
        let password = "SecretAccountPassword!456";

        let keystore = Web3Keystore::encrypt(&secret_key, address, password).unwrap();
        assert_eq!(keystore.version, 3);
        assert_eq!(keystore.crypto.kdf, "pbkdf2");
        assert_eq!(keystore.crypto.cipher, "aes-128-ctr");

        let decrypted = keystore.decrypt(password).unwrap();
        assert_eq!(*decrypted, secret_key);

        // Wrong password fails MAC verification
        assert!(keystore.decrypt("WrongPassword").is_err());
    }

    #[test]
    fn web3_v3_rejects_bad_dklen_and_kdf() {
        let mut secret_key = [0u8; 32];
        secret_key[31] = 0x77;
        let keystore = Web3Keystore::encrypt(
            &secret_key,
            "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            "SecretAccountPassword!456",
        )
        .unwrap();

        // Hostile dklen must be rejected before any KDF work.
        let mut bad_dklen = keystore.clone();
        bad_dklen.crypto.kdfparams.dklen = 64;
        assert!(bad_dklen.decrypt("SecretAccountPassword!456").is_err());

        // scrypt keystores are rejected with UnsupportedKdf.
        let mut scrypt_ks = keystore.clone();
        scrypt_ks.crypto.kdf = "scrypt".to_string();
        assert!(matches!(
            scrypt_ks.decrypt("SecretAccountPassword!456"),
            Err(KeystoreError::UnsupportedKdf(_))
        ));

        // Non-v3 versions are rejected.
        let mut bad_version = keystore;
        bad_version.version = 1;
        assert!(matches!(
            bad_version.decrypt("SecretAccountPassword!456"),
            Err(KeystoreError::UnsupportedVersion(1))
        ));
    }
}
