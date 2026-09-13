use crate::error::{KeystoreError, Result};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type Aes128Ctr128BE = ctr::Ctr128BE<aes::Aes128>;

/// Encrypt plaintext using AES-256-GCM (used in native SXIAUM v2 keystores).
pub fn encrypt_aes256_gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Generic(format!("Failed to init AES-256-GCM: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| KeystoreError::Generic(format!("AES-256-GCM encryption failed: {e:?}")))?;
    Ok(ciphertext)
}

/// Decrypt ciphertext using AES-256-GCM (authenticated encryption with integrated tag verification).
pub fn decrypt_aes256_gcm(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Generic(format!("Failed to init AES-256-GCM: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| KeystoreError::InvalidPasswordOrCorruptData)?;
    Ok(Zeroizing::new(decrypted))
}

/// Encrypt or decrypt data using AES-128-CTR (128-bit big-endian counter; standard in EIP-2335 and Web3 v3).
pub fn apply_aes128_ctr(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut cipher = Aes128Ctr128BE::new(key.into(), iv.into());
    let mut buffer = Zeroizing::new(data.to_vec());
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

/// Compute SHA-256 checksum for EIP-2335 keystores: `SHA256(dk[16..32] || ciphertext)`.
pub fn compute_eip2335_checksum(mac_key: &[u8; 16], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(mac_key);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Verify SHA-256 checksum for EIP-2335 keystores in constant time.
pub fn verify_eip2335_checksum(
    mac_key: &[u8; 16],
    ciphertext: &[u8],
    expected_checksum: &[u8; 32],
) -> bool {
    let computed = compute_eip2335_checksum(mac_key, ciphertext);
    constant_time_eq_32(&computed, expected_checksum)
}

/// Compute Keccak-256 MAC for Web3 Secret Storage v3 keystores: `Keccak256(dk[16..32] || ciphertext)`.
pub fn compute_web3_mac(mac_key: &[u8; 16], ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(mac_key);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Verify Keccak-256 MAC for Web3 Secret Storage v3 keystores in constant time.
pub fn verify_web3_mac(mac_key: &[u8; 16], ciphertext: &[u8], expected_mac: &[u8; 32]) -> bool {
    let computed = compute_web3_mac(mac_key, ciphertext);
    constant_time_eq_32(&computed, expected_mac)
}

/// Constant-time comparison for 32-byte arrays to prevent timing side-channel attacks.
#[inline]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time comparison for arbitrary byte slices.
#[inline]
pub fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes256_gcm_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x99u8; 12];
        let plaintext = b"secret-blockchain-validator-key-12345";

        let ciphertext = encrypt_aes256_gcm(&key, &nonce, plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);

        let decrypted = decrypt_aes256_gcm(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);

        // Tampered ciphertext fails authentication
        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(decrypt_aes256_gcm(&key, &nonce, &tampered).is_err());
    }

    #[test]
    fn aes128_ctr_roundtrip() {
        let key = [0x22u8; 16];
        let iv = [0x44u8; 16];
        let plaintext = b"hello-eip2335-and-web3-keystore";

        let ciphertext = apply_aes128_ctr(&key, &iv, plaintext).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = apply_aes128_ctr(&key, &iv, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn checksum_verification_works() {
        let mac_key = [0x11u8; 16];
        let ciphertext = b"encrypted-data-blob";
        let checksum = compute_eip2335_checksum(&mac_key, ciphertext);

        assert!(verify_eip2335_checksum(&mac_key, ciphertext, &checksum));

        let wrong_key = [0x12u8; 16];
        assert!(!verify_eip2335_checksum(&wrong_key, ciphertext, &checksum));
    }

    #[test]
    fn web3_mac_verification_works() {
        let mac_key = [0x33u8; 16];
        let ciphertext = b"web3-secret-storage-v3-payload";
        let mac = compute_web3_mac(&mac_key, ciphertext);

        assert!(verify_web3_mac(&mac_key, ciphertext, &mac));

        // Tampered ciphertext must fail MAC verification.
        let mut tampered = ciphertext.to_vec();
        tampered[0] ^= 0x80;
        assert!(!verify_web3_mac(&mac_key, &tampered, &mac));
    }

    #[test]
    fn constant_time_comparisons() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(constant_time_eq_32(&a, &b));
        assert!(!constant_time_eq_32(&a, &c));

        assert!(constant_time_eq_slice(
            b"x".repeat(64).as_slice(),
            b"x".repeat(64).as_slice()
        ));
        assert!(!constant_time_eq_slice(b"a", b"b"));
        assert!(!constant_time_eq_slice(b"abc", b"ab"));
    }
}
