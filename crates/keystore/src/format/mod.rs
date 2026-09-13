pub mod eip2335;
pub mod native;
pub mod web3_v3;

pub use eip2335::Eip2335Keystore;
pub use native::NativeKeystoreWrapper;
pub use web3_v3::Web3Keystore;

use crate::error::{KeystoreError, Result};
use crate::KeyEntry;
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate a random RFC 4122 version 4 UUID string (shared by keystore formats).
pub(crate) fn generate_uuid_v4() -> String {
    let mut u = [0u8; 16];
    OsRng.fill_bytes(&mut u);
    u[6] = (u[6] & 0x0f) | 0x40; // version 4
    u[8] = (u[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    )
}

/// Automatically detect the format of raw JSON bytes and decrypt to a `KeyEntry`.
///
/// Detection order:
/// 1. Native SXIAUM wrapper (v2 Argon2id, or legacy PBKDF2 outside production)
/// 2. EIP-2335 (BLS12-381 validator keys, version 4)
/// 3. Web3 Secret Storage v3 (account keys)
/// 4. Raw unencrypted `KeyEntry` — forbidden when `SXIAUM_ENV=production`
pub fn detect_and_decrypt(data: &[u8], password: &str, default_id: &str) -> Result<KeyEntry> {
    if data.is_empty() {
        return Err(KeystoreError::CorruptedKeystore(
            default_id.to_string(),
            "empty keystore file".to_string(),
        ));
    }

    if data.len() > crate::MAX_KEY_DATA_SIZE {
        return Err(KeystoreError::InvalidKeyLength {
            expected: crate::MAX_KEY_DATA_SIZE,
            actual: data.len(),
        });
    }

    // 1. Try parsing as NativeKeystoreWrapper (v2 Argon2id or legacy PBKDF2)
    if let Ok(wrapper) = serde_json::from_slice::<NativeKeystoreWrapper>(data) {
        if !wrapper.salt.is_empty() && !wrapper.nonce.is_empty() && !wrapper.ciphertext.is_empty() {
            return wrapper.decrypt(password);
        }
    }

    // 2. Try parsing as EIP-2335 Keystore (v4)
    if let Ok(eip) = serde_json::from_slice::<Eip2335Keystore>(data) {
        if eip.version == 4 && eip.crypto.cipher.function == "aes-128-ctr" {
            return eip.to_key_entry(password, default_id);
        }
    }

    // 3. Try parsing as Web3 v3 Keystore (v3)
    if let Ok(w3) = serde_json::from_slice::<Web3Keystore>(data) {
        if w3.version == 3 {
            return w3.to_key_entry(password);
        }
    }

    // 4. Try parsing as raw unencrypted KeyEntry (allowed only in non-production environments)
    if let Ok(entry) = serde_json::from_slice::<KeyEntry>(data) {
        if crate::password::is_production() {
            return Err(KeystoreError::PlaintextForbiddenInProduction);
        }
        return Ok(entry);
    }

    Err(KeystoreError::CorruptedKeystore(
        default_id.to_string(),
        "unrecognized keystore JSON format".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v4_format_is_valid() {
        for _ in 0..32 {
            let id = generate_uuid_v4();
            assert_eq!(id.len(), 36);
            let parts: Vec<&str> = id.split('-').collect();
            assert_eq!(parts.len(), 5);
            assert_eq!(
                parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
                vec![8, 4, 4, 4, 12]
            );
            assert!(id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
            // Version nibble must be '4'
            assert!(parts[2].starts_with('4'));
            // Variant nibble must be 8,9,a,b
            assert!(matches!(
                parts[3].chars().next().unwrap(),
                '8' | '9' | 'a' | 'b'
            ));
        }
    }

    #[test]
    fn uuid_v4_values_are_unique() {
        let a = generate_uuid_v4();
        let b = generate_uuid_v4();
        assert_ne!(a, b);
    }
}
