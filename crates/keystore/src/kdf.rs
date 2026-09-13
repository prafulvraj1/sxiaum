use crate::error::{KeystoreError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Standard Argon2id configuration for mainnet SXIAUM v2 keystores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: crate::ARGON2_MEMORY_KIB,
            time_cost: crate::ARGON2_TIME_COST,
            parallelism: crate::ARGON2_PARALLELISM,
        }
    }
}

/// Derive a 32-byte key using Argon2id.
pub fn derive_argon2id(
    password: &str,
    salt: &[u8],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    if !(16..=64).contains(&salt.len()) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!("invalid salt length for Argon2id: {}", salt.len()),
        ));
    }

    if !(1024..=1024 * 1024).contains(&params.memory_kib) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!(
                "Argon2 memory_kib out of safe bounds: {}",
                params.memory_kib
            ),
        ));
    }

    if !(1..=100).contains(&params.time_cost) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!("Argon2 time_cost out of safe bounds: {}", params.time_cost),
        ));
    }

    if !(1..=16).contains(&params.parallelism) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!(
                "Argon2 parallelism out of safe bounds: {}",
                params.parallelism
            ),
        ));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| KeystoreError::Generic(format!("Argon2 params error: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| KeystoreError::Generic(format!("Argon2 key derivation failed: {e}")))?;

    Ok(key)
}

/// Derive a 32-byte key using PBKDF2-HMAC-SHA256.
pub fn derive_pbkdf2_sha256(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if !(16..=64).contains(&salt.len()) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!("invalid salt length for PBKDF2: {}", salt.len()),
        ));
    }

    if !(1000..=5_000_000).contains(&iterations) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!("PBKDF2 iterations out of bounds: {iterations}"),
        ));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, key.as_mut())
        .map_err(|e| KeystoreError::Generic(format!("PBKDF2-HMAC-SHA256 error: {e:?}")))?;

    Ok(key)
}

/// Derive arbitrary length key using PBKDF2-HMAC-SHA512 (used in BIP-39 mnemonic seed generation).
pub fn derive_pbkdf2_sha512(
    password: &str,
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if !(1000..=5_000_000).contains(&iterations) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!("PBKDF2-SHA512 iterations out of bounds: {iterations}"),
        ));
    }

    // Bound the derived length to prevent memory exhaustion from hostile inputs.
    if !(16..=256).contains(&out_len) {
        return Err(KeystoreError::CorruptedKeystore(
            "kdf".into(),
            format!("PBKDF2-SHA512 output length out of bounds: {out_len}"),
        ));
    }

    let mut key = Zeroizing::new(vec![0u8; out_len]);
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, iterations, key.as_mut_slice())
        .map_err(|e| KeystoreError::Generic(format!("PBKDF2-HMAC-SHA512 error: {e:?}")))?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_derives_consistently() {
        let salt = [42u8; 16];
        let params = Argon2Params {
            memory_kib: 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let key1 = derive_argon2id("test-password", &salt, &params).unwrap();
        let key2 = derive_argon2id("test-password", &salt, &params).unwrap();
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn pbkdf2_sha256_derives_consistently() {
        let salt = [7u8; 16];
        let key1 = derive_pbkdf2_sha256("test-password", &salt, 1000).unwrap();
        let key2 = derive_pbkdf2_sha256("test-password", &salt, 1000).unwrap();
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn rejects_out_of_bounds_kdf_inputs() {
        let salt = [1u8; 16];

        // Salt length bounds
        assert!(derive_argon2id("pw-12chars", &salt[..8], &Argon2Params::default()).is_err());
        assert!(derive_pbkdf2_sha256("pw-12chars", &salt[..8], 1000).is_err());

        // Iteration bounds
        assert!(derive_pbkdf2_sha256("pw-12chars", &salt, 999).is_err());
        assert!(derive_pbkdf2_sha512("pw-12chars", &salt, 5_000_001, 64).is_err());

        // Output length bounds
        assert!(derive_pbkdf2_sha512("pw-12chars", &salt, 2048, 8).is_err());
        assert!(derive_pbkdf2_sha512("pw-12chars", &salt, 2048, 1024).is_err());

        // Argon2 parameter bounds
        let bad_mem = Argon2Params {
            memory_kib: 512,
            ..Default::default()
        };
        assert!(derive_argon2id("pw-12chars", &salt, &bad_mem).is_err());
        let bad_time = Argon2Params {
            time_cost: 200,
            ..Default::default()
        };
        assert!(derive_argon2id("pw-12chars", &salt, &bad_time).is_err());
        let bad_lanes = Argon2Params {
            parallelism: 32,
            ..Default::default()
        };
        assert!(derive_argon2id("pw-12chars", &salt, &bad_lanes).is_err());
    }
}
