//! Message signing and verification engine for Ed25519 and BLS12-381.

use crate::cli::KeyType;
use crate::error::{KeytoolError, Result};
use sxiaum_crypto::bls::{bls_sign, bls_verify, BlsPrivateKey, BlsPublicKey, BlsSignature};
use sxiaum_crypto::ed25519::{sign, verify};
use sxiaum_keystore::{validate_bls12_381_secret_key, validate_ed25519_secret_key};
use sxiaum_types::validator::{BLS_POP_LEN, BLS_PUBKEY_LEN};

/// Sign an arbitrary message using private key bytes.
pub fn sign_message(
    key_type: KeyType,
    private_key_bytes: &[u8],
    message_bytes: &[u8],
) -> Result<String> {
    match key_type {
        KeyType::Ed25519 => {
            validate_ed25519_secret_key(private_key_bytes)?;
            let mut priv_arr = [0u8; 32];
            priv_arr.copy_from_slice(private_key_bytes);
            let sig = sign(&priv_arr, message_bytes);
            Ok(hex::encode(sig.0))
        }
        KeyType::Bls => {
            validate_bls12_381_secret_key(private_key_bytes)?;
            let sk = BlsPrivateKey(private_key_bytes.to_vec());
            let sig =
                bls_sign(&sk, message_bytes).map_err(|e| KeytoolError::Crypto(e.to_string()))?;
            Ok(hex::encode(&sig.0))
        }
    }
}

/// Verify an arbitrary message signature against a public key.
pub fn verify_message_signature(
    key_type: KeyType,
    public_key_hex: &str,
    message_bytes: &[u8],
    signature_hex: &str,
) -> Result<bool> {
    let clean_pk = public_key_hex
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let clean_sig = signature_hex
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    let pub_bytes = hex::decode(clean_pk)?;
    let sig_bytes = hex::decode(clean_sig)?;

    match key_type {
        KeyType::Ed25519 => {
            if pub_bytes.len() != 32 {
                return Err(KeytoolError::Crypto(format!(
                    "Ed25519 public key must be 32 bytes (got {})",
                    pub_bytes.len()
                )));
            }
            if sig_bytes.len() != 64 {
                return Err(KeytoolError::Crypto(format!(
                    "Ed25519 signature must be 64 bytes (got {})",
                    sig_bytes.len()
                )));
            }
            let mut pub_arr = [0u8; 32];
            pub_arr.copy_from_slice(&pub_bytes);
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig_bytes);

            Ok(verify(&pub_arr, message_bytes, &sig_arr))
        }
        KeyType::Bls => {
            if pub_bytes.len() != BLS_PUBKEY_LEN {
                return Err(KeytoolError::Crypto(format!(
                    "BLS public key must be {BLS_PUBKEY_LEN} bytes (got {})",
                    pub_bytes.len()
                )));
            }
            if sig_bytes.len() != BLS_POP_LEN {
                return Err(KeytoolError::Crypto(format!(
                    "BLS signature must be {BLS_POP_LEN} bytes (got {})",
                    sig_bytes.len()
                )));
            }
            let pk = BlsPublicKey(pub_bytes);
            let sig = BlsSignature(sig_bytes);
            Ok(bls_verify(&pk, message_bytes, &sig))
        }
    }
}
