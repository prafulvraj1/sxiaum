//! Production validator registration and staking deposit payload generator.

use crate::error::{KeytoolError, Result};
use serde::{Deserialize, Serialize};
use sxiaum_crypto::bls::{create_proof_of_possession, verify_proof_of_possession, BlsPrivateKey};
use sxiaum_types::validator::BLS_POP_LEN;

/// Validator staking deposit payload submitted to the on-chain consensus contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorDepositPayload {
    /// Consensus BLS12-381 public key (48 bytes in hex).
    pub pubkey: String,
    /// Withdrawal credentials (e.g. 20-byte or 32-byte address in hex).
    pub withdrawal_credentials: String,
    /// Amount of SXIAUM tokens deposited (e.g., "32.0").
    pub amount: String,
    /// RFC 9380 Proof-of-Possession signature (96 bytes in hex).
    pub proof_of_possession: String,
    /// Unix timestamp of payload generation.
    pub timestamp_utc: u64,
}

/// Validate that a withdrawal credentials string is well-formed hex and standard length (20 or 32 bytes).
pub fn validate_withdrawal_address(address_str: &str) -> Result<String> {
    let clean = address_str
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if clean.is_empty() {
        return Err(KeytoolError::InvalidFormat(
            "withdrawal address cannot be empty".to_string(),
        ));
    }

    let decoded = hex::decode(clean).map_err(|e| {
        KeytoolError::InvalidFormat(format!("withdrawal address is not valid hex: {e}"))
    })?;

    if decoded.len() != 20 && decoded.len() != 32 {
        return Err(KeytoolError::InvalidFormat(format!(
            "invalid withdrawal credentials length: expected 20 or 32 bytes, got {}",
            decoded.len()
        )));
    }

    Ok(format!("0x{}", hex::encode(decoded)))
}

/// Maximum deposit amount in whole SXIAUM tokens.
const MAX_DEPOSIT_WHOLE: u128 = 100_000_000;

/// Maximum number of fractional decimal places accepted for a deposit amount.
const MAX_AMOUNT_DECIMALS: usize = 9;

/// Validate and canonically normalize a deposit amount string.
///
/// Money handling must never go through binary floats: this parser accepts
/// only the strict grammar `[0-9]+(\.[0-9]{1,9})?`, rejects scientific
/// notation, signs, whitespace-embedded input, and out-of-range values, and
/// returns a canonical form with leading zeros stripped and trailing
/// fractional zeros removed (e.g. `"0032.500"` → `"32.5"`).
pub fn validate_deposit_amount(amount_str: &str) -> Result<String> {
    let clean = amount_str.trim();
    if clean.is_empty() {
        return Err(KeytoolError::InvalidFormat(
            "deposit amount cannot be empty".to_string(),
        ));
    }

    let (whole_str, frac_str) = match clean.split_once('.') {
        None => (clean, ""),
        Some((w, f)) => (w, f),
    };

    if whole_str.is_empty() && frac_str.is_empty() {
        return Err(KeytoolError::InvalidFormat(format!(
            "invalid deposit amount '{clean}'"
        )));
    }
    if whole_str.len() > 1 && whole_str.starts_with('0') {
        return Err(KeytoolError::InvalidFormat(format!(
            "deposit amount '{clean}' has non-canonical leading zeros"
        )));
    }
    if !whole_str.bytes().all(|b| b.is_ascii_digit())
        || !frac_str.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(KeytoolError::InvalidFormat(format!(
            "invalid deposit amount '{clean}': only plain decimal digits are allowed \
             (no signs, scientific notation, or separators)"
        )));
    }
    if frac_str.len() > MAX_AMOUNT_DECIMALS {
        return Err(KeytoolError::InvalidFormat(format!(
            "deposit amount '{clean}' exceeds maximum precision of {MAX_AMOUNT_DECIMALS} decimal places"
        )));
    }

    // Reject the all-zero value ("0", "0.000").
    if whole_str.bytes().all(|b| b == b'0') && frac_str.bytes().all(|b| b == b'0') {
        return Err(KeytoolError::InvalidFormat(format!(
            "deposit amount must be positive and non-zero (got {clean})"
        )));
    }

    let whole: u128 = if whole_str.is_empty() {
        0
    } else {
        whole_str.parse().map_err(|_| {
            KeytoolError::InvalidFormat(format!("deposit amount '{clean}' is out of range"))
        })?
    };
    if whole > MAX_DEPOSIT_WHOLE {
        return Err(KeytoolError::InvalidFormat(format!(
            "deposit amount exceeds maximum allowed bound of {MAX_DEPOSIT_WHOLE} (got {clean})"
        )));
    }

    // Canonicalize: strip leading zeros from the whole part and trailing zeros
    // from the fraction.
    let whole_canonical = whole.to_string();
    let frac_trimmed = frac_str.trim_end_matches('0');
    Ok(if frac_trimmed.is_empty() {
        whole_canonical
    } else {
        format!("{whole_canonical}.{frac_trimmed}")
    })
}

/// Create a validator deposit payload from a BLS private key and verify its PoP before returning.
pub fn create_validator_deposit_payload(
    secret_key_bytes: &[u8],
    withdrawal_address: &str,
    amount: &str,
) -> Result<ValidatorDepositPayload> {
    // 1. Validate BLS secret key scalar and derive the public key via the
    //    shared helper (identical derivation to PoP generation and mnemonic
    //    derive paths).
    let public_key = crate::generator::bls_public_key_from_secret(secret_key_bytes)?;

    // 2. Validate withdrawal address & amount
    let normalized_withdrawal = validate_withdrawal_address(withdrawal_address)?;
    let normalized_amount = validate_deposit_amount(amount)?;

    let secret = BlsPrivateKey(secret_key_bytes.to_vec());

    let pop = create_proof_of_possession(&secret, &public_key)
        .map_err(|e| KeytoolError::Crypto(e.to_string()))?;

    if pop.0.len() != BLS_POP_LEN {
        return Err(KeytoolError::Crypto(format!(
            "Generated PoP signature invalid length: expected {BLS_POP_LEN} bytes, got {}",
            pop.0.len()
        )));
    }

    // Pre-verify PoP to ensure mathematical validity
    let valid = verify_proof_of_possession(&public_key, &pop);
    if !valid {
        return Err(KeytoolError::Crypto(
            "Proof-of-Possession verification failed against derived public key".to_string(),
        ));
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| KeytoolError::Crypto(format!("system clock before UNIX epoch: {e}")))?
        .as_secs();

    Ok(ValidatorDepositPayload {
        pubkey: hex::encode(&public_key.0),
        withdrawal_credentials: normalized_withdrawal,
        amount: normalized_amount,
        proof_of_possession: hex::encode(&pop.0),
        timestamp_utc: timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_deposit_payload_creation() {
        let mut secret = [0u8; 32];
        secret[0] = 7;
        let withdrawal = "0x1122334455667788990011223344556677889900";

        let payload = create_validator_deposit_payload(&secret, withdrawal, "32.0").unwrap();
        // Amount is canonically normalized: trailing fractional zero removed.
        assert_eq!(payload.amount, "32");
        assert_eq!(payload.withdrawal_credentials, withdrawal);
        assert_eq!(payload.pubkey.len(), 96); // 48 bytes hex
        assert_eq!(payload.proof_of_possession.len(), 192); // 96 bytes hex
    }

    #[test]
    fn test_rejects_invalid_withdrawal_address() {
        let mut secret = [0u8; 32];
        secret[0] = 7;

        assert!(create_validator_deposit_payload(&secret, "", "32").is_err());
        assert!(create_validator_deposit_payload(&secret, "not-hex", "32").is_err());
        // Wrong length (2 bytes).
        assert!(create_validator_deposit_payload(&secret, "0x1234", "32").is_err());
        // Wrong length (21 bytes).
        let bad21 = format!("0x{}", "11".repeat(21));
        assert!(create_validator_deposit_payload(&secret, &bad21, "32").is_err());
    }

    #[test]
    fn test_accepts_20_and_32_byte_withdrawal_addresses() {
        let secret = [7u8; 32];
        let w20 = "1122334455667788990011223344556677889900";
        let w32 = "aa".repeat(32);

        let p20 = create_validator_deposit_payload(&secret, w20, "1.5").unwrap();
        assert_eq!(p20.withdrawal_credentials, format!("0x{w20}"));

        let p32 = create_validator_deposit_payload(&secret, &w32, "1.5").unwrap();
        assert_eq!(p32.withdrawal_credentials, format!("0x{w32}"));

        // Uppercase hex is accepted and lower-cased on output.
        let upper = format!("0x{}", w20.to_ascii_uppercase());
        let pu = create_validator_deposit_payload(&secret, &upper, "1.5").unwrap();
        assert_eq!(pu.withdrawal_credentials, format!("0x{w20}"));
    }

    #[test]
    fn test_rejects_invalid_amount() {
        let mut secret = [0u8; 32];
        secret[0] = 7;
        let withdrawal = "0x1122334455667788990011223344556677889900";

        for bad in [
            "",
            "0",
            "0.000",
            "-10.0",
            "abc",
            "1e5",
            "+32",
            "1,000",
            "0x20",
            "0032",
            "inf",
            "nan",
            ".",
            "1.1234567890", // > 9 decimal places
            "  ",
        ] {
            assert!(
                create_validator_deposit_payload(&secret, withdrawal, bad).is_err(),
                "amount '{bad}' must be rejected"
            );
        }
    }

    #[test]
    fn test_amount_canonicalization_and_bounds() {
        assert_eq!(validate_deposit_amount("32.500").unwrap(), "32.5");
        assert_eq!(validate_deposit_amount(".5").unwrap(), "0.5");
        assert_eq!(validate_deposit_amount("32.").unwrap(), "32");
        assert_eq!(validate_deposit_amount("100000000").unwrap(), "100000000");

        // One micro-unit above the maximum whole-token bound.
        assert!(validate_deposit_amount("100000001").is_err());
    }
}
