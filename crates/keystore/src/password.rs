use crate::error::{KeystoreError, Result};
use std::env;

/// Minimum passphrase length in development/test environments.
pub const MIN_PASSWORD_LEN_DEV: usize = 8;

/// Minimum passphrase length in production environments.
pub const MIN_PASSWORD_LEN_PROD: usize = 12;

/// Known weak/trivial dictionary passwords rejected in production.
const COMMON_WEAK_PASSWORDS: &[&str] = &[
    "password",
    "password123",
    "password1234",
    "123456789012",
    "admin12345678",
    "validator123",
    "sxiaumvalidator",
    "letmein12345",
    "changeme1234",
    "root12345678",
    "iloveyou1234",
];

/// Returns true if `SXIAUM_ENV=production` or `SXIAUM_SRS_MODE=production`.
pub fn is_production() -> bool {
    let env_val = env::var("SXIAUM_ENV").unwrap_or_default();
    let srs_val = env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    env_val.eq_ignore_ascii_case("production") || srs_val.eq_ignore_ascii_case("production")
}

/// Validate passphrase strength according to environment policy.
pub fn validate_password(password: &str) -> Result<()> {
    let min_len = if is_production() {
        MIN_PASSWORD_LEN_PROD
    } else {
        MIN_PASSWORD_LEN_DEV
    };

    if password.len() < min_len {
        return Err(KeystoreError::WeakPassword(format!(
            "passphrase length ({}) is shorter than minimum required ({})",
            password.len(),
            min_len
        )));
    }

    let lower = password.to_ascii_lowercase();
    for &weak in COMMON_WEAK_PASSWORDS {
        if lower.contains(weak) {
            return Err(KeystoreError::WeakPassword(format!(
                "passphrase contains common dictionary sequence '{}'",
                weak
            )));
        }
    }

    // Check for repetitive characters (e.g. "aaaaaaaaaaaa")
    if password
        .chars()
        .all(|c| c == password.chars().next().unwrap())
    {
        return Err(KeystoreError::WeakPassword(
            "passphrase contains only repeated characters".to_string(),
        ));
    }

    // In production, enforce character class diversity (must contain at least 2 distinct classes)
    if is_production() {
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password
            .chars()
            .any(|c| c.is_ascii_punctuation() || !c.is_ascii_alphanumeric());

        let class_count =
            (has_upper as u8) + (has_lower as u8) + (has_digit as u8) + (has_symbol as u8);
        if class_count < 2 {
            return Err(KeystoreError::WeakPassword(
                "production passphrase must contain characters from at least 2 categories (uppercase, lowercase, digits, symbols)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Calculate an approximate entropy score (bits of entropy) for a passphrase.
pub fn calculate_entropy_bits(password: &str) -> f64 {
    let char_count = password.chars().count();
    if char_count == 0 {
        return 0.0;
    }

    let mut pool_size = 0f64;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool_size += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool_size += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool_size += 10.0;
    }
    if password
        .chars()
        .any(|c| c.is_ascii_punctuation() || !c.is_ascii_alphanumeric())
    {
        pool_size += 32.0;
    }

    // Non-ASCII (e.g. CJK) characters contribute a large effective pool.
    if !password.is_ascii() {
        pool_size += 100.0;
    }

    if pool_size <= 0.0 {
        pool_size = 256.0;
    }

    (char_count as f64) * pool_size.log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_strong_passwords() {
        assert!(validate_password("SecurePassphrase123!").is_ok());
        assert!(validate_password("correct-horse-battery-staple").is_ok());
    }

    #[test]
    fn rejects_too_short_passwords() {
        assert!(validate_password("short").is_err());
    }

    #[test]
    fn rejects_dictionary_and_repeated_passwords() {
        assert!(validate_password("password123456").is_err());
        assert!(validate_password("aaaaaaaaaaaa").is_err());
    }

    #[test]
    fn calculates_entropy_correctly() {
        let score_simple = calculate_entropy_bits("password");
        let score_complex = calculate_entropy_bits("C0mpl3x!P@ssw0rd#2026");
        assert!(score_complex > score_simple);
        assert_eq!(calculate_entropy_bits(""), 0.0);
    }

    #[test]
    fn entropy_counts_chars_not_bytes() {
        // 8 two-byte chars must count as 8 characters, never as 16.
        let score = calculate_entropy_bits("\u{00e9}".repeat(8).as_str());
        let expected_pool: f64 = 32.0 + 100.0; // symbol-class + non-ASCII bonus
        assert!((score - 8.0 * expected_pool.log2()).abs() < 1e-9);
    }
}
