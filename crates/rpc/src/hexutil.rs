//! Shared hex/quantity parsing and formatting helpers for RPC handlers.
//!
//! This module is the single authority for wire-format conversions in the RPC
//! crate. It replaces three divergent `CopyToSliceExt` trait copies (D5) and
//! two divergent address parsers (D21), and fixes their shared defects:
//!
//! - Heights given as decimal strings (`"123"`) were parsed as HEX (`0x123`).
//!   Decimal strings now parse as decimal; only `0x`-prefixed strings are hex.
//! - `trim_start_matches("0x")` stripped REPEATED prefixes (`"0x0x10"` →
//!   `"10"`). [`strip_hex_prefix`] strips exactly one prefix.
//! - Lowercase-only matching rejected uppercase `0X...` input.
//! - Short hex storage keys were silently LEFT-PADDED to 32 bytes. Storage
//!   keys are now parsed as U256 quantities with strict bounds, which matches
//!   Ethereum `eth_getStorageAt` semantics (`position` is a quantity).

use crate::error::RpcError;
use primitive_types::U256;
use serde_json::Value;
use sxiaum_types::{Address, Hash};

/// Strips a single leading `0x` or `0X` prefix, if present.
pub fn strip_hex_prefix(s: &str) -> &str {
    if let Some(rest) = s.strip_prefix("0x") {
        rest
    } else if let Some(rest) = s.strip_prefix("0X") {
        rest
    } else {
        s
    }
}

/// Formats bytes as a `0x`-prefixed lowercase hex string.
pub fn hex_data(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Formats a [`Hash`] as a `0x`-prefixed string.
pub fn hex_hash(hash: &Hash) -> String {
    hex_data(hash)
}

/// Formats a U256 as a minimal `0x`-prefixed quantity string.
pub fn quantity(value: impl Into<U256>) -> String {
    let value = value.into();
    if value.is_zero() {
        "0x0".to_string()
    } else {
        format!("0x{:x}", value)
    }
}

fn decode_hex_str(s: &str, what: &'static str) -> Result<Vec<u8>, RpcError> {
    hex::decode(strip_hex_prefix(s))
        .map_err(|_| RpcError::InvalidParams(format!("invalid {what} hex")))
}

/// Parses an exact 32-byte hash from raw JSON (string form required).
pub fn parse_hash(value: &Value) -> Result<Hash, RpcError> {
    let s = value
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("hash must be a string".into()))?;
    parse_hash_str(s)
}

/// Parses an exact 32-byte hash from a string.
pub fn parse_hash_str(s: &str) -> Result<Hash, RpcError> {
    let decoded = decode_hex_str(s, "hash")?;
    if decoded.len() != 32 {
        return Err(RpcError::InvalidParams(
            "hash must be exactly 32 bytes".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Parses an address accepting either 20-byte EVM addresses or native
/// 32-byte addresses. Single shared implementation (fixes D21 divergence).
pub fn parse_address_str(s: &str) -> Result<Address, RpcError> {
    let decoded = decode_hex_str(s, "address")?;
    match decoded.len() {
        20 => {
            let mut eth = [0u8; 20];
            eth.copy_from_slice(&decoded);
            Ok(Address::from_ethereum_address(eth))
        }
        32 => {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&decoded);
            Ok(Address(addr))
        }
        _ => Err(RpcError::InvalidParams(
            "address must be 20 or 32 bytes".into(),
        )),
    }
}

/// Parses an address from raw JSON (string form required).
pub fn parse_address(value: &Value) -> Result<Address, RpcError> {
    let s = value
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("address must be a string".into()))?;
    parse_address_str(s)
}

/// Renders an address for RPC responses.
///
/// EVM-compatible addresses are rendered as canonical 20-byte values; native
/// 32-byte addresses are shown in full rather than silently truncated.
pub fn address(address: &Address) -> String {
    if address.is_evm_compatible() {
        hex_data(&address.to_ethereum_address_lossy())
    } else {
        hex_data(address.as_bytes())
    }
}

/// Parses a 32-byte storage key / word using Ethereum quantity semantics.
///
/// Accepts any hex-encoded U256 (`"0x0"`, `"0x1"`, full 64-nibble words) and
/// encodes it big-endian into exactly 32 bytes. Values wider than 32 bytes
/// are rejected instead of being truncated or silently padded.
pub fn parse_word256(value: &Value) -> Result<[u8; 32], RpcError> {
    let s = value.as_str().ok_or_else(|| {
        RpcError::InvalidParams("storage key must be a hex quantity string".into())
    })?;
    parse_word256_str(s)
}

/// See [`parse_word256`].
pub fn parse_word256_str(s: &str) -> Result<[u8; 32], RpcError> {
    let trimmed = strip_hex_prefix(s);
    let word = if trimmed.is_empty() {
        U256::zero()
    } else {
        // Reject anything that does not fit in 32 bytes up front so the error
        // message is precise rather than an opaque radix failure.
        if trimmed.len() > 64 {
            return Err(RpcError::InvalidParams(
                "storage key must fit in 32 bytes".into(),
            ));
        }
        U256::from_str_radix(trimmed, 16)
            .map_err(|_| RpcError::InvalidParams("invalid storage key quantity".into()))?
    };

    let mut out = [0u8; 32];
    word.to_big_endian(&mut out);
    Ok(out)
}

/// Parses a block height from raw JSON.
///
/// Numbers are used directly. Strings starting with `0x`/`0X` parse as hex;
/// all other strings parse as DECIMAL (fixes `"123"` previously parsing as
/// hex `0x123` = 291).
pub fn parse_height_value(value: &Value) -> Result<u64, RpcError> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| RpcError::InvalidParams("height must be a non-negative u64".into())),
        Value::String(s) => parse_height_str(s),
        _ => Err(RpcError::InvalidParams(
            "height must be a number or decimal/hex string".into(),
        )),
    }
}

/// See [`parse_height_value`].
pub fn parse_height_str(s: &str) -> Result<u64, RpcError> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(RpcError::InvalidParams("empty height".into()));
    }
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        let digits = strip_hex_prefix(trimmed);
        if digits.is_empty() {
            return Err(RpcError::InvalidParams("invalid hex height".into()));
        }
        u64::from_str_radix(digits, 16)
            .map_err(|_| RpcError::InvalidParams("invalid hex height".into()))
    } else {
        trimmed
            .parse::<u64>()
            .map_err(|_| RpcError::InvalidParams("invalid decimal height".into()))
    }
}

/// Parses arbitrary hex data (`input`, raw transactions) from raw JSON.
pub fn parse_bytes(value: &Value) -> Result<Vec<u8>, RpcError> {
    let s = value
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("bytes value must be a hex string".into()))?;
    decode_hex_str(s, "bytes")
}

/// Parses a hex quantity (or small JSON number) into a U256.
pub fn parse_quantity(value: &Value) -> Result<U256, RpcError> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .map(U256::from)
            .ok_or_else(|| RpcError::InvalidParams("quantity must be unsigned".into())),
        Value::String(s) => {
            let trimmed = strip_hex_prefix(s.trim());
            if trimmed.is_empty() {
                Ok(U256::zero())
            } else if trimmed.len() > 64 {
                Err(RpcError::InvalidParams("quantity exceeds 32 bytes".into()))
            } else {
                U256::from_str_radix(trimmed, 16)
                    .map_err(|_| RpcError::InvalidParams("invalid hex quantity".into()))
            }
        }
        _ => Err(RpcError::InvalidParams(
            "quantity must be a hex string or number".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strip_prefix_strips_exactly_once() {
        assert_eq!(strip_hex_prefix("0x10"), "10");
        assert_eq!(strip_hex_prefix("0X10"), "10");
        assert_eq!(strip_hex_prefix("0x0x10"), "0x10");
        assert_eq!(strip_hex_prefix("deadbeef"), "deadbeef");
        assert_eq!(strip_hex_prefix(""), "");
    }

    #[test]
    fn height_decimal_string_is_decimal() {
        // Regression: was parsed as hex ("123" → 291).
        assert_eq!(parse_height_value(&json!("123")).unwrap(), 123);
        assert_eq!(parse_height_value(&json!("0x123")).unwrap(), 0x123);
        assert_eq!(parse_height_value(&json!("0XFF")).unwrap(), 255);
        assert_eq!(parse_height_value(&json!(7)).unwrap(), 7);
        assert!(parse_height_value(&json!("-1")).is_err());
        assert!(parse_height_value(&json!("")).is_err());
        assert!(parse_height_value(&json!("0x")).is_err());
        assert!(parse_height_value(&json!(true)).is_err());
    }

    #[test]
    fn hash_requires_exact_length() {
        let h = parse_hash(&json!(format!("0x{}", "ab".repeat(32)))).unwrap();
        assert_eq!(h, [0xab; 32]);
        assert!(parse_hash(&json!(format!("0x{}", "ab".repeat(31)))).is_err());
        assert!(parse_hash(&json!(format!("0x{}", "zz".repeat(32)))).is_err());
        assert!(parse_hash(&json!(42)).is_err());
    }

    #[test]
    fn address_accepts_20_and_32_bytes_only() {
        assert!(parse_address(&json!(format!("0x{}", "11".repeat(20)))).is_ok());
        assert!(parse_address(&json!(format!("0x{}", "22".repeat(32)))).is_ok());
        assert!(parse_address(&json!(format!("0x{}", "33".repeat(19)))).is_err());
    }

    #[test]
    fn word_parses_as_number_left_padded_to_32_bytes() {
        let w = parse_word256(&json!("0x1")).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(w, expected);

        let full = parse_word256(&json!(format!("0x{}", "ab".repeat(32)))).unwrap();
        assert_eq!(full, [0xab; 32]);

        // 33-byte key overflows U256 → rejected, not truncated.
        assert!(parse_word256(&json!(format!("0x{}", "cd".repeat(33)))).is_err());
        assert!(parse_word256(&json!(42)).is_err());
    }

    #[test]
    fn quantities_render_minimally() {
        assert_eq!(quantity(U256::zero()), "0x0");
        assert_eq!(quantity(U256::one()), "0x1");
        assert_eq!(quantity(U256::from(255u32)), "0xff");
    }
}
