//! SXIAUM token denomination utilities.
//!
//! Denomination hierarchy:
//!   1 SXI  = 1_000_000_000_000_000_000 aSXI  (atto-SXI, the smallest on-chain unit)
//!   1 mSX = 1_000_000_000_000_000     aSXI  (milli-SXI)
//!   1 -SX = 1_000_000_000_000         aSXI  (micro-SXI)
//!
//! The node stores balances in aSXI (analogous to Wei in Ethereum).

pub const ASX_PER_SX: u128 = 1_000_000_000_000_000_000; // 10^18

/// Format a raw aSXI amount into a human-readable SXI string.
/// e.g. 1_000_000_000_000_000_000 -> "1 SXI", 1_500_000_000_000_000_000 -> "1.5 SXI"
#[allow(dead_code)]
pub fn format_sx(a_sxi: u128) -> String {
    let whole = a_sxi / ASX_PER_SX;
    let frac = a_sxi % ASX_PER_SX;
    if frac == 0 {
        format!("{} SXI", whole)
    } else {
        let frac_str = format!("{:018}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{} SXI", whole, trimmed)
    }
}

/// Format aSXI compactly:  e.g. 500_000_000_000_000_000 - "0.5 SXI"
/// Falls back to aSXI notation for amounts smaller than 0.000001 SXI
pub fn format_sx_compact(a_sxi: u128) -> String {
    if a_sxi == 0 {
        return "0 SXI".to_string();
    }

    // If it's less than 0.000001 SXI, format as raw aSXI.
    if a_sxi < ASX_PER_SX / 1_000_000 {
        return format!("{} aSXI", a_sxi);
    }

    let whole = a_sxi / ASX_PER_SX;
    let frac = a_sxi % ASX_PER_SX;

    if frac == 0 {
        format!("{} SXI", whole)
    } else {
        // Up to 9 decimal places, trailing zeros stripped
        let frac_str = format!("{:018}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        let trimmed = &trimmed[..trimmed.len().min(9)]; // max 9 dp
        let trimmed = trimmed.trim_end_matches('0');
        if trimmed.is_empty() {
            format!("{} SXI", whole)
        } else {
            format!("{}.{} SXI", whole, trimmed)
        }
    }
}

/// Parse a value string that may be in aSXI (plain integer) or SXI (e.g. "1.5SX" / "1.5 SXI").
/// Returns the value in aSXI units.
pub fn parse_value(s: &str) -> anyhow::Result<u128> {
    let s = s.trim();
    let upper = s.to_uppercase();
    // Accept both "SX" and "SXI" suffixes (with optional surrounding whitespace).
    let (numeric, is_sx) = if upper.ends_with("SXI") {
        let end = s.len().saturating_sub(3);
        (s[..end].trim(), true)
    } else if upper.ends_with("SX") {
        let end = s.len().saturating_sub(2);
        (s[..end].trim(), true)
    } else {
        (s, false)
    };

    if is_sx {
        // Parse as decimal SXI
        if numeric.is_empty() {
            anyhow::bail!("Invalid SXI amount: {}", s);
        }
        if let Some(dot_pos) = numeric.find('.') {
            let whole: u128 = if numeric[..dot_pos].is_empty() {
                0
            } else {
                numeric[..dot_pos]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid SXI amount: {}", s))?
            };
            let frac_str = &numeric[dot_pos + 1..];
            if frac_str.len() > 18 {
                anyhow::bail!("Too many decimal places in SXI amount (max 18): {}", s);
            }
            let frac_padded = format!("{:0<18}", frac_str);
            let frac: u128 = frac_padded
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid fractional SXI: {}", s))?;
            Ok(whole
                .checked_mul(ASX_PER_SX)
                .and_then(|v| v.checked_add(frac))
                .ok_or_else(|| anyhow::anyhow!("SXI amount overflow: {}", s))?)
        } else {
            let whole: u128 = numeric
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid SXI amount: {}", s))?;
            whole
                .checked_mul(ASX_PER_SX)
                .ok_or_else(|| anyhow::anyhow!("SXI amount overflow: {}", s))
        }
    } else {
        // Plain aSXI integer
        s.parse::<u128>().map_err(|_| {
            anyhow::anyhow!(
                "Invalid aSXI amount (must be a plain integer or end with 'SX'/'SXI'): {}",
                s
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_zero() {
        assert_eq!(format_sx_compact(0), "0 SXI");
    }

    #[test]
    fn format_one_sx() {
        assert_eq!(format_sx_compact(ASX_PER_SX), "1 SXI");
    }

    #[test]
    fn format_fractional() {
        assert_eq!(format_sx_compact(ASX_PER_SX / 2), "0.5 SXI");
    }

    #[test]
    fn format_sx_whole_and_fractional() {
        assert_eq!(format_sx(0), "0 SXI");
        assert_eq!(format_sx(ASX_PER_SX), "1 SXI");
        assert_eq!(format_sx(ASX_PER_SX * 5), "5 SXI");
        assert_eq!(format_sx(ASX_PER_SX / 2), "0.5 SXI");
        assert_eq!(format_sx(ASX_PER_SX + ASX_PER_SX / 4), "1.25 SXI");
        assert_eq!(
            format_sx(1_000_000_000_000_000_001),
            "1.000000000000000001 SXI"
        );
    }

    #[test]
    fn parse_plain_asx() {
        assert_eq!(parse_value("1000").unwrap(), 1000);
    }

    #[test]
    fn parse_sx_whole() {
        assert_eq!(parse_value("1SX").unwrap(), ASX_PER_SX);
        assert_eq!(parse_value("1 SXI").unwrap(), ASX_PER_SX);
    }

    #[test]
    fn parse_sx_fractional() {
        assert_eq!(parse_value("1.5SX").unwrap(), ASX_PER_SX + ASX_PER_SX / 2);
        assert_eq!(parse_value("0.5 SXI").unwrap(), ASX_PER_SX / 2);
    }
}
