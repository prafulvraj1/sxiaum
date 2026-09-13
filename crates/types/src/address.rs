use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;
use std::fmt;
use std::str::FromStr;
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
pub struct Address(pub [u8; 32]);
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error(
        "address cannot be losslessly projected to 20 bytes: \
         first 12 bytes are non-zero (not EVM-compatible)"
    )]
    AmbiguousProjection,
    #[error("invalid hexadecimal address encoding: {0}")]
    InvalidHex(String),
    #[error("invalid address length: expected 40 or 64 hex characters, got {0}")]
    InvalidLength(usize),
    #[error("invalid EIP-55 mixed-case checksum address")]
    InvalidChecksum,
}
impl From<hex::FromHexError> for AddressError {
    fn from(err: hex::FromHexError) -> Self {
        AddressError::InvalidHex(err.to_string())
    }
}
impl Address {
    pub const ZERO: Self = Self([0u8; 32]);
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn create_contract_address(sender: &Address, nonce: u64) -> Self {
        if sender.is_evm_compatible() {
            let mut sender20 = [0u8; 20];
            sender20.copy_from_slice(&sender.0[12..]);
            let mut stream = rlp::RlpStream::new_list(2);
            stream.append(&sender20.as_slice());
            stream.append(&nonce);
            let encoded = stream.out().to_vec();
            let digest = Keccak256::digest(&encoded);
            let mut eth = [0u8; 20];
            eth.copy_from_slice(&digest[12..]);
            return Self::from_ethereum_address(eth);
        }
        let mut hasher = Keccak256::new();
        hasher.update(b"sxiaum:create:v1");
        hasher.update(sender.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }
    pub const fn zero() -> Self {
        Self::ZERO
    }
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < 32 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
    #[must_use]
    pub fn is_evm_compatible(&self) -> bool {
        self.0[..12].iter().all(|&b| b == 0)
    }
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(s: &str) -> Result<Self, AddressError> {
        Self::from_str(s)
    }
    pub fn from_ethereum_address(bytes20: [u8; 20]) -> Self {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(&bytes20);
        Self(bytes)
    }
    pub fn to_ethereum_address(&self) -> Result<[u8; 20], AddressError> {
        if !self.is_evm_compatible() {
            return Err(AddressError::AmbiguousProjection);
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&self.0[12..]);
        Ok(bytes)
    }
    pub fn to_ethereum_address_lossy(&self) -> [u8; 20] {
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&self.0[12..]);
        bytes
    }
    pub fn to_checksum_address(&self) -> Result<String, AddressError> {
        let bytes20 = self.to_ethereum_address()?;
        Ok(eip55_checksum(&bytes20))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
pub fn eip55_checksum(bytes20: &[u8; 20]) -> String {
    let hex_addr = hex::encode(bytes20);
    let hash = Keccak256::digest(hex_addr.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_digit() {
            out.push(c);
        } else {
            let byte = hash[i / 2];
            let nibble = if i % 2 == 0 {
                (byte >> 4) & 0x0f
            } else {
                byte & 0x0f
            };
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c.to_ascii_lowercase());
            }
        }
    }
    out
}
fn validate_eip55_checksum_from_bytes(raw_hex: &str, bytes20: &[u8; 20]) -> bool {
    let has_upper = raw_hex.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = raw_hex.chars().any(|c| c.is_ascii_lowercase());
    if !(has_upper && has_lower) {
        return true;
    }
    let expected = eip55_checksum(bytes20);
    &expected[2..] == raw_hex
}
impl FromStr for Address {
    type Err = AddressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let clean = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        match clean.len() {
            40 => {
                let decoded = hex::decode(clean)?;
                let mut bytes20 = [0u8; 20];
                bytes20.copy_from_slice(&decoded);
                if !validate_eip55_checksum_from_bytes(clean, &bytes20) {
                    return Err(AddressError::InvalidChecksum);
                }
                Ok(Self::from_ethereum_address(bytes20))
            }
            64 => {
                let decoded = hex::decode(clean)?;
                let mut bytes32 = [0u8; 32];
                bytes32.copy_from_slice(&decoded);
                Ok(Self(bytes32))
            }
            len => Err(AddressError::InvalidLength(len)),
        }
    }
}
impl AsRef<[u8; 32]> for Address {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}
impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_evm_compatible() {
            write!(f, "0x{}", hex::encode(&self.0[12..]))
        } else {
            write!(f, "0x{}", self.to_hex())
        }
    }
}
impl From<[u8; 32]> for Address {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
impl TryFrom<&[u8]> for Address {
    type Error = AddressError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(AddressError::InvalidLength(bytes.len()));
        }
        let mut addr = [0u8; 32];
        addr.copy_from_slice(bytes);
        Ok(Self(addr))
    }
}
impl From<Address> for [u8; 32] {
    fn from(address: Address) -> [u8; 32] {
        address.0
    }
}
#[cfg(test)]
mod tests {
    use super::{Address, AddressError};
    use std::str::FromStr;
    #[test]
    fn derives_address_from_public_key_with_sha256() {
        let public_key = [7u8; 32];
        let address = Address::from_public_key(&public_key);
        assert_eq!(
            address.to_hex(),
            "4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
        assert!(!address.is_evm_compatible());
        assert_eq!(
            address.to_ethereum_address(),
            Err(AddressError::AmbiguousProjection)
        );
    }
    #[test]
    fn zero_address_helpers_are_consistent() {
        let address = Address::zero();
        assert!(address.is_zero());
        assert!(address.is_evm_compatible());
        assert_eq!(address.as_bytes(), &[0u8; 32]);
        assert_eq!(address.to_string(), format!("0x{}", "00".repeat(20)));
    }
    #[test]
    fn hex_round_trip_supports_prefixed_strings() {
        let original = Address([0x11; 32]);
        let encoded = format!("0x{}", original.to_hex());
        let decoded = Address::from_hex(&encoded).expect("hex decoding should work");
        assert_eq!(decoded, original);
    }
    #[test]
    fn try_from_slice_validates_length() {
        let bytes = [3u8; 32];
        let address = Address::try_from(bytes.as_slice()).expect("32-byte slice is valid");
        let round_trip: [u8; 32] = address.into();
        assert_eq!(address, Address(bytes));
        assert_eq!(round_trip, bytes);
        assert!(Address::try_from(&bytes[..31]).is_err());
    }
    #[test]
    fn serde_and_bincode_round_trip() {
        let address = Address::random();
        let json = serde_json::to_string(&address).expect("json serialization should work");
        let json_round_trip: Address =
            serde_json::from_str(&json).expect("json deserialization should work");
        let bytes = bincode::serialize(&address).expect("bincode serialization should work");
        let bincode_round_trip: Address =
            bincode::deserialize(&bytes).expect("bincode deserialization should work");
        assert_eq!(json_round_trip, address);
        assert_eq!(bincode_round_trip, address);
    }
    #[test]
    fn ordering_is_lexicographic_for_deterministic_collections() {
        let lower = Address([0u8; 32]);
        let higher = Address([1u8; 32]);
        assert!(lower < higher);
    }
    #[test]
    fn evm_round_trip_is_lossless() {
        let evm_bytes: [u8; 20] = [0xAB; 20];
        let addr = Address::from_ethereum_address(evm_bytes);
        assert!(addr.is_evm_compatible());
        assert_eq!(addr.to_ethereum_address().unwrap(), evm_bytes);
    }
    #[test]
    fn non_evm_address_rejects_projection() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xFF;
        let addr = Address(bytes);
        assert!(!addr.is_evm_compatible());
        assert_eq!(
            addr.to_ethereum_address(),
            Err(AddressError::AmbiguousProjection)
        );
        assert_eq!(
            addr.to_checksum_address(),
            Err(AddressError::AmbiguousProjection)
        );
        assert_eq!(addr.to_ethereum_address_lossy(), bytes[12..]);
    }
    #[test]
    fn lossy_projection_matches_validating_projection_for_evm_addresses() {
        let evm_bytes: [u8; 20] = [0x5A; 20];
        let addr = Address::from_ethereum_address(evm_bytes);
        assert_eq!(addr.to_ethereum_address_lossy(), evm_bytes);
        assert_eq!(
            addr.to_ethereum_address_lossy(),
            addr.to_ethereum_address().expect("lossless projection")
        );
        assert_eq!(
            Address::from_ethereum_address(addr.to_ethereum_address_lossy()),
            addr
        );
    }
    #[test]
    fn eip55_checksum_test_vectors() {
        let vectors = [
            (
                "5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                "fb6916095ca1df60bb79ce92ce3ea74c37c5d359",
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
            (
                "dbf03b407c01e7cd3cbea99509d93f8dddc8c6fb",
                "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            ),
            (
                "52908400098527886e0f7030069857d2e4169ee7",
                "0x52908400098527886E0F7030069857D2E4169EE7",
            ),
            (
                "de709f2102306220921060314715629080e2fb77",
                "0xde709f2102306220921060314715629080e2fb77",
            ),
            (
                "27b1fdb04752bbc536007a920d24acb045561c26",
                "0x27b1fdb04752bbc536007a920d24acb045561c26",
            ),
        ];
        for (input, expected_checksum) in vectors {
            let addr = Address::from_str(input).expect("valid address");
            assert_eq!(addr.to_checksum_address().unwrap(), expected_checksum);
            let parsed = Address::from_str(expected_checksum).expect("checksummed parse");
            assert_eq!(parsed, addr);
        }
        let corrupted = "0x5aaEb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert_eq!(
            Address::from_str(corrupted),
            Err(AddressError::InvalidChecksum)
        );
    }
    #[test]
    fn from_str_supports_20_and_32_bytes() {
        let evm_str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let evm_addr = Address::from_str(evm_str).unwrap();
        assert!(evm_addr.is_evm_compatible());
        let native_str = "0x4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0";
        let native_addr = Address::from_str(native_str).unwrap();
        assert!(!native_addr.is_evm_compatible());
        assert_eq!(native_addr.to_hex(), native_str[2..]);
        assert!(matches!(
            Address::from_str("0x1234"),
            Err(AddressError::InvalidLength(4))
        ));
    }
    #[test]
    fn create_matches_ethereum_create_for_evm_sender() {
        use sha3::Digest;
        let sender20 = [0x11u8; 20];
        let sender = Address::from_ethereum_address(sender20);
        let derived = Address::create_contract_address(&sender, 7u64);
        assert!(derived.is_evm_compatible());
        let mut stream = rlp::RlpStream::new_list(2);
        stream.append(&sender20.as_slice());
        stream.append(&7u64);
        let encoded = stream.out().to_vec();
        let digest = sha3::Keccak256::digest(&encoded);
        let mut expected20 = [0u8; 20];
        expected20.copy_from_slice(&digest[12..]);
        assert_eq!(derived.to_ethereum_address().unwrap(), expected20);
        let again = Address::create_contract_address(&sender, 7u64);
        assert_eq!(derived, again);
        let different_nonce = Address::create_contract_address(&sender, 8u64);
        assert_ne!(derived, different_nonce);
    }
    #[test]
    fn create_for_native_sender_is_deterministic_and_bound() {
        let sender = Address([0x99u8; 32]);
        assert!(!sender.is_evm_compatible());
        let a = Address::create_contract_address(&sender, 1u64);
        let b = Address::create_contract_address(&sender, 1u64);
        let c = Address::create_contract_address(&sender, 2u64);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, sender);
    }
    #[test]
    fn random_uses_secure_entropy_and_is_unique() {
        let a = Address::random();
        let b = Address::random();
        assert_ne!(a.as_bytes(), &[0u8; 32]);
        assert_ne!(b.as_bytes(), &[0u8; 32]);
        assert_ne!(a, b);
    }
}
