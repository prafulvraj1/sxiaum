use anyhow::{bail, Result};
use bincode::Options;
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sxiaum_types::Address;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub [u8; 32]);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PrivateKey(<redacted>)")
    }
}

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn public_key(&self) -> PublicKey {
        let signing_key = SigningKey::from_bytes(&self.0);
        PublicKey(signing_key.verifying_key().to_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let arr = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Self(arr))
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn validate(&self) -> Result<()> {
        VerifyingKey::from_bytes(&self.0)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {:?}", e))
    }

    /// Convert the public key to a canonical blockchain Address.
    pub fn address(&self) -> Address {
        Address::from_public_key(&self.0)
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn validate(&self) -> Result<()> {
        let _ = DalekSignature::from_slice(&self.0)
            .map_err(|e| anyhow::anyhow!("Invalid Ed25519 signature encoding: {:?}", e))?;
        Ok(())
    }

    pub fn encode_network(&self) -> Result<Vec<u8>> {
        bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .reject_trailing_bytes()
            .serialize(self)
            .map_err(|e| anyhow::anyhow!("Encoding signature failed: {:?}", e))
    }

    pub fn decode_network(bytes: &[u8]) -> Result<Self> {
        bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Decoding signature failed: {:?}", e))
    }
}

/// Generate a cryptographically secure random keypair.
pub fn generate_keypair() -> (PrivateKey, PublicKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    (
        PrivateKey(signing_key.to_bytes()),
        PublicKey(signing_key.verifying_key().to_bytes()),
    )
}

/// Create a keypair from a specific 32-byte seed.
pub fn keypair_from_seed(seed: [u8; 32]) -> (PrivateKey, PublicKey) {
    let signing_key = SigningKey::from_bytes(&seed);
    (
        PrivateKey(signing_key.to_bytes()),
        PublicKey(signing_key.verifying_key().to_bytes()),
    )
}

/// Sign a message using a private key (SigningKey).
/// Ed25519 is deterministic by default.
pub fn sign(private_key_bytes: &[u8; 32], message: &[u8]) -> Signature {
    let signing_key = SigningKey::from_bytes(private_key_bytes);
    let sig = signing_key.sign(message);
    Signature(sig.to_bytes())
}

/// Verify an Ed25519 signature against a public key and message.
pub fn verify(public_key_bytes: &[u8; 32], message: &[u8], signature_bytes: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(public_key_bytes) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = match DalekSignature::from_slice(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    verifying_key.verify_strict(message, &sig).is_ok()
}

impl crate::signer::Signer for PrivateKey {
    fn sign(&self, message: &[u8]) -> anyhow::Result<Signature> {
        Ok(sign(&self.0, message))
    }

    fn public_key(&self) -> PublicKey {
        let signing_key = SigningKey::from_bytes(&self.0);
        PublicKey(signing_key.verifying_key().to_bytes())
    }
}

/// NOTE: Ed25519 does not support public key recovery from a (message, signature) pair
/// in the same way as secp256k1 (ECDSA) does. The public key must be provided separately.
pub fn recover_public_key(_message: &[u8], _signature: &Signature) -> Result<PublicKey> {
    bail!("Public key recovery is not supported by the Ed25519 cryptosystem. Use ECDSA if recovery is required.")
}

#[cfg(feature = "fuzz-targets")]
pub fn fuzz_target_signature_verification(
    public_key: [u8; 32],
    message: &[u8],
    signature: [u8; 64],
) {
    let _ = verify(&public_key, message, &signature);
}

// Support for bincode encoding for networking
impl PublicKey {
    pub fn try_encode_network(&self) -> Result<Vec<u8>> {
        bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .reject_trailing_bytes()
            .serialize(self)
            .map_err(|e| anyhow::anyhow!("Public key network serialization failed: {:?}", e))
    }

    pub fn decode_network(bytes: &[u8]) -> Result<Self> {
        bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .reject_trailing_bytes()
            .deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Decoding public key failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        generate_keypair, keypair_from_seed, recover_public_key, sign, verify, PublicKey, Signature,
    };

    #[test]
    fn generated_keypair_round_trips_to_address_and_bytes() {
        let (_private_key, public_key) = generate_keypair();

        assert_eq!(PublicKey::from_bytes(public_key.to_bytes()), public_key);
        assert_ne!(public_key.address(), sxiaum_types::Address::zero());
        public_key
            .validate()
            .expect("generated public key should validate");
    }

    #[test]
    fn keypair_from_seed_is_deterministic() {
        let seed = [7u8; 32];
        let first = keypair_from_seed(seed);
        let second = keypair_from_seed(seed);

        assert_eq!(first.0 .0, second.0 .0);
        assert_eq!(first.1, second.1);
    }

    #[test]
    fn signing_is_deterministic_and_verifiable() {
        let (private_key, public_key) = keypair_from_seed([8u8; 32]);
        let message = b"sxiaum-ed25519";

        let first = sign(&private_key.0, message);
        let second = sign(&private_key.0, message);

        assert_eq!(first, second);
        assert!(verify(&public_key.0, message, &first.0));
    }

    #[test]
    fn verification_fails_for_wrong_message_or_key() {
        let (private_key, public_key) = keypair_from_seed([9u8; 32]);
        let (_, other_public_key) = keypair_from_seed([10u8; 32]);
        let signature = sign(&private_key.0, b"message");

        assert!(!verify(&public_key.0, b"different-message", &signature.0));
        assert!(!verify(&other_public_key.0, b"message", &signature.0));
    }

    #[test]
    fn signature_and_public_key_wrappers_round_trip() {
        let (_private_key, public_key) = keypair_from_seed([11u8; 32]);
        let signature = Signature::from_bytes([12u8; 64]);

        assert_eq!(
            public_key.to_bytes(),
            PublicKey::from_bytes(public_key.to_bytes()).to_bytes()
        );
        assert_eq!(signature.to_bytes(), [12u8; 64]);
        public_key
            .validate()
            .expect("derived public key should validate");
    }

    #[test]
    fn malformed_serialized_key_and_signature_inputs_are_rejected() {
        assert!(PublicKey::decode_network(&[1u8, 2u8, 3u8]).is_err());
        assert!(bincode::deserialize::<Signature>(&[1u8, 2u8, 3u8]).is_err());
    }

    #[test]
    fn strict_verification_rejects_tampered_signature_bytes() {
        let (private_key, public_key) = keypair_from_seed([21u8; 32]);
        let mut signature = sign(&private_key.0, b"message").to_bytes();
        signature[63] ^= 0x80;

        assert!(!verify(&public_key.0, b"message", &signature));
    }

    #[test]
    fn bincode_and_network_encoding_round_trip() {
        let (_private_key, public_key) = keypair_from_seed([13u8; 32]);
        let signature = Signature::from_bytes([14u8; 64]);

        let public_key_bytes = public_key
            .try_encode_network()
            .expect("public key serialization should succeed");
        let decoded_public_key =
            PublicKey::decode_network(&public_key_bytes).expect("public key decode should succeed");
        let signature_bytes =
            bincode::serialize(&signature).expect("signature bincode serialization should succeed");
        let decoded_signature: Signature = bincode::deserialize(&signature_bytes)
            .expect("signature bincode deserialization should succeed");

        assert_eq!(decoded_public_key, public_key);
        assert_eq!(decoded_signature, signature);
    }

    #[test]
    fn public_key_recovery_is_explicitly_unsupported() {
        let signature = Signature::from_bytes([15u8; 64]);

        assert!(recover_public_key(b"message", &signature).is_err());
    }
}
