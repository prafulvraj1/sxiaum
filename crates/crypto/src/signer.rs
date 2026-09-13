use crate::ed25519::{PublicKey, Signature};
use anyhow::Result;

/// An abstract interface for objects that can produce cryptographic signatures.
///
/// This trait is designed to be implemented by both in-memory private keys
/// and external HSMs (Hardware Security Modules) or remote signing services.
///
/// Canonical data types (transactions, headers, votes) sign their unique,
/// type-separated canonical hashes. [`sign_with_domain`] provides domain-separated
/// signing for raw byte payloads.
pub trait Signer: Send + Sync {
    /// Sign a message and return the resulting signature.
    fn sign(&self, message: &[u8]) -> Result<Signature>;

    /// Return the public key associated with this signer.
    fn public_key(&self) -> PublicKey;

    /// Sign a message with an explicit domain separation tag.
    ///
    /// The domain tag is length-prefixed and prepended to the message before signing,
    /// preventing signatures from being replayed across different protocol contexts
    /// (e.g. a block signature cannot be reused as a transaction signature) and
    /// eliminating delimiter collision between variable-length domain strings.
    ///
    /// Canonical framing: `[u32 domain_len (4 bytes LE)][domain_bytes][message_bytes]`.
    ///
    /// Default implementation prepends the length-framed domain tag to the message.
    /// Implementations MAY override this for HSM-specific domain handling.
    fn sign_with_domain(&self, domain: &str, message: &[u8]) -> Result<Signature> {
        let domain_bytes = domain.as_bytes();
        let mut tagged = Vec::with_capacity(4 + domain_bytes.len() + message.len());
        tagged.extend_from_slice(&(domain_bytes.len() as u32).to_le_bytes());
        tagged.extend_from_slice(domain_bytes);
        tagged.extend_from_slice(message);
        self.sign(&tagged)
    }
}

/// Construct the canonical domain-framed byte payload for domain-separated signing.
pub fn domain_sign_payload(domain: &str, message: &[u8]) -> Vec<u8> {
    let domain_bytes = domain.as_bytes();
    let mut payload = Vec::with_capacity(4 + domain_bytes.len() + message.len());
    payload.extend_from_slice(&(domain_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(domain_bytes);
    payload.extend_from_slice(message);
    payload
}
