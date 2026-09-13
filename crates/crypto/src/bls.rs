use anyhow::{bail, Result};
use ark_bls12_381::{g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    CurveGroup, PrimeGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsPublicKey(pub Vec<u8>); // Compressed G1

use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct BlsPrivateKey(pub Vec<u8>); // Field element Fr

impl std::fmt::Debug for BlsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsPrivateKey(<redacted>)")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlsSignature(pub Vec<u8>); // Compressed G2

impl BlsPublicKey {
    pub fn from_g1(g1: &G1Projective) -> Self {
        let mut bytes = Vec::new();
        g1.serialize_compressed(&mut bytes)
            .expect("G1Projective serialization to compressed bytes should never fail");
        Self(bytes)
    }

    pub fn to_g1(&self) -> Result<G1Projective> {
        if self.0.len() != G1Affine::default().compressed_size() {
            bail!("Invalid BLS G1 public key length: {}", self.0.len());
        }
        let pk = G1Projective::deserialize_compressed(&self.0[..])
            .map_err(|e| anyhow::anyhow!("Invalid BLS G1 public key format: {:?}", e))?;
        // Security check: ensure public key is not the identity point (zero)
        if pk.is_zero() {
            bail!("BLS Public Key cannot be the identity point");
        }
        Ok(pk)
    }

    /// Fallible storage serialization that propagates errors.
    pub fn try_encode_storage(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("BLS public key storage serialization failed: {:?}", e))
    }
}

impl BlsPrivateKey {
    /// Fallible storage serialization that propagates errors.
    pub fn try_encode_storage(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("BLS private key storage serialization failed: {:?}", e))
    }
}

impl BlsSignature {
    pub fn from_g2(g2: &G2Projective) -> Self {
        let mut bytes = Vec::new();
        g2.serialize_compressed(&mut bytes)
            .expect("G2Projective serialization to compressed bytes should never fail");
        Self(bytes)
    }

    pub fn to_g2(&self) -> Result<G2Projective> {
        if self.0.len() != G2Affine::default().compressed_size() {
            bail!("Invalid BLS G2 signature length: {}", self.0.len());
        }
        let sig = G2Projective::deserialize_compressed(&self.0[..])
            .map_err(|e| anyhow::anyhow!("Invalid BLS G2 signature: {:?}", e))?;
        if sig.is_zero() {
            bail!("BLS signature cannot be the identity point");
        }
        Ok(sig)
    }

    /// Fallible storage serialization that propagates errors.
    pub fn try_encode_storage(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("BLS signature storage serialization failed: {:?}", e))
    }
}

/// Generate a new BLS keypair (G1 public key, Fr private key).
pub fn bls_generate_keypair() -> (BlsPrivateKey, BlsPublicKey) {
    let mut rng = OsRng;
    let sk = Fr::rand(&mut rng);
    let pk = G1Projective::generator() * sk;

    let mut sk_bytes = Vec::new();
    sk.serialize_compressed(&mut sk_bytes)
        .expect("Fr field element serialization to compressed bytes should never fail");

    (BlsPrivateKey(sk_bytes), BlsPublicKey::from_g1(&pk))
}

/// Sign a message using a BLS private key (returns compressed G2 signature).
pub fn bls_sign(sk_bytes: &BlsPrivateKey, message: &[u8]) -> Result<BlsSignature> {
    let mut sk = Fr::deserialize_compressed(&sk_bytes.0[..])
        .map_err(|e| anyhow::anyhow!("Invalid BLS private key: {:?}", e))?;
    if sk.is_zero() {
        bail!("BLS private key cannot be zero");
    }
    // Hash message to G2 for signing
    let h = hash_to_g2(message);
    if h.is_zero() {
        bail!("Hash to G2 produced identity point");
    }
    let sig = h * sk;
    sk.zeroize();
    if sig.is_zero() {
        bail!("Generated BLS signature cannot be identity point");
    }
    Ok(BlsSignature::from_g2(&sig))
}

/// Verify a single BLS signature against a public key and message.
pub fn bls_verify(pk_bytes: &BlsPublicKey, message: &[u8], sig_bytes: &BlsSignature) -> bool {
    let pk = match pk_bytes.to_g1() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = match sig_bytes.to_g2() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if pk.is_zero() || sig.is_zero() {
        return false;
    }
    let h = hash_to_g2(message);
    if h.is_zero() {
        return false;
    }

    // Check e(PK, H(m)) == e(G1, sig)
    let p1 = Bls12_381::pairing(pk, h);
    let p2 = Bls12_381::pairing(G1Projective::generator(), sig);
    p1 == p2
}

/// Aggregate multiple BLS signatures into a single signature.
pub fn aggregate_signatures(sigs: &[BlsSignature]) -> Result<BlsSignature> {
    if sigs.is_empty() {
        bail!("Empty signature list for aggregation");
    }
    let mut agg = G2Projective::default(); // Identity
    for s_bytes in sigs {
        let pt = s_bytes.to_g2()?;
        if pt.is_zero() {
            bail!("Input signature to aggregate is identity point");
        }
        agg += pt;
    }
    if agg.is_zero() {
        bail!("Aggregated BLS signature cannot be identity point");
    }
    Ok(BlsSignature::from_g2(&agg))
}

/// Aggregate multiple BLS public keys into a single public key.
pub fn aggregate_public_keys(pks: &[BlsPublicKey]) -> Result<BlsPublicKey> {
    if pks.is_empty() {
        bail!("Empty public key list for aggregation");
    }
    let mut agg = G1Projective::default();
    for pk_bytes in pks {
        let pt = pk_bytes.to_g1()?;
        if pt.is_zero() {
            bail!("Input public key to aggregate is identity point");
        }
        agg += pt;
    }
    if agg.is_zero() {
        bail!("Aggregated BLS public key cannot be identity point");
    }
    Ok(BlsPublicKey::from_g1(&agg))
}

/// Verify an aggregated BLS signature against an aggregated public key and the original message.
///
/// Equivalent to [`bls_verify`] — aggregation is a linear combination, so the
/// aggregate verifies with a single pairing check against the aggregate key.
pub fn verify_aggregate_signature(
    agg_pk: &BlsPublicKey,
    message: &[u8],
    agg_sig: &BlsSignature,
) -> bool {
    bls_verify(agg_pk, message, agg_sig)
}

/// Hash a message to G2 using the IETF BLS draft-05 specification.
///
/// Uses the "hash_to_curve" primitive (random-oracle encoding) with:
///   - curve:  BLS12-381 G2
///   - hash:   SHA-256 (XMD construction)
///   - map:    Simplified SWU + 3-isogeny (identical to `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`)
///   - domain: `SXIAUM-BLS-G2-SHA256-SSWU-RO:<domain_suffix>` where the suffix is
///     the caller's domain separation tag (e.g. the 32-byte DOMAIN_CONSENSUS constant).
///
/// # Security
///
/// The previous implementation computed `G2_generator * Fr::from_bytes(hash)`, which is
/// NOT a secure map-to-curve.  The scalar `s = hash(msg)` produces a point `s * G` on
/// the prime-order subgroup, but the discrete-log relationship between the message hash
/// and the resulting point is known, enabling forged-signature attacks in some settings.
///
/// This implementation calls `ark_ec::hashing::HashToCurve` which implements the full
/// hash_to_field -> map_to_curve -> clear_cofactor pipeline from RFC draft IRTF-CFRG-09,
/// ensuring uniform distribution and no known-discrete-log weakness.
fn hash_to_g2(message: &[u8]) -> G2Projective {
    // Domain separation tag: identifies this as a consensus vote message.
    // Format follows IETF BLS draft-05 section 4.2.2.
    const DST: &[u8] = b"SXIAUM-BLS-G2-SHA256-SSWU-RO-CONSENSUS-V1";

    // Apply additional domain hashing so messages from different SXIAUM
    // consensus domains cannot be re-used across protocols.
    let domain_tagged_msg = {
        let d_hash = crate::hash::domain_hash(crate::hash::DOMAIN_CONSENSUS, message);
        d_hash.to_vec()
    };

    let hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256>, WBMap<g2::Config>>::new(
            DST,
        )
        .expect("BLS12-381 G2 hash-to-curve hasher initialisation should not fail");

    hasher
        .hash(&domain_tagged_msg)
        .expect("BLS12-381 G2 hash-to-curve should not fail for a valid message")
        .into()
}

/// Domain separation tag used for Proof-of-Possession (PoP).
/// Distinct from the message DST so a PoP cannot be replayed as a vote signature.
const POP_DST: &[u8] = b"SXIAUM-BLS-G2-SHA256-SSWU-RO-POP-V1";

/// Generate a Proof-of-Possession (PoP) for a BLS public key.
///
/// The PoP is a BLS signature over the compressed G1 public-key bytes itself,
/// using a distinct domain separation tag (`POP_DST`) to prevent cross-protocol replay.
///
/// **Why PoP matters:** In naive BLS aggregation, an adversary can choose a public key
/// `PK_adv = PK_honest * (-1)` (a "rogue key"), so that aggregating PK_honest + PK_adv
/// yields the identity point.  A PoP proves knowledge of the corresponding private key,
/// eliminating rogue-key attacks without requiring message distinctness or signed message
/// augmentation.
///
/// **Protocol:** Validators MUST submit a valid PoP at registration time.  The validator
/// set manager MUST call `verify_proof_of_possession` before adding a key to the set.
/// This requirement is enforced by the production preflight and validator-set update path.
pub fn create_proof_of_possession(sk: &BlsPrivateKey, pk: &BlsPublicKey) -> Result<BlsSignature> {
    let mut sk_fr = Fr::deserialize_compressed(&sk.0[..])
        .map_err(|e| anyhow::anyhow!("Invalid BLS private key for PoP: {:?}", e))?;
    if sk_fr.is_zero() {
        bail!("BLS private key for PoP cannot be zero");
    }

    // Validate that pk is a valid non-identity curve point
    let pk_pt = pk.to_g1()?;
    if pk_pt.is_zero() {
        bail!("BLS public key for PoP cannot be identity point");
    }

    // Hash the compressed public key bytes to G2 using the PoP DST.
    let hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256>, WBMap<g2::Config>>::new(
            POP_DST,
        )
        .expect("BLS12-381 G2 PoP hasher initialisation should not fail");

    let pk_bytes = &pk.0;
    let h: G2Projective = hasher
        .hash(pk_bytes)
        .expect("hash-to-G2 for PoP should not fail")
        .into();
    if h.is_zero() {
        bail!("Hash to G2 for PoP produced identity point");
    }

    let sig: G2Projective = h * sk_fr;
    sk_fr.zeroize();
    if sig.is_zero() {
        bail!("Generated PoP signature cannot be identity point");
    }
    Ok(BlsSignature::from_g2(&sig))
}

/// Verify a Proof-of-Possession (PoP) for a BLS public key.
///
/// Returns `true` iff the PoP was created with the private key corresponding to `pk`.
///
/// **Must be called before any public key is added to the validator set.**
pub fn verify_proof_of_possession(pk: &BlsPublicKey, pop: &BlsSignature) -> bool {
    let pk_g1 = match pk.to_g1() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let pop_g2 = match pop.to_g2() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if pk_g1.is_zero() || pop_g2.is_zero() {
        return false;
    }

    // Hash the compressed public key bytes to G2 using the PoP DST.
    let hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256>, WBMap<g2::Config>>::new(
            POP_DST,
        )
        .expect("BLS12-381 G2 PoP hasher initialisation should not fail");

    let h: G2Projective = match hasher.hash(&pk.0) {
        Ok(point) => point.into(),
        Err(_) => return false,
    };
    if h.is_zero() {
        return false;
    }

    // Verify: e(PK, H_pop(PK)) == e(G1_generator, PoP)
    let lhs = Bls12_381::pairing(pk_g1, h);
    let rhs = Bls12_381::pairing(G1Projective::generator(), pop_g2);
    lhs == rhs
}

/// Calculate a domain-separated hash for consensus messages (voting/proposals).
pub fn consensus_message_hash(data: &[u8]) -> crate::hash::Hash {
    crate::hash::domain_hash(crate::hash::DOMAIN_CONSENSUS, data)
}

// --- Specialized Consensus Voting Methods ---

/// Sign a consensus vote (typically the domain-separated block-hash message)
/// using a validator's BLS private key.
pub fn validator_vote_signature(sk: &BlsPrivateKey, block_hash: &[u8]) -> Result<BlsSignature> {
    bls_sign(sk, block_hash)
}

/// Verify a single validator's vote signature against their public key and the voted block hash.
pub fn verify_vote_signature(pk: &BlsPublicKey, block_hash: &[u8], sig: &BlsSignature) -> bool {
    bls_verify(pk, block_hash, sig)
}

/// Aggregate multiple validator votes into a single aggregated BLS signature.
pub fn aggregate_votes(votes: &[BlsSignature]) -> Result<BlsSignature> {
    aggregate_signatures(votes)
}

/// Verify a Quorum Certificate (QC) signature against the aggregated public key of the committee.
pub fn verify_quorum_certificate(
    agg_pk: &BlsPublicKey,
    block_hash: &[u8],
    agg_sig: &BlsSignature,
) -> bool {
    verify_aggregate_signature(agg_pk, block_hash, agg_sig)
}

/// High-performance batch verification of multiple (PK, message, signature) triples.
/// Uses random linear combinations to verify all signatures in O(1) pairing operations on the signature side.
pub fn batch_signature_verification(
    pks: &[BlsPublicKey],
    messages: &[&[u8]],
    sigs: &[BlsSignature],
) -> bool {
    if pks.len() != messages.len() || pks.len() != sigs.len() || pks.is_empty() {
        return false;
    }

    let mut combined_sig = G2Projective::default();
    let mut left_points: Vec<G1Affine> = Vec::with_capacity(pks.len());
    let mut right_points: Vec<G2Affine> = Vec::with_capacity(pks.len());
    let mut rng = OsRng;

    for i in 0..pks.len() {
        let pk = match pks[i].to_g1() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sig = match sigs[i].to_g2() {
            Ok(s) => s,
            Err(_) => return false,
        };
        if pk.is_zero() || sig.is_zero() {
            return false;
        }
        let h = hash_to_g2(messages[i]);
        if h.is_zero() {
            return false;
        }

        // Sample a strictly non-zero random scalar r_i for security against cancellation/rogue-key attacks
        let mut r = Fr::rand(&mut rng);
        while r.is_zero() {
            r = Fr::rand(&mut rng);
        }

        combined_sig += sig * r;
        left_points.push((pk * r).into());
        right_points.push(h.into());
    }

    if combined_sig.is_zero() {
        return false;
    }

    // Check e(G1, CombinedSig) == Product of e(PK_i*r_i, H(m_i))
    let p_left = Bls12_381::pairing(G1Projective::generator(), combined_sig);
    let p_right = Bls12_381::multi_pairing(left_points.iter(), right_points.iter());

    p_left == p_right
}

/// Verify an aggregate BLS signature over distinct messages from multiple public keys.
///
/// Checks that e(G1, agg_sig) == Product_{i=1}^n e(PK_i, H(m_i)) using multi-pairing.
///
/// # Security Invariant
/// All messages MUST be strictly distinct at the cryptographic boundary.
/// If duplicate messages are supplied, rogue-key attacks are possible unless Proof-of-Possession
/// has been verified for all public keys prior to aggregation.
pub fn verify_aggregate_signatures_distinct_messages(
    pks: &[BlsPublicKey],
    messages: &[&[u8]],
    agg_sig: &BlsSignature,
) -> bool {
    if pks.len() != messages.len() || pks.is_empty() {
        return false;
    }

    // Enforce distinct messages using exact canonical byte slices.
    let mut seen = std::collections::HashSet::with_capacity(messages.len());
    for msg in messages {
        if !seen.insert(*msg) {
            return false; // Duplicate message rejected
        }
    }

    let sig_g2 = match agg_sig.to_g2() {
        Ok(s) => s,
        Err(_) => return false,
    };
    if sig_g2.is_zero() {
        return false;
    }

    let mut left_points: Vec<G1Affine> = Vec::with_capacity(pks.len());
    let mut right_points: Vec<G2Affine> = Vec::with_capacity(pks.len());

    for i in 0..pks.len() {
        let pk = match pks[i].to_g1() {
            Ok(p) => p,
            Err(_) => return false,
        };
        if pk.is_zero() {
            return false;
        }
        let h = hash_to_g2(messages[i]);
        if h.is_zero() {
            return false;
        }
        left_points.push(pk.into_affine());
        right_points.push(h.into_affine());
    }

    let p_left = Bls12_381::pairing(G1Projective::generator(), sig_g2);
    let p_right = Bls12_381::multi_pairing(left_points.iter(), right_points.iter());

    p_left == p_right
}

#[cfg(feature = "fuzz-targets")]
pub fn fuzz_target_bls_verification(public_key: &[u8], message: &[u8], signature: &[u8]) {
    let _ = bls_verify(
        &BlsPublicKey(public_key.to_vec()),
        message,
        &BlsSignature(signature.to_vec()),
    );
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_public_keys, aggregate_signatures, aggregate_votes, batch_signature_verification,
        bls_generate_keypair, bls_sign, bls_verify, consensus_message_hash,
        create_proof_of_possession, validator_vote_signature, verify_aggregate_signature,
        verify_proof_of_possession, verify_quorum_certificate, verify_vote_signature,
    };
    use super::{BlsPublicKey, BlsSignature};
    use ark_bls12_381::{G1Affine, G2Affine};
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn generated_bls_keypair_signs_and_verifies() {
        let (private_key, public_key) = bls_generate_keypair();
        let message = b"sxiaum-bls";
        let signature = bls_sign(&private_key, message).expect("bls signing should succeed");

        assert!(bls_verify(&public_key, message, &signature));
    }

    #[test]
    fn aggregate_signature_and_public_key_verify() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message = b"qc-message";

        let sig1 = bls_sign(&sk1, message).expect("signature one should succeed");
        let sig2 = bls_sign(&sk2, message).expect("signature two should succeed");
        let agg_sig = aggregate_signatures(&[sig1.clone(), sig2.clone()])
            .expect("signature aggregation should succeed");
        let agg_pk = aggregate_public_keys(&[pk1.clone(), pk2.clone()])
            .expect("public key aggregation should succeed");

        assert!(verify_aggregate_signature(&agg_pk, message, &agg_sig));
        assert!(verify_quorum_certificate(&agg_pk, message, &agg_sig));
        assert_eq!(
            aggregate_votes(&[sig1, sig2]).expect("vote aggregation should succeed"),
            agg_sig
        );
    }

    #[test]
    fn batch_verification_accepts_valid_signatures() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message_one = b"vote-one";
        let message_two = b"vote-two";
        let sig1 = bls_sign(&sk1, message_one).expect("signature one should succeed");
        let sig2 = bls_sign(&sk2, message_two).expect("signature two should succeed");

        assert!(batch_signature_verification(
            &[pk1, pk2],
            &[message_one.as_slice(), message_two.as_slice()],
            &[sig1, sig2],
        ));
    }

    #[test]
    fn batch_verification_rejects_mismatched_message() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message_one = b"vote-one";
        let message_two = b"vote-two";
        let sig1 = bls_sign(&sk1, message_one).expect("signature one should succeed");
        let sig2 = bls_sign(&sk2, message_two).expect("signature two should succeed");

        assert!(!batch_signature_verification(
            &[pk1, pk2],
            &[message_one.as_slice(), b"tampered".as_slice()],
            &[sig1, sig2],
        ));
    }

    #[test]
    fn vote_signature_helpers_and_consensus_hash_work() {
        let (private_key, public_key) = bls_generate_keypair();
        let block_hash = consensus_message_hash(b"block");
        let vote_signature = validator_vote_signature(&private_key, &block_hash)
            .expect("vote signing should succeed");

        assert!(verify_vote_signature(
            &public_key,
            &block_hash,
            &vote_signature
        ));
        assert_eq!(
            consensus_message_hash(b"block"),
            consensus_message_hash(b"block")
        );
    }

    #[test]
    fn direct_vote_helper_api_round_trips() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let message = consensus_message_hash(b"prepare-vote");
        let sig1 =
            validator_vote_signature(&sk1, &message).expect("first vote signature should succeed");
        let sig2 =
            validator_vote_signature(&sk2, &message).expect("second vote signature should succeed");
        let aggregate_public_key = aggregate_public_keys(&[pk1.clone(), pk2.clone()])
            .expect("public key aggregation should succeed");
        let aggregate_signature = aggregate_votes(&[sig1.clone(), sig2.clone()])
            .expect("vote aggregation should succeed");

        assert!(verify_vote_signature(&pk1, &message, &sig1));
        assert!(verify_vote_signature(&pk2, &message, &sig2));
        assert!(verify_quorum_certificate(
            &aggregate_public_key,
            &message,
            &aggregate_signature,
        ));
    }

    #[test]
    fn storage_serialization_round_trips() {
        let (private_key, public_key) = bls_generate_keypair();
        let signature = bls_sign(&private_key, b"storage").expect("signature should succeed");

        let pubkey_bytes = public_key
            .try_encode_storage()
            .expect("public key serialization should succeed");
        let privkey_bytes = private_key
            .try_encode_storage()
            .expect("private key serialization should succeed");
        let sig_bytes = signature
            .try_encode_storage()
            .expect("signature serialization should succeed");

        let decoded_public_key = bincode::deserialize::<super::BlsPublicKey>(&pubkey_bytes)
            .expect("public key deserialization should succeed");
        let decoded_private_key = bincode::deserialize::<super::BlsPrivateKey>(&privkey_bytes)
            .expect("private key deserialization should succeed");
        let decoded_signature = bincode::deserialize::<super::BlsSignature>(&sig_bytes)
            .expect("signature deserialization should succeed");

        assert_eq!(decoded_public_key, public_key);
        assert_eq!(decoded_private_key, private_key);
        assert_eq!(decoded_signature, signature);
    }

    #[test]
    fn invalid_public_key_and_signature_points_are_rejected() {
        assert!(
            BlsPublicKey(vec![0u8; G1Affine::default().compressed_size()])
                .to_g1()
                .is_err()
        );
        assert!(
            BlsSignature(vec![0u8; G2Affine::default().compressed_size()])
                .to_g2()
                .is_err()
        );
        assert!(BlsPublicKey(vec![1u8; 7]).to_g1().is_err());
        assert!(BlsSignature(vec![1u8; 7]).to_g2().is_err());
    }

    // - TICKET-04: IETF SWU hash-to-G2 and Proof-of-Possession tests -

    #[test]
    fn ietf_hash_to_g2_sign_verify_round_trips() {
        // Basic sanity: the new IETF hash-to-G2 function still produces
        // valid signatures that verify correctly.
        let (sk, pk) = bls_generate_keypair();
        let msg = b"sxiaum-ietf-h2c";
        let sig = bls_sign(&sk, msg).expect("signing should succeed");
        assert!(bls_verify(&pk, msg, &sig), "signature should verify");
    }

    #[test]
    fn ietf_hash_to_g2_different_messages_produce_different_hashes() {
        // Two distinct messages must not map to the same G2 point.
        let (sk, _) = bls_generate_keypair();
        let sig1 = bls_sign(&sk, b"message-A").expect("sig1");
        let sig2 = bls_sign(&sk, b"message-B").expect("sig2");
        assert_ne!(
            sig1.0, sig2.0,
            "distinct messages must produce distinct signatures"
        );
    }

    #[test]
    fn proof_of_possession_verifies_correctly() {
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).expect("PoP creation should succeed");
        assert!(
            verify_proof_of_possession(&pk, &pop),
            "PoP should verify against the matching public key"
        );
    }

    #[test]
    fn proof_of_possession_rejects_wrong_public_key() {
        let (sk1, pk1) = bls_generate_keypair();
        let (_, pk2) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk1, &pk1).expect("PoP creation should succeed");
        // The PoP was created over pk1's bytes; it must not verify against pk2.
        assert!(
            !verify_proof_of_possession(&pk2, &pop),
            "PoP must not verify against a different public key"
        );
    }

    #[test]
    fn proof_of_possession_does_not_verify_as_regular_vote_signature() {
        // A PoP must not be replayable as a vote signature because the DSTs differ.
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).expect("PoP creation should succeed");
        // The PoP is a signature over pk.0 (the compressed public key) under POP_DST.
        // Attempting to verify it as a vote signature over pk.0 with the
        // consensus DST should fail.
        assert!(
            !bls_verify(&pk, &pk.0, &pop),
            "PoP must not verify as a regular vote signature"
        );
    }

    #[test]
    fn aggregate_signatures_distinct_messages_verifies() {
        let (sk1, pk1) = bls_generate_keypair();
        let (sk2, pk2) = bls_generate_keypair();
        let (sk3, pk3) = bls_generate_keypair();

        let msg1 = b"tx-batch-1";
        let msg2 = b"tx-batch-2";
        let msg3 = b"tx-batch-3";

        let sig1 = bls_sign(&sk1, msg1).expect("sig1");
        let sig2 = bls_sign(&sk2, msg2).expect("sig2");
        let sig3 = bls_sign(&sk3, msg3).expect("sig3");

        let agg_sig = aggregate_signatures(&[sig1, sig2, sig3]).expect("aggregate");

        let pks = vec![pk1, pk2, pk3];
        let msgs = vec![msg1.as_slice(), msg2.as_slice(), msg3.as_slice()];

        assert!(super::verify_aggregate_signatures_distinct_messages(
            &pks, &msgs, &agg_sig
        ));

        // Tampered message should fail
        let tampered_msgs = vec![msg1.as_slice(), b"tampered".as_slice(), msg3.as_slice()];
        assert!(!super::verify_aggregate_signatures_distinct_messages(
            &pks,
            &tampered_msgs,
            &agg_sig
        ));
    }
}
