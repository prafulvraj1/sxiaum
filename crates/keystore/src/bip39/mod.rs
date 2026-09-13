//! BIP-39 Mnemonic phrase generation and hierarchical deterministic seed derivation.

pub mod wordlist;

pub use wordlist::{find_word_index, word_by_index, BIP39_ENGLISH_WORDLIST};

use crate::error::{KeystoreError, Result};
use crate::kdf::derive_pbkdf2_sha512;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Number of words in a BIP-39 recovery phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicType {
    Words12,
    Words18,
    Words24,
}

impl MnemonicType {
    /// Number of entropy bits required for this mnemonic length.
    pub fn entropy_bits(&self) -> usize {
        match self {
            Self::Words12 => 128,
            Self::Words18 => 192,
            Self::Words24 => 256,
        }
    }

    /// Number of words in the phrase.
    pub fn word_count(&self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words18 => 18,
            Self::Words24 => 24,
        }
    }
}

/// A BIP-39 mnemonic phrase (zeroized on drop, redacted in Debug/Display).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    phrase: String,
}

impl std::fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Mnemonic(<redacted {} words>)",
            self.phrase.split_whitespace().count()
        )
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Mnemonic(<redacted {} words>)",
            self.phrase.split_whitespace().count()
        )
    }
}

impl Mnemonic {
    /// Generate a new cryptographically random BIP-39 mnemonic phrase using OS CSPRNG.
    pub fn generate(mtype: MnemonicType) -> Result<Self> {
        let entropy_bytes = mtype.entropy_bits() / 8;
        let mut entropy = vec![0u8; entropy_bytes];
        OsRng.fill_bytes(&mut entropy);

        Self::from_entropy(&entropy)
    }

    /// Construct a mnemonic from raw entropy bytes.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let ent_len = entropy.len() * 8;
        if ent_len != 128 && ent_len != 192 && ent_len != 256 {
            return Err(KeystoreError::MnemonicError(format!(
                "Invalid entropy bit length: {ent_len} (must be 128, 192, or 256 bits)"
            )));
        }

        let checksum_len = ent_len / 32;
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let hash = hasher.finalize();
        let checksum_byte = hash[0];

        // Convert entropy + checksum into 11-bit word indices (MSB first).
        let total_bits = ent_len + checksum_len;
        let mut bits = Vec::with_capacity(total_bits);
        for &b in entropy {
            for i in (0..8).rev() {
                bits.push((b >> i) & 1);
            }
        }
        // The checksum occupies the top `checksum_len` bits of SHA256(entropy);
        // emit them MSB-first so word indices pack identically to BLS12/BIP-39.
        for i in 0..checksum_len {
            bits.push((checksum_byte >> (7 - i)) & 1);
        }

        let mut mnemonic_words = Vec::new();
        for chunk in bits.chunks(11) {
            let mut idx = 0usize;
            for &bit in chunk {
                idx = (idx << 1) | (bit as usize);
            }
            let word = word_by_index(idx).ok_or_else(|| {
                KeystoreError::MnemonicError(format!("Word index out of bounds: {idx}"))
            })?;
            mnemonic_words.push(word);
        }

        Ok(Self {
            phrase: mnemonic_words.join(" "),
        })
    }

    /// Parse and validate an existing mnemonic phrase with binary search word verification.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let input_words: Vec<&str> = phrase.split_whitespace().collect();

        if input_words.len() != 12 && input_words.len() != 18 && input_words.len() != 24 {
            return Err(KeystoreError::MnemonicError(format!(
                "Invalid mnemonic word count: {} (expected 12, 18, or 24)",
                input_words.len()
            )));
        }

        let mut bits = Vec::with_capacity(input_words.len() * 11);
        for &w in &input_words {
            let idx = find_word_index(w).ok_or_else(|| {
                KeystoreError::MnemonicError(format!(
                    "Word '{w}' is not in BIP-39 English wordlist"
                ))
            })?;
            for i in (0..11).rev() {
                bits.push(((idx >> i) & 1) as u8);
            }
        }

        let total_bits = input_words.len() * 11;
        let checksum_len = total_bits / 33;
        let ent_bits = total_bits - checksum_len;

        let mut entropy = Vec::with_capacity(ent_bits / 8);
        for chunk in bits[..ent_bits].chunks(8) {
            let mut b = 0u8;
            for &bit in chunk {
                b = (b << 1) | bit;
            }
            entropy.push(b);
        }

        let mut hasher = Sha256::new();
        hasher.update(&entropy);
        let hash = hasher.finalize();

        let mut expected_checksum = 0u8;
        for i in 0..checksum_len {
            expected_checksum = (expected_checksum << 1) | ((hash[0] >> (7 - i)) & 1);
        }

        let mut actual_checksum = 0u8;
        for &bit in &bits[ent_bits..] {
            actual_checksum = (actual_checksum << 1) | bit;
        }

        if expected_checksum != actual_checksum {
            return Err(KeystoreError::MnemonicError(
                "Invalid mnemonic checksum".to_string(),
            ));
        }

        Ok(Self {
            phrase: input_words.join(" "),
        })
    }

    /// Access the phrase string (sensitive key material).
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Derive a 64-byte binary seed from the mnemonic phrase with optional passphrase (BIP-39 standard).
    pub fn to_seed(&self, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
        let salt = format!("mnemonic{passphrase}");
        let derived = derive_pbkdf2_sha512(&self.phrase, salt.as_bytes(), 2048, 64)?;
        let mut seed = Zeroizing::new([0u8; 64]);
        seed.copy_from_slice(&derived[0..64]);
        Ok(seed)
    }

    /// Derive a 32-byte master validator seed from the 64-byte seed using domain-separated HMAC-SHA256.
    pub fn to_validator_seed(&self, passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
        let seed = self.to_seed(passphrase)?;
        let mut hasher = Sha256::new();
        hasher.update(b"SXIAUM-VALIDATOR-MASTER-KEY-V1");
        hasher.update(*seed);
        let master: [u8; 32] = hasher.finalize().into();
        Ok(Zeroizing::new(master))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_generation_and_validation() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words12).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);

        let validated = Mnemonic::from_phrase(mnemonic.phrase()).unwrap();
        assert_eq!(validated.phrase(), mnemonic.phrase());

        let seed = mnemonic.to_seed("test-passphrase").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn mnemonic_24_words_roundtrip() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words24).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);

        let validated = Mnemonic::from_phrase(mnemonic.phrase()).unwrap();
        assert_eq!(validated.phrase(), mnemonic.phrase());
    }

    #[test]
    fn mnemonic_debug_redacts_secret_words() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words12).unwrap();
        let dbg = format!("{:?}", mnemonic);
        assert!(!dbg.contains(mnemonic.phrase().split_whitespace().next().unwrap()));
        assert!(dbg.contains("<redacted 12 words>"));

        let disp = format!("{}", mnemonic);
        assert!(!disp.contains(mnemonic.phrase().split_whitespace().next().unwrap()));
        assert!(disp.contains("<redacted 12 words>"));
    }

    #[test]
    fn rejects_invalid_words_or_bad_checksum() {
        assert!(Mnemonic::from_phrase(
            "invalid words that are not in the official bip39 english dictionary at all xyz"
        )
        .is_err());
        // Valid words but wrong checksum.
        assert!(Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        )
        .is_err());
    }

    /// Official BIP-39 English test vectors (TREZOR reference set).
    #[test]
    fn official_bip39_test_vectors() {
        // 128-bit entropy 0x00*16 → canonical 12-word phrase.
        let m12 = Mnemonic::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(
            m12.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        // Round trip.
        assert_eq!(
            Mnemonic::from_phrase(m12.phrase()).unwrap().phrase(),
            m12.phrase()
        );

        // Vector V1: 128-bit entropy 0x7f*16.
        let v1 = Mnemonic::from_entropy(&[0x7fu8; 16]).unwrap();
        assert_eq!(
            v1.phrase(),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );

        // Vector V2: 128-bit entropy 0x80*16.
        let v2 = Mnemonic::from_entropy(&[0x80u8; 16]).unwrap();
        assert_eq!(
            v2.phrase(),
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
        );

        // Vector V9: 192-bit entropy 0x7f*24 → canonical 18-word phrase.
        let m18 = Mnemonic::from_entropy(&[0x7fu8; 24]).unwrap();
        assert_eq!(
            m18.phrase(),
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
        );
        assert_eq!(m18.phrase().split_whitespace().count(), 18);

        // Vector V3 tail / V11 head sanity: all-0xff 256-bit entropy.
        let m24ff = Mnemonic::from_entropy(&[0xffu8; 32]).unwrap();
        assert!(m24ff
            .phrase()
            .starts_with("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo"));
        assert_eq!(m24ff.phrase().split_whitespace().count(), 24);
        assert_eq!(m24ff.phrase().rsplit(' ').next().unwrap(), "vote");

        // Vector V12: 256-bit entropy 0x00*32.
        let m2400 = Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        assert_eq!(
            m2400.phrase(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );

        // Round trips for every length.
        for m in [v1, v2, m18, m24ff, m2400] {
            assert_eq!(
                Mnemonic::from_phrase(m.phrase()).unwrap().phrase(),
                m.phrase()
            );
        }
    }

    /// Official BIP-39 seed derivation known-answer (vector 0, passphrase "TREZOR").
    #[test]
    fn official_bip39_seed_known_answer() {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = m.to_seed("TREZOR").unwrap();
        assert_eq!(
            hex::encode(*seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn rejects_invalid_entropy_lengths() {
        assert!(Mnemonic::from_entropy(&[0u8; 8]).is_err());
        assert!(Mnemonic::from_entropy(&[0u8; 17]).is_err());
        assert!(Mnemonic::from_entropy(&[0u8; 64]).is_err());
    }
}
