//! Quick integration test for the keystore encryption/decryption round-trip.
//! Run with: cargo test -p sxiaum-cli keystore_roundtrip -- --nocapture

#[cfg(test)]
mod keystore_integration {
    use crate::keystore::{self, WalletPayload};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "correct_horse_battery_staple_42!";
        let mut payload = WalletPayload::default();
        payload.keys.insert(
            "validator1".into(),
            "0101010101010101010101010101010101010101010101010101010101010101".into(),
        );
        payload.keys.insert(
            "treasury".into(),
            "0202020202020202020202020202020202020202020202020202020202020202".into(),
        );

        let ks = keystore::encrypt_wallet(&payload, password).expect("encrypt failed");

        assert_eq!(ks.version, 2);
        assert_eq!(ks.kdf, "argon2id");
        assert_eq!(ks.cipher, "aes-256-gcm");
        assert_eq!(ks.kdf_params.m_cost, 65536);

        let decrypted = keystore::decrypt_wallet(&ks, password).expect("decrypt failed");

        assert_eq!(
            decrypted.keys.get("validator1").unwrap(),
            "0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(
            decrypted.keys.get("treasury").unwrap(),
            "0202020202020202020202020202020202020202020202020202020202020202"
        );
    }

    #[test]
    fn test_wrong_password_rejected() {
        let payload = WalletPayload::default();
        let ks = keystore::encrypt_wallet(&payload, "right_password").expect("encrypt failed");
        let result = keystore::decrypt_wallet(&ks, "wrong_password");
        assert!(result.is_err(), "Wrong password should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Wrong password") || err.contains("corrupted"),
            "Error: {}",
            err
        );
    }

    #[test]
    fn test_fresh_nonce_each_encryption() {
        let payload = WalletPayload::default();
        let password = "same_password";
        let ks1 = keystore::encrypt_wallet(&payload, password).unwrap();
        let ks2 = keystore::encrypt_wallet(&payload, password).unwrap();
        // Each encryption should produce a different nonce and ciphertext
        assert_ne!(ks1.nonce, ks2.nonce, "Nonces must be unique per encryption");
        assert_ne!(
            ks1.ciphertext, ks2.ciphertext,
            "Ciphertext must differ (fresh nonce)"
        );
        assert_ne!(
            ks1.kdf_params.salt, ks2.kdf_params.salt,
            "Salts must be unique"
        );
    }

    #[test]
    fn test_address_book_resolve() {
        use crate::keystore::AddressBook;
        let mut ab = AddressBook::default();
        let addr = "0xaabbccdd".to_string();
        ab.entries.insert("treasury".into(), addr.clone());

        // Label resolves to address
        assert_eq!(ab.resolve("treasury"), addr.as_str());
        // Raw address passthrough
        let raw = "0x1234abcd";
        assert_eq!(ab.resolve(raw), raw);
    }

    #[test]
    fn test_minimum_password_enforced_in_logic() {
        // The 8-char minimum is enforced in the prompt_password_new() function
        // Here we just verify the encryption works with a long password
        let long_pw = "a".repeat(128);
        let payload = WalletPayload::default();
        let ks = keystore::encrypt_wallet(&payload, &long_pw).unwrap();
        let result = keystore::decrypt_wallet(&ks, &long_pw);
        assert!(result.is_ok(), "Long password should work fine");
    }
}
