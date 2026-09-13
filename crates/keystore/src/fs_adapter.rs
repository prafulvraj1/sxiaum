use super::{validate_key_id, KeyEntry, KeyStore};
use crate::error::{KeystoreError, Result};
use crate::format::eip2335::Eip2335Keystore;
use crate::format::native::NativeKeystoreWrapper;
use crate::format::web3_v3::Web3Keystore;
use crate::password::{is_production, validate_password};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

fn key_path(dir: &Path, id: &str) -> Result<PathBuf> {
    validate_key_id(id).map_err(|e| KeystoreError::InvalidKeyId(e.to_string()))?;
    // `.tmp.` is a reserved suffix fragment used by atomic writes; reject it so
    // temporary files can never be mistaken for (or clobber) real key entries.
    if id.contains(".tmp.") {
        return Err(KeystoreError::InvalidKeyId(format!(
            "key id '{id}' uses the reserved '.tmp.' fragment"
        )));
    }
    let path = dir.join(id);
    for c in path.components() {
        if matches!(c, std::path::Component::ParentDir) {
            return Err(KeystoreError::PathTraversal(id.to_string()));
        }
    }
    Ok(path)
}

/// Filesystem-backed encrypted keystore with Argon2id + AES-256-GCM and multi-format support.
pub struct FsKeyStore {
    dir: PathBuf,
    password: Option<Zeroizing<String>>,
}

impl FsKeyStore {
    /// Create a plaintext keystore (forbidden when `SXIAUM_ENV=production`).
    pub fn new(dir: impl AsRef<Path>) -> Self {
        FsKeyStore {
            dir: dir.as_ref().to_path_buf(),
            password: None,
        }
    }

    /// Create an encrypted keystore with Argon2id + AES-256-GCM.
    ///
    /// The passphrase is validated against the environment password policy
    /// immediately, so weak passphrases are rejected before any key is written.
    pub fn new_encrypted(dir: impl AsRef<Path>, password: String) -> Result<Self> {
        validate_password(&password)?;
        Ok(FsKeyStore {
            dir: dir.as_ref().to_path_buf(),
            password: Some(Zeroizing::new(password)),
        })
    }

    /// Update/re-encrypt a key with a new passphrase explicitly.
    pub async fn change_password(
        &self,
        id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        validate_password(new_password)?;
        let entry = self
            .get_with_password(id, old_password)
            .await?
            .ok_or_else(|| KeystoreError::KeyNotFound(id.to_string()))?;

        let wrapper = NativeKeystoreWrapper::encrypt(&entry, new_password)?;
        let data = serde_json::to_vec_pretty(&wrapper)?;
        self.write_atomic(id, &data).await?;
        tracing::info!("Successfully re-encrypted key '{}' with new passphrase", id);
        Ok(())
    }

    /// Decrypt a key with an explicitly provided passphrase (overriding default).
    pub async fn get_with_password(&self, id: &str, password: &str) -> Result<Option<KeyEntry>> {
        let path = key_path(&self.dir, id)?;
        if path.is_symlink() {
            return Err(KeystoreError::PathTraversal(format!(
                "symlink key paths are forbidden: {}",
                path.display()
            )));
        }

        match fs::read(&path).await {
            Ok(bytes) => {
                let entry = crate::format::detect_and_decrypt(&bytes, password, id)?;
                Ok(Some(entry))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KeystoreError::Io(e)),
        }
    }

    /// Import an EIP-2335 keystore JSON directly into this keystore.
    pub async fn import_eip2335(
        &self,
        id: &str,
        eip: &Eip2335Keystore,
        password: &str,
    ) -> Result<()> {
        validate_key_id(id).map_err(|e| KeystoreError::InvalidKeyId(e.to_string()))?;
        let entry = eip.to_key_entry(password, id)?;
        self.put(entry).await
    }

    /// Import a Web3 Secret Storage v3 keystore JSON directly into this keystore.
    pub async fn import_web3_v3(&self, w3: &Web3Keystore, password: &str) -> Result<()> {
        let entry = w3.to_key_entry(password)?;
        self.put(entry).await
    }

    /// Internal atomic file write helper with restrictive permissions and crash safety.
    async fn write_atomic(&self, id: &str, data: &[u8]) -> Result<()> {
        if data.len() > crate::MAX_KEY_DATA_SIZE {
            return Err(KeystoreError::InvalidKeyLength {
                expected: crate::MAX_KEY_DATA_SIZE,
                actual: data.len(),
            });
        }

        fs::create_dir_all(&self.dir).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }

        let path = key_path(&self.dir, id)?;
        if path.is_symlink() {
            return Err(KeystoreError::PathTraversal(format!(
                "symlink target paths are forbidden: {}",
                path.display()
            )));
        }

        let rnd = rand::random::<u64>();
        let tmp = path.with_extension(format!("tmp.{}", rnd));

        let write_res: Result<()> = async {
            #[cfg(unix)]
            let mut file = {
                use std::os::unix::fs::OpenOptionsExt;
                let mut opts = fs::OpenOptions::new();
                opts.write(true).create_new(true).mode(0o600);
                opts.open(&tmp).await?
            };

            #[cfg(not(unix))]
            let mut file = {
                let mut opts = fs::OpenOptions::new();
                opts.write(true).create_new(true);
                opts.open(&tmp).await?
            };

            file.write_all(data).await?;
            file.flush().await?;
            file.sync_all().await?;
            drop(file);

            #[cfg(windows)]
            {
                if path.exists() {
                    let _ = fs::remove_file(&path).await;
                }
            }

            fs::rename(&tmp, &path).await?;
            Ok(())
        }
        .await;

        if write_res.is_err() {
            let _ = fs::remove_file(&tmp).await;
        }

        write_res
    }
}

#[async_trait]
impl KeyStore for FsKeyStore {
    async fn put(&self, key: KeyEntry) -> Result<()> {
        if self.password.is_none() {
            if is_production() {
                return Err(KeystoreError::PlaintextForbiddenInProduction);
            }
            tracing::warn!(
                "FsKeyStore writing UNENCRYPTED key material for key '{}'",
                key.id
            );
        }

        let data = if let Some(ref pass) = self.password {
            validate_password(pass.as_str())?;
            let wrapper = NativeKeystoreWrapper::encrypt(&key, pass.as_str())?;
            serde_json::to_vec_pretty(&wrapper)?
        } else {
            serde_json::to_vec_pretty(&key)?
        };

        self.write_atomic(&key.id, &data).await
    }

    async fn get(&self, id: &str) -> Result<Option<KeyEntry>> {
        let path = key_path(&self.dir, id)?;
        if path.is_symlink() {
            return Err(KeystoreError::PathTraversal(format!(
                "symlink key paths are forbidden: {}",
                path.display()
            )));
        }

        match fs::read(&path).await {
            Ok(bytes) => {
                if let Some(ref pass) = self.password {
                    // Decrypt without silent on-disk mutation.
                    let entry = crate::format::detect_and_decrypt(&bytes, pass.as_str(), id)?;
                    Ok(Some(entry))
                } else {
                    if is_production() {
                        return Err(KeystoreError::PlaintextForbiddenInProduction);
                    }
                    if let Ok(wrapper) = serde_json::from_slice::<NativeKeystoreWrapper>(&bytes) {
                        if !wrapper.salt.is_empty() && !wrapper.nonce.is_empty() {
                            return Err(KeystoreError::CorruptedKeystore(
                                id.to_string(),
                                "key is encrypted; passphrase is required".to_string(),
                            ));
                        }
                    }
                    let entry: KeyEntry = serde_json::from_slice(&bytes)?;
                    Ok(Some(entry))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KeystoreError::Io(e)),
        }
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let path = key_path(&self.dir, id)?;
        if path.is_symlink() {
            return Err(KeystoreError::PathTraversal(format!(
                "symlink key paths are forbidden: {}",
                path.display()
            )));
        }
        match fs::remove_file(path).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KeystoreError::Io(e)),
        }
    }

    async fn list(&self) -> Result<Vec<String>> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = fs::read_dir(&self.dir).await?;
        let mut keys = Vec::new();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() && !path.is_symlink() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.contains(".tmp") && validate_key_id(name).is_ok() {
                        keys.push(name.to_string());
                    }
                }
            }
        }
        keys.sort();
        Ok(keys)
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        let path = key_path(&self.dir, id)?;
        if path.is_symlink() {
            return Err(KeystoreError::PathTraversal(format!(
                "symlink key paths are forbidden: {}",
                path.display()
            )));
        }
        Ok(path.is_file())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyStoreExt;
    use sxiaum_crypto::ed25519::PrivateKey as Ed25519PrivateKey;
    use sxiaum_types::Address;
    use tempfile::tempdir;

    #[tokio::test]
    async fn fs_keystore_round_trips_key_entry_plaintext() {
        let tempdir = tempdir().expect("tempdir should create");
        let store = FsKeyStore::new(tempdir.path());
        let entry = KeyEntry {
            id: "groth16-pk".to_string(),
            kind: "proving-key".to_string(),
            data: b"proving-key-bytes".to_vec(),
        };

        store.put(entry.clone()).await.expect("put should succeed");

        assert!(store.exists("groth16-pk").await.expect("exists check"));
        let loaded = store
            .get("groth16-pk")
            .await
            .expect("get should succeed")
            .expect("entry should exist");
        assert_eq!(loaded, entry);

        let list = store.list().await.expect("list should succeed");
        assert_eq!(list, vec!["groth16-pk".to_string()]);

        store
            .delete("groth16-pk")
            .await
            .expect("delete should succeed");
        assert!(!store.exists("groth16-pk").await.expect("exists check"));
        assert!(store
            .get("groth16-pk")
            .await
            .expect("get should succeed")
            .is_none());
    }

    #[tokio::test]
    async fn fs_keystore_round_trips_key_entry_encrypted() {
        let tempdir = tempdir().expect("tempdir should create");
        let store =
            FsKeyStore::new_encrypted(tempdir.path(), "my-secure-passphrase123!".to_string())
                .unwrap();
        let entry = KeyEntry {
            id: "groth16-pk-enc".to_string(),
            kind: "proving-key".to_string(),
            data: b"proving-key-bytes-encrypted".to_vec(),
        };

        store.put(entry.clone()).await.expect("put should succeed");

        // Should load successfully with correct password
        let loaded = store
            .get("groth16-pk-enc")
            .await
            .expect("get should succeed")
            .expect("entry should exist");
        assert_eq!(loaded, entry);

        // Loading with wrong password or plaintext mode should fail
        let plaintext_store = FsKeyStore::new(tempdir.path());
        let res = plaintext_store.get("groth16-pk-enc").await;
        assert!(res.is_err());

        let wrong_password_store =
            FsKeyStore::new_encrypted(tempdir.path(), "wrong-passphrase123!".to_string()).unwrap();
        let res_wrong = wrong_password_store.get("groth16-pk-enc").await;
        assert!(res_wrong.is_err());
    }

    #[tokio::test]
    async fn fs_keystore_typed_keys_round_trip() {
        let tempdir = tempdir().expect("tempdir should create");
        let store =
            FsKeyStore::new_encrypted(tempdir.path(), "Passphrase123456789!".to_string()).unwrap();

        let ed_key = Ed25519PrivateKey([7u8; 32]);
        store
            .put_ed25519_key("validator-ed25519", &ed_key)
            .await
            .expect("put ed25519");

        let loaded_ed = store
            .get_ed25519_key("validator-ed25519")
            .await
            .expect("get ed25519")
            .expect("ed25519 should exist");
        assert_eq!(loaded_ed.0, [7u8; 32]);

        let addr = Address([3u8; 32]);
        let mut priv_key = [0u8; 32];
        priv_key[31] = 0x42;
        store
            .put_account_key(&addr, &priv_key)
            .await
            .expect("put account key");

        let loaded_acc = store
            .get_account_key(&addr)
            .await
            .expect("get account key")
            .expect("account key should exist");
        assert_eq!(loaded_acc, priv_key);
    }

    #[tokio::test]
    async fn fs_keystore_password_change_works() {
        let tempdir = tempdir().expect("tempdir should create");
        let store =
            FsKeyStore::new_encrypted(tempdir.path(), "InitialPassphrase123!".to_string()).unwrap();

        let ed_key = Ed25519PrivateKey([11u8; 32]);
        store
            .put_ed25519_key("val-key", &ed_key)
            .await
            .expect("put ed25519");

        // Change password
        store
            .change_password(
                "val-key",
                "InitialPassphrase123!",
                "NewSecretPassphrase456!",
            )
            .await
            .expect("change password");

        // Old store fails to read
        assert!(store.get("val-key").await.is_err());

        // New store reads successfully
        let new_store =
            FsKeyStore::new_encrypted(tempdir.path(), "NewSecretPassphrase456!".to_string())
                .unwrap();
        let loaded = new_store
            .get_ed25519_key("val-key")
            .await
            .expect("get key")
            .expect("key exists");
        assert_eq!(loaded.0, [11u8; 32]);
    }

    #[tokio::test]
    async fn rejects_parent_dir_id() {
        let tempdir = tempdir().expect("tempdir should create");
        let store = FsKeyStore::new(tempdir.path());
        let entry = KeyEntry {
            id: "../escape".to_string(),
            kind: "ed25519".to_string(),
            data: vec![1; 32],
        };
        assert!(store.put(entry).await.is_err());
    }

    #[tokio::test]
    async fn rejects_slash_id() {
        let tempdir = tempdir().expect("tempdir should create");
        let store = FsKeyStore::new(tempdir.path());
        let entry = KeyEntry {
            id: "a/b".to_string(),
            kind: "ed25519".to_string(),
            data: vec![1; 32],
        };
        assert!(store.put(entry).await.is_err());
    }

    #[tokio::test]
    async fn rejects_reserved_tmp_fragment_id() {
        let tempdir = tempdir().expect("tempdir should create");
        let store = FsKeyStore::new(tempdir.path());
        let entry = KeyEntry {
            id: "key.tmp.12345".to_string(),
            kind: "ed25519".to_string(),
            data: vec![1; 32],
        };
        assert!(store.put(entry).await.is_err());
        assert!(store.get("key.tmp.12345").await.is_err());
    }

    #[test]
    fn encrypted_constructor_rejects_weak_passphrase() {
        let tempdir = tempdir().expect("tempdir should create");
        // Too short + dictionary word.
        assert!(FsKeyStore::new_encrypted(tempdir.path(), "password".to_string()).is_err());
        // Repeated characters.
        assert!(FsKeyStore::new_encrypted(tempdir.path(), "aaaaaaaaaaaa".to_string()).is_err());
        // Valid passphrase constructs fine.
        assert!(
            FsKeyStore::new_encrypted(tempdir.path(), "Str0ng-Passphrase!".to_string()).is_ok()
        );
    }
}
