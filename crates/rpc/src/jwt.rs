use anyhow::{bail, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtKey {
    pub kid: String,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtKeyset {
    pub keys: Vec<JwtKey>,
}

/// How often the keys file may be stat-ed for modification changes. The
/// previous implementation ran a metadata syscall on EVERY token validation;
/// under load that is a per-request filesystem round trip for a file that
/// essentially never changes.
const RELOAD_CHECK_INTERVAL: Duration = Duration::from_secs(1);

pub struct JwtManager {
    keys_file: Option<PathBuf>,
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    last_modified: Arc<RwLock<Option<SystemTime>>>,
    last_check: Arc<RwLock<Instant>>,
}

impl JwtManager {
    pub fn new(keys_file: Option<PathBuf>) -> Self {
        Self {
            keys_file,
            keys: Arc::new(RwLock::new(HashMap::new())),
            last_modified: Arc::new(RwLock::new(None)),
            last_check: Arc::new(RwLock::new(Instant::now() - RELOAD_CHECK_INTERVAL)),
        }
    }

    pub async fn reload_if_changed(&self) -> Result<()> {
        let Some(path) = &self.keys_file else {
            return Ok(());
        };

        if !path.exists() {
            return Ok(());
        }

        // Throttle the filesystem check to at most once per interval.
        {
            let mut last = self.last_check.write().await;
            if last.elapsed() < RELOAD_CHECK_INTERVAL {
                return Ok(());
            }
            *last = Instant::now();
        }

        let meta = std::fs::metadata(path)?;
        let modified = meta.modified()?;

        let last_mod = *self.last_modified.read().await;
        if last_mod == Some(modified) {
            return Ok(()); // Unchanged
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read JWT keys file: {}", path.display()))?;
        let keyset: JwtKeyset = serde_json::from_str(&content)
            .with_context(|| "failed to parse JWT keys file as JSON keyset")?;

        let mut new_keys = HashMap::new();
        for mut key in keyset.keys {
            if key.secret.len() < crate::MIN_JWT_SECRET_BYTES {
                warn!(
                    "JWT key with kid '{}' is too short (< {} bytes). Skipping.",
                    key.kid,
                    crate::MIN_JWT_SECRET_BYTES
                );
            } else {
                new_keys.insert(
                    key.kid.clone(),
                    DecodingKey::from_secret(key.secret.as_bytes()),
                );
            }
            // SECURITY: scrub plaintext secret material from memory as soon
            // as the decoding key owns its own copy.
            use zeroize::Zeroize;
            key.secret.zeroize();
        }

        *self.keys.write().await = new_keys;
        *self.last_modified.write().await = Some(modified);

        info!("Reloaded JWT keys from file: {}", path.display());
        Ok(())
    }

    pub async fn validate_token<T: serde::de::DeserializeOwned>(&self, token: &str) -> Result<T> {
        self.reload_if_changed().await.unwrap_or_else(|e| {
            warn!("Failed to reload JWT keys: {}", e);
        });

        let header = decode_header(token).with_context(|| "Invalid JWT header")?;
        let kid = header.kid.unwrap_or_else(|| "default".to_string());

        // Check if we have the key loaded from file
        let loaded = self.keys.read().await.get(&kid).cloned();
        let decoding_key = match loaded {
            Some(key) => key,
            None => {
                // Fallback to SXIAUM_RPC_JWT_SECRET (or legacy SXIAUM_JWT_SECRET)
                // environment variable for backward compatibility.
                match std::env::var("SXIAUM_RPC_JWT_SECRET")
                    .or_else(|_| std::env::var("SXIAUM_JWT_SECRET"))
                {
                    Ok(env_secret) => {
                        if env_secret.len() >= crate::MIN_JWT_SECRET_BYTES {
                            DecodingKey::from_secret(env_secret.as_bytes())
                        } else {
                            bail!("JWT token rejected: unknown kid '{}' and fallback SXIAUM_RPC_JWT_SECRET is too short (< 32 bytes)", kid);
                        }
                    }
                    Err(_) => {
                        bail!("JWT token rejected: unknown kid '{}' and no fallback SXIAUM_RPC_JWT_SECRET found", kid)
                    }
                }
            }
        };

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp"]);
        let token_data = decode::<T>(token, &decoding_key, &validation)
            .with_context(|| "Failed to validate JWT signature")?;

        Ok(token_data.claims)
    }
}
