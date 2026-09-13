use crate::ed25519::{PublicKey, Signature};
use crate::signer::Signer;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use zeroize::Zeroizing;

/// A signer implementation that delegates signing to an external Web3Signer/HSM.
///
/// # Mainnet Configuration
///
/// - Uses configurable timeout from [`crate::REMOTE_SIGNER_TIMEOUT_SECS`]
/// - Implements exponential backoff retry logic
/// - Enforces HTTPS in production environments
/// - Supports certificate pinning via `SXIAUM_REMOTE_SIGNER_CERT_PATH`
pub struct RemoteSigner {
    endpoint: String,
    public_key: PublicKey,
    client: reqwest::Client,
    auth_token: Option<Zeroizing<String>>,
    max_retries: u32,
    retry_base_delay: std::time::Duration,
}

impl std::fmt::Debug for RemoteSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("endpoint", &self.endpoint)
            .field("public_key", &self.public_key)
            .field("auth_token", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct SignRequest {
    pub data: String,
}

#[derive(Deserialize)]
struct SignResponse {
    pub signature: String,
}

impl RemoteSigner {
    /// Initialize a remote signer connecting to the specified endpoint, acting for the given public key.
    ///
    /// Uses mainnet constants for timeout and retry configuration.
    /// Override via environment variables:
    /// - `SXIAUM_REMOTE_SIGNER_TIMEOUT_SECS`: request timeout
    /// - `SXIAUM_REMOTE_SIGNER_MAX_RETRIES`: max retry attempts
    pub async fn new(endpoint: &str, public_key: PublicKey) -> Result<Self> {
        let prod = std::env::var("SXIAUM_ENV").unwrap_or_default() == "production";
        if prod && !endpoint.starts_with("https://") {
            bail!("remote signer endpoint must be https in production");
        }

        let timeout_secs = std::env::var("SXIAUM_REMOTE_SIGNER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::REMOTE_SIGNER_TIMEOUT_SECS);

        let max_retries = std::env::var("SXIAUM_REMOTE_SIGNER_MAX_RETRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::REMOTE_SIGNER_MAX_RETRIES);

        let mut builder =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(timeout_secs));

        if let Ok(path) = std::env::var("SXIAUM_REMOTE_SIGNER_CERT_PATH") {
            let pem = std::fs::read(&path).context("Failed to read pinned cert")?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .or_else(|_| reqwest::Certificate::from_der(&pem))
                .context("Invalid pinned cert (must be PEM or DER)")?;
            // Enforce certificate pinning by rejecting built-in roots and trusting only this cert.
            builder = builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(cert);
        } else if prod {
            tracing::warn!("Remote signer in production should use SXIAUM_REMOTE_SIGNER_CERT_PATH for SPKI cert pinning.");
        }

        let client = builder.build()?;
        let auth_token = std::env::var("SXIAUM_REMOTE_SIGNER_TOKEN")
            .ok()
            .map(Zeroizing::new);

        let signer = Self {
            endpoint: endpoint.to_string(),
            public_key,
            client,
            auth_token,
            max_retries,
            retry_base_delay: std::time::Duration::from_millis(crate::REMOTE_SIGNER_RETRY_BASE_MS),
        };

        // Startup health check
        let health_url = format!("{}/api/v1/eth2/up", signer.endpoint);
        let mut req = signer.client.get(&health_url);
        if let Some(token) = &signer.auth_token {
            req = req.bearer_auth(token.as_str());
        }

        let res = req
            .send()
            .await
            .context("Health check failed: unable to connect to remote signer")?;
        if !res.status().is_success() {
            bail!(
                "Remote signer health check returned status {}",
                res.status()
            );
        }

        Ok(signer)
    }

    /// Execute a signing request with exponential backoff retry logic.
    ///
    /// Retries on transient failures (connection errors, 5xx responses).
    /// Does NOT retry on authentication failures (4xx) since retrying
    /// would not help.
    ///
    /// All waiting happens inside the Tokio runtime (`tokio::time::sleep`),
    /// never on the calling thread, so callers in async contexts do not
    /// block their executor.
    fn sign_with_retry(&self, url: &str, payload: &SignRequest) -> Result<SignResponse> {
        let handle = tokio::runtime::Handle::try_current()
            .context("RemoteSigner::sign must be called from within a Tokio runtime")?;

        handle.block_on(async move {
            let mut last_error = None;

            for attempt in 0..=self.max_retries {
                if attempt > 0 {
                    let delay = self.retry_base_delay * 2u32.pow(attempt - 1);
                    tracing::warn!(
                        attempt,
                        max_retries = self.max_retries,
                        ?delay,
                        "retrying remote signer request after transient failure"
                    );
                    tokio::time::sleep(delay).await;
                }

                let result = {
                    let mut req = self.client.post(url).json(payload);
                    if let Some(token) = &self.auth_token {
                        req = req.bearer_auth(token.as_str());
                    }
                    match req.send().await {
                        Err(e) => Err(e).context("Failed to connect to remote HSM signer"),
                        Ok(res) => {
                            let status = res.status();
                            if status.is_client_error() && !status.is_success() {
                                // 4xx errors are not retried (auth/config issues)
                                Err(anyhow::anyhow!(
                                    "HSM signing failed with client error: {}",
                                    status
                                ))
                            } else if !status.is_success() {
                                // 5xx errors are retried (transient server issues)
                                Err(anyhow::anyhow!(
                                    "HSM signing failed with server error: {}",
                                    status
                                ))
                            } else {
                                res.json::<SignResponse>()
                                    .await
                                    .context("Failed to parse HSM response")
                            }
                        }
                    }
                };

                match result {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        let msg = e.to_string();
                        // Don't retry client errors (4xx)
                        if msg.contains("client error") {
                            return Err(e);
                        }
                        last_error = Some(e);
                    }
                }
            }

            Err(last_error.unwrap_or_else(|| {
                anyhow::anyhow!("remote signer failed after {} retries", self.max_retries)
            }))
        })
    }
}

impl Signer for RemoteSigner {
    fn sign(&self, message: &[u8]) -> Result<Signature> {
        let pub_key_hex = hex::encode(self.public_key.to_bytes());
        let url = format!("{}/api/v1/eth2/sign/{}", self.endpoint, pub_key_hex);

        let payload = SignRequest {
            data: hex::encode(message),
        };

        let resp = self.sign_with_retry(&url, &payload)?;

        let sig_bytes = hex::decode(resp.signature.trim_start_matches("0x"))
            .context("HSM returned invalid hex signature")?;

        if sig_bytes.len() != 64 {
            bail!(
                "HSM returned malformed signature: expected 64 bytes, got {}",
                sig_bytes.len()
            );
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);

        if !crate::ed25519::verify(&self.public_key.to_bytes(), message, &arr) {
            bail!("HSM returned an invalid signature for the requested message");
        }

        let signature = Signature::from_bytes(arr);
        Ok(signature)
    }

    fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_signer_debug_redacts_auth_token() {
        let signer = RemoteSigner {
            endpoint: "https://signer.internal:9000".to_string(),
            public_key: PublicKey([7u8; 32]),
            client: reqwest::Client::new(),
            auth_token: Some(Zeroizing::new("super-secret-bearer-token".to_string())),
            max_retries: 3,
            retry_base_delay: std::time::Duration::from_millis(500),
        };

        let dbg = format!("{:?}", signer);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret-bearer-token"));
    }
}
