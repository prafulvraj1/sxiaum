use super::{validate_key_id, KeyEntry, KeyStore};
use crate::error::{KeystoreError, Result};
use crate::password::is_production;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use std::env;
use std::future::Future;
use std::time::Duration;
use zeroize::Zeroizing;

/// HashiCorp Vault KV-v2-backed key storage backend for HSM-grade security.
///
/// Authentication uses the standard `X-Vault-Token` header. Requests are
/// retried with exponential backoff on network errors and HTTP 5xx responses.
pub struct VaultKeyStore {
    client: Client,
    base_url: String,
    token: Zeroizing<String>,
    namespace: Option<String>,
    headers: HeaderMap,
    max_retries: u32,
}

/// Extracts the lowercase HOST component (no scheme, port, credentials, or
/// path) from an absolute URL, handling IPv6 bracket notation.
fn extract_url_host(base_url: &str) -> String {
    let after_scheme = base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo if present.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: host ends at the closing bracket.
        let host = rest.split(']').next().unwrap_or(rest);
        host.to_ascii_lowercase()
    } else {
        authority
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    }
}

/// Returns true when the bare host is loopback, link-local metadata, or the
/// unspecified address — all forbidden as production Vault endpoints.
fn is_blocked_production_host(host: &str) -> bool {
    matches!(
        host,
        "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "::1"
            | "::"
            | "169.254.169.254"
            | "metadata.google.internal"
    ) || host.starts_with("127.")
        || host.starts_with("169.254.169.")
}

impl std::fmt::Debug for VaultKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKeyStore")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .field("namespace", &self.namespace)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

impl VaultKeyStore {
    pub fn new(base_url: String, token: String) -> Result<Self> {
        let in_prod = is_production()
            || env::var("SXIAUM_VAULT_MODE")
                .unwrap_or_default()
                .eq_ignore_ascii_case("production");

        if in_prod && token.is_empty() {
            return Err(KeystoreError::VaultError(
                "Vault token must be set when SXIAUM_ENV=production or SXIAUM_VAULT_MODE=production".into(),
            ));
        }

        let timeout_secs = env::var("SXIAUM_VAULT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        // Normalize: strip any trailing slash so path joins never double up.
        let base_url = base_url.trim_end_matches('/').to_string();

        if in_prod {
            if !base_url.starts_with("https://") {
                return Err(KeystoreError::VaultError(
                    "Vault URL must use HTTPS when SXIAUM_ENV=production or SXIAUM_VAULT_MODE=production".into(),
                ));
            }
            let host = extract_url_host(&base_url);
            // SECURITY: the blocklist must match the BARE host. The previous
            // comparison ran against `host:port` (e.g. "127.0.0.1:8200"), so
            // ANY port-suffixed loopback / metadata URL silently bypassed
            // this production guard.
            if is_blocked_production_host(&host) {
                return Err(KeystoreError::VaultError(
                    "Vault URL must not point to loopback or cloud metadata services in production"
                        .into(),
                ));
            }
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| {
                KeystoreError::VaultError(format!("Failed to build Vault HTTP client: {e}"))
            })?;

        Ok(VaultKeyStore {
            client,
            base_url,
            token: Zeroizing::new(token),
            namespace: None,
            headers: HeaderMap::new(),
            max_retries: 3,
        })
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn with_header(mut self, name: impl AsRef<str>, value: impl AsRef<str>) -> Result<Self> {
        let header_name = HeaderName::from_bytes(name.as_ref().as_bytes())
            .map_err(|e| KeystoreError::VaultError(format!("Invalid header name: {e}")))?;
        let header_value = HeaderValue::from_str(value.as_ref())
            .map_err(|e| KeystoreError::VaultError(format!("Invalid header value: {e}")))?;
        self.headers.insert(header_name, header_value);
        Ok(self)
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    fn request_headers(&self) -> Result<HeaderMap> {
        let mut headers = self.headers.clone();
        if !self.token.is_empty() {
            headers.insert(
                HeaderName::from_static("x-vault-token"),
                HeaderValue::from_str(self.token.as_str())
                    .map_err(|e| KeystoreError::VaultError(format!("Token header error: {e}")))?,
            );
        }
        if let Some(namespace) = &self.namespace {
            if let Ok(value) = HeaderValue::from_str(namespace) {
                headers.insert(HeaderName::from_static("x-vault-namespace"), value);
            }
        }
        Ok(headers)
    }

    /// Send a request with exponential backoff on network errors and 5xx.
    /// Any completed response (including 404 and other client errors) is
    /// returned to the caller for status-specific handling.
    async fn send_with_retry<F, Fut>(&self, f: F) -> Result<reqwest::Response>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = std::result::Result<reqwest::Response, reqwest::Error>>,
    {
        let mut attempt = 0u32;
        let mut backoff = Duration::from_millis(100);

        loop {
            attempt += 1;
            match f().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_server_error() && attempt <= self.max_retries {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_millis(1_600));
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if attempt <= self.max_retries {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_millis(1_600));
                        continue;
                    }
                    return Err(KeystoreError::VaultError(format!(
                        "Vault request error after {} attempt(s): {e}",
                        attempt
                    )));
                }
            }
        }
    }

    async fn get_json(&self, url: &str) -> Result<Option<serde_json::Value>> {
        let headers = self.request_headers()?;
        let resp = self
            .send_with_retry(|| self.client.get(url).headers(headers.clone()).send())
            .await?;

        let status = resp.status();
        if status.is_success() {
            let v = resp.json().await.map_err(|e| {
                KeystoreError::VaultError(format!("Failed to parse Vault JSON response: {e}"))
            })?;
            Ok(Some(v))
        } else if status.as_u16() == 404 {
            Ok(None)
        } else {
            Err(KeystoreError::VaultError(format!(
                "Vault returned HTTP status {status}"
            )))
        }
    }

    async fn put_json(&self, url: &str, body: serde_json::Value) -> Result<()> {
        let headers = self.request_headers()?;
        let resp = self
            .send_with_retry(|| {
                self.client
                    .post(url)
                    .headers(headers.clone())
                    .json(&body)
                    .send()
            })
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(KeystoreError::VaultError(format!(
                "Vault put failed with status {status}"
            )))
        }
    }

    async fn delete_url(&self, url: &str) -> Result<()> {
        let headers = self.request_headers()?;
        let resp = self
            .send_with_retry(|| self.client.delete(url).headers(headers.clone()).send())
            .await?;

        let status = resp.status();
        if status.is_success() || status.as_u16() == 404 {
            Ok(())
        } else {
            Err(KeystoreError::VaultError(format!(
                "Vault delete failed with status {status}"
            )))
        }
    }

    fn data_url(&self, id: &str) -> String {
        format!("{}/v1/secret/data/{}", self.base_url, id)
    }

    fn metadata_url(&self, id: &str) -> String {
        format!("{}/v1/secret/metadata/{}", self.base_url, id)
    }

    fn parse_entry(&self, id: &str, v: serde_json::Value) -> Result<Option<KeyEntry>> {
        // KV v2 wraps the secret payload under data.data; tolerate KV v1 (data.*).
        let d = v
            .pointer("/data/data")
            .or_else(|| v.get("data"))
            .ok_or_else(|| {
                KeystoreError::CorruptedKeystore(
                    id.to_string(),
                    "Vault response missing secret payload".to_string(),
                )
            })?;
        let kind = d.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        let data_b64 = d.get("data").and_then(|k| k.as_str()).unwrap_or("");
        let data = STANDARD.decode(data_b64).map_err(|e| {
            KeystoreError::CorruptedKeystore(id.to_string(), format!("base64 decode: {e}"))
        })?;
        // Reconstruct through the validating constructor so kind/id/length
        // invariants hold for anything returned by this backend.
        KeyEntry::new(id.to_string(), kind.to_string(), data).map(Some)
    }
}

#[async_trait]
impl KeyStore for VaultKeyStore {
    async fn put(&self, key: KeyEntry) -> Result<()> {
        validate_key_id(&key.id).map_err(|e| KeystoreError::InvalidKeyId(e.to_string()))?;
        let url = self.data_url(&key.id);
        let body = serde_json::json!({
            "data": {
                "kind": key.kind,
                "data": STANDARD.encode(&key.data)
            }
        });
        self.put_json(&url, body).await
    }

    async fn get(&self, id: &str) -> Result<Option<KeyEntry>> {
        validate_key_id(id).map_err(|e| KeystoreError::InvalidKeyId(e.to_string()))?;
        match self.get_json(&self.data_url(id)).await? {
            Some(v) => self.parse_entry(id, v),
            None => Ok(None),
        }
    }

    async fn delete(&self, id: &str) -> Result<()> {
        validate_key_id(id).map_err(|e| KeystoreError::InvalidKeyId(e.to_string()))?;
        self.delete_url(&self.metadata_url(id)).await
    }

    async fn list(&self) -> Result<Vec<String>> {
        let url = format!("{}/v1/secret/metadata?list=true", self.base_url);
        match self.get_json(&url).await? {
            None => Ok(Vec::new()),
            Some(v) => {
                let mut keys = Vec::new();
                if let Some(arr) = v.pointer("/data/keys").and_then(|k| k.as_array()) {
                    for k in arr {
                        if let Some(s) = k.as_str() {
                            let clean = s.trim_end_matches('/');
                            if validate_key_id(clean).is_ok() {
                                keys.push(clean.to_string());
                            }
                        }
                    }
                }
                keys.sort();
                Ok(keys)
            }
        }
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        validate_key_id(id).map_err(|e| KeystoreError::InvalidKeyId(e.to_string()))?;
        Ok(self.get_json(&self.metadata_url(id)).await?.is_some())
    }
}

#[cfg(test)]
mod tests {

    /// Serializes every `VaultKeyStore::new` call: the constructor reads
    /// process-global env (`SXIAUM_VAULT_MODE`, `SXIAUM_ENV`) and tests run
    /// in parallel threads. Without this guard, the production-gate test's
    /// temporary `SXIAUM_VAULT_MODE=production` leaked into sibling tests'
    /// constructions and flipped their HTTP mock URLs into policy rejections
    /// (nondeterministic failures under full-workspace load).
    fn vault_env_guard() -> std::sync::MutexGuard<'static, ()> {
        static VAULT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        VAULT_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    use super::*;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    /// Runs `body` on a dedicated current-thread runtime so the env-var
    /// mutex guard is acquired before any await point exists. Holding the
    /// std-guard across awaits inside an async fn is a deadlock hazard
    /// (clippy::await_holding_lock); this shape keeps the same serialization
    /// semantics without ever polling an async fn while the guard is alive.
    fn with_env_guard_blocking<F>(body: F)
    where
        F: Future<Output = ()>,
    {
        let _env = vault_env_guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(body);
    }

    #[test]
    fn vault_put_sends_token_namespace_and_custom_headers() {
        with_env_guard_blocking(async {
            let server = MockServer::start().await;

            Mock::given(method("POST"))
                .and(path("/v1/secret/data/circuit-vk"))
                .and(header("x-vault-token", "secret-token"))
                .and(header("x-vault-namespace", "team-a"))
                .and(header("x-key-class", "groth16-vk"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;

            let store = { VaultKeyStore::new(server.uri(), "secret-token".to_string()).unwrap() }
                .with_namespace("team-a")
                .with_header("x-key-class", "groth16-vk")
                .expect("header should be valid");

            store
                .put(
                    KeyEntry::new(
                        "circuit-vk".to_string(),
                        "verifying-key".to_string(),
                        b"vk-bytes".to_vec(),
                    )
                    .unwrap(),
                )
                .await
                .expect("vault put should succeed");
        });
    }

    #[test]
    fn vault_get_round_trips_key_entry() {
        with_env_guard_blocking(async {
            let server = MockServer::start().await;

            let encoded = STANDARD.encode(b"pk-bytes");
            Mock::given(method("GET"))
                .and(path("/v1/secret/data/circuit-pk"))
                .and(header("x-vault-token", "secret-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {
                        "data": {
                            "kind": "proving-key",
                            "data": encoded,
                        }
                    }
                })))
                .expect(1)
                .mount(&server)
                .await;

            let store = { VaultKeyStore::new(server.uri(), "secret-token".to_string()).unwrap() };
            let entry = store
                .get("circuit-pk")
                .await
                .expect("get should succeed")
                .expect("key should exist");

            assert_eq!(entry.id, "circuit-pk");
            assert_eq!(entry.kind, "proving-key");
            assert_eq!(entry.data, b"pk-bytes");
        });
    }

    #[test]
    fn vault_get_missing_returns_none_and_list_exists_work() {
        with_env_guard_blocking(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/v1/secret/metadata"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {
                        "keys": ["key1", "key2", "invalid/nested/"]
                    }
                })))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/v1/secret/metadata/key1"))
                // CORRECTNESS: real Vault returns a JSON document for existing
                // keys. An empty 200 forced get_json's resp.json() to attempt
                // decoding a zero-byte body, which fails outright and turns any
                // transport hiccup into this decode error.
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "created_time": "2026-01-01T00:00:00Z" }
                })))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/v1/secret/metadata/key2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "data": { "kind": "srs", "data": "" } }
                })))
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/v1/secret/metadata/missing-key"))
                // Only exists() consults the metadata endpoint for a missing key;
                // get() reads the DATA endpoint (mocked separately below).
                .respond_with(ResponseTemplate::new(404))
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/v1/secret/data/missing-key"))
                .respond_with(ResponseTemplate::new(404))
                .expect(1)
                .mount(&server)
                .await;

            let store = { VaultKeyStore::new(server.uri(), "secret-token".to_string()).unwrap() };
            let keys = store.list().await.expect("list should succeed");
            assert_eq!(keys, vec!["key1".to_string(), "key2".to_string()]);

            assert!(store.exists("key1").await.expect("exists check"));
            assert!(!store
                .exists("missing-key")
                .await
                .expect("missing exists check"));
            assert!(store
                .get("missing-key")
                .await
                .expect("missing get should be Ok(None)")
                .is_none());
        });
    }

    #[test]
    fn vault_get_rejects_invalid_kind_on_reconstruction() {
        with_env_guard_blocking(async {
            let server = MockServer::start().await;

            let encoded = STANDARD.encode(b"k");
            Mock::given(method("GET"))
                .and(path("/v1/secret/data/bad-kind"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {
                        "data": {
                            "kind": "definitely-not-a-kind",
                            "data": encoded,
                        }
                    }
                })))
                .mount(&server)
                .await;

            let store = { VaultKeyStore::new(server.uri(), "secret-token".to_string()).unwrap() };
            let res = store.get("bad-kind").await;
            assert!(matches!(
                res,
                Err(KeystoreError::InvalidKeyType(_) | KeystoreError::CorruptedKeystore(_, _))
            ));
        });
    }

    #[test]
    fn vault_retries_on_500_then_succeeds() {
        with_env_guard_blocking(async {
            let server = MockServer::start().await;

            let encoded = STANDARD.encode(b"vk-bytes");
            // First response fails with 500; retry then succeeds.
            Mock::given(method("GET"))
                .and(path("/v1/secret/data/flaky-key"))
                .respond_with(ResponseTemplate::new(500))
                .up_to_n_times(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/secret/data/flaky-key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "data": { "kind": "verifying-key", "data": encoded } }
                })))
                .expect(1)
                .mount(&server)
                .await;

            let store = { VaultKeyStore::new(server.uri(), "secret-token".to_string()).unwrap() }
                .with_max_retries(3);
            let entry = store
                .get("flaky-key")
                .await
                .expect("retry should recover from transient 500")
                .expect("key should exist after retry");
            assert_eq!(entry.data, b"vk-bytes");
        });
    }

    #[test]
    fn request_headers_omit_token_when_empty() {
        let _env = vault_env_guard();
        let store =
            { VaultKeyStore::new("http://127.0.0.1:8200".to_string(), "".to_string()).unwrap() };
        let headers = store.request_headers().expect("headers built");
        assert!(headers.get("x-vault-token").is_none());
    }

    #[test]
    fn request_headers_include_token_when_present() {
        let _env = vault_env_guard();
        let store = {
            VaultKeyStore::new(
                "http://127.0.0.1:8200".to_string(),
                "secret-token".to_string(),
            )
            .unwrap()
        };
        let headers = store.request_headers().expect("headers built");
        assert_eq!(
            headers.get("x-vault-token").map(|v| v.to_str().unwrap()),
            Some("secret-token")
        );
    }

    #[test]
    fn base_url_trailing_slash_is_normalized() {
        let _env = vault_env_guard();
        let store = {
            VaultKeyStore::new("http://127.0.0.1:8200///".to_string(), "t".to_string()).unwrap()
        };
        assert_eq!(
            store.data_url("abc"),
            "http://127.0.0.1:8200/v1/secret/data/abc"
        );
        assert_eq!(
            store.metadata_url("abc"),
            "http://127.0.0.1:8200/v1/secret/metadata/abc"
        );
    }

    #[test]
    fn production_requires_https_and_non_loopback() {
        let _g = vault_env_guard();

        // These checks are skipped outside production mode; simulate prod via
        // SXIAUM_VAULT_MODE which this constructor reads directly. The value
        // is restored on drop so a failing assertion cannot poison siblings.
        struct RestoreMode;
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                env::remove_var("SXIAUM_VAULT_MODE");
            }
        }
        let _restore = RestoreMode;
        env::set_var("SXIAUM_VAULT_MODE", "production");

        // Pin the gate before EVERY construction: if ambient interference
        // ever clears the variable mid-test, we fail with a precise message
        // instead of an opaque policy-assertion mismatch.
        macro_rules! require_prod_gate {
            () => {
                assert_eq!(
                    env::var("SXIAUM_VAULT_MODE").unwrap_or_default(),
                    "production",
                    "SXIAUM_VAULT_MODE was cleared mid-test"
                );
            };
        }

        require_prod_gate!();
        let http_res = VaultKeyStore::new(
            "http://vault.internal:8200".to_string(),
            "token".to_string(),
        );
        require_prod_gate!();
        let loopback_res =
            VaultKeyStore::new("https://127.0.0.1:8200".to_string(), "token".to_string());
        require_prod_gate!();
        let metadata_res =
            VaultKeyStore::new("https://169.254.169.254".to_string(), "token".to_string());
        require_prod_gate!();
        let empty_token_res =
            VaultKeyStore::new("https://vault.internal:8200".to_string(), "".to_string());
        require_prod_gate!();
        env::remove_var("SXIAUM_VAULT_MODE");

        assert!(http_res.is_err());
        assert!(loopback_res.is_err());
        assert!(metadata_res.is_err());
        assert!(empty_token_res.is_err());

        // Valid production config passes.
        let ok = VaultKeyStore::new(
            "https://vault.internal:8200".to_string(),
            "token".to_string(),
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn host_extraction_strips_port_and_userinfo() {
        assert_eq!(extract_url_host("https://127.0.0.1:8200"), "127.0.0.1");
        assert_eq!(
            extract_url_host("https://user:pw@vault.internal:8200/x"),
            "vault.internal"
        );
        assert_eq!(extract_url_host("https://[::1]:8200/v1"), "::1");
        assert_eq!(
            extract_url_host("https://METADATA.GOOGLE.INTERNAL"),
            "metadata.google.internal"
        );
    }

    #[test]
    fn production_blocklist_covers_port_suffixed_loopback() {
        // SECURITY REGRESSION (H-54 class): with SXIAUM_VAULT_MODE=production,
        // port-qualified loopback endpoints used to bypass the blocklist
        // because the guard compared "host:port" against bare names.
        let _g = vault_env_guard();

        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                env::remove_var("SXIAUM_VAULT_MODE");
            }
        }
        let _restore = Restore;
        env::set_var("SXIAUM_VAULT_MODE", "production");

        for url in [
            "https://127.0.0.1:8200",
            "https://localhost:8200",
            "https://[::1]:8200",
            "https://169.254.169.254:8200",
            "https://127.1.2.3:8200",     // 127/8 loopback range
            "http://vault.internal:8200", // non-HTTPS blocked separately
        ] {
            assert!(
                VaultKeyStore::new(url.to_string(), "token".to_string()).is_err(),
                "production Vault URL {url} must be rejected"
            );
        }
    }
}
