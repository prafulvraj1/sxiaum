use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::Rng;
use serde_json::json;
use sxiaum_types::Address;

/// Call a JSON-RPC method on the SXIAUM node
pub async fn call_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value> {
    let response: serde_json::Value = client
        .post(url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;

    if let Some(err) = response.get("error") {
        anyhow::bail!("RPC Error: {}", err);
    }

    Ok(response["result"].clone())
}

/// Generate a new random Ed25519 keypair
pub fn generate_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let privkey_hex = format!("0x{}", hex::encode(seed));
    let pubkey_hex = format!("0x{}", hex::encode(verifying_key.as_bytes()));

    (privkey_hex, pubkey_hex)
}

/// Derive an address from a public key
pub fn derive_address(pubkey_hex: &str) -> Result<String> {
    let pubkey_bytes = hex::decode(pubkey_hex.trim_start_matches("0x"))?;
    if pubkey_bytes.len() != 32 {
        anyhow::bail!("Public key must be 32 bytes");
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);

    let address = Address::from_public_key(&pubkey_array);
    Ok(format!("0x{}", hex::encode(address.as_bytes())))
}

/// Parse a hex string to a 32-byte array
pub fn parse_hex32(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        anyhow::bail!("Input must be exactly 32 bytes");
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Format vc to readable token amount
#[allow(dead_code)]
pub fn format_balance(wei: u128) -> String {
    format!("{:.6} tokens", wei as f64 / 1e18)
}

/// Devnet public accounts + env var names (no secrets embedded).
///
/// Tuple: `(address, key_env_or_placeholder, balance)`.
/// Private hex is **not** returned unless `SXIAUM_SHOW_DEVNET_KEYS=1` and the
/// matching env var is set (or falls back to well-known test seed for display only).
pub fn load_devnet_config() -> Result<Vec<(String, String, String)>> {
    let show_keys = std::env::var("SXIAUM_SHOW_DEVNET_KEYS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Public addresses match genesis / validator set; private material lives only in env.
    let accounts = [
        (
            "0x34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e",
            "SXIAUM_VALIDATOR_KEY_1",
            "1000000000000000000000000000",
            "0x0101010101010101010101010101010101010101010101010101010101010101",
        ),
        (
            "0x6a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827",
            "SXIAUM_VALIDATOR_KEY_2",
            "1000000000000000000000000000",
            "0x0202020202020202020202020202020202020202020202020202020202020202",
        ),
        (
            "0xb62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709",
            "SXIAUM_VALIDATOR_KEY_3",
            "1000000000000000000000000000",
            "0x0303030303030303030303030303030303030303030303030303030303030303",
        ),
        (
            "0xc5b940ed3f65c391965de8295fc5d25f474fa57b48d36eb10ad363b8539c1b79",
            "SXIAUM_VALIDATOR_KEY_4",
            "1000000000000000000000000000",
            "0x0404040404040404040404040404040404040404040404040404040404040404",
        ),
    ];

    let mut out = Vec::with_capacity(accounts.len());
    for (addr, env_name, balance, well_known_test_seed) in accounts {
        let key_field = if show_keys {
            std::env::var(env_name).unwrap_or_else(|_| {
                // Display-only fallback for local demos; never used by the node from this path.
                well_known_test_seed.to_string()
            })
        } else {
            format!("(set ${env_name} environment variable)")
        };
        out.push((addr.to_string(), key_field, balance.to_string()));
    }
    Ok(out)
}
