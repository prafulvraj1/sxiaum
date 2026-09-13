#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::epoch_sync::{EpochHandoverCertificate, ValidatorSignature};
#[cfg(feature = "wasm")]
use crate::light_client::{NanoLightClient, NanoLightConfig};
#[cfg(feature = "wasm")]
use sxiaum_block::BlockHeader;
#[cfg(feature = "wasm")]
use sxiaum_state::VerkleProof;
#[cfg(feature = "wasm")]
use sxiaum_types::{Account, Address, Hash};

/// WebAssembly-exported wrapper around `NanoLightClient`.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub struct WasmNanoLightClient {
    inner: NanoLightClient,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl WasmNanoLightClient {
    /// Create a new `WasmNanoLightClient` with JSON configuration.
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> Result<WasmNanoLightClient, JsValue> {
        let config: NanoLightConfig = serde_json::from_str(config_json)
            .map_err(|e| JsValue::from_str(&format!("invalid config JSON: {e}")))?;
        let inner = NanoLightClient::new(config)
            .map_err(|e| JsValue::from_str(&format!("failed to initialize nano client: {e}")))?;
        Ok(Self { inner })
    }

    /// Verify and append a block header.
    #[wasm_bindgen(js_name = verifyHeader)]
    pub fn verify_header(
        &mut self,
        header_json: &str,
        signatures_json: &str,
        hotstuff_view: Option<u64>,
        hotstuff_phase: Option<u8>,
        current_time: u64,
    ) -> Result<String, JsValue> {
        let header: BlockHeader = serde_json::from_str(header_json)
            .map_err(|e| JsValue::from_str(&format!("invalid header JSON: {e}")))?;
        let sigs: Vec<ValidatorSignature> = serde_json::from_str(signatures_json)
            .map_err(|e| JsValue::from_str(&format!("invalid signatures JSON: {e}")))?;

        let hotstuff_meta = match (hotstuff_view, hotstuff_phase) {
            (Some(v), Some(p)) => Some((v, p)),
            _ => None,
        };

        let block_hash = self
            .inner
            .verify_and_append_header(header, &sigs, hotstuff_meta, current_time)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(hex::encode(block_hash))
    }

    /// Verify an account balance / state against a verified state root.
    #[wasm_bindgen(js_name = verifyAccountState)]
    pub fn verify_account_state(
        &self,
        address_hex: &str,
        account_json: &str,
        root_hex: &str,
        proof_json: &str,
    ) -> Result<bool, JsValue> {
        let addr_bytes = hex::decode(address_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("invalid address hex: {e}")))?;
        let address = Address::try_from(addr_bytes.as_slice())
            .map_err(|_| JsValue::from_str("invalid address byte length"))?;

        let account: Account = serde_json::from_str(account_json)
            .map_err(|e| JsValue::from_str(&format!("invalid account JSON: {e}")))?;
        account
            .validate()
            .map_err(|e| JsValue::from_str(&format!("invalid account state: {e}")))?;

        let root_bytes = hex::decode(root_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("invalid root hex: {e}")))?;
        let mut root = [0u8; 32];
        if root_bytes.len() != 32 {
            return Err(JsValue::from_str("root must be 32 bytes"));
        }
        root.copy_from_slice(&root_bytes);

        let proof: VerkleProof = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from_str(&format!("invalid proof JSON: {e}")))?;

        self.inner
            .verify_account_balance(&address, &account, root, &proof)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Verify a contract storage slot value against a verified state root.
    #[wasm_bindgen(js_name = verifyStorageSlot)]
    pub fn verify_storage_slot(
        &self,
        address_hex: &str,
        slot_hex: &str,
        value_hex: &str,
        root_hex: &str,
        proof_json: &str,
    ) -> Result<bool, JsValue> {
        let addr_bytes = hex::decode(address_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("invalid address hex: {e}")))?;
        let address = Address::try_from(addr_bytes.as_slice())
            .map_err(|_| JsValue::from_str("invalid address byte length"))?;

        let slot = decode_hash_32(slot_hex)?;
        let val = decode_hash_32(value_hex)?;
        let root = decode_hash_32(root_hex)?;

        let proof: VerkleProof = serde_json::from_str(proof_json)
            .map_err(|e| JsValue::from_str(&format!("invalid proof JSON: {e}")))?;

        self.inner
            .verify_storage_slot(&address, slot, val, root, &proof)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Apply an epoch handover certificate.
    ///
    /// `current_time` anchors mainnet-strict validation of the boundary header.
    #[wasm_bindgen(js_name = applyEpochHandover)]
    pub fn apply_epoch_handover(
        &mut self,
        certificate_json: &str,
        current_time: u64,
    ) -> Result<(), JsValue> {
        let cert: EpochHandoverCertificate = serde_json::from_str(certificate_json)
            .map_err(|e| JsValue::from_str(&format!("invalid certificate JSON: {e}")))?;
        self.inner
            .epoch_manager
            .verify_and_apply_handover(&cert, current_time)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get current verified chain height.
    #[wasm_bindgen(js_name = currentHeight)]
    pub fn current_height(&self) -> u64 {
        self.inner.current_height()
    }
}

#[cfg(feature = "wasm")]
fn decode_hash_32(hex_str: &str) -> Result<Hash, JsValue> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x"))
        .map_err(|e| JsValue::from_str(&format!("invalid hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("hash string must decode to 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
