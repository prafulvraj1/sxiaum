//! C-compatible FFI ABI for embedding `sxiaum-nano` into iOS (Swift) and Android (Kotlin / JNI).

use crate::epoch_sync::{EpochHandoverCertificate, ValidatorSignature};
use crate::light_client::{NanoLightClient, NanoLightConfig};
use std::ffi::CStr;
use std::os::raw::c_char;
use sxiaum_block::BlockHeader;
use sxiaum_state::VerkleProof;
use sxiaum_types::{Account, Address, Hash};

/// Instantiate a new `NanoLightClient` instance from JSON configuration.
///
/// Returns a raw pointer to `NanoLightClient`, or null on failure.
/// The caller is responsible for freeing the memory via [`sxiaum_nano_light_client_free`].
///
/// # Safety
///
/// `config_json` must be a valid, non-null, null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn sxiaum_nano_light_client_new(
    config_json: *const c_char,
) -> *mut NanoLightClient {
    if config_json.is_null() {
        return std::ptr::null_mut();
    }

    let c_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let config: NanoLightConfig = match serde_json::from_str(c_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    match NanoLightClient::new(config) {
        Ok(client) => Box::into_raw(Box::new(client)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Free a `NanoLightClient` instance allocated by [`sxiaum_nano_light_client_new`].
///
/// # Safety
///
/// `client` must be a valid pointer obtained from [`sxiaum_nano_light_client_new`]
/// and must not be used after this call.
#[no_mangle]
pub unsafe extern "C" fn sxiaum_nano_light_client_free(client: *mut NanoLightClient) {
    if !client.is_null() {
        drop(Box::from_raw(client));
    }
}

/// Verify a candidate block header and append to in-memory buffer.
///
/// Returns 0 on success, copying the 32-byte block hash into `out_hash_buf` (must be >= 32 bytes).
/// Returns negative error code on failure.
///
/// # Safety
///
/// - `client` must point to a valid, live `NanoLightClient`.
/// - `header_json` and `sigs_json` must be valid, null-terminated UTF-8 C strings.
/// - `out_hash_buf` must point to a writable memory region of at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn sxiaum_nano_verify_header(
    client: *mut NanoLightClient,
    header_json: *const c_char,
    sigs_json: *const c_char,
    current_time: u64,
    out_hash_buf: *mut u8,
) -> i32 {
    if client.is_null() || header_json.is_null() || sigs_json.is_null() || out_hash_buf.is_null() {
        return -1;
    }

    let node = &mut *client;

    let header_str = match CStr::from_ptr(header_json).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    let sigs_str = match CStr::from_ptr(sigs_json).to_str() {
        Ok(s) => s,
        Err(_) => return -3,
    };

    let header: BlockHeader = match serde_json::from_str(header_str) {
        Ok(h) => h,
        Err(_) => return -4,
    };
    let sigs: Vec<ValidatorSignature> = match serde_json::from_str(sigs_str) {
        Ok(s) => s,
        Err(_) => return -5,
    };

    match node.verify_and_append_header(header, &sigs, None, current_time) {
        Ok(hash) => {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_hash_buf, 32);
            0
        }
        Err(_) => -6,
    }
}

/// Verify an account state proof against a trusted state root.
///
/// Returns 1 on valid proof, 0 on invalid proof, -1 on error.
///
/// # Safety
///
/// - `client` must point to a valid, live `NanoLightClient`.
/// - `address_hex`, `account_json`, `root_hex`, and `proof_json` must be valid,
///   null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn sxiaum_nano_verify_account_proof(
    client: *mut NanoLightClient,
    address_hex: *const c_char,
    account_json: *const c_char,
    root_hex: *const c_char,
    proof_json: *const c_char,
) -> i32 {
    if client.is_null()
        || address_hex.is_null()
        || account_json.is_null()
        || root_hex.is_null()
        || proof_json.is_null()
    {
        return -1;
    }

    let node = &*client;

    let addr_str = match CStr::from_ptr(address_hex).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let acct_str = match CStr::from_ptr(account_json).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let root_str = match CStr::from_ptr(root_hex).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let proof_str = match CStr::from_ptr(proof_json).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let addr_bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let address = match Address::try_from(addr_bytes.as_slice()) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    let account: Account = match serde_json::from_str(acct_str) {
        Ok(account) => account,
        Err(_) => return -1,
    };
    if account.validate().is_err() {
        return -1;
    }

    let root_bytes = match hex::decode(root_str.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    if root_bytes.len() != 32 {
        return -1;
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_bytes);

    let proof: VerkleProof = match serde_json::from_str(proof_str) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    match node.verify_account_balance(&address, &account, root, &proof) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// Verify a contract storage slot proof against a trusted state root.
///
/// Returns 1 on valid proof, 0 on invalid proof, -1 on error.
///
/// # Safety
///
/// - `client` must point to a valid, live `NanoLightClient`.
/// - `address_hex`, `slot_hex`, `value_hex`, `root_hex`, and `proof_json` must be valid,
///   null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn sxiaum_nano_verify_storage_proof(
    client: *mut NanoLightClient,
    address_hex: *const c_char,
    slot_hex: *const c_char,
    value_hex: *const c_char,
    root_hex: *const c_char,
    proof_json: *const c_char,
) -> i32 {
    if client.is_null()
        || address_hex.is_null()
        || slot_hex.is_null()
        || value_hex.is_null()
        || root_hex.is_null()
        || proof_json.is_null()
    {
        return -1;
    }

    let node = &*client;

    let addr_str = match CStr::from_ptr(address_hex).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let slot_str = match CStr::from_ptr(slot_hex).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let val_str = match CStr::from_ptr(value_hex).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let root_str = match CStr::from_ptr(root_hex).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let proof_str = match CStr::from_ptr(proof_json).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let addr_bytes = match hex::decode(addr_str.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => return -1,
    };
    let address = match Address::try_from(addr_bytes.as_slice()) {
        Ok(a) => a,
        Err(_) => return -1,
    };

    let slot = match parse_32_bytes(slot_str) {
        Some(s) => s,
        None => return -1,
    };
    let val = match parse_32_bytes(val_str) {
        Some(v) => v,
        None => return -1,
    };
    let root = match parse_32_bytes(root_str) {
        Some(r) => r,
        None => return -1,
    };

    let proof: VerkleProof = match serde_json::from_str(proof_str) {
        Ok(p) => p,
        Err(_) => return -1,
    };

    match node.verify_storage_slot(&address, slot, val, root, &proof) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => -1,
    }
}

/// Apply an epoch handover certificate to rotate validator set.
///
/// `current_time` anchors mainnet-strict validation of the boundary header.
///
/// Returns 0 on success, -1 on failure.
///
/// # Safety
///
/// - `client` must point to a valid, live `NanoLightClient`.
/// - `cert_json` must be a valid, null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn sxiaum_nano_epoch_handover(
    client: *mut NanoLightClient,
    cert_json: *const c_char,
    current_time: u64,
) -> i32 {
    if client.is_null() || cert_json.is_null() {
        return -1;
    }

    let node = &mut *client;
    let cert_str = match CStr::from_ptr(cert_json).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let cert: EpochHandoverCertificate = match serde_json::from_str(cert_str) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    match node.epoch_manager.verify_and_apply_handover(&cert, current_time) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

fn parse_32_bytes(hex_str: &str) -> Option<Hash> {
    let bytes = hex::decode(hex_str.trim_start_matches("0x")).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use sxiaum_types::Validator;

    #[test]
    fn nano_ffi_null_pointer_safety() {
        unsafe {
            // Null config json
            let client = sxiaum_nano_light_client_new(std::ptr::null());
            assert!(client.is_null());

            // Null client free
            sxiaum_nano_light_client_free(std::ptr::null_mut());

            // Null args to verify_header
            let mut out = [0u8; 32];
            let res = sxiaum_nano_verify_header(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                1000,
                out.as_mut_ptr(),
            );
            assert_eq!(res, -1);
        }
    }

    #[test]
    fn nano_ffi_c_abi_roundtrip_and_safety() {
        unsafe {
            let pubkey = [1u8; 32];
            let address = Address::from_public_key(&pubkey);
            let mut v = Validator::new(address, pubkey, primitive_types::U256::from(1000));
            v.voting_power = 100;
            v.status = sxiaum_types::ValidatorStatus::Active;

            let config = NanoLightConfig {
                genesis_state_root: [0u8; 32],
                initial_validator_set: vec![v],
                ring_buffer_capacity: 128,
                max_timestamp_drift_secs: 5,
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            };
            let json_str = serde_json::to_string(&config).expect("serialize config");
            let c_json = CString::new(json_str).expect("cstring");

            let client = sxiaum_nano_light_client_new(c_json.as_ptr());
            assert!(!client.is_null(), "valid config json must instantiate client");

            sxiaum_nano_light_client_free(client);
        }
    }
}
