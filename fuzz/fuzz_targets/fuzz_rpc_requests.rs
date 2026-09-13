#![no_main]

use libfuzzer_sys::fuzz_target;
use sxiaum_rpc::error::JsonRpcError;
use sxiaum_rpc::protocol::{JsonRpcRequest, JsonRpcResponse};

fuzz_target!(|data: &[u8]| {
    // 1. Single JSON-RPC request parsing and validation
    if let Ok(req) = serde_json::from_slice::<JsonRpcRequest>(data) {
        let validation_res = req.validate();
        match validation_res {
            Ok(()) => {
                let resp = JsonRpcResponse::success(req.id.clone(), serde_json::json!({"status": "ok"}));
                let _ = serde_json::to_vec(&resp);
            }
            Err(err) => {
                let resp = JsonRpcResponse::error(req.id.clone(), err);
                let _ = serde_json::to_vec(&resp);
            }
        }
    }

    // 2. Batch JSON-RPC request parsing
    if let Ok(batch) = serde_json::from_slice::<Vec<JsonRpcRequest>>(data) {
        for req in batch {
            let _ = req.validate();
            let err_resp = JsonRpcResponse::error(req.id, JsonRpcError::invalid_request("fuzz test"));
            let _ = serde_json::to_vec(&err_resp);
        }
    }

    // 3. Generic JSON-RPC Value structure testing
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Some(obj) = val.as_object() {
            let _ = obj.get("jsonrpc");
            let _ = obj.get("method");
            let _ = obj.get("params");
            let _ = obj.get("id");
        }
    }
});

