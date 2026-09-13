#![no_main]

use libfuzzer_sys::fuzz_target;
use primitive_types::U256;
use std::sync::Arc;
use sxiaum_execution::evm_runtime::{compute_contract_address, EvmConfig, EvmRuntime};
use sxiaum_state::StateDb;
use sxiaum_storage::MemoryDatabaseBackend;
use sxiaum_types::{Address, Transaction, SXIAUM_CHAIN_ID};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Initialize in-memory storage and state database
    let storage = Arc::new(MemoryDatabaseBackend::new());
    let state = Arc::new(StateDb::new(storage));

    // 2. Setup caller address and seed with balance for gas and deployment value
    let caller_addr = Address([1u8; 32]);
    let initial_balance = U256::from(10_000_000_000_000_000_000u128); // 10 SXI
    let _ = state.set_balance(&caller_addr, initial_balance);
    let _ = state.commit();

    let config = EvmConfig::new(SXIAUM_CHAIN_ID);
    let runtime = EvmRuntime::new(config, state.state_root());

    // 3. Fuzz contract deployment with fuzzed bytecode as init-code
    let mut deploy_tx = Transaction::new_contract_deploy(
        caller_addr,
        U256::zero(),
        0,
        data.to_vec(),
    );
    deploy_tx.gas_limit = 1_000_000;
    deploy_tx.gas_price = U256::from(1);
    deploy_tx.chain_id = Some(SXIAUM_CHAIN_ID);

    let deploy_result = runtime.deploy_contract(&state, &deploy_tx);

    // 4. If deployment succeeds or if we test calls, fuzz contract execution
    if let Ok(res) = deploy_result {
        if res.success {
            let contract_addr = compute_contract_address(&caller_addr, 0);

            // Fuzz contract call with sub-slice calldata
            let call_data = if data.len() > 4 { &data[4..] } else { data };
            let mut call_tx = Transaction::new_contract_call(
                caller_addr,
                contract_addr,
                U256::zero(),
                1,
                call_data.to_vec(),
            );
            call_tx.gas_limit = 500_000;
            call_tx.gas_price = U256::from(1);
            call_tx.chain_id = Some(SXIAUM_CHAIN_ID);

            let _ = runtime.call_contract_read_only(&state, &call_tx);
            let _ = runtime.execute_contract_call(&state, &call_tx);
        }
    }
});

