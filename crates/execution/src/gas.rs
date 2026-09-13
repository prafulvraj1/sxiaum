//! Production mainnet gas accounting for SXIAUM execution.
//!
//! # Design
//!
//! SXIAUM uses a **reduced Verkle-optimized schedule** relative to Ethereum
//! (see whitepaper §10). Base transfer / storage constants remain intentionally
//! lower than the Yellow Paper, while **accounting structure** matches Cancun:
//!
//! * Memory expansion quadratic cost
//! * Cold / warm storage access (EIP-2929 style)
//! * Net-metered `SSTORE` with original / current / new (EIP-2200)
//! * Refund counter capped at `gas_used / MAX_REFUND_QUOTIENT` (EIP-3529)
//! * Full Cancun precompile gas schedule
//!
//! Outer transaction fee accounting (`deduct_fee` / `refund_unused`) is separate
//! from in-execution refunds: prepaid gas is charged upfront; unused gas and
//! applied execution refunds are credited back after final gas is known.

use anyhow::{bail, Result};
use primitive_types::U256;
use std::collections::HashSet;
use sxiaum_types::{Account, Transaction};

// ---------------------------------------------------------------------------
// Base schedule (whitepaper §10.1 — Verkle-optimized)
// ---------------------------------------------------------------------------

/// Base intrinsic gas for a simple transfer (Ethereum: 21_000).
pub const INTRINSIC_GAS: u64 = 210;
/// Value-transfer gas cost (same base as intrinsic on SXIAUM).
pub const VALUE_TRANSFER_GAS: u64 = 210;
/// Warm storage read cost (Verkle-amortized; Ethereum warm SLOAD: 100).
pub const STORAGE_READ_GAS: u64 = 48;
/// Base storage write cost for a non-zero → non-zero update (warm).
pub const STORAGE_WRITE_GAS: u64 = 200;
/// Gas per non-zero calldata byte (Ethereum: 16).
pub const CALLDATA_GAS: u64 = 1;
/// Gas per zero calldata byte (parity with Ethereum EIP-2028).
pub const CALLDATA_ZERO_GAS: u64 = 4;

// ---------------------------------------------------------------------------
// Memory expansion (Yellow Paper C_mem)
// ---------------------------------------------------------------------------

/// Linear coefficient for memory expansion (`G_memory`).
pub const MEMORY_GAS: u64 = 3;
/// Quadratic divisor for memory expansion cost (`a² / 512`).
pub const MEMORY_EXPANSION_QUOTIENT: u64 = 512;
/// Maximum EVM memory size in words (to bound quadratic cost DoS).
pub const MAX_MEMORY_WORDS: u64 = 0x1FFFFFF;

// ---------------------------------------------------------------------------
// Storage access — cold / warm (EIP-2929 adapted to SXIAUM scale)
// ---------------------------------------------------------------------------

/// Extra gas charged the first time a storage key is touched in a tx.
/// Ethereum cold SLOAD surcharge is 2_000; SXIAUM uses a Verkle-scaled 20.
pub const COLD_SLOAD_COST: u64 = 20;
/// Warm storage slot access cost (equals [`STORAGE_READ_GAS`]).
pub const WARM_STORAGE_READ_COST: u64 = STORAGE_READ_GAS;
/// Cold account access surcharge (Ethereum: 2_600; scaled).
pub const COLD_ACCOUNT_ACCESS_COST: u64 = 26;
/// Warm account access cost (Ethereum: 100; scaled).
pub const WARM_ACCOUNT_ACCESS_COST: u64 = 10;

// ---------------------------------------------------------------------------
// SSTORE net metering (EIP-2200 / London, scaled to SXIAUM)
// ---------------------------------------------------------------------------

/// `SSTORE` when setting a slot from zero to non-zero (create storage).
pub const SSTORE_SET_GAS: u64 = 200;
/// `SSTORE` when resetting a non-zero slot to a different non-zero value.
pub const SSTORE_RESET_GAS: u64 = 50;
/// Minimum gas that must remain for `SSTORE` (EIP-2200 / EIP-1706).
/// Scaled ~100x down from Ethereum's 2_300 to match the Verkle schedule.
pub const SSTORE_SENTRY_GAS: u64 = 23;
/// Refund for clearing a non-zero slot back to zero (EIP-3529 removed
/// selfdestruct refunds but kept SSTORE clear refunds at 4_800 on Ethereum;
/// SXIAUM scales to 48).
pub const SSTORE_CLEARS_SCHEDULE: u64 = 48;
/// Refund when restoring original non-zero value after dirty writes.
///
/// **EIP-3529 (London)** removed this refund; set to 0 for Cancun.
pub const SSTORE_RESET_REFUND: u64 = 0;
/// Refund when restoring original zero after dirty writes that set non-zero.
///
/// **EIP-3529 (London)** removed `R_SSET`; set to 0 for Cancun.
pub const SSTORE_SET_REFUND: u64 = 0;

// ---------------------------------------------------------------------------
// Create / code deposit / copy
// ---------------------------------------------------------------------------

/// Extra intrinsic gas for contract-creation transactions.
pub const TX_CREATE_GAS: u64 = 320;
/// Gas per byte of deployed runtime code (Ethereum: 200).
pub const CODE_DEPOSIT_GAS: u64 = 2;
/// Gas per word copied by `CALLDATACOPY` / `CODECOPY` / `RETURNDATACOPY`.
pub const COPY_GAS: u64 = 3;
/// Gas per word of `KECCAK256` input (plus base).
pub const KECCAK256_WORD_GAS: u64 = 6;
/// Base gas for `KECCAK256`.
pub const KECCAK256_GAS: u64 = 30;
/// Gas per 32-byte word of initcode (EIP-3860), scaled.
pub const INITCODE_WORD_GAS: u64 = 2;

// ---------------------------------------------------------------------------
// Refund policy (EIP-3529)
// ---------------------------------------------------------------------------

/// Maximum refund is `gas_used / MAX_REFUND_QUOTIENT` (Ethereum: 5).
pub const MAX_REFUND_QUOTIENT: u64 = 5;

// ---------------------------------------------------------------------------
// Precompile addresses (20-byte Ethereum form, low 20 of SXIAUM Address)
// ---------------------------------------------------------------------------

/// `ecrecover` — 0x01
pub const PRECOMPILE_ECRECOVER: u8 = 0x01;
/// `sha256` — 0x02
pub const PRECOMPILE_SHA256: u8 = 0x02;
/// `ripemd160` — 0x03
pub const PRECOMPILE_RIPEMD160: u8 = 0x03;
/// `identity` (data copy) — 0x04
pub const PRECOMPILE_IDENTITY: u8 = 0x04;
/// `modexp` — 0x05
pub const PRECOMPILE_MODEXP: u8 = 0x05;
/// `ecAdd` (bn256/alt_bn128) — 0x06
pub const PRECOMPILE_ECADD: u8 = 0x06;
/// `ecMul` (bn256/alt_bn128) — 0x07
pub const PRECOMPILE_ECMUL: u8 = 0x07;
/// `ecPairing` (bn256/alt_bn128) — 0x08
pub const PRECOMPILE_ECPAIRING: u8 = 0x08;
/// `blake2f` — 0x09
pub const PRECOMPILE_BLAKE2F: u8 = 0x09;
/// `point evaluation` (KZG / EIP-4844) — 0x0a
pub const PRECOMPILE_POINT_EVALUATION: u8 = 0x0a;

// Precompile base gas (Cancun / Istanbul values — kept at Ethereum parity so
// revm SpecId::CANCUN and this schedule agree for precompile metering).
pub const ECRECOVER_GAS: u64 = 3_000;
pub const SHA256_BASE_GAS: u64 = 60;
pub const SHA256_PER_WORD_GAS: u64 = 12;
pub const RIPEMD160_BASE_GAS: u64 = 600;
pub const RIPEMD160_PER_WORD_GAS: u64 = 120;
pub const IDENTITY_BASE_GAS: u64 = 15;
pub const IDENTITY_PER_WORD_GAS: u64 = 3;
pub const ECADD_GAS: u64 = 150;
pub const ECMUL_GAS: u64 = 6_000;
pub const ECPAIRING_BASE_GAS: u64 = 45_000;
pub const ECPAIRING_PER_POINT_GAS: u64 = 34_000;
pub const BLAKE2F_GAS_PER_ROUND: u64 = 1;
pub const POINT_EVALUATION_GAS: u64 = 50_000;
/// EIP-2565 modexp minimum gas.
pub const MODEXP_MIN_GAS: u64 = 200;

// ---------------------------------------------------------------------------
// Access-list / warm-cold tracking key
// ---------------------------------------------------------------------------

/// 32-byte storage key identity used by the access tracker.
pub type StorageKey = [u8; 32];
/// 20-byte account key (Ethereum address form).
pub type AccountKey = [u8; 20];

/// Result of an `SSTORE` gas calculation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SStoreGas {
    /// Gas that must be consumed immediately (dynamic cost).
    pub gas_cost: u64,
    /// Refund delta: positive credits the refund counter; negative debits it.
    pub refund_delta: i64,
}

/// Gas schedule snapshot used by meters and helpers.
///
/// Defaults match the mainnet Verkle-optimized constants above. Tests or
/// future hard-forks can construct alternate schedules without rewriting call
/// sites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasSchedule {
    pub intrinsic: u64,
    pub value_transfer: u64,
    pub storage_read: u64,
    pub storage_write: u64,
    pub calldata_non_zero: u64,
    pub calldata_zero: u64,
    pub memory: u64,
    pub memory_quotient: u64,
    pub cold_sload: u64,
    pub warm_sload: u64,
    pub cold_account: u64,
    pub warm_account: u64,
    pub sstore_set: u64,
    pub sstore_reset: u64,
    pub sstore_clears_refund: u64,
    pub sstore_sentry: u64,
    pub tx_create: u64,
    pub code_deposit: u64,
    pub max_refund_quotient: u64,
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl GasSchedule {
    /// Canonical SXIAUM mainnet schedule (Cancun-structured, Verkle-scaled).
    pub const fn mainnet() -> Self {
        Self {
            intrinsic: INTRINSIC_GAS,
            value_transfer: VALUE_TRANSFER_GAS,
            storage_read: STORAGE_READ_GAS,
            storage_write: STORAGE_WRITE_GAS,
            calldata_non_zero: CALLDATA_GAS,
            calldata_zero: CALLDATA_ZERO_GAS,
            memory: MEMORY_GAS,
            memory_quotient: MEMORY_EXPANSION_QUOTIENT,
            cold_sload: COLD_SLOAD_COST,
            warm_sload: WARM_STORAGE_READ_COST,
            cold_account: COLD_ACCOUNT_ACCESS_COST,
            warm_account: WARM_ACCOUNT_ACCESS_COST,
            sstore_set: SSTORE_SET_GAS,
            sstore_reset: SSTORE_RESET_GAS,
            sstore_clears_refund: SSTORE_CLEARS_SCHEDULE,
            sstore_sentry: SSTORE_SENTRY_GAS,
            tx_create: TX_CREATE_GAS,
            code_deposit: CODE_DEPOSIT_GAS,
            max_refund_quotient: MAX_REFUND_QUOTIENT,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure cost functions
// ---------------------------------------------------------------------------

/// Word count for `len` bytes (`ceil(len / 32)`).
#[inline]
pub fn num_words(len: usize) -> u64 {
    ((len as u64).saturating_add(31)) / 32
}

/// Absolute memory cost for a size of `words` 32-byte words.
///
/// Yellow Paper: `C_mem(a) = G_memory * a + a² / 512`.
pub fn memory_cost(words: u64, schedule: &GasSchedule) -> u64 {
    if words == 0 {
        return 0;
    }
    let words = words.min(MAX_MEMORY_WORDS);
    let linear = words.saturating_mul(schedule.memory);
    let quadratic = words.saturating_mul(words) / schedule.memory_quotient;
    linear.saturating_add(quadratic)
}

/// Incremental memory expansion cost from `old_words` to `new_words`.
///
/// Returns 0 when the memory size does not grow.
pub fn memory_expansion_cost(old_words: u64, new_words: u64, schedule: &GasSchedule) -> u64 {
    if new_words <= old_words {
        return 0;
    }
    memory_cost(new_words, schedule).saturating_sub(memory_cost(old_words, schedule))
}

/// Memory words required to cover byte range `[offset, offset + len)`.
pub fn memory_words_for_range(offset: u64, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let end = offset.saturating_add(len);
    num_words(end as usize)
}

/// `SLOAD` dynamic gas given warm/cold status.
pub fn sload_gas(is_warm: bool, schedule: &GasSchedule) -> u64 {
    if is_warm {
        schedule.warm_sload
    } else {
        schedule.warm_sload.saturating_add(schedule.cold_sload)
    }
}

/// Account-access gas (CALL / BALANCE / EXTCODE* target) given warm/cold.
pub fn account_access_gas(is_warm: bool, schedule: &GasSchedule) -> u64 {
    if is_warm {
        schedule.warm_account
    } else {
        schedule.cold_account
    }
}

/// Net-metered `SSTORE` gas (EIP-2200 / London), using SXIAUM unit costs.
///
/// `original` — value at the beginning of the transaction  
/// `current`  — value currently in the slot  
/// `new`      — value being written  
/// `is_warm`  — whether the slot was already accessed this transaction
///
/// Refunds are returned as a signed delta applied to the refund counter
/// (positive = credit, negative = claw back a prior credit).
pub fn sstore_gas(
    original: U256,
    current: U256,
    new: U256,
    is_warm: bool,
    schedule: &GasSchedule,
) -> SStoreGas {
    // No-op store still pays warm/cold access.
    if current == new {
        let access = if is_warm {
            schedule.warm_sload
        } else {
            schedule.cold_sload.saturating_add(schedule.warm_sload)
        };
        return SStoreGas {
            gas_cost: access,
            refund_delta: 0,
        };
    }

    let mut gas_cost: u64;
    let mut refund_delta: i64 = 0;

    if original == current {
        // Clean slot (first write in this tx relative to original).
        if original.is_zero() {
            gas_cost = schedule.sstore_set;
        } else {
            gas_cost = schedule.sstore_reset;
            if new.is_zero() {
                refund_delta += schedule.sstore_clears_refund as i64;
            }
        }
    } else {
        // Dirty slot — already written earlier in this tx.
        gas_cost = schedule.warm_sload;

        // Adjust refunds when dirty writes undo / redo clears.
        if !original.is_zero() {
            if current.is_zero() {
                // Was cleared; now setting non-zero again → claw back clear refund.
                refund_delta -= schedule.sstore_clears_refund as i64;
            } else if new.is_zero() {
                // Clearing again → re-credit clear refund.
                refund_delta += schedule.sstore_clears_refund as i64;
            }
        }

        // Reset-to-original refunds.
        if original == new {
            if original.is_zero() {
                // Dirty path had set non-zero from zero; restoring zero.
                refund_delta += SSTORE_SET_REFUND as i64;
            } else {
                refund_delta += SSTORE_RESET_REFUND as i64;
            }
        }
    }

    // Cold slot surcharge on first access.
    if !is_warm {
        gas_cost = gas_cost.saturating_add(schedule.cold_sload);
    }

    SStoreGas {
        gas_cost,
        refund_delta,
    }
}

/// Code-deposit cost for `len` bytes of runtime bytecode.
pub fn code_deposit_cost(len: usize, schedule: &GasSchedule) -> u64 {
    (len as u64).saturating_mul(schedule.code_deposit)
}

/// Initcode cost per EIP-3860 word (scaled).
pub fn initcode_cost(len: usize) -> u64 {
    num_words(len).saturating_mul(INITCODE_WORD_GAS)
}

/// `KECCAK256` gas for `len` input bytes (no memory expansion).
pub fn keccak256_gas(len: usize) -> u64 {
    KECCAK256_GAS.saturating_add(num_words(len).saturating_mul(KECCAK256_WORD_GAS))
}

/// Copy operation gas for `len` bytes (no memory expansion).
pub fn copy_gas(len: usize) -> u64 {
    num_words(len).saturating_mul(COPY_GAS)
}

// ---------------------------------------------------------------------------
// Precompile gas
// ---------------------------------------------------------------------------

/// Return `true` if `addr_byte` is a known Cancun precompile (0x01..=0x0a).
#[inline]
pub fn is_precompile(addr_low_byte: u8) -> bool {
    matches!(addr_low_byte, 0x01..=0x0a)
}

/// Gas cost for a precompile call given the low address byte and input.
///
/// Costs match the Ethereum Cancun schedule so behaviour aligns with
/// `revm::primitives::SpecId::CANCUN`. Returns `None` for unknown addresses.
pub fn precompile_gas(address: u8, input: &[u8]) -> Option<u64> {
    Some(match address {
        PRECOMPILE_ECRECOVER => ECRECOVER_GAS,
        PRECOMPILE_SHA256 => SHA256_BASE_GAS
            .saturating_add(num_words(input.len()).saturating_mul(SHA256_PER_WORD_GAS)),
        PRECOMPILE_RIPEMD160 => RIPEMD160_BASE_GAS
            .saturating_add(num_words(input.len()).saturating_mul(RIPEMD160_PER_WORD_GAS)),
        PRECOMPILE_IDENTITY => IDENTITY_BASE_GAS
            .saturating_add(num_words(input.len()).saturating_mul(IDENTITY_PER_WORD_GAS)),
        PRECOMPILE_MODEXP => modexp_gas(input),
        PRECOMPILE_ECADD => ECADD_GAS,
        PRECOMPILE_ECMUL => ECMUL_GAS,
        PRECOMPILE_ECPAIRING => {
            // Input must be a multiple of 192 bytes (each pairing point).
            if !input.len().is_multiple_of(192) {
                return Some(u64::MAX); // caller should treat as OOG / fail
            }
            let k = (input.len() / 192) as u64;
            ECPAIRING_BASE_GAS.saturating_add(k.saturating_mul(ECPAIRING_PER_POINT_GAS))
        }
        PRECOMPILE_BLAKE2F => blake2f_gas(input)?,
        PRECOMPILE_POINT_EVALUATION => POINT_EVALUATION_GAS,
        _ => return None,
    })
}

/// EIP-2565 modular exponentiation gas.
///
/// Input layout: `[bsize(32) | esize(32) | msize(32) | b | e | m]`.
///
/// The adjusted exponent length follows EIP-198 / EIP-2565:
/// * If `esize <= 32`: `max(bit_length(E) - 1, 0)`
/// * If `esize >  32`: `8 * (esize - 32) + max(bit_length(E[:32]) - 1, 0)`
///
/// where `bit_length` is the number of bits in the big-endian representation
/// of the exponent (0 if the exponent is all-zero).
pub fn modexp_gas(input: &[u8]) -> u64 {
    let read_u64 = |offset: usize| -> u64 {
        if input.len() < offset + 32 {
            return 0;
        }
        // If any of the leading 24 bytes are non-zero, length exceeds u64::MAX.
        if input[offset..offset + 24].iter().any(|&b| b != 0) {
            return u64::MAX;
        }
        let mut bytes = [0u8; 8];
        // Take the low 8 bytes of the 32-byte big-endian length word.
        bytes.copy_from_slice(&input[offset + 24..offset + 32]);
        u64::from_be_bytes(bytes)
    };

    let bsize = read_u64(0);
    let esize = read_u64(32);
    let msize = read_u64(64);

    if bsize == u64::MAX || esize == u64::MAX || msize == u64::MAX {
        return u64::MAX;
    }

    let max_len = bsize.max(msize);
    let words = num_words(max_len as usize);
    let multiplication_complexity = words.saturating_mul(words);

    // Compute the bit length of the first min(32, esize) bytes of the exponent,
    // interpreted as a big-endian unsigned integer.
    let exp_head_offset = 96usize.saturating_add(bsize as usize);
    let exp_head_len = (esize.min(32)) as usize;
    let bit_length: u64 = if esize == 0 || exp_head_offset >= input.len() {
        0
    } else {
        let available = input.len().saturating_sub(exp_head_offset);
        let take = exp_head_len.min(available);
        let mut bl: u64 = 0;
        for i in 0..take {
            let byte = input[exp_head_offset + i];
            if byte != 0 {
                // Big-endian bit length: 8 * (remaining bytes after this one)
                //                   + (8 - leading_zeros of this byte).
                bl = 8u64
                    .saturating_mul((take - i) as u64)
                    .saturating_sub(byte.leading_zeros() as u64);
                break;
            }
        }
        bl
    };

    // Adjusted exponent length (EIP-198 / EIP-2565).
    let msb_pos = if bit_length > 0 { bit_length - 1 } else { 0 };
    let adjusted_exp: u64 = if esize <= 32 {
        msb_pos
    } else {
        8u64.saturating_mul(esize.saturating_sub(32))
            .saturating_add(msb_pos)
    };

    // If adjusted_exp is 0 the gas is 0 (clamped to MODEXP_MIN_GAS below).
    let gas = if adjusted_exp == 0 {
        0u64
    } else {
        multiplication_complexity
            .saturating_mul(adjusted_exp)
            .saturating_div(3)
    };
    gas.max(MODEXP_MIN_GAS)
}

/// Blake2F gas: rounds are big-endian bytes 0..4 of the 213-byte input.
fn blake2f_gas(input: &[u8]) -> Option<u64> {
    if input.len() != 213 {
        return None;
    }
    let rounds = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    Some((rounds as u64).saturating_mul(BLAKE2F_GAS_PER_ROUND))
}

// ---------------------------------------------------------------------------
// Gas meter
// ---------------------------------------------------------------------------

/// Per-transaction gas meter with memory, storage access, and refund state.
#[derive(Clone, Debug)]
pub struct GasMeter {
    pub gas_limit: u64,
    pub gas_used: u64,
    /// Accumulated execution refunds (not yet applied to `gas_used`).
    pub gas_refund: u64,
    /// Current EVM memory size in 32-byte words.
    pub memory_words: u64,
    /// Warm storage keys touched so far in this transaction.
    warm_storage: HashSet<StorageKey>,
    /// Warm accounts touched so far in this transaction.
    warm_accounts: HashSet<AccountKey>,
    /// Active gas schedule.
    pub schedule: GasSchedule,
}

impl Default for GasMeter {
    fn default() -> Self {
        Self::new(0)
    }
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self::with_schedule(limit, GasSchedule::mainnet())
    }

    pub fn with_schedule(limit: u64, schedule: GasSchedule) -> Self {
        Self {
            gas_limit: limit,
            gas_used: 0,
            gas_refund: 0,
            memory_words: 0,
            warm_storage: HashSet::new(),
            warm_accounts: HashSet::new(),
            schedule,
        }
    }

    /// Consume `amount` gas or fail with out-of-gas.
    pub fn consume(&mut self, amount: u64) -> Result<()> {
        let next = self.gas_used.saturating_add(amount);
        if next > self.gas_limit {
            bail!(
                "out of gas: attempted to use {}, limit {}",
                next,
                self.gas_limit
            );
        }
        self.gas_used = next;
        Ok(())
    }

    pub fn remaining(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }

    /// Record an execution refund (EIP-2200 / EIP-3529 counter).
    ///
    /// Does **not** immediately reduce `gas_used`. Call [`Self::apply_refunds`]
    /// at the end of the transaction to apply the capped refund.
    pub fn record_refund(&mut self, amount: u64) {
        self.gas_refund = self.gas_refund.saturating_add(amount);
    }

    /// Apply a signed refund delta (positive credit, negative claw-back).
    pub fn apply_refund_delta(&mut self, delta: i64) {
        if delta >= 0 {
            self.record_refund(delta as u64);
        } else {
            let claw = (-delta) as u64;
            self.gas_refund = self.gas_refund.saturating_sub(claw);
        }
    }

    /// Credit a refund into the counter.
    ///
    /// Historical callers treated this as an immediate reduction of
    /// `gas_used`. For mainnet correctness the amount is queued and must be
    /// finalized with [`Self::apply_refunds`]. Immediate reduction is still
    /// available via [`Self::credit_gas`] for non-EVM fee adjustments.
    pub fn refund(&mut self, amount: u64) {
        self.record_refund(amount);
    }

    /// Unconditionally reduce `gas_used` (fee / test helper, not EIP refund).
    pub fn credit_gas(&mut self, amount: u64) {
        self.gas_used = self.gas_used.saturating_sub(amount);
    }

    /// Apply the refund counter subject to EIP-3529:
    /// `min(gas_refund, gas_used / max_refund_quotient)`.
    ///
    /// Returns the amount actually applied (subtracted from `gas_used`).
    pub fn apply_refunds(&mut self) -> u64 {
        if self.schedule.max_refund_quotient == 0 || self.gas_used == 0 {
            self.gas_refund = 0;
            return 0;
        }
        let cap = self.gas_used / self.schedule.max_refund_quotient;
        let applied = self.gas_refund.min(cap);
        self.gas_used = self.gas_used.saturating_sub(applied);
        self.gas_refund = 0;
        applied
    }

    /// Final gas used after applying the refund cap (does not mutate state).
    pub fn effective_gas_used(&self) -> u64 {
        if self.schedule.max_refund_quotient == 0 || self.gas_used == 0 {
            return self.gas_used;
        }
        let cap = self.gas_used / self.schedule.max_refund_quotient;
        self.gas_used.saturating_sub(self.gas_refund.min(cap))
    }

    pub fn out_of_gas(&self) -> bool {
        self.gas_used >= self.gas_limit
    }

    pub fn reset(&mut self) {
        self.gas_used = 0;
        self.gas_refund = 0;
        self.memory_words = 0;
        self.warm_storage.clear();
        self.warm_accounts.clear();
    }

    // -- Memory -------------------------------------------------------------

    /// Expand memory to cover `[offset, offset+len)` and charge expansion gas.
    pub fn charge_memory(&mut self, offset: u64, len: u64) -> Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        let required = memory_words_for_range(offset, len);
        let cost = memory_expansion_cost(self.memory_words, required, &self.schedule);
        self.consume(cost)?;
        if required > self.memory_words {
            self.memory_words = required;
        }
        Ok(cost)
    }

    // -- Storage access -----------------------------------------------------

    /// Mark a storage key warm; returns `true` if it was already warm.
    pub fn touch_storage(&mut self, key: StorageKey) -> bool {
        !self.warm_storage.insert(key)
    }

    /// Mark an account warm; returns `true` if it was already warm.
    pub fn touch_account(&mut self, key: AccountKey) -> bool {
        !self.warm_accounts.insert(key)
    }

    pub fn is_storage_warm(&self, key: &StorageKey) -> bool {
        self.warm_storage.contains(key)
    }

    pub fn is_account_warm(&self, key: &AccountKey) -> bool {
        self.warm_accounts.contains(key)
    }

    /// Charge `SLOAD` for `key`, updating the warm set.
    pub fn charge_sload(&mut self, key: StorageKey) -> Result<u64> {
        let warm = self.touch_storage(key);
        let cost = sload_gas(warm, &self.schedule);
        self.consume(cost)?;
        Ok(cost)
    }

    /// Charge net-metered `SSTORE` for `key`, updating warm set and refunds.
    pub fn charge_sstore(
        &mut self,
        key: StorageKey,
        original: U256,
        current: U256,
        new: U256,
    ) -> Result<SStoreGas> {
        // EIP-2200 sentry: fail if remaining gas <= sentry threshold.
        if self.remaining() <= self.schedule.sstore_sentry {
            bail!(
                "out of gas: SSTORE sentry (remaining {}, sentry {})",
                self.remaining(),
                self.schedule.sstore_sentry
            );
        }
        let warm = self.touch_storage(key);
        let result = sstore_gas(original, current, new, warm, &self.schedule);
        self.consume(result.gas_cost)?;
        self.apply_refund_delta(result.refund_delta);
        Ok(result)
    }

    /// Charge account access (CALL target, BALANCE, EXTCODE*, …).
    pub fn charge_account_access(&mut self, key: AccountKey) -> Result<u64> {
        let warm = self.touch_account(key);
        let cost = account_access_gas(warm, &self.schedule);
        self.consume(cost)?;
        Ok(cost)
    }

    /// Charge a precompile invocation (Cancun schedule).
    pub fn charge_precompile(&mut self, address: u8, input: &[u8]) -> Result<u64> {
        let cost = precompile_gas(address, input)
            .ok_or_else(|| anyhow::anyhow!("unknown precompile address 0x{address:02x}"))?;
        if cost == u64::MAX {
            bail!("precompile input invalid / would exceed gas");
        }
        self.consume(cost)?;
        Ok(cost)
    }

    // -- Fee helpers --------------------------------------------------------

    pub fn gas_price(&self, tx: &Transaction) -> U256 {
        tx.gas_price
    }

    pub fn calculate_fee(&self, tx: &Transaction) -> Result<U256> {
        self.gas_price(tx)
            .checked_mul(U256::from(self.effective_gas_used()))
            .ok_or_else(|| anyhow::anyhow!("gas fee multiplication overflow"))
    }

    pub fn deduct_fee(&mut self, account: &mut Account, tx: &Transaction) -> Result<U256> {
        let prepaid = self
            .gas_price(tx)
            .checked_mul(U256::from(self.gas_limit))
            .ok_or_else(|| anyhow::anyhow!("prepaid gas multiplication overflow"))?;
        account.checked_sub_balance(prepaid)?;
        Ok(prepaid)
    }

    pub fn refund_unused(&self, account: &mut Account, tx: &Transaction) -> Result<U256> {
        let prepaid = self
            .gas_price(tx)
            .checked_mul(U256::from(self.gas_limit))
            .ok_or_else(|| anyhow::anyhow!("prepaid gas multiplication overflow"))?;
        let used_fee = self
            .gas_price(tx)
            .checked_mul(U256::from(self.effective_gas_used()))
            .ok_or_else(|| anyhow::anyhow!("used gas multiplication overflow"))?;
        let refund = prepaid
            .checked_sub(used_fee)
            .ok_or_else(|| anyhow::anyhow!("used fee exceeds prepaid gas"))?;
        if refund > U256::zero() {
            account.checked_add_balance(refund)?;
        }
        Ok(refund)
    }

    pub fn gas_cost_transfer(&self) -> u64 {
        self.schedule.value_transfer
    }

    pub fn gas_cost_storage_read(&self) -> u64 {
        self.schedule.storage_read
    }

    pub fn gas_cost_storage_write(&self) -> u64 {
        self.schedule.storage_write
    }

    pub fn gas_cost_contract_call(&self) -> u64 {
        self.schedule.intrinsic + self.gas_cost_storage_read() + self.gas_cost_storage_write()
    }
}

// ---------------------------------------------------------------------------
// Intrinsic / validation
// ---------------------------------------------------------------------------

/// Calculate the intrinsic gas for a transaction based on its calldata.
///
/// Non-zero bytes cost `CALLDATA_GAS` (1 gas), zero bytes cost
/// `CALLDATA_ZERO_GAS` (4 gas), matching the SXIAUM reduced gas schedule.
/// Contract-creation transactions also pay [`TX_CREATE_GAS`] plus initcode
/// word gas (EIP-3860 scaled).
pub fn calculate_intrinsic_gas(data: &[u8]) -> u64 {
    calculate_intrinsic_gas_ex(data, false)
}

/// Intrinsic gas with explicit create flag.
pub fn calculate_intrinsic_gas_ex(data: &[u8], is_create: bool) -> u64 {
    let schedule = GasSchedule::mainnet();
    let mut gas = schedule.intrinsic;
    if is_create {
        gas = gas.saturating_add(schedule.tx_create);
        gas = gas.saturating_add(initcode_cost(data.len()));
    }
    for &byte in data {
        if byte != 0 {
            gas = gas.saturating_add(schedule.calldata_non_zero);
        } else {
            gas = gas.saturating_add(schedule.calldata_zero);
        }
    }
    gas
}

/// Validate that a transaction's gas limit is within mainnet bounds.
///
/// Checks:
/// * Gas limit > 0
/// * Gas limit >= intrinsic gas for the transaction's data
/// * Gas limit <= `MAX_TRANSACTION_GAS_LIMIT`
pub fn validate_gas_limit(tx: &Transaction) -> Result<()> {
    if tx.gas_limit == 0 {
        bail!("gas limit must be greater than zero");
    }

    let is_create = tx.to.is_none();
    let intrinsic = calculate_intrinsic_gas_ex(&tx.data, is_create);
    if tx.gas_limit < intrinsic {
        bail!(
            "gas limit {} is below intrinsic gas {} for this transaction",
            tx.gas_limit,
            intrinsic
        );
    }

    if tx.gas_limit > crate::MAX_TRANSACTION_GAS_LIMIT {
        bail!(
            "gas limit {} exceeds maximum transaction gas limit {}",
            tx.gas_limit,
            crate::MAX_TRANSACTION_GAS_LIMIT
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sxiaum_types::Address;

    #[test]
    fn gas_meter_supports_limits_fees_refunds_and_cost_helpers() {
        let tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
        let gas_limit = 10_000u64;
        let mut meter = GasMeter::new(gas_limit);
        let mut account = Account::new(Address([3u8; 32]));
        account.balance = U256::from(100_000u64);

        meter.consume(500).expect("consume should succeed");
        assert_eq!(meter.remaining(), gas_limit - 500);
        assert!(!meter.out_of_gas());
        assert_eq!(meter.gas_price(&tx), tx.gas_price);
        assert_eq!(
            meter.calculate_fee(&tx).expect("fee calculation"),
            U256::from(500u64)
        );
        assert_eq!(meter.gas_cost_transfer(), VALUE_TRANSFER_GAS);
        assert_eq!(meter.gas_cost_storage_read(), STORAGE_READ_GAS);
        assert_eq!(meter.gas_cost_storage_write(), STORAGE_WRITE_GAS);
        assert_eq!(
            meter.gas_cost_contract_call(),
            INTRINSIC_GAS + STORAGE_READ_GAS + STORAGE_WRITE_GAS
        );

        let fee_tx = {
            let mut t = Transaction::new_transfer(
                Address([1u8; 32]),
                Address([2u8; 32]),
                U256::from(1u64),
                0,
            );
            t.gas_limit = gas_limit;
            t
        };
        let starting_balance = account.balance;
        let prepaid = meter
            .deduct_fee(&mut account, &fee_tx)
            .expect("fee deduction should succeed");
        assert_eq!(prepaid, fee_tx.gas_cost());
        assert_eq!(account.balance, starting_balance - prepaid);
        let refund = meter
            .refund_unused(&mut account, &fee_tx)
            .expect("refund should succeed");
        assert_eq!(refund, fee_tx.gas_cost() - U256::from(500u64));
        assert_eq!(account.balance, starting_balance - U256::from(500u64));

        // Queued refund + apply (EIP-3529: cap = gas_used/5 = 100).
        meter.refund(250);
        assert_eq!(meter.gas_refund, 250);
        let applied = meter.apply_refunds();
        assert_eq!(applied, 100); // capped
        assert_eq!(meter.gas_used, 400);
        meter.reset();
        assert_eq!(meter.gas_used, 0);
        assert_eq!(meter.gas_refund, 0);
    }

    #[test]
    fn fee_helpers_reject_overflow_and_underflow() {
        let mut meter = GasMeter::new(2);
        let mut tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::zero(), 0);
        tx.gas_limit = 2;
        tx.gas_price = U256::MAX;

        let mut account = Account::new(Address([3u8; 32]));
        account.balance = U256::MAX;

        assert!(
            meter.deduct_fee(&mut account, &tx).is_err(),
            "prepaid fee multiplication overflow must abort"
        );
        assert_eq!(account.balance, U256::MAX);

        tx.gas_price = U256::one();
        let prepaid = meter
            .deduct_fee(&mut account, &tx)
            .expect("prepaid fee deduction");
        assert_eq!(prepaid, U256::from(2u64));
        assert_eq!(account.balance, U256::MAX - U256::from(2u64));

        let mut poor = Account::new(Address([4u8; 32]));
        poor.balance = U256::one();
        assert!(
            meter.deduct_fee(&mut poor, &tx).is_err(),
            "insufficient balance must abort the debit"
        );
        assert_eq!(poor.balance, U256::one());

        account.balance = U256::MAX;
        assert!(
            meter.refund_unused(&mut account, &tx).is_err(),
            "refund credit overflow must abort"
        );
        assert_eq!(account.balance, U256::MAX);

        account.balance = U256::zero();
        assert_eq!(
            meter
                .refund_unused(&mut account, &tx)
                .expect("refund calculation"),
            U256::from(2u64)
        );
        assert_eq!(account.balance, U256::from(2u64));
    }

    #[test]
    fn calculate_intrinsic_gas_accounts_for_zero_and_non_zero_bytes() {
        assert_eq!(calculate_intrinsic_gas(&[]), INTRINSIC_GAS);
        assert_eq!(
            calculate_intrinsic_gas(&[0u8, 1u8, 2u8]),
            INTRINSIC_GAS + CALLDATA_ZERO_GAS + CALLDATA_GAS + CALLDATA_GAS
        );
        // Create adds TX_CREATE_GAS + initcode words.
        let create = calculate_intrinsic_gas_ex(&[0u8; 32], true);
        assert_eq!(
            create,
            INTRINSIC_GAS + TX_CREATE_GAS + INITCODE_WORD_GAS + CALLDATA_ZERO_GAS * 32
        );
    }

    #[test]
    fn validate_gas_limit_rejects_zero_and_excessive_limits() {
        let mut tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);

        tx.gas_limit = 0;
        assert!(validate_gas_limit(&tx).is_err());

        tx.gas_limit = 1;
        assert!(validate_gas_limit(&tx).is_err());

        tx.gas_limit = 210;
        assert!(validate_gas_limit(&tx).is_ok());

        tx.gas_limit = crate::MAX_TRANSACTION_GAS_LIMIT + 1;
        assert!(validate_gas_limit(&tx).is_err());

        tx.gas_limit = crate::MAX_TRANSACTION_GAS_LIMIT;
        assert!(validate_gas_limit(&tx).is_ok());
    }

    #[test]
    fn memory_expansion_matches_yellow_paper_formula() {
        let schedule = GasSchedule::mainnet();
        // 0 → 0: free
        assert_eq!(memory_expansion_cost(0, 0, &schedule), 0);
        // Growing to 1 word: 3*1 + 1/512 = 3
        assert_eq!(memory_expansion_cost(0, 1, &schedule), 3);
        // Growing to 2 words: 3*2 + 4/512 = 6
        assert_eq!(memory_cost(2, &schedule), 6);
        // Incremental 1 → 2 equals absolute(2) − absolute(1)
        assert_eq!(
            memory_expansion_cost(1, 2, &schedule),
            memory_cost(2, &schedule) - memory_cost(1, &schedule)
        );
        // No growth
        assert_eq!(memory_expansion_cost(10, 5, &schedule), 0);

        // Larger size: words=32 → 3*32 + 1024/512 = 96 + 2 = 98
        assert_eq!(memory_cost(32, &schedule), 98);
    }

    #[test]
    fn gas_meter_charges_memory_expansion() {
        let mut meter = GasMeter::new(10_000);
        let cost = meter.charge_memory(0, 64).expect("mem expand");
        // 2 words → cost 6
        assert_eq!(cost, 6);
        assert_eq!(meter.memory_words, 2);
        assert_eq!(meter.gas_used, 6);

        // Same range again: no extra charge
        let cost2 = meter.charge_memory(0, 64).expect("no expand");
        assert_eq!(cost2, 0);
        assert_eq!(meter.gas_used, 6);

        // Extend to 128 bytes (4 words)
        let cost3 = meter.charge_memory(0, 128).expect("expand more");
        assert_eq!(
            cost3,
            memory_cost(4, &meter.schedule) - memory_cost(2, &meter.schedule)
        );
        assert_eq!(meter.memory_words, 4);
    }

    #[test]
    fn sload_cold_then_warm() {
        let mut meter = GasMeter::new(10_000);
        let key = [0x11u8; 32];
        let cold = meter.charge_sload(key).unwrap();
        assert_eq!(cold, WARM_STORAGE_READ_COST + COLD_SLOAD_COST);
        let warm = meter.charge_sload(key).unwrap();
        assert_eq!(warm, WARM_STORAGE_READ_COST);
        assert_eq!(meter.gas_used, cold + warm);
    }

    #[test]
    fn sstore_set_clear_and_refund_cap() {
        // SSTORE sentry requires remaining > 2300, so use a large limit.
        let mut meter = GasMeter::new(100_000);
        let key = [0xAAu8; 32];

        // zero → non-zero (set)
        let r = meter
            .charge_sstore(key, U256::zero(), U256::zero(), U256::from(1u64))
            .unwrap();
        assert_eq!(r.gas_cost, SSTORE_SET_GAS + COLD_SLOAD_COST); // cold first touch
        assert_eq!(r.refund_delta, 0);

        // non-zero → zero (clear) on dirty path from original=0:
        // original was 0, current is 1, new is 0 → dirty, restore original.
        // EIP-3529 removed R_SSET, so the restore-to-zero refund is 0.
        let r2 = meter
            .charge_sstore(key, U256::zero(), U256::from(1u64), U256::zero())
            .unwrap();
        assert!(r2.gas_cost > 0);
        assert_eq!(r2.refund_delta, 0); // EIP-3529: no restore-to-zero refund

        // Apply refunds with EIP-3529 cap (no refunds queued → 0 applied)
        let used_before = meter.gas_used;
        let applied = meter.apply_refunds();
        assert_eq!(applied, 0);
        assert_eq!(meter.gas_used, used_before);
    }

    #[test]
    fn sstore_clean_clear_refund() {
        let mut meter = GasMeter::new(100_000);
        let key = [0xBBu8; 32];
        let original = U256::from(7u64);
        // Clean clear: original == current == 7 → 0
        let r = meter
            .charge_sstore(key, original, original, U256::zero())
            .unwrap();
        assert_eq!(r.gas_cost, SSTORE_RESET_GAS + COLD_SLOAD_COST);
        assert_eq!(r.refund_delta, SSTORE_CLEARS_SCHEDULE as i64);
        assert_eq!(meter.gas_refund, SSTORE_CLEARS_SCHEDULE);
    }

    #[test]
    fn sstore_sentry_rejects_low_gas() {
        let mut meter = GasMeter::new(SSTORE_SENTRY_GAS); // remaining == sentry
        let err = meter
            .charge_sstore([0; 32], U256::zero(), U256::zero(), U256::from(1u64))
            .unwrap_err();
        assert!(err.to_string().contains("sentry"));

        // Just above sentry still needs enough gas to pay the SSTORE itself.
        let mut meter_ok = GasMeter::new(SSTORE_SENTRY_GAS + SSTORE_SET_GAS + COLD_SLOAD_COST + 1);
        assert!(meter_ok
            .charge_sstore([1u8; 32], U256::zero(), U256::zero(), U256::from(1u64))
            .is_ok());
    }

    #[test]
    fn precompile_gas_cancun_schedule() {
        assert_eq!(
            precompile_gas(PRECOMPILE_ECRECOVER, &[]),
            Some(ECRECOVER_GAS)
        );
        assert_eq!(
            precompile_gas(PRECOMPILE_SHA256, &[0u8; 64]),
            Some(SHA256_BASE_GAS + 2 * SHA256_PER_WORD_GAS)
        );
        assert_eq!(
            precompile_gas(PRECOMPILE_IDENTITY, &[0u8; 32]),
            Some(IDENTITY_BASE_GAS + IDENTITY_PER_WORD_GAS)
        );
        assert_eq!(precompile_gas(PRECOMPILE_ECADD, &[]), Some(ECADD_GAS));
        assert_eq!(precompile_gas(PRECOMPILE_ECMUL, &[]), Some(ECMUL_GAS));
        assert_eq!(
            precompile_gas(PRECOMPILE_ECPAIRING, &[]),
            Some(ECPAIRING_BASE_GAS)
        );
        assert_eq!(
            precompile_gas(PRECOMPILE_ECPAIRING, &[0u8; 192]),
            Some(ECPAIRING_BASE_GAS + ECPAIRING_PER_POINT_GAS)
        );
        assert_eq!(
            precompile_gas(PRECOMPILE_POINT_EVALUATION, &[]),
            Some(POINT_EVALUATION_GAS)
        );
        assert!(precompile_gas(0x00, &[]).is_none());
        assert!(precompile_gas(0x0b, &[]).is_none());

        // Blake2F: 213-byte input, rounds in first 4 bytes
        let mut blake_in = [0u8; 213];
        blake_in[0..4].copy_from_slice(&12u32.to_be_bytes());
        assert_eq!(precompile_gas(PRECOMPILE_BLAKE2F, &blake_in), Some(12));
    }

    #[test]
    fn gas_meter_charge_precompile() {
        let mut meter = GasMeter::new(10_000);
        let used = meter
            .charge_precompile(PRECOMPILE_SHA256, &[0u8; 32])
            .unwrap();
        assert_eq!(used, SHA256_BASE_GAS + SHA256_PER_WORD_GAS);
        assert_eq!(meter.gas_used, used);
    }

    #[test]
    fn refund_cap_eip_3529() {
        let mut meter = GasMeter::new(10_000);
        meter.consume(1_000).unwrap();
        meter.record_refund(10_000); // huge refund
        let applied = meter.apply_refunds();
        assert_eq!(applied, 200); // 1000/5
        assert_eq!(meter.gas_used, 800);
        assert_eq!(meter.gas_refund, 0);
    }

    #[test]
    fn effective_gas_used_is_non_mutating() {
        let mut meter = GasMeter::new(10_000);
        meter.consume(500).unwrap();
        meter.record_refund(100);
        assert_eq!(meter.effective_gas_used(), 400); // min(100, 500/5=100)
        assert_eq!(meter.gas_used, 500); // unchanged
        assert_eq!(meter.gas_refund, 100);
    }

    #[test]
    fn account_access_cold_warm() {
        let mut meter = GasMeter::new(10_000);
        let acct = [0x42u8; 20];
        let c = meter.charge_account_access(acct).unwrap();
        assert_eq!(c, COLD_ACCOUNT_ACCESS_COST);
        let w = meter.charge_account_access(acct).unwrap();
        assert_eq!(w, WARM_ACCOUNT_ACCESS_COST);
    }

    #[test]
    fn modexp_has_minimum_gas() {
        // Empty / tiny input still pays MODEXP_MIN_GAS
        assert_eq!(modexp_gas(&[]), MODEXP_MIN_GAS);
        assert!(modexp_gas(&[0u8; 96]) >= MODEXP_MIN_GAS);
    }

    #[test]
    fn modexp_known_answer_vectors() {
        fn modexp_input(bsize: u64, esize: u64, msize: u64, body: &[u8]) -> Vec<u8> {
            let mut input = vec![0u8; 96];
            input[24..32].copy_from_slice(&bsize.to_be_bytes());
            input[56..64].copy_from_slice(&esize.to_be_bytes());
            input[88..96].copy_from_slice(&msize.to_be_bytes());
            input.extend_from_slice(body);
            input
        }

        // exponent = 0 → adjusted_exp = 0 → min gas
        let input = modexp_input(1, 0, 1, &[0xFF, 0x01]);
        assert_eq!(modexp_gas(&input), MODEXP_MIN_GAS);

        // 256-byte modulus, 32-byte exp with MSB set
        // words=8, mult=64, bit_length=256, adjusted=255, gas=64*255/3=5440
        let mut body = vec![0u8; 256];
        body.extend_from_slice(&[0x80; 32]);
        body.extend_from_slice(&[0u8; 256]);
        let input = modexp_input(256, 32, 256, &body);
        assert_eq!(modexp_gas(&input), 5440);

        // esize > 32 with first 32 bytes of exponent all zero:
        // bit_length = 0, adjusted = 8*(33-32) + 0 = 8, gas = 64*8/3 = 170 → 200
        let mut body = vec![0u8; 256]; // base
        body.extend_from_slice(&[0u8; 32]); // first 32 bytes of exp (all zero)
        body.push(0xFF); // byte 33 of exponent
        body.extend_from_slice(&[0u8; 256]); // modulus
        let input = modexp_input(256, 33, 256, &body);
        assert_eq!(modexp_gas(&input), MODEXP_MIN_GAS); // 170 < 200

        // esize > 32 with large esize to exceed min gas:
        // esize=64, first 32 bytes zero, adjusted = 8*32 = 256, gas = 64*256/3 = 5461
        let mut body = vec![0u8; 256]; // base
        body.extend_from_slice(&[0u8; 32]); // first 32 bytes of exp (all zero)
        body.extend_from_slice(&[0u8; 32]); // remaining 32 bytes of exp
        body.extend_from_slice(&[0u8; 256]); // modulus
        let input = modexp_input(256, 64, 256, &body);
        assert_eq!(modexp_gas(&input), 5461);

        // all-zero exponent → min gas
        let mut body = vec![0u8; 256];
        body.extend_from_slice(&[0u8; 32]);
        body.extend_from_slice(&[0u8; 256]);
        let input = modexp_input(256, 32, 256, &body);
        assert_eq!(modexp_gas(&input), MODEXP_MIN_GAS);
    }

    #[test]
    fn modexp_gas_overflow_upper_bytes() {
        // If high 24 bytes of bsize are non-zero, modexp_gas returns u64::MAX
        let mut input = vec![0u8; 96];
        input[0] = 0x01; // non-zero in upper 24 bytes
        assert_eq!(modexp_gas(&input), u64::MAX);

        // If high 24 bytes of esize are non-zero
        let mut input2 = vec![0u8; 96];
        input2[32] = 0x80;
        assert_eq!(modexp_gas(&input2), u64::MAX);

        // If high 24 bytes of msize are non-zero
        let mut input3 = vec![0u8; 96];
        input3[64] = 0xFF;
        assert_eq!(modexp_gas(&input3), u64::MAX);
    }
}
