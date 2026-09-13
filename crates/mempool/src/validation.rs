use crate::error::MempoolError;
use anyhow::Result;
use lru::LruCache;
use parking_lot::Mutex;
use primitive_types::U256;
use rayon::prelude::*;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::num::NonZeroUsize;
use std::sync::Arc;
use sxiaum_state::StateDb;
use sxiaum_types::{Account, Hash, Transaction, SXIAUM_CHAIN_ID};
use tracing::warn;

/// Maximum transaction size in bytes; canonical definition lives in the
/// crate root ([`crate::MAX_TX_SIZE`]) and is re-exported here for callers
/// that import from this module.
pub use crate::MAX_TX_SIZE;

/// Default number of entries in the seen-transactions LRU cache.
/// At 32 bytes per hash, 1M entries costs ~32 MB - acceptable for a long-running node.
/// Set `SXIAUM_MEMPOOL_SEEN_TX_CACHE_SIZE` to override.
pub const DEFAULT_SEEN_TX_CACHE_SIZE: usize = 1_000_000;

#[derive(Clone, Debug)]
pub struct TxValidationConfig {
    pub min_gas_price: U256,
    pub max_gas_limit: u64,
    pub max_transaction_size: usize,
    pub max_future_nonce_gap: u64,
    /// The expected chain_id for this network. Transactions with a different or absent
    /// chain_id field will be rejected under EIP-155 replay protection rules.
    pub chain_id: u64,
    /// Maximum number of entries in the seen-transactions LRU cache.
    /// Once full, the oldest entry is evicted so memory stays bounded.
    pub max_seen_tx_cache: usize,
    seen_transactions: Arc<Mutex<LruCache<Hash, ()>>>,
}

impl Default for TxValidationConfig {
    fn default() -> Self {
        let raw_env = std::env::var("SXIAUM_MEMPOOL_SEEN_TX_CACHE_SIZE").ok();
        let cache_size = match raw_env {
            Some(ref s) => match s.parse::<usize>() {
                Ok(0) => {
                    warn!(
                        "Configured SXIAUM_MEMPOOL_SEEN_TX_CACHE_SIZE=0 is invalid; falling back to default {}",
                        DEFAULT_SEEN_TX_CACHE_SIZE
                    );
                    DEFAULT_SEEN_TX_CACHE_SIZE
                }
                Ok(v) => v,
                Err(_) => {
                    warn!(
                        "Configured SXIAUM_MEMPOOL_SEEN_TX_CACHE_SIZE='{}' is not a valid integer; falling back to default {}",
                        s, DEFAULT_SEEN_TX_CACHE_SIZE
                    );
                    DEFAULT_SEEN_TX_CACHE_SIZE
                }
            },
            None => DEFAULT_SEEN_TX_CACHE_SIZE,
        };
        let non_zero_cache = NonZeroUsize::new(cache_size).unwrap_or_else(|| {
            NonZeroUsize::new(DEFAULT_SEEN_TX_CACHE_SIZE).unwrap_or(NonZeroUsize::MIN)
        });
        Self {
            min_gas_price: U256::from(1u64),
            max_gas_limit: sxiaum_block::MAX_BLOCK_GAS_LIMIT,
            max_transaction_size: MAX_TX_SIZE,
            max_future_nonce_gap: 1024,
            chain_id: SXIAUM_CHAIN_ID,
            max_seen_tx_cache: non_zero_cache.get(),
            seen_transactions: Arc::new(Mutex::new(LruCache::new(non_zero_cache))),
        }
    }
}

/// Validates transactions before they enter the mempool.
pub struct TxValidator {
    pub(crate) state: Arc<StateDb>,
    pub(crate) config: TxValidationConfig,
    /// Dedicated rayon pool for parallel signature / batch validation.
    rayon_pool: Arc<ThreadPool>,
}

impl TxValidator {
    pub fn try_new(state: Arc<StateDb>, config: TxValidationConfig) -> Result<Self> {
        let rayon_pool = ThreadPoolBuilder::new()
            .thread_name(|i| format!("mempool-validator-{}", i))
            .build()
            .map_err(|e| {
                anyhow::anyhow!("failed to build mempool validation rayon pool: {:?}", e)
            })?;
        Ok(Self {
            state,
            config,
            rayon_pool: Arc::new(rayon_pool),
        })
    }

    pub fn new(state: Arc<StateDb>, config: TxValidationConfig) -> Self {
        let rayon_pool = ThreadPoolBuilder::new()
            .thread_name(|i| format!("mempool-validator-{}", i))
            .build()
            .or_else(|_| ThreadPoolBuilder::new().num_threads(1).build())
            .expect("fallback thread pool allocation must succeed");
        Self {
            state,
            config,
            rayon_pool: Arc::new(rayon_pool),
        }
    }

    pub fn state(&self) -> &Arc<StateDb> {
        &self.state
    }

    /// Full validation: structural checks + duplicate detection.
    /// Use this when a transaction first arrives at the mempool.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        self.verify_chain_id(tx)?;
        self.reject_malformed_transactions(tx)?;
        self.verify_transaction_signature(tx)?;
        self.verify_sender_address(tx)?;
        self.verify_nonce_correctness(tx)?;
        self.verify_sufficient_balance(tx)?;
        self.verify_gas_limit(tx)?;
        self.verify_gas_price_threshold(tx)?;
        self.verify_transaction_size(tx)?;
        self.reject_duplicate_transactions(tx)?;
        Ok(())
    }

    /// Subset of checks safe to repeat at block-selection time
    /// (skips duplicate detection so the same tx can be re-evaluated).
    pub fn validate_transaction_for_selection(&self, tx: &Transaction) -> Result<()> {
        self.verify_chain_id(tx)?;
        self.reject_malformed_transactions(tx)?;
        self.verify_transaction_signature(tx)?;
        self.verify_sender_address(tx)?;
        self.verify_nonce_correctness(tx)?;
        self.verify_sufficient_balance(tx)?;
        self.verify_gas_limit(tx)?;
        self.verify_gas_price_threshold(tx)?;
        self.verify_transaction_size(tx)?;
        Ok(())
    }

    /// Reject transactions whose chain_id does not match this network's chain_id.
    /// Prevents replay of transactions from other chains.
    fn verify_chain_id(&self, tx: &Transaction) -> Result<()> {
        match tx.chain_id {
            None => Err(MempoolError::MissingChainId.into()),
            Some(id) if id != self.config.chain_id => Err(MempoolError::ChainIdMismatch {
                expected: self.config.chain_id,
                actual: id,
            }
            .into()),
            _ => Ok(()),
        }
    }

    /// Alias used by Mempool.
    pub fn validate(&self, tx: &Transaction) -> Result<()> {
        self.validate_transaction(tx)
    }

    /// Mark a transaction hash as seen in the bounded cache upon successful insertion.
    pub fn mark_seen(&self, hash: &Hash) {
        let mut seen = self.config.seen_transactions.lock();
        seen.put(*hash, ());
    }

    /// Unmark a transaction hash from the seen cache (e.g. if removed or evicted).
    pub fn unmark_seen(&self, hash: &Hash) {
        let mut seen = self.config.seen_transactions.lock();
        seen.pop(hash);
    }

    /// Return true if the transaction hash is in the seen cache.
    pub fn is_seen(&self, hash: &Hash) -> bool {
        let seen = self.config.seen_transactions.lock();
        seen.contains(hash)
    }

    /// Verify the signatures of a batch of transactions in parallel using the
    /// rayon thread pool. Returns one `Result<()>` per input transaction.
    pub fn parallel_signature_verification(&self, txs: &[Transaction]) -> Vec<Result<()>> {
        self.rayon_pool.install(|| {
            txs.par_iter()
                .map(|tx| self.verify_transaction_signature(tx))
                .collect()
        })
    }

    /// Validate a batch of transactions with two phases:
    /// 1. Parallelisable pre-checks (chain ID, signature, address, gas, size) via rayon.
    /// 2. Sequential state-dependent checks (nonce, balance, TTL, duplicates).
    ///
    /// Returns one `Result<()>` per input transaction.
    pub fn batch_transaction_validation(&self, txs: &[Transaction]) -> Vec<Result<()>> {
        // Phase 1: parallel structural pre-checks.
        let precheck: Vec<Result<()>> = self.rayon_pool.install(|| {
            txs.par_iter()
                .map(|tx| {
                    self.verify_chain_id(tx)?;
                    self.reject_malformed_transactions(tx)?;
                    self.verify_transaction_signature(tx)?;
                    self.verify_sender_address(tx)?;
                    self.verify_gas_limit(tx)?;
                    self.verify_gas_price_threshold(tx)?;
                    self.verify_transaction_size(tx)?;
                    Ok(())
                })
                .collect()
        });

        // Phase 2: sequential state-dependent checks.
        txs.iter()
            .zip(precheck)
            .map(|(tx, pre)| {
                pre?;
                self.verify_nonce_correctness(tx)?;
                self.verify_sufficient_balance(tx)?;
                self.reject_duplicate_transactions(tx)?;
                Ok(())
            })
            .collect()
    }

    // Individual checks

    /// Verify the ECDSA/BLS signature matches the declared sender.
    fn verify_transaction_signature(&self, tx: &Transaction) -> Result<()> {
        if !tx.verify_signature()? {
            return Err(MempoolError::InvalidSignature.into());
        }
        Ok(())
    }

    /// Reject transactions whose `from` field is the zero address.
    fn verify_sender_address(&self, tx: &Transaction) -> Result<()> {
        if tx.from.is_zero() {
            return Err(MempoolError::ZeroSenderAddress.into());
        }
        Ok(())
    }

    /// Reject nonces that are already used (too low) or unreachably far ahead.
    fn verify_nonce_correctness(&self, tx: &Transaction) -> Result<()> {
        let account = self
            .state
            .get_account(&tx.from)
            .map_err(|e| MempoolError::StateDb(e.to_string()))?
            .unwrap_or_else(|| Account::new(tx.from));
        if tx.nonce < account.nonce {
            return Err(MempoolError::InvalidNonce {
                expected: account.nonce,
                actual: tx.nonce,
            }
            .into());
        }
        let max_nonce = account
            .nonce
            .saturating_add(self.config.max_future_nonce_gap);
        if tx.nonce > max_nonce {
            return Err(MempoolError::NonceGapExceeded {
                actual: tx.nonce,
                max: max_nonce,
            }
            .into());
        }
        Ok(())
    }

    /// Reject if the sender cannot cover `value + gas_price * gas_limit` or has insufficient spendable funds due to vesting lockup.
    fn verify_sufficient_balance(&self, tx: &Transaction) -> Result<()> {
        let (total_cost, overflowed) = tx.value.overflowing_add(tx.gas_cost());
        if overflowed {
            return Err(MempoolError::TotalCostOverflow.into());
        }
        let account = self
            .state
            .get_account(&tx.from)
            .map_err(|e| MempoolError::StateDb(e.to_string()))?
            .unwrap_or_else(|| Account::new(tx.from));
        let mut spendable = account.balance;
        if let Some(schedule) = self
            .state
            .get_vesting_schedule(&tx.from)
            .map_err(|e| MempoolError::StateDb(e.to_string()))?
        {
            let now = unix_timestamp();
            let locked = schedule.locked_amount(now);
            spendable = spendable.saturating_sub(locked);
        }
        if spendable < total_cost {
            return Err(MempoolError::InsufficientBalance.into());
        }
        Ok(())
    }

    /// Reject zero gas limits, limits below intrinsic gas, and limits above the configured maximum.
    fn verify_gas_limit(&self, tx: &Transaction) -> Result<()> {
        if tx.gas_limit == 0 {
            return Err(MempoolError::ZeroGasLimit.into());
        }
        let intrinsic =
            sxiaum_execution::calculate_intrinsic_gas_ex(&tx.data, tx.is_contract_creation());
        if tx.gas_limit < intrinsic {
            return Err(MempoolError::GasLimitBelowIntrinsic {
                gas_limit: tx.gas_limit,
                intrinsic,
            }
            .into());
        }
        if tx.gas_limit > self.config.max_gas_limit {
            return Err(MempoolError::GasLimitExceedsMax {
                gas_limit: tx.gas_limit,
                max: self.config.max_gas_limit,
            }
            .into());
        }
        Ok(())
    }

    /// Reject transactions whose gas price is below the configured floor.
    fn verify_gas_price_threshold(&self, tx: &Transaction) -> Result<()> {
        if tx.gas_price < self.config.min_gas_price {
            return Err(MempoolError::GasPriceBelowMinimum.into());
        }
        Ok(())
    }

    /// Reject transactions whose serialised size exceeds the configured limit.
    fn verify_transaction_size(&self, tx: &Transaction) -> Result<()> {
        let size = tx.size_bytes()?;
        if size > self.config.max_transaction_size {
            return Err(MempoolError::TransactionTooLarge {
                size,
                max: self.config.max_transaction_size,
            }
            .into());
        }
        Ok(())
    }

    /// Reject a transaction whose hash was already accepted in this session.
    /// Non-mutating: does not insert into cache so that rejected submissions can be retried.
    fn reject_duplicate_transactions(&self, tx: &Transaction) -> Result<()> {
        let hash = tx.try_hash()?;
        let seen = self.config.seen_transactions.lock();
        if seen.contains(&hash) {
            return Err(MempoolError::DuplicateTransaction(hex::encode(hash)).into());
        }
        Ok(())
    }

    /// Reject transactions that fail basic structural invariants:
    /// - must pass `Transaction::validate_basic`
    /// - must carry a signature
    /// - contract-creation transactions must include init code
    fn reject_malformed_transactions(&self, tx: &Transaction) -> Result<()> {
        tx.validate_basic()?;
        if tx.signature.is_none() {
            return Err(MempoolError::UnsignedTransaction.into());
        }
        if tx.to.is_none() && tx.data.is_empty() {
            return Err(MempoolError::EmptyContractCreation.into());
        }
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub type TransactionValidator = TxValidator;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use sxiaum_state::StateDb;
    use sxiaum_storage::MemoryDatabaseBackend;
    use sxiaum_types::{Account, Address, SXIAUM_CHAIN_ID};

    fn setup_test_validator() -> (TxValidator, Arc<StateDb>, Address, SigningKey) {
        let backend = Arc::new(MemoryDatabaseBackend::new());
        let state = Arc::new(StateDb::new(backend));
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let pubkey = signing_key.verifying_key().to_bytes();
        let sender = Address::from_public_key(&pubkey);

        let mut acc = Account::new(sender);
        acc.balance = U256::from(10_000_000_000_000_000_000u128); // 10 SXI
        acc.nonce = 5;
        state.update_account(&sender, &acc).unwrap();

        let validator = TxValidator::new(state.clone(), TxValidationConfig::default());
        (validator, state, sender, signing_key)
    }

    #[test]
    fn test_valid_transaction_passes() {
        let (validator, _, sender, sk) = setup_test_validator();
        let recipient = Address([2u8; 32]);
        let mut tx = Transaction::new_transfer(sender, recipient, U256::from(1_000), 5);
        tx.chain_id = Some(SXIAUM_CHAIN_ID);
        tx.gas_limit = 21_000;
        tx.gas_price = U256::from(10);
        tx.sign(&sk).unwrap();

        assert!(validator.validate(&tx).is_ok());
    }

    #[test]
    fn test_rejects_missing_or_mismatched_chain_id() {
        let (validator, _, sender, sk) = setup_test_validator();
        let recipient = Address([2u8; 32]);

        // Missing chain_id
        let mut tx1 = Transaction::new_transfer(sender, recipient, U256::from(100), 5);
        tx1.chain_id = None;
        tx1.sign(&sk).unwrap();
        assert!(validator.validate(&tx1).is_err());

        // Mismatched chain_id
        let mut tx2 = Transaction::new_transfer(sender, recipient, U256::from(100), 5);
        tx2.chain_id = Some(99999);
        tx2.sign(&sk).unwrap();
        assert!(validator.validate(&tx2).is_err());
    }

    #[test]
    fn test_rejects_stale_or_excessive_nonce() {
        let (validator, _, sender, sk) = setup_test_validator();
        let recipient = Address([2u8; 32]);

        // Stale nonce (< 5)
        let mut tx_stale = Transaction::new_transfer(sender, recipient, U256::from(100), 4);
        tx_stale.chain_id = Some(SXIAUM_CHAIN_ID);
        tx_stale.sign(&sk).unwrap();
        assert!(validator.validate(&tx_stale).is_err());

        // Excessive nonce gap (> 5 + 1024)
        let mut tx_gap = Transaction::new_transfer(sender, recipient, U256::from(100), 5 + 1025);
        tx_gap.chain_id = Some(SXIAUM_CHAIN_ID);
        tx_gap.sign(&sk).unwrap();
        assert!(validator.validate(&tx_gap).is_err());
    }

    #[test]
    fn test_rejects_insufficient_balance() {
        let (validator, state, sender, sk) = setup_test_validator();
        let recipient = Address([2u8; 32]);

        // Reduce balance to 100
        let mut acc = state.get_account(&sender).unwrap().unwrap();
        acc.balance = U256::from(100);
        state.update_account(&sender, &acc).unwrap();

        let mut tx = Transaction::new_transfer(sender, recipient, U256::from(1000), 5);
        tx.chain_id = Some(SXIAUM_CHAIN_ID);
        tx.sign(&sk).unwrap();
        assert!(validator.validate(&tx).is_err());
    }

    #[test]
    fn test_rejects_duplicate_transactions() {
        let (validator, _, sender, sk) = setup_test_validator();
        let recipient = Address([2u8; 32]);

        let mut tx = Transaction::new_transfer(sender, recipient, U256::from(100), 5);
        tx.chain_id = Some(SXIAUM_CHAIN_ID);
        tx.sign(&sk).unwrap();

        assert!(validator.validate(&tx).is_ok());
        let hash = tx.try_hash().unwrap();
        validator.mark_seen(&hash);
        assert!(
            validator.validate(&tx).is_err(),
            "Duplicate tx must be rejected after being marked seen"
        );
        validator.unmark_seen(&hash);
        assert!(
            validator.validate(&tx).is_ok(),
            "Tx must be valid again after unmark_seen"
        );
    }

    #[test]
    fn test_batch_and_parallel_validation() {
        let (validator, _, sender, sk) = setup_test_validator();
        let recipient = Address([2u8; 32]);

        let mut tx1 = Transaction::new_transfer(sender, recipient, U256::from(10), 5);
        tx1.chain_id = Some(SXIAUM_CHAIN_ID);
        tx1.sign(&sk).unwrap();

        let mut tx2 = Transaction::new_transfer(sender, recipient, U256::from(20), 6);
        tx2.chain_id = Some(SXIAUM_CHAIN_ID);
        tx2.sign(&sk).unwrap();

        let batch = vec![tx1, tx2];
        let sig_results = validator.parallel_signature_verification(&batch);
        assert_eq!(sig_results.len(), 2);
        assert!(sig_results[0].is_ok());
        assert!(sig_results[1].is_ok());

        let batch_results = validator.batch_transaction_validation(&batch);
        assert_eq!(batch_results.len(), 2);
        assert!(batch_results[0].is_ok());
        assert!(batch_results[1].is_ok());
    }
}
