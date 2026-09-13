use crate::{Address, Canonical};
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use primitive_types::U256;
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
pub const SXIAUM_CHAIN_ID: u64 = 13_689;
pub const SXIAUM_CHAIN_ID_HEX: &str = "0x3579";
pub const SXIAUM_CHAIN_ID_STR: &str = "13689";
pub const SECP256K1_N_DIV_2: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];
pub const MAX_TX_DATA_SIZE: usize = 131072;
pub const MAX_TX_GAS_LIMIT: u64 = 30_000_000;
pub const MAX_LOG_TOPICS: usize = 4;
pub const MAX_LOG_DATA_SIZE: usize = 131072;
pub const MAX_RECEIPT_LOGS: usize = 256;
use crate::serialization::serde_sig;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub from: Address,
    pub to: Option<Address>,
    #[serde(default)]
    pub signer_pubkey: Option<[u8; 32]>,
    pub value: U256,
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: U256,
    pub data: Vec<u8>,
    #[serde(with = "serde_sig")]
    pub signature: Option<[u8; 64]>,
    #[serde(default)]
    pub chain_id: Option<u64>,
    #[serde(default)]
    pub ethereum_y_parity: Option<u8>,
    #[serde(default)]
    pub ethereum_sighash: Option<[u8; 32]>,
    #[serde(default)]
    pub ethereum_tx_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub ethereum_raw: Option<Vec<u8>>,
}
impl Transaction {
    pub fn new_transfer(from: Address, to: Address, value: U256, nonce: u64) -> Self {
        Self {
            from,
            to: Some(to),
            signer_pubkey: None,
            value,
            nonce,
            gas_limit: 210,
            gas_price: U256::from(1),
            data: Vec::new(),
            signature: None,
            chain_id: Some(SXIAUM_CHAIN_ID),
            ethereum_y_parity: None,
            ethereum_sighash: None,
            ethereum_tx_hash: None,
            ethereum_raw: None,
        }
    }
    pub fn new_contract_call(
        from: Address,
        to: Address,
        value: U256,
        nonce: u64,
        data: Vec<u8>,
    ) -> Self {
        Self {
            from,
            to: Some(to),
            signer_pubkey: None,
            value,
            nonce,
            gas_limit: 1000,
            gas_price: U256::from(1),
            data,
            signature: None,
            chain_id: Some(SXIAUM_CHAIN_ID),
            ethereum_y_parity: None,
            ethereum_sighash: None,
            ethereum_tx_hash: None,
            ethereum_raw: None,
        }
    }
    pub fn new_contract_deploy(from: Address, value: U256, nonce: u64, code: Vec<u8>) -> Self {
        Self {
            from,
            to: None,
            signer_pubkey: None,
            value,
            nonce,
            gas_limit: 10000,
            gas_price: U256::from(1),
            data: code,
            signature: None,
            chain_id: Some(SXIAUM_CHAIN_ID),
            ethereum_y_parity: None,
            ethereum_sighash: None,
            ethereum_tx_hash: None,
            ethereum_raw: None,
        }
    }
    #[cfg(test)]
    pub fn hash(&self) -> [u8; 32] {
        self.try_hash()
            .expect("transaction serialization for hashing must succeed")
    }
    pub fn try_hash(&self) -> Result<[u8; 32]> {
        if self.is_ethereum_transaction() {
            return Ok(self.verified_ethereum_envelope()?.tx_hash);
        }
        let mut hasher = Sha256::new();
        let mut temp = self.clone();
        temp.signature = None;
        let bytes = temp.try_encode()?;
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Ok(out)
    }
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<()> {
        let public_key = signing_key.verifying_key().to_bytes();
        let derived_sender = Address::from_public_key(&public_key);
        if derived_sender != self.from {
            bail!(
                "signing key does not match transaction sender: expected {}, derived {}",
                self.from,
                derived_sender
            );
        }
        self.signer_pubkey = Some(public_key);
        let hash = self.try_hash()?;
        let sig = signing_key.sign(&hash);
        self.signature = Some(sig.to_bytes());
        Ok(())
    }
    pub fn verify_signature(&self) -> Result<bool> {
        if self.is_ethereum_transaction() {
            return self.verify_ethereum_signature();
        }
        let sig_bytes = self
            .signature
            .ok_or_else(|| anyhow::anyhow!("No signature present"))?;
        let public_key_bytes = self
            .signer_pubkey
            .ok_or_else(|| anyhow::anyhow!("No signer public key present"))?;
        if Address::from_public_key(&public_key_bytes) != self.from {
            bail!("signer public key does not match transaction sender address");
        }
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;
        let sig = Signature::from_bytes(&sig_bytes);
        let hash = self.try_hash()?;
        public_key
            .verify_strict(&hash, &sig)
            .map(|_| true)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {:?}", e))
    }
    pub fn sender(&self) -> Result<Address> {
        if self.is_ethereum_transaction() {
            return self.recover_ethereum_sender();
        }
        let public_key_bytes = self
            .signer_pubkey
            .ok_or_else(|| anyhow::anyhow!("No signer public key present"))?;
        let derived = Address::from_public_key(&public_key_bytes);
        if derived != self.from {
            bail!("signer public key does not match transaction sender address");
        }
        Ok(derived)
    }
    pub fn validate_signature(&self) -> Result<()> {
        if !self.verify_signature()? {
            bail!("Transaction signature is invalid");
        }
        Ok(())
    }
    #[must_use]
    pub fn gas_cost(&self) -> U256 {
        self.gas_price.saturating_mul(U256::from(self.gas_limit))
    }
    pub fn intrinsic_gas(&self) -> u64 {
        if self.is_ethereum_transaction() {
            let mut gas = if self.is_contract_creation() {
                let initcode_words = (self.data.len() as u64).div_ceil(32);
                53_000u64.saturating_add(initcode_words.saturating_mul(2))
            } else {
                21_000u64
            };
            for &byte in &self.data {
                if byte == 0 {
                    gas = gas.saturating_add(4);
                } else {
                    gas = gas.saturating_add(16);
                }
            }
            gas
        } else {
            let mut gas = if self.is_contract_creation() {
                530u64
            } else {
                210u64
            };
            for &byte in &self.data {
                if byte == 0 {
                    gas = gas.saturating_add(4);
                } else {
                    gas = gas.saturating_add(1);
                }
            }
            gas
        }
    }
    #[inline]
    pub fn effective_gas_price(&self, _base_fee: U256) -> U256 {
        self.gas_price
    }
    pub fn size_bytes(&self) -> Result<usize> {
        self.try_encode().map(|b| b.len())
    }
    #[must_use]
    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }
    #[must_use]
    pub fn is_contract_call(&self) -> bool {
        self.to.is_some() && !self.data.is_empty()
    }
    pub fn validate_gas_limit(&self) -> Result<()> {
        if self.gas_limit == 0 {
            bail!("Gas limit must be greater than zero");
        }
        if self.gas_limit > MAX_TX_GAS_LIMIT {
            bail!("Gas limit exceeds maximum transaction gas limit");
        }
        let intrinsic = self.intrinsic_gas();
        if self.gas_limit < intrinsic {
            bail!("Gas limit below intrinsic gas");
        }
        Ok(())
    }
    pub fn validate_nonce(&self, expected_nonce: u64) -> Result<()> {
        if self.nonce != expected_nonce {
            bail!(
                "Invalid transaction nonce. Expected {}, got {}",
                expected_nonce,
                self.nonce
            );
        }
        Ok(())
    }
    pub fn validate_basic(&self) -> Result<()> {
        self.validate_gas_limit()?;
        if self.gas_price.is_zero() {
            bail!("Gas price must be greater than zero");
        }
        if self.data.len() > MAX_TX_DATA_SIZE {
            bail!("Transaction data exceeds maximum size");
        }
        if self.is_contract_creation() && self.data.is_empty() {
            bail!("Contract creation must include deployment code");
        }
        if self.chain_id != Some(SXIAUM_CHAIN_ID) {
            bail!(
                "Invalid or missing chain_id. Expected {}, got {:?}",
                SXIAUM_CHAIN_ID,
                self.chain_id
            );
        }
        let has_partial_eth = self.ethereum_y_parity.is_some()
            || self.ethereum_sighash.is_some()
            || self.ethereum_tx_hash.is_some();
        let is_ethereum = self.ethereum_raw.is_some();
        if !is_ethereum && has_partial_eth {
            bail!("Partial Ethereum fields without raw envelope");
        }
        let is_native = self.signer_pubkey.is_some();
        if is_ethereum && is_native {
            bail!("Transaction cannot have both Ethereum and native signature fields");
        }
        if !is_ethereum {
            if self.signature.is_none() || self.signer_pubkey.is_none() {
                bail!("Native transaction must carry signature and signer_pubkey");
            }
        }
        if self.signature.is_some() && !is_ethereum && self.signer_pubkey.is_none() {
            bail!("Native signed transaction must include signer_pubkey");
        }
        if is_ethereum {
            let envelope = self.verified_ethereum_envelope()?;
            if envelope.chain_id != SXIAUM_CHAIN_ID {
                bail!("Ethereum transaction chain_id mismatch");
            }
        } else if let Some(pubkey) = self.signer_pubkey {
            let derived_sender = Address::from_public_key(&pubkey);
            if derived_sender != self.from {
                bail!(
                    "signer public key does not match transaction sender address: expected {}, derived {}",
                    self.from,
                    derived_sender
                );
            }
        }
        Ok(())
    }
    pub fn rlp_encode(&self) -> Vec<u8> {
        rlp::encode(self).to_vec()
    }
    pub fn rlp_decode(bytes: &[u8]) -> Result<Self> {
        rlp::decode(bytes).map_err(|error| anyhow::anyhow!("RLP decode failed: {:?}", error))
    }
    pub fn from_ethereum_raw(raw: &[u8]) -> Result<Self> {
        EthereumRawTransaction::decode(raw)?.into_transaction(raw.to_vec())
    }
    fn verify_ethereum_signature(&self) -> Result<bool> {
        Ok(self.verified_ethereum_envelope()?.recover_sender()? == self.from)
    }
    fn recover_ethereum_sender(&self) -> Result<Address> {
        self.verified_ethereum_envelope()?.recover_sender()
    }
    fn is_ethereum_transaction(&self) -> bool {
        self.ethereum_raw.is_some()
    }
    fn verified_ethereum_envelope(&self) -> Result<EthereumRawTransaction> {
        let raw = self.ethereum_raw.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Ethereum transaction is missing its signed raw envelope")
        })?;
        let envelope = EthereumRawTransaction::decode(raw)?;
        if envelope.chain_id != SXIAUM_CHAIN_ID {
            bail!("Ethereum transaction chain_id mismatch");
        }
        let recovered_sender = envelope.recover_sender()?;
        if self.from != recovered_sender
            || self.to != envelope.to
            || self.value != envelope.value
            || self.nonce != envelope.nonce
            || self.gas_limit != envelope.gas_limit
            || self.gas_price != envelope.gas_price
            || self.data != envelope.data
            || self.chain_id != Some(envelope.chain_id)
            || self.signature != Some(envelope.signature)
            || self.ethereum_y_parity != Some(envelope.y_parity)
            || self.ethereum_sighash != Some(envelope.sighash)
            || self.ethereum_tx_hash != Some(envelope.tx_hash)
            || self.signer_pubkey.is_some()
        {
            bail!("Ethereum transaction fields do not match the signed raw envelope");
        }
        Ok(envelope)
    }
    pub fn recover_ethereum_sender_from_parts(
        sig_bytes: [u8; 64],
        y_parity: u8,
        sighash: [u8; 32],
    ) -> Result<Address> {
        if y_parity > 1 {
            bail!(
                "invalid Ethereum recovery id yParity: expected 0 or 1, got {}",
                y_parity
            );
        }
        let s_bytes = &sig_bytes[32..64];
        if s_bytes > &SECP256K1_N_DIV_2[..] {
            bail!("malleable Ethereum signature: s value exceeds secp256k1 n2");
        }
        let recovery_id = RecoveryId::from_i32(i32::from(y_parity))
            .map_err(|e| anyhow::anyhow!("invalid Ethereum recovery id: {:?}", e))?;
        let signature = RecoverableSignature::from_compact(&sig_bytes, recovery_id)
            .map_err(|e| anyhow::anyhow!("invalid Ethereum signature: {:?}", e))?;
        let message = Message::from_slice(&sighash)
            .map_err(|e| anyhow::anyhow!("invalid Ethereum signing hash: {:?}", e))?;
        let secp = Secp256k1::new();
        let public_key = secp
            .recover_ecdsa(&message, &signature)
            .map_err(|e| anyhow::anyhow!("Ethereum sender recovery failed: {:?}", e))?;
        let uncompressed = public_key.serialize_uncompressed();
        let digest = Keccak256::digest(&uncompressed[1..]);
        let mut eth_addr = [0u8; 20];
        eth_addr.copy_from_slice(&digest[12..]);
        Ok(Address::from_ethereum_address(eth_addr))
    }
}
impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(11);
        s.append(&self.from.0.as_slice());
        match &self.to {
            Some(addr) => {
                s.append(&addr.0.as_slice());
            }
            None => {
                s.append_empty_data();
            }
        }
        match &self.signer_pubkey {
            Some(pubkey) => {
                s.append(&pubkey.as_slice());
            }
            None => {
                s.append_empty_data();
            }
        }
        let mut value_bytes = [0u8; 32];
        self.value.to_big_endian(&mut value_bytes);
        s.append(&value_bytes.as_slice());
        s.append(&self.nonce);
        s.append(&self.gas_limit);
        let mut price_bytes = [0u8; 32];
        self.gas_price.to_big_endian(&mut price_bytes);
        s.append(&price_bytes.as_slice());
        s.append(&self.data);
        match &self.signature {
            Some(sig) => {
                s.append(&sig.as_slice());
            }
            None => {
                s.append_empty_data();
            }
        }
        s.append(&self.chain_id.unwrap_or_default());
        match &self.ethereum_raw {
            Some(raw) => {
                s.append(raw);
            }
            None => {
                s.append_empty_data();
            }
        }
    }
}
impl Decodable for Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, rlp::DecoderError> {
        let count = rlp.item_count()?;
        if count < 10 || count > 11 {
            return Err(rlp::DecoderError::Custom("invalid transaction field count"));
        }
        Ok(Self {
            from: {
                let bytes: Vec<u8> = rlp.val_at(0)?;
                Address(
                    bytes
                        .try_into()
                        .map_err(|_| rlp::DecoderError::Custom("Invalid from address length"))?,
                )
            },
            to: {
                let bytes: Vec<u8> = rlp.val_at(1)?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(Address(bytes.try_into().map_err(|_| {
                        rlp::DecoderError::Custom("Invalid address length")
                    })?))
                }
            },
            signer_pubkey: {
                let bytes: Vec<u8> = rlp.val_at(2)?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(
                        bytes
                            .try_into()
                            .map_err(|_| rlp::DecoderError::Custom("Invalid public key length"))?,
                    )
                }
            },
            value: {
                let bytes: Vec<u8> = rlp.val_at(3)?;
                decode_u256_rlp(&bytes, "value")?
            },
            nonce: rlp.val_at(4)?,
            gas_limit: rlp.val_at(5)?,
            gas_price: {
                let bytes: Vec<u8> = rlp.val_at(6)?;
                decode_u256_rlp(&bytes, "gas_price")?
            },
            data: {
                let data: Vec<u8> = rlp.val_at(7)?;
                if data.len() > MAX_TX_DATA_SIZE {
                    return Err(rlp::DecoderError::Custom("transaction data too large"));
                }
                data
            },
            signature: {
                let bytes: Vec<u8> = rlp.val_at(8)?;
                if bytes.is_empty() {
                    None
                } else {
                    Some(
                        bytes
                            .try_into()
                            .map_err(|_| rlp::DecoderError::Custom("Invalid signature length"))?,
                    )
                }
            },
            chain_id: if count > 9 {
                let v: u64 = rlp.val_at(9)?;
                if v == 0 {
                    None
                } else {
                    Some(v)
                }
            } else {
                None
            },
            ethereum_y_parity: None,
            ethereum_sighash: None,
            ethereum_tx_hash: None,
            ethereum_raw: if count > 10 {
                let raw: Vec<u8> = rlp.val_at(10)?;
                if raw.is_empty() {
                    None
                } else {
                    if raw.len() > MAX_TX_DATA_SIZE + 8192 {
                        return Err(rlp::DecoderError::Custom("ethereum raw too large"));
                    }
                    Some(raw)
                }
            } else {
                None
            },
        })
    }
}
#[derive(Clone)]
struct EthereumRawTransaction {
    nonce: u64,
    gas_limit: u64,
    gas_price: U256,
    to: Option<Address>,
    value: U256,
    data: Vec<u8>,
    chain_id: u64,
    y_parity: u8,
    signature: [u8; 64],
    sighash: [u8; 32],
    tx_hash: [u8; 32],
}
impl EthereumRawTransaction {
    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() {
            bail!("empty raw Ethereum transaction");
        }
        if raw.len() > MAX_TX_DATA_SIZE + 8192 {
            bail!("raw Ethereum transaction too large");
        }
        let tx_hash = keccak256(raw);
        match raw[0] {
            0x01 => Self::decode_eip2930(&raw[1..], tx_hash),
            0x02 => Self::decode_eip1559(&raw[1..], tx_hash),
            v if v >= 0xc0 => Self::decode_legacy(raw, tx_hash),
            v => bail!("unsupported Ethereum transaction type {}", v),
        }
    }
    fn decode_legacy(raw: &[u8], tx_hash: [u8; 32]) -> Result<Self> {
        let rlp = Rlp::new(raw);
        if !rlp.is_list() || rlp.item_count()? != 9 {
            bail!("invalid legacy Ethereum transaction RLP");
        }
        let nonce = u256_to_u64(rlp_u256_at(&rlp, 0)?, "nonce")?;
        let gas_price = rlp_u256_at(&rlp, 1)?;
        let gas_limit = u256_to_u64(rlp_u256_at(&rlp, 2)?, "gas limit")?;
        let to = rlp_eth_address_at(&rlp, 3)?;
        let value = rlp_u256_at(&rlp, 4)?;
        let data: Vec<u8> = rlp.val_at(5)?;
        if data.len() > MAX_TX_DATA_SIZE {
            bail!("Ethereum transaction data too large");
        }
        let v = rlp_u256_at(&rlp, 6)?;
        let r = rlp_u256_at(&rlp, 7)?;
        let s = rlp_u256_at(&rlp, 8)?;
        let v_u64 = u256_to_u64(v, "v")?;
        let (chain_id, y_parity, sighash_payload) = if v_u64 == 27 || v_u64 == 28 {
            bail!("legacy Ethereum transaction without EIP-155 replay protection rejected");
        } else if v_u64 >= 35 {
            let chain_id = (v_u64 - 35) / 2;
            let y_parity = ((v_u64 - 35) % 2) as u8;
            (
                chain_id,
                y_parity,
                legacy_unsigned_payload(&rlp, Some(chain_id))?,
            )
        } else {
            bail!("unsupported legacy Ethereum v value: {}", v_u64);
        };
        if chain_id != SXIAUM_CHAIN_ID {
            bail!("Ethereum transaction chain_id mismatch");
        }
        Ok(Self {
            nonce,
            gas_limit,
            gas_price,
            to,
            value,
            data,
            chain_id,
            y_parity,
            signature: compact_signature(r, s),
            sighash: keccak256(&sighash_payload),
            tx_hash,
        })
    }
    fn decode_eip2930(raw_body: &[u8], tx_hash: [u8; 32]) -> Result<Self> {
        let rlp = Rlp::new(raw_body);
        if !rlp.is_list() || rlp.item_count()? != 11 {
            bail!("invalid EIP-2930 Ethereum transaction RLP");
        }
        let chain_id = u256_to_u64(rlp_u256_at(&rlp, 0)?, "chain id")?;
        if chain_id != SXIAUM_CHAIN_ID {
            bail!("Ethereum transaction chain_id mismatch");
        }
        let nonce = u256_to_u64(rlp_u256_at(&rlp, 1)?, "nonce")?;
        let gas_price = rlp_u256_at(&rlp, 2)?;
        let gas_limit = u256_to_u64(rlp_u256_at(&rlp, 3)?, "gas limit")?;
        let to = rlp_eth_address_at(&rlp, 4)?;
        let value = rlp_u256_at(&rlp, 5)?;
        let data: Vec<u8> = rlp.val_at(6)?;
        if data.len() > MAX_TX_DATA_SIZE {
            bail!("Ethereum transaction data too large");
        }
        let y_parity = u256_to_recovery_id(rlp_u256_at(&rlp, 8)?)?;
        let r = rlp_u256_at(&rlp, 9)?;
        let s = rlp_u256_at(&rlp, 10)?;
        let sighash = typed_sighash(0x01, &rlp, 8)?;
        Ok(Self {
            nonce,
            gas_limit,
            gas_price,
            to,
            value,
            data,
            chain_id,
            y_parity,
            signature: compact_signature(r, s),
            sighash,
            tx_hash,
        })
    }
    fn decode_eip1559(raw_body: &[u8], tx_hash: [u8; 32]) -> Result<Self> {
        let rlp = Rlp::new(raw_body);
        if !rlp.is_list() || rlp.item_count()? != 12 {
            bail!("invalid EIP-1559 Ethereum transaction RLP");
        }
        let chain_id = u256_to_u64(rlp_u256_at(&rlp, 0)?, "chain id")?;
        if chain_id != SXIAUM_CHAIN_ID {
            bail!("Ethereum transaction chain_id mismatch");
        }
        let nonce = u256_to_u64(rlp_u256_at(&rlp, 1)?, "nonce")?;
        let max_priority_fee = rlp_u256_at(&rlp, 2)?;
        let max_fee = rlp_u256_at(&rlp, 3)?;
        let gas_limit = u256_to_u64(rlp_u256_at(&rlp, 4)?, "gas limit")?;
        let to = rlp_eth_address_at(&rlp, 5)?;
        let value = rlp_u256_at(&rlp, 6)?;
        let data: Vec<u8> = rlp.val_at(7)?;
        if data.len() > MAX_TX_DATA_SIZE {
            bail!("Ethereum transaction data too large");
        }
        let y_parity = u256_to_recovery_id(rlp_u256_at(&rlp, 9)?)?;
        let r = rlp_u256_at(&rlp, 10)?;
        let s = rlp_u256_at(&rlp, 11)?;
        let sighash = typed_sighash(0x02, &rlp, 9)?;
        Ok(Self {
            nonce,
            gas_limit,
            gas_price: max_fee.max(max_priority_fee),
            to,
            value,
            data,
            chain_id,
            y_parity,
            signature: compact_signature(r, s),
            sighash,
            tx_hash,
        })
    }
    fn recover_sender(&self) -> Result<Address> {
        Transaction::recover_ethereum_sender_from_parts(self.signature, self.y_parity, self.sighash)
    }
    fn into_transaction(self, raw: Vec<u8>) -> Result<Transaction> {
        let sender = self.recover_sender()?;
        let tx = Transaction {
            from: sender,
            to: self.to,
            signer_pubkey: None,
            value: self.value,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            data: self.data,
            signature: Some(self.signature),
            chain_id: Some(self.chain_id),
            ethereum_y_parity: Some(self.y_parity),
            ethereum_sighash: Some(self.sighash),
            ethereum_tx_hash: Some(self.tx_hash),
            ethereum_raw: Some(raw),
        };
        tx.verified_ethereum_envelope()?;
        tx.validate_gas_limit()?;
        Ok(tx)
    }
}
fn rlp_u256_at(rlp: &Rlp<'_>, index: usize) -> Result<U256> {
    let bytes: Vec<u8> = rlp.val_at(index)?;
    if bytes.len() > 32 {
        bail!("Ethereum integer field {} exceeds 256 bits", index);
    }
    Ok(U256::from_big_endian(&bytes))
}
fn decode_u256_rlp(bytes: &[u8], _field: &str) -> Result<U256, rlp::DecoderError> {
    if bytes.len() > 32 {
        return Err(rlp::DecoderError::Custom("integer field exceeds 256 bits"));
    }
    Ok(U256::from_big_endian(bytes))
}
fn rlp_eth_address_at(rlp: &Rlp<'_>, index: usize) -> Result<Option<Address>> {
    let bytes: Vec<u8> = rlp.val_at(index)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 20 {
        bail!("Ethereum address field must be 20 bytes");
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(Some(Address::from_ethereum_address(addr)))
}
fn u256_to_u64(value: U256, label: &str) -> Result<u64> {
    if value > U256::from(u64::MAX) {
        bail!("Ethereum {} exceeds u64", label);
    }
    Ok(value.low_u64())
}
fn u256_to_recovery_id(value: U256) -> Result<u8> {
    let id = u256_to_u64(value, "yParity")?;
    if id > 1 {
        bail!("Ethereum yParity must be 0 or 1");
    }
    Ok(id as u8)
}
fn compact_signature(r: U256, s: U256) -> [u8; 64] {
    let mut out = [0u8; 64];
    r.to_big_endian(&mut out[..32]);
    s.to_big_endian(&mut out[32..]);
    out
}
fn legacy_unsigned_payload(rlp: &Rlp<'_>, chain_id: Option<u64>) -> Result<Vec<u8>> {
    let mut stream = RlpStream::new();
    if let Some(chain_id) = chain_id {
        stream.begin_list(9);
        for index in 0..6 {
            stream.append_raw(rlp.at(index)?.as_raw(), 1);
        }
        stream.append(&chain_id);
        stream.append(&0u8);
        stream.append(&0u8);
    } else {
        stream.begin_list(6);
        for index in 0..6 {
            stream.append_raw(rlp.at(index)?.as_raw(), 1);
        }
    }
    Ok(stream.out().to_vec())
}
fn typed_sighash(tx_type: u8, rlp: &Rlp<'_>, unsigned_fields: usize) -> Result<[u8; 32]> {
    let mut stream = RlpStream::new();
    stream.begin_list(unsigned_fields);
    for index in 0..unsigned_fields {
        stream.append_raw(rlp.at(index)?.as_raw(), 1);
    }
    let mut payload = Vec::with_capacity(1 + stream.as_raw().len());
    payload.push(tx_type);
    payload.extend_from_slice(stream.as_raw());
    Ok(keccak256(&payload))
}
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}
impl Log {
    pub fn new(address: Address, topics: Vec<[u8; 32]>, data: Vec<u8>) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.topics.len() > MAX_LOG_TOPICS {
            bail!("log topics exceed maximum");
        }
        if self.data.len() > MAX_LOG_DATA_SIZE {
            bail!("log data exceeds maximum");
        }
        Ok(())
    }
    pub fn topic_hash(&self) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        for topic in &self.topics {
            hasher.update(topic);
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
    pub fn bloom(&self) -> [u8; 256] {
        let mut bloom = [0u8; 256];
        let addr_bytes: &[u8] = if self.address.is_evm_compatible() {
            &self.address.0[12..]
        } else {
            &self.address.0[..]
        };
        add_to_bloom(&mut bloom, addr_bytes);
        for topic in &self.topics {
            add_to_bloom(&mut bloom, topic);
        }
        bloom
    }
    pub fn try_encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        <Self as Canonical>::try_encode(self)
    }
}
fn add_to_bloom(bloom: &mut [u8; 256], item: &[u8]) {
    let hash = keccak256(item);
    for i in 0..3 {
        let high = hash[2 * i] as usize;
        let low = hash[2 * i + 1] as usize;
        let bit_index = ((high & 0x07) << 8 | low) % 2048;
        let byte_pos = 255 - (bit_index / 8);
        let bit_pos = bit_index % 8;
        bloom[byte_pos] |= 1 << bit_pos;
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub tx_hash: [u8; 32],
    pub status: bool,
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub state_root: Option<[u8; 32]>,
    #[serde(default)]
    pub cumulative_gas_used: u64,
}
impl Receipt {
    pub fn new_success(tx_hash: [u8; 32], gas_used: u64, state_root: Option<[u8; 32]>) -> Self {
        Self {
            tx_hash,
            status: true,
            gas_used,
            logs: Vec::new(),
            state_root,
            cumulative_gas_used: gas_used,
        }
    }
    pub fn new_failure(tx_hash: [u8; 32], gas_used: u64) -> Self {
        Self {
            tx_hash,
            status: false,
            gas_used,
            logs: Vec::new(),
            state_root: None,
            cumulative_gas_used: gas_used,
        }
    }
    pub fn add_log(&mut self, entry: Log) -> Result<()> {
        entry.validate()?;
        if self.logs.len() >= MAX_RECEIPT_LOGS {
            bail!("receipt logs exceed maximum");
        }
        self.logs.push(entry);
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        if self.logs.len() > MAX_RECEIPT_LOGS {
            bail!("receipt logs exceed maximum");
        }
        for log in &self.logs {
            log.validate()?;
        }
        if !self.status && self.state_root.is_some() {
            bail!("failed receipt must not carry state root");
        }
        if self.cumulative_gas_used < self.gas_used {
            bail!("cumulative gas below tx gas");
        }
        Ok(())
    }
    pub fn bloom(&self) -> [u8; 256] {
        let mut composite = [0u8; 256];
        for log in &self.logs {
            let log_bloom = log.bloom();
            for i in 0..256 {
                composite[i] |= log_bloom[i];
            }
        }
        composite
    }
    pub fn try_hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        <Self as Canonical>::try_hash(self)
    }
    #[cfg(test)]
    pub fn hash(&self) -> [u8; 32] {
        self.try_hash().unwrap()
    }
    pub fn try_bincode_encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        <Self as Canonical>::try_encode(self)
    }
}
#[cfg(test)]
mod tests {
    use super::{keccak256, Transaction, MAX_TX_DATA_SIZE, SXIAUM_CHAIN_ID};
    use crate::{Address, Canonical};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use rlp::RlpStream;
    use secp256k1::{Message, Secp256k1, SecretKey};
    #[test]
    fn constructors_set_expected_defaults() {
        let from = Address([1u8; 32]);
        let to = Address([2u8; 32]);
        let transfer = Transaction::new_transfer(from, to, U256::from(5u64), 7);
        let call = Transaction::new_contract_call(from, to, U256::from(6u64), 8, vec![1, 2]);
        let deploy = Transaction::new_contract_deploy(from, U256::from(7u64), 9, vec![3, 4]);
        assert_eq!(transfer.to, Some(to));
        assert_eq!(transfer.signer_pubkey, None);
        assert_eq!(transfer.gas_limit, 210);
        assert!(call.is_contract_call());
        assert_eq!(call.gas_limit, 1_000);
        assert!(deploy.is_contract_creation());
        assert_eq!(deploy.gas_limit, 10_000);
    }
    #[test]
    fn signing_and_signature_validation_work() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let from = Address::from_public_key(&public_key);
        let to = Address([3u8; 32]);
        let mut tx = Transaction::new_transfer(from, to, U256::from(10u64), 1);
        tx.sign(&signing_key).expect("signing should succeed");
        assert_eq!(tx.signer_pubkey, Some(public_key));
        assert!(tx.verify_signature().expect("verification should succeed"));
        tx.validate_signature().expect("signature should validate");
        assert_eq!(tx.sender().expect("sender recovery should work"), from);
        tx.validate_basic().expect("signed basic must pass");
    }
    #[test]
    fn sender_recovery_requires_embedded_public_key() {
        let tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
        assert!(tx.sender().is_err());
        assert!(tx.verify_signature().is_err());
        assert!(tx.validate_basic().is_err());
    }
    #[test]
    fn signing_rejects_mismatched_sender_address() {
        let signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let mut tx = Transaction::new_transfer(
            Address([12u8; 32]),
            Address([13u8; 32]),
            U256::from(1u64),
            0,
        );
        assert!(tx.sign(&signing_key).is_err());
    }
    #[test]
    fn gas_cost_size_and_hash_are_deterministic() {
        let signing_key = SigningKey::from_bytes(&[21u8; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_contract_call(
            from,
            Address([5u8; 32]),
            U256::from(9u64),
            2,
            vec![9, 8, 7],
        );
        tx.gas_limit = 500;
        tx.sign(&signing_key).expect("sign");
        assert_eq!(tx.gas_cost(), U256::from(500u64));
        assert!(tx.size_bytes().unwrap() > 0);
        assert_eq!(tx.try_hash().unwrap(), tx.try_hash().unwrap());
        assert_eq!(tx.intrinsic_gas(), 210 + 3);
        tx.validate_basic().expect("basic must pass");
    }
    #[test]
    fn validation_helpers_reject_invalid_nonce_and_gas() {
        let signing_key = SigningKey::from_bytes(&[22u8; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx =
            Transaction::new_transfer(from, Address([7u8; 32]), U256::from(1u64), 3);
        tx.sign(&signing_key).expect("sign");
        assert!(tx.validate_nonce(2).is_err());
        tx.gas_limit = 0;
        assert!(tx.validate_gas_limit().is_err());
        assert!(tx.validate_basic().is_err());
    }
    #[test]
    fn validate_basic_rejects_invalid_contract_deploys() {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx =
            Transaction::new_contract_deploy(from, U256::from(1u64), 0, Vec::new());
        tx.sign(&signing_key).expect("sign");
        assert!(tx.validate_basic().is_err());
    }
    #[test]
    fn validate_basic_rejects_unsigned_and_oversized() {
        let tx =
            Transaction::new_transfer(Address([6u8; 32]), Address([7u8; 32]), U256::from(1u64), 3);
        assert!(tx.validate_basic().is_err());
        let signing_key = SigningKey::from_bytes(&[24u8; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut big = Transaction::new_contract_call(from, Address([7u8; 32]), U256::from(1u64), 0, vec![1u8; MAX_TX_DATA_SIZE + 1]);
        big.gas_limit = super::MAX_TX_GAS_LIMIT;
        big.sign(&signing_key).expect("sign");
        assert!(big.validate_basic().is_err());
        let mut low_gas = Transaction::new_contract_call(from, Address([7u8; 32]), U256::from(1u64), 0, vec![1u8; 100]);
        low_gas.gas_limit = 211;
        low_gas.sign(&signing_key).expect("sign");
        assert!(low_gas.validate_basic().is_err());
    }
    #[test]
    fn validate_basic_rejects_partial_ethereum_markers() {
        let signing_key = SigningKey::from_bytes(&[25u8; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(from, Address([8u8; 32]), U256::from(1u64), 0);
        tx.sign(&signing_key).expect("sign");
        tx.ethereum_y_parity = Some(1);
        tx.ethereum_sighash = Some([9u8; 32]);
        tx.ethereum_tx_hash = Some([10u8; 32]);
        assert!(tx.validate_basic().is_err());
        assert!(tx.try_hash().is_ok());
    }
    #[test]
    fn sender_rejects_spoofed_from() {
        let sk_a = SigningKey::from_bytes(&[26u8; 32]);
        let pk_a = sk_a.verifying_key().to_bytes();
        let from_a = Address::from_public_key(&pk_a);
        let mut tx = Transaction::new_transfer(from_a, Address([9u8; 32]), U256::from(1u64), 0);
        tx.sign(&sk_a).expect("sign");
        tx.from = Address([0xFFu8; 32]);
        assert!(tx.sender().is_err());
        assert!(tx.verify_signature().is_err());
        assert!(tx.validate_basic().is_err());
    }
    #[test]
    fn bincode_and_rlp_round_trip() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let from = Address::from_public_key(&public_key);
        let mut tx = Transaction::new_contract_call(
            from,
            Address([10u8; 32]),
            U256::from(15u64),
            5,
            vec![1, 2, 3, 4],
        );
        tx.sign(&signing_key).expect("signing should succeed");
        let encoded = tx.try_encode().expect("canonical encode should work");
        let decoded: Transaction =
            Transaction::decode(&encoded).expect("canonical decode should work");
        let rlp_round_trip =
            Transaction::rlp_decode(&tx.rlp_encode()).expect("rlp should round-trip");
        assert_eq!(decoded, tx);
        assert_eq!(rlp_round_trip.from, tx.from);
        assert_eq!(rlp_round_trip.to, tx.to);
        assert_eq!(rlp_round_trip.value, tx.value);
        assert_eq!(rlp_round_trip.nonce, tx.nonce);
        assert_eq!(rlp_round_trip.gas_limit, tx.gas_limit);
        assert_eq!(rlp_round_trip.data, tx.data);
        assert_eq!(rlp_round_trip.signature, tx.signature);
        assert_eq!(rlp_round_trip.chain_id, tx.chain_id);
    }
    #[test]
    fn rlp_decode_rejects_oversized_integers_without_panicking() {
        use rlp::RlpStream;
        let mut stream = RlpStream::new_list(10);
        stream.append(&vec![0u8; 32]);
        stream.append(&Vec::<u8>::new());
        stream.append(&vec![2u8; 32]);
        stream.append(&vec![0xffu8; 33]);
        stream.append(&0u64);
        stream.append(&21_000u64);
        stream.append(&vec![0x01u8; 33]);
        stream.append(&vec![1u8, 2, 3]);
        stream.append(&vec![0u8; 64]);
        stream.append(&SXIAUM_CHAIN_ID);
        let bytes = stream.out().to_vec();
        let result = Transaction::rlp_decode(&bytes);
        assert!(
            result.is_err(),
            "oversized RLP integer must be rejected, not panic"
        );
    }
    #[test]
    fn rlp_rejects_bad_field_count() {
        let mut stream = RlpStream::new_list(3);
        stream.append(&Vec::<u8>::new());
        stream.append(&Vec::<u8>::new());
        stream.append(&Vec::<u8>::new());
        let bytes = stream.out().to_vec();
        assert!(Transaction::rlp_decode(&bytes).is_err());
    }
    #[test]
    fn decodes_and_verifies_ethereum_legacy_raw_transaction() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[3u8; 32]).expect("valid secret key");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize_uncompressed();
        let sender_hash = keccak256(&public_key_bytes[1..]);
        let mut sender20 = [0u8; 20];
        sender20.copy_from_slice(&sender_hash[12..]);
        let to20 = [0x22u8; 20];
        let nonce = 7u64;
        let gas_price = 1_500_000_000u64;
        let gas_limit = 21_000u64;
        let value = 123u64;
        let data = Vec::<u8>::new();
        let mut signing = RlpStream::new_list(9);
        signing.append(&nonce);
        signing.append(&gas_price);
        signing.append(&gas_limit);
        signing.append(&to20.as_slice());
        signing.append(&value);
        signing.append(&data);
        signing.append(&SXIAUM_CHAIN_ID);
        signing.append(&0u8);
        signing.append(&0u8);
        let sighash = keccak256(signing.as_raw());
        let message = Message::from_slice(&sighash).expect("32-byte message");
        let sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (recovery_id, compact) = sig.serialize_compact();
        let v = SXIAUM_CHAIN_ID * 2 + 35 + recovery_id.to_i32() as u64;
        let r = U256::from_big_endian(&compact[..32]);
        let s = U256::from_big_endian(&compact[32..]);
        let mut signed = RlpStream::new_list(9);
        signed.append(&nonce);
        signed.append(&gas_price);
        signed.append(&gas_limit);
        signed.append(&to20.as_slice());
        signed.append(&value);
        signed.append(&data);
        signed.append(&v);
        signed.append(&u256_minimal_bytes(r).as_slice());
        signed.append(&u256_minimal_bytes(s).as_slice());
        let raw = signed.out().to_vec();
        let tx = Transaction::from_ethereum_raw(&raw).expect("raw tx should decode");
        assert_eq!(tx.from, Address::from_ethereum_address(sender20));
        assert_eq!(tx.to, Some(Address::from_ethereum_address(to20)));
        assert_eq!(tx.nonce, nonce);
        assert_eq!(tx.gas_limit, gas_limit);
        assert_eq!(tx.gas_price, U256::from(gas_price));
        assert_eq!(tx.value, U256::from(value));
        assert_eq!(tx.chain_id, Some(SXIAUM_CHAIN_ID));
        assert_eq!(tx.try_hash().unwrap(), keccak256(&raw));
        assert!(tx.verify_signature().expect("Ethereum signature verifies"));
        tx.validate_basic().expect("eth basic must pass");
        let mut forged = tx.clone();
        forged.to = Some(Address([0xabu8; 32]));
        forged.value = U256::from(999_999u64);
        assert!(forged.validate_basic().is_err());
        assert!(forged.verify_signature().is_err());
        assert!(forged.try_hash().is_err());
    }
    fn u256_minimal_bytes(value: U256) -> Vec<u8> {
        if value.is_zero() {
            return Vec::new();
        }
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        let first = bytes.iter().position(|b| *b != 0).unwrap_or(31);
        bytes[first..].to_vec()
    }
    #[test]
    fn rejects_pre_eip155_and_unknown_types() {
        assert!(Transaction::from_ethereum_raw(&[]).is_err());
        assert!(Transaction::from_ethereum_raw(&[0x03, 0x01, 0x02]).is_err());
        assert!(Transaction::from_ethereum_raw(&[0x04, 0x01, 0x02]).is_err());
        let oversized = vec![0xf8u8; MAX_TX_DATA_SIZE + 9000];
        assert!(Transaction::from_ethereum_raw(&oversized).is_err());
    }
    #[test]
    fn test_dual_sig_path_and_strict_parity_fuzzing() {
        use rand::{thread_rng, Rng};
        let mut rng = thread_rng();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        for _ in 0..100 {
            let mut tx = Transaction::new_transfer(
                Address::from_public_key(&signing_key.verifying_key().to_bytes()),
                Address([rng.gen(); 32]),
                U256::from(rng.gen::<u64>()),
                rng.gen(),
            );
            tx.sign(&signing_key).unwrap();
            tx.ethereum_y_parity = Some(rng.gen_range(0..=1));
            tx.ethereum_sighash = Some([rng.gen(); 32]);
            tx.ethereum_tx_hash = Some([rng.gen(); 32]);
            assert!(
                tx.validate_basic().is_err(),
                "Dual sig path must fail validation"
            );
            let mut eth_tx = Transaction::new_transfer(
                Address::zero(),
                Address([rng.gen(); 32]),
                U256::from(rng.gen::<u64>()),
                rng.gen(),
            );
            eth_tx.ethereum_y_parity = Some(rng.gen_range(2..=255));
            eth_tx.ethereum_sighash = Some([rng.gen(); 32]);
            eth_tx.ethereum_tx_hash = Some([rng.gen(); 32]);
            assert!(
                eth_tx.validate_basic().is_err(),
                "Invalid y_parity must fail validation"
            );
            eth_tx.ethereum_y_parity = Some(rng.gen_range(0..=1));
            eth_tx.chain_id = Some(rng.gen_range(0..=1000));
            if eth_tx.chain_id != Some(SXIAUM_CHAIN_ID) {
                assert!(
                    eth_tx.validate_basic().is_err(),
                    "Invalid chain_id must fail validation"
                );
            }
        }
    }
}
#[cfg(test)]
mod log_tests {
    use super::{Log, MAX_LOG_DATA_SIZE, MAX_LOG_TOPICS};
    use crate::Address;
    #[test]
    fn new_log_initializes_expected_fields() {
        let address = Address([1u8; 32]);
        let topics = vec![[2u8; 32], [3u8; 32]];
        let data = vec![4, 5, 6];
        let log = Log::new(address, topics.clone(), data.clone());
        assert_eq!(log.address, address);
        assert_eq!(log.topics, topics);
        assert_eq!(log.data, data);
        log.validate().expect("valid log");
    }
    #[test]
    fn topic_hash_uses_keccak_and_is_deterministic() {
        let log = Log::new(Address([7u8; 32]), vec![[8u8; 32], [9u8; 32]], vec![1, 2]);
        assert_eq!(log.topic_hash(), log.topic_hash());
        let mut hasher = sha3::Keccak256::new();
        use sha3::Digest;
        hasher.update([8u8; 32]);
        hasher.update([9u8; 32]);
        let digest = hasher.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&digest);
        assert_eq!(log.topic_hash(), expected);
    }
    #[test]
    fn bloom_filter_generation() {
        let address = Address::from_ethereum_address([0x55; 20]);
        let topic1 = [0x11; 32];
        let topic2 = [0x22; 32];
        let log = Log::new(address, vec![topic1, topic2], vec![1, 2, 3]);
        let bloom = log.bloom();
        assert_ne!(bloom, [0u8; 256]);
    }
    #[test]
    fn log_validation_enforces_bounds() {
        let addr = Address([1u8; 32]);
        let too_many = Log::new(addr, vec![[1u8; 32]; MAX_LOG_TOPICS + 1], vec![]);
        assert!(too_many.validate().is_err());
        assert!(too_many.try_encode().is_err());
        let big_data = Log::new(addr, vec![[1u8; 32]], vec![0u8; MAX_LOG_DATA_SIZE + 1]);
        assert!(big_data.validate().is_err());
    }
    #[test]
    fn encode_round_trip_preserves_log() {
        let log = Log::new(
            Address([10u8; 32]),
            vec![[11u8; 32], [12u8; 32]],
            vec![13, 14, 15],
        );
        let encoded = log.try_encode().unwrap();
        let decoded: Log =
            <Log as crate::Canonical>::decode(&encoded).expect("log deserialization should work");
        assert_eq!(decoded, log);
    }
    #[test]
    fn serde_round_trip_preserves_log() {
        let log = Log::new(Address([16u8; 32]), vec![[17u8; 32]], vec![18, 19]);
        let json = serde_json::to_string(&log).expect("log json serialization should work");
        let decoded: Log =
            serde_json::from_str(&json).expect("log json deserialization should work");
        assert_eq!(decoded, log);
    }
}
#[cfg(test)]
mod receipt_tests {
    use super::{Log, Receipt, MAX_RECEIPT_LOGS};
    use crate::Address;
    #[test]
    fn new_success_initializes_expected_fields() {
        let tx_hash = [1u8; 32];
        let state_root = Some([2u8; 32]);
        let receipt = Receipt::new_success(tx_hash, 21_000, state_root);
        assert_eq!(receipt.tx_hash, tx_hash);
        assert!(receipt.status);
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(receipt.cumulative_gas_used, 21_000);
        assert!(receipt.logs.is_empty());
        assert_eq!(receipt.state_root, state_root);
        receipt.validate().expect("valid receipt");
    }
    #[test]
    fn new_failure_clears_state_root() {
        let tx_hash = [3u8; 32];
        let receipt = Receipt::new_failure(tx_hash, 50_000);
        assert_eq!(receipt.tx_hash, tx_hash);
        assert!(!receipt.status);
        assert_eq!(receipt.gas_used, 50_000);
        assert!(receipt.logs.is_empty());
        assert_eq!(receipt.state_root, None);
    }
    #[test]
    fn add_log_and_bloom_computation() {
        let mut receipt = Receipt::new_success([4u8; 32], 30_000, Some([5u8; 32]));
        let log = Log::new(Address([6u8; 32]), vec![[7u8; 32]], vec![1, 2, 3]);
        receipt.add_log(log.clone()).expect("add log");
        assert_eq!(receipt.logs, vec![log]);
        let bloom = receipt.bloom();
        assert_ne!(bloom, [0u8; 256]);
    }
    #[test]
    fn receipt_validation_enforces_invariants() {
        let mut receipt = Receipt::new_failure([9u8; 32], 10);
        receipt.state_root = Some([1u8; 32]);
        assert!(receipt.validate().is_err());
        assert!(receipt.try_hash().is_err());
        let mut receipt = Receipt::new_success([9u8; 32], 100, None);
        receipt.cumulative_gas_used = 10;
        assert!(receipt.validate().is_err());
        let mut receipt = Receipt::new_success([9u8; 32], 10, None);
        let mut i = 0usize;
        while i < MAX_RECEIPT_LOGS {
            receipt.add_log(Log::new(Address([1u8; 32]), vec![], vec![])).expect("add");
            i += 1;
        }
        assert!(receipt.add_log(Log::new(Address([1u8; 32]), vec![], vec![])).is_err());
    }
    #[test]
    fn hash_and_bincode_are_deterministic() {
        let mut receipt = Receipt::new_success([8u8; 32], 42_000, Some([9u8; 32]));
        receipt.add_log(Log::new(
            Address([10u8; 32]),
            vec![[11u8; 32]],
            vec![4, 5, 6],
        )).expect("add log");
        let first_hash = receipt.try_hash().unwrap();
        let second_hash = receipt.try_hash().unwrap();
        let encoded = receipt.try_bincode_encode().unwrap();
        let decoded: Receipt = <Receipt as crate::Canonical>::decode(&encoded)
            .expect("receipt deserialization should work");
        assert_eq!(first_hash, second_hash);
        assert_eq!(decoded, receipt);
    }
    #[test]
    fn serde_round_trip_preserves_receipt_fields() {
        let mut receipt = Receipt::new_failure([12u8; 32], 64_000);
        receipt.add_log(Log::new(
            Address([13u8; 32]),
            vec![[14u8; 32], [15u8; 32]],
            vec![7, 8, 9],
        )).expect("add log");
        let json = serde_json::to_string(&receipt).expect("receipt json serialization should work");
        let decoded: Receipt =
            serde_json::from_str(&json).expect("receipt json deserialization should work");
        assert_eq!(decoded, receipt);
    }
}
