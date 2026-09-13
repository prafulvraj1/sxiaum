use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
pub trait Canonical: Serialize + DeserializeOwned {
    fn try_encode(&self) -> Result<Vec<u8>> {
        use bincode::Options;
        let options = bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .with_limit(8 * 1024 * 1024)
            .reject_trailing_bytes();
        options
            .serialize(self)
            .map_err(|e| anyhow::anyhow!("serialize error: {}", e))
    }
    fn try_encode_to_writer<W: std::io::Write>(&self, writer: W) -> Result<()> {
        use bincode::Options;
        let options = bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .with_limit(8 * 1024 * 1024)
            .reject_trailing_bytes();
        options
            .serialize_into(writer, self)
            .map_err(|e| anyhow::anyhow!("serialize_into error: {}", e))
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        use bincode::Options;
        if bytes.len() > 8 * 1024 * 1024 {
            anyhow::bail!("decode input exceeds maximum canonical size");
        }
        let options = bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .with_limit(8 * 1024 * 1024)
            .reject_trailing_bytes();
        options
            .deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("Decoding failed: {:?}", e))
    }
    fn decode_from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        use bincode::Options;
        let options = bincode::options()
            .with_little_endian()
            .with_varint_encoding()
            .with_limit(8 * 1024 * 1024)
            .reject_trailing_bytes();
        options
            .deserialize_from(reader)
            .map_err(|e| anyhow::anyhow!("deserialize_from failed: {:?}", e))
    }
    fn try_hash(&self) -> Result<[u8; 32]> {
        let bytes = self.try_encode()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        Ok(hash_bytes)
    }
}
impl<T: Serialize + DeserializeOwned> Canonical for T {}
pub mod serde_sig {
    use serde::de::Error;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(val: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match val {
            Some(bytes) => s.serialize_some(bytes.as_slice()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<Vec<u8>> = serde::Deserialize::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(bytes) => {
                if bytes.len() != 64 {
                    return Err(D::Error::custom("expected exactly 64-byte ed25519 signature"));
                }
                let mut out = [0u8; 64];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::Canonical;
    use serde::{Deserialize, Serialize};
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SampleData {
        id: u64,
        tag: String,
        payload: Vec<u8>,
    }
    #[test]
    fn canonical_round_trip_and_hashing() {
        let item = SampleData {
            id: 42,
            tag: "sxiaum".to_string(),
            payload: vec![1, 2, 3, 4],
        };
        let encoded = item.try_encode().expect("encode");
        let decoded = SampleData::decode(&encoded).expect("decode");
        assert_eq!(decoded, item);
        let hash1 = item.try_hash().expect("hash");
        let hash2 = item.try_hash().expect("hash");
        assert_eq!(hash1, hash2);
        let mut cursor = std::io::Cursor::new(Vec::new());
        item.try_encode_to_writer(&mut cursor)
            .expect("encode to writer");
        cursor.set_position(0);
        let streamed: SampleData =
            SampleData::decode_from_reader(&mut cursor).expect("decode from reader");
        assert_eq!(streamed, item);
    }
    #[test]
    fn canonical_rejects_oversized_and_trailing() {
        let item = SampleData {
            id: 1,
            tag: "a".to_string(),
            payload: vec![0u8; 16],
        };
        let mut encoded = item.try_encode().expect("encode");
        encoded.push(0xFF);
        assert!(SampleData::decode(&encoded).is_err());
        let huge = vec![0u8; 8 * 1024 * 1024 + 1];
        assert!(SampleData::decode(&huge).is_err());
    }
}
