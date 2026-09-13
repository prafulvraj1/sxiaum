use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sxiaum_types::Canonical;

const VERKLE_BRANCHING_FACTOR: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerkleNode {
    pub commitment: [u8; 32],
    pub children: Vec<Option<Box<VerkleNode>>>,
    pub value: Option<[u8; 32]>,
    pub depth: u8,
}

impl VerkleNode {
    pub fn new_internal(depth: u8) -> Self {
        Self {
            commitment: sxiaum_crypto::kzg::get_empty_commitment(),
            children: vec![None; VERKLE_BRANCHING_FACTOR],
            value: None,
            depth,
        }
    }

    pub fn new_leaf(_key: [u8; 32], value: [u8; 32]) -> Self {
        let mut node = Self {
            commitment: [0u8; 32],
            children: vec![None; VERKLE_BRANCHING_FACTOR],
            value: Some(value),
            depth: 32,
        };
        node.refresh_commitment();
        node
    }

    pub fn is_leaf(&self) -> bool {
        self.value.is_some() && self.children.iter().all(Option::is_none)
    }

    pub fn child(&self, index: usize) -> Option<&VerkleNode> {
        self.children.get(index).and_then(|child| child.as_deref())
    }

    pub fn set_child(&mut self, index: usize, node: VerkleNode) -> Result<Option<VerkleNode>> {
        let slot = self.children.get_mut(index).ok_or_else(|| {
            anyhow!(
                "child index out of bounds: {} (max {})",
                index,
                VERKLE_BRANCHING_FACTOR
            )
        })?;
        let previous = slot.replace(Box::new(node)).map(|boxed| *boxed);
        self.refresh_commitment();
        Ok(previous)
    }

    pub fn remove_child(&mut self, index: usize) -> Result<Option<VerkleNode>> {
        let slot = self.children.get_mut(index).ok_or_else(|| {
            anyhow!(
                "child index out of bounds: {} (max {})",
                index,
                VERKLE_BRANCHING_FACTOR
            )
        })?;
        let removed = slot.take().map(|boxed| *boxed);
        self.refresh_commitment();
        Ok(removed)
    }

    pub fn update_value(&mut self, value: [u8; 32]) {
        self.value = Some(value);
        self.refresh_commitment();
    }

    pub(crate) fn clear_value(&mut self) {
        self.value = None;
        self.refresh_commitment();
    }

    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub fn vector_values(&self) -> Vec<Option<[u8; 32]>> {
        self.children
            .iter()
            .enumerate()
            .map(|(index, child)| {
                child
                    .as_ref()
                    .map(|node| node.commitment)
                    .or(if index == 0 { self.value } else { None })
            })
            .collect()
    }

    pub fn kzg_commitment_bytes(&self) -> Result<Vec<u8>> {
        sxiaum_crypto::kzg::compute_kzg_commitment_bytes(&self.vector_values())
            .map_err(|e| anyhow!("failed to compute KZG commitment: {}", e))
    }

    pub fn kzg_opening(&self, index: usize) -> Result<Vec<u8>> {
        sxiaum_crypto::kzg::open_kzg(&self.vector_values(), index)
            .map_err(|e| anyhow!("failed to compute KZG opening: {}", e))
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.try_encode()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes)
    }

    pub fn try_hash(&self) -> Result<[u8; 32]> {
        <Self as Canonical>::try_hash(self)
    }

    pub fn empty() -> Self {
        Self::new_internal(0)
    }

    pub fn children_count(&self) -> usize {
        self.children.iter().flatten().count()
    }

    pub fn validate_structure(&self) -> Result<()> {
        if self.children.len() != VERKLE_BRANCHING_FACTOR {
            bail!(
                "invalid children length: expected {}, got {}",
                VERKLE_BRANCHING_FACTOR,
                self.children.len()
            );
        }

        if self.is_leaf() {
            return Ok(());
        }

        if self.value.is_some() && self.children_count() > 0 {
            bail!("node cannot contain both a leaf value and child nodes");
        }

        for (index, child) in self.children.iter().enumerate() {
            if let Some(child) = child {
                if child.depth != self.depth.saturating_add(1) {
                    return Err(anyhow!(
                        "child at index {} has depth {}, expected {}",
                        index,
                        child.depth,
                        self.depth.saturating_add(1)
                    ));
                }
                child.validate_structure()?;
            }
        }

        let expected_commitment = self.compute_commitment();
        if self.commitment != expected_commitment {
            bail!("cached node commitment does not match computed commitment");
        }

        Ok(())
    }

    fn refresh_commitment(&mut self) {
        self.commitment = self.compute_commitment();
    }

    pub(crate) fn recompute_commitment(&mut self) {
        self.refresh_commitment();
    }

    fn compute_commitment(&self) -> [u8; 32] {
        sxiaum_crypto::kzg::compute_kzg_commitment(&self.vector_values())
    }
}

#[cfg(test)]
mod tests {
    use super::VerkleNode;

    fn value(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn internal_and_empty_nodes_initialize_correctly() {
        let internal = VerkleNode::new_internal(3);
        let empty = VerkleNode::empty();

        assert_eq!(internal.depth, 3);
        assert_eq!(internal.children.len(), 256);
        assert_eq!(internal.children_count(), 0);
        assert!(!internal.is_leaf());
        assert_eq!(empty.depth, 0);
        assert_eq!(empty.children.len(), 256);
    }

    #[test]
    fn leaf_nodes_expose_value_and_commitment() {
        let leaf = VerkleNode::new_leaf([1u8; 32], value(9));

        assert!(leaf.is_leaf());
        assert_eq!(leaf.value, Some(value(9)));
        assert_ne!(leaf.commitment(), [0u8; 32]);
        assert_eq!(leaf.children_count(), 0);
    }

    #[test]
    fn child_set_get_remove_updates_commitment() {
        let mut root = VerkleNode::new_internal(0);
        let original_commitment = root.commitment();
        let child = VerkleNode::new_internal(1);

        assert!(root
            .set_child(7, child)
            .expect("set_child should succeed")
            .is_none());
        assert!(root.child(7).is_some());
        assert_eq!(root.children_count(), 1);
        assert_ne!(root.commitment(), original_commitment);

        let removed = root
            .remove_child(7)
            .expect("remove_child should succeed")
            .expect("child should exist");
        assert_eq!(removed.depth, 1);
        assert!(root.child(7).is_none());
        assert_eq!(root.children_count(), 0);
    }

    #[test]
    fn update_value_and_hash_are_deterministic() {
        let mut node = VerkleNode::new_internal(0);
        let initial_hash = node.try_hash().unwrap();

        node.update_value(value(5));

        assert_eq!(node.value, Some(value(5)));
        assert_eq!(node.try_hash().unwrap(), node.try_hash().unwrap());
        assert_ne!(node.try_hash().unwrap(), initial_hash);
    }

    #[test]
    fn serialization_round_trip_preserves_node() {
        let mut node = VerkleNode::new_internal(0);
        node.set_child(1, VerkleNode::new_internal(1))
            .expect("set_child should succeed");
        let bytes = node.serialize().expect("serialize should succeed");
        let decoded = VerkleNode::deserialize(&bytes).expect("node decode should succeed");

        assert_eq!(decoded.depth, node.depth);
        assert_eq!(decoded.commitment(), node.commitment());
        assert_eq!(decoded.children_count(), node.children_count());
    }

    #[test]
    fn validate_structure_accepts_valid_nodes() {
        let mut root = VerkleNode::new_internal(0);
        root.set_child(3, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        let leaf = VerkleNode::new_leaf([4u8; 32], value(8));

        root.validate_structure()
            .expect("valid Verkle tree structure should pass");
        leaf.validate_structure()
            .expect("standalone leaf structure should pass");
    }

    #[test]
    fn validate_structure_rejects_invalid_depth_or_commitment() {
        let mut root = VerkleNode::new_internal(0);
        root.set_child(0, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        let mut wrong_depth = root.clone();
        wrong_depth.children[0] = Some(Box::new(VerkleNode::new_internal(9)));
        wrong_depth.recompute_commitment();
        assert!(wrong_depth.validate_structure().is_err());

        let mut stale_commitment = root.clone();
        stale_commitment.commitment = [0u8; 32];
        assert!(stale_commitment.validate_structure().is_err());
    }

    #[test]
    fn validate_structure_rejects_mixed_value_and_children() {
        let mut node = VerkleNode::new_internal(0);
        node.set_child(1, VerkleNode::new_internal(1))
            .expect("set_child should succeed");
        node.value = Some(value(7));
        node.recompute_commitment();

        assert!(node.validate_structure().is_err());
    }
}
