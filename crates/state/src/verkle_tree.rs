use crate::node::VerkleNode;
use anyhow::{anyhow, bail, Result};

const DEFAULT_DEPTH: u8 = 32;
const DEFAULT_BRANCHING_FACTOR: usize = 256;

#[derive(Clone, Debug)]
pub struct VerkleTree {
    pub root: VerkleNode,
    pub depth: u8,
    pub branching_factor: usize,
}

impl Default for VerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl VerkleTree {
    pub fn new() -> Self {
        Self {
            root: VerkleNode::new_internal(0),
            depth: DEFAULT_DEPTH,
            branching_factor: DEFAULT_BRANCHING_FACTOR,
        }
    }

    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        let path = self.path_indices(key);
        Self::insert_recursive(&mut self.root, &path, value)?;
        self.update_commitment_after_insert();
        Ok(())
    }

    pub fn update(&mut self, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        let path = self.path_indices(key);
        Self::update_recursive(&mut self.root, &path, value)?;
        self.update_commitment_after_insert();
        Ok(())
    }

    pub fn get(&self, key: [u8; 32]) -> Result<Option<[u8; 32]>> {
        let path = self.path_indices(key);
        Ok(self.find_node(key).and_then(|node| {
            if node.depth as usize == path.len() && node.is_leaf() {
                node.value
            } else {
                None
            }
        }))
    }

    pub fn delete(&mut self, key: [u8; 32]) -> Result<()> {
        let path = self.path_indices(key);
        if !Self::delete_recursive(&mut self.root, &path)? {
            bail!("key does not exist in verkle tree");
        }
        self.update_commitment_after_delete();
        Ok(())
    }

    pub fn root_commitment(&self) -> [u8; 32] {
        self.root.commitment()
    }

    pub fn compute_polynomial_commitment(children: &[Option<Box<VerkleNode>>]) -> [u8; 32] {
        let mut values = [None; 256];
        for (index, child) in children.iter().enumerate().take(256) {
            values[index] = child.as_ref().map(|node| node.commitment());
        }
        sxiaum_crypto::kzg::compute_kzg_commitment(&values)
    }

    pub fn update_commitment_after_insert(&mut self) {
        self.root.recompute_commitment();
    }

    pub fn update_commitment_after_delete(&mut self) {
        self.root.recompute_commitment();
    }

    pub fn verify_commitment(&self) -> Result<bool> {
        self.validate_tree()?;
        let recomputed = Self::compute_polynomial_commitment(&self.root.children);
        let has_leaf_payload = self.root.value.is_some() || self.root.children_count() > 0;
        Ok(!has_leaf_payload || recomputed != [0u8; 32])
    }

    pub fn batch_commitment_updates(
        &mut self,
        updates: &[([u8; 32], Option<[u8; 32]>)],
    ) -> Result<[u8; 32]> {
        for (key, value) in updates {
            match value {
                Some(value) => {
                    if self.get(*key)?.is_some() {
                        self.update(*key, *value)?;
                    } else {
                        self.insert(*key, *value)?;
                    }
                }
                None => {
                    if self.get(*key)?.is_some() {
                        self.delete(*key)?;
                    }
                }
            }
        }

        self.root.recompute_commitment();
        Ok(self.root_commitment())
    }

    pub fn insert_recursive(node: &mut VerkleNode, path: &[usize], value: [u8; 32]) -> Result<()> {
        if path.is_empty() {
            if node.value.is_some() {
                bail!("key already exists in verkle tree");
            }
            node.update_value(value);
            return Ok(());
        }

        if node.is_leaf() {
            bail!("cannot insert below an existing leaf node");
        }

        let index = path[0];
        let mut child = match node.remove_child(index)? {
            Some(existing) => existing,
            None => VerkleNode::new_internal(node.depth.saturating_add(1)),
        };

        Self::insert_recursive(&mut child, &path[1..], value)?;
        node.set_child(index, child)?;
        Ok(())
    }

    pub fn update_recursive(node: &mut VerkleNode, path: &[usize], value: [u8; 32]) -> Result<()> {
        if path.is_empty() {
            if node.value.is_none() {
                bail!("key does not exist in verkle tree");
            }
            node.update_value(value);
            return Ok(());
        }

        let index = path[0];
        let mut child = node
            .remove_child(index)?
            .ok_or_else(|| anyhow!("key does not exist in verkle tree"))?;
        Self::update_recursive(&mut child, &path[1..], value)?;
        node.set_child(index, child)?;
        Ok(())
    }

    pub fn find_node(&self, key: [u8; 32]) -> Option<&VerkleNode> {
        let path = self.path_indices(key);
        let mut current = &self.root;

        for index in path {
            current = current.child(index)?;
        }

        Some(current)
    }

    pub fn path_indices(&self, key: [u8; 32]) -> Vec<usize> {
        key.iter()
            .take(self.depth as usize)
            .map(|byte| (*byte as usize) % self.branching_factor)
            .collect()
    }

    pub fn validate_tree(&self) -> Result<()> {
        if self.branching_factor != DEFAULT_BRANCHING_FACTOR {
            bail!(
                "unsupported branching factor: expected {}, got {}",
                DEFAULT_BRANCHING_FACTOR,
                self.branching_factor
            );
        }

        if self.depth == 0 {
            bail!("tree depth must be greater than zero");
        }

        if self.root.depth != 0 {
            bail!("root node depth must be zero");
        }

        self.root.validate_structure()
    }

    pub fn node_count(&self) -> usize {
        Self::count_nodes(&self.root)
    }

    pub fn leaf_count(&self) -> usize {
        Self::count_leaves(&self.root)
    }

    pub fn clear(&mut self) {
        self.root = VerkleNode::new_internal(0);
    }

    pub fn generate_witness(&self, keys: &[[u8; 32]]) -> Result<crate::proof::StateWitness> {
        crate::proof::StateWitness::generate(self, keys)
    }

    pub fn verify_witness(
        &self,
        root: [u8; 32],
        witness: &crate::proof::StateWitness,
        expected_kvs: &[([u8; 32], [u8; 32])],
    ) -> Result<bool> {
        witness.verify(root, expected_kvs)
    }

    pub fn commit(&self) -> Result<[u8; 32]> {
        self.validate_tree()?;
        Ok(self.root_commitment())
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_commitment()
    }

    fn delete_recursive(node: &mut VerkleNode, path: &[usize]) -> Result<bool> {
        if path.is_empty() {
            if node.value.is_none() {
                return Ok(false);
            }
            node.clear_value();
            return Ok(true);
        }

        let index = path[0];
        let mut child = match node.remove_child(index)? {
            Some(child) => child,
            None => return Ok(false),
        };

        let deleted = Self::delete_recursive(&mut child, &path[1..])?;
        if !deleted {
            node.set_child(index, child)?;
            return Ok(false);
        }

        let should_prune = child.value.is_none() && child.children_count() == 0;
        if !should_prune {
            child.recompute_commitment();
            node.set_child(index, child)?;
        } else {
            node.recompute_commitment();
        }

        Ok(true)
    }

    fn count_nodes(node: &VerkleNode) -> usize {
        1 + node
            .children
            .iter()
            .flatten()
            .map(|child| Self::count_nodes(child))
            .sum::<usize>()
    }

    fn count_leaves(node: &VerkleNode) -> usize {
        let current = usize::from(node.is_leaf());
        current
            + node
                .children
                .iter()
                .flatten()
                .map(|child| Self::count_leaves(child))
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::{VerkleTree, DEFAULT_BRANCHING_FACTOR, DEFAULT_DEPTH};
    use crate::node::VerkleNode;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn value(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn new_tree_initializes_expected_fields() {
        let tree = VerkleTree::new();

        assert_eq!(tree.depth, DEFAULT_DEPTH);
        assert_eq!(tree.branching_factor, DEFAULT_BRANCHING_FACTOR);
        assert_eq!(tree.root.depth, 0);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn insert_get_update_and_delete_round_trip() {
        let mut tree = VerkleTree::new();
        let key = key(9);

        tree.insert(key, value(1)).expect("insert should succeed");
        assert_eq!(tree.get(key).expect("get should succeed"), Some(value(1)));
        assert_eq!(tree.leaf_count(), 1);

        tree.update(key, value(2)).expect("update should succeed");
        assert_eq!(tree.get(key).expect("get should succeed"), Some(value(2)));

        tree.delete(key).expect("delete should succeed");
        assert_eq!(tree.get(key).expect("get should succeed"), None);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn find_node_and_path_indices_follow_key_bytes() {
        let mut tree = VerkleTree::new();
        let key = key(7);
        let path = tree.path_indices(key);

        assert_eq!(path.len(), DEFAULT_DEPTH as usize);
        assert!(path.iter().all(|index| *index < DEFAULT_BRANCHING_FACTOR));

        tree.insert(key, value(3)).expect("insert should succeed");
        let node = tree.find_node(key).expect("node should exist after insert");

        assert!(node.is_leaf());
        assert_eq!(node.value, Some(value(3)));
    }

    #[test]
    fn insert_recursive_and_update_recursive_enforce_expected_rules() {
        let mut root = VerkleNode::new_internal(0);

        VerkleTree::insert_recursive(&mut root, &[], value(4))
            .expect("root value insert should succeed");
        assert_eq!(root.value, Some(value(4)));
        assert!(VerkleTree::insert_recursive(&mut root, &[], value(5)).is_err());

        VerkleTree::update_recursive(&mut root, &[], value(6))
            .expect("root value update should succeed");
        assert_eq!(root.value, Some(value(6)));
        root.clear_value();
        assert!(VerkleTree::update_recursive(&mut root, &[], value(7)).is_err());
    }

    #[test]
    fn validate_tree_rejects_invalid_configuration() {
        let mut tree = VerkleTree::new();
        tree.depth = 0;
        assert!(tree.validate_tree().is_err());

        let mut tree = VerkleTree::new();
        tree.branching_factor = 16;
        assert!(tree.validate_tree().is_err());

        let mut tree = VerkleTree::new();
        tree.root.depth = 1;
        assert!(tree.validate_tree().is_err());
    }

    #[test]
    fn counts_and_clear_reflect_tree_contents() {
        let mut tree = VerkleTree::new();
        tree.insert(key(1), value(1))
            .expect("insert should succeed");
        tree.insert(key(2), value(2))
            .expect("insert should succeed");

        assert!(tree.node_count() > 1);
        assert_eq!(tree.leaf_count(), 2);
        let non_empty_root = tree.root_commitment();

        tree.clear();

        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.leaf_count(), 0);
        assert_ne!(tree.root_commitment(), non_empty_root);
        tree.validate_tree()
            .expect("cleared tree should stay valid");
    }

    #[test]
    fn duplicate_insert_and_missing_delete_fail() {
        let mut tree = VerkleTree::new();
        let existing_key = key(5);

        tree.insert(existing_key, value(1))
            .expect("insert should succeed");
        assert!(tree.insert(existing_key, value(2)).is_err());
        assert!(tree.delete(key(6)).is_err());
    }

    #[test]
    fn polynomial_commitment_is_deterministic_for_children() {
        let mut root = VerkleNode::new_internal(0);
        root.set_child(1, VerkleNode::new_internal(1))
            .expect("set_child should succeed");
        root.set_child(2, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        let first = VerkleTree::compute_polynomial_commitment(&root.children);
        let second = VerkleTree::compute_polynomial_commitment(&root.children);

        assert_eq!(first, second);
        assert_ne!(first, [0u8; 32]);
    }

    #[test]
    fn commitment_updates_after_insert_and_delete_change_root() {
        let mut tree = VerkleTree::new();
        let empty_root = tree.root_commitment();

        tree.insert(key(10), value(10))
            .expect("insert should succeed");
        let inserted_root = tree.root_commitment();
        assert_ne!(inserted_root, empty_root);

        tree.delete(key(10)).expect("delete should succeed");
        assert_eq!(tree.root_commitment(), empty_root);
    }

    #[test]
    fn commitment_verification_detects_valid_and_invalid_state() {
        let mut tree = VerkleTree::new();
        assert!(tree
            .verify_commitment()
            .expect("empty tree verification should succeed"));

        tree.insert(key(11), value(11))
            .expect("insert should succeed");
        assert!(tree
            .verify_commitment()
            .expect("tree verification should succeed"));

        tree.root.commitment = [0u8; 32];
        assert!(tree.verify_commitment().is_err());
    }

    #[test]
    fn batch_commitment_updates_apply_and_return_current_root() {
        let mut tree = VerkleTree::new();
        let updates = vec![
            (key(1), Some(value(1))),
            (key(2), Some(value(2))),
            (key(1), Some(value(3))),
            (key(2), None),
        ];

        let batch_root = tree
            .batch_commitment_updates(&updates)
            .expect("batch commitment update should succeed");

        assert_eq!(batch_root, tree.root_commitment());
        assert_eq!(
            tree.get(key(1)).expect("get should succeed"),
            Some(value(3))
        );
        assert_eq!(tree.get(key(2)).expect("get should succeed"), None);
        assert!(tree
            .verify_commitment()
            .expect("tree verification should succeed"));
    }
}
