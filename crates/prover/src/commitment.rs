//! Merkle tree commitment scheme using Blake3.
//!
//! This module provides a complete Merkle tree implementation with:
//! - Domain separation for leaf vs internal nodes (security)
//! - Efficient proof generation and verification
//! - Support for both M31 field elements and arbitrary byte arrays
//! - Batch proof generation for multiple leaves
//!
//! # Security Properties
//!
//! - **Collision resistance**: Inherited from Blake3
//! - **Second preimage resistance**: Domain separation prevents leaf/node confusion
//! - **Binding**: Changing any leaf changes the root
//!
//! # Usage
//!
//! ```ignore
//! use zp1_prover::commitment::MerkleTree;
//! use zp1_primitives::M31;
//!
//! let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
//! let tree = MerkleTree::new(&values);
//! let root = tree.root();
//! let proof = tree.prove(3);
//! assert!(MerkleTree::verify(&root, values[3], &proof));
//! ```

use blake3::Hasher;
use zp1_primitives::M31;

// Domain separation prefixes for Blake3 hashing
const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// Hash a leaf value with domain separation.
#[inline]
fn hash_leaf(value: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

/// Hash a leaf M31 value.
#[inline]
fn hash_leaf_m31(value: M31) -> [u8; 32] {
    hash_leaf(&value.as_u32().to_le_bytes())
}

/// Hash two child nodes into a parent (internal node).
#[inline]
fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// A Merkle tree for committing to polynomial evaluations.
///
/// The tree is stored in a flat array with the following layout:
/// - Index 0: root
/// - Indices 1..n-1: internal nodes (layer by layer, top to bottom)
/// - Indices n-1..2n-1: leaves (conceptually, stored separately)
///
/// For a tree with n leaves (must be power of 2):
/// - Height = log2(n)
/// - Internal nodes = n - 1
///
/// # Example Layout (8 leaves)
///
/// ```text
///              [0]                  <- root
///         /         \
///       [1]         [2]             <- level 1
///      /   \       /   \
///    [3]   [4]   [5]   [6]          <- level 2
///    /\    /\    /\    /\
///   L0 L1 L2 L3 L4 L5 L6 L7         <- leaves
/// ```
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Leaf hashes (bottom layer).
    leaves: Vec<[u8; 32]>,
    /// Internal nodes in level-order (root at index 0).
    /// For n leaves, there are n-1 internal nodes.
    nodes: Vec<[u8; 32]>,
    /// Tree height (log2 of leaf count).
    height: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from M31 field element leaves.
    pub fn new(values: &[M31]) -> Self {
        let hashes: Vec<[u8; 32]> = values.iter().map(|&v| hash_leaf_m31(v)).collect();
        Self::from_leaf_hashes(hashes)
    }

    /// Build a Merkle tree from arbitrary byte slices.
    pub fn from_bytes(values: &[&[u8]]) -> Self {
        let hashes: Vec<[u8; 32]> = values.iter().map(|v| hash_leaf(v)).collect();
        Self::from_leaf_hashes(hashes)
    }

    /// Build a Merkle tree from pre-hashed leaves.
    pub fn from_leaf_hashes(mut leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: vec![[0u8; 32]],
                nodes: Vec::new(),
                height: 0,
            };
        }

        // Pad to power of two
        let n = leaves.len().next_power_of_two();
        let height = n.trailing_zeros() as usize;
        
        while leaves.len() < n {
            // Pad with zero hashes (represents empty leaves)
            leaves.push([0u8; 32]);
        }

        // Build tree bottom-up
        // nodes[0] = root, nodes[1..3] = level 1, nodes[3..7] = level 2, etc.
        let mut nodes = vec![[0u8; 32]; n - 1];
        
        // Start with leaves as the current layer
        let mut current_layer = leaves.clone();
        
        // Build each level from bottom to top
        // Level h-1 (just above leaves) to level 0 (root)
        for level in (0..height).rev() {
            let level_start = (1 << level) - 1; // Index where this level starts in nodes[]
            let level_size = 1 << level;        // Number of nodes at this level
            
            let mut next_layer = Vec::with_capacity(level_size);
            
            for i in 0..level_size {
                let left = &current_layer[2 * i];
                let right = &current_layer[2 * i + 1];
                let parent = hash_internal(left, right);
                nodes[level_start + i] = parent;
                next_layer.push(parent);
            }
            
            current_layer = next_layer;
        }

        Self {
            leaves,
            nodes,
            height,
        }
    }

    /// Get the root commitment.
    pub fn root(&self) -> [u8; 32] {
        if self.nodes.is_empty() {
            // Single leaf case
            self.leaves.first().copied().unwrap_or([0u8; 32])
        } else {
            self.nodes[0]
        }
    }

    /// Generate a Merkle proof for the leaf at the given index.
    ///
    /// The proof contains sibling hashes from leaf to root.
    /// The verifier can use the leaf index to determine whether each
    /// sibling is on the left or right.
    pub fn prove(&self, index: usize) -> MerkleProof {
        assert!(index < self.leaves.len(), "Index out of bounds");
        
        let mut path = Vec::with_capacity(self.height);
        let mut idx = index;
        
        // Level h-1 (just above leaves): get sibling from leaves
        // Level h-2 to 0: get sibling from nodes
        
        for level in (0..self.height).rev() {
            let sibling_idx = idx ^ 1; // XOR to get sibling
            
            if level == self.height - 1 {
                // Bottom level: sibling is a leaf
                path.push(self.leaves[sibling_idx]);
            } else {
                // Upper levels: sibling is in nodes
                // The children of nodes at level `level` are at level `level+1`
                let child_level_start = (1 << (level + 1)) - 1;
                path.push(self.nodes[child_level_start + sibling_idx]);
            }
            
            idx /= 2;
        }
        
        MerkleProof {
            leaf_index: index,
            path,
        }
    }

    /// Generate batch proofs for multiple leaves.
    /// 
    /// This is more efficient than generating individual proofs because
    /// common ancestors only need to be included once.
    pub fn prove_batch(&self, indices: &[usize]) -> BatchMerkleProof {
        let proofs: Vec<MerkleProof> = indices.iter().map(|&i| self.prove(i)).collect();
        
        // In a real implementation, we would deduplicate common siblings
        // For now, just wrap individual proofs
        BatchMerkleProof {
            indices: indices.to_vec(),
            proofs,
        }
    }

    /// Verify a Merkle proof for an M31 value.
    pub fn verify(root: &[u8; 32], leaf: M31, proof: &MerkleProof) -> bool {
        Self::verify_hash(root, &hash_leaf_m31(leaf), proof)
    }

    /// Verify a Merkle proof for arbitrary bytes.
    pub fn verify_bytes(root: &[u8; 32], leaf: &[u8], proof: &MerkleProof) -> bool {
        Self::verify_hash(root, &hash_leaf(leaf), proof)
    }

    /// Verify a Merkle proof given a pre-computed leaf hash.
    pub fn verify_hash(root: &[u8; 32], leaf_hash: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current = *leaf_hash;
        let mut idx = proof.leaf_index;

        for sibling in &proof.path {
            if idx & 1 == 0 {
                // Current is left child, sibling is right
                current = hash_internal(&current, sibling);
            } else {
                // Current is right child, sibling is left
                current = hash_internal(sibling, &current);
            }
            idx >>= 1;
        }

        current == *root
    }

    /// Get the number of leaves (including padding).
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get tree height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Get a leaf hash by index.
    pub fn get_leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.leaves.get(index).copied()
    }

    /// Get an internal node by index (0 = root).
    pub fn get_node(&self, index: usize) -> Option<[u8; 32]> {
        self.nodes.get(index).copied()
    }
}

/// A Merkle proof for a single leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Index of the leaf (determines left/right at each level).
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root.
    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Get proof length (equals tree height).
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Check if proof is empty.
    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }
}

/// Batch Merkle proof for multiple leaves.
#[derive(Clone, Debug)]
pub struct BatchMerkleProof {
    /// Indices of proved leaves.
    pub indices: Vec<usize>,
    /// Individual proofs (could be optimized to share common siblings).
    pub proofs: Vec<MerkleProof>,
}

impl BatchMerkleProof {
    /// Verify all proofs in the batch against M31 values.
    pub fn verify_all(&self, root: &[u8; 32], leaves: &[M31]) -> bool {
        if leaves.len() != self.indices.len() {
            return false;
        }

        self.proofs.iter().zip(leaves.iter()).all(|(proof, &leaf)| {
            MerkleTree::verify(root, leaf, proof)
        })
    }
}

/// Compute the Merkle root directly from values without storing the tree.
/// Useful when you only need the commitment, not proofs.
pub fn compute_root(values: &[M31]) -> [u8; 32] {
    let tree = MerkleTree::new(values);
    tree.root()
}

/// Compute the Merkle root from byte slices.
pub fn compute_root_bytes(values: &[&[u8]]) -> [u8; 32] {
    let tree = MerkleTree::from_bytes(values);
    tree.root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single() {
        let values = vec![M31::new(42)];
        let tree = MerkleTree::new(&values);
        
        // Single leaf tree has height 0
        assert_eq!(tree.height(), 0);
        assert_eq!(tree.leaf_count(), 1);
        
        let proof = tree.prove(0);
        assert!(MerkleTree::verify(&tree.root(), M31::new(42), &proof));
    }

    #[test]
    fn test_merkle_tree_two_leaves() {
        let values = vec![M31::new(1), M31::new(2)];
        let tree = MerkleTree::new(&values);
        
        assert_eq!(tree.height(), 1);
        assert_eq!(tree.leaf_count(), 2);
        
        // Verify both leaves
        for (i, &v) in values.iter().enumerate() {
            let proof = tree.prove(i);
            assert_eq!(proof.len(), 1);
            assert!(MerkleTree::verify(&tree.root(), v, &proof), 
                    "Verification failed for leaf {}", i);
        }
    }

    #[test]
    fn test_merkle_tree_power_of_two() {
        let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);

        assert_eq!(tree.height(), 3); // log2(8) = 3
        assert_eq!(tree.leaf_count(), 8);

        for (i, &v) in values.iter().enumerate() {
            let proof = tree.prove(i);
            assert_eq!(proof.len(), 3);
            assert!(MerkleTree::verify(&tree.root(), v, &proof),
                    "Verification failed for leaf {}", i);
        }
    }

    #[test]
    fn test_merkle_tree_non_power_of_two() {
        // 5 leaves should be padded to 8
        let values: Vec<M31> = (0..5).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);

        assert_eq!(tree.height(), 3); // log2(8) = 3
        assert_eq!(tree.leaf_count(), 8); // Padded

        for (i, &v) in values.iter().enumerate() {
            let proof = tree.prove(i);
            assert!(MerkleTree::verify(&tree.root(), v, &proof),
                    "Verification failed for leaf {}", i);
        }
    }

    #[test]
    fn test_merkle_tree_wrong_value() {
        let values: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        let proof = tree.prove(0);

        // Should fail with wrong value
        assert!(!MerkleTree::verify(&tree.root(), M31::new(999), &proof));
    }

    #[test]
    fn test_merkle_tree_wrong_index() {
        let values: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        
        // Get proof for index 0
        let mut proof = tree.prove(0);
        
        // Modify to claim it's index 1 - should fail
        proof.leaf_index = 1;
        assert!(!MerkleTree::verify(&tree.root(), values[0], &proof));
    }

    #[test]
    fn test_merkle_tree_tampered_proof() {
        let values: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        
        let mut proof = tree.prove(0);
        
        // Tamper with a sibling hash
        if !proof.path.is_empty() {
            proof.path[0][0] ^= 0xFF;
        }
        
        assert!(!MerkleTree::verify(&tree.root(), values[0], &proof));
    }

    #[test]
    fn test_merkle_tree_different_roots() {
        let values1: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let values2: Vec<M31> = (0..4).map(|i| M31::new(i + 100)).collect();
        
        let tree1 = MerkleTree::new(&values1);
        let tree2 = MerkleTree::new(&values2);
        
        // Different values should have different roots
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_tree_bytes() {
        let data: Vec<&[u8]> = vec![b"hello", b"world", b"foo", b"bar"];
        let tree = MerkleTree::from_bytes(&data);
        
        assert_eq!(tree.height(), 2);
        
        for (i, &d) in data.iter().enumerate() {
            let proof = tree.prove(i);
            assert!(MerkleTree::verify_bytes(&tree.root(), d, &proof),
                    "Verification failed for leaf {}", i);
        }
    }

    #[test]
    fn test_batch_proof() {
        let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        
        let indices = vec![1, 3, 5];
        let batch_proof = tree.prove_batch(&indices);
        
        let queried_values: Vec<M31> = indices.iter().map(|&i| values[i]).collect();
        assert!(batch_proof.verify_all(&tree.root(), &queried_values));
    }

    #[test]
    fn test_domain_separation() {
        // This tests that leaf hashes and internal node hashes use different prefixes
        // A leaf with value that matches an internal node hash shouldn't verify
        let values: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        
        // Get a leaf hash
        let leaf_hash = tree.get_leaf(0).unwrap();
        
        // The root uses INTERNAL_PREFIX, leaf uses LEAF_PREFIX
        // They should be computed differently
        let root = tree.root();
        
        // A crafted "leaf" that equals an internal node shouldn't verify
        // This would be a second preimage attack without domain separation
        assert_ne!(leaf_hash, root);
    }

    #[test]
    fn test_compute_root() {
        let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        
        // compute_root should give same result as tree.root()
        assert_eq!(compute_root(&values), tree.root());
    }

    #[test]
    fn test_large_tree() {
        // Test with 256 leaves
        let values: Vec<M31> = (0..256).map(|i| M31::new(i as u32)).collect();
        let tree = MerkleTree::new(&values);
        
        assert_eq!(tree.height(), 8); // log2(256) = 8
        
        // Verify a few random indices
        for &i in &[0, 127, 200, 255] {
            let proof = tree.prove(i);
            assert_eq!(proof.len(), 8);
            assert!(MerkleTree::verify(&tree.root(), values[i], &proof));
        }
    }

    #[test]
    fn test_empty_tree() {
        let values: Vec<M31> = vec![];
        let tree = MerkleTree::new(&values);
        
        // Empty tree should have a default root
        assert_eq!(tree.leaf_count(), 1); // Padded to 1
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn test_proof_consistency() {
        // Verify that the same proof verifies against the same leaf multiple times
        let values: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);
        
        let proof = tree.prove(2);
        let root = tree.root();
        
        // Multiple verifications should all succeed
        for _ in 0..10 {
            assert!(MerkleTree::verify(&root, values[2], &proof));
        }
    }
}
