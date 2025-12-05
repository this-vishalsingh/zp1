//! Merkle tree commitment scheme.

use blake3::Hasher;
use zp1_primitives::M31;

/// A Merkle tree for committing to polynomial evaluations.
pub struct MerkleTree {
    /// Leaf hashes (bottom layer).
    leaves: Vec<[u8; 32]>,
    /// Internal nodes (layer by layer, root at index 0).
    nodes: Vec<[u8; 32]>,
    /// Tree height (log2 of leaf count).
    height: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from field element leaves.
    pub fn new(values: &[M31]) -> Self {
        let n = values.len().next_power_of_two();
        let height = n.trailing_zeros() as usize;

        // Hash leaves
        let mut leaves: Vec<[u8; 32]> = values
            .iter()
            .map(|v| {
                let mut hasher = Hasher::new();
                hasher.update(&v.as_u32().to_le_bytes());
                *hasher.finalize().as_bytes()
            })
            .collect();

        // Pad to power of two
        while leaves.len() < n {
            leaves.push([0u8; 32]);
        }

        // Build tree bottom-up
        let mut nodes = vec![[0u8; 32]; n - 1];
        let mut layer = leaves.clone();

        for level in (0..height).rev() {
            let layer_start = (1 << level) - 1;
            let mut next_layer = Vec::with_capacity(layer.len() / 2);

            for i in 0..(layer.len() / 2) {
                let mut hasher = Hasher::new();
                hasher.update(&layer[2 * i]);
                hasher.update(&layer[2 * i + 1]);
                let hash = *hasher.finalize().as_bytes();
                nodes[layer_start + i] = hash;
                next_layer.push(hash);
            }

            layer = next_layer;
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
            if self.leaves.is_empty() {
                [0u8; 32]
            } else {
                self.leaves[0]
            }
        } else {
            self.nodes[0]
        }
    }

    /// Generate a Merkle proof for the leaf at the given index.
    pub fn prove(&self, index: usize) -> MerkleProof {
        let mut path = Vec::with_capacity(self.height);
        let mut idx = index;

        // Start from leaves
        let mut layer_size = self.leaves.len();
        let mut layer_start = self.nodes.len(); // leaves are conceptually after nodes

        for _level in 0..self.height {
            let sibling_idx = idx ^ 1;
            let sibling_hash = if layer_start == self.nodes.len() {
                // We're at the leaf layer
                self.leaves[sibling_idx]
            } else {
                self.nodes[layer_start + sibling_idx]
            };

            path.push(sibling_hash);

            idx /= 2;
            layer_size /= 2;
            if layer_start == self.nodes.len() {
                layer_start = self.nodes.len() - layer_size;
            } else {
                layer_start = layer_start - layer_size;
            }
        }

        MerkleProof {
            leaf_index: index,
            path,
        }
    }

    /// Verify a Merkle proof.
    pub fn verify(root: &[u8; 32], leaf: M31, proof: &MerkleProof) -> bool {
        let mut hasher = Hasher::new();
        hasher.update(&leaf.as_u32().to_le_bytes());
        let mut current = *hasher.finalize().as_bytes();

        let mut idx = proof.leaf_index;

        for sibling in &proof.path {
            let mut hasher = Hasher::new();
            if idx & 1 == 0 {
                hasher.update(&current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current);
            }
            current = *hasher.finalize().as_bytes();
            idx /= 2;
        }

        current == *root
    }

    /// Get the number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get tree height.
    pub fn height(&self) -> usize {
        self.height
    }
}

/// A Merkle proof for a single leaf.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Index of the leaf.
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root.
    pub path: Vec<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_single() {
        let values = vec![M31::new(42)];
        let tree = MerkleTree::new(&values);
        let proof = tree.prove(0);
        assert!(MerkleTree::verify(&tree.root(), M31::new(42), &proof));
    }

    #[test]
    fn test_merkle_tree_multiple() {
        let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let tree = MerkleTree::new(&values);

        for (i, &v) in values.iter().enumerate() {
            let proof = tree.prove(i);
            assert!(MerkleTree::verify(&tree.root(), v, &proof));
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
}
