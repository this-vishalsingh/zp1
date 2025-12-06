//! Proof aggregation for combining transaction proofs into block proofs.

use serde::{Serialize, Deserialize};
use ethers::types::H256;
use crate::{TransactionProof, Result, EthereumError};

/// Aggregated proof for an entire block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProof {
    /// Block number
    pub block_number: u64,
    
    /// Block hash
    pub block_hash: H256,
    
    /// Parent block hash
    pub parent_hash: H256,
    
    /// Transaction proofs (or aggregated proof)
    pub transaction_proofs: Vec<TransactionProof>,
    
    /// Aggregated STARK proof (if using recursion, serialized)
    #[serde(with = "serde_bytes")]
    pub aggregated_proof: Option<Vec<u8>>,
    
    /// Merkle root of transaction proofs
    pub proof_merkle_root: [u8; 32],
    
    /// Total gas used
    pub total_gas_used: u64,
}

impl BlockProof {
    /// Get the block number.
    pub fn number(&self) -> u64 {
        self.block_number
    }

    /// Get the block hash.
    pub fn hash(&self) -> H256 {
        self.block_hash
    }

    /// Get the commitment (proof merkle root).
    pub fn commitment(&self) -> &[u8; 32] {
        &self.proof_merkle_root
    }

    /// Number of transactions in the block.
    pub fn num_transactions(&self) -> usize {
        self.transaction_proofs.len()
    }

    /// Total gas used in the block.
    pub fn total_gas(&self) -> u64 {
        self.total_gas_used
    }
}

/// Proof aggregator for combining transaction proofs.
pub struct ProofAggregator {
    use_recursion: bool,
}

impl ProofAggregator {
    /// Create a new proof aggregator.
    pub fn new(use_recursion: bool) -> Self {
        Self { use_recursion }
    }

    /// Aggregate transaction proofs into a block proof.
    pub fn aggregate(
        &self,
        block_number: u64,
        block_hash: H256,
        parent_hash: H256,
        tx_proofs: Vec<TransactionProof>,
    ) -> Result<BlockProof> {
        // Calculate total gas
        let total_gas_used: u64 = tx_proofs.iter()
            .map(|p| p.gas_used())
            .sum();

        // Compute Merkle root of proofs
        let proof_merkle_root = self.compute_merkle_root(&tx_proofs)?;

        // TODO: Implement recursive proof aggregation
        let aggregated_proof = if self.use_recursion {
            // Use ZP1's recursive prover to combine proofs
            None // Placeholder
        } else {
            None
        };

        Ok(BlockProof {
            block_number,
            block_hash,
            parent_hash,
            transaction_proofs: tx_proofs,
            aggregated_proof,
            proof_merkle_root,
            total_gas_used,
        })
    }

    /// Compute Merkle root of transaction proofs.
    fn compute_merkle_root(&self, proofs: &[TransactionProof]) -> Result<[u8; 32]> {
        use blake3::Hasher;
        
        if proofs.is_empty() {
            return Ok([0u8; 32]);
        }

        // Simple merkle tree construction
        let mut leaves: Vec<[u8; 32]> = proofs.iter()
            .map(|p| {
                let mut hasher = Hasher::new();
                hasher.update(&p.tx_hash.0);
                *hasher.finalize().as_bytes()
            })
            .collect();

        // Build tree bottom-up
        while leaves.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut hasher = Hasher::new();
                hasher.update(&chunk[0]);
                if chunk.len() == 2 {
                    hasher.update(&chunk[1]);
                }
                next_level.push(*hasher.finalize().as_bytes());
            }
            leaves = next_level;
        }

        Ok(leaves[0])
    }

    /// Verify a block proof.
    pub fn verify(&self, proof: &BlockProof) -> Result<bool> {
        // Verify merkle root
        let computed_root = self.compute_merkle_root(&proof.transaction_proofs)?;
        if computed_root != proof.proof_merkle_root {
            return Ok(false);
        }

        // Verify each transaction proof
        // TODO: Implement proper verification
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_empty() {
        let aggregator = ProofAggregator::new(false);
        let root = aggregator.compute_merkle_root(&[]).unwrap();
        assert_eq!(root, [0u8; 32]);
    }
}
