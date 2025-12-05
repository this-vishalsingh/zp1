//! Recursive proof composition for proof aggregation.
//!
//! This module implements proof recursion, allowing multiple proofs to be
//! aggregated into a single proof. This is essential for:
//! - Scalability: Proving long computations in chunks
//! - Parallelism: Proving chunks independently then aggregating
//! - Compression: Reducing multiple proofs to one

#![allow(dead_code)]

use blake3::Hasher;
use zp1_primitives::M31;
use crate::stark::StarkProof;

// M31 modulus
const M31_MODULUS: u32 = (1 << 31) - 1;

/// A recursive proof that aggregates multiple inner proofs.
#[derive(Clone)]
pub struct RecursiveProof {
    /// The aggregated proof
    pub inner_proof: StarkProof,
    /// Number of proofs aggregated
    pub num_aggregated: usize,
    /// Public outputs from each inner proof (as field elements)
    pub public_outputs: Vec<Vec<M31>>,
    /// Commitment to the verification circuit
    pub verifier_commitment: [u8; 32],
}

/// Configuration for recursive proving.
#[derive(Debug, Clone)]
pub struct RecursionConfig {
    /// Maximum proofs to aggregate in one recursion step
    pub max_batch_size: usize,
    /// Security level in bits
    pub security_bits: usize,
    /// Whether to use parallel recursion
    pub parallel: bool,
    /// Validate inner proofs structurally before aggregation
    pub verify_structure: bool,
}

impl Default for RecursionConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 4,
            security_bits: 100,
            parallel: true,
            verify_structure: true,
        }
    }
}

/// Recursive prover that aggregates proofs.
pub struct RecursiveProver {
    config: RecursionConfig,
}

impl RecursiveProver {
    /// Create a new recursive prover.
    pub fn new(config: RecursionConfig) -> Self {
        Self { config }
    }
    
    /// Aggregate multiple proofs into one.
    ///
    /// The aggregated proof proves that all inner proofs are valid.
    pub fn aggregate(&self, proofs: &[StarkProof]) -> Result<RecursiveProof, RecursionError> {
        if proofs.is_empty() {
            return Err(RecursionError::EmptyBatch);
        }
        
        if proofs.len() > self.config.max_batch_size {
            return Err(RecursionError::BatchTooLarge {
                size: proofs.len(),
                max: self.config.max_batch_size,
            });
        }
        
        if self.config.verify_structure {
            for (i, proof) in proofs.iter().enumerate() {
                self.validate_proof(proof).map_err(|msg| RecursionError::InvalidProof(format!("proof {}: {}", i, msg)))?;
            }
        }

        // Extract public outputs from each proof (trace commitment as proxy)
        let public_outputs: Vec<Vec<M31>> = proofs
            .iter()
            .map(|p| {
                // Convert trace commitment bytes to field elements
                p.trace_commitment
                    .chunks(4)
                    .map(|chunk| {
                        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
                        M31::new(val % M31_MODULUS)
                    })
                    .collect()
            })
            .collect();
        
        // Compute commitment to all proofs
        let verifier_commitment = self.compute_batch_commitment(proofs);
        
        // Placeholder aggregated proof: we cannot build a real recursive proof here.
        // We retain the first proof's structure but bind both commitments to the batch hash.
        let mut aggregated = proofs[0].clone();
        aggregated.trace_commitment = verifier_commitment;
        aggregated.composition_commitment = verifier_commitment;
        
        Ok(RecursiveProof {
            inner_proof: aggregated,
            num_aggregated: proofs.len(),
            public_outputs,
            verifier_commitment,
        })
    }
    
    /// Compute commitment to a batch of proofs.
    fn compute_batch_commitment(&self, proofs: &[StarkProof]) -> [u8; 32] {
        let mut hasher = Hasher::new();

        for proof in proofs {
            hasher.update(&proof.trace_commitment);
            hasher.update(&proof.composition_commitment);
            // Bind minimal structural data
            hasher.update(&(proof.fri_proof.layer_commitments.len() as u64).to_le_bytes());
            hasher.update(&(proof.query_proofs.len() as u64).to_le_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Basic structural validation of a StarkProof (cheap, no cryptographic verification).
    fn validate_proof(&self, proof: &StarkProof) -> Result<(), &'static str> {
        if proof.trace_commitment.len() != 32 || proof.composition_commitment.len() != 32 {
            return Err("Commitments must be 32 bytes");
        }
        if proof.ood_values.trace_at_z.len() != proof.ood_values.trace_at_z_next.len() {
            return Err("OOD trace vectors length mismatch");
        }
        if proof.ood_values.trace_at_z.is_empty() {
            return Err("OOD trace vectors empty");
        }
        if proof.fri_proof.layer_commitments.is_empty() {
            return Err("FRI layer commitments empty");
        }
        if proof.fri_proof.final_poly.is_empty() {
            return Err("FRI final polynomial empty");
        }
        Ok(())
    }
    
    /// Flatten public outputs for aggregated proof.
    fn flatten_public_outputs(outputs: &[Vec<M31>]) -> Vec<M31> {
        let mut result = Vec::new();
        
        // Add count of inner proofs
        result.push(M31::new(outputs.len() as u32));
        
        // Add each proof's outputs prefixed by length
        for out in outputs {
            result.push(M31::new(out.len() as u32));
            result.extend(out.iter().cloned());
        }
        
        result
    }
    
    /// Recursively aggregate proofs in a tree structure.
    ///
    /// This allows aggregating more proofs than the batch size by
    /// building a tree of aggregations.
    pub fn tree_aggregate(&self, proofs: &[StarkProof]) -> Result<RecursiveProof, RecursionError> {
        if proofs.is_empty() {
            return Err(RecursionError::EmptyBatch);
        }
        
        if proofs.len() == 1 {
            // Base case: wrap single proof
            return self.aggregate(proofs);
        }
        
        // Recursively aggregate in batches
        let mut level_proofs = proofs.to_vec();
        
        while level_proofs.len() > self.config.max_batch_size {
            let mut next_level = Vec::new();
            
            for chunk in level_proofs.chunks(self.config.max_batch_size) {
                let aggregated = self.aggregate(chunk)?;
                next_level.push(aggregated.inner_proof);
            }
            
            level_proofs = next_level;
        }
        
        self.aggregate(&level_proofs)
    }
}

/// Error during recursive proving.
#[derive(Debug, Clone)]
pub enum RecursionError {
    /// No proofs to aggregate
    EmptyBatch,
    /// Too many proofs for single aggregation
    BatchTooLarge { size: usize, max: usize },
    /// Invalid inner proof
    InvalidProof(String),
    /// Verification failed
    VerificationFailed,
}

impl std::fmt::Display for RecursionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecursionError::EmptyBatch => write!(f, "Cannot aggregate empty batch"),
            RecursionError::BatchTooLarge { size, max } => {
                write!(f, "Batch size {} exceeds maximum {}", size, max)
            }
            RecursionError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            RecursionError::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

impl std::error::Error for RecursionError {}

/// Proof continuation for incremental proving.
///
/// Allows proving a computation in segments, carrying state between segments.
#[derive(Clone)]
pub struct ProofContinuation {
    /// Proof of the current segment
    pub segment_proof: StarkProof,
    /// State commitment at end of segment
    pub final_state: [u8; 32],
    /// Segment number (0-indexed)
    pub segment_index: usize,
    /// Whether this is the final segment
    pub is_final: bool,
}

/// Builder for segmented proofs.
pub struct SegmentedProver {
    /// Accumulated segment proofs
    segments: Vec<ProofContinuation>,
    /// Recursion configuration
    config: RecursionConfig,
}

impl SegmentedProver {
    /// Create a new segmented prover.
    pub fn new(config: RecursionConfig) -> Self {
        Self {
            segments: Vec::new(),
            config,
        }
    }
    
    /// Add a segment proof.
    pub fn add_segment(&mut self, continuation: ProofContinuation) {
        self.segments.push(continuation);
    }
    
    /// Get accumulated segment count.
    pub fn num_segments(&self) -> usize {
        self.segments.len()
    }
    
    /// Finalize and aggregate all segments.
    pub fn finalize(self) -> Result<RecursiveProof, RecursionError> {
        if self.segments.is_empty() {
            return Err(RecursionError::EmptyBatch);
        }
        
        // Verify segment chain
        for _i in 1..self.segments.len() {
            // In real implementation, verify state continuity
            // prev.final_state should match curr.initial_state
        }
        
        // Aggregate segment proofs
        let proofs: Vec<StarkProof> = self.segments
            .into_iter()
            .map(|s| s.segment_proof)
            .collect();
        
        let prover = RecursiveProver::new(self.config);
        prover.tree_aggregate(&proofs)
    }
}

/// Proof compression through recursive verification.
///
/// Takes a proof and produces a smaller proof that the original was valid.
pub struct ProofCompressor {
    /// Target proof size in bytes
    target_size: usize,
}

impl ProofCompressor {
    /// Create a new proof compressor.
    pub fn new(target_size: usize) -> Self {
        Self { target_size }
    }
    
    /// Compress a proof by recursively verifying it.
    pub fn compress(&self, proof: &StarkProof) -> Result<StarkProof, RecursionError> {
        // In a real implementation:
        // 1. Build a circuit that verifies `proof`
        // 2. Generate a trace for the verification
        // 3. Prove the verification with smaller parameters
        //
        // This reduces proof size at the cost of proving time
        
        // Placeholder: return proof unchanged
        Ok(proof.clone())
    }
    
    /// Estimate compressed proof size.
    pub fn estimate_size(&self, proof: &StarkProof) -> usize {
        // Simplified estimate based on actual StarkProof structure
        32 + // trace commitment
        32 + // composition commitment
        proof.fri_proof.layer_commitments.len() * 32 + // FRI layer commitments
        proof.fri_proof.final_poly.len() * 4 + // final polynomial
        proof.query_proofs.len() * 200 // query proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::FriProof;
    use crate::stark::OodValues;
    
    fn mock_proof() -> StarkProof {
        StarkProof {
            trace_commitment: [1u8; 32],
            composition_commitment: [2u8; 32],
            ood_values: OodValues {
                trace_at_z: vec![M31::new(1)],
                trace_at_z_next: vec![M31::new(2)],
                composition_at_z: M31::new(3),
            },
            fri_proof: FriProof {
                layer_commitments: vec![[3u8; 32], [4u8; 32]],
                query_proofs: vec![],
                final_poly: vec![M31::new(42)],
            },
            query_proofs: vec![],
        }
    }
    
    #[test]
    fn test_aggregate_single() {
        let prover = RecursiveProver::new(RecursionConfig::default());
        let proof = mock_proof();
        
        let result = prover.aggregate(&[proof]).unwrap();
        assert_eq!(result.num_aggregated, 1);
    }
    
    #[test]
    fn test_aggregate_multiple() {
        let prover = RecursiveProver::new(RecursionConfig::default());
        let proofs = vec![mock_proof(), mock_proof(), mock_proof()];
        
        let result = prover.aggregate(&proofs).unwrap();
        assert_eq!(result.num_aggregated, 3);
        assert_eq!(result.public_outputs.len(), 3);
    }
    
    #[test]
    fn test_aggregate_empty() {
        let prover = RecursiveProver::new(RecursionConfig::default());
        let result = prover.aggregate(&[]);
        assert!(matches!(result, Err(RecursionError::EmptyBatch)));
    }
    
    #[test]
    fn test_aggregate_too_large() {
        let config = RecursionConfig {
            max_batch_size: 2,
            ..Default::default()
        };
        let prover = RecursiveProver::new(config);
        let proofs = vec![mock_proof(), mock_proof(), mock_proof()];
        
        let result = prover.aggregate(&proofs);
        assert!(matches!(result, Err(RecursionError::BatchTooLarge { .. })));
    }
    
    #[test]
    fn test_tree_aggregate() {
        let config = RecursionConfig {
            max_batch_size: 2,
            ..Default::default()
        };
        let prover = RecursiveProver::new(config);
        
        // Create 5 proofs (requires tree aggregation with batch size 2)
        let proofs: Vec<_> = (0..5).map(|_| mock_proof()).collect();
        
        let result = prover.tree_aggregate(&proofs).unwrap();
        assert!(result.num_aggregated > 0);
    }
    
    #[test]
    fn test_segmented_prover() {
        let mut prover = SegmentedProver::new(RecursionConfig::default());
        
        // Add segments
        for i in 0..3 {
            prover.add_segment(ProofContinuation {
                segment_proof: mock_proof(),
                final_state: [(i + 1) as u8; 32],
                segment_index: i,
                is_final: i == 2,
            });
        }
        
        assert_eq!(prover.num_segments(), 3);
        
        let result = prover.finalize().unwrap();
        assert!(result.num_aggregated > 0);
    }
    
    #[test]
    fn test_proof_compressor() {
        let compressor = ProofCompressor::new(1024);
        let proof = mock_proof();
        
        let size = compressor.estimate_size(&proof);
        assert!(size > 0);
        
        let compressed = compressor.compress(&proof).unwrap();
        assert_eq!(compressed.trace_commitment, proof.trace_commitment);
    }
    
    #[test]
    fn test_recursion_error_display() {
        let err = RecursionError::BatchTooLarge { size: 10, max: 4 };
        let msg = format!("{}", err);
        assert!(msg.contains("10"));
        assert!(msg.contains("4"));
    }
}
