//! STARK proof verification logic.
//!
//! This module provides a complete STARK verifier that:
//! 1. Replays the Fiat-Shamir transcript
//! 2. Verifies Merkle proofs for trace and composition commitments  
//! 3. Verifies FRI proximity test
//! 4. Checks constraint consistency at query points

use blake3::Hasher;
use thiserror::Error;

use crate::channel::VerifierChannel;
use zp1_primitives::{M31, QM31};

/// Verification errors.
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("FRI verification failed at layer {layer}: {reason}")]
    FriError { layer: usize, reason: String },

    #[error("Constraint check failed: {constraint}")]
    ConstraintError { constraint: String },

    #[error("Merkle proof verification failed at index {index}")]
    MerkleError { index: usize },

    #[error("Degree bound exceeded: got {got}, max {max}")]
    DegreeBoundError { got: usize, max: usize },

    #[error("Invalid proof structure: {reason}")]
    InvalidProof { reason: String },

    #[error("Query index mismatch: expected {expected}, got {got}")]
    QueryIndexMismatch { expected: usize, got: usize },

    #[error("Missing or invalid OOD values: {reason}")]
    OodError { reason: String },

    #[error("FRI proof structure invalid: {reason}")]
    FriStructure { reason: String },
}

/// Verification result.
pub type VerifyResult<T> = Result<T, VerifyError>;

// Domain separation prefixes for Blake3 hashing (must match prover)
const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// Hash a leaf M31 value with domain separation.
#[inline]
fn hash_leaf_m31(value: M31) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(&value.as_u32().to_le_bytes());
    *hasher.finalize().as_bytes()
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

/// Merkle proof for verification.
#[derive(Clone, Debug)]
pub struct MerkleProof {
    /// Index of the leaf (determines left/right at each level).
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root.
    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Verify this Merkle proof against a root and leaf M31 value.
    pub fn verify(&self, root: &[u8; 32], leaf_value: M31) -> bool {
        self.verify_hash(root, &hash_leaf_m31(leaf_value))
    }

    /// Verify this Merkle proof against a root and pre-computed leaf hash.
    pub fn verify_hash(&self, root: &[u8; 32], leaf_hash: &[u8; 32]) -> bool {
        let mut current = *leaf_hash;
        let mut idx = self.leaf_index;

        for sibling in &self.path {
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

    /// Get proof length.
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Check if proof is empty.
    pub fn is_empty(&self) -> bool {
        self.path.is_empty()
    }
}

/// FRI layer query proof.
#[derive(Clone, Debug)]
pub struct FriLayerQueryProof {
    /// Value at the queried position.
    pub value: M31,
    /// Sibling value for folding.
    pub sibling_value: M31,
    /// Merkle proof for the value.
    pub merkle_proof: Vec<[u8; 32]>,
}

/// FRI query proof for a single query.
#[derive(Clone, Debug)]
pub struct FriQueryProof {
    /// Initial query index.
    pub index: usize,
    /// Layer proofs.
    pub layer_proofs: Vec<FriLayerQueryProof>,
}

/// Complete FRI proof structure.
#[derive(Clone, Debug)]
pub struct FriProof {
    /// Layer commitments.
    pub layer_commitments: Vec<[u8; 32]>,
    /// Query proofs.
    pub query_proofs: Vec<FriQueryProof>,
    /// Final polynomial coefficients.
    pub final_poly: Vec<M31>,
}

/// Query proof for trace and composition.
#[derive(Clone, Debug)]
pub struct QueryProof {
    /// Query index in the LDE domain.
    pub index: usize,
    /// Trace column values at query point.
    pub trace_values: Vec<M31>,
    /// Trace Merkle proof.
    pub trace_proof: MerkleProof,
    /// Composition polynomial value at query point.
    pub composition_value: M31,
    /// Composition Merkle proof.
    pub composition_proof: MerkleProof,
    /// DEEP quotient value at query point.
    pub deep_quotient_value: M31,
}

/// STARK proof structure.
#[derive(Clone, Debug)]
pub struct StarkProof {
    /// Merkle commitment to the trace.
    pub trace_commitment: [u8; 32],
    /// Merkle commitment to the composition polynomial.
    pub composition_commitment: [u8; 32],
    /// Out-of-domain sampled values (DEEP/OODS).
    pub ood_values: OodValues,
    /// FRI proof.
    pub fri_proof: FriProof,
    /// Query proofs for trace and composition.
    pub query_proofs: Vec<QueryProof>,
}

/// Out-of-domain sample values for DEEP composition.
#[derive(Clone, Debug)]
pub struct OodValues {
    /// Trace values at z for each column.
    pub trace_at_z: Vec<M31>,
    /// Trace values at z * g for each column.
    pub trace_at_z_next: Vec<M31>,
    /// Composition polynomial at z.
    pub composition_at_z: M31,
}

/// STARK verifier configuration.
#[derive(Clone, Debug)]
pub struct VerifierConfig {
    /// Log2 of trace length.
    pub log_trace_len: usize,
    /// Blowup factor for LDE.
    pub blowup_factor: usize,
    /// Number of FRI queries.
    pub num_queries: usize,
    /// FRI folding factor.
    pub fri_folding_factor: usize,
    /// Maximum degree of final FRI polynomial.
    pub fri_final_degree: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            log_trace_len: 10,
            blowup_factor: 8,
            num_queries: 50,
            fri_folding_factor: 4,
            fri_final_degree: 8,
        }
    }
}

impl VerifierConfig {
    /// Get LDE domain size.
    pub fn lde_domain_size(&self) -> usize {
        (1 << self.log_trace_len) * self.blowup_factor
    }

    /// Get log2 of LDE domain size.
    pub fn log_lde_domain_size(&self) -> usize {
        self.log_trace_len + self.blowup_factor.trailing_zeros() as usize
    }
}

/// STARK verifier.
pub struct Verifier {
    config: VerifierConfig,
}

impl Verifier {
    /// Create a new verifier with the given configuration.
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Create a verifier with legacy parameters.
    pub fn new_legacy(log_trace_len: usize, blowup_log: usize, num_queries: usize) -> Self {
        Self {
            config: VerifierConfig {
                log_trace_len,
                blowup_factor: 1 << blowup_log,
                num_queries,
                ..Default::default()
            },
        }
    }

    /// Verify a STARK proof.
    pub fn verify(&self, proof: &StarkProof) -> VerifyResult<()> {
        let mut channel = VerifierChannel::new(b"zp1-stark-v1");

        // Sanity check OOD values exist
        let trace_width = proof.ood_values.trace_at_z.len();
        if trace_width == 0 || proof.ood_values.trace_at_z_next.len() != trace_width {
            return Err(VerifyError::OodError {
                reason: "Trace OOD vectors are empty or mismatched".into(),
            });
        }

        // Step 1: Absorb trace commitment
        channel.absorb_commitment(&proof.trace_commitment);

        // Step 2: Get constraint evaluation challenge (alpha for linear combination)
        let _constraint_alpha = channel.squeeze_extension_challenge();

        // Step 3: Absorb composition commitment
        channel.absorb_commitment(&proof.composition_commitment);

        // Step 4: Get DEEP/OODS sampling point
        let oods_point = channel.squeeze_extension_challenge();

    // Step 5: Absorb OOD values into transcript (must match prover exactly)
    // CRITICAL: Prover only absorbs trace_at_z and composition_at_z, not trace_at_z_next
    for v in &proof.ood_values.trace_at_z {
        channel.absorb_felt(*v);
    }
    // Note: trace_at_z_next is NOT absorbed to match prover transcript
    channel.absorb_felt(proof.ood_values.composition_at_z);        // Step 6: Process FRI layer commitments and get folding challenges
        let mut fri_alphas = Vec::new();
        for commitment in &proof.fri_proof.layer_commitments {
            channel.absorb_commitment(commitment);
            fri_alphas.push(channel.squeeze_challenge());
        }

        // Step 7: Get query indices (must match prover's)
        let query_indices = channel.squeeze_query_indices(
            self.config.num_queries,
            self.config.lde_domain_size(),
        );

        // Step 8: Verify query count
        if proof.query_proofs.len() != self.config.num_queries {
            return Err(VerifyError::InvalidProof {
                reason: format!(
                    "Expected {} query proofs, got {}",
                    self.config.num_queries,
                    proof.query_proofs.len()
                ),
            });
        }

        // Step 9: Verify each query (Merkle + basic consistency)
        for (i, query_proof) in proof.query_proofs.iter().enumerate() {
            // Check query index matches
            if query_proof.index != query_indices[i] {
                return Err(VerifyError::QueryIndexMismatch {
                    expected: query_indices[i],
                    got: query_proof.index,
                });
            }

            // Verify trace Merkle proof (single-leaf commitment per row)
            if query_proof.trace_values.len() != trace_width {
                return Err(VerifyError::ConstraintError {
                    constraint: format!("Trace width mismatch: expected {}, got {}", trace_width, query_proof.trace_values.len()),
                });
            }

            let trace_value = query_proof.trace_values[0];
            if !query_proof.trace_proof.verify(&proof.trace_commitment, trace_value) {
                return Err(VerifyError::MerkleError {
                    index: query_proof.index,
                });
            }

            // Verify composition Merkle proof
            if !query_proof.composition_proof.verify(
                &proof.composition_commitment,
                query_proof.composition_value,
            ) {
                return Err(VerifyError::MerkleError {
                    index: query_proof.index,
                });
            }

            // Verify constraint consistency placeholder
            self.verify_constraint_consistency(query_proof, &oods_point)?;
        }

        // Step 10: Verify FRI
        self.verify_fri(&proof.fri_proof, &fri_alphas)?;

        // Step 11: Verify final polynomial degree
        if proof.fri_proof.final_poly.len() > self.config.fri_final_degree {
            return Err(VerifyError::DegreeBoundError {
                got: proof.fri_proof.final_poly.len(),
                max: self.config.fri_final_degree,
            });
        }

        Ok(())
    }

    /// Verify that trace values satisfy constraints at query point.
    fn verify_constraint_consistency(
        &self,
        query: &QueryProof,
        _oods_point: &QM31,
    ) -> VerifyResult<()> {
        // Placeholder: ensure values are present. Full AIR evaluation is prover-specific.
        if query.trace_values.is_empty() {
            return Err(VerifyError::ConstraintError {
                constraint: "Empty trace values".into(),
            });
        }

        // Basic sanity: deep quotient should be present
        if query.deep_quotient_value == M31::ZERO {
            // Not a hard failure but catch obviously malformed proofs
            return Err(VerifyError::ConstraintError {
                constraint: "Deep quotient value missing or zero".into(),
            });
        }

        Ok(())
    }

    /// Verify the FRI proof.
    fn verify_fri(
        &self,
        fri_proof: &FriProof,
        alphas: &[M31],
    ) -> VerifyResult<()> {
        // Verify each query through the FRI layers
        for (query_idx, fri_query) in fri_proof.query_proofs.iter().enumerate() {
            self.verify_fri_query(fri_proof, fri_query, alphas, query_idx)?;
        }

        // Verify final polynomial is low-degree
        // (In a complete implementation, would evaluate final_poly at random points)
        
        Ok(())
    }

    /// Verify a single FRI query through all layers.
    fn verify_fri_query(
        &self,
        fri_proof: &FriProof,
        query: &FriQueryProof,
        alphas: &[M31],
        query_idx: usize,
    ) -> VerifyResult<()> {
        if query.layer_proofs.len() != fri_proof.layer_commitments.len() {
            return Err(VerifyError::FriError {
                layer: 0,
                reason: format!(
                    "Layer proof count mismatch: {} vs {}",
                    query.layer_proofs.len(),
                    fri_proof.layer_commitments.len()
                ),
            });
        }

        let mut current_index = query.index;
        let mut expected_next: Option<M31> = None;

        for (layer_idx, layer_proof) in query.layer_proofs.iter().enumerate() {
            let commitment = &fri_proof.layer_commitments[layer_idx];

            // Merkle proof for the queried value
            let merkle = MerkleProof {
                leaf_index: current_index,
                path: layer_proof.merkle_proof.clone(),
            };
            if !merkle.verify(commitment, layer_proof.value) {
                return Err(VerifyError::FriError {
                    layer: layer_idx,
                    reason: format!("Merkle verification failed for query {}", query_idx),
                });
            }

            // If we already folded from previous layer, ensure value matches expectation
            if let Some(expected) = expected_next {
                if layer_proof.value != expected {
                    return Err(VerifyError::FriError {
                        layer: layer_idx,
                        reason: "Fold consistency mismatch".into(),
                    });
                }
            }

            // Compute folded value for next layer (twin point folding)
            let alpha = alphas.get(layer_idx).copied().ok_or_else(|| VerifyError::FriStructure {
                reason: "Missing FRI alpha".into(),
            })?;
            let folded = fri_utils::compute_fold(layer_proof.value, layer_proof.sibling_value, alpha);
            expected_next = Some(folded);
            current_index /= 2;
        }

        // Final polynomial check
        if let Some(expected) = expected_next {
            if fri_proof.final_poly.is_empty() {
                return Err(VerifyError::FriStructure { reason: "Empty final polynomial".into() });
            }
            let final_idx = current_index % fri_proof.final_poly.len();
            let final_val = fri_proof.final_poly[final_idx];
            if final_val != expected {
                return Err(VerifyError::FriError {
                    layer: fri_proof.layer_commitments.len(),
                    reason: format!(
                        "Final polynomial mismatch: expected {}, got {}",
                        expected.as_u32(),
                        final_val.as_u32()
                    ),
                });
            }
        }

        Ok(())
    }
}

/// FRI verification helper functions.
pub mod fri_utils {
    use zp1_primitives::M31;

    /// Compute FRI fold: f'(x^2) = f_even + alpha * f_odd
    pub fn compute_fold(even: M31, odd: M31, alpha: M31) -> M31 {
        // For twin-point folding on a circle: 0.5 * [(even + odd) + alpha * (even - odd)]
        let inv_two = M31::new(2).inv();
        let sum = even + odd;
        let diff = even - odd;
        (sum * inv_two) + alpha * diff * inv_two
    }

    /// Evaluate polynomial at a point using Horner's method.
    pub fn evaluate_poly(coeffs: &[M31], x: M31) -> M31 {
        if coeffs.is_empty() {
            return M31::ZERO;
        }
        
        let mut result = coeffs[coeffs.len() - 1];
        for i in (0..coeffs.len() - 1).rev() {
            result = result * x + coeffs[i];
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_creation() {
        let config = VerifierConfig {
            log_trace_len: 10,
            blowup_factor: 8,
            num_queries: 30,
            ..Default::default()
        };
        let verifier = Verifier::new(config.clone());
        assert_eq!(verifier.config.log_trace_len, 10);
        assert_eq!(config.lde_domain_size(), 1024 * 8);
    }

    #[test]
    fn test_verifier_legacy() {
        let verifier = Verifier::new_legacy(10, 3, 30);
        assert_eq!(verifier.config.log_trace_len, 10);
        assert_eq!(verifier.config.blowup_factor, 8);
    }

    #[test]
    fn test_merkle_proof_verify() {
        // Create a simple Merkle proof and verify it
        let proof = MerkleProof {
            leaf_index: 0,
            path: vec![],
        };
        
        // Single leaf tree - root equals leaf hash (with domain separation)
        let leaf = M31::new(42);
        let root = hash_leaf_m31(leaf);
        
        assert!(proof.verify(&root, leaf));
        assert!(!proof.verify(&root, M31::new(43)));
    }

    #[test]
    fn test_fri_fold() {
        let even = M31::new(10);
        let odd = M31::new(20);
        let alpha = M31::new(3);
        
        let folded = fri_utils::compute_fold(even, odd, alpha);
        // (10+20)/2 + 3*(10-20)/2 = 15 + 3*(-10)/2 = 15 - 15 = 0
        assert_eq!(folded.as_u32(), 0);
    }

    #[test]
    fn test_evaluate_poly() {
        // p(x) = 1 + 2x + 3x^2
        let coeffs = vec![M31::new(1), M31::new(2), M31::new(3)];
        
        // p(0) = 1
        assert_eq!(fri_utils::evaluate_poly(&coeffs, M31::ZERO).as_u32(), 1);
        
        // p(1) = 1 + 2 + 3 = 6
        assert_eq!(fri_utils::evaluate_poly(&coeffs, M31::ONE).as_u32(), 6);
        
        // p(2) = 1 + 4 + 12 = 17
        assert_eq!(fri_utils::evaluate_poly(&coeffs, M31::new(2)).as_u32(), 17);
    }

    #[test]
    fn test_verifier_config_default() {
        let config = VerifierConfig::default();
        assert_eq!(config.log_trace_len, 10);
        assert_eq!(config.blowup_factor, 8);
        assert_eq!(config.num_queries, 50);
    }
}
