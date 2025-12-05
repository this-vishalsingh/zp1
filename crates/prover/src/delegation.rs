//! Delegation Argument for precompile circuit calls.
//!
//! This module implements the delegation mechanism that allows the main RISC-V
//! execution to call out to specialized precompile circuits (BLAKE2s, U256, etc.).
//!
//! # Delegation Protocol
//!
//! 1. **Trigger**: CSRRW opcode with specific CSR addresses triggers delegation
//! 2. **Set Equality**: Input/output tuples proven via log-derivative lookup
//! 3. **Separate Subtrees**: Each delegation type has its own Merkle subtree
//!
//! # Architecture
//!
//! ```text
//! Main Execution Trace                    Delegation Circuits
//! ┌─────────────────────┐                ┌──────────────────┐
//! │  ...                │                │  BLAKE2s Circuit │
//! │  CSRRW x1, 0xC00    │ ──────────────▶│  ┌────────────┐  │
//! │  (delegation call)  │   set equality │  │ Input      │  │
//! │  ...                │ ◀──────────────│  │ Processing │  │
//! │  CSRRW x2, 0xC01    │                │  │ Output     │  │
//! │  (result readback)  │                │  └────────────┘  │
//! └─────────────────────┘                └──────────────────┘
//! ```
//!
//! # CSR Address Mapping
//!
//! | CSR Address | Name | Function |
//! |-------------|------|----------|
//! | 0xC00 | DELEG_BLAKE2S | BLAKE2s hash delegation |
//! | 0xC01 | DELEG_BLAKE3 | BLAKE3 hash delegation |
//! | 0xC10 | DELEG_U256_ADD | U256 addition |
//! | 0xC11 | DELEG_U256_MUL | U256 multiplication |
//! | 0xC12 | DELEG_U256_MOD | U256 modular reduction |

use zp1_primitives::{M31, QM31};
use std::collections::HashMap;

/// Delegation CSR addresses.
pub mod csr {
    /// BLAKE2s hash delegation
    pub const DELEG_BLAKE2S: u32 = 0xC00;
    /// BLAKE3 hash delegation  
    pub const DELEG_BLAKE3: u32 = 0xC01;
    /// U256 addition
    pub const DELEG_U256_ADD: u32 = 0xC10;
    /// U256 multiplication
    pub const DELEG_U256_MUL: u32 = 0xC11;
    /// U256 modular reduction
    pub const DELEG_U256_MOD: u32 = 0xC12;
    /// Keccak-256 hash
    pub const DELEG_KECCAK: u32 = 0xC20;
    /// ECDSA verification
    pub const DELEG_ECDSA: u32 = 0xC30;
}

/// Delegation type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DelegationType {
    /// BLAKE2s hash computation
    Blake2s,
    /// BLAKE3 hash computation
    Blake3,
    /// U256 addition
    U256Add,
    /// U256 multiplication
    U256Mul,
    /// U256 modular reduction
    U256Mod,
    /// Keccak-256 hash
    Keccak,
    /// ECDSA signature verification
    Ecdsa,
}

impl DelegationType {
    /// Get delegation type from CSR address.
    pub fn from_csr(csr: u32) -> Option<Self> {
        match csr {
            csr::DELEG_BLAKE2S => Some(DelegationType::Blake2s),
            csr::DELEG_BLAKE3 => Some(DelegationType::Blake3),
            csr::DELEG_U256_ADD => Some(DelegationType::U256Add),
            csr::DELEG_U256_MUL => Some(DelegationType::U256Mul),
            csr::DELEG_U256_MOD => Some(DelegationType::U256Mod),
            csr::DELEG_KECCAK => Some(DelegationType::Keccak),
            csr::DELEG_ECDSA => Some(DelegationType::Ecdsa),
            _ => None,
        }
    }

    /// Get CSR address for this delegation type.
    pub fn to_csr(self) -> u32 {
        match self {
            DelegationType::Blake2s => csr::DELEG_BLAKE2S,
            DelegationType::Blake3 => csr::DELEG_BLAKE3,
            DelegationType::U256Add => csr::DELEG_U256_ADD,
            DelegationType::U256Mul => csr::DELEG_U256_MUL,
            DelegationType::U256Mod => csr::DELEG_U256_MOD,
            DelegationType::Keccak => csr::DELEG_KECCAK,
            DelegationType::Ecdsa => csr::DELEG_ECDSA,
        }
    }

    /// Convert to field element for constraint encoding.
    pub fn to_field(self) -> M31 {
        match self {
            DelegationType::Blake2s => M31::ZERO,
            DelegationType::Blake3 => M31::ONE,
            DelegationType::U256Add => M31::new(2),
            DelegationType::U256Mul => M31::new(3),
            DelegationType::U256Mod => M31::new(4),
            DelegationType::Keccak => M31::new(5),
            DelegationType::Ecdsa => M31::new(6),
        }
    }
}

/// A delegation call from the main execution.
#[derive(Debug, Clone)]
pub struct DelegationCall {
    /// Type of delegation
    pub deleg_type: DelegationType,
    /// Global timestamp when call was made
    pub timestamp: u64,
    /// Input data (memory addresses or immediate values)
    pub inputs: Vec<u32>,
    /// Output data (memory addresses for results)
    pub outputs: Vec<u32>,
    /// Unique call ID for matching
    pub call_id: u64,
}

impl DelegationCall {
    /// Create a new delegation call.
    pub fn new(
        deleg_type: DelegationType,
        timestamp: u64,
        inputs: Vec<u32>,
        outputs: Vec<u32>,
        call_id: u64,
    ) -> Self {
        Self { deleg_type, timestamp, inputs, outputs, call_id }
    }

    /// Compute fingerprint for log-derivative lookup.
    pub fn fingerprint(&self, alpha: QM31) -> QM31 {
        let mut fp = QM31::from(self.deleg_type.to_field());
        let mut alpha_power = alpha;
        
        // Include call ID
        fp = fp + alpha_power * QM31::from(M31::new((self.call_id & 0x7FFFFFFF) as u32));
        alpha_power = alpha_power * alpha;
        
        // Include timestamp
        fp = fp + alpha_power * QM31::from(M31::new((self.timestamp & 0x7FFFFFFF) as u32));
        alpha_power = alpha_power * alpha;
        
        // Include inputs
        for &input in &self.inputs {
            fp = fp + alpha_power * QM31::from(M31::new(input));
            alpha_power = alpha_power * alpha;
        }
        
        // Include outputs
        for &output in &self.outputs {
            fp = fp + alpha_power * QM31::from(M31::new(output));
            alpha_power = alpha_power * alpha;
        }
        
        fp
    }
}

/// A delegation result from a precompile circuit.
#[derive(Debug, Clone)]
pub struct DelegationResult {
    /// Type of delegation (must match call)
    pub deleg_type: DelegationType,
    /// Call ID (must match call)
    pub call_id: u64,
    /// Computed output values
    pub outputs: Vec<u32>,
    /// Proof of correct computation (circuit-specific)
    pub computation_proof: Vec<M31>,
}

impl DelegationResult {
    /// Create a new delegation result.
    pub fn new(
        deleg_type: DelegationType,
        call_id: u64,
        outputs: Vec<u32>,
        computation_proof: Vec<M31>,
    ) -> Self {
        Self { deleg_type, call_id, outputs, computation_proof }
    }
}

/// Delegation argument prover using log-derivative lookup.
pub struct DelegationArgumentProver {
    /// Delegation calls from main execution
    calls: Vec<DelegationCall>,
    /// Delegation results from precompile circuits
    results: Vec<DelegationResult>,
    /// Log-derivative challenge
    alpha: QM31,
    /// Batch challenge
    beta: QM31,
}

impl DelegationArgumentProver {
    /// Create a new delegation argument prover.
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            results: Vec::new(),
            alpha: QM31::ZERO,
            beta: QM31::ZERO,
        }
    }

    /// Add a delegation call.
    pub fn add_call(&mut self, call: DelegationCall) {
        self.calls.push(call);
    }

    /// Add a delegation result.
    pub fn add_result(&mut self, result: DelegationResult) {
        self.results.push(result);
    }

    /// Set log-derivative challenges.
    pub fn set_challenges(&mut self, alpha: QM31, beta: QM31) {
        self.alpha = alpha;
        self.beta = beta;
    }

    /// Generate delegation argument columns.
    pub fn generate_columns(&self) -> DelegationColumns {
        let n_calls = self.calls.len();
        let n_results = self.results.len();
        
        // Call columns
        let mut call_type = Vec::with_capacity(n_calls);
        let mut call_id = Vec::with_capacity(n_calls);
        let mut call_timestamp = Vec::with_capacity(n_calls);
        let mut call_fingerprints = Vec::with_capacity(n_calls);
        
        // Result columns  
        let mut result_type = Vec::with_capacity(n_results);
        let mut result_call_id = Vec::with_capacity(n_results);
        let mut result_fingerprints = Vec::with_capacity(n_results);
        
        for call in &self.calls {
            call_type.push(call.deleg_type.to_field());
            call_id.push(M31::new((call.call_id & 0x7FFFFFFF) as u32));
            call_timestamp.push(M31::new((call.timestamp & 0x7FFFFFFF) as u32));
            call_fingerprints.push(call.fingerprint(self.alpha));
        }
        
        for result in &self.results {
            result_type.push(result.deleg_type.to_field());
            result_call_id.push(M31::new((result.call_id & 0x7FFFFFFF) as u32));
            // Result fingerprint should match call fingerprint for same call_id
            result_fingerprints.push(self.compute_result_fingerprint(result));
        }
        
        // Compute log-derivative accumulator
        let (log_deriv_num, log_deriv_denom) = self.compute_log_derivative();
        
        DelegationColumns {
            call_type,
            call_id,
            call_timestamp,
            call_fingerprints,
            result_type,
            result_call_id,
            result_fingerprints,
            log_deriv_numerator: log_deriv_num,
            log_deriv_denominator: log_deriv_denom,
        }
    }

    /// Compute result fingerprint for set equality check.
    fn compute_result_fingerprint(&self, result: &DelegationResult) -> QM31 {
        let mut fp = QM31::from(result.deleg_type.to_field());
        let mut alpha_power = self.alpha;
        
        // Include call ID
        fp = fp + alpha_power * QM31::from(M31::new((result.call_id & 0x7FFFFFFF) as u32));
        alpha_power = alpha_power * self.alpha;
        
        // Include outputs (inputs not needed - they're determined by call)
        for &output in &result.outputs {
            fp = fp + alpha_power * QM31::from(M31::new(output));
            alpha_power = alpha_power * self.alpha;
        }
        
        fp
    }

    /// Compute log-derivative accumulator for set equality.
    /// 
    /// For set equality, we need: Σ 1/(call_fp + β) = Σ 1/(result_fp + β)
    fn compute_log_derivative(&self) -> (Vec<QM31>, Vec<QM31>) {
        let n = self.calls.len().max(self.results.len());
        let mut numerator = vec![QM31::ONE; n];
        let mut denominator = vec![QM31::ONE; n];
        
        // Accumulate call fingerprints
        let mut call_prod = QM31::ONE;
        for (i, call) in self.calls.iter().enumerate() {
            let fp = call.fingerprint(self.alpha) + self.beta;
            call_prod = call_prod * fp;
            if i < numerator.len() {
                numerator[i] = call_prod;
            }
        }
        
        // Accumulate result fingerprints
        let mut result_prod = QM31::ONE;
        for (i, result) in self.results.iter().enumerate() {
            let fp = self.compute_result_fingerprint(result) + self.beta;
            result_prod = result_prod * fp;
            if i < denominator.len() {
                denominator[i] = result_prod;
            }
        }
        
        (numerator, denominator)
    }

    /// Verify delegation argument (for testing/debugging).
    pub fn verify(&self) -> Result<(), DelegationError> {
        // Check that every call has exactly one matching result
        let mut result_map: HashMap<u64, &DelegationResult> = HashMap::new();
        for result in &self.results {
            if result_map.insert(result.call_id, result).is_some() {
                return Err(DelegationError::DuplicateResult { call_id: result.call_id });
            }
        }
        
        for call in &self.calls {
            match result_map.get(&call.call_id) {
                None => {
                    return Err(DelegationError::MissingResult { call_id: call.call_id });
                }
                Some(result) => {
                    if result.deleg_type != call.deleg_type {
                        return Err(DelegationError::TypeMismatch {
                            call_id: call.call_id,
                            expected: call.deleg_type,
                            actual: result.deleg_type,
                        });
                    }
                }
            }
        }
        
        Ok(())
    }

    /// Get calls grouped by delegation type (for parallel circuit proving).
    pub fn by_type(&self) -> HashMap<DelegationType, Vec<&DelegationCall>> {
        let mut grouped = HashMap::new();
        for call in &self.calls {
            grouped.entry(call.deleg_type).or_insert_with(Vec::new).push(call);
        }
        grouped
    }
}

impl Default for DelegationArgumentProver {
    fn default() -> Self {
        Self::new()
    }
}

/// Generated delegation argument columns.
#[derive(Debug, Clone)]
pub struct DelegationColumns {
    // Call columns (from main execution)
    pub call_type: Vec<M31>,
    pub call_id: Vec<M31>,
    pub call_timestamp: Vec<M31>,
    pub call_fingerprints: Vec<QM31>,
    
    // Result columns (from precompile circuits)
    pub result_type: Vec<M31>,
    pub result_call_id: Vec<M31>,
    pub result_fingerprints: Vec<QM31>,
    
    // Log-derivative accumulator
    pub log_deriv_numerator: Vec<QM31>,
    pub log_deriv_denominator: Vec<QM31>,
}

/// Delegation argument error.
#[derive(Debug, Clone)]
pub enum DelegationError {
    /// Delegation call without matching result
    MissingResult { call_id: u64 },
    /// Duplicate result for same call
    DuplicateResult { call_id: u64 },
    /// Type mismatch between call and result
    TypeMismatch {
        call_id: u64,
        expected: DelegationType,
        actual: DelegationType,
    },
    /// Invalid inputs for delegation type
    InvalidInputs {
        deleg_type: DelegationType,
        message: String,
    },
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::MissingResult { call_id } => {
                write!(f, "Missing result for delegation call {}", call_id)
            }
            DelegationError::DuplicateResult { call_id } => {
                write!(f, "Duplicate result for delegation call {}", call_id)
            }
            DelegationError::TypeMismatch { call_id, expected, actual } => {
                write!(f, "Type mismatch for call {}: expected {:?}, got {:?}", 
                       call_id, expected, actual)
            }
            DelegationError::InvalidInputs { deleg_type, message } => {
                write!(f, "Invalid inputs for {:?}: {}", deleg_type, message)
            }
        }
    }
}

impl std::error::Error for DelegationError {}

/// Memory subtree for delegation circuit.
/// 
/// Each delegation type has its own Merkle subtree for pre-commitment,
/// enabling parallel proving of delegation circuits.
#[derive(Debug, Clone)]
pub struct DelegationSubtree {
    /// Delegation type for this subtree
    pub deleg_type: DelegationType,
    /// Calls processed by this circuit
    pub calls: Vec<DelegationCall>,
    /// Results computed by this circuit
    pub results: Vec<DelegationResult>,
    /// Commitment to this subtree
    pub commitment: [u8; 32],
}

impl DelegationSubtree {
    /// Create a new delegation subtree.
    pub fn new(deleg_type: DelegationType) -> Self {
        Self {
            deleg_type,
            calls: Vec::new(),
            results: Vec::new(),
            commitment: [0u8; 32],
        }
    }

    /// Process a call and compute result.
    pub fn process_call(&mut self, call: DelegationCall) -> DelegationResult {
        let outputs = self.compute_delegation(&call);
        let result = DelegationResult::new(
            call.deleg_type,
            call.call_id,
            outputs,
            Vec::new(), // Computation proof filled by circuit
        );
        
        self.calls.push(call);
        self.results.push(result.clone());
        result
    }

    /// Compute delegation output (placeholder - real impl in delegation crate).
    fn compute_delegation(&self, call: &DelegationCall) -> Vec<u32> {
        match self.deleg_type {
            DelegationType::Blake2s => {
                // Placeholder: return hash of inputs
                vec![0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0]
            }
            DelegationType::Blake3 => {
                vec![0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0]
            }
            DelegationType::U256Add => {
                // Simple placeholder: assume 8 u32 limbs, return sum
                if call.inputs.len() >= 16 {
                    let mut result = vec![0u32; 8];
                    let mut carry = 0u64;
                    for i in 0..8 {
                        let sum = call.inputs[i] as u64 + call.inputs[i + 8] as u64 + carry;
                        result[i] = sum as u32;
                        carry = sum >> 32;
                    }
                    result
                } else {
                    call.outputs.clone()
                }
            }
            _ => call.outputs.clone(),
        }
    }

    /// Get columns for this delegation subtree.
    pub fn get_columns(&self) -> Vec<Vec<M31>> {
        let n = self.calls.len();
        let mut type_col = Vec::with_capacity(n);
        let mut call_id_col = Vec::with_capacity(n);
        
        for call in &self.calls {
            type_col.push(call.deleg_type.to_field());
            call_id_col.push(M31::new((call.call_id & 0x7FFFFFFF) as u32));
        }
        
        vec![type_col, call_id_col]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_type_from_csr() {
        assert_eq!(DelegationType::from_csr(0xC00), Some(DelegationType::Blake2s));
        assert_eq!(DelegationType::from_csr(0xC10), Some(DelegationType::U256Add));
        assert_eq!(DelegationType::from_csr(0x123), None);
    }

    #[test]
    fn test_delegation_call_fingerprint() {
        let call = DelegationCall::new(
            DelegationType::Blake2s,
            100,
            vec![0x1000, 0x2000],
            vec![0x3000],
            1,
        );
        
        let alpha = QM31::from(M31::new(7));
        let fp1 = call.fingerprint(alpha);
        let fp2 = call.fingerprint(alpha);
        
        // Same call should give same fingerprint
        assert_eq!(fp1, fp2);
        
        // Different call should give different fingerprint
        let call2 = DelegationCall::new(
            DelegationType::Blake2s,
            100,
            vec![0x1000, 0x2001], // Different input
            vec![0x3000],
            1,
        );
        let fp3 = call2.fingerprint(alpha);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_delegation_argument_verify_valid() {
        let mut prover = DelegationArgumentProver::new();
        
        prover.add_call(DelegationCall::new(
            DelegationType::Blake2s, 100, vec![0x1000], vec![0x2000], 1
        ));
        prover.add_call(DelegationCall::new(
            DelegationType::U256Add, 200, vec![0x3000], vec![0x4000], 2
        ));
        
        prover.add_result(DelegationResult::new(
            DelegationType::Blake2s, 1, vec![0xABCD], vec![]
        ));
        prover.add_result(DelegationResult::new(
            DelegationType::U256Add, 2, vec![0xEF01], vec![]
        ));
        
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_delegation_argument_verify_missing_result() {
        let mut prover = DelegationArgumentProver::new();
        
        prover.add_call(DelegationCall::new(
            DelegationType::Blake2s, 100, vec![0x1000], vec![0x2000], 1
        ));
        // No result added!
        
        let result = prover.verify();
        assert!(result.is_err());
        
        if let Err(DelegationError::MissingResult { call_id }) = result {
            assert_eq!(call_id, 1);
        } else {
            panic!("Expected MissingResult error");
        }
    }

    #[test]
    fn test_delegation_argument_verify_type_mismatch() {
        let mut prover = DelegationArgumentProver::new();
        
        prover.add_call(DelegationCall::new(
            DelegationType::Blake2s, 100, vec![0x1000], vec![0x2000], 1
        ));
        prover.add_result(DelegationResult::new(
            DelegationType::U256Add, 1, vec![0xABCD], vec![] // Wrong type!
        ));
        
        let result = prover.verify();
        assert!(result.is_err());
        
        if let Err(DelegationError::TypeMismatch { expected, actual, .. }) = result {
            assert_eq!(expected, DelegationType::Blake2s);
            assert_eq!(actual, DelegationType::U256Add);
        }
    }

    #[test]
    fn test_delegation_subtree() {
        let mut subtree = DelegationSubtree::new(DelegationType::Blake2s);
        
        let call = DelegationCall::new(
            DelegationType::Blake2s, 100, vec![0x1000, 0x2000], vec![], 1
        );
        
        let result = subtree.process_call(call);
        
        assert_eq!(result.deleg_type, DelegationType::Blake2s);
        assert_eq!(result.call_id, 1);
        assert!(!result.outputs.is_empty());
    }

    #[test]
    fn test_by_type() {
        let mut prover = DelegationArgumentProver::new();
        
        prover.add_call(DelegationCall::new(DelegationType::Blake2s, 100, vec![], vec![], 1));
        prover.add_call(DelegationCall::new(DelegationType::U256Add, 200, vec![], vec![], 2));
        prover.add_call(DelegationCall::new(DelegationType::Blake2s, 300, vec![], vec![], 3));
        
        let by_type = prover.by_type();
        
        assert_eq!(by_type.get(&DelegationType::Blake2s).map(|v| v.len()), Some(2));
        assert_eq!(by_type.get(&DelegationType::U256Add).map(|v| v.len()), Some(1));
    }
}
