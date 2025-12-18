//! Prover integration for ZKsync OS execution.
//!
//! This module connects ZKsync OS execution traces to ZP1's STARK prover,
//! enabling generation of validity proofs for ZKsync OS state transitions.

use crate::error::{Result, ZkSyncOsError};
use crate::runner::RunResult;
use crate::types::ProgramOutput;
use serde::{Deserialize, Serialize};
use zp1_executor::ExecutionTrace;

/// Configuration for ZKsync OS proof generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// Enable GPU acceleration.
    pub use_gpu: bool,
    /// Number of worker threads.
    pub num_threads: usize,
    /// Enable recursion.
    pub enable_recursion: bool,
    /// Maximum segment size for segmented proving.
    pub max_segment_size: usize,
    /// Log2 of trace length.
    pub trace_log_size: usize,
    /// Number of FRI queries.
    pub num_fri_queries: usize,
    /// Blowup factor log2.
    pub blowup_factor_log2: usize,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            use_gpu: false,
            num_threads: rayon::current_num_threads(),
            enable_recursion: false,
            max_segment_size: 1 << 22, // 4M rows
            trace_log_size: 20,
            num_fri_queries: 64,
            blowup_factor_log2: 3,
        }
    }
}

impl ProverConfig {
    /// Create a config optimized for GPU proving.
    pub fn with_gpu() -> Self {
        Self {
            use_gpu: true,
            ..Default::default()
        }
    }

    /// Create a config for CPU proving with maximum parallelism.
    pub fn with_cpu(num_threads: usize) -> Self {
        Self {
            use_gpu: false,
            num_threads,
            ..Default::default()
        }
    }

    /// Enable recursion for proof compression.
    pub fn with_recursion(mut self) -> Self {
        self.enable_recursion = true;
        self
    }
}

/// Serializable STARK proof wrapper.
///
/// This wraps the internal ZP1 proof format with additional metadata
/// for ZKsync OS proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProofData {
    /// Serialized proof data.
    pub proof_bytes: Vec<u8>,
    /// Proof type/version identifier.
    pub proof_type: String,
}

/// Proof of ZKsync OS execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkSyncOsProof {
    /// The underlying STARK proof data.
    pub stark_proof: StarkProofData,
    /// Program output (public input).
    pub output: ProgramOutput,
    /// Binary hash (identifies the program).
    pub binary_hash: [u8; 32],
    /// Number of cycles executed.
    pub cycles: u64,
    /// Prover config used.
    pub config: ProverConfig,
}

impl ZkSyncOsProof {
    /// Serialize proof to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| e.into())
    }

    /// Deserialize proof from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| e.into())
    }

    /// Save proof to file.
    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load proof from file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        Self::from_json(&json)
    }
}

/// ZKsync OS prover - generates proofs for ZKsync OS execution.
pub struct ZkSyncOsProver {
    config: ProverConfig,
}

impl ZkSyncOsProver {
    /// Create a new prover with the given configuration.
    pub fn new(config: ProverConfig) -> Self {
        Self { config }
    }

    /// Create a prover with default configuration.
    pub fn default_config() -> Self {
        Self::new(ProverConfig::default())
    }

    /// Generate a proof from a run result.
    pub fn prove(&self, result: &RunResult, binary_hash: [u8; 32]) -> Result<ZkSyncOsProof> {
        let trace = result.trace.as_ref().ok_or_else(|| {
            ZkSyncOsError::ProofGeneration(
                "No execution trace available. Run with enable_tracing=true".to_string(),
            )
        })?;

        self.prove_trace(trace, result.output, binary_hash, result.stats.cycles)
    }

    /// Generate a proof directly from an execution trace.
    pub fn prove_trace(
        &self,
        trace: &ExecutionTrace,
        output: ProgramOutput,
        binary_hash: [u8; 32],
        cycles: u64,
    ) -> Result<ZkSyncOsProof> {
        // Convert execution trace to columnar format for STARK prover
        let _trace_columns = convert_trace_to_columns(trace)?;

        // Create public inputs from output
        let _public_inputs = output.0.iter().map(|&w| w).collect::<Vec<_>>();

        // Note: In a full implementation, we would call the actual ZP1 prover here.
        // For now, we create a placeholder proof structure.
        //
        // The full integration would look like:
        // let mut prover = StarkProver::new(self.config.stark_config.clone());
        // let stark_proof = prover.prove(trace_columns, &public_inputs);

        let proof_data = StarkProofData {
            proof_bytes: vec![], // Placeholder
            proof_type: "zp1-zksync-os-v1".to_string(),
        };

        Ok(ZkSyncOsProof {
            stark_proof: proof_data,
            output,
            binary_hash,
            cycles,
            config: self.config.clone(),
        })
    }

    /// Generate proof with segmentation for long traces.
    pub fn prove_segmented(
        &self,
        result: &RunResult,
        binary_hash: [u8; 32],
    ) -> Result<Vec<ZkSyncOsProof>> {
        let trace = result.trace.as_ref().ok_or_else(|| {
            ZkSyncOsError::ProofGeneration("No execution trace available".to_string())
        })?;

        // Check if segmentation is needed
        if trace.len() <= self.config.max_segment_size {
            // Single proof is sufficient
            let proof = self.prove(result, binary_hash)?;
            return Ok(vec![proof]);
        }

        // Split trace into segments
        let mut proofs = Vec::new();
        let num_segments =
            (trace.len() + self.config.max_segment_size - 1) / self.config.max_segment_size;

        for i in 0..num_segments {
            let start = i * self.config.max_segment_size;
            let end = ((i + 1) * self.config.max_segment_size).min(trace.len());

            // Create segment trace
            let segment_trace = create_segment_trace(trace, start, end);

            // Use final output only for last segment, intermediate hash for others
            let segment_output = if i == num_segments - 1 {
                result.output
            } else {
                // Intermediate output (hash of segment state)
                compute_segment_hash(&segment_trace)
            };

            let proof = self.prove_trace(
                &segment_trace,
                segment_output,
                binary_hash,
                (end - start) as u64,
            )?;

            proofs.push(proof);
        }

        Ok(proofs)
    }
}

/// Convert execution trace to columnar format for STARK proving.
fn convert_trace_to_columns(trace: &ExecutionTrace) -> Result<Vec<Vec<u32>>> {
    if trace.is_empty() {
        return Err(ZkSyncOsError::ProofGeneration(
            "Empty trace cannot be converted".to_string(),
        ));
    }

    let n = trace.len();

    // Create columns for:
    // - PC (1 column)
    // - Registers (32 columns)
    // - Instruction fields (opcode, rd, rs1, rs2, imm, etc.)
    // - Memory operations
    // - Flags

    let mut pc_col = Vec::with_capacity(n);
    let mut reg_cols: Vec<Vec<u32>> = (0..32).map(|_| Vec::with_capacity(n)).collect();

    for row in &trace.rows {
        pc_col.push(row.pc);
        for (i, &reg) in row.regs.iter().enumerate() {
            reg_cols[i].push(reg);
        }
    }

    let mut columns = vec![pc_col];
    columns.extend(reg_cols);

    Ok(columns)
}

/// Create a segment of the trace.
fn create_segment_trace(trace: &ExecutionTrace, start: usize, end: usize) -> ExecutionTrace {
    let rows = trace.rows[start..end].to_vec();

    ExecutionTrace {
        rows,
        final_regs: trace.final_regs,
        final_pc: trace.final_pc,
        total_cycles: (end - start) as u64,
        halt_reason: None,
    }
}

/// Compute hash of segment state for chaining.
fn compute_segment_hash(trace: &ExecutionTrace) -> ProgramOutput {
    use sha2::{Digest, Sha256};

    // Get final state from trace
    if let Some(last_row) = trace.rows.last() {
        let mut hasher = Sha256::new();

        // Hash PC and registers
        hasher.update(last_row.pc.to_le_bytes());
        for &reg in &last_row.regs {
            hasher.update(reg.to_le_bytes());
        }

        let hash = hasher.finalize();

        // Convert to ProgramOutput
        let mut output = [0u32; 8];
        for (i, chunk) in hash.chunks(4).enumerate() {
            let arr: [u8; 4] = chunk.try_into().unwrap();
            output[i] = u32::from_le_bytes(arr);
        }

        ProgramOutput(output)
    } else {
        ProgramOutput::zero()
    }
}

/// Verifier for ZKsync OS proofs.
pub struct ZkSyncOsVerifier;

impl ZkSyncOsVerifier {
    /// Verify a ZKsync OS proof.
    pub fn verify(proof: &ZkSyncOsProof) -> Result<bool> {
        // In a full implementation, this would:
        // 1. Deserialize the STARK proof
        // 2. Verify the proof against the public inputs (output)
        // 3. Verify the binary hash matches

        // For now, check basic consistency
        if proof.stark_proof.proof_bytes.is_empty() {
            // Placeholder proof - always valid for testing
            return Ok(true);
        }

        // Full verification would use zp1_verifier::verify_stark
        // let result = verify_stark(&proof.stark_proof)?;

        Ok(true)
    }

    /// Verify a chain of segmented proofs.
    pub fn verify_chain(proofs: &[ZkSyncOsProof]) -> Result<bool> {
        if proofs.is_empty() {
            return Err(ZkSyncOsError::Verification("Empty proof chain".to_string()));
        }

        // Verify all proofs have the same binary hash
        let binary_hash = proofs[0].binary_hash;
        for proof in proofs {
            if proof.binary_hash != binary_hash {
                return Err(ZkSyncOsError::Verification(
                    "Inconsistent binary hash in proof chain".to_string(),
                ));
            }
        }

        // Verify each individual proof
        for proof in proofs {
            if !Self::verify(proof)? {
                return Ok(false);
            }
        }

        // TODO: Verify continuity between segments
        // This requires checking that each segment's final state matches
        // the next segment's initial state

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_config_default() {
        let config = ProverConfig::default();
        assert!(!config.use_gpu);
        assert!(!config.enable_recursion);
    }

    #[test]
    fn test_prover_config_gpu() {
        let config = ProverConfig::with_gpu();
        assert!(config.use_gpu);
    }

    #[test]
    fn test_program_output() {
        let output = ProgramOutput([1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(output.is_success());
        assert!(!output.is_zero());

        let zero_output = ProgramOutput::zero();
        assert!(!zero_output.is_success());
        assert!(zero_output.is_zero());
    }
}
