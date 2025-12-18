//! ZKsync OS runner - execute zksync-os binaries on ZP1.
//!
//! This module provides the main execution interface for running ZKsync OS
//! RISC-V binaries using ZP1's executor.

use crate::error::{Result, ZkSyncOsError};
use crate::oracle::{NonDeterminismSource, OracleSource};
use crate::types::{BlockContext, ExecutionStats, ProgramOutput};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use zp1_executor::{Cpu, ExecutionTrace};

/// Configuration for ZKsync OS execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    /// Maximum number of cycles to execute.
    pub max_cycles: u64,
    /// Memory size in bytes.
    pub memory_size: usize,
    /// Entry point address (default: 0).
    pub entry_point: u32,
    /// Enable execution tracing for proof generation.
    pub enable_tracing: bool,
    /// Enable profiling/diagnostics.
    pub enable_profiling: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            // 2^36 cycles, same as zksync-os default
            max_cycles: 1 << 36,
            // 16 MB memory
            memory_size: 16 * 1024 * 1024,
            entry_point: 0,
            enable_tracing: true,
            enable_profiling: false,
        }
    }
}

impl RunConfig {
    /// Create a config optimized for testing (fewer cycles, smaller memory).
    pub fn for_testing() -> Self {
        Self {
            max_cycles: 1 << 25,
            memory_size: 4 * 1024 * 1024,
            entry_point: 0,
            enable_tracing: true,
            enable_profiling: false,
        }
    }

    /// Create a config optimized for proving (full tracing).
    pub fn for_proving() -> Self {
        Self {
            max_cycles: 1 << 36,
            memory_size: 16 * 1024 * 1024,
            entry_point: 0,
            enable_tracing: true,
            enable_profiling: false,
        }
    }
}

/// Result of running a ZKsync OS binary.
#[derive(Debug)]
pub struct RunResult {
    /// Program output (public input for proof).
    pub output: ProgramOutput,
    /// Execution trace (for proof generation).
    pub trace: Option<ExecutionTrace>,
    /// Execution statistics.
    pub stats: ExecutionStats,
    /// Oracle reads (witness data).
    pub witness: Vec<u32>,
    /// Whether execution was successful.
    pub success: bool,
}

impl RunResult {
    /// Check if the execution was successful (non-zero output).
    pub fn is_success(&self) -> bool {
        self.success && self.output.is_success()
    }
}

/// ZKsync OS binary runner using ZP1 executor.
pub struct ZkSyncOsRunner;

impl ZkSyncOsRunner {
    /// Run a ZKsync OS binary with the given oracle data.
    ///
    /// # Arguments
    ///
    /// * `binary` - The RISC-V binary (raw bytes, not ELF)
    /// * `oracle` - Non-determinism source providing witness data
    /// * `config` - Execution configuration
    ///
    /// # Returns
    ///
    /// A `RunResult` containing the output, trace, and statistics.
    pub fn run<S: NonDeterminismSource>(
        binary: &[u8],
        mut oracle: S,
        config: RunConfig,
    ) -> Result<RunResult> {
        let start_time = Instant::now();

        // Initialize CPU
        let mut cpu = Cpu::with_memory_size(config.memory_size);

        if config.enable_tracing {
            cpu.enable_tracing();
        }

        // Load binary into memory
        // ZKsync OS binaries expect to be loaded at address 0
        cpu.load_program(config.entry_point, binary)
            .map_err(|e| ZkSyncOsError::Execution(format!("Failed to load binary: {}", e)))?;

        // Track statistics
        let mut stats = ExecutionStats::default();
        let mut output = ProgramOutput::zero();
        let mut oracle_reads = Vec::new();
        let mut success = false;

        // Execute with CSR-based oracle interface
        loop {
            if cpu.cycle >= config.max_cycles {
                return Err(ZkSyncOsError::CycleLimitExceeded {
                    executed: cpu.cycle,
                    limit: config.max_cycles,
                });
            }

            // Check for CSR reads/writes (oracle interaction)
            // In ZKsync OS, CSR reads from address 0x800 get oracle data
            // This is handled via ECALL in our implementation

            match cpu.step() {
                Ok(Some(_row)) => {
                    // Instruction executed successfully
                    stats.cycles += 1;
                }
                Ok(None) => {
                    // Program ended (ECALL/EBREAK)
                    // Extract output from registers (a0-a7 contain the 8 output words)
                    output = ProgramOutput([
                        cpu.get_reg(10), // a0
                        cpu.get_reg(11), // a1
                        cpu.get_reg(12), // a2
                        cpu.get_reg(13), // a3
                        cpu.get_reg(14), // a4
                        cpu.get_reg(15), // a5
                        cpu.get_reg(16), // a6
                        cpu.get_reg(17), // a7
                    ]);
                    success = true;
                    break;
                }
                Err(e) => {
                    // Check if this is a syscall we should handle
                    // ZKsync OS uses ECALL for oracle reads
                    // a7 contains syscall number, a0-a6 are arguments
                    let syscall = cpu.get_reg(17); // a7

                    match syscall {
                        // Oracle read syscall
                        0x800 => {
                            if let Some(word) = oracle.read() {
                                oracle_reads.push(word);
                                cpu.set_reg(10, word); // Return in a0
                                stats.oracle_reads += 1;
                                // Advance PC past ECALL
                                cpu.pc = cpu.pc.wrapping_add(4);
                                continue;
                            } else {
                                return Err(ZkSyncOsError::Oracle(
                                    "Oracle underflow: no more data available".to_string(),
                                ));
                            }
                        }
                        // Finish/halt syscall
                        0x802 => {
                            // Extract output and finish
                            output = ProgramOutput([
                                cpu.get_reg(10),
                                cpu.get_reg(11),
                                cpu.get_reg(12),
                                cpu.get_reg(13),
                                cpu.get_reg(14),
                                cpu.get_reg(15),
                                cpu.get_reg(16),
                                cpu.get_reg(17),
                            ]);
                            success = true;
                            break;
                        }
                        _ => {
                            return Err(ZkSyncOsError::Execution(format!(
                                "Execution error at PC {:#x}: {}",
                                cpu.pc, e
                            )));
                        }
                    }
                }
            }
        }

        // Collect trace if enabled
        let trace = cpu.take_trace();

        // Calculate final stats
        stats.execution_time_ns = start_time.elapsed().as_nanos() as u64;

        Ok(RunResult {
            output,
            trace,
            stats,
            witness: oracle_reads,
            success,
        })
    }

    /// Run a ZKsync OS binary from a file.
    pub fn run_file<S: NonDeterminismSource>(
        path: &std::path::Path,
        oracle: S,
        config: RunConfig,
    ) -> Result<RunResult> {
        let binary = std::fs::read(path)?;
        Self::run(&binary, oracle, config)
    }

    /// Load a binary from raw bytes.
    pub fn load_binary(bytes: &[u8]) -> Result<Vec<u32>> {
        if bytes.len() % 4 != 0 {
            return Err(ZkSyncOsError::InvalidBinary(
                "Binary size must be a multiple of 4 bytes".to_string(),
            ));
        }

        let words: Vec<u32> = bytes
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        Ok(words)
    }

    /// Pad binary for proving (ensure size is power of 2).
    pub fn pad_binary_for_proving(binary: &mut Vec<u32>) {
        // Find next power of 2
        let len = binary.len();
        let target = len.next_power_of_two();

        // Pad with NOPs (ADDI x0, x0, 0 = 0x00000013)
        binary.resize(target, 0x00000013);
    }
}

/// Builder for creating oracle data for ZKsync OS execution.
pub struct OracleBuilder {
    oracle: OracleSource,
}

impl OracleBuilder {
    /// Create a new oracle builder.
    pub fn new() -> Self {
        Self {
            oracle: OracleSource::new(),
        }
    }

    /// Add block context to oracle.
    pub fn with_block_context(mut self, ctx: &BlockContext) -> Self {
        self.oracle.push_words(ctx.to_oracle_words());
        self
    }

    /// Add raw witness data.
    pub fn with_witness(mut self, witness: &[u32]) -> Self {
        self.oracle.push_words(witness.iter().copied());
        self
    }

    /// Add bytes as witness data.
    pub fn with_bytes(mut self, bytes: &[u8]) -> Self {
        self.oracle.push_bytes(bytes);
        self
    }

    /// Build the oracle source.
    pub fn build(self) -> OracleSource {
        self.oracle
    }
}

impl Default for OracleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_config_default() {
        let config = RunConfig::default();
        assert_eq!(config.max_cycles, 1 << 36);
        assert!(config.enable_tracing);
    }

    #[test]
    fn test_oracle_builder() {
        let ctx = BlockContext {
            block_number: 12345,
            timestamp: 1000000,
            ..Default::default()
        };

        let oracle = OracleBuilder::new()
            .with_block_context(&ctx)
            .with_witness(&[1, 2, 3])
            .build();

        assert!(!oracle.is_empty());
    }

    #[test]
    fn test_load_binary() {
        let bytes = vec![0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
        let words = ZkSyncOsRunner::load_binary(&bytes).unwrap();
        assert_eq!(words, vec![0x00000013, 0x00000013]);
    }

    #[test]
    fn test_pad_binary() {
        let mut binary = vec![0x00000013; 3];
        ZkSyncOsRunner::pad_binary_for_proving(&mut binary);
        assert_eq!(binary.len(), 4); // Next power of 2
    }
}
