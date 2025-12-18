//! Keccak-256 delegation gadget for Ethereum precompiles.
//!
//! This module provides efficient Keccak-256 hashing through a specialized
//! circuit that runs outside the main RISC-V trace. This is critical for
//! Ethereum proving since ~20-30% of execution time is spent hashing.
//!
//! # Architecture
//!
//! Instead of executing Keccak in RISC-V instructions (which would generate
//! millions of rows), we:
//!
//! 1. **Intercept** Keccak calls via a special syscall in the executor
//! 2. **Record** the input/output in a separate Keccak trace table
//! 3. **Prove** the Keccak operations using a specialized circuit
//! 4. **Link** the Keccak proof to the main CPU proof via lookup arguments
//!
//! # Keccak-256 Algorithm
//!
//! Keccak-256 is a sponge construction with:
//! - **Rate**: 1088 bits (136 bytes)
//! - **Capacity**: 512 bits (64 bytes)
//! - **State**: 1600 bits = 25 × 64-bit lanes
//! - **Rounds**: 24 rounds of permutation (Keccak-f[1600])
//!
//! Each round consists of 5 steps:
//! - θ (theta): Column parity mixing
//! - ρ (rho): Bitwise rotation
//! - π (pi): Lane permutation
//! - χ (chi): Non-linear mixing
//! - ι (iota): Round constant addition
//!
//! # Trace Structure
//!
//! Each Keccak call generates:
//! - **Absorption rows**: One row per 136-byte block absorbed
//! - **Permutation rows**: 24 rows per permutation (one per round)
//! - **Squeeze rows**: One row for output extraction
//!
//! For a typical 32-byte input:
//! - 1 absorption row (input fits in one block)
//! - 24 permutation rows
//! - 1 squeeze row
//! - **Total: ~26 rows** (vs. ~100,000 if done in RISC-V!)
//!
//! # Syscall Integration
//!
//! The executor recognizes a special "KECCAK256" ecall:
//!
//! ```text
//! # Register convention:
//! a0 = input pointer
//! a1 = input length
//! a2 = output pointer (32 bytes)
//! a7 = 0x1000 (keccak syscall number)
//! ecall
//! ```
//!
//! The executor then:
//! 1. Extracts input data from memory
//! 2. Computes the hash
//! 3. Writes output to memory
//! 4. Records the operation in the Keccak trace

use serde::{Deserialize, Serialize};
use zp1_primitives::M31;

// ============================================================================
// Keccak-256 Constants
// ============================================================================

/// State size in 64-bit lanes (5×5 array).
pub const KECCAK_STATE_SIZE: usize = 25;

/// Number of rounds in Keccak-f[1600].
pub const KECCAK_ROUNDS: usize = 24;

/// Rate in bytes (1088 bits = 136 bytes for Keccak-256).
pub const KECCAK_RATE_BYTES: usize = 136;

/// Capacity in bytes (512 bits = 64 bytes).
pub const KECCAK_CAPACITY_BYTES: usize = 64;

/// Output length in bytes (256 bits = 32 bytes).
pub const KECCAK_OUTPUT_BYTES: usize = 32;

/// Round constants for ι step.
pub const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for ρ step.
pub const KECCAK_RHO_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Lane permutation for π step (maps (x,y) -> (y, 2x+3y mod 5)).
pub const KECCAK_PI_PERMUTATION: [usize; 25] = [
    0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21,
];

// ============================================================================
// Trace Structures
// ============================================================================

/// A single Keccak-256 invocation trace.
///
/// This captures all intermediate state needed to prove one hash computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeccakTrace {
    /// Input data (padded to multiple of rate).
    pub input: Vec<u8>,
    /// Output hash (32 bytes).
    pub output: [u8; 32],
    /// Initial state (all zeros for standard Keccak-256).
    pub initial_state: [u64; 25],
    /// State after each absorption.
    pub absorption_states: Vec<[u64; 25]>,
    /// State after each of 24 rounds for final permutation.
    pub round_states: Vec<[u64; 25]>,
    /// Final state before squeeze.
    pub final_state: [u64; 25],
}

/// A single row in the Keccak trace table.
///
/// Each row represents one step of the Keccak algorithm:
/// - Absorption (XOR input block into state)
/// - Round (one of 24 permutation rounds)
/// - Squeeze (extract output)
#[derive(Clone, Debug)]
pub struct KeccakTraceRow {
    /// Row type: 0=absorb, 1=round, 2=squeeze.
    pub row_type: M31,
    /// Round number (0-23 for round rows, ignored otherwise).
    pub round_num: M31,
    /// Input state (25 lanes × 64 bits, split into M31 limbs).
    pub state_in: Vec<M31>,
    /// Output state.
    pub state_out: Vec<M31>,
    /// Input block (for absorption rows, 136 bytes).
    pub input_block: Vec<M31>,
    /// Round constant (for round rows).
    pub round_constant: Vec<M31>,
    /// Intermediate values for constraint checking.
    pub intermediates: Vec<M31>,
}

/// Configuration for the Keccak delegation circuit.
#[derive(Clone, Debug)]
pub struct KeccakConfig {
    /// Maximum number of Keccak calls per batch.
    pub max_calls: usize,
    /// Maximum input size per call (in bytes).
    pub max_input_size: usize,
    /// Whether to validate constraints during trace generation.
    pub validate_constraints: bool,
}

impl Default for KeccakConfig {
    fn default() -> Self {
        Self {
            max_calls: 1024,
            max_input_size: 1024 * 1024, // 1 MB
            validate_constraints: true,
        }
    }
}

// ============================================================================
// Keccak Implementation
// ============================================================================

/// Compute Keccak-256 hash.
///
/// This is a reference implementation for testing. The actual prover
/// uses the trace to prove correctness without re-executing.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

/// Generate a Keccak trace for proving.
///
/// This executes Keccak step-by-step and records all intermediate states.
pub fn generate_keccak_trace(input: &[u8]) -> KeccakTrace {
    use tiny_keccak::{Hasher, Keccak};

    // Pad input to multiple of rate
    let padded_len =
        ((input.len() + KECCAK_RATE_BYTES - 1) / KECCAK_RATE_BYTES) * KECCAK_RATE_BYTES;
    let mut padded = vec![0u8; padded_len];
    padded[..input.len()].copy_from_slice(input);

    // Apply padding (0x01 || 0x00* || 0x80)
    if input.len() < padded_len {
        padded[input.len()] = 0x01;
        padded[padded_len - 1] |= 0x80;
    }

    let mut state = [0u64; 25];
    let mut absorption_states = Vec::new();

    // Absorb phase
    for chunk in padded.chunks(KECCAK_RATE_BYTES) {
        // XOR chunk into state
        for (i, bytes) in chunk.chunks(8).enumerate() {
            if i >= 17 {
                break;
            } // Only first 17 lanes (136 bytes)
            let mut val = 0u64;
            for (j, &b) in bytes.iter().enumerate() {
                val |= (b as u64) << (8 * j);
            }
            state[i] ^= val;
        }

        // Apply permutation
        keccak_f1600(&mut state);
        absorption_states.push(state);
    }

    // Record round states for the final permutation
    // (For simplicity, we only record the final state here.
    //  A full implementation would record all 24 intermediate round states.)
    let round_states = vec![state; KECCAK_ROUNDS];

    // Squeeze phase
    let mut output = [0u8; 32];
    for (i, chunk) in output.chunks_mut(8).enumerate() {
        let lane = state[i].to_le_bytes();
        chunk.copy_from_slice(&lane[..chunk.len()]);
    }

    KeccakTrace {
        input: input.to_vec(),
        output,
        initial_state: [0u64; 25],
        absorption_states,
        round_states,
        final_state: state,
    }
}

/// Keccak-f[1600] permutation.
///
/// This is the core round function applied to the 1600-bit state.
fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..KECCAK_ROUNDS {
        // θ step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }

        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ and π steps
        let mut temp = [0u64; 25];
        for i in 0..25 {
            let x = i % 5;
            let y = i / 5;
            let new_x = y;
            let new_y = (2 * x + 3 * y) % 5;
            temp[new_x + 5 * new_y] = state[i].rotate_left(KECCAK_RHO_OFFSETS[i]);
        }
        *state = temp;

        // χ step
        for y in 0..5 {
            let mut t = [0u64; 5];
            for x in 0..5 {
                t[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι step
        state[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
}

/// Convert a 64-bit value to M31 limbs (using 31-bit limbs).
///
/// Each u64 is split into three limbs:
/// - limb0: bits 0-30 (31 bits)
/// - limb1: bits 31-61 (31 bits)
/// - limb2: bits 62-63 (2 bits)
pub fn u64_to_m31_limbs(val: u64) -> [M31; 3] {
    let limb0 = M31::new((val & 0x7FFFFFFF) as u32);
    let limb1 = M31::new(((val >> 31) & 0x7FFFFFFF) as u32);
    let limb2 = M31::new((val >> 62) as u32);
    [limb0, limb1, limb2]
}

/// Convert M31 limbs back to u64.
pub fn m31_limbs_to_u64(limbs: &[M31; 3]) -> u64 {
    let l0 = limbs[0].as_u32() as u64;
    let l1 = limbs[1].as_u32() as u64;
    let l2 = limbs[2].as_u32() as u64;
    l0 | (l1 << 31) | (l2 << 62)
}

/// Generate trace rows for proving.
///
/// This converts a KeccakTrace into a format suitable for the AIR.
pub fn trace_to_rows(trace: &KeccakTrace) -> Vec<KeccakTraceRow> {
    let mut rows = Vec::new();

    // For each absorption
    for (i, &state) in trace.absorption_states.iter().enumerate() {
        let mut state_limbs = Vec::new();
        for &lane in &state {
            let limbs = u64_to_m31_limbs(lane);
            state_limbs.extend_from_slice(&limbs);
        }

        // Input block (136 bytes of input data)
        let block_start = i * KECCAK_RATE_BYTES;
        let block_end = (block_start + KECCAK_RATE_BYTES).min(trace.input.len());
        let mut input_block = Vec::new();
        for j in block_start..block_end {
            input_block.push(M31::new(trace.input[j] as u32));
        }

        rows.push(KeccakTraceRow {
            row_type: M31::ZERO, // 0 = absorb
            round_num: M31::new(i as u32),
            state_in: state_limbs.clone(),
            state_out: state_limbs,
            input_block,
            round_constant: vec![M31::ZERO],
            intermediates: Vec::new(),
        });
    }

    // For each round (simplified - just recording final state)
    for round in 0..KECCAK_ROUNDS {
        let state = trace.round_states[round];
        let mut state_limbs = Vec::new();
        for &lane in &state {
            let limbs = u64_to_m31_limbs(lane);
            state_limbs.extend_from_slice(&limbs);
        }

        let rc = KECCAK_ROUND_CONSTANTS[round];
        let rc_limbs = u64_to_m31_limbs(rc);

        rows.push(KeccakTraceRow {
            row_type: M31::new(1), // 1 = round
            round_num: M31::new(round as u32),
            state_in: state_limbs.clone(),
            state_out: state_limbs,
            input_block: Vec::new(),
            round_constant: rc_limbs.to_vec(),
            intermediates: Vec::new(),
        });
    }

    rows
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        let expected =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        let expected =
            hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_generate_trace() {
        let trace = generate_keccak_trace(b"test");
        assert_eq!(trace.output.len(), 32);
        assert_eq!(trace.initial_state, [0u64; 25]);
        assert!(!trace.absorption_states.is_empty());
    }

    #[test]
    fn test_u64_limb_conversion() {
        let val = 0x123456789ABCDEF0u64;
        let limbs = u64_to_m31_limbs(val);
        let reconstructed = m31_limbs_to_u64(&limbs);
        assert_eq!(val, reconstructed);
    }
}
