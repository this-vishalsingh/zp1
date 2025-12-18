//! Integration tests for the zp1 RISC-V proving system.
//!
//! This crate demonstrates the complete pipeline:
//! 1. Define a RISC-V program
//! 2. Execute it to generate an execution trace
//! 3. Build trace columns for the AIR
//! 4. Generate a STARK proof
//! 5. Verify the proof

pub mod encode;
pub mod pipeline;
pub mod programs;
