//! # ZP1 ZKsync OS Integration
//!
//! This crate provides integration between ZP1 (a RISC-V zkVM) and ZKsync OS,
//! enabling ZP1 to execute and prove zksync-os RISC-V binaries.
//!
//! ## Overview
//!
//! ZKsync OS is a state transition function for ZKsync that supports multiple
//! execution environments (EVM, EraVM, WASM, etc.). It is compiled to RISC-V
//! and designed to be proven by a RISC-V prover.
//!
//! This crate provides:
//! - **Runner**: Execute zksync-os binaries on ZP1's RISC-V executor
//! - **Oracle Interface**: Non-determinism source for feeding witness data
//! - **Prover Integration**: Generate ZP1 proofs for zksync-os execution
//! - **Witness Utilities**: Tools for working with zksync-os witnesses
//!
//! ## Usage
//!
//! ```rust,ignore
//! use zp1_zksync_os::{ZkSyncOsRunner, OracleSource, RunConfig};
//!
//! // Load the zksync-os binary
//! let binary = std::fs::read("zksync_os/for_tests.bin")?;
//!
//! // Create an oracle with witness data
//! let mut oracle = OracleSource::new();
//! oracle.push_witness(&witness_data);
//!
//! // Run the binary
//! let config = RunConfig::default();
//! let result = ZkSyncOsRunner::run(&binary, oracle, config)?;
//!
//! // Generate a proof
//! let proof = result.prove()?;
//! ```
//!
//! ## Architecture
//!
//! ZKsync OS uses a CSR (Control and Status Register) based oracle interface
//! for non-deterministic inputs. This includes:
//! - Block metadata (block number, timestamp, gas limit, etc.)
//! - Transaction data
//! - Storage access (reads/writes)
//! - Preimage data
//!
//! ZP1 implements this interface through the [`OracleSource`] type, which
//! provides the same semantics as the original `QuasiUARTSource`.

pub mod error;
pub mod oracle;
pub mod prover;
pub mod runner;
pub mod types;
pub mod witness;

pub use error::{Result, ZkSyncOsError};
pub use oracle::{NonDeterminismSource, OracleSource, WitnessCollectingOracle};
pub use prover::{ProverConfig, ZkSyncOsProof, ZkSyncOsProver, ZkSyncOsVerifier};
pub use runner::{OracleBuilder, RunConfig, RunResult, ZkSyncOsRunner};
pub use types::*;
pub use witness::{Witness, WitnessBuilder, WitnessSource};
