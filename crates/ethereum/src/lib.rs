//! Ethereum block proving integration for ZP1.
//!
//! This crate provides the bridge between Ethereum blocks and ZP1's RISC-V zkVM,
//! enabling generation of zero-knowledge proofs for Ethereum block execution.
//!
//! # Architecture
//!
//! Following industry standards (SP1, Risc0, OpenVM), EVM execution happens INSIDE
//! the zkVM guest program, not on the host:
//!
//! ```text
//! Host:
//!   Fetch Block/Tx → Prepare Inputs → Execute Guest in zkVM → Extract Proof
//!
//! Guest (runs inside zkVM):
//!   Read Inputs → Execute with Revm → Produce Results → Commit to Journal
//!
//! Flow:
//!   Ethereum Block → Guest Program (Revm) → RISC-V Trace → STARK Proof
//! ```
//!
//! ## Guest vs Host
//!
//! - **Guest** (`guest/`): Runs INSIDE zkVM, executes transactions with revm
//! - **Host** (`src/`): Prepares data, invokes guest, generates proofs
//! - **evm.rs**: Legacy direct execution (being phased out)
//!
//! # Usage
//!
//! ```rust,no_run
//! use zp1_ethereum::{BlockProver, ProverConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let config = ProverConfig::default();
//!     let mut prover = BlockProver::new(config).await.unwrap();
//!     
//!     // Prove a single block
//!     let proof = prover.prove_block(12345).await.unwrap();
//!     println!("Block proof generated: {:?}", proof.commitment());
//! }
//! ```

pub mod aggregation;
pub mod config;
pub mod evm;
pub mod fetcher;
pub mod guest_executor;
pub mod prover;
pub mod rpc_db;
pub mod transaction;

pub use aggregation::{BlockProof, ProofAggregator};
pub use config::ProverConfig;
pub use fetcher::{BlockData, BlockFetcher};
pub use prover::{BlockProver, TransactionProver};
pub use transaction::{TransactionProof, TransactionResult};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthereumError {
    #[error("Failed to fetch block: {0}")]
    BlockFetchError(String),

    #[error("Failed to execute transaction: {0}")]
    ExecutionError(String),

    #[error("Failed to generate proof: {0}")]
    ProvingError(String),

    #[error("Failed to aggregate proofs: {0}")]
    AggregationError(String),

    #[error("RPC error: {0}")]
    RpcError(#[from] ethers::providers::ProviderError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EthereumError>;
