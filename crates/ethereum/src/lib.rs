//! Ethereum block proving integration for ZP1.
//!
//! This crate provides the bridge between Ethereum blocks and ZP1's RISC-V zkVM,
//! enabling generation of zero-knowledge proofs for Ethereum block execution.
//!
//! # Architecture
//!
//! ```text
//! Ethereum Block → Transaction Batch → EVM Execution → RISC-V Trace → STARK Proof
//! ```
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

pub mod fetcher;
pub mod prover;
pub mod transaction;
pub mod aggregation;
pub mod config;

pub use fetcher::{BlockFetcher, BlockData};
pub use prover::{BlockProver, TransactionProver};
pub use transaction::{TransactionProof, TransactionResult};
pub use aggregation::{ProofAggregator, BlockProof};
pub use config::ProverConfig;

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
