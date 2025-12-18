//! Error types for ZKsync OS integration.

use thiserror::Error;

/// Result type for ZKsync OS operations.
pub type Result<T> = std::result::Result<T, ZkSyncOsError>;

/// Errors that can occur during ZKsync OS operations.
#[derive(Error, Debug)]
pub enum ZkSyncOsError {
    /// Failed to load binary file
    #[error("Failed to load binary: {0}")]
    BinaryLoad(String),

    /// Invalid binary format
    #[error("Invalid binary format: {0}")]
    InvalidBinary(String),

    /// Execution error
    #[error("Execution error: {0}")]
    Execution(String),

    /// Oracle/witness error
    #[error("Oracle error: {0}")]
    Oracle(String),

    /// Out of gas/resources
    #[error("Out of resources: {0}")]
    OutOfResources(String),

    /// Cycle limit exceeded
    #[error("Cycle limit exceeded: executed {executed} cycles, limit was {limit}")]
    CycleLimitExceeded { executed: u64, limit: u64 },

    /// Invalid output
    #[error("Invalid output: {0}")]
    InvalidOutput(String),

    /// Proof generation error
    #[error("Proof generation error: {0}")]
    ProofGeneration(String),

    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// ZP1 executor error
    #[error("Executor error: {0}")]
    Executor(String),

    /// ZP1 prover error
    #[error("Prover error: {0}")]
    Prover(String),
}
