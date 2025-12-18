//! Configuration for Ethereum block proving.

use serde::{Deserialize, Serialize};

/// Configuration for the Ethereum prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// RPC endpoint URL
    pub rpc_url: String,

    /// Maximum execution steps per transaction
    pub max_steps: u64,

    /// STARK blowup factor
    pub blowup_factor: usize,

    /// Number of FRI queries
    pub num_queries: usize,

    /// Target security bits
    pub security_bits: usize,

    /// Enable parallel proving
    pub parallel: bool,

    /// Number of worker threads
    pub num_threads: usize,

    /// Enable GPU acceleration
    pub use_gpu: bool,

    /// Output directory for proofs
    pub output_dir: String,
}

impl Default for ProverConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            max_steps: 10_000_000,
            blowup_factor: 8,
            num_queries: 50,
            security_bits: 100,
            parallel: true,
            num_threads: num_cpus::get(),
            use_gpu: false,
            output_dir: "./proofs".to_string(),
        }
    }
}

impl ProverConfig {
    /// Create config for mainnet proving
    pub fn mainnet(rpc_url: String) -> Self {
        Self {
            rpc_url,
            max_steps: 100_000_000, // Higher for mainnet
            num_queries: 80,        // Higher security
            security_bits: 128,
            ..Default::default()
        }
    }

    /// Create config for testnet proving (faster)
    pub fn testnet(rpc_url: String) -> Self {
        Self {
            rpc_url,
            max_steps: 10_000_000,
            num_queries: 30, // Lower for testing
            security_bits: 80,
            ..Default::default()
        }
    }

    /// Create config for local development
    pub fn local() -> Self {
        Self {
            rpc_url: "http://localhost:8545".to_string(),
            max_steps: 1_000_000,
            num_queries: 20,
            security_bits: 80,
            parallel: false, // Easier debugging
            ..Default::default()
        }
    }
}
