//! Transaction execution and proving.

use serde::{Serialize, Deserialize};
use ethers::types::H256;

/// Result of executing a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    /// Transaction hash
    pub hash: H256,
    
    /// Gas used
    pub gas_used: u64,
    
    /// Success status
    pub success: bool,
    
    /// Return data
    pub return_data: Vec<u8>,
    
    /// State changes (simplified)
    pub state_changes: Vec<StateChange>,
}

/// A state change from transaction execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: ethers::types::Address,
    pub slot: ethers::types::U256,
    pub old_value: ethers::types::U256,
    pub new_value: ethers::types::U256,
}

/// Proof for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Transaction hash
    pub tx_hash: H256,
    
    /// STARK proof (serialized as bytes)
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
    
    /// Public inputs (state root before/after, etc.)
    pub public_inputs: Vec<u8>,
    
    /// Execution result
    pub result: TransactionResult,
}

impl TransactionProof {
    /// Get the transaction hash.
    pub fn hash(&self) -> H256 {
        self.tx_hash
    }

    /// Check if transaction succeeded.
    pub fn is_success(&self) -> bool {
        self.result.success
    }

    /// Get gas used.
    pub fn gas_used(&self) -> u64 {
        self.result.gas_used
    }
}
