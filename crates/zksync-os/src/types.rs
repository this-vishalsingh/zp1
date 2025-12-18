//! Common types for ZKsync OS integration.

use serde::{Deserialize, Serialize};

/// ZKsync OS program output (256 bits / 8 u32 words).
/// This is exposed as the public input in proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProgramOutput(pub [u32; 8]);

impl ProgramOutput {
    /// Create a new zero output.
    pub fn zero() -> Self {
        Self([0; 8])
    }

    /// Check if output is zero (indicates failure in zksync-os).
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    /// Check if execution was successful (non-zero output).
    pub fn is_success(&self) -> bool {
        !self.is_zero()
    }

    /// Convert to bytes (big-endian).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, word) in self.0.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        bytes
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.to_bytes()))
    }
}

impl From<[u32; 8]> for ProgramOutput {
    fn from(words: [u32; 8]) -> Self {
        Self(words)
    }
}

impl AsRef<[u32; 8]> for ProgramOutput {
    fn as_ref(&self) -> &[u32; 8] {
        &self.0
    }
}

/// Block context information for ZKsync OS execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockContext {
    /// Block number
    pub block_number: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Gas limit for the block
    pub gas_limit: u64,
    /// Coinbase address (20 bytes)
    pub coinbase: [u8; 20],
    /// Base fee per gas
    pub base_fee: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Previous block hash
    pub prev_block_hash: [u8; 32],
    /// Mix hash / prevrandao
    pub mix_hash: [u8; 32],
}

impl BlockContext {
    /// Encode to oracle words.
    pub fn to_oracle_words(&self) -> Vec<u32> {
        let mut words = Vec::new();

        // Block number (2 words)
        words.push(self.block_number as u32);
        words.push((self.block_number >> 32) as u32);

        // Timestamp (2 words)
        words.push(self.timestamp as u32);
        words.push((self.timestamp >> 32) as u32);

        // Gas limit (2 words)
        words.push(self.gas_limit as u32);
        words.push((self.gas_limit >> 32) as u32);

        // Coinbase (5 words, 20 bytes)
        for chunk in self.coinbase.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            words.push(u32::from_le_bytes(word));
        }

        // Base fee (2 words)
        words.push(self.base_fee as u32);
        words.push((self.base_fee >> 32) as u32);

        // Chain ID (2 words)
        words.push(self.chain_id as u32);
        words.push((self.chain_id >> 32) as u32);

        // Previous block hash (8 words)
        for chunk in self.prev_block_hash.chunks(4) {
            words.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }

        // Mix hash (8 words)
        for chunk in self.mix_hash.chunks(4) {
            words.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        }

        words
    }
}

/// Transaction data for ZKsync OS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    pub tx_type: TxType,
    /// Sender address
    pub from: [u8; 20],
    /// Recipient address (None for contract creation)
    pub to: Option<[u8; 20]>,
    /// Value in wei
    pub value: [u8; 32],
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price or max fee per gas
    pub gas_price: u64,
    /// Max priority fee per gas (for EIP-1559)
    pub max_priority_fee: Option<u64>,
    /// Nonce
    pub nonce: u64,
    /// Input data (calldata)
    pub data: Vec<u8>,
    /// Access list (for EIP-2930)
    pub access_list: Vec<AccessListEntry>,
}

/// Transaction types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxType {
    /// Legacy transaction
    Legacy = 0,
    /// EIP-2930 access list transaction
    AccessList = 1,
    /// EIP-1559 transaction
    Eip1559 = 2,
    /// EIP-4844 blob transaction
    Blob = 3,
}

impl Default for TxType {
    fn default() -> Self {
        Self::Legacy
    }
}

/// Access list entry for EIP-2930.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListEntry {
    /// Account address
    pub address: [u8; 20],
    /// Storage keys
    pub storage_keys: Vec<[u8; 32]>,
}

/// Storage access information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAccess {
    /// Account address
    pub address: [u8; 20],
    /// Storage key
    pub key: [u8; 32],
    /// Storage value
    pub value: [u8; 32],
}

/// Execution statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionStats {
    /// Total cycles executed
    pub cycles: u64,
    /// Memory high watermark (bytes)
    pub memory_peak: u64,
    /// Number of oracle reads
    pub oracle_reads: u64,
    /// Number of storage reads
    pub storage_reads: u64,
    /// Number of storage writes
    pub storage_writes: u64,
    /// Execution time (nanoseconds)
    pub execution_time_ns: u64,
}

// Simple hex encoding (to avoid external dependency)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
