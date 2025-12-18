//! Witness handling for ZKsync OS.
//!
//! This module provides utilities for creating, loading, and managing
//! witness data that is fed to ZKsync OS during execution.

use crate::error::{Result, ZkSyncOsError};
use crate::oracle::OracleSource;
use crate::types::{BlockContext, StorageAccess};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;

/// A complete witness for ZKsync OS execution.
///
/// This contains all non-deterministic inputs needed for proving:
/// - Block metadata
/// - Transactions
/// - Storage accesses (reads)
/// - Preimages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// Raw oracle data as u32 words.
    pub oracle_data: Vec<u32>,
    /// Block context (optional, for metadata).
    pub block_context: Option<BlockContext>,
    /// Number of transactions.
    pub tx_count: usize,
    /// Storage accesses.
    pub storage_accesses: Vec<StorageAccess>,
}

impl Witness {
    /// Create a new empty witness.
    pub fn new() -> Self {
        Self {
            oracle_data: Vec::new(),
            block_context: None,
            tx_count: 0,
            storage_accesses: Vec::new(),
        }
    }

    /// Create a witness from raw oracle data.
    pub fn from_oracle_data(data: Vec<u32>) -> Self {
        Self {
            oracle_data: data,
            block_context: None,
            tx_count: 0,
            storage_accesses: Vec::new(),
        }
    }

    /// Load witness from a binary file.
    ///
    /// The file format is raw u32 words in little-endian format.
    pub fn load_binary(path: &Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.len() % 4 != 0 {
            return Err(ZkSyncOsError::InvalidBinary(
                "Witness file size must be a multiple of 4 bytes".to_string(),
            ));
        }

        let oracle_data: Vec<u32> = buffer
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect();

        Ok(Self::from_oracle_data(oracle_data))
    }

    /// Load witness from a JSON file.
    pub fn load_json(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let witness: Witness = serde_json::from_reader(file)?;
        Ok(witness)
    }

    /// Save witness to a binary file.
    pub fn save_binary(&self, path: &Path) -> Result<()> {
        let mut file = std::fs::File::create(path)?;
        for word in &self.oracle_data {
            file.write_all(&word.to_le_bytes())?;
        }
        Ok(())
    }

    /// Save witness to a JSON file.
    pub fn save_json(&self, path: &Path) -> Result<()> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }

    /// Convert to oracle source for execution.
    pub fn to_oracle(&self) -> OracleSource {
        OracleSource::with_data(self.oracle_data.iter().copied())
    }

    /// Get the number of oracle words.
    pub fn len(&self) -> usize {
        self.oracle_data.len()
    }

    /// Check if witness is empty.
    pub fn is_empty(&self) -> bool {
        self.oracle_data.is_empty()
    }
}

impl Default for Witness {
    fn default() -> Self {
        Self::new()
    }
}

/// Source for reading witness data.
pub trait WitnessSource {
    /// Get the witness data.
    fn get_witness(&self) -> Result<Witness>;
}

/// File-based witness source.
pub struct FileWitnessSource {
    path: std::path::PathBuf,
}

impl FileWitnessSource {
    /// Create a new file witness source.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl WitnessSource for FileWitnessSource {
    fn get_witness(&self) -> Result<Witness> {
        let ext = self.path.extension().and_then(|s| s.to_str());
        match ext {
            Some("json") => Witness::load_json(&self.path),
            _ => Witness::load_binary(&self.path),
        }
    }
}

/// In-memory witness source.
pub struct MemoryWitnessSource {
    witness: Witness,
}

impl MemoryWitnessSource {
    /// Create a new in-memory witness source.
    pub fn new(witness: Witness) -> Self {
        Self { witness }
    }

    /// Create from raw oracle data.
    pub fn from_data(data: Vec<u32>) -> Self {
        Self {
            witness: Witness::from_oracle_data(data),
        }
    }
}

impl WitnessSource for MemoryWitnessSource {
    fn get_witness(&self) -> Result<Witness> {
        Ok(self.witness.clone())
    }
}

/// Builder for constructing witnesses programmatically.
#[derive(Default)]
pub struct WitnessBuilder {
    oracle_data: Vec<u32>,
    block_context: Option<BlockContext>,
    storage_accesses: Vec<StorageAccess>,
}

impl WitnessBuilder {
    /// Create a new witness builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add block context.
    pub fn with_block_context(mut self, ctx: BlockContext) -> Self {
        // Encode block context into oracle data
        self.oracle_data.extend(ctx.to_oracle_words());
        self.block_context = Some(ctx);
        self
    }

    /// Add raw oracle data.
    pub fn with_data(mut self, data: &[u32]) -> Self {
        self.oracle_data.extend_from_slice(data);
        self
    }

    /// Add a single word.
    pub fn push(mut self, word: u32) -> Self {
        self.oracle_data.push(word);
        self
    }

    /// Add a u64 (as two words).
    pub fn push_u64(mut self, value: u64) -> Self {
        self.oracle_data.push(value as u32);
        self.oracle_data.push((value >> 32) as u32);
        self
    }

    /// Add bytes.
    pub fn push_bytes(mut self, bytes: &[u8]) -> Self {
        for chunk in bytes.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.oracle_data.push(u32::from_le_bytes(word));
        }
        self
    }

    /// Add a storage access.
    pub fn with_storage_access(self, access: StorageAccess) -> Self {
        // Encode storage access - chain the push_bytes calls properly
        let builder = self
            .push_bytes(&access.address)
            .push_bytes(&access.key)
            .push_bytes(&access.value);
        let mut result = builder;
        result.storage_accesses.push(access);
        result
    }

    /// Build the witness.
    pub fn build(self) -> Witness {
        Witness {
            oracle_data: self.oracle_data,
            block_context: self.block_context,
            tx_count: 0,
            storage_accesses: self.storage_accesses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oracle::NonDeterminismSource;

    #[test]
    fn test_witness_builder() {
        let witness = WitnessBuilder::new().push(1).push(2).push(3).build();

        assert_eq!(witness.len(), 3);
        assert_eq!(witness.oracle_data, vec![1, 2, 3]);
    }

    #[test]
    fn test_witness_to_oracle() {
        let witness = Witness::from_oracle_data(vec![10, 20, 30]);
        let mut oracle = witness.to_oracle();

        assert_eq!(oracle.read(), Some(10));
        assert_eq!(oracle.read(), Some(20));
        assert_eq!(oracle.read(), Some(30));
        assert_eq!(oracle.read(), None);
    }

    #[test]
    fn test_witness_serialization() {
        let witness = WitnessBuilder::new()
            .push(0x12345678)
            .push_u64(0xDEADBEEFCAFEBABE)
            .build();

        let json = serde_json::to_string(&witness).unwrap();
        let deserialized: Witness = serde_json::from_str(&json).unwrap();

        assert_eq!(witness.oracle_data, deserialized.oracle_data);
    }
}
