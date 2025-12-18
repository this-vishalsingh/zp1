//! Oracle/Non-determinism source for ZKsync OS.
//!
//! ZKsync OS uses CSR (Control and Status Register) reads to receive non-deterministic
//! inputs from the outside world. This module implements the interface that ZP1 uses
//! to provide these values during execution.

use std::collections::VecDeque;

/// Trait for non-determinism sources compatible with ZKsync OS.
///
/// This mirrors the `NonDeterminismCSRSource` trait from zksync-os-runner,
/// providing the same semantics for feeding data to the RISC-V program.
pub trait NonDeterminismSource {
    /// Read a 32-bit word from the oracle.
    fn read(&mut self) -> Option<u32>;

    /// Check if there's more data available.
    fn has_data(&self) -> bool;

    /// Get the number of remaining words.
    fn remaining(&self) -> usize;
}

/// A simple queue-based oracle source.
///
/// This is equivalent to `QuasiUARTSource` in the original zksync-os implementation.
/// It provides a FIFO queue of 32-bit words that the RISC-V program can read via CSR.
#[derive(Debug, Clone, Default)]
pub struct OracleSource {
    /// Queue of 32-bit words to feed to the program
    oracle: VecDeque<u32>,
    /// Track read operations for witness collection
    reads: Vec<u32>,
    /// Track total reads
    total_reads: usize,
}

impl OracleSource {
    /// Create a new empty oracle source.
    pub fn new() -> Self {
        Self {
            oracle: VecDeque::new(),
            reads: Vec::new(),
            total_reads: 0,
        }
    }

    /// Create an oracle source with initial data.
    pub fn with_data(data: impl IntoIterator<Item = u32>) -> Self {
        Self {
            oracle: data.into_iter().collect(),
            reads: Vec::new(),
            total_reads: 0,
        }
    }

    /// Create from a byte slice (converts to u32 words, little-endian).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut oracle = VecDeque::new();
        for chunk in bytes.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            oracle.push_back(u32::from_le_bytes(word));
        }
        Self {
            oracle,
            reads: Vec::new(),
            total_reads: 0,
        }
    }

    /// Push a single word to the oracle queue.
    pub fn push(&mut self, word: u32) {
        self.oracle.push_back(word);
    }

    /// Push multiple words to the oracle queue.
    pub fn push_words(&mut self, words: impl IntoIterator<Item = u32>) {
        self.oracle.extend(words);
    }

    /// Push bytes as words (little-endian).
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(4) {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.oracle.push_back(u32::from_le_bytes(word));
        }
    }

    /// Push a u64 as two u32 words (little-endian).
    pub fn push_u64(&mut self, value: u64) {
        self.oracle.push_back(value as u32);
        self.oracle.push_back((value >> 32) as u32);
    }

    /// Push a u128 as four u32 words (little-endian).
    pub fn push_u128(&mut self, value: u128) {
        self.oracle.push_back(value as u32);
        self.oracle.push_back((value >> 32) as u32);
        self.oracle.push_back((value >> 64) as u32);
        self.oracle.push_back((value >> 96) as u32);
    }

    /// Push a 256-bit value as eight u32 words (little-endian).
    pub fn push_u256(&mut self, bytes: &[u8; 32]) {
        for chunk in bytes.chunks(4) {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            self.oracle.push_back(word);
        }
    }

    /// Get the recorded reads (for witness collection).
    pub fn get_reads(&self) -> &[u32] {
        &self.reads
    }

    /// Get total number of reads performed.
    pub fn total_reads(&self) -> usize {
        self.total_reads
    }

    /// Clear the reads history.
    pub fn clear_reads(&mut self) {
        self.reads.clear();
        self.total_reads = 0;
    }

    /// Get the current queue length.
    pub fn len(&self) -> usize {
        self.oracle.len()
    }

    /// Check if the oracle queue is empty.
    pub fn is_empty(&self) -> bool {
        self.oracle.is_empty()
    }
}

impl NonDeterminismSource for OracleSource {
    fn read(&mut self) -> Option<u32> {
        let word = self.oracle.pop_front();
        if let Some(w) = word {
            self.reads.push(w);
            self.total_reads += 1;
        }
        word
    }

    fn has_data(&self) -> bool {
        !self.oracle.is_empty()
    }

    fn remaining(&self) -> usize {
        self.oracle.len()
    }
}

/// A read-witness collecting oracle that wraps another oracle.
///
/// This records all reads for witness generation/dumping.
pub struct WitnessCollectingOracle<S: NonDeterminismSource> {
    inner: S,
    reads: Vec<u32>,
}

impl<S: NonDeterminismSource> WitnessCollectingOracle<S> {
    /// Create a new witness-collecting wrapper.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            reads: Vec::new(),
        }
    }

    /// Get the collected witness data.
    pub fn into_witness(self) -> Vec<u32> {
        self.reads
    }

    /// Get a reference to collected reads.
    pub fn reads(&self) -> &[u32] {
        &self.reads
    }
}

impl<S: NonDeterminismSource> NonDeterminismSource for WitnessCollectingOracle<S> {
    fn read(&mut self) -> Option<u32> {
        let word = self.inner.read();
        if let Some(w) = word {
            self.reads.push(w);
        }
        word
    }

    fn has_data(&self) -> bool {
        self.inner.has_data()
    }

    fn remaining(&self) -> usize {
        self.inner.remaining()
    }
}

/// CSR addresses used by ZKsync OS for oracle communication.
pub mod csr {
    /// CSR address for reading from oracle (input)
    pub const ORACLE_READ: u32 = 0x800;

    /// CSR address for writing to oracle (output)  
    pub const ORACLE_WRITE: u32 = 0x801;

    /// CSR address for signaling completion
    pub const FINISH: u32 = 0x802;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oracle_basic() {
        let mut oracle = OracleSource::with_data([1, 2, 3, 4]);

        assert_eq!(oracle.remaining(), 4);
        assert!(oracle.has_data());

        assert_eq!(oracle.read(), Some(1));
        assert_eq!(oracle.read(), Some(2));
        assert_eq!(oracle.read(), Some(3));
        assert_eq!(oracle.read(), Some(4));
        assert_eq!(oracle.read(), None);

        assert_eq!(oracle.total_reads(), 4);
        assert_eq!(oracle.get_reads(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_oracle_from_bytes() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut oracle = OracleSource::from_bytes(&bytes);

        assert_eq!(oracle.read(), Some(0x04030201));
        assert_eq!(oracle.read(), Some(0x08070605));
    }

    #[test]
    fn test_witness_collecting() {
        let inner = OracleSource::with_data([10, 20, 30]);
        let mut oracle = WitnessCollectingOracle::new(inner);

        oracle.read();
        oracle.read();
        oracle.read();

        assert_eq!(oracle.reads(), &[10, 20, 30]);
    }
}
