//! Simple byte-addressable memory for RV32IM executor.
//!
//! # Alignment Requirements
//!
//! The memory subsystem enforces strict alignment for multi-byte accesses:
//! - **Word (32-bit)**: Must be 4-byte aligned (addr % 4 == 0)
//! - **Halfword (16-bit)**: Must be 2-byte aligned (addr % 2 == 0)
//! - **Byte (8-bit)**: No alignment requirement
//!
//! Unaligned accesses result in `UnalignedAccess` errors which are
//! unprovable traps that will cause prover failure.

use crate::error::ExecutorError;
use serde::{Deserialize, Serialize};

/// Default memory size: 16 MB
pub const DEFAULT_MEM_SIZE: usize = 16 * 1024 * 1024;

/// Memory subsystem for the executor.
#[derive(Clone, Serialize, Deserialize)]
pub struct Memory {
    /// Flat byte-addressable memory.
    data: Vec<u8>,
}

impl Memory {
    /// Create a new memory with the given size in bytes.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }

    /// Create memory with default size.
    pub fn with_default_size() -> Self {
        Self::new(DEFAULT_MEM_SIZE)
    }

    /// Get the memory size.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Load a program image into memory starting at the given address.
    pub fn load_program(&mut self, addr: u32, program: &[u8]) -> Result<(), ExecutorError> {
        let start = addr as usize;
        let end = start + program.len();
        if end > self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        self.data[start..end].copy_from_slice(program);
        Ok(())
    }

    /// Read a byte from memory.
    #[inline]
    pub fn read_u8(&self, addr: u32) -> Result<u8, ExecutorError> {
        let idx = addr as usize;
        if idx >= self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        Ok(self.data[idx])
    }

    /// Read a halfword (16-bit) from memory (little-endian).
    ///
    /// # Errors
    /// Returns `UnalignedAccess` if addr is not 2-byte aligned (unprovable trap).
    #[inline]
    pub fn read_u16(&self, addr: u32) -> Result<u16, ExecutorError> {
        if addr & 1 != 0 {
            return Err(ExecutorError::UnalignedAccess {
                addr,
                access_type: "halfword read",
                required: 2,
            });
        }
        let idx = addr as usize;
        if idx + 1 >= self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        Ok(u16::from_le_bytes([self.data[idx], self.data[idx + 1]]))
    }

    /// Read a word (32-bit) from memory (little-endian).
    ///
    /// # Errors
    /// Returns `UnalignedAccess` if addr is not 4-byte aligned (unprovable trap).
    #[inline]
    pub fn read_u32(&self, addr: u32) -> Result<u32, ExecutorError> {
        if addr & 3 != 0 {
            return Err(ExecutorError::UnalignedAccess {
                addr,
                access_type: "word read",
                required: 4,
            });
        }
        let idx = addr as usize;
        if idx + 3 >= self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        Ok(u32::from_le_bytes([
            self.data[idx],
            self.data[idx + 1],
            self.data[idx + 2],
            self.data[idx + 3],
        ]))
    }

    /// Write a byte to memory.
    #[inline]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> Result<(), ExecutorError> {
        let idx = addr as usize;
        if idx >= self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        self.data[idx] = val;
        Ok(())
    }

    /// Write a halfword (16-bit) to memory (little-endian).
    ///
    /// # Errors
    /// Returns `UnalignedAccess` if addr is not 2-byte aligned (unprovable trap).
    #[inline]
    pub fn write_u16(&mut self, addr: u32, val: u16) -> Result<(), ExecutorError> {
        if addr & 1 != 0 {
            return Err(ExecutorError::UnalignedAccess {
                addr,
                access_type: "halfword write",
                required: 2,
            });
        }
        let idx = addr as usize;
        if idx + 1 >= self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        let bytes = val.to_le_bytes();
        self.data[idx] = bytes[0];
        self.data[idx + 1] = bytes[1];
        Ok(())
    }

    /// Write a word (32-bit) to memory (little-endian).
    ///
    /// # Errors
    /// Returns `UnalignedAccess` if addr is not 4-byte aligned (unprovable trap).
    #[inline]
    pub fn write_u32(&mut self, addr: u32, val: u32) -> Result<(), ExecutorError> {
        if addr & 3 != 0 {
            return Err(ExecutorError::UnalignedAccess {
                addr,
                access_type: "word write",
                required: 4,
            });
        }
        let idx = addr as usize;
        if idx + 3 >= self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr });
        }
        let bytes = val.to_le_bytes();
        self.data[idx] = bytes[0];
        self.data[idx + 1] = bytes[1];
        self.data[idx + 2] = bytes[2];
        self.data[idx + 3] = bytes[3];
        Ok(())
    }

    /// Get a slice of memory for inspection.
    pub fn slice(&self, start: u32, len: usize) -> Option<&[u8]> {
        let s = start as usize;
        if s + len <= self.data.len() {
            Some(&self.data[s..s + len])
        } else {
            None
        }
    }

    /// Write a slice of bytes to memory.
    pub fn write_slice(&mut self, start: u32, data: &[u8]) -> Result<(), ExecutorError> {
        let s = start as usize;
        if s + data.len() > self.data.len() {
            return Err(ExecutorError::OutOfBounds { addr: start });
        }
        self.data[s..s + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Check if an address range is valid.
    pub fn is_valid_range(&self, start: u32, len: u32) -> bool {
        let s = start as usize;
        let l = len as usize;
        s.checked_add(l).map_or(false, |end| end <= self.data.len())
    }

    /// Alias for read_u8 for backwards compatibility.
    #[inline]
    pub fn read_byte(&self, addr: u32) -> Result<u8, ExecutorError> {
        self.read_u8(addr)
    }

    /// Alias for write_u8 for backwards compatibility.
    #[inline]
    pub fn write_byte(&mut self, addr: u32, val: u8) -> Result<(), ExecutorError> {
        self.write_u8(addr, val)
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::with_default_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_u32() {
        let mut mem = Memory::new(1024);
        mem.write_u32(0x100, 0xDEADBEEF).unwrap();
        assert_eq!(mem.read_u32(0x100).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_unaligned_access() {
        let mem = Memory::new(1024);
        assert!(mem.read_u32(0x101).is_err());
        assert!(mem.read_u16(0x101).is_err());
    }

    #[test]
    fn test_load_program() {
        let mut mem = Memory::new(1024);
        let program = [0x13, 0x00, 0x00, 0x00]; // NOP
        mem.load_program(0x0, &program).unwrap();
        assert_eq!(mem.read_u32(0x0).unwrap(), 0x00000013);
    }
}
