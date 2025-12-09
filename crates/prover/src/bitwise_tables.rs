//! Bitwise lookup tables for efficient AND/OR/XOR verification.
//!
//! Instead of 32 polynomial constraints per bitwise operation, we use
//! precomputed 8-bit lookup tables. A 32-bit operation becomes 4 lookups.
//!
//! # Performance
//! - **Before**: 32 polynomial constraints + 96 witness columns per op
//! - **After**: 4 lookup accesses + 8 witness columns per op
//!
//! # Tables
//! Each table has (2^8)^2 = 65536 entries mapping (a, b) -> result

use zp1_primitives::M31;

/// Combined bitwise table for all three operations.
/// Uses index-based multiplicity tracking for LogUp proof generation.
pub struct BitwiseLookupTables {
    /// AND table values: entry[a*256+b] = a & b
    pub and_values: Vec<M31>,
    /// OR table values: entry[a*256+b] = a | b  
    pub or_values: Vec<M31>,
    /// XOR table values: entry[a*256+b] = a ^ b
    pub xor_values: Vec<M31>,
    /// Multiplicity counters for each table (tracked by index)
    and_mult: Vec<u32>,
    or_mult: Vec<u32>,
    xor_mult: Vec<u32>,
}

impl BitwiseLookupTables {
    /// Create all three bitwise lookup tables.
    pub fn new() -> Self {
        let size = 256 * 256;
        let mut and_values = Vec::with_capacity(size);
        let mut or_values = Vec::with_capacity(size);
        let mut xor_values = Vec::with_capacity(size);
        
        for a in 0u32..256 {
            for b in 0u32..256 {
                and_values.push(M31::new(a & b));
                or_values.push(M31::new(a | b));
                xor_values.push(M31::new(a ^ b));
            }
        }
        
        Self {
            and_values,
            or_values,
            xor_values,
            and_mult: vec![0; size],
            or_mult: vec![0; size],
            xor_mult: vec![0; size],
        }
    }
    
    /// Look up 8-bit AND: returns a & b and increments multiplicity
    #[inline]
    pub fn and8(&mut self, a: u8, b: u8) -> M31 {
        let idx = (a as usize) * 256 + (b as usize);
        self.and_mult[idx] += 1;
        self.and_values[idx]
    }
    
    /// Look up 8-bit OR: returns a | b and increments multiplicity
    #[inline]
    pub fn or8(&mut self, a: u8, b: u8) -> M31 {
        let idx = (a as usize) * 256 + (b as usize);
        self.or_mult[idx] += 1;
        self.or_values[idx]
    }
    
    /// Look up 8-bit XOR: returns a ^ b and increments multiplicity
    #[inline]
    pub fn xor8(&mut self, a: u8, b: u8) -> M31 {
        let idx = (a as usize) * 256 + (b as usize);
        self.xor_mult[idx] += 1;
        self.xor_values[idx]
    }
    
    /// Perform 32-bit AND using 4 byte-wise lookups.
    pub fn and32(&mut self, a: u32, b: u32) -> u32 {
        let mut result = 0u32;
        for i in 0..4 {
            let a_byte = ((a >> (i * 8)) & 0xFF) as u8;
            let b_byte = ((b >> (i * 8)) & 0xFF) as u8;
            let r = self.and8(a_byte, b_byte).value();
            result |= r << (i * 8);
        }
        result
    }
    
    /// Perform 32-bit OR using 4 byte-wise lookups.
    pub fn or32(&mut self, a: u32, b: u32) -> u32 {
        let mut result = 0u32;
        for i in 0..4 {
            let a_byte = ((a >> (i * 8)) & 0xFF) as u8;
            let b_byte = ((b >> (i * 8)) & 0xFF) as u8;
            let r = self.or8(a_byte, b_byte).value();
            result |= r << (i * 8);
        }
        result
    }
    
    /// Perform 32-bit XOR using 4 byte-wise lookups.
    pub fn xor32(&mut self, a: u32, b: u32) -> u32 {
        let mut result = 0u32;
        for i in 0..4 {
            let a_byte = ((a >> (i * 8)) & 0xFF) as u8;
            let b_byte = ((b >> (i * 8)) & 0xFF) as u8;
            let r = self.xor8(a_byte, b_byte).value();
            result |= r << (i * 8);
        }
        result
    }
    
    /// Get multiplicities for LogUp proof generation.
    pub fn get_multiplicities(&self) -> (&[u32], &[u32], &[u32]) {
        (&self.and_mult, &self.or_mult, &self.xor_mult)
    }
    
    /// Get table values for LogUp proof generation.
    pub fn get_values(&self) -> (&[M31], &[M31], &[M31]) {
        (&self.and_values, &self.or_values, &self.xor_values)
    }
}

impl Default for BitwiseLookupTables {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_and() {
        let mut tables = BitwiseLookupTables::new();
        
        assert_eq!(tables.and8(0, 0), M31::new(0));         // 0 & 0 = 0
        assert_eq!(tables.and8(255, 255), M31::new(255));   // 0xFF & 0xFF = 0xFF
        assert_eq!(tables.and8(0xAA, 0x55), M31::new(0));   // 0xAA & 0x55 = 0
    }
    
    #[test]
    fn test_or() {
        let mut tables = BitwiseLookupTables::new();
        
        assert_eq!(tables.or8(0, 0), M31::new(0));          // 0 | 0 = 0
        assert_eq!(tables.or8(0xAA, 0x55), M31::new(255));  // 0xAA | 0x55 = 0xFF
    }
    
    #[test]
    fn test_xor() {
        let mut tables = BitwiseLookupTables::new();
        
        assert_eq!(tables.xor8(0xFF, 0xFF), M31::new(0));   // 0xFF ^ 0xFF = 0
        assert_eq!(tables.xor8(0xAA, 0x55), M31::new(255)); // 0xAA ^ 0x55 = 0xFF
    }
    
    #[test]
    fn test_bitwise_32bit() {
        let mut tables = BitwiseLookupTables::new();
        
        let a = 0xDEADBEEF_u32;
        let b = 0xCAFEBABE_u32;
        
        assert_eq!(tables.and32(a, b), a & b);
        assert_eq!(tables.or32(a, b), a | b);
        assert_eq!(tables.xor32(a, b), a ^ b);
    }
    
    #[test]
    fn test_multiplicity_tracking() {
        let mut tables = BitwiseLookupTables::new();
        
        // Perform some lookups
        tables.and8(0x12, 0x34);
        tables.and8(0x12, 0x34);  // Same lookup twice
        
        let (and_mult, _, _) = tables.get_multiplicities();
        let idx = 0x12 * 256 + 0x34;
        
        // Should have been looked up twice
        assert_eq!(and_mult[idx], 2);
    }
}
