//! 16-bit limb utilities for 32-bit word decomposition.
//!
//! RISC-V 32-bit values are decomposed into two 16-bit limbs for
//! efficient range checking and constraint degree reduction in AIR.

use crate::field::M31;

/// Decompose a 32-bit value into two 16-bit limbs (low, high).
#[inline]
pub fn to_limbs(val: u32) -> (u16, u16) {
    let lo = (val & 0xFFFF) as u16;
    let hi = (val >> 16) as u16;
    (lo, hi)
}

/// Reconstruct a 32-bit value from two 16-bit limbs (low, high).
#[inline]
pub fn from_limbs(lo: u16, hi: u16) -> u32 {
    (lo as u32) | ((hi as u32) << 16)
}

/// Decompose a 32-bit value into two M31 field elements representing the limbs.
#[inline]
pub fn to_limbs_m31(val: u32) -> (M31, M31) {
    let (lo, hi) = to_limbs(val);
    (M31::new(lo as u32), M31::new(hi as u32))
}

/// Reconstruct a 32-bit value from two M31 limbs.
/// Assumes the limbs are in range [0, 2^16).
#[inline]
pub fn from_limbs_m31(lo: M31, hi: M31) -> u32 {
    from_limbs(lo.as_u32() as u16, hi.as_u32() as u16)
}

/// Check if a value fits in 16 bits.
#[inline]
pub const fn is_u16(val: u32) -> bool {
    val <= 0xFFFF
}

/// Check if an M31 element represents a valid 16-bit limb.
#[inline]
pub fn is_valid_limb(val: M31) -> bool {
    is_u16(val.as_u32())
}

/// Decompose a 64-bit value into four 16-bit limbs (for intermediate products).
#[inline]
pub fn to_limbs_64(val: u64) -> (u16, u16, u16, u16) {
    let l0 = (val & 0xFFFF) as u16;
    let l1 = ((val >> 16) & 0xFFFF) as u16;
    let l2 = ((val >> 32) & 0xFFFF) as u16;
    let l3 = ((val >> 48) & 0xFFFF) as u16;
    (l0, l1, l2, l3)
}

/// Reconstruct a 64-bit value from four 16-bit limbs.
#[inline]
pub fn from_limbs_64(l0: u16, l1: u16, l2: u16, l3: u16) -> u64 {
    (l0 as u64) | ((l1 as u64) << 16) | ((l2 as u64) << 32) | ((l3 as u64) << 48)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_32() {
        for val in [0u32, 1, 0xFFFF, 0x10000, 0xFFFFFFFF, 0xDEADBEEF] {
            let (lo, hi) = to_limbs(val);
            assert_eq!(from_limbs(lo, hi), val);
        }
    }

    #[test]
    fn test_roundtrip_64() {
        for val in [0u64, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xDEADBEEFCAFEBABE] {
            let (l0, l1, l2, l3) = to_limbs_64(val);
            assert_eq!(from_limbs_64(l0, l1, l2, l3), val);
        }
    }

    #[test]
    fn test_m31_limbs() {
        let val = 0xABCD1234u32;
        let (lo, hi) = to_limbs_m31(val);
        assert!(is_valid_limb(lo));
        assert!(is_valid_limb(hi));
        assert_eq!(from_limbs_m31(lo, hi), val);
    }
}
