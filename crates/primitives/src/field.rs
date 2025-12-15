//! Mersenne31 field arithmetic.
//!
//! The Mersenne31 prime is p = 2^31 - 1 = 2147483647.
//! This field is efficient for STARK proving due to fast reduction
//! and good NTT-friendly properties via Circle STARKs or extension towers.

use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg};
use bytemuck::{Pod, Zeroable};
use serde::{Deserialize, Serialize};

/// The Mersenne31 prime: 2^31 - 1
pub const P: u32 = (1 << 31) - 1;

/// A field element in the Mersenne31 field.
///
/// Internally stored as a u32 in the range [0, P).
/// All arithmetic operations maintain this invariant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable, Serialize, Deserialize)]
#[repr(transparent)]
pub struct M31(pub u32);

impl M31 {
    /// The additive identity (zero).
    pub const ZERO: Self = Self(0);

    /// The multiplicative identity (one).
    pub const ONE: Self = Self(1);

    /// The prime modulus.
    pub const P: u32 = P;

    /// Create a new M31 element, reducing if necessary.
    #[inline]
    pub const fn new(val: u32) -> Self {
        // Apply double reduction to handle values >= 2*P
        // First reduction: if val >= P, subtract P
        let reduced = if val >= P { val - P } else { val };
        // Second reduction: if still >= P, subtract P again
        let reduced = if reduced >= P { reduced - P } else { reduced };
        Self(reduced)
    }

    /// Create from a u64, reducing mod P.
    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self::new((val % (P as u64)) as u32)
    }

    /// Reduce a u32 that may be in [0, 2P) to [0, P).
    #[inline]
    const fn reduce(val: u32) -> u32 {
        let reduced = val.wrapping_sub(P);
        if reduced < P { reduced } else { val }
    }

    /// Reduce a u64 product to M31.
    /// Uses the identity: x mod (2^31 - 1) = (x & P) + (x >> 31), iterated.
    #[inline]
    fn reduce_u64(val: u64) -> u32 {
        // First reduction: split into low 31 bits and high bits
        let lo = (val as u32) & P;
        let hi = (val >> 31) as u32;
        let sum = lo + hi;
        // sum is at most 2^32 - 1, so one more reduction suffices
        Self::reduce(Self::reduce(sum))
    }

    /// Get the inner value.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Get the inner value (alias for as_u32).
    #[inline]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// Compute the multiplicative inverse using Fermat's little theorem.
    /// a^(-1) = a^(p-2) mod p
    ///
    /// Panics if self is zero.
    #[inline]
    pub fn inv(self) -> Self {
        assert!(self.0 != 0, "cannot invert zero");
        self.pow(P - 2)
    }

    /// Exponentiation by squaring.
    #[inline]
    pub fn pow(self, mut exp: u32) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result *= base;
            }
            base *= base;
            exp >>= 1;
        }
        result
    }

    /// Exponentiation by squaring with u64 exponent.
    #[inline]
    pub fn pow_u64(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result *= base;
            }
            base *= base;
            exp >>= 1;
        }
        result
    }

    /// Square the element.
    #[inline]
    pub fn square(self) -> Self {
        self * self
    }

    /// Double the element (add to itself).
    #[inline]
    pub fn double(self) -> Self {
        self + self
    }

    /// Check if zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

// --- Arithmetic trait implementations ---

impl Add for M31 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        let sum = self.0 + rhs.0;
        Self(Self::reduce(sum))
    }
}

impl AddAssign for M31 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for M31 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        // Add P before subtracting to avoid underflow
        let diff = self.0.wrapping_add(P).wrapping_sub(rhs.0);
        Self(Self::reduce(diff))
    }
}

impl SubAssign for M31 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for M31 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let prod = (self.0 as u64) * (rhs.0 as u64);
        Self(Self::reduce_u64(prod))
    }
}

impl MulAssign for M31 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Neg for M31 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            self
        } else {
            Self(P - self.0)
        }
    }
}

impl From<u32> for M31 {
    #[inline]
    fn from(val: u32) -> Self {
        Self::new(val)
    }
}

impl From<M31> for u32 {
    #[inline]
    fn from(val: M31) -> u32 {
        val.0
    }
}

// --- Display ---

impl core::fmt::Display for M31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = M31::new(100);
        let b = M31::new(200);
        assert_eq!((a + b).as_u32(), 300);

        // Test wrap-around
        let c = M31::new(P - 1);
        let d = M31::new(2);
        assert_eq!((c + d).as_u32(), 1);
    }

    #[test]
    fn test_sub() {
        let a = M31::new(300);
        let b = M31::new(100);
        assert_eq!((a - b).as_u32(), 200);

        // Test underflow wrap
        let c = M31::new(1);
        let d = M31::new(2);
        assert_eq!((c - d).as_u32(), P - 1);
    }

    #[test]
    fn test_mul() {
        let a = M31::new(1000);
        let b = M31::new(2000);
        assert_eq!((a * b).as_u32(), 2_000_000);

        // Test large product reduction
        let c = M31::new(P - 1);
        let d = M31::new(2);
        // (P-1) * 2 = 2P - 2 ≡ P - 2 (mod P)
        assert_eq!((c * d).as_u32(), P - 2);
    }

    #[test]
    fn test_inv() {
        let a = M31::new(123456);
        let a_inv = a.inv();
        assert_eq!((a * a_inv).as_u32(), 1);

        // Test a few more
        for val in [1, 2, 3, 1000, P - 1] {
            let x = M31::new(val);
            let x_inv = x.inv();
            assert_eq!((x * x_inv).as_u32(), 1);
        }
    }

    #[test]
    fn test_pow() {
        let a = M31::new(2);
        assert_eq!(a.pow(10).as_u32(), 1024);

        // 2^31 mod (2^31 - 1) = 1
        assert_eq!(a.pow(31).as_u32(), 1);
    }

    #[test]
    fn test_neg() {
        let a = M31::new(100);
        let neg_a = -a;
        assert_eq!((a + neg_a).as_u32(), 0);

        assert_eq!((-M31::ZERO).as_u32(), 0);
    }

    /// Proof of Concept test demonstrating the bug in M31::new()
    /// 
    /// This test verifies that `new()` correctly reduces values >= 2*P.
    /// The original implementation only performed a single reduction step,
    /// which failed for values >= 2*P (values >= 2^32 - 2).
    #[test]
    fn test_new_reduction_bug_poc() {
        const TWO_P: u32 = 2 * P;
        
        // Test Case 1: val = 2*P = 2^32 - 2
        // Expected: 2*P mod P = 0
        let m1 = M31::new(TWO_P);
        assert_eq!(m1.as_u32(), 0, "M31::new(2*P) should be 0");

        // Test Case 2: val = u32::MAX = 2^32 - 1
        // Expected: (2^32 - 1) mod (2^31 - 1) = 1
        let m2 = M31::new(u32::MAX);
        assert_eq!(m2.as_u32(), 1, "M31::new(u32::MAX) should be 1");
    }

    /// Additional edge case tests for M31::new()
    #[test]
    fn test_new_edge_cases() {
        const TWO_P: u32 = 2 * P;
        
        // Basic values
        assert_eq!(M31::new(0).as_u32(), 0);
        assert_eq!(M31::new(1).as_u32(), 1);
        assert_eq!(M31::new(P - 1).as_u32(), P - 1);
        
        // Values at P boundary
        assert_eq!(M31::new(P).as_u32(), 0);
        assert_eq!(M31::new(P + 1).as_u32(), 1);
        
        // Values at 2*P boundary
        assert_eq!(M31::new(TWO_P - 1).as_u32(), P - 1);
        assert_eq!(M31::new(TWO_P).as_u32(), 0);
        
        // Maximum value
        assert_eq!(M31::new(u32::MAX).as_u32(), 1);
    }
}
