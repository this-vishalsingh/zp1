//! Quartic extension field over Mersenne31.
//!
//! # Field Tower Construction
//!
//! We construct QM31 using a tower of two quadratic extensions:
//!
//! 1. **CM31 = M31[i]/(i² + 1)** - Complex extension where i² = -1
//!    - Since M31 ≡ 3 (mod 4), -1 is NOT a quadratic residue, so this is irreducible
//!    - Elements: a + bi where a, b ∈ M31
//!    - Conjugate: conj(a + bi) = a - bi
//!    - Norm: N(z) = z * conj(z) = a² + b² (always in M31)
//!
//! 2. **QM31 = CM31[u]/(u² - (2+i))** - Quartic extension where u² = 2 + i
//!    - (2+i) is NOT a square in CM31, so this is irreducible
//!    - Elements: z₀ + z₁u where z₀, z₁ ∈ CM31
//!    - Conjugate: conj(z₀ + z₁u) = z₀ - z₁u
//!    - Norm: N(α) = α * conj(α) = z₀² - (2+i)z₁² (in CM31)
//!
//! This gives |QM31| = (2³¹ - 1)⁴ ≈ 2^124 bits of security.
//!
//! # Representation
//!
//! QM31 elements are stored as (a, b, c, d) representing:
//! ```text
//! a + bi + cu + diu = a + bi + (c + di)u
//! ```
//! where:
//! - a, b, c, d ∈ M31
//! - i² = -1
//! - u² = 2 + i

use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use crate::field::M31;

// ============================================================================
// CM31: Complex Extension M31[i]/(i² + 1)
// ============================================================================

/// An element of CM31 = M31[i]/(i² + 1).
///
/// Represented as a + bi where a, b ∈ M31 and i² = -1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CM31 {
    /// Real part
    pub a: M31,
    /// Imaginary part (coefficient of i)
    pub b: M31,
}

impl CM31 {
    /// The additive identity.
    pub const ZERO: Self = Self { a: M31::ZERO, b: M31::ZERO };

    /// The multiplicative identity.
    pub const ONE: Self = Self { a: M31::ONE, b: M31::ZERO };

    /// The imaginary unit i where i² = -1.
    pub const I: Self = Self { a: M31::ZERO, b: M31::ONE };

    /// Create a new CM31 element.
    #[inline]
    pub const fn new(a: M31, b: M31) -> Self {
        Self { a, b }
    }

    /// Embed an M31 element into CM31.
    #[inline]
    pub const fn from_base(val: M31) -> Self {
        Self { a: val, b: M31::ZERO }
    }

    /// Check if this is a real element (b = 0).
    #[inline]
    pub fn is_real(&self) -> bool {
        self.b.is_zero()
    }

    /// Check if zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.a.is_zero() && self.b.is_zero()
    }

    /// Complex conjugate: conj(a + bi) = a - bi.
    #[inline]
    pub fn conjugate(self) -> Self {
        Self { a: self.a, b: -self.b }
    }

    /// Norm: N(z) = z * conj(z) = a² + b² (result is in M31).
    #[inline]
    pub fn norm(self) -> M31 {
        self.a * self.a + self.b * self.b
    }

    /// Compute the multiplicative inverse.
    ///
    /// For z = a + bi:
    /// z⁻¹ = conj(z) / N(z) = (a - bi) / (a² + b²)
    #[inline]
    pub fn inv(self) -> Self {
        let n = self.norm();
        assert!(!n.is_zero(), "cannot invert zero element in CM31");
        let n_inv = n.inv();
        Self {
            a: self.a * n_inv,
            b: -self.b * n_inv,
        }
    }

    /// Square the element.
    /// (a + bi)² = (a² - b²) + 2abi
    #[inline]
    pub fn square(self) -> Self {
        let two = M31::new(2);
        Self {
            a: self.a * self.a - self.b * self.b,
            b: two * self.a * self.b,
        }
    }
}

impl Add for CM31 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self { a: self.a + rhs.a, b: self.b + rhs.b }
    }
}

impl AddAssign for CM31 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) { *self = *self + rhs; }
}

impl Sub for CM31 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self { a: self.a - rhs.a, b: self.b - rhs.b }
    }
}

impl SubAssign for CM31 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) { *self = *self - rhs; }
}

impl Mul for CM31 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        // (a + bi)(c + di) = (ac - bd) + (ad + bc)i
        Self {
            a: self.a * rhs.a - self.b * rhs.b,
            b: self.a * rhs.b + self.b * rhs.a,
        }
    }
}

impl MulAssign for CM31 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; }
}

impl Neg for CM31 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Self { a: -self.a, b: -self.b }
    }
}

impl From<M31> for CM31 {
    #[inline]
    fn from(val: M31) -> Self { Self::from_base(val) }
}

// ============================================================================
// QM31: Quartic Extension CM31[u]/(u² - (2+i))
// ============================================================================

/// The non-residue in CM31 used to define the extension: u² = 2 + i.
pub const U_SQUARED: CM31 = CM31 { a: M31(2), b: M31(1) };

/// An element of QM31 = CM31[u]/(u² - (2+i)).
///
/// Represented as z₀ + z₁u where z₀, z₁ ∈ CM31.
/// Equivalently stored as (a, b, c, d) representing a + bi + cu + diu.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QM31 {
    /// Coefficient z₀ = a + bi (constant part)
    pub c0: M31,
    pub c1: M31,
    /// Coefficient z₁ = c + di (coefficient of u)
    pub c2: M31,
    pub c3: M31,
}

impl QM31 {
    /// The additive identity.
    pub const ZERO: Self = Self {
        c0: M31::ZERO, c1: M31::ZERO,
        c2: M31::ZERO, c3: M31::ZERO,
    };

    /// The multiplicative identity.
    pub const ONE: Self = Self {
        c0: M31::ONE, c1: M31::ZERO,
        c2: M31::ZERO, c3: M31::ZERO,
    };

    /// Create from four M31 coefficients: a + bi + cu + diu.
    #[inline]
    pub const fn new(c0: M31, c1: M31, c2: M31, c3: M31) -> Self {
        Self { c0, c1, c2, c3 }
    }

    /// Create from two CM31 elements: z₀ + z₁u.
    #[inline]
    pub const fn from_cm31(z0: CM31, z1: CM31) -> Self {
        Self { c0: z0.a, c1: z0.b, c2: z1.a, c3: z1.b }
    }

    /// Get the z₀ component (constant part).
    #[inline]
    pub const fn z0(&self) -> CM31 {
        CM31 { a: self.c0, b: self.c1 }
    }

    /// Get the z₁ component (coefficient of u).
    #[inline]
    pub const fn z1(&self) -> CM31 {
        CM31 { a: self.c2, b: self.c3 }
    }

    /// Embed an M31 element into QM31.
    #[inline]
    pub const fn from_base(val: M31) -> Self {
        Self {
            c0: val, c1: M31::ZERO,
            c2: M31::ZERO, c3: M31::ZERO,
        }
    }

    /// Embed a CM31 element into QM31.
    #[inline]
    pub const fn from_cm31_base(val: CM31) -> Self {
        Self { c0: val.a, c1: val.b, c2: M31::ZERO, c3: M31::ZERO }
    }

    /// Check if this element is in the base field M31.
    #[inline]
    pub fn is_base(&self) -> bool {
        self.c1.is_zero() && self.c2.is_zero() && self.c3.is_zero()
    }

    /// Check if this element is in CM31 (z₁ = 0).
    #[inline]
    pub fn is_cm31(&self) -> bool {
        self.c2.is_zero() && self.c3.is_zero()
    }

    /// Check if zero.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero() && self.c3.is_zero()
    }

    /// Conjugate over CM31: conj(z₀ + z₁u) = z₀ - z₁u.
    #[inline]
    pub fn conjugate(self) -> Self {
        Self {
            c0: self.c0, c1: self.c1,
            c2: -self.c2, c3: -self.c3,
        }
    }

    /// Norm to CM31: N(α) = α * conj(α) = z₀² - (2+i)z₁².
    #[inline]
    pub fn norm_cm31(self) -> CM31 {
        let z0 = self.z0();
        let z1 = self.z1();
        // z₀² - (2+i)·z₁²
        z0 * z0 - U_SQUARED * (z1 * z1)
    }

    /// Full norm to M31: N_M31(α) = N_CM31(N_QM31(α)).
    #[inline]
    pub fn norm_m31(self) -> M31 {
        self.norm_cm31().norm()
    }

    /// Compute the multiplicative inverse.
    ///
    /// For α = z₀ + z₁u:
    /// α⁻¹ = conj(α) / N(α)
    ///     = (z₀ - z₁u) / (z₀² - (2+i)z₁²)
    ///
    /// Where the division is in CM31.
    pub fn inv(self) -> Self {
        let z0 = self.z0();
        let z1 = self.z1();

        // Norm in CM31
        let norm = z0 * z0 - U_SQUARED * (z1 * z1);
        assert!(!norm.is_zero(), "cannot invert zero element in QM31");

        let norm_inv = norm.inv();

        // α⁻¹ = (z₀ - z₁u) · norm⁻¹
        let inv_z0 = z0 * norm_inv;
        let inv_z1 = CM31::ZERO - z1 * norm_inv;

        Self::from_cm31(inv_z0, inv_z1)
    }

    /// Square the element.
    #[inline]
    pub fn square(self) -> Self {
        self * self
    }

    /// Double the element.
    #[inline]
    pub fn double(self) -> Self {
        self + self
    }

    /// Exponentiation by squaring.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }
        result
    }

    /// Get the c0 coefficient.
    #[inline]
    pub const fn c0(&self) -> M31 { self.c0 }

    /// Get the c1 coefficient.
    #[inline]
    pub const fn c1(&self) -> M31 { self.c1 }

    /// Get the c2 coefficient.
    #[inline]
    pub const fn c2(&self) -> M31 { self.c2 }

    /// Get the c3 coefficient.
    #[inline]
    pub const fn c3(&self) -> M31 { self.c3 }
}

// ============================================================================
// QM31 Arithmetic Operations
// ============================================================================

impl Add for QM31 {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 + rhs.c0,
            c1: self.c1 + rhs.c1,
            c2: self.c2 + rhs.c2,
            c3: self.c3 + rhs.c3,
        }
    }
}

impl AddAssign for QM31 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) { *self = *self + rhs; }
}

impl Sub for QM31 {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0 - rhs.c0,
            c1: self.c1 - rhs.c1,
            c2: self.c2 - rhs.c2,
            c3: self.c3 - rhs.c3,
        }
    }
}

impl SubAssign for QM31 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) { *self = *self - rhs; }
}

impl Mul for QM31 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        // (z₀ + z₁u)(w₀ + w₁u) = z₀w₀ + (z₀w₁ + z₁w₀)u + z₁w₁u²
        //                      = z₀w₀ + (2+i)z₁w₁ + (z₀w₁ + z₁w₀)u
        let z0 = self.z0();
        let z1 = self.z1();
        let w0 = rhs.z0();
        let w1 = rhs.z1();

        // result_z0 = z₀w₀ + (2+i)z₁w₁
        let z1w1 = z1 * w1;
        let result_z0 = z0 * w0 + U_SQUARED * z1w1;

        // result_z1 = z₀w₁ + z₁w₀
        let result_z1 = z0 * w1 + z1 * w0;

        Self::from_cm31(result_z0, result_z1)
    }
}

impl MulAssign for QM31 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; }
}

impl Neg for QM31 {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self {
            c0: -self.c0,
            c1: -self.c1,
            c2: -self.c2,
            c3: -self.c3,
        }
    }
}

impl Div for QM31 {
    type Output = Self;

    #[inline]
    fn div(self, rhs: Self) -> Self {
        self * rhs.inv()
    }
}

impl DivAssign for QM31 {
    #[inline]
    fn div_assign(&mut self, rhs: Self) { *self = *self / rhs; }
}

impl From<M31> for QM31 {
    #[inline]
    fn from(val: M31) -> Self { Self::from_base(val) }
}

impl From<CM31> for QM31 {
    #[inline]
    fn from(val: CM31) -> Self { Self::from_cm31_base(val) }
}

// ============================================================================
// Display implementations
// ============================================================================

impl core::fmt::Display for CM31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.b.is_zero() {
            write!(f, "{}", self.a)
        } else if self.a.is_zero() {
            write!(f, "{}i", self.b)
        } else {
            write!(f, "{} + {}i", self.a, self.b)
        }
    }
}

impl core::fmt::Display for QM31 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "({} + {}i) + ({} + {}i)u", self.c0, self.c1, self.c2, self.c3)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------- CM31 Tests --------------------

    #[test]
    fn test_cm31_add() {
        let a = CM31::new(M31::new(3), M31::new(4));
        let b = CM31::new(M31::new(5), M31::new(6));
        let c = a + b;
        assert_eq!(c.a.as_u32(), 8);
        assert_eq!(c.b.as_u32(), 10);
    }

    #[test]
    fn test_cm31_mul() {
        // (3 + 4i)(5 + 6i) = 15 + 18i + 20i + 24i² = 15 + 38i - 24 = -9 + 38i
        let a = CM31::new(M31::new(3), M31::new(4));
        let b = CM31::new(M31::new(5), M31::new(6));
        let c = a * b;
        // -9 mod P = P - 9
        assert_eq!(c.a.as_u32(), M31::P - 9);
        assert_eq!(c.b.as_u32(), 38);
    }

    #[test]
    fn test_cm31_mul_identity() {
        let a = CM31::new(M31::new(123), M31::new(456));
        assert_eq!(a * CM31::ONE, a);
        assert_eq!(CM31::ONE * a, a);
    }

    #[test]
    fn test_cm31_conjugate() {
        let z = CM31::new(M31::new(3), M31::new(4));
        let conj_z = z.conjugate();
        assert_eq!(conj_z.a.as_u32(), 3);
        assert_eq!(conj_z.b.as_u32(), M31::P - 4);
    }

    #[test]
    fn test_cm31_norm() {
        // |3 + 4i|² = 9 + 16 = 25
        let z = CM31::new(M31::new(3), M31::new(4));
        assert_eq!(z.norm().as_u32(), 25);
    }

    #[test]
    fn test_cm31_inv() {
        let a = CM31::new(M31::new(123), M31::new(456));
        let a_inv = a.inv();
        let prod = a * a_inv;
        assert_eq!(prod, CM31::ONE);
    }

    #[test]
    fn test_cm31_i_squared() {
        // i² = -1
        let i = CM31::I;
        let i_sq = i * i;
        assert_eq!(i_sq.a.as_u32(), M31::P - 1); // -1
        assert_eq!(i_sq.b.as_u32(), 0);
    }

    // -------------------- QM31 Tests --------------------

    #[test]
    fn test_qm31_add() {
        let a = QM31::new(M31::new(1), M31::new(2), M31::new(3), M31::new(4));
        let b = QM31::new(M31::new(5), M31::new(6), M31::new(7), M31::new(8));
        let c = a + b;
        assert_eq!(c.c0.as_u32(), 6);
        assert_eq!(c.c1.as_u32(), 8);
        assert_eq!(c.c2.as_u32(), 10);
        assert_eq!(c.c3.as_u32(), 12);
    }

    #[test]
    fn test_qm31_mul_identity() {
        let a = QM31::new(M31::new(123), M31::new(456), M31::new(789), M31::new(101112));
        assert_eq!(a * QM31::ONE, a);
        assert_eq!(QM31::ONE * a, a);
    }

    #[test]
    fn test_qm31_mul_base() {
        // Multiplying two base field elements should stay in base field
        let a = QM31::from_base(M31::new(100));
        let b = QM31::from_base(M31::new(200));
        let c = a * b;
        assert!(c.is_base());
        assert_eq!(c.c0.as_u32(), 20000);
    }

    #[test]
    fn test_qm31_mul_cm31() {
        // Multiplying two CM31 elements should stay in CM31
        let a = QM31::from_cm31_base(CM31::new(M31::new(3), M31::new(4)));
        let b = QM31::from_cm31_base(CM31::new(M31::new(5), M31::new(6)));
        let c = a * b;
        assert!(c.is_cm31());
    }

    #[test]
    fn test_qm31_u_squared() {
        // u² = 2 + i
        let u = QM31::from_cm31(CM31::ZERO, CM31::ONE); // 0 + 1·u
        let u_sq = u * u;
        // Should be (2 + i) + 0·u
        assert_eq!(u_sq.c0.as_u32(), 2);
        assert_eq!(u_sq.c1.as_u32(), 1);
        assert_eq!(u_sq.c2.as_u32(), 0);
        assert_eq!(u_sq.c3.as_u32(), 0);
    }

    #[test]
    fn test_qm31_inv() {
        let a = QM31::new(M31::new(123), M31::new(456), M31::new(789), M31::new(321));
        let a_inv = a.inv();
        let prod = a * a_inv;

        assert_eq!(prod.c0.as_u32(), 1);
        assert_eq!(prod.c1.as_u32(), 0);
        assert_eq!(prod.c2.as_u32(), 0);
        assert_eq!(prod.c3.as_u32(), 0);
    }

    #[test]
    fn test_qm31_inv_base() {
        // Inverting a base field element in QM31 should give a base field result
        let a = QM31::from_base(M31::new(12345));
        let a_inv = a.inv();
        assert!(a_inv.is_base());
        assert_eq!(a * a_inv, QM31::ONE);
    }

    #[test]
    fn test_qm31_inv_cm31() {
        // Inverting a CM31 element in QM31 should stay in CM31
        let a = QM31::from_cm31_base(CM31::new(M31::new(123), M31::new(456)));
        let a_inv = a.inv();
        assert!(a_inv.is_cm31());
        assert_eq!(a * a_inv, QM31::ONE);
    }

    #[test]
    fn test_qm31_div() {
        let a = QM31::new(M31::new(100), M31::new(200), M31::new(300), M31::new(400));
        let b = QM31::new(M31::new(10), M31::new(20), M31::new(30), M31::new(40));
        let c = a / b;
        // Verify: b * c = a
        assert_eq!(b * c, a);
    }

    #[test]
    fn test_qm31_pow() {
        let a = QM31::new(M31::new(2), M31::new(3), M31::new(5), M31::new(7));
        let a_sq = a.pow(2);
        assert_eq!(a_sq, a * a);

        let a_cubed = a.pow(3);
        assert_eq!(a_cubed, a * a * a);
    }

    #[test]
    fn test_qm31_conjugate() {
        let a = QM31::new(M31::new(1), M31::new(2), M31::new(3), M31::new(4));
        let conj_a = a.conjugate();
        // conj(z₀ + z₁u) = z₀ - z₁u
        assert_eq!(conj_a.c0.as_u32(), 1);
        assert_eq!(conj_a.c1.as_u32(), 2);
        assert_eq!(conj_a.c2.as_u32(), M31::P - 3);
        assert_eq!(conj_a.c3.as_u32(), M31::P - 4);
    }

    #[test]
    fn test_qm31_norm_is_in_cm31() {
        let a = QM31::new(M31::new(123), M31::new(456), M31::new(789), M31::new(321));
        // a * conj(a) should be in CM31 (z₁ = 0)
        let prod = a * a.conjugate();
        assert!(prod.is_cm31());
    }

    #[test]
    fn test_qm31_associativity() {
        let a = QM31::new(M31::new(1), M31::new(2), M31::new(3), M31::new(4));
        let b = QM31::new(M31::new(5), M31::new(6), M31::new(7), M31::new(8));
        let c = QM31::new(M31::new(9), M31::new(10), M31::new(11), M31::new(12));
        assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn test_qm31_commutativity() {
        let a = QM31::new(M31::new(111), M31::new(222), M31::new(333), M31::new(444));
        let b = QM31::new(M31::new(555), M31::new(666), M31::new(777), M31::new(888));
        assert_eq!(a * b, b * a);
    }

    #[test]
    fn test_qm31_distributivity() {
        let a = QM31::new(M31::new(1), M31::new(2), M31::new(3), M31::new(4));
        let b = QM31::new(M31::new(5), M31::new(6), M31::new(7), M31::new(8));
        let c = QM31::new(M31::new(9), M31::new(10), M31::new(11), M31::new(12));
        assert_eq!(a * (b + c), a * b + a * c);
    }
}
