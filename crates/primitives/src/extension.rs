//! Quartic extension field over M31.
//!
//! QM31 = M31[x] / (x^4 - 11), providing ~124 bits of security for
//! lookup grand products and FRI folding challenges.
//!
//! Represented as (a0, a1, a2, a3) where the element is
//! a0 + a1*w + a2*w^2 + a3*w^3, with w^4 = 11.

use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg};
use serde::{Deserialize, Serialize};
use crate::field::M31;

/// The constant for the irreducible polynomial: w^4 = W4
/// We use w^4 = 11 (a small quadratic non-residue in M31).
const W4: M31 = M31(11);

/// An element of the quartic extension field QM31 = M31[w]/(w^4 - 11).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QM31 {
    /// Coefficients: c0 + c1*w + c2*w^2 + c3*w^3
    pub c0: M31,
    pub c1: M31,
    pub c2: M31,
    pub c3: M31,
}

impl QM31 {
    /// The additive identity.
    pub const ZERO: Self = Self {
        c0: M31::ZERO,
        c1: M31::ZERO,
        c2: M31::ZERO,
        c3: M31::ZERO,
    };

    /// The multiplicative identity.
    pub const ONE: Self = Self {
        c0: M31::ONE,
        c1: M31::ZERO,
        c2: M31::ZERO,
        c3: M31::ZERO,
    };

    /// Create a new QM31 element.
    #[inline]
    pub const fn new(c0: M31, c1: M31, c2: M31, c3: M31) -> Self {
        Self { c0, c1, c2, c3 }
    }

    /// Embed an M31 element into QM31.
    #[inline]
    pub const fn from_base(val: M31) -> Self {
        Self {
            c0: val,
            c1: M31::ZERO,
            c2: M31::ZERO,
            c3: M31::ZERO,
        }
    }

    /// Check if this element is in the base field (c1 = c2 = c3 = 0).
    #[inline]
    pub fn is_base(&self) -> bool {
        self.c1.is_zero() && self.c2.is_zero() && self.c3.is_zero()
    }

    /// Square the element.
    #[inline]
    pub fn square(self) -> Self {
        self * self
    }

    /// Compute the multiplicative inverse.
    ///
    /// Uses the formula for inversion in a degree-4 extension via norm.
    /// Panics if self is zero.
    pub fn inv(self) -> Self {
        // For a quartic extension with w^4 = 11, we use:
        // Compute via conjugates and norm down to base field.
        //
        // The norm N(a) = a * conj1(a) * conj2(a) * conj3(a) is in M31.
        // Then a^(-1) = conj1(a) * conj2(a) * conj3(a) / N(a).
        //
        // For efficiency, we use a tower approach: QM31 = CM31[v]/(v^2 - u)
        // where CM31 = M31[u]/(u^2 - 11), then v^2 = u.
        //
        // Simplified direct computation for now (can be optimized):

        // Compute a * conj(a) in the quadratic subfield, then invert.
        // This is a standard approach for quartic extensions.

        // For w^4 = 11:
        // conj(a0 + a1*w + a2*w^2 + a3*w^3) at w -> -w gives:
        // a0 - a1*w + a2*w^2 - a3*w^3
        //
        // But we need all four conjugates for the norm.
        // Let's use a simpler direct Gaussian elimination approach:

        // Actually, use the standard formula for degree-4 inversion.
        // a^(-1) = adj(a) / det(a) where we view multiplication as a matrix.

        // For simplicity, compute via repeated conjugates:
        // Let b = a * conj_w(a) where conj_w swaps sign of odd powers.
        // b is in M31[w^2], i.e., has form b0 + b2*w^2.
        // Then compute c = b * conj_{w^2}(b) which is in M31.
        // Finally a^(-1) = conj_w(a) * conj_{w^2}(b) / c.

        let a = self;

        // conj_w: a0 + a1*w + a2*w^2 + a3*w^3 -> a0 - a1*w + a2*w^2 - a3*w^3
        let a_conj_w = QM31::new(a.c0, -a.c1, a.c2, -a.c3);

        // b = a * a_conj_w should have c1 = c3 = 0
        let b = a * a_conj_w;
        // b is in the subfield M31[w^2], so b.c1 and b.c3 should be zero (or tiny due to reduction)
        debug_assert!(b.c1.is_zero() && b.c3.is_zero(), "conjugate product not in subfield");

        // b = b0 + b2*w^2. Its conjugate under w^2 -> -w^2 is b0 - b2*w^2.
        // But w^4 = 11, so (w^2)^2 = 11. In M31[w^2]/(w^4 - 11) = M31[u]/(u^2 - 11):
        // conj: b0 + b2*u -> b0 - b2*u doesn't work directly since u^2 = 11, not -11.
        //
        // For M31[u]/(u^2 - 11), the "conjugate" is the Galois conjugate under u -> -u,
        // but that's not in the field if 11 is not a square.
        //
        // Let's use a different approach: compute norm via resultant.
        // norm(a) = Res(a(x), x^4 - 11) as polynomial in the coefficients.

        // For practical implementation, use the explicit formula:
        // Let a = (a0, a1, a2, a3). Multiplication by a is a 4x4 matrix M_a.
        // det(M_a) is the norm, and adj(M_a) gives the inverse coefficients.

        // Direct 4x4 determinant computation:
        // Compute det directly:
        let det = Self::compute_norm(a.c0, a.c1, a.c2, a.c3);
        assert!(!det.is_zero(), "cannot invert zero element in QM31");

        let det_inv = det.inv();

        // Adjugate coefficients (scaled inverse)
        let (adj0, adj1, adj2, adj3) = Self::compute_adjugate(a.c0, a.c1, a.c2, a.c3);

        QM31::new(
            adj0 * det_inv,
            adj1 * det_inv,
            adj2 * det_inv,
            adj3 * det_inv,
        )
    }

    /// Compute the norm (determinant of multiplication matrix) for inversion.
    fn compute_norm(a0: M31, a1: M31, a2: M31, a3: M31) -> M31 {
        // The multiplication matrix for a = a0 + a1*w + a2*w^2 + a3*w^3 is:
        // [a0,    11*a3, 11*a2, 11*a1]
        // [a1,    a0,    11*a3, 11*a2]
        // [a2,    a1,    a0,    11*a3]
        // [a3,    a2,    a1,    a0   ]
        //
        // This is a circulant-like matrix. The determinant can be computed
        // via the formula for such matrices.

        let w4 = W4;

        // Using direct expansion (can be optimized with Frobenius):
        // det = a0^4 + 11*a1^4 + 121*a2^4 + 1331*a3^4
        //     - 6*a0^2*a2^2*11 - 6*a1^2*a3^2*11
        //     + ... (cross terms)

        // For correctness, let's compute a * conj products:
        // N(a) = (a0^2 + 11*a2^2 - 2*11*a1*a3)^2 - 11*(2*a0*a2 - a1^2 - 11*a3^2)^2
        // This formula comes from the tower: QM31 = CM31[v]/(v^2 - u) where CM31 = M31[u]/(u^2 - 11).

        // Let's define:
        // In CM31: let z = a0 + a2*u, w_coef = a1 + a3*u (where the element is z + w_coef * v)
        // Then norm_CM31(z) = a0^2 - 11*a2^2 (Galois conjugate formula for u -> -u)
        // Wait, that's for u^2 = -11. We have u^2 = 11, so the norm is a0^2 - 11*a2^2 only if we
        // extend to where 11 has a square root.

        // Simpler: directly compute det of 4x4 using cofactor expansion.
        // This is O(1) field operations, acceptable for now.

        // Row 0: [a0, 11*a3, 11*a2, 11*a1]
        // Row 1: [a1, a0,    11*a3, 11*a2]
        // Row 2: [a2, a1,    a0,    11*a3]
        // Row 3: [a3, a2,    a1,    a0   ]

        let m00 = a0; let m01 = w4 * a3; let m02 = w4 * a2; let m03 = w4 * a1;
        let m10 = a1; let m11 = a0;      let m12 = w4 * a3; let m13 = w4 * a2;
        let m20 = a2; let m21 = a1;      let m22 = a0;      let m23 = w4 * a3;
        let m30 = a3; let m31 = a2;      let m32 = a1;      let m33 = a0;

        // det = m00 * det3x3(rows 1,2,3 cols 1,2,3) - m01 * det3x3(...) + ...
        let minor00 = Self::det3(m11, m12, m13, m21, m22, m23, m31, m32, m33);
        let minor01 = Self::det3(m10, m12, m13, m20, m22, m23, m30, m32, m33);
        let minor02 = Self::det3(m10, m11, m13, m20, m21, m23, m30, m31, m33);
        let minor03 = Self::det3(m10, m11, m12, m20, m21, m22, m30, m31, m32);

        m00 * minor00 - m01 * minor01 + m02 * minor02 - m03 * minor03
    }

    /// 3x3 determinant helper.
    #[inline]
    fn det3(a: M31, b: M31, c: M31, d: M31, e: M31, f: M31, g: M31, h: M31, i: M31) -> M31 {
        a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)
    }

    /// Compute adjugate matrix first row (gives inverse coefficients when divided by det).
    fn compute_adjugate(a0: M31, a1: M31, a2: M31, a3: M31) -> (M31, M31, M31, M31) {
        let w4 = W4;

        let m00 = a0; let m01 = w4 * a3; let m02 = w4 * a2; let m03 = w4 * a1;
        let m10 = a1; let m11 = a0;      let m12 = w4 * a3; let m13 = w4 * a2;
        let m20 = a2; let m21 = a1;      let m22 = a0;      let m23 = w4 * a3;
        let m30 = a3; let m31 = a2;      let m32 = a1;      let m33 = a0;

        // Adjugate first row = cofactors of first column
        let adj0 = Self::det3(m11, m12, m13, m21, m22, m23, m31, m32, m33);
        let adj1 = -Self::det3(m01, m02, m03, m21, m22, m23, m31, m32, m33);
        let adj2 = Self::det3(m01, m02, m03, m11, m12, m13, m31, m32, m33);
        let adj3 = -Self::det3(m01, m02, m03, m11, m12, m13, m21, m22, m23);

        // Wait, adjugate transpose: adj[i][j] = (-1)^(i+j) * M[j][i]
        // For the inverse, we need the first row of adj^T, which is the first column of adj.
        // The first column of adj is the cofactors of the first row of M.

        // Cofactor C[0][j] = (-1)^j * minor of (0,j)
        let c00 = Self::det3(m11, m12, m13, m21, m22, m23, m31, m32, m33);
        let c01 = -Self::det3(m10, m12, m13, m20, m22, m23, m30, m32, m33);
        let c02 = Self::det3(m10, m11, m13, m20, m21, m23, m30, m31, m33);
        let c03 = -Self::det3(m10, m11, m12, m20, m21, m22, m30, m31, m32);

        // adj^T first row = [C00, C10, C20, C30]
        // We need the full adjugate to get all inverse coefficients.
        // Since a^{-1} = adj(M_a)^T * e_0 / det, where e_0 = (1,0,0,0),
        // we get a^{-1} = (adj^T)[0] / det = first row of adj^T / det.

        // First row of adj^T = first column of adj = cofactors of first row of M.
        // These are c00, c01, c02, c03 computed above, but we need column cofactors.

        // Actually, to get a^{-1}, note that M_a * a^{-1} = I, so the first column of M_a^{-1}
        // gives the representation of 1/a. The first column of M^{-1} = adj(M)^T / det column 0.

        // adj(M)^T column 0 = adj(M) row 0 = cofactors of M row 0.
        // Cofactor(0,j) = (-1)^j * minor(0,j).

        (c00, c01, c02, c03)
    }

    #[allow(dead_code)]
    fn adjugate_and_det(_a0: M31, _a1: M31, _a2: M31, _a3: M31) -> (M31, M31, M31, M31) {
        // Placeholder; we use compute_norm and compute_adjugate separately.
        unimplemented!()
    }
}

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
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
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
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for QM31 {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        // Schoolbook multiplication with reduction using w^4 = 11.
        let a = self;
        let b = rhs;
        let w4 = W4;

        // Product before reduction:
        // c0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1)
        // c1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2)
        // c2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3)
        // c3 = a0*b3 + a1*b2 + a2*b1 + a3*b0

        let c0 = a.c0 * b.c0 + w4 * (a.c1 * b.c3 + a.c2 * b.c2 + a.c3 * b.c1);
        let c1 = a.c0 * b.c1 + a.c1 * b.c0 + w4 * (a.c2 * b.c3 + a.c3 * b.c2);
        let c2 = a.c0 * b.c2 + a.c1 * b.c1 + a.c2 * b.c0 + w4 * (a.c3 * b.c3);
        let c3 = a.c0 * b.c3 + a.c1 * b.c2 + a.c2 * b.c1 + a.c3 * b.c0;

        Self { c0, c1, c2, c3 }
    }
}

impl MulAssign for QM31 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
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

impl From<M31> for QM31 {
    #[inline]
    fn from(val: M31) -> Self {
        Self::from_base(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let one = QM31::ONE;
        assert_eq!(a * one, a);
        assert_eq!(one * a, a);
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
    fn test_qm31_inv() {
        let a = QM31::new(M31::new(123), M31::new(456), M31::new(789), M31::new(321));
        let a_inv = a.inv();
        let prod = a * a_inv;

        // Should be very close to ONE (exact in finite field)
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

        let prod = a * a_inv;
        assert_eq!(prod, QM31::ONE);
    }
}
