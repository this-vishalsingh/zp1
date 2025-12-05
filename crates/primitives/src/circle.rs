//! Circle group and Circle FFT for Mersenne31.
//!
//! M31 doesn't have large 2-adic subgroups (p-1 = 2 * 3 * 7 * ...),
//! so standard NTT doesn't work. Instead, we use the circle group
//! { (x, y) : x^2 + y^2 = 1 } over M31.
//!
//! The circle group over M31 has order |C| = 2 * (p + 1) = 2^32,
//! giving us plenty of room for large FFT domains.
//!
//! Reference: Circle STARKs (Polygon/StarkWare)

use crate::field::M31;

/// Modular square root using Tonelli-Shanks (simplified for M31).
/// M31 = 3 mod 4, so sqrt(a) = a^((p+1)/4) when a is a QR.
fn sqrt_m31(a: M31) -> Option<M31> {
    if a == M31::ZERO {
        return Some(M31::ZERO);
    }
    
    // For p = 3 mod 4: sqrt(a) = a^((p+1)/4)
    // p + 1 = 2^31, so (p+1)/4 = 2^29
    let exp = 1u64 << 29;
    let r = a.pow_u64(exp);
    
    // Verify
    if r * r == a {
        Some(r)
    } else {
        None
    }
}

/// A point on the circle x^2 + y^2 = 1 over M31.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CirclePoint {
    pub x: M31,
    pub y: M31,
}

impl CirclePoint {
    /// The identity element (1, 0).
    pub const IDENTITY: Self = Self { x: M31::ONE, y: M31::ZERO };

    /// The point (0, 1) - has order 4.
    pub const J: Self = Self { x: M31::ZERO, y: M31::ONE };

    /// Create a new circle point.
    pub const fn new(x: M31, y: M31) -> Self {
        Self { x, y }
    }

    /// Create a point from x-coordinate, computing y.
    pub fn from_x(x: M31) -> Option<Self> {
        // y^2 = 1 - x^2
        let y2 = M31::ONE - x * x;
        sqrt_m31(y2).map(|y| Self { x, y })
    }

    /// Generator of a subgroup of order 2^k.
    /// The full circle group has order 2^32.
    pub fn generator(log_order: usize) -> Self {
        assert!(log_order <= 31, "Maximum subgroup order is 2^31");
        
        // Start with the generator of order 2^31 and square down
        let mut g = Self::generator_max_two_adicity();
        
        for _ in log_order..31 {
            g = g.double();
        }
        
        g
    }

    /// Generator of the maximal 2-adic subgroup (order 2^31).
    /// This is a carefully chosen point that generates a subgroup of order 2^31.
    fn generator_max_two_adicity() -> Self {
        // For x^2 + y^2 = 1 mod p with p = 2^31 - 1:
        // We need a point of order exactly 2^31.
        //
        // The circle group is isomorphic to Z/(p+1)Z = Z/2^31 Z.
        // A generator of the 2^31 subgroup corresponds to picking
        // a "small angle" that generates the full domain.
        //
        // Using the standard Circle STARK generator for M31:
        // These values are verified to satisfy x^2 + y^2 = 1 and
        // have order exactly 2^31.
        Self {
            x: M31::new(2),
            y: M31::new(1268011823),
        }
    }

    /// Double a point (squaring in the circle group).
    /// Uses angle doubling: (cos θ, sin θ)² = (cos 2θ, sin 2θ)
    /// = (cos²θ - sin²θ, 2 cos θ sin θ) = (2x² - 1, 2xy)
    #[inline]
    pub fn double(self) -> Self {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        Self {
            x: x2 - y2,
            y: (self.x * self.y).double(),
        }
    }

    /// Multiply two circle points (group addition = complex multiplication).
    /// (cos α, sin α) * (cos β, sin β) = (cos(α+β), sin(α+β))
    /// = (cos α cos β - sin α sin β, cos α sin β + sin α cos β)
    #[inline]
    pub fn mul(self, other: Self) -> Self {
        Self {
            x: self.x * other.x - self.y * other.y,
            y: self.x * other.y + self.y * other.x,
        }
    }

    /// Inverse (conjugate for unit circle).
    /// (x, y)^(-1) = (x, -y)
    #[inline]
    pub fn inv(self) -> Self {
        Self {
            x: self.x,
            y: -self.y,
        }
    }

    /// Compute self^n using repeated squaring.
    pub fn pow(self, mut n: u64) -> Self {
        let mut result = Self::IDENTITY;
        let mut base = self;
        
        while n > 0 {
            if n & 1 == 1 {
                result = result.mul(base);
            }
            base = base.double();
            n >>= 1;
        }
        
        result
    }

    /// Check if this is the identity.
    #[inline]
    pub fn is_identity(self) -> bool {
        self.x == M31::ONE && self.y == M31::ZERO
    }

    /// Verify that this point is on the circle.
    #[inline]
    pub fn is_valid(self) -> bool {
        self.x * self.x + self.y * self.y == M31::ONE
    }

    /// Get the x-coordinate (used in polynomial evaluations).
    #[inline]
    pub fn x_coord(self) -> M31 {
        self.x
    }
}

/// Circle FFT domain - a coset of the circle group.
#[derive(Clone, Debug)]
pub struct CircleDomain {
    /// Log2 of the domain size.
    pub log_size: usize,
    /// Domain size = 2^log_size.
    pub size: usize,
    /// Generator of this domain (point of order `size`).
    pub generator: CirclePoint,
    /// Precomputed domain points: [g^0, g^1, ..., g^(size-1)].
    points: Vec<CirclePoint>,
}

impl CircleDomain {
    /// Create a new circle domain of size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        let size = 1 << log_size;
        let generator = CirclePoint::generator(log_size);
        
        // Precompute all domain points
        let mut points = Vec::with_capacity(size);
        let mut current = CirclePoint::IDENTITY;
        for _ in 0..size {
            points.push(current);
            current = current.mul(generator);
        }
        
        Self {
            log_size,
            size,
            generator,
            points,
        }
    }

    /// Get the i-th domain point (wraps around if i >= size).
    #[inline]
    pub fn get_point(&self, i: usize) -> CirclePoint {
        self.points[i % self.size]
    }

    /// Get all domain points.
    pub fn points(&self) -> &[CirclePoint] {
        &self.points
    }

    /// Get all x-coordinates (for polynomial evaluation).
    pub fn x_coords(&self) -> Vec<M31> {
        self.points.iter().map(|p| p.x).collect()
    }
}

/// Circle FFT - transform between coefficient and evaluation representations.
/// Uses the Twin-Coset approach where evaluation points come in (x, y) and (x, -y) pairs.
#[derive(Clone, Debug)]
pub struct CircleFFT {
    domain: CircleDomain,
    /// Twiddle factors for the FFT butterfly operations.
    twiddles: Vec<M31>,
    /// Inverse twiddle factors.
    inv_twiddles: Vec<M31>,
}

impl CircleFFT {
    /// Create a new Circle FFT for domain size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        let domain = CircleDomain::new(log_size);
        
        // Precompute twiddle factors
        // For circle FFT, twiddles are based on x-coordinates at each level
        let size = domain.size;
        let mut twiddles = Vec::with_capacity(size);
        let mut inv_twiddles = Vec::with_capacity(size);
        
        for level in 0..log_size {
            let level_size = 1 << level;
            let step = size / (2 * level_size);
            
            for j in 0..level_size {
                let point = domain.get_point(j * step);
                twiddles.push(point.x);
                inv_twiddles.push(point.x); // Same for inverse due to structure
            }
        }
        
        Self {
            domain,
            twiddles,
            inv_twiddles,
        }
    }

    /// Forward FFT: coefficients -> evaluations.
    /// Evaluates a polynomial at all domain points.
    pub fn fft(&self, coeffs: &[M31]) -> Vec<M31> {
        let n = self.domain.size;
        assert!(coeffs.len() <= n, "Input too large for domain");
        
        // Pad to domain size
        let mut data: Vec<M31> = coeffs.to_vec();
        data.resize(n, M31::ZERO);
        
        // Bit-reverse permutation
        bit_reverse_permutation(&mut data);
        
        // Cooley-Tukey butterflies
        for level in 0..self.domain.log_size {
            let half_block = 1 << level;
            let block_size = half_block * 2;
            
            for block_start in (0..n).step_by(block_size) {
                for j in 0..half_block {
                    let i = block_start + j;
                    let u = data[i];
                    let v = data[i + half_block];
                    
                    // Butterfly: add/sub only for standard FFT structure
                    // For circle FFT, we use x-coordinate based twiddles
                    let twiddle_idx = (j * (n / block_size)) % n;
                    let w = self.domain.get_point(twiddle_idx).x;
                    
                    let t = v * w;
                    data[i] = u + t;
                    data[i + half_block] = u - t;
                }
            }
        }
        
        data
    }

    /// Inverse FFT: evaluations -> coefficients.
    pub fn ifft(&self, evals: &[M31]) -> Vec<M31> {
        let n = self.domain.size;
        assert_eq!(evals.len(), n, "Input must match domain size");
        
        let mut data = evals.to_vec();
        
        // Bit-reverse permutation
        bit_reverse_permutation(&mut data);
        
        // Inverse butterflies (reverse order, conjugate twiddles)
        for level in 0..self.domain.log_size {
            let half_block = 1 << level;
            let block_size = half_block * 2;
            
            for block_start in (0..n).step_by(block_size) {
                for j in 0..half_block {
                    let i = block_start + j;
                    let u = data[i];
                    let v = data[i + half_block];
                    
                    let twiddle_idx = (j * (n / block_size)) % n;
                    // Use inverse point for inverse transform
                    let w = self.domain.get_point(n - twiddle_idx).x;
                    
                    let t = v * w;
                    data[i] = u + t;
                    data[i + half_block] = u - t;
                }
            }
        }
        
        // Scale by 1/n
        let n_inv = M31::new(n as u32).inv();
        for x in &mut data {
            *x *= n_inv;
        }
        
        data
    }

    /// Low-degree extension: extend evaluations to a larger domain.
    pub fn extend(&self, evals: &[M31], log_extension: usize) -> Vec<M31> {
        // Get coefficients via iFFT
        let coeffs = self.ifft(evals);
        
        // Create larger FFT
        let new_log_size = self.domain.log_size + log_extension;
        let extended_fft = CircleFFT::new(new_log_size);
        
        // FFT on larger domain
        extended_fft.fft(&coeffs)
    }

    /// Get domain size.
    pub fn size(&self) -> usize {
        self.domain.size
    }

    /// Get log domain size.
    pub fn log_size(&self) -> usize {
        self.domain.log_size
    }

    /// Get a domain point.
    pub fn get_domain_point(&self, i: usize) -> CirclePoint {
        self.domain.get_point(i)
    }
}

/// Bit-reverse permutation in-place.
fn bit_reverse_permutation(data: &mut [M31]) {
    let n = data.len();
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros() as usize;
    
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            data.swap(i, j);
        }
    }
}

/// Reverse the bits of a number.
#[inline]
fn bit_reverse(mut x: usize, bits: usize) -> usize {
    let mut result = 0;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// Evaluate a polynomial at a single point using Horner's method.
pub fn evaluate_poly(coeffs: &[M31], x: M31) -> M31 {
    let mut result = M31::ZERO;
    for &c in coeffs.iter().rev() {
        result = result * x + c;
    }
    result
}

/// Interpolate a polynomial through (x_i, y_i) pairs using Lagrange.
/// This is O(n²) and only for small inputs/testing.
pub fn interpolate_naive(xs: &[M31], ys: &[M31]) -> Vec<M31> {
    let n = xs.len();
    assert_eq!(n, ys.len());
    
    let mut coeffs = vec![M31::ZERO; n];
    
    for i in 0..n {
        // Compute Lagrange basis polynomial L_i
        let mut basis = vec![M31::ZERO; n];
        basis[0] = M31::ONE;
        let mut denom = M31::ONE;
        
        let mut basis_degree = 0;
        for j in 0..n {
            if i == j {
                continue;
            }
            
            denom *= xs[i] - xs[j];
            
            // Multiply basis by (x - x_j)
            for k in (1..=basis_degree + 1).rev() {
                basis[k] = basis[k - 1] - xs[j] * basis[k];
            }
            basis[0] = -xs[j] * basis[0];
            basis_degree += 1;
        }
        
        // Add y_i * L_i / denom
        let scale = ys[i] * denom.inv();
        for k in 0..n {
            coeffs[k] += scale * basis[k];
        }
    }
    
    coeffs
}

/// Coset - a shifted copy of a domain (for LDE).
#[derive(Clone, Debug)]
pub struct Coset {
    /// Base domain.
    pub domain: CircleDomain,
    /// Coset shift.
    pub shift: CirclePoint,
    /// Shifted points.
    shifted_points: Vec<CirclePoint>,
}

impl Coset {
    /// Create a coset by shifting the domain.
    pub fn new(domain: CircleDomain, shift: CirclePoint) -> Self {
        let shifted_points = domain.points.iter()
            .map(|p| p.mul(shift))
            .collect();
        
        Self { domain, shift, shifted_points }
    }

    /// Create a standard LDE coset (shifted off the base domain).
    pub fn lde_coset(log_size: usize) -> Self {
        let domain = CircleDomain::new(log_size);
        // Shift by a generator of a larger group to get disjoint coset
        let shift = CirclePoint::generator(log_size + 1);
        Self::new(domain, shift)
    }

    /// Get the i-th coset element.
    pub fn get_point(&self, i: usize) -> CirclePoint {
        self.shifted_points[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt() {
        // Test sqrt of 4 = 2
        let four = M31::new(4);
        let two = sqrt_m31(four).unwrap();
        assert!(two * two == four);
        
        // Test sqrt of 1 = 1
        let one = M31::ONE;
        let r = sqrt_m31(one).unwrap();
        assert!(r * r == one);
    }

    #[test]
    fn test_circle_point_identity() {
        let p = CirclePoint::IDENTITY;
        assert!(p.is_valid());
        assert!(p.is_identity());
    }

    #[test]
    fn test_generator_is_valid() {
        // Check that the base generator is actually on the circle
        let g = CirclePoint::generator_max_two_adicity();
        let lhs = g.x * g.x + g.y * g.y;
        assert_eq!(lhs, M31::ONE, "Generator must satisfy x^2 + y^2 = 1");
    }

    #[test]
    fn test_circle_point_double() {
        let g = CirclePoint::generator(4);
        assert!(g.is_valid(), "Generator must be on circle");
        
        let g2 = g.double();
        assert!(g2.is_valid(), "Double must stay on circle");
        
        // g^2 should equal g * g
        let g_mul_g = g.mul(g);
        assert_eq!(g2.x, g_mul_g.x);
        assert_eq!(g2.y, g_mul_g.y);
    }

    #[test]
    fn test_circle_point_order() {
        // Generator of order 2^4 = 16
        let g = CirclePoint::generator(4);
        let g16 = g.pow(16);
        assert!(g16.is_identity(), "g^16 should be identity, got ({}, {})", g16.x.value(), g16.y.value());
        
        // g^8 should not be identity
        let g8 = g.pow(8);
        assert!(!g8.is_identity(), "g^8 should not be identity");
    }

    #[test]
    fn test_circle_domain() {
        let domain = CircleDomain::new(3);
        assert_eq!(domain.size, 8);
        
        // First point should be identity
        assert!(domain.get_point(0).is_identity());
        
        // All points should be valid
        for i in 0..domain.size {
            assert!(domain.get_point(i).is_valid(), "Point {} invalid", i);
        }
    }

    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse(0b000, 3), 0b000);
        assert_eq!(bit_reverse(0b001, 3), 0b100);
        assert_eq!(bit_reverse(0b010, 3), 0b010);
        assert_eq!(bit_reverse(0b100, 3), 0b001);
    }

    #[test]
    fn test_evaluate_poly() {
        // f(x) = 1 + 2x + 3x^2
        let coeffs = vec![M31::new(1), M31::new(2), M31::new(3)];
        
        // f(0) = 1
        assert_eq!(evaluate_poly(&coeffs, M31::ZERO), M31::new(1));
        
        // f(1) = 1 + 2 + 3 = 6
        assert_eq!(evaluate_poly(&coeffs, M31::ONE), M31::new(6));
        
        // f(2) = 1 + 4 + 12 = 17
        assert_eq!(evaluate_poly(&coeffs, M31::new(2)), M31::new(17));
    }

    #[test]
    fn test_interpolate() {
        let xs: Vec<M31> = (0..4).map(|i| M31::new(i)).collect();
        let ys = vec![M31::new(1), M31::new(6), M31::new(17), M31::new(34)];
        
        let coeffs = interpolate_naive(&xs, &ys);
        
        // Verify interpolation
        for (i, &x) in xs.iter().enumerate() {
            let y = evaluate_poly(&coeffs, x);
            assert_eq!(y, ys[i], "Interpolation failed at x={}", i);
        }
    }

    #[test]
    fn test_fft_constant() {
        // FFT of constant polynomial should give constant evaluations
        let fft = CircleFFT::new(3);
        let coeffs = vec![M31::new(42), M31::ZERO, M31::ZERO, M31::ZERO,
                         M31::ZERO, M31::ZERO, M31::ZERO, M31::ZERO];
        
        let evals = fft.fft(&coeffs);
        
        // All evaluations of f(x) = 42 should be 42
        for (i, &e) in evals.iter().enumerate() {
            assert_eq!(e, M31::new(42), "Eval at {} should be 42, got {}", i, e.value());
        }
    }
}
