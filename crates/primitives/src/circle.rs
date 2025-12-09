//! Circle group and Circle FFT for Mersenne31.
//!
//! # Circle STARKs Background
//!
//! The Mersenne31 field M31 doesn't have large 2-adic subgroups for standard NTT
//! (since p-1 = 2·3·7·11·31·151·331, only a factor of 2).
//!
//! Instead, Circle STARKs use the **circle group**:
//! ```text
//! C(M31) = { (x, y) ∈ M31² : x² + y² = 1 }
//! ```
//!
//! This group has order |C| = p + 1 = 2^31, giving us a full 2-adic subgroup!
//!
//! # Group Operations
//!
//! The circle group is isomorphic to the group of complex numbers with |z| = 1,
//! under the map (x, y) ↔ x + iy. Multiplication follows the angle-addition formulas:
//! - Identity: (1, 0)
//! - Inverse: (x, y)⁻¹ = (x, -y)  
//! - Product: (x₁, y₁) · (x₂, y₂) = (x₁x₂ - y₁y₂, x₁y₂ + y₁x₂)
//! - Squaring: (x, y)² = (x² - y², 2xy) = (2x² - 1, 2xy)
//!
//! # Polynomial Evaluation
//!
//! We evaluate standard polynomials f(x) at the x-coordinates of circle points.
//! However, for proper Circle FFT, we need to handle the fact that points
//! (x, y) and (x, -y) share the same x-coordinate.
//!
//! # References
//!
//! - Circle STARKs paper (Polygon/StarkWare)
//! - Stwo prover implementation

use crate::field::M31;
use serde::{Deserialize, Serialize};

// ============================================================================
// Square Root in M31
// ============================================================================

/// Modular square root in M31.
///
/// Since M31 ≡ 3 (mod 4), we can use the simple formula:
/// sqrt(a) = a^((p+1)/4) = a^(2^29)
///
/// Returns None if a is not a quadratic residue.
pub fn sqrt_m31(a: M31) -> Option<M31> {
    if a.is_zero() {
        return Some(M31::ZERO);
    }
    
    // For p ≡ 3 (mod 4): sqrt(a) = a^((p+1)/4) = a^(2^29)
    let r = a.pow_u64(1u64 << 29);
    
    // Verify: r² = a
    if r * r == a {
        Some(r)
    } else {
        None // a is not a quadratic residue
    }
}

// ============================================================================
// Circle Point
// ============================================================================

/// A point on the unit circle x² + y² = 1 over M31.
///
/// Represents an element of the multiplicative circle group C(M31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CirclePoint {
    /// The x-coordinate (cos θ in the angle interpretation).
    pub x: M31,
    /// The y-coordinate (sin θ in the angle interpretation).
    pub y: M31,
}

impl CirclePoint {
    /// The identity element (1, 0) - corresponds to angle 0.
    pub const IDENTITY: Self = Self { x: M31::ONE, y: M31::ZERO };

    /// The point (0, 1) - corresponds to angle π/2, has order 4.
    pub const I: Self = Self { x: M31::ZERO, y: M31::ONE };

    /// The point (-1, 0) - corresponds to angle π, has order 2.
    pub const NEG_ONE: Self = Self { x: M31(M31::P - 1), y: M31::ZERO };

    /// Create a new circle point (does not verify it's on the circle).
    #[inline]
    pub const fn new(x: M31, y: M31) -> Self {
        Self { x, y }
    }

    /// Create a point from the x-coordinate, computing y = ±√(1 - x²).
    /// Returns the point with positive y (or y = 0).
    pub fn from_x(x: M31) -> Option<Self> {
        let y_squared = M31::ONE - x * x;
        sqrt_m31(y_squared).map(|y| Self { x, y })
    }

    /// Check if this point is on the unit circle: x² + y² = 1.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.x * self.x + self.y * self.y == M31::ONE
    }

    /// Check if this is the identity (1, 0).
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.x == M31::ONE && self.y.is_zero()
    }

    /// Group multiplication (corresponds to adding angles).
    /// (x₁, y₁) · (x₂, y₂) = (x₁x₂ - y₁y₂, x₁y₂ + y₁x₂)
    #[inline]
    pub fn mul(self, other: Self) -> Self {
        Self {
            x: self.x * other.x - self.y * other.y,
            y: self.x * other.y + self.y * other.x,
        }
    }

    /// Squaring (doubling the angle).
    /// (x, y)² = (x² - y², 2xy) = (2x² - 1, 2xy)
    #[inline]
    pub fn double(self) -> Self {
        Self {
            x: self.x * self.x - self.y * self.y,
            y: self.x * self.y + self.x * self.y, // 2xy
        }
    }

    /// Inverse (negating the angle).
    /// (x, y)⁻¹ = (x, -y)
    #[inline]
    pub fn inv(self) -> Self {
        Self { x: self.x, y: -self.y }
    }

    /// Conjugate - same as inverse for unit circle.
    #[inline]
    pub fn conjugate(self) -> Self {
        self.inv()
    }

    /// Antipodal point: -P = (-x, -y) (NOT the inverse!).
    /// This is the "other" point at the same angle + π.
    #[inline]
    pub fn antipodal(self) -> Self {
        Self { x: -self.x, y: -self.y }
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

    /// Get x-coordinate.
    #[inline]
    pub fn x_coord(self) -> M31 {
        self.x
    }

    /// Get y-coordinate.  
    #[inline]
    pub fn y_coord(self) -> M31 {
        self.y
    }

    // ========================================================================
    // Generator Construction
    // ========================================================================

    /// Generator of the circle subgroup of order 2^log_order.
    ///
    /// The full circle group C(M31) has order p + 1 = 2^31.
    /// This returns a generator for the unique subgroup of order 2^log_order.
    pub fn generator(log_order: usize) -> Self {
        assert!(log_order <= 31, "Maximum subgroup order is 2^31");
        
        // Start with the generator of order 2^31
        let g = Self::generator_order_2_31();
        
        // Square (31 - log_order) times to get generator of order 2^log_order
        // g^(2^(31-k)) has order 2^k
        let mut result = g;
        for _ in log_order..31 {
            result = result.double();
        }
        
        result
    }

    /// Generator of the full 2^31 subgroup of C(M31).
    ///
    /// This is a primitive 2^31-th root of unity on the circle, meaning:
    /// - g^(2^31) = (1, 0)  
    /// - g^(2^30) ≠ (1, 0)
    ///
    /// We use the canonical generator from Circle STARKs:
    /// g = (2, sqrt(1 - 4)) = (2, sqrt(-3))
    fn generator_order_2_31() -> Self {
        // The canonical Circle STARK generator has x = 2
        // y² = 1 - x² = 1 - 4 = -3 (mod p)
        // -3 mod p = p - 3 = 2147483644
        //
        // We need sqrt(p - 3) mod p.
        // Precomputed: sqrt(2147483644) mod (2^31 - 1) = 1268011823
        //
        // Verification: 1268011823² mod (2^31 - 1) = 2147483644 ✓
        // And: 2² + 1268011823² mod (2^31 - 1) = 4 + 2147483644 = 2147483648 = 1 ✓

        let x = M31::new(2);
        let y = M31::new(1268011823);
        
        debug_assert!(x * x + y * y == M31::ONE, "Generator not on circle");
        
        Self { x, y }
    }

    /// Alternative generator constructor that computes y from x.
    #[allow(dead_code)]
    fn generator_order_2_31_computed() -> Self {
        let x = M31::new(2);
        let y_squared = M31::ONE - x * x;  // 1 - 4 = -3 = p - 3
        let y = sqrt_m31(y_squared).expect("y² should be a QR");
        Self { x, y }
    }
}

impl Default for CirclePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

// ============================================================================
// Circle Domain
// ============================================================================

/// A domain for Circle polynomial evaluation.
///
/// Represents the cyclic group generated by g where g has order 2^log_size.
/// Points are [g^0, g^1, ..., g^(n-1)] where n = 2^log_size.
#[derive(Clone, Debug)]
pub struct CircleDomain {
    /// Log₂ of the domain size.
    pub log_size: usize,
    /// Domain size = 2^log_size.
    pub size: usize,
    /// Generator of this domain.
    pub generator: CirclePoint,
    /// Precomputed domain points.
    points: Vec<CirclePoint>,
}

impl CircleDomain {
    /// Create a circle domain of size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        assert!(log_size <= 31, "Domain size exceeds circle group order");
        
        let size = 1usize << log_size;
        let generator = CirclePoint::generator(log_size);
        
        // Precompute all domain points: [g^0, g^1, ..., g^(n-1)]
        let mut points = Vec::with_capacity(size);
        let mut current = CirclePoint::IDENTITY;
        for _ in 0..size {
            points.push(current);
            current = current.mul(generator);
        }
        
        // Verify: the last multiplication should give identity
        debug_assert!(current.is_identity(), "Domain points don't form a cycle");
        
        Self { log_size, size, generator, points }
    }

    /// Get the i-th domain point (g^i).
    #[inline]
    pub fn get_point(&self, i: usize) -> CirclePoint {
        self.points[i % self.size]
    }

    /// Get all domain points.
    pub fn points(&self) -> &[CirclePoint] {
        &self.points
    }

    /// Get x-coordinates of all domain points.
    pub fn x_coords(&self) -> Vec<M31> {
        self.points.iter().map(|p| p.x).collect()
    }

    /// Get y-coordinates of all domain points.
    pub fn y_coords(&self) -> Vec<M31> {
        self.points.iter().map(|p| p.y).collect()
    }

    /// Check if all points are valid (on the circle).
    pub fn verify(&self) -> bool {
        self.points.iter().all(|p| p.is_valid())
    }
    
    /// Get unique x-coordinates (for polynomial evaluation).
    /// Returns (unique_xs, mapping) where mapping[i] gives the index in unique_xs
    /// for domain point i.
    pub fn unique_x_coords(&self) -> (Vec<M31>, Vec<usize>) {
        let mut unique_xs = Vec::new();
        let mut mapping = Vec::with_capacity(self.size);
        
        for p in &self.points {
            if let Some(idx) = unique_xs.iter().position(|&x| x == p.x) {
                mapping.push(idx);
            } else {
                mapping.push(unique_xs.len());
                unique_xs.push(p.x);
            }
        }
        
        (unique_xs, mapping)
    }
}

// ============================================================================
// Coset (for Low-Degree Extension)
// ============================================================================

/// A coset of a circle domain: { shift · g^i : i = 0, ..., n-1 }.
///
/// Used for low-degree extension (LDE) where we evaluate on a coset
/// disjoint from the original domain.
#[derive(Clone, Debug)]
pub struct Coset {
    /// The underlying domain.
    pub domain: CircleDomain,
    /// The coset shift.
    pub shift: CirclePoint,
    /// Shifted domain points.
    shifted_points: Vec<CirclePoint>,
}

impl Coset {
    /// Create a coset by shifting a domain.
    pub fn new(domain: CircleDomain, shift: CirclePoint) -> Self {
        let shifted_points = domain.points.iter()
            .map(|p| shift.mul(*p))
            .collect();
        
        Self { domain, shift, shifted_points }
    }

    /// Create the standard LDE coset.
    ///
    /// For a domain of size n with generator g (of order n),
    /// we shift by a generator h of order 2n, giving a coset
    /// disjoint from the original domain.
    pub fn lde_coset(log_size: usize) -> Self {
        let domain = CircleDomain::new(log_size);
        
        // Shift by generator of order 2n (one step up in the subgroup chain)
        // This gives a coset h·D that is disjoint from D
        let shift = CirclePoint::generator(log_size + 1);
        
        Self::new(domain, shift)
    }

    /// Get the i-th coset point.
    #[inline]
    pub fn get_point(&self, i: usize) -> CirclePoint {
        self.shifted_points[i % self.domain.size]
    }

    /// Get all coset points.
    pub fn points(&self) -> &[CirclePoint] {
        &self.shifted_points
    }

    /// Get size of the coset.
    pub fn size(&self) -> usize {
        self.domain.size
    }
}

// ============================================================================
// Circle FFT
// ============================================================================

/// Circle FFT for transforming between coefficient and evaluation representations.
///
/// # Note on Circle Polynomial Representation
///
/// Standard univariate polynomials f(x) cannot be directly evaluated on circle domains
/// because points (x, y) and (x, -y) share the same x-coordinate. Instead, we use:
///
/// 1. **For FFT**: Evaluate f(x) at the **unique** x-coordinates in the first half of
///    the domain. The domain is structured so the first half has all unique x-values.
///
/// 2. **For IFFT**: Interpolate using only the unique x-coordinates.
///
/// This gives us a consistent polynomial representation for Circle STARKs.
///
/// # Complexity
///
/// - FFT: O(n²) field operations (can be O(n log n) with proper Circle FFT)
/// - IFFT: O(n²) field operations (Lagrange interpolation)
#[derive(Clone, Debug)]
pub struct CircleFFT {
    /// The evaluation domain.
    domain: CircleDomain,
}

impl CircleFFT {
    /// Create a Circle FFT for domain size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        let domain = CircleDomain::new(log_size);
        Self { domain }
    }

    /// Forward FFT: polynomial coefficients → evaluations.
    ///
    /// Input: coefficients [c₀, c₁, ..., c_{n/2-1}] (degree < n/2)
    /// Output: evaluations [f(p₀), f(p₁), ..., f(p_{n-1})]
    ///
    /// The polynomial is evaluated at all domain points using their x-coordinates.
    /// For twin points (x, y) and (x, -y), they get the same evaluation f(x).
    pub fn fft(&self, coeffs: &[M31]) -> Vec<M31> {
        let n = self.domain.size;
        let half = n / 2;
        
        // Pad coefficients to half domain size (max useful degree)
        let mut padded = coeffs.to_vec();
        if padded.len() > half {
            padded.truncate(half);
        }
        padded.resize(half, M31::ZERO);
        
        // Evaluate at each domain point's x-coordinate
        let mut evals = Vec::with_capacity(n);
        
        for i in 0..n {
            let x = self.domain.get_point(i).x;
            let val = evaluate_poly(&padded, x);
            evals.push(val);
        }
        
        evals
    }

    /// Inverse FFT: evaluations → polynomial coefficients.
    ///
    /// Input: evaluations [f(p₀), f(p₁), ..., f(p_{n-1})]  
    /// Output: coefficients [c₀, c₁, ..., c_{n/2-1}]
    ///
    /// Uses only the first half of evaluations (which correspond to unique x-coordinates
    /// in a properly structured domain).
    pub fn ifft(&self, evals: &[M31]) -> Vec<M31> {
        let n = self.domain.size;
        let half = n / 2;
        
        assert_eq!(evals.len(), n, "Evaluation count must match domain size");
        
        // Get x-coordinates of first half (should be unique)
        let xs: Vec<M31> = (0..half).map(|i| self.domain.get_point(i).x).collect();
        let ys: Vec<M31> = (0..half).map(|i| evals[i]).collect();
        
        // Lagrange interpolation on the unique x-coordinates
        interpolate_lagrange(&xs, &ys)
    }

    /// Low-degree extension: extend evaluations to a larger domain.
    ///
    /// Given evaluations on domain D of size n, returns evaluations
    /// on a domain D' of size n · 2^log_extension.
    pub fn extend(&self, evals: &[M31], log_extension: usize) -> Vec<M31> {
        // Recover coefficients
        let coeffs = self.ifft(evals);
        
        // Evaluate on larger domain
        let extended_fft = CircleFFT::new(self.domain.log_size + log_extension);
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

    /// Get the domain.
    pub fn domain(&self) -> &CircleDomain {
        &self.domain
    }
}

// ============================================================================
// Fast Circle FFT (O(n log n) Butterfly Algorithm)
// ============================================================================
// Based on Stwo's proven implementation (Apache 2.0 licensed)

/// Butterfly operation for forward FFT.
/// 
/// Given v0, v1 and twiddle factor t, computes:
/// - v0_new = v0 + v1 * t
/// - v1_new = v0 - v1 * t
#[inline]
pub fn butterfly(v0: &mut M31, v1: &mut M31, twid: M31) {
    let tmp = *v1 * twid;
    *v1 = *v0 - tmp;
    *v0 = *v0 + tmp;
}

/// Inverse butterfly operation for inverse FFT.
/// 
/// Given v0, v1 and inverse twiddle factor it, computes:
/// - v0_new = v0 + v1
/// - v1_new = (v0 - v1) * it
#[inline]  
pub fn ibutterfly(v0: &mut M31, v1: &mut M31, itwid: M31) {
    let tmp = *v0;
    *v0 = tmp + *v1;
    *v1 = (tmp - *v1) * itwid;
}

/// Precomputed twiddle factors for efficient FFT.
/// 
/// Twiddles are the x-coordinates of domain points, bit-reversed for
/// efficient access during the butterfly passes.
#[derive(Clone, Debug)]
pub struct CircleTwiddles {
    /// Forward twiddles (x-coordinates of coset points).
    pub twiddles: Vec<M31>,
    /// Inverse twiddles (multiplicative inverses).
    pub itwiddles: Vec<M31>,
    /// Log size of the domain.
    pub log_size: usize,
}

impl CircleTwiddles {
    /// Precompute twiddle factors for a domain of size 2^log_size.
    /// 
    /// Follows Stwo's algorithm: for each layer, store x-coordinates
    /// of coset points in bit-reversed order.
    pub fn new(log_size: usize) -> Self {
        if log_size == 0 {
            return Self {
                twiddles: vec![M31::ONE],
                itwiddles: vec![M31::ONE],
                log_size,
            };
        }
        
        if log_size == 1 {
            // For size 2, we just need the y-coordinate of the generator
            let gen = CirclePoint::generator(1);
            return Self {
                twiddles: vec![gen.y, M31::ONE],
                itwiddles: vec![gen.y.inv(), M31::ONE],
                log_size,
            };
        }
        
        // Start with a coset that generates the domain
        // Use generator of order 2^log_size
        let mut coset = CirclePoint::generator(log_size);
        let mut coset_size = 1usize << log_size;
        
        let mut twiddles = Vec::with_capacity(coset_size);
        
        // For each layer, compute and store twiddles
        // The twiddles are the x-coordinates of coset points
        for layer in 0..log_size {
            let start_idx = twiddles.len();
            let half_size = coset_size / 2;
            
            // For each layer, collect x-coordinates of the first half of coset points
            // Start from identity and step by generator
            let mut point = CirclePoint::IDENTITY;
            for _ in 0..half_size {
                twiddles.push(point.x);
                point = point.mul(coset);
            }
            
            // Bit-reverse this layer's twiddles
            if half_size > 1 {
                bit_reverse_permutation(&mut twiddles[start_idx..]);
            }
            
            // Double the coset generator for next layer
            coset = coset.double();
            coset_size /= 2;
            
            // After first layer, x-coordinates should all be non-zero
            // The identity point has x=1, and we step by a generator that
            // produces points with different x-coords
            if layer == 0 && half_size > 0 {
                // First layer contains identity (x=1), which is fine
            }
        }
        
        // Pad to power of 2 for alignment
        twiddles.push(M31::ONE);
        
        // Compute inverse twiddles with safe fallback for any zeros
        let itwiddles: Vec<M31> = twiddles.iter().map(|t| {
            if t.is_zero() {
                M31::ONE // Fallback for zero (should not happen in well-formed domains)
            } else {
                t.inv()
            }
        }).collect();
        
        Self { twiddles, itwiddles, log_size }
    }
    
    /// Get twiddles for a specific layer.
    fn layer_twiddles(&self, layer: usize) -> &[M31] {
        if layer >= self.log_size {
            return &[];
        }
        
        // Calculate start index for this layer
        let mut start = 0;
        let mut layer_size = 1 << (self.log_size - 1);
        for _ in 0..layer {
            start += layer_size;
            layer_size /= 2;
        }
        
        &self.twiddles[start..(start + layer_size.max(1))]
    }
}

/// Fast Circle FFT implementation.
/// 
/// NOTE: Currently delegates to the O(n²) CircleFFT for correctness.
/// The butterfly operations above are ready for O(n log n) implementation.
/// 
/// TODO: Implement proper O(n log n) butterfly-based Circle FFT.
/// See: https://github.com/starkware-libs/stwo
#[derive(Clone, Debug)]
pub struct FastCircleFFT {
    /// Delegate to proven implementation.
    inner: CircleFFT,
    #[allow(dead_code)]
    twiddles: CircleTwiddles,
}

impl FastCircleFFT {
    /// Create a Fast Circle FFT for domain size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        Self { 
            inner: CircleFFT::new(log_size),
            twiddles: CircleTwiddles::new(log_size),
        }
    }
    
    /// Forward FFT: polynomial coefficients → evaluations.
    pub fn fft(&self, coeffs: &[M31]) -> Vec<M31> {
        self.inner.fft(coeffs)
    }
    
    /// Inverse FFT: evaluations → polynomial coefficients.
    pub fn ifft(&self, evals: &[M31]) -> Vec<M31> {
        self.inner.ifft(evals)
    }
    
    /// Low-degree extension using FFT.
    pub fn extend(&self, evals: &[M31], log_extension: usize) -> Vec<M31> {
        self.inner.extend(evals, log_extension)
    }
    
    /// Get domain size.
    pub fn size(&self) -> usize {
        self.inner.size()
    }
    
    /// Get log domain size.
    pub fn log_size(&self) -> usize {
        self.inner.log_size()
    }
    
    /// Get the domain.
    pub fn domain(&self) -> &CircleDomain {
        self.inner.domain()
    }
}

/// Execute one layer of the FFT butterfly algorithm.
/// 
/// This processes all butterflies at a given layer with the same twiddle factor.
#[inline]
fn fft_layer_loop<F>(
    values: &mut [M31], 
    layer: usize, 
    h: usize, 
    twid: M31, 
    butterfly_fn: F
) where F: Fn(&mut M31, &mut M31, M31) {
    let layer_size = 1 << layer;
    for l in 0..layer_size {
        let idx0 = (h << (layer + 1)) + l;
        let idx1 = idx0 + layer_size;
        if idx1 < values.len() {
            let (mut val0, mut val1) = (values[idx0], values[idx1]);
            butterfly_fn(&mut val0, &mut val1, twid);
            values[idx0] = val0;
            values[idx1] = val1;
        }
    }
}

/// Compute circle twiddles (layer 0) from line twiddles (layer 1).
/// 
/// The relationship between consecutive domain points allows us to derive
/// the y-coordinate twiddles from the x-coordinate twiddles.
fn circle_twiddles_from_line(line_twiddles: &[M31]) -> impl Iterator<Item = M31> + '_ {
    // Each pair of x-coordinates [x, y] generates circle twiddles [y, -y, -x, x]
    line_twiddles.chunks(2).flat_map(|chunk| {
        if chunk.len() == 2 {
            vec![chunk[1], -chunk[1], -chunk[0], chunk[0]]
        } else if chunk.len() == 1 {
            vec![chunk[0]]
        } else {
            vec![]
        }
    })
}

/// Evaluate polynomial at a single point using Horner's method.
///
/// For f(x) = c₀ + c₁x + c₂x² + ... + cₙxⁿ, computes f(point).
/// Complexity: O(n) field operations.
#[inline]
pub fn evaluate_poly(coeffs: &[M31], point: M31) -> M31 {
    let mut result = M31::ZERO;
    for &c in coeffs.iter().rev() {
        result = result * point + c;
    }
    result
}

/// Lagrange interpolation: given (xᵢ, yᵢ) pairs, find polynomial f with f(xᵢ) = yᵢ.
///
/// Complexity: O(n²) field operations.
/// Panics if xs contains duplicates.
pub fn interpolate_lagrange(xs: &[M31], ys: &[M31]) -> Vec<M31> {
    let n = xs.len();
    assert_eq!(n, ys.len(), "xs and ys must have same length");
    
    if n == 0 {
        return vec![];
    }
    if n == 1 {
        return vec![ys[0]];
    }
    
    // Check for duplicates
    for i in 0..n {
        for j in (i+1)..n {
            assert!(xs[i] != xs[j], "Duplicate x values in interpolation: x[{}] = x[{}] = {}", 
                    i, j, xs[i].value());
        }
    }
    
    let mut coeffs = vec![M31::ZERO; n];
    
    for i in 0..n {
        // Compute Lagrange basis polynomial Lᵢ(x) = ∏_{j≠i} (x - xⱼ)/(xᵢ - xⱼ)
        
        // First compute denominator: ∏_{j≠i} (xᵢ - xⱼ)
        let mut denom = M31::ONE;
        for j in 0..n {
            if i != j {
                denom = denom * (xs[i] - xs[j]);
            }
        }
        
        // Scale factor: yᵢ / denom
        let scale = ys[i] * denom.inv();
        
        // Build numerator polynomial: ∏_{j≠i} (x - xⱼ)
        let mut basis = vec![M31::ONE];
        for j in 0..n {
            if i != j {
                // Multiply by (x - xⱼ)
                let mut new_basis = vec![M31::ZERO; basis.len() + 1];
                for (k, &b) in basis.iter().enumerate() {
                    new_basis[k + 1] = new_basis[k + 1] + b;        // +b·x
                    new_basis[k] = new_basis[k] - b * xs[j];        // -b·xⱼ
                }
                basis = new_basis;
            }
        }
        
        // Add scaled basis to result
        for (k, &b) in basis.iter().enumerate() {
            if k < n {
                coeffs[k] = coeffs[k] + scale * b;
            }
        }
    }
    
    coeffs
}

/// Multiply two polynomials.
///
/// Given f = [f₀, f₁, ...] and g = [g₀, g₁, ...], computes f·g.
/// Complexity: O(n·m) where n, m are the degrees.
pub fn poly_mul(f: &[M31], g: &[M31]) -> Vec<M31> {
    if f.is_empty() || g.is_empty() {
        return vec![];
    }
    
    let mut result = vec![M31::ZERO; f.len() + g.len() - 1];
    
    for (i, &fi) in f.iter().enumerate() {
        for (j, &gj) in g.iter().enumerate() {
            result[i + j] = result[i + j] + fi * gj;
        }
    }
    
    result
}

/// Add two polynomials.
pub fn poly_add(f: &[M31], g: &[M31]) -> Vec<M31> {
    let max_len = f.len().max(g.len());
    let mut result = vec![M31::ZERO; max_len];
    
    for (i, &fi) in f.iter().enumerate() {
        result[i] = result[i] + fi;
    }
    for (i, &gi) in g.iter().enumerate() {
        result[i] = result[i] + gi;
    }
    
    result
}

/// Subtract two polynomials.
pub fn poly_sub(f: &[M31], g: &[M31]) -> Vec<M31> {
    let max_len = f.len().max(g.len());
    let mut result = vec![M31::ZERO; max_len];
    
    for (i, &fi) in f.iter().enumerate() {
        result[i] = result[i] + fi;
    }
    for (i, &gi) in g.iter().enumerate() {
        result[i] = result[i] - gi;
    }
    
    result
}

/// Scale a polynomial by a constant.
pub fn poly_scale(f: &[M31], c: M31) -> Vec<M31> {
    f.iter().map(|&fi| fi * c).collect()
}

/// Compute the degree of a polynomial (highest non-zero coefficient index).
/// Returns None for the zero polynomial.
pub fn poly_degree(f: &[M31]) -> Option<usize> {
    for (i, &c) in f.iter().enumerate().rev() {
        if !c.is_zero() {
            return Some(i);
        }
    }
    None
}

/// Polynomial division with remainder.
/// Returns (quotient, remainder) such that f = q·g + r with deg(r) < deg(g).
pub fn poly_divmod(f: &[M31], g: &[M31]) -> (Vec<M31>, Vec<M31>) {
    let g_deg = match poly_degree(g) {
        Some(d) => d,
        None => panic!("Division by zero polynomial"),
    };
    
    let f_deg = match poly_degree(f) {
        Some(d) => d,
        None => return (vec![], vec![]), // 0 / g = 0 remainder 0
    };
    
    if f_deg < g_deg {
        return (vec![], f.to_vec());
    }
    
    let mut remainder = f.to_vec();
    let mut quotient = vec![M31::ZERO; f_deg - g_deg + 1];
    
    let lead_g_inv = g[g_deg].inv();
    
    for i in (0..=f_deg - g_deg).rev() {
        let coeff = remainder[i + g_deg] * lead_g_inv;
        quotient[i] = coeff;
        
        for j in 0..=g_deg {
            remainder[i + j] = remainder[i + j] - coeff * g[j];
        }
    }
    
    // Trim trailing zeros from remainder
    while remainder.len() > 1 && remainder.last() == Some(&M31::ZERO) {
        remainder.pop();
    }
    
    (quotient, remainder)
}

// ============================================================================
// Bit Reversal (for FFT)
// ============================================================================

/// Bit-reverse permutation of a slice.
#[allow(dead_code)]
pub fn bit_reverse_permutation<T: Copy>(data: &mut [T]) {
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

/// Reverse the bits of x, treating it as a log_n-bit number.
#[inline]
pub fn bit_reverse(x: usize, log_n: usize) -> usize {
    x.reverse_bits() >> (usize::BITS as usize - log_n)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt() {
        // sqrt(4) = 2
        let four = M31::new(4);
        let r = sqrt_m31(four).unwrap();
        assert!(r * r == four);
        
        // sqrt(1) = 1
        assert!(sqrt_m31(M31::ONE).unwrap() * sqrt_m31(M31::ONE).unwrap() == M31::ONE);
        
        // sqrt(0) = 0
        assert_eq!(sqrt_m31(M31::ZERO), Some(M31::ZERO));
    }

    #[test]
    fn test_circle_point_identity() {
        let id = CirclePoint::IDENTITY;
        assert!(id.is_valid());
        assert!(id.is_identity());
        assert_eq!(id.x, M31::ONE);
        assert_eq!(id.y, M31::ZERO);
    }

    #[test]
    fn test_circle_point_mul() {
        let p = CirclePoint::generator(4);
        
        // p * identity = p
        assert_eq!(p.mul(CirclePoint::IDENTITY), p);
        
        // identity * p = p  
        assert_eq!(CirclePoint::IDENTITY.mul(p), p);
        
        // p * p^(-1) = identity
        let p_inv = p.inv();
        assert!(p.mul(p_inv).is_identity());
    }

    #[test]
    fn test_circle_point_double() {
        let g = CirclePoint::generator(4);
        assert!(g.is_valid());
        
        let g2 = g.double();
        assert!(g2.is_valid());
        
        // g.double() should equal g.mul(g)
        assert_eq!(g2, g.mul(g));
    }

    #[test]
    fn test_generator_is_valid() {
        // Check generator is on circle
        let g = CirclePoint::generator_order_2_31();
        assert!(g.is_valid(), "Generator must satisfy x² + y² = 1");
        
        // Verify the specific values
        assert_eq!(g.x, M31::new(2));
        let y_sq = g.y * g.y;
        let expected_y_sq = M31::ONE - g.x * g.x; // 1 - 4 = -3
        assert_eq!(y_sq, expected_y_sq);
    }

    #[test]
    fn test_circle_point_order() {
        // Generator of order 2^4 = 16
        let g = CirclePoint::generator(4);
        
        // g^16 should be identity
        let g16 = g.pow(16);
        assert!(g16.is_identity(), "g^16 should be identity");
        
        // g^8 should NOT be identity
        let g8 = g.pow(8);
        assert!(!g8.is_identity(), "g^8 should not be identity");
        
        // g^4 should NOT be identity
        let g4 = g.pow(4);
        assert!(!g4.is_identity(), "g^4 should not be identity");
    }

    #[test]
    fn test_circle_domain() {
        let domain = CircleDomain::new(3);
        assert_eq!(domain.size, 8);
        assert_eq!(domain.log_size, 3);
        
        // First point is identity
        assert!(domain.get_point(0).is_identity());
        
        // All points are valid
        assert!(domain.verify());
        
        // All points are distinct
        for i in 0..domain.size {
            for j in (i + 1)..domain.size {
                assert_ne!(domain.get_point(i), domain.get_point(j));
            }
        }
    }

    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse(0b000, 3), 0b000);
        assert_eq!(bit_reverse(0b001, 3), 0b100);
        assert_eq!(bit_reverse(0b010, 3), 0b010);
        assert_eq!(bit_reverse(0b011, 3), 0b110);
        assert_eq!(bit_reverse(0b100, 3), 0b001);
        assert_eq!(bit_reverse(0b101, 3), 0b101);
        assert_eq!(bit_reverse(0b110, 3), 0b011);
        assert_eq!(bit_reverse(0b111, 3), 0b111);
    }

    #[test]
    fn test_evaluate_poly() {
        // f(x) = 1 + 2x + 3x²
        let coeffs = vec![M31::new(1), M31::new(2), M31::new(3)];
        
        // f(0) = 1
        assert_eq!(evaluate_poly(&coeffs, M31::ZERO), M31::new(1));
        
        // f(1) = 1 + 2 + 3 = 6
        assert_eq!(evaluate_poly(&coeffs, M31::ONE), M31::new(6));
        
        // f(2) = 1 + 4 + 12 = 17
        assert_eq!(evaluate_poly(&coeffs, M31::new(2)), M31::new(17));
        
        // f(10) = 1 + 20 + 300 = 321
        assert_eq!(evaluate_poly(&coeffs, M31::new(10)), M31::new(321));
    }

    #[test]
    fn test_interpolate() {
        // Points: (0,1), (1,6), (2,17), (3,34)
        // These lie on f(x) = 1 + 2x + 3x²
        let xs = vec![M31::new(0), M31::new(1), M31::new(2), M31::new(3)];
        let ys = vec![M31::new(1), M31::new(6), M31::new(17), M31::new(34)];
        
        let coeffs = interpolate_lagrange(&xs, &ys);
        
        // Verify interpolation
        for i in 0..4 {
            let y = evaluate_poly(&coeffs, xs[i]);
            assert_eq!(y, ys[i], "Interpolation failed at x={}", i);
        }
    }

    #[test]
    fn test_fft_constant() {
        // FFT of constant polynomial f(x) = 42
        let fft = CircleFFT::new(3);
        let coeffs = vec![M31::new(42)];
        
        let evals = fft.fft(&coeffs);
        
        // All evaluations should be 42
        for (i, &e) in evals.iter().enumerate() {
            assert_eq!(e, M31::new(42), "Eval at {} should be 42", i);
        }
    }

    #[test]
    fn test_fft_linear() {
        // FFT of f(x) = 1 + 2x
        let fft = CircleFFT::new(2);
        let coeffs = vec![M31::new(1), M31::new(2)];
        
        let evals = fft.fft(&coeffs);
        
        // Verify each evaluation manually
        for i in 0..4 {
            let x = fft.get_domain_point(i).x;
            let expected = M31::new(1) + M31::new(2) * x;
            assert_eq!(evals[i], expected, "FFT mismatch at point {}", i);
        }
    }

    #[test]
    fn test_fft_ifft_roundtrip() {
        let fft = CircleFFT::new(3);
        let half = fft.size() / 2;
        
        // Original polynomial of degree < n/2
        let original = vec![
            M31::new(1), M31::new(2), M31::new(3), M31::new(4),
        ];
        assert!(original.len() <= half);
        
        let evals = fft.fft(&original);
        let recovered = fft.ifft(&evals);
        
        // Should recover original coefficients
        for i in 0..original.len() {
            assert_eq!(recovered[i], original[i], 
                "Roundtrip failed at {}: got {}, expected {}", 
                i, recovered[i].value(), original[i].value());
        }
    }

    #[test]
    fn test_poly_mul() {
        // (1 + x) * (1 + 2x) = 1 + 3x + 2x²
        let f = vec![M31::new(1), M31::new(1)];
        let g = vec![M31::new(1), M31::new(2)];
        let h = poly_mul(&f, &g);
        
        assert_eq!(h.len(), 3);
        assert_eq!(h[0], M31::new(1));
        assert_eq!(h[1], M31::new(3));
        assert_eq!(h[2], M31::new(2));
    }

    #[test]
    fn test_poly_divmod() {
        // (2x² + 3x + 1) / (x + 1) = (2x + 1) remainder 0
        let f = vec![M31::new(1), M31::new(3), M31::new(2)];
        let g = vec![M31::new(1), M31::new(1)];
        
        let (q, r) = poly_divmod(&f, &g);
        
        // Verify: f = q*g + r
        let qg = poly_mul(&q, &g);
        let reconstructed = poly_add(&qg, &r);
        
        for i in 0..f.len() {
            assert_eq!(reconstructed[i], f[i], "Division check failed at {}", i);
        }
    }

    #[test]
    fn test_lde_extension() {
        let fft = CircleFFT::new(2);
        
        // Polynomial: f(x) = 1 + 2x (degree 1, fits in domain of size 4)
        let coeffs = vec![M31::new(1), M31::new(2)];
        let evals = fft.fft(&coeffs);
        
        // Extend to domain of size 8
        let extended = fft.extend(&evals, 1);
        
        assert_eq!(extended.len(), 8);
        
        // Verify extended evaluations are correct
        let extended_fft = CircleFFT::new(3);
        for i in 0..8 {
            let x = extended_fft.get_domain_point(i).x;
            let expected = evaluate_poly(&coeffs, x);
            assert_eq!(extended[i], expected, "LDE mismatch at {}", i);
        }
    }
    
    #[test]
    fn test_domain_x_coords_first_half_unique() {
        // For a domain of size n, verify the first n/2 x-coordinates are unique
        let domain = CircleDomain::new(4);  // size 16
        let half = domain.size / 2;
        
        let xs: Vec<M31> = (0..half).map(|i| domain.get_point(i).x).collect();
        
        // Check uniqueness
        for i in 0..half {
            for j in (i+1)..half {
                assert_ne!(xs[i], xs[j], "Duplicate x at positions {} and {}", i, j);
            }
        }
    }
    
    // ========================================================================
    // FastCircleFFT Tests (O(n log n) butterfly algorithm)
    // ========================================================================
    
    #[test]
    fn test_fast_fft_butterfly_basic() {
        // Test the basic butterfly operation
        let mut v0 = M31::new(3);
        let mut v1 = M31::new(5);
        let twid = M31::new(2);
        
        // v0_new = v0 + v1*t = 3 + 5*2 = 13
        // v1_new = v0 - v1*t = 3 - 5*2 = 3 - 10 = -7 mod p
        butterfly(&mut v0, &mut v1, twid);
        
        assert_eq!(v0, M31::new(13));
        assert_eq!(v1, M31::ZERO - M31::new(7));  // -7 mod p
    }
    
    #[test]
    fn test_fast_fft_ibutterfly_basic() {
        // Test the inverse butterfly operation
        let mut v0 = M31::new(8);
        let mut v1 = M31::new(4);
        let itwid = M31::new(2);
        
        // v0_new = v0 + v1 = 8 + 4 = 12
        // v1_new = (v0 - v1) * it = (8 - 4) * 2 = 8
        ibutterfly(&mut v0, &mut v1, itwid);
        
        assert_eq!(v0, M31::new(12));
        assert_eq!(v1, M31::new(8));
    }
    
    #[test]
    fn test_fast_fft_small_sizes() {
        // Test size 4 (log_size 2) - smallest working size
        let fft4 = FastCircleFFT::new(2);
        // For size 4, we provide 2 coefficients (n/2 = 2)
        let coeffs4 = vec![M31::new(1), M31::new(2)]; // f(x) = 1 + 2x
        let evals4 = fft4.fft(&coeffs4);
        assert_eq!(evals4.len(), 4, "FFT should produce 4 evaluations");
        
        // Test size 8 (log_size 3)
        let fft8 = FastCircleFFT::new(3);
        // For size 8, we provide 4 coefficients (n/2 = 4)
        let coeffs8 = vec![M31::new(1), M31::new(2), M31::new(3), M31::new(4)];
        let evals8 = fft8.fft(&coeffs8);
        assert_eq!(evals8.len(), 8, "FFT should produce 8 evaluations");
    }
    
    #[test]
    fn test_fast_fft_roundtrip() {
        // Test that fft followed by ifft preserves coefficients
        // CircleFFT: fft takes n/2 coeffs -> n evals, ifft takes n evals -> n/2 coeffs
        for log_size in 2..=5 {
            let fast_fft = FastCircleFFT::new(log_size);
            let n = 1 << log_size;
            let half = n / 2;
            
            // Create test coefficients (only n/2 meaningful for degree < n/2)
            let coeffs: Vec<M31> = (0..half).map(|i| M31::new((i * 7 + 13) as u32 % 1000)).collect();
            
            // Forward FFT: n/2 coeffs -> n evals
            let evals = fast_fft.fft(&coeffs);
            assert_eq!(evals.len(), n, "FFT output size mismatch for log_size {}", log_size);
            
            // Inverse FFT: n evals -> n/2 coeffs
            let recovered = fast_fft.ifft(&evals);
            assert_eq!(recovered.len(), half, "IFFT output size mismatch for log_size {}", log_size);
            
            // Check roundtrip for the meaningful coefficients
            for i in 0..half {
                assert_eq!(
                    recovered[i], coeffs[i], 
                    "Roundtrip failed at index {} for log_size {}: got {:?}, expected {:?}",
                    i, log_size, recovered[i], coeffs[i]
                );
            }
        }
    }

    #[test]
    fn test_fast_fft_extend() {
        let fft = FastCircleFFT::new(3);  // size 8
        
        // Create coefficients (n/2 = 4 meaningful coefficients)
        let coeffs: Vec<M31> = (0..4).map(|i| M31::new(i as u32)).collect();
        let evals = fft.fft(&coeffs);
        
        // Extend to size 16
        let extended = fft.extend(&evals, 1);
        assert_eq!(extended.len(), 16);
    }
}
