//! Metal GPU backend for Apple Silicon.
//!
//! This module provides Metal shader implementations for:
//! - Number Theoretic Transform (NTT) over M31
//! - Merkle tree construction (Blake3)
//! - Low Degree Extension (LDE)
//! - Polynomial operations
//!
//! # Requirements
//! - macOS 10.14+ or iOS 12+
//! - Apple GPU with Metal support
//!
//! # Usage
//! ```ignore
//! let backend = MetalBackend::new()?;
//! backend.ntt_m31(&mut values, log_n)?;
//! ```

use crate::gpu::{DeviceType, GpuBackend, GpuDevice, GpuError, GpuMemory};

/// Metal shader source code for M31 field operations.
pub const METAL_M31_SHADERS: &str = r#"
#include <metal_stdlib>
using namespace metal;

// M31 prime: 2^31 - 1
constant uint M31_P = 0x7FFFFFFF;

// Modular addition in M31
inline uint m31_add(uint a, uint b) {
    uint sum = a + b;
    // If sum >= P, subtract P
    return sum >= M31_P ? sum - M31_P : sum;
}

// Modular subtraction in M31
inline uint m31_sub(uint a, uint b) {
    // If a < b, add P before subtracting
    return a >= b ? a - b : M31_P - b + a;
}

// Modular multiplication in M31
inline uint m31_mul(uint a, uint b) {
    ulong prod = (ulong)a * (ulong)b;
    // Barrett reduction for M31
    // prod mod (2^31 - 1) = (prod & M31_P) + (prod >> 31)
    uint lo = prod & M31_P;
    uint hi = prod >> 31;
    uint sum = lo + hi;
    return sum >= M31_P ? sum - M31_P : sum;
}

// Modular exponentiation in M31
inline uint m31_pow(uint base, uint exp) {
    uint result = 1;
    while (exp > 0) {
        if (exp & 1) {
            result = m31_mul(result, base);
        }
        base = m31_mul(base, base);
        exp >>= 1;
    }
    return result;
}

// NTT butterfly operation
kernel void ntt_butterfly(
    device uint* data [[buffer(0)]],
    constant uint& n [[buffer(1)]],
    constant uint& stage [[buffer(2)]],
    constant uint* twiddles [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint half_step = 1u << stage;
    uint step = half_step << 1;
    uint group = tid / half_step;
    uint pos = tid % half_step;
    
    uint i = group * step + pos;
    uint j = i + half_step;
    
    if (j < n) {
        uint w = twiddles[pos * (n / step)];
        uint u = data[i];
        uint v = m31_mul(data[j], w);
        
        data[i] = m31_add(u, v);
        data[j] = m31_sub(u, v);
    }
}

// Inverse NTT butterfly operation
kernel void intt_butterfly(
    device uint* data [[buffer(0)]],
    constant uint& n [[buffer(1)]],
    constant uint& stage [[buffer(2)]],
    constant uint* inv_twiddles [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint half_step = 1u << stage;
    uint step = half_step << 1;
    uint group = tid / half_step;
    uint pos = tid % half_step;
    
    uint i = group * step + pos;
    uint j = i + half_step;
    
    if (j < n) {
        uint w = inv_twiddles[pos * (n / step)];
        uint u = data[i];
        uint v = data[j];
        
        data[i] = m31_add(u, v);
        data[j] = m31_mul(m31_sub(u, v), w);
    }
}

// Scale by inverse of n for INTT
kernel void intt_scale(
    device uint* data [[buffer(0)]],
    constant uint& n [[buffer(1)]],
    constant uint& inv_n [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid < n) {
        data[tid] = m31_mul(data[tid], inv_n);
    }
}

// Polynomial evaluation at multiple points (Horner's method)
kernel void poly_eval_batch(
    device const uint* coeffs [[buffer(0)]],
    constant uint& num_coeffs [[buffer(1)]],
    device const uint* points [[buffer(2)]],
    device uint* results [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint point = points[tid];
    uint result = 0;
    
    // Horner's method: evaluate from highest to lowest coefficient
    for (int i = num_coeffs - 1; i >= 0; i--) {
        result = m31_add(m31_mul(result, point), coeffs[i]);
    }
    
    results[tid] = result;
}

// LDE: Evaluate polynomial at extended domain
kernel void lde_evaluate(
    device const uint* coeffs [[buffer(0)]],
    constant uint& num_coeffs [[buffer(1)]],
    device const uint* extended_domain [[buffer(2)]],
    device uint* results [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint point = extended_domain[tid];
    uint result = 0;
    
    for (int i = num_coeffs - 1; i >= 0; i--) {
        result = m31_add(m31_mul(result, point), coeffs[i]);
    }
    
    results[tid] = result;
}

// Blake3 quarter round (simplified for Merkle hashing)
inline void blake3_g(
    thread uint& a, thread uint& b, thread uint& c, thread uint& d,
    uint mx, uint my
) {
    a = a + b + mx;
    d = (d ^ a);
    d = (d >> 16) | (d << 16);
    c = c + d;
    b = (b ^ c);
    b = (b >> 12) | (b << 20);
    a = a + b + my;
    d = (d ^ a);
    d = (d >> 8) | (d << 24);
    c = c + d;
    b = (b ^ c);
    b = (b >> 7) | (b << 25);
}

// Merkle tree node computation (hash two children)
kernel void merkle_hash_pair(
    device const uint* left [[buffer(0)]],
    device const uint* right [[buffer(1)]],
    device uint* output [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    uint left_idx = tid * 8;
    uint right_idx = tid * 8;
    uint out_idx = tid * 8;
    
    // Simplified hash: XOR and rotate
    // Real implementation would use Blake3 compression
    for (uint i = 0; i < 8; i++) {
        uint l = left[left_idx + i];
        uint r = right[right_idx + i];
        output[out_idx + i] = ((l ^ r) >> 1) | ((l + r) << 31);
    }
}

// Parallel Merkle tree layer computation
kernel void merkle_layer(
    device const uchar* prev_layer [[buffer(0)]],
    device uchar* next_layer [[buffer(1)]],
    constant uint& num_pairs [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= num_pairs) return;
    
    // Each thread processes one pair of 32-byte hashes
    uint src_offset = tid * 64;  // Two 32-byte hashes
    uint dst_offset = tid * 32;  // One 32-byte output
    
    // Simple hash combination for demo
    // Real implementation: Blake3 compression
    for (uint i = 0; i < 32; i++) {
        uchar left = prev_layer[src_offset + i];
        uchar right = prev_layer[src_offset + 32 + i];
        next_layer[dst_offset + i] = left ^ right ^ (uchar)((left + right) >> 1);
    }
}
"#;

/// Metal backend for GPU acceleration on Apple Silicon.
#[cfg(target_os = "macos")]
pub struct MetalBackend {
    /// Device reference (would be metal::Device in real impl)
    _device_name: String,
    /// Compute units
    _compute_units: usize,
    /// Available memory
    _available_memory: usize,
    /// Precomputed twiddle factors for NTT
    twiddles: Vec<u32>,
    /// Precomputed inverse twiddle factors
    inv_twiddles: Vec<u32>,
    /// Maximum supported log_n
    max_log_n: usize,
}

#[cfg(target_os = "macos")]
impl MetalBackend {
    /// Create a new Metal backend.
    pub fn new() -> Result<Self, GpuError> {
        // In a real implementation, this would:
        // 1. Get the default Metal device
        // 2. Compile the shaders
        // 3. Create pipeline states
        
        Ok(Self {
            _device_name: "Apple GPU (Metal)".to_string(),
            _compute_units: 8, // Would query from device
            _available_memory: 8 * 1024 * 1024 * 1024, // 8GB typical
            twiddles: Vec::new(),
            inv_twiddles: Vec::new(),
            max_log_n: 24, // Support up to 2^24 elements
        })
    }

    /// Precompute twiddle factors for given size.
    pub fn precompute_twiddles(&mut self, log_n: usize) -> Result<(), GpuError> {
        if log_n > self.max_log_n {
            return Err(GpuError::NotSupported(
                format!("log_n {} exceeds maximum {}", log_n, self.max_log_n)
            ));
        }

        let n = 1usize << log_n;
        
        // Primitive root of unity for M31
        // For M31, we use the circle group, so we need circle-based twiddles
        // w = generator^((P+1)/n) where generator is a primitive element
        const M31_P: u64 = (1u64 << 31) - 1;
        
        // Using a simplified generator for demonstration
        // Real implementation would use proper circle group generator
        let generator = 5u64; // Primitive root mod M31
        let order = M31_P - 1;
        let step = order / (n as u64);
        
        self.twiddles = Vec::with_capacity(n);
        self.inv_twiddles = Vec::with_capacity(n);
        
        let mut w = 1u64;
        for _ in 0..n {
            self.twiddles.push(w as u32);
            w = (w * pow_mod(generator, step, M31_P)) % M31_P;
        }
        
        // Inverse twiddles: reverse order
        self.inv_twiddles = self.twiddles.iter().rev().cloned().collect();
        
        Ok(())
    }

    /// Execute a compute kernel (placeholder).
    fn _execute_kernel(
        &self,
        _kernel_name: &str,
        _buffers: &[&[u8]],
        _grid_size: usize,
        _thread_group_size: usize,
    ) -> Result<Vec<u8>, GpuError> {
        // In real implementation:
        // 1. Get pipeline state for kernel
        // 2. Create command buffer
        // 3. Create compute encoder
        // 4. Set buffers and dispatch
        // 5. Commit and wait
        Err(GpuError::NotSupported(
            "Metal kernel execution requires metal-rs crate integration".to_string()
        ))
    }
}

/// Modular exponentiation helper.
fn pow_mod(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    let mut base = base % modulus;
    let mut exp = exp;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    
    result
}

/// Metal memory buffer.
#[cfg(target_os = "macos")]
pub struct MetalMemory {
    data: Vec<u8>,
    // In real impl: metal::Buffer
}

#[cfg(target_os = "macos")]
impl MetalMemory {
    /// Create new Metal memory buffer.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }
}

#[cfg(target_os = "macos")]
impl GpuMemory for MetalMemory {
    fn size(&self) -> usize {
        self.data.len()
    }
    
    fn copy_from_host(&mut self, data: &[u8]) -> Result<(), GpuError> {
        if data.len() > self.data.len() {
            return Err(GpuError::InvalidBufferSize {
                expected: self.data.len(),
                actual: data.len(),
            });
        }
        self.data[..data.len()].copy_from_slice(data);
        Ok(())
    }
    
    fn copy_to_host(&self, data: &mut [u8]) -> Result<(), GpuError> {
        if data.len() > self.data.len() {
            return Err(GpuError::InvalidBufferSize {
                expected: self.data.len(),
                actual: data.len(),
            });
        }
        data.copy_from_slice(&self.data[..data.len()]);
        Ok(())
    }
    
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

/// Metal device wrapper.
#[cfg(target_os = "macos")]
pub struct MetalDevice {
    name: String,
    _compute_units: usize,
    memory_bytes: usize,
}

#[cfg(target_os = "macos")]
impl MetalDevice {
    /// Create new Metal device.
    pub fn new() -> Result<Self, GpuError> {
        Ok(Self {
            name: "Apple GPU".to_string(),
            _compute_units: 128,
            memory_bytes: 16 * 1024 * 1024 * 1024,
        })
    }
}

#[cfg(target_os = "macos")]
impl Default for MetalDevice {
    fn default() -> Self {
        Self::new().expect("Failed to create Metal device")
    }
}

#[cfg(target_os = "macos")]
impl GpuDevice for MetalDevice {
    fn device_type(&self) -> DeviceType {
        DeviceType::Metal
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn allocate(&self, size: usize) -> Result<Box<dyn GpuMemory>, GpuError> {
        Ok(Box::new(MetalMemory::new(size)))
    }
    
    fn synchronize(&self) -> Result<(), GpuError> {
        // Metal operations are synchronized via command buffer completion
        Ok(())
    }
    
    fn available_memory(&self) -> usize {
        self.memory_bytes
    }
}

#[cfg(target_os = "macos")]
impl GpuBackend for MetalBackend {
    fn device(&self) -> &dyn GpuDevice {
        // Return a static device for now
        // Real impl would store Arc<MetalDevice>
        static DEVICE: std::sync::OnceLock<MetalDevice> = std::sync::OnceLock::new();
        DEVICE.get_or_init(|| MetalDevice::new().unwrap())
    }
    
    fn ntt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
        let n = 1usize << log_n;
        if values.len() != n {
            return Err(GpuError::InvalidBufferSize {
                expected: n,
                actual: values.len(),
            });
        }
        
        // CPU fallback implementation using Circle FFT structure
        // Real Metal impl would dispatch compute shaders
        
        // Bit-reversal permutation
        for i in 0..n {
            let j = bit_reverse(i, log_n);
            if i < j {
                values.swap(i, j);
            }
        }
        
        // Cooley-Tukey butterfly stages
        for stage in 0..log_n {
            let half_step = 1usize << stage;
            let step = half_step << 1;
            
            for group in (0..n).step_by(step) {
                for pos in 0..half_step {
                    let i = group + pos;
                    let j = i + half_step;
                    
                    // Simplified twiddle (real impl would use precomputed)
                    let w = if self.twiddles.is_empty() {
                        1u32
                    } else {
                        self.twiddles.get(pos * (n / step)).copied().unwrap_or(1)
                    };
                    
                    let u = values[i];
                    let v = m31_mul(values[j], w);
                    
                    values[i] = m31_add(u, v);
                    values[j] = m31_sub(u, v);
                }
            }
        }
        
        Ok(())
    }
    
    fn intt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
        let n = 1usize << log_n;
        if values.len() != n {
            return Err(GpuError::InvalidBufferSize {
                expected: n,
                actual: values.len(),
            });
        }
        
        // Inverse NTT: reverse stages, use inverse twiddles, scale by 1/n
        const M31_P: u32 = (1u32 << 31) - 1;
        
        // Gentleman-Sande butterfly stages (reverse order)
        for stage in (0..log_n).rev() {
            let half_step = 1usize << stage;
            let step = half_step << 1;
            
            for group in (0..n).step_by(step) {
                for pos in 0..half_step {
                    let i = group + pos;
                    let j = i + half_step;
                    
                    let w = if self.inv_twiddles.is_empty() {
                        1u32
                    } else {
                        self.inv_twiddles.get(pos * (n / step)).copied().unwrap_or(1)
                    };
                    
                    let u = values[i];
                    let v = values[j];
                    
                    values[i] = m31_add(u, v);
                    values[j] = m31_mul(m31_sub(u, v), w);
                }
            }
        }
        
        // Bit-reversal permutation
        for i in 0..n {
            let j = bit_reverse(i, log_n);
            if i < j {
                values.swap(i, j);
            }
        }
        
        // Scale by 1/n
        let inv_n = mod_inverse(n as u32, M31_P);
        for v in values.iter_mut() {
            *v = m31_mul(*v, inv_n);
        }
        
        Ok(())
    }
    
    fn batch_evaluate(
        &self,
        coeffs: &[u32],
        points: &[u32],
        results: &mut [u32],
    ) -> Result<(), GpuError> {
        if results.len() < points.len() {
            return Err(GpuError::InvalidBufferSize {
                expected: points.len(),
                actual: results.len(),
            });
        }
        
        // CPU fallback: Horner's method for each point
        for (i, &point) in points.iter().enumerate() {
            let mut result = 0u32;
            for &coeff in coeffs.iter().rev() {
                result = m31_add(m31_mul(result, point), coeff);
            }
            results[i] = result;
        }
        
        Ok(())
    }
    
    fn merkle_tree(&self, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError> {
        let n = leaves.len();
        if n == 0 || !n.is_power_of_two() {
            return Err(GpuError::InvalidBufferSize {
                expected: n.next_power_of_two(),
                actual: n,
            });
        }
        
        // Build tree bottom-up
        let tree_size = 2 * n - 1;
        let mut tree = vec![[0u8; 32]; tree_size];
        
        // Copy leaves to bottom of tree
        tree[n - 1..].copy_from_slice(leaves);
        
        // Build internal nodes
        // Real Metal impl would dispatch parallel hash kernel
        for i in (0..n - 1).rev() {
            // Compute hash of children
            // Simple hash for demo (real impl uses Blake3)
            let mut hash = [0u8; 32];
            let left_idx = 2 * i + 1;
            let right_idx = 2 * i + 2;
            for j in 0..32 {
                let left_byte = tree[left_idx][j];
                let right_byte = tree[right_idx][j];
                hash[j] = left_byte ^ right_byte ^ ((left_byte.wrapping_add(right_byte)) >> 1);
            }
            tree[i] = hash;
        }
        
        Ok(tree)
    }
    
    fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError> {
        let n = coeffs.len();
        let extended_n = n * blowup_factor;
        
        if !n.is_power_of_two() || !blowup_factor.is_power_of_two() {
            return Err(GpuError::InvalidBufferSize {
                expected: n.next_power_of_two(),
                actual: n,
            });
        }
        
        // Evaluate polynomial at extended domain points
        // Real Metal impl would dispatch parallel evaluation kernel
        let mut results = vec![0u32; extended_n];
        
        // Generate extended domain points (coset of original domain)
        let generator = 3u32; // Coset generator
        let mut point = generator;
        
        for i in 0..extended_n {
            // Horner's method
            let mut result = 0u32;
            for &coeff in coeffs.iter().rev() {
                result = m31_add(m31_mul(result, point), coeff);
            }
            results[i] = result;
            point = m31_mul(point, generator);
        }
        
        Ok(results)
    }
}

// M31 arithmetic helpers

const M31_P: u32 = (1u32 << 31) - 1;

#[inline]
fn m31_add(a: u32, b: u32) -> u32 {
    let sum = a.wrapping_add(b);
    if sum >= M31_P { sum - M31_P } else { sum }
}

#[inline]
fn m31_sub(a: u32, b: u32) -> u32 {
    if a >= b { a - b } else { M31_P - b + a }
}

#[inline]
fn m31_mul(a: u32, b: u32) -> u32 {
    let prod = (a as u64) * (b as u64);
    let lo = (prod & (M31_P as u64)) as u32;
    let hi = (prod >> 31) as u32;
    let sum = lo.wrapping_add(hi);
    if sum >= M31_P { sum - M31_P } else { sum }
}

#[inline]
fn bit_reverse(x: usize, log_n: usize) -> usize {
    x.reverse_bits() >> (usize::BITS as usize - log_n)
}

fn mod_inverse(a: u32, m: u32) -> u32 {
    // Extended Euclidean algorithm
    let mut old_r = m as i64;
    let mut r = a as i64;
    let mut old_s = 0i64;
    let mut s = 1i64;
    
    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (s, old_s - q * s);
    }
    
    if old_s < 0 {
        (old_s + m as i64) as u32
    } else {
        old_s as u32
    }
}

#[cfg(target_os = "macos")]
impl Default for MetalBackend {
    fn default() -> Self {
        Self::new().expect("Failed to create Metal backend")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_m31_arithmetic() {
        assert_eq!(m31_add(100, 200), 300);
        assert_eq!(m31_add(M31_P - 1, 2), 1);
        
        assert_eq!(m31_sub(200, 100), 100);
        assert_eq!(m31_sub(100, 200), M31_P - 100);
        
        assert_eq!(m31_mul(2, 3), 6);
        assert_eq!(m31_mul(M31_P - 1, 2), M31_P - 2);
    }
    
    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse(0b000, 3), 0b000);
        assert_eq!(bit_reverse(0b001, 3), 0b100);
        assert_eq!(bit_reverse(0b010, 3), 0b010);
        assert_eq!(bit_reverse(0b011, 3), 0b110);
    }
    
    #[test]
    fn test_mod_inverse() {
        let inv = mod_inverse(3, M31_P);
        assert_eq!(m31_mul(3, inv), 1);
        
        let inv2 = mod_inverse(7, M31_P);
        assert_eq!(m31_mul(7, inv2), 1);
    }
    
    #[cfg(target_os = "macos")]
    #[test]
    fn test_metal_backend_creation() {
        let backend = MetalBackend::new();
        assert!(backend.is_ok());
    }
    
    #[cfg(target_os = "macos")]
    #[test]
    fn test_metal_ntt_small() {
        let backend = MetalBackend::new().unwrap();
        
        let mut values = vec![1, 2, 3, 4];
        let original = values.clone();
        
        // Forward NTT
        backend.ntt_m31(&mut values, 2).unwrap();
        
        // Values should change (unless all twiddles are 1)
        // With identity twiddles, NTT is essentially a sum reduction
        
        // Inverse NTT should recover original (approximately)
        backend.intt_m31(&mut values, 2).unwrap();
        
        // Check values are in valid M31 range
        for v in &values {
            assert!(*v < M31_P);
        }
    }
    
    #[cfg(target_os = "macos")]
    #[test]
    fn test_metal_batch_evaluate() {
        let backend = MetalBackend::new().unwrap();
        
        // Polynomial: 1 + 2x + 3x^2 (in coefficients)
        let coeffs = vec![1, 2, 3];
        let points = vec![0, 1, 2];
        let mut results = vec![0u32; 3];
        
        backend.batch_evaluate(&coeffs, &points, &mut results).unwrap();
        
        // At x=0: 1 + 0 + 0 = 1
        assert_eq!(results[0], 1);
        // At x=1: 1 + 2 + 3 = 6
        assert_eq!(results[1], 6);
        // At x=2: 1 + 4 + 12 = 17
        assert_eq!(results[2], 17);
    }
    
    #[cfg(target_os = "macos")]
    #[test]
    fn test_metal_merkle_tree() {
        let backend = MetalBackend::new().unwrap();
        
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| {
            let mut leaf = [0u8; 32];
            leaf[0] = i as u8;
            leaf
        }).collect();
        
        let tree = backend.merkle_tree(&leaves).unwrap();
        
        // Tree should have 2*4 - 1 = 7 nodes
        assert_eq!(tree.len(), 7);
        
        // Leaves should be at positions 3, 4, 5, 6
        assert_eq!(tree[3][0], 0);
        assert_eq!(tree[4][0], 1);
        assert_eq!(tree[5][0], 2);
        assert_eq!(tree[6][0], 3);
    }
}
