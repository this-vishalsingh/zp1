//! GPU backend trait and implementations.

#![allow(dead_code)]

use std::sync::Arc;
use crate::gpu::DeviceType;

/// Error type for GPU operations.
#[derive(Debug, Clone)]
pub enum GpuError {
    /// Device not available
    DeviceNotAvailable(String),
    /// Out of memory
    OutOfMemory { requested: usize, available: usize },
    /// Kernel execution failed
    KernelError(String),
    /// Invalid buffer size
    InvalidBufferSize { expected: usize, actual: usize },
    /// Synchronization error
    SyncError(String),
    /// Feature not supported
    NotSupported(String),
}

impl std::fmt::Display for GpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuError::DeviceNotAvailable(msg) => write!(f, "Device not available: {}", msg),
            GpuError::OutOfMemory { requested, available } => {
                write!(f, "Out of GPU memory: requested {} bytes, {} available", requested, available)
            }
            GpuError::KernelError(msg) => write!(f, "Kernel execution failed: {}", msg),
            GpuError::InvalidBufferSize { expected, actual } => {
                write!(f, "Invalid buffer size: expected {}, got {}", expected, actual)
            }
            GpuError::SyncError(msg) => write!(f, "Synchronization error: {}", msg),
            GpuError::NotSupported(msg) => write!(f, "Feature not supported: {}", msg),
        }
    }
}

impl std::error::Error for GpuError {}

/// Represents memory allocated on a GPU device.
pub trait GpuMemory: Send + Sync {
    /// Get the size of the allocated memory in bytes.
    fn size(&self) -> usize;
    
    /// Copy data from host to device.
    fn copy_from_host(&mut self, data: &[u8]) -> Result<(), GpuError>;
    
    /// Copy data from device to host.
    fn copy_to_host(&self, data: &mut [u8]) -> Result<(), GpuError>;
    
    /// Get raw pointer (for internal use).
    fn as_ptr(&self) -> *const u8;
    
    /// Get mutable raw pointer (for internal use).
    fn as_mut_ptr(&mut self) -> *mut u8;
}

/// Represents a GPU compute device.
pub trait GpuDevice: Send + Sync {
    /// Get device type.
    fn device_type(&self) -> DeviceType;
    
    /// Get device name.
    fn name(&self) -> &str;
    
    /// Allocate memory on device.
    fn allocate(&self, size: usize) -> Result<Box<dyn GpuMemory>, GpuError>;
    
    /// Synchronize all pending operations.
    fn synchronize(&self) -> Result<(), GpuError>;
    
    /// Get available memory in bytes.
    fn available_memory(&self) -> usize;
}

/// GPU backend providing accelerated cryptographic operations.
pub trait GpuBackend: Send + Sync {
    /// Get the underlying device.
    fn device(&self) -> &dyn GpuDevice;
    
    /// Perform Number Theoretic Transform (NTT) on M31 elements.
    fn ntt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError>;
    
    /// Perform inverse NTT on M31 elements.
    fn intt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError>;
    
    /// Batch polynomial evaluation at multiple points.
    fn batch_evaluate(
        &self,
        coeffs: &[u32],
        points: &[u32],
        results: &mut [u32],
    ) -> Result<(), GpuError>;
    
    /// Compute Merkle tree from leaf hashes.
    fn merkle_tree(&self, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError>;
    
    /// Low Degree Extension (LDE) of polynomial.
    fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError>;
}

/// CPU fallback implementation of GPU memory.
pub struct CpuMemory {
    data: Vec<u8>,
}

impl CpuMemory {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }
}

impl GpuMemory for CpuMemory {
    fn size(&self) -> usize {
        self.data.len()
    }
    
    fn copy_from_host(&mut self, data: &[u8]) -> Result<(), GpuError> {
        if data.len() != self.data.len() {
            return Err(GpuError::InvalidBufferSize {
                expected: self.data.len(),
                actual: data.len(),
            });
        }
        self.data.copy_from_slice(data);
        Ok(())
    }
    
    fn copy_to_host(&self, data: &mut [u8]) -> Result<(), GpuError> {
        if data.len() != self.data.len() {
            return Err(GpuError::InvalidBufferSize {
                expected: self.data.len(),
                actual: data.len(),
            });
        }
        data.copy_from_slice(&self.data);
        Ok(())
    }
    
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }
    
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

/// CPU fallback implementation of GPU device.
pub struct CpuDevice {
    name: String,
}

impl CpuDevice {
    pub fn new() -> Self {
        Self {
            name: "CPU Fallback".to_string(),
        }
    }
}

impl Default for CpuDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuDevice for CpuDevice {
    fn device_type(&self) -> DeviceType {
        DeviceType::Cpu
    }
    
    fn name(&self) -> &str {
        &self.name
    }
    
    fn allocate(&self, size: usize) -> Result<Box<dyn GpuMemory>, GpuError> {
        Ok(Box::new(CpuMemory::new(size)))
    }
    
    fn synchronize(&self) -> Result<(), GpuError> {
        // CPU operations are synchronous
        Ok(())
    }
    
    fn available_memory(&self) -> usize {
        // Return a large value for CPU
        usize::MAX
    }
}

/// CPU fallback backend implementation.
pub struct CpuBackend {
    device: Arc<CpuDevice>,
}

impl CpuBackend {
    pub fn new() -> Self {
        Self {
            device: Arc::new(CpuDevice::new()),
        }
    }
}

impl Default for CpuBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuBackend for CpuBackend {
    fn device(&self) -> &dyn GpuDevice {
        self.device.as_ref()
    }
    
    fn ntt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
        let n = 1usize << log_n;
        if values.len() != n {
            return Err(GpuError::InvalidBufferSize {
                expected: n,
                actual: values.len(),
            });
        }

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

                    // Simplified twiddle (real GPU impl would use precomputed table)
                    let w = 1u32;

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

        // Gentleman-Sande butterfly stages (reverse order)
        for stage in (0..log_n).rev() {
            let half_step = 1usize << stage;
            let step = half_step << 1;

            for group in (0..n).step_by(step) {
                for pos in 0..half_step {
                    let i = group + pos;
                    let j = i + half_step;

                    // Simplified inverse twiddle
                    let w = 1u32;

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
        
        use zp1_primitives::field::M31;
        
        // Evaluate polynomial at each point
        for (i, &point) in points.iter().enumerate() {
            let x = M31::new(point);
            let mut result = M31::ZERO;
            let mut x_pow = M31::ONE;
            
            for &coeff in coeffs {
                result = result + M31::new(coeff) * x_pow;
                x_pow = x_pow * x;
            }
            
            results[i] = result.value();
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

        // Build tree bottom-up (matches CUDA/Metal fallback hash)
        let tree_size = 2 * n - 1;
        let mut tree = vec![[0u8; 32]; tree_size];

        tree[n - 1..].copy_from_slice(leaves);

        for i in (0..n - 1).rev() {
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
        let mut results = vec![0u32; extended_n];

        let generator = 3u32;
        let mut point = generator;

        for i in 0..extended_n {
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cpu_memory() {
        let mut mem = CpuMemory::new(32);
        assert_eq!(mem.size(), 32);
        
        let data = vec![1u8; 32];
        mem.copy_from_host(&data).unwrap();
        
        let mut output = vec![0u8; 32];
        mem.copy_to_host(&mut output).unwrap();
        
        assert_eq!(data, output);
    }
    
    #[test]
    fn test_cpu_device() {
        let device = CpuDevice::new();
        assert_eq!(device.device_type(), DeviceType::Cpu);
        assert!(device.name().contains("CPU"));
        
        let mem = device.allocate(64).unwrap();
        assert_eq!(mem.size(), 64);
        
        device.synchronize().unwrap();
    }
    
    #[test]
    fn test_cpu_backend_batch_evaluate() {
        let backend = CpuBackend::new();
        
        // Polynomial: 1 + 2x + 3x^2
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
    
    #[test]
    fn test_gpu_error_display() {
        let err = GpuError::OutOfMemory { requested: 1000, available: 500 };
        let msg = format!("{}", err);
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }
}
