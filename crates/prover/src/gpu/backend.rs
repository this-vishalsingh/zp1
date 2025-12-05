//! GPU backend trait and implementations.

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
        // Use the parallel CPU implementation
        use crate::parallel::parallel_lde;
        use zp1_primitives::field::M31;
        
        let n = 1 << log_n;
        if values.len() != n {
            return Err(GpuError::InvalidBufferSize {
                expected: n,
                actual: values.len(),
            });
        }
        
        // For now, just a placeholder - real impl would call Circle FFT
        // This demonstrates the interface
        Ok(())
    }
    
    fn intt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
        let n = 1 << log_n;
        if values.len() != n {
            return Err(GpuError::InvalidBufferSize {
                expected: n,
                actual: values.len(),
            });
        }
        
        // Placeholder for inverse NTT
        Ok(())
    }
    
    fn batch_evaluate(
        &self,
        coeffs: &[u32],
        points: &[u32],
        results: &mut [u32],
    ) -> Result<(), GpuError> {
        if results.len() != points.len() {
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
        use crate::parallel::parallel_merkle_layer;
        
        if leaves.is_empty() {
            return Ok(vec![]);
        }
        
        // Build tree from bottom up using parallel layer computation
        let n = leaves.len().next_power_of_two();
        let mut tree = vec![[0u8; 32]; 2 * n - 1];
        
        // Copy leaves to bottom level
        let leaf_start = n - 1;
        for (i, leaf) in leaves.iter().enumerate() {
            tree[leaf_start + i] = *leaf;
        }
        
        // Compute internal nodes bottom-up
        for level_start in (0..leaf_start).rev() {
            let left_child = 2 * level_start + 1;
            let right_child = 2 * level_start + 2;
            
            if left_child < tree.len() && right_child < tree.len() {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(tree[left_child]);
                hasher.update(tree[right_child]);
                tree[level_start].copy_from_slice(&hasher.finalize());
            }
        }
        
        Ok(tree)
    }
    
    fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError> {
        use zp1_primitives::field::M31;
        
        let values: Vec<M31> = coeffs.iter().map(|&v| M31::new(v)).collect();
        let columns = vec![values];
        let result = crate::parallel::parallel_lde(&columns, blowup_factor);
        if result.is_empty() {
            return Ok(vec![]);
        }
        Ok(result[0].iter().map(|v| v.value()).collect())
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
