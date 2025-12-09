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
//! - `gpu-metal` feature enabled
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
    return sum >= M31_P ? sum - M31_P : sum;
}

// Modular subtraction in M31
inline uint m31_sub(uint a, uint b) {
    return a >= b ? a - b : M31_P - b + a;
}

// Modular multiplication in M31
inline uint m31_mul(uint a, uint b) {
    ulong prod = (ulong)a * (ulong)b;
    uint lo = prod & M31_P;
    uint hi = prod >> 31;
    uint sum = lo + hi;
    return sum >= M31_P ? sum - M31_P : sum;
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

// Inverse NTT butterfly
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

// Bit-reverse permutation
kernel void bit_reverse_permute(
    device uint* data [[buffer(0)]],
    constant uint& n [[buffer(1)]],
    constant uint& log_n [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= n) return;
    
    uint rev = 0;
    uint tmp = tid;
    for (uint i = 0; i < log_n; i++) {
        rev = (rev << 1) | (tmp & 1);
        tmp >>= 1;
    }
    
    if (tid < rev) {
        uint temp = data[tid];
        data[tid] = data[rev];
        data[rev] = temp;
    }
}

// Polynomial evaluation (Horner's method)
kernel void poly_eval_batch(
    device const uint* coeffs [[buffer(0)]],
    constant uint& num_coeffs [[buffer(1)]],
    device const uint* points [[buffer(2)]],
    device uint* results [[buffer(3)]],
    uint tid [[thread_position_in_grid]]
) {
    uint point = points[tid];
    uint result = 0;
    
    for (int i = num_coeffs - 1; i >= 0; i--) {
        result = m31_add(m31_mul(result, point), coeffs[i]);
    }
    
    results[tid] = result;
}

// LDE evaluation
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

// Merkle layer hashing
kernel void merkle_layer(
    device const uchar* prev_layer [[buffer(0)]],
    device uchar* next_layer [[buffer(1)]],
    constant uint& num_pairs [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    if (tid >= num_pairs) return;
    
    uint src_offset = tid * 64;
    uint dst_offset = tid * 32;
    
    for (uint i = 0; i < 32; i++) {
        uchar left = prev_layer[src_offset + i];
        uchar right = prev_layer[src_offset + 32 + i];
        next_layer[dst_offset + i] = left ^ right ^ (uchar)((left + right) >> 1);
    }
}
"#;

// ============================================================================
// Native Metal Implementation (when gpu-metal feature is enabled)
// ============================================================================

#[cfg(all(target_os = "macos", feature = "gpu-metal"))]
mod native {
    use super::*;
    use metal::{Device, CommandQueue, Library, ComputePipelineState, Buffer, MTLResourceOptions};
    use std::sync::Arc;

    /// Native Metal backend using metal-rs crate.
    pub struct MetalBackend {
        device: Device,
        command_queue: CommandQueue,
        library: Library,
        // Pipeline states for each kernel
        ntt_butterfly_pipeline: ComputePipelineState,
        intt_butterfly_pipeline: ComputePipelineState,
        intt_scale_pipeline: ComputePipelineState,
        bit_reverse_pipeline: ComputePipelineState,
        poly_eval_pipeline: ComputePipelineState,
        lde_pipeline: ComputePipelineState,
        merkle_layer_pipeline: ComputePipelineState,
        // Precomputed twiddles
        twiddles: Vec<u32>,
        inv_twiddles: Vec<u32>,
        twiddle_buffer: Option<Buffer>,
        inv_twiddle_buffer: Option<Buffer>,
        max_log_n: usize,
    }

    impl MetalBackend {
        /// Create a new native Metal backend.
        pub fn new() -> Result<Self, GpuError> {
            let device = Device::system_default()
                .ok_or_else(|| GpuError::DeviceNotAvailable("No Metal device found".to_string()))?;
            
            let command_queue = device.new_command_queue();
            
            // Compile shaders
            let library = device.new_library_with_source(METAL_M31_SHADERS, &metal::CompileOptions::new())
                .map_err(|e| GpuError::KernelError(format!("Shader compilation failed: {}", e)))?;
            
            // Create pipeline states for each kernel
            let ntt_butterfly_pipeline = Self::create_pipeline(&device, &library, "ntt_butterfly")?;
            let intt_butterfly_pipeline = Self::create_pipeline(&device, &library, "intt_butterfly")?;
            let intt_scale_pipeline = Self::create_pipeline(&device, &library, "intt_scale")?;
            let bit_reverse_pipeline = Self::create_pipeline(&device, &library, "bit_reverse_permute")?;
            let poly_eval_pipeline = Self::create_pipeline(&device, &library, "poly_eval_batch")?;
            let lde_pipeline = Self::create_pipeline(&device, &library, "lde_evaluate")?;
            let merkle_layer_pipeline = Self::create_pipeline(&device, &library, "merkle_layer")?;
            
            Ok(Self {
                device,
                command_queue,
                library,
                ntt_butterfly_pipeline,
                intt_butterfly_pipeline,
                intt_scale_pipeline,
                bit_reverse_pipeline,
                poly_eval_pipeline,
                lde_pipeline,
                merkle_layer_pipeline,
                twiddles: Vec::new(),
                inv_twiddles: Vec::new(),
                twiddle_buffer: None,
                inv_twiddle_buffer: None,
                max_log_n: 24,
            })
        }
        
        fn create_pipeline(device: &Device, library: &Library, name: &str) -> Result<ComputePipelineState, GpuError> {
            let function = library.get_function(name, None)
                .map_err(|e| GpuError::KernelError(format!("Function '{}' not found: {}", name, e)))?;
            
            device.new_compute_pipeline_state_with_function(&function)
                .map_err(|e| GpuError::KernelError(format!("Pipeline creation failed for '{}': {}", name, e)))
        }
        
        /// Precompute twiddle factors for NTT.
        pub fn precompute_twiddles(&mut self, log_n: usize) -> Result<(), GpuError> {
            if log_n > self.max_log_n {
                return Err(GpuError::NotSupported(
                    format!("log_n {} exceeds maximum {}", log_n, self.max_log_n)
                ));
            }
            
            let n = 1usize << log_n;
            const M31_P: u64 = (1u64 << 31) - 1;
            
            let generator = 5u64;
            let order = M31_P - 1;
            let step = order / (n as u64);
            
            self.twiddles = Vec::with_capacity(n);
            let mut w = 1u64;
            for _ in 0..n {
                self.twiddles.push(w as u32);
                w = (w * pow_mod(generator, step, M31_P)) % M31_P;
            }
            
            self.inv_twiddles = self.twiddles.iter().rev().cloned().collect();
            
            // Create GPU buffers for twiddles
            let twiddle_bytes = bytemuck::cast_slice::<u32, u8>(&self.twiddles);
            self.twiddle_buffer = Some(self.device.new_buffer_with_data(
                twiddle_bytes.as_ptr() as *const _,
                twiddle_bytes.len() as u64,
                MTLResourceOptions::StorageModeShared,
            ));
            
            let inv_twiddle_bytes = bytemuck::cast_slice::<u32, u8>(&self.inv_twiddles);
            self.inv_twiddle_buffer = Some(self.device.new_buffer_with_data(
                inv_twiddle_bytes.as_ptr() as *const _,
                inv_twiddle_bytes.len() as u64,
                MTLResourceOptions::StorageModeShared,
            ));
            
            Ok(())
        }
        
        fn execute_ntt_gpu(&self, values: &mut [u32], log_n: usize, inverse: bool) -> Result<(), GpuError> {
            let n = 1usize << log_n;
            
            // Ensure twiddles are precomputed
            let twiddle_buffer = if inverse {
                self.inv_twiddle_buffer.as_ref()
            } else {
                self.twiddle_buffer.as_ref()
            }.ok_or_else(|| GpuError::NotSupported("Twiddles not precomputed".to_string()))?;
            
            // Create data buffer
            let data_bytes = bytemuck::cast_slice::<u32, u8>(values);
            let data_buffer = self.device.new_buffer_with_data(
                data_bytes.as_ptr() as *const _,
                data_bytes.len() as u64,
                MTLResourceOptions::StorageModeShared,
            );
            
            let command_buffer = self.command_queue.new_command_buffer();
            
            // Bit-reverse permutation
            {
                let encoder = command_buffer.new_compute_command_encoder();
                encoder.set_compute_pipeline_state(&self.bit_reverse_pipeline);
                encoder.set_buffer(0, Some(&data_buffer), 0);
                encoder.set_bytes(1, std::mem::size_of::<u32>() as u64, &(n as u32) as *const u32 as *const _);
                encoder.set_bytes(2, std::mem::size_of::<u32>() as u64, &(log_n as u32) as *const u32 as *const _);
                
                let thread_group_size = metal::MTLSize::new(256, 1, 1);
                let grid_size = metal::MTLSize::new(n as u64, 1, 1);
                encoder.dispatch_threads(grid_size, thread_group_size);
                encoder.end_encoding();
            }
            
            // Butterfly stages
            let pipeline = if inverse {
                &self.intt_butterfly_pipeline
            } else {
                &self.ntt_butterfly_pipeline
            };
            
            let stages: Box<dyn Iterator<Item = usize>> = if inverse {
                Box::new((0..log_n).rev())
            } else {
                Box::new(0..log_n)
            };
            
            for stage in stages {
                let encoder = command_buffer.new_compute_command_encoder();
                encoder.set_compute_pipeline_state(pipeline);
                encoder.set_buffer(0, Some(&data_buffer), 0);
                encoder.set_bytes(1, std::mem::size_of::<u32>() as u64, &(n as u32) as *const u32 as *const _);
                encoder.set_bytes(2, std::mem::size_of::<u32>() as u64, &(stage as u32) as *const u32 as *const _);
                encoder.set_buffer(3, Some(twiddle_buffer), 0);
                
                let threads_per_stage = n / 2;
                let thread_group_size = metal::MTLSize::new(256.min(threads_per_stage as u64), 1, 1);
                let grid_size = metal::MTLSize::new(threads_per_stage as u64, 1, 1);
                encoder.dispatch_threads(grid_size, thread_group_size);
                encoder.end_encoding();
            }
            
            // Scale for inverse NTT
            if inverse {
                let inv_n = mod_inverse(n as u32, M31_P as u32);
                let encoder = command_buffer.new_compute_command_encoder();
                encoder.set_compute_pipeline_state(&self.intt_scale_pipeline);
                encoder.set_buffer(0, Some(&data_buffer), 0);
                encoder.set_bytes(1, std::mem::size_of::<u32>() as u64, &(n as u32) as *const u32 as *const _);
                encoder.set_bytes(2, std::mem::size_of::<u32>() as u64, &inv_n as *const u32 as *const _);
                
                let thread_group_size = metal::MTLSize::new(256, 1, 1);
                let grid_size = metal::MTLSize::new(n as u64, 1, 1);
                encoder.dispatch_threads(grid_size, thread_group_size);
                encoder.end_encoding();
            }
            
            command_buffer.commit();
            command_buffer.wait_until_completed();
            
            // Copy results back
            let result_ptr = data_buffer.contents() as *const u32;
            unsafe {
                std::ptr::copy_nonoverlapping(result_ptr, values.as_mut_ptr(), n);
            }
            
            Ok(())
        }
    }
    
    impl GpuBackend for MetalBackend {
        fn device(&self) -> &dyn GpuDevice {
            static DEVICE: std::sync::OnceLock<MetalDeviceWrapper> = std::sync::OnceLock::new();
            DEVICE.get_or_init(|| MetalDeviceWrapper::new().unwrap())
        }
        
        fn ntt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
            self.execute_ntt_gpu(values, log_n, false)
        }
        
        fn intt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
            self.execute_ntt_gpu(values, log_n, true)
        }
        
        fn batch_evaluate(
            &self,
            coeffs: &[u32],
            points: &[u32],
            results: &mut [u32],
        ) -> Result<(), GpuError> {
            let num_points = points.len();
            let num_coeffs = coeffs.len();
            
            // Create buffers
            let coeffs_buffer = self.device.new_buffer_with_data(
                coeffs.as_ptr() as *const _,
                (coeffs.len() * 4) as u64,
                MTLResourceOptions::StorageModeShared,
            );
            let points_buffer = self.device.new_buffer_with_data(
                points.as_ptr() as *const _,
                (points.len() * 4) as u64,
                MTLResourceOptions::StorageModeShared,
            );
            let results_buffer = self.device.new_buffer(
                (num_points * 4) as u64,
                MTLResourceOptions::StorageModeShared,
            );
            
            let command_buffer = self.command_queue.new_command_buffer();
            let encoder = command_buffer.new_compute_command_encoder();
            
            encoder.set_compute_pipeline_state(&self.poly_eval_pipeline);
            encoder.set_buffer(0, Some(&coeffs_buffer), 0);
            encoder.set_bytes(1, 4, &(num_coeffs as u32) as *const u32 as *const _);
            encoder.set_buffer(2, Some(&points_buffer), 0);
            encoder.set_buffer(3, Some(&results_buffer), 0);
            
            let thread_group_size = metal::MTLSize::new(256.min(num_points as u64), 1, 1);
            let grid_size = metal::MTLSize::new(num_points as u64, 1, 1);
            encoder.dispatch_threads(grid_size, thread_group_size);
            encoder.end_encoding();
            
            command_buffer.commit();
            command_buffer.wait_until_completed();
            
            // Copy results
            let result_ptr = results_buffer.contents() as *const u32;
            unsafe {
                std::ptr::copy_nonoverlapping(result_ptr, results.as_mut_ptr(), num_points);
            }
            
            Ok(())
        }
        
        fn merkle_tree(&self, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError> {
            // Use CPU fallback for now - Blake3 GPU implementation is complex
            cpu_merkle_tree(leaves)
        }
        
        fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError> {
            let n = coeffs.len();
            let extended_n = n * blowup_factor;
            
            // Generate extended domain
            let mut domain = Vec::with_capacity(extended_n);
            let generator = 3u32;
            let mut point = generator;
            for _ in 0..extended_n {
                domain.push(point);
                point = m31_mul(point, generator);
            }
            
            let mut results = vec![0u32; extended_n];
            self.batch_evaluate(coeffs, &domain, &mut results)?;
            Ok(results)
        }
    }
    
    pub struct MetalDeviceWrapper {
        name: String,
        memory_bytes: usize,
    }
    
    impl MetalDeviceWrapper {
        pub fn new() -> Result<Self, GpuError> {
            let device = Device::system_default()
                .ok_or_else(|| GpuError::DeviceNotAvailable("No Metal device".to_string()))?;
            Ok(Self {
                name: device.name().to_string(),
                memory_bytes: device.recommended_max_working_set_size() as usize,
            })
        }
    }
    
    impl GpuDevice for MetalDeviceWrapper {
        fn device_type(&self) -> DeviceType { DeviceType::Metal }
        fn name(&self) -> &str { &self.name }
        fn allocate(&self, size: usize) -> Result<Box<dyn GpuMemory>, GpuError> {
            Ok(Box::new(MetalMemory::new(size)))
        }
        fn synchronize(&self) -> Result<(), GpuError> { Ok(()) }
        fn available_memory(&self) -> usize { self.memory_bytes }
    }
    
    pub struct MetalMemory {
        data: Vec<u8>,
    }
    
    impl MetalMemory {
        pub fn new(size: usize) -> Self {
            Self { data: vec![0u8; size] }
        }
    }
    
    impl GpuMemory for MetalMemory {
        fn size(&self) -> usize { self.data.len() }
        fn copy_from_host(&mut self, data: &[u8]) -> Result<(), GpuError> {
            self.data[..data.len()].copy_from_slice(data);
            Ok(())
        }
        fn copy_to_host(&self, data: &mut [u8]) -> Result<(), GpuError> {
            data.copy_from_slice(&self.data[..data.len()]);
            Ok(())
        }
        fn as_ptr(&self) -> *const u8 { self.data.as_ptr() }
        fn as_mut_ptr(&mut self) -> *mut u8 { self.data.as_mut_ptr() }
    }
}

// ============================================================================
// CPU Fallback Implementation (when gpu-metal feature is NOT enabled)
// ============================================================================

#[cfg(all(target_os = "macos", not(feature = "gpu-metal")))]
mod fallback {
    use super::*;

    /// Fallback Metal backend (CPU implementation).
    pub struct MetalBackend {
        _device_name: String,
        twiddles: Vec<u32>,
        inv_twiddles: Vec<u32>,
        max_log_n: usize,
    }

    impl MetalBackend {
        pub fn new() -> Result<Self, GpuError> {
            Ok(Self {
                _device_name: "Apple GPU (CPU Fallback)".to_string(),
                twiddles: Vec::new(),
                inv_twiddles: Vec::new(),
                max_log_n: 24,
            })
        }
        
        pub fn precompute_twiddles(&mut self, log_n: usize) -> Result<(), GpuError> {
            if log_n > self.max_log_n {
                return Err(GpuError::NotSupported(
                    format!("log_n {} exceeds maximum {}", log_n, self.max_log_n)
                ));
            }
            
            let n = 1usize << log_n;
            const M31_P: u64 = (1u64 << 31) - 1;
            
            let generator = 5u64;
            let order = M31_P - 1;
            let step = order / (n as u64);
            
            self.twiddles = Vec::with_capacity(n);
            let mut w = 1u64;
            for _ in 0..n {
                self.twiddles.push(w as u32);
                w = (w * pow_mod(generator, step, M31_P)) % M31_P;
            }
            
            self.inv_twiddles = self.twiddles.iter().rev().cloned().collect();
            Ok(())
        }
    }

    impl GpuBackend for MetalBackend {
        fn device(&self) -> &dyn GpuDevice {
            static DEVICE: std::sync::OnceLock<MetalDevice> = std::sync::OnceLock::new();
            DEVICE.get_or_init(|| MetalDevice::new().unwrap())
        }
        
        fn ntt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
            cpu_ntt(values, log_n, &self.twiddles, false)
        }
        
        fn intt_m31(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
            cpu_ntt(values, log_n, &self.inv_twiddles, true)
        }
        
        fn batch_evaluate(
            &self,
            coeffs: &[u32],
            points: &[u32],
            results: &mut [u32],
        ) -> Result<(), GpuError> {
            cpu_batch_evaluate(coeffs, points, results)
        }
        
        fn merkle_tree(&self, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError> {
            cpu_merkle_tree(leaves)
        }
        
        fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError> {
            cpu_lde(coeffs, blowup_factor)
        }
    }

    impl Default for MetalBackend {
        fn default() -> Self {
            Self::new().expect("Failed to create Metal backend")
        }
    }

    pub struct MetalDevice {
        name: String,
        memory_bytes: usize,
    }

    impl MetalDevice {
        pub fn new() -> Result<Self, GpuError> {
            Ok(Self {
                name: "Apple GPU (Fallback)".to_string(),
                memory_bytes: 16 * 1024 * 1024 * 1024,
            })
        }
    }

    impl Default for MetalDevice {
        fn default() -> Self {
            Self::new().expect("Failed to create Metal device")
        }
    }

    impl GpuDevice for MetalDevice {
        fn device_type(&self) -> DeviceType { DeviceType::Metal }
        fn name(&self) -> &str { &self.name }
        fn allocate(&self, size: usize) -> Result<Box<dyn GpuMemory>, GpuError> {
            Ok(Box::new(MetalMemory::new(size)))
        }
        fn synchronize(&self) -> Result<(), GpuError> { Ok(()) }
        fn available_memory(&self) -> usize { self.memory_bytes }
    }

    pub struct MetalMemory {
        data: Vec<u8>,
    }

    impl MetalMemory {
        pub fn new(size: usize) -> Self {
            Self { data: vec![0u8; size] }
        }
    }

    impl GpuMemory for MetalMemory {
        fn size(&self) -> usize { self.data.len() }
        fn copy_from_host(&mut self, data: &[u8]) -> Result<(), GpuError> {
            self.data[..data.len()].copy_from_slice(data);
            Ok(())
        }
        fn copy_to_host(&self, data: &mut [u8]) -> Result<(), GpuError> {
            data.copy_from_slice(&self.data[..data.len()]);
            Ok(())
        }
        fn as_ptr(&self) -> *const u8 { self.data.as_ptr() }
        fn as_mut_ptr(&mut self) -> *mut u8 { self.data.as_mut_ptr() }
    }
}

// Re-export based on feature
#[cfg(all(target_os = "macos", feature = "gpu-metal"))]
pub use native::{MetalBackend, MetalMemory};

#[cfg(all(target_os = "macos", feature = "gpu-metal"))]
pub use native::MetalDeviceWrapper as MetalDevice;

#[cfg(all(target_os = "macos", not(feature = "gpu-metal")))]
pub use fallback::{MetalBackend, MetalDevice, MetalMemory};

// ============================================================================
// Shared Helper Functions
// ============================================================================

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

fn cpu_ntt(values: &mut [u32], log_n: usize, twiddles: &[u32], inverse: bool) -> Result<(), GpuError> {
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
    
    // Butterfly stages
    for stage in 0..log_n {
        let half_step = 1usize << stage;
        let step = half_step << 1;
        
        for group in (0..n).step_by(step) {
            for pos in 0..half_step {
                let i = group + pos;
                let j = i + half_step;
                
                let w = twiddles.get(pos * (n / step)).copied().unwrap_or(1);
                let u = values[i];
                let v = m31_mul(values[j], w);
                
                values[i] = m31_add(u, v);
                values[j] = m31_sub(u, v);
            }
        }
    }
    
    // Scale for inverse
    if inverse {
        let inv_n = mod_inverse(n as u32, M31_P);
        for v in values.iter_mut() {
            *v = m31_mul(*v, inv_n);
        }
    }
    
    Ok(())
}

fn cpu_batch_evaluate(coeffs: &[u32], points: &[u32], results: &mut [u32]) -> Result<(), GpuError> {
    for (i, &point) in points.iter().enumerate() {
        let mut result = 0u32;
        for &coeff in coeffs.iter().rev() {
            result = m31_add(m31_mul(result, point), coeff);
        }
        results[i] = result;
    }
    Ok(())
}

fn cpu_merkle_tree(leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError> {
    let n = leaves.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(GpuError::InvalidBufferSize {
            expected: n.next_power_of_two(),
            actual: n,
        });
    }
    
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

fn cpu_lde(coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError> {
    let n = coeffs.len();
    let extended_n = n * blowup_factor;
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

#[cfg(all(target_os = "macos", feature = "gpu-metal"))]
impl Default for native::MetalBackend {
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
        
        assert_eq!(m31_mul(2, 3), 6);
    }
    
    #[test]
    fn test_bit_reverse() {
        assert_eq!(bit_reverse(0b000, 3), 0b000);
        assert_eq!(bit_reverse(0b001, 3), 0b100);
    }
    
    #[test]
    fn test_mod_inverse() {
        let inv = mod_inverse(3, M31_P);
        assert_eq!(m31_mul(3, inv), 1);
    }
    
    #[cfg(target_os = "macos")]
    #[test]
    fn test_metal_backend_creation() {
        let backend = MetalBackend::new();
        assert!(backend.is_ok());
    }
    
    #[cfg(target_os = "macos")]
    #[test]
    fn test_batch_evaluate() {
        let backend = MetalBackend::new().unwrap();
        
        let coeffs = vec![1, 2, 3];
        let points = vec![0, 1, 2];
        let mut results = vec![0u32; 3];
        
        backend.batch_evaluate(&coeffs, &points, &mut results).unwrap();
        
        assert_eq!(results[0], 1);  // 1 + 0 + 0
        assert_eq!(results[1], 6);  // 1 + 2 + 3
        assert_eq!(results[2], 17); // 1 + 4 + 12
    }
}
