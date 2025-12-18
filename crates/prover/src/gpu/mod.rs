//! GPU acceleration backend for the prover.
//!
//! This module provides traits and implementations for GPU-accelerated
//! cryptographic operations used in STARK proving.
//!
//! # Supported Backends
//!
//! - **Metal**: Apple Silicon GPUs (macOS/iOS)
//! - **CPU**: Fallback implementation (always available)
//!
//! # Usage
//!
//! ```ignore
//! use zp1_prover::gpu::{detect_devices, DeviceType, get_backend};
//!
//! // Detect available devices
//! let devices = detect_devices();
//!
//! // Get the best available backend
//! let backend = get_backend()?;
//!
//! // Use NTT acceleration
//! backend.ntt_m31(&mut values, log_n)?;
//! ```

mod backend;
mod operations;

// Platform-specific backends
#[cfg(target_os = "macos")]
pub mod metal;


pub use backend::{GpuBackend, GpuDevice, GpuError, GpuMemory, CpuBackend};
pub use operations::{GpuNtt, GpuPolynomial, GpuMerkle};

#[cfg(target_os = "macos")]
pub use metal::{MetalBackend, MetalDevice, MetalMemory, METAL_M31_SHADERS};


/// GPU device type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// Apple Metal device
    Metal,
    /// CPU fallback (no GPU)
    Cpu,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Metal => write!(f, "Metal"),
            DeviceType::Cpu => write!(f, "CPU"),
        }
    }
}

/// Detect available GPU devices on the system.
pub fn detect_devices() -> Vec<DeviceInfo> {
    let mut devices = Vec::new();
    
    // Check for Metal (macOS)
    #[cfg(target_os = "macos")]
    {
        devices.push(DeviceInfo {
            device_type: DeviceType::Metal,
            name: "Apple GPU".to_string(),
            compute_units: 0, // Would be populated by Metal API
            memory_bytes: 0,
            available: true,
        });
    }
    
    // CPU fallback is always available
    devices.push(DeviceInfo {
        device_type: DeviceType::Cpu,
        name: "CPU Fallback".to_string(),
        compute_units: num_cpus(),
        memory_bytes: 0,
        available: true,
    });
    
    devices
}

/// Information about a GPU device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Type of device (Metal, CPU)
    pub device_type: DeviceType,
    /// Device name
    pub name: String,
    /// Number of compute units
    pub compute_units: usize,
    /// Total memory in bytes
    pub memory_bytes: usize,
    /// Whether the device is currently available
    pub available: bool,
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

/// Get the best available GPU backend.
/// 
/// Priority: Metal (macOS) > CPU
/// 
/// # Returns
/// A boxed GpuBackend implementation.
pub fn get_backend() -> Result<Box<dyn GpuBackend>, GpuError> {
    // Try Metal on macOS
    #[cfg(target_os = "macos")]
    {
        match MetalBackend::new() {
            Ok(backend) => return Ok(Box::new(backend)),
            Err(_) => {} // Fall through to CPU
        }
    }
    
    // CPU fallback
    Ok(Box::new(CpuBackend::default()))
}

/// Get a specific backend by device type.
pub fn get_backend_for_device(device_type: DeviceType) -> Result<Box<dyn GpuBackend>, GpuError> {
    match device_type {
        #[cfg(target_os = "macos")]
        DeviceType::Metal => Ok(Box::new(MetalBackend::new()?)),
        
        #[cfg(not(target_os = "macos"))]
        DeviceType::Metal => Err(GpuError::DeviceNotAvailable(
            "Metal is only available on macOS".to_string()
        )),
        
        DeviceType::Cpu => Ok(Box::new(CpuBackend::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_devices() {
        let devices = detect_devices();
        assert!(!devices.is_empty());
        
        // CPU fallback should always be present
        let has_cpu = devices.iter().any(|d| d.device_type == DeviceType::Cpu);
        assert!(has_cpu);
    }
    
    #[test]
    fn test_device_type_display() {
        assert_eq!(format!("{}", DeviceType::Metal), "Metal");
        assert_eq!(format!("{}", DeviceType::Cpu), "CPU");
    }
    
    #[test]
    fn test_get_backend() {
        let backend = get_backend();
        assert!(backend.is_ok());
    }
    
    #[test]
    fn test_get_cpu_backend() {
        let backend = get_backend_for_device(DeviceType::Cpu);
        assert!(backend.is_ok());
    }
}