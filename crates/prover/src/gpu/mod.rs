//! GPU acceleration backend for the prover.
//!
//! This module provides traits and implementations for GPU-accelerated
//! cryptographic operations used in STARK proving.

mod backend;
mod operations;

pub use backend::{GpuBackend, GpuDevice, GpuError, GpuMemory};
pub use operations::{GpuNtt, GpuPolynomial, GpuMerkle};

/// GPU device type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// NVIDIA CUDA device
    Cuda,
    /// Apple Metal device
    Metal,
    /// CPU fallback (no GPU)
    Cpu,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Cuda => write!(f, "CUDA"),
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
    /// Type of device (CUDA, Metal, CPU)
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
        assert_eq!(format!("{}", DeviceType::Cuda), "CUDA");
        assert_eq!(format!("{}", DeviceType::Metal), "Metal");
        assert_eq!(format!("{}", DeviceType::Cpu), "CPU");
    }
}
