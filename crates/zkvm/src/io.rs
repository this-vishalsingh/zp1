//! I/O operations for guest programs
//!
//! This module provides functions for communicating with the host:
//! - Reading inputs from the host
//! - Committing outputs to the public journal
//! - Providing hints to the prover (not verified)
//!
//! # I/O Protocol
//!
//! Communication with the host uses syscalls:
//! - `READ` (0x02): Read input data from host into guest memory
//! - `COMMIT` (0x03): Write output data to the public journal
//! - `HINT` (0x04): Send unverified hint data to the prover

use serde::{Deserialize, Serialize};

/// Maximum buffer size for I/O operations (64 KB)
const MAX_IO_BUFFER_SIZE: usize = 65536;

/// Read typed input from the host
///
/// This function reads serialized data from the host and deserializes it.
/// The data must implement `serde::Deserialize`.
///
/// # Protocol
///
/// 1. First READ syscall with null pointer returns the size of the next input
/// 2. Second READ syscall with sized buffer reads the actual data
/// 3. Data is deserialized using bincode
///
/// # Example
///
/// ```rust,ignore
/// let x: u32 = read();
/// let data: Vec<u8> = read();
/// ```
///
/// # Panics
///
/// Panics if:
/// - Called outside of the zkVM guest environment
/// - Deserialization fails
/// - Input buffer size exceeds MAX_IO_BUFFER_SIZE
pub fn read<T: for<'de> Deserialize<'de>>() -> T {
    #[cfg(target_arch = "riscv32")]
    {
        // Step 1: Query the size of the next input
        let size: u32;
        unsafe {
            core::arch::asm!(
                "li a7, 0x02",       // READ syscall
                "li a0, 0",          // NULL pointer = query size
                "li a1, 0",          // max_size = 0 for query
                "ecall",
                "mv {size}, a0",
                size = out(reg) size,
            );
        }
        
        let size = size as usize;
        if size == 0 {
            panic!("read(): no input available");
        }
        if size > MAX_IO_BUFFER_SIZE {
            panic!("read(): input too large");
        }
        
        // Step 2: Allocate buffer and read the data
        // Using a fixed-size buffer on the stack for simplicity
        // In a full implementation, this would use dynamic allocation
        let mut buffer = [0u8; MAX_IO_BUFFER_SIZE];
        let bytes_read: u32;
        
        unsafe {
            core::arch::asm!(
                "li a7, 0x02",       // READ syscall
                "mv a0, {buf_ptr}",  // buffer pointer
                "mv a1, {buf_len}",  // buffer length
                "ecall",
                "mv {bytes_read}, a0",
                buf_ptr = in(reg) buffer.as_mut_ptr(),
                buf_len = in(reg) size,
                bytes_read = out(reg) bytes_read,
            );
        }
        
        // Step 3: Deserialize using bincode
        let data = &buffer[..bytes_read as usize];
        bincode::deserialize(data).expect("read(): deserialization failed")
    }
    
    #[cfg(not(target_arch = "riscv32"))]
    {
        panic!("read() only works in zkVM guest (riscv32 target)")
    }
}

/// Read raw bytes from the host input
///
/// Lower-level function that reads raw bytes without deserialization.
/// Useful when you need direct access to input data.
///
/// # Returns
///
/// A tuple containing:
/// - Slice of the read data
/// - Number of bytes read
///
/// # Example
///
/// ```rust,ignore
/// let (data, len) = read_slice();
/// ```
#[cfg(target_arch = "riscv32")]
pub fn read_slice(buffer: &mut [u8]) -> usize {
    let bytes_read: u32;
    
    unsafe {
        core::arch::asm!(
            "li a7, 0x02",       // READ syscall
            "mv a0, {buf_ptr}",  // buffer pointer
            "mv a1, {buf_len}",  // buffer length
            "ecall",
            "mv {bytes_read}, a0",
            buf_ptr = in(reg) buffer.as_mut_ptr(),
            buf_len = in(reg) buffer.len(),
            bytes_read = out(reg) bytes_read,
        );
    }
    
    bytes_read as usize
}

/// Query the size of the next input without consuming it
///
/// # Returns
///
/// The size in bytes of the next input, or 0 if no input is available.
#[cfg(target_arch = "riscv32")]
pub fn peek_input_size() -> usize {
    let size: u32;
    unsafe {
        core::arch::asm!(
            "li a7, 0x02",       // READ syscall
            "li a0, 0",          // NULL pointer = query size
            "li a1, 0",          // max_size = 0 for query
            "ecall",
            "mv {size}, a0",
            size = out(reg) size,
        );
    }
    size as usize
}

/// Commit typed output to the public journal
///
/// This function serializes the value and commits it to the public outputs
/// that will be verified as part of the proof.
///
/// # Protocol
///
/// 1. Value is serialized using bincode
/// 2. COMMIT syscall writes data to the public journal
/// 3. Journal contents become part of the proof's public inputs
///
/// # Example
///
/// ```rust,ignore
/// commit(&42u32);
/// commit(&vec![1u8, 2, 3, 4]);
/// ```
///
/// # Panics
///
/// Panics if:
/// - Called outside of the zkVM guest environment
/// - Serialization fails
/// - Serialized data exceeds MAX_IO_BUFFER_SIZE
pub fn commit<T: Serialize>(value: &T) {
    #[cfg(target_arch = "riscv32")]
    {
        // Serialize the value using bincode
        let data = bincode::serialize(value).expect("commit(): serialization failed");
        
        if data.len() > MAX_IO_BUFFER_SIZE {
            panic!("commit(): output too large");
        }
        
        // Call COMMIT syscall
        unsafe {
            core::arch::asm!(
                "li a7, 0x03",       // COMMIT syscall
                "mv a0, {data_ptr}", // data pointer
                "mv a1, {data_len}", // data length
                "ecall",
                data_ptr = in(reg) data.as_ptr(),
                data_len = in(reg) data.len(),
                out("a0") _,         // clobber return value
            );
        }
    }
    
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = value; // silence unused warning
        panic!("commit() only works in zkVM guest (riscv32 target)")
    }
}

/// Commit raw bytes to the public journal
///
/// Lower-level function that commits raw bytes without serialization.
/// Useful for committing pre-serialized data or raw hashes.
///
/// # Example
///
/// ```rust,ignore
/// let hash = keccak256(b"data");
/// commit_slice(&hash);
/// ```
pub fn commit_slice(data: &[u8]) {
    #[cfg(target_arch = "riscv32")]
    {
        unsafe {
            core::arch::asm!(
                "li a7, 0x03",       // COMMIT syscall
                "mv a0, {data_ptr}", // data pointer
                "mv a1, {data_len}", // data length
                "ecall",
                data_ptr = in(reg) data.as_ptr(),
                data_len = in(reg) data.len(),
                out("a0") _,         // clobber return value
            );
        }
    }
    
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = data;
        panic!("commit_slice() only works in zkVM guest (riscv32 target)")
    }
}

/// Provide hint to prover (not cryptographically verified)
///
/// Hints allow guest programs to provide data to the prover that
/// is not part of the public inputs/outputs. This is useful for
/// optimization but should never be trusted for correctness.
///
/// # Protocol
///
/// 1. Value is serialized using bincode
/// 2. HINT syscall sends data to the prover
/// 3. Prover can use this for witness generation
///
/// # Security
///
/// **WARNING**: Hints are NOT verified. Never use hints for security-critical
/// data. Always verify hint data within the guest program.
///
/// # Example
///
/// ```rust,ignore
/// // Provide a hint about expected intermediate value
/// hint(&intermediate_computation);
/// ```
pub fn hint<T: Serialize>(value: &T) {
    #[cfg(target_arch = "riscv32")]
    {
        // Serialize the value using bincode
        if let Ok(data) = bincode::serialize(value) {
            if data.len() <= MAX_IO_BUFFER_SIZE {
                unsafe {
                    core::arch::asm!(
                        "li a7, 0x04",       // HINT syscall
                        "mv a0, {data_ptr}", // data pointer
                        "mv a1, {data_len}", // data length
                        "ecall",
                        data_ptr = in(reg) data.as_ptr(),
                        data_len = in(reg) data.len(),
                        out("a0") _,         // clobber return value
                    );
                }
            }
            // Silently ignore oversized hints - they're optional
        }
        // Silently ignore serialization failures - hints are optional
    }
    
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = value; // silence unused warning
        // No-op outside zkVM - hints are optional
    }
}

/// Provide raw bytes as a hint to the prover
///
/// Lower-level function that sends raw bytes as a hint.
///
/// # Example
///
/// ```rust,ignore
/// hint_slice(&precomputed_data);
/// ```
pub fn hint_slice(data: &[u8]) {
    #[cfg(target_arch = "riscv32")]
    {
        if data.len() <= MAX_IO_BUFFER_SIZE {
            unsafe {
                core::arch::asm!(
                    "li a7, 0x04",       // HINT syscall
                    "mv a0, {data_ptr}", // data pointer
                    "mv a1, {data_len}", // data length
                    "ecall",
                    data_ptr = in(reg) data.as_ptr(),
                    data_len = in(reg) data.len(),
                    out("a0") _,         // clobber return value
                );
            }
        }
    }
    
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = data; // No-op outside zkVM
    }
}

/// Write to stdout (for debugging)
///
/// This is primarily for testing and debugging guest programs.
/// Output is not part of the verified computation.
pub fn print(msg: &str) {
    #[cfg(target_arch = "riscv32")]
    {
        let bytes = msg.as_bytes();
        unsafe {
            core::arch::asm!(
                "li a7, 0x01",  // WRITE syscall
                "li a0, 1",      // fd = stdout
                "mv a1, {ptr}",
                "mv a2, {len}",
                "ecall",
                ptr = in(reg) bytes.as_ptr(),
                len = in(reg) bytes.len(),
                out("a0") _,  // clobber return value
            );
        }
    }
    
    #[cfg(not(target_arch = "riscv32"))]
    {
        // For testing outside zkVM
        #[cfg(feature = "std")]
        println!("{}", msg);
    }
}
