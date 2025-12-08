//! ZP1 zkVM Guest Library
//!
//! This library provides the interface for writing guest programs that run inside
//! the ZP1 zkVM. Guest programs are RISC-V binaries that are executed and proven.
//!
//! # Overview
//!
//! The zkVM guest library provides:
//! - **I/O functions**: Read inputs from host, commit outputs to public journal
//! - **Syscalls**: Invoke precompiles for cryptographic operations
//! - **no_std support**: Works in bare-metal RISC-V environment
//!
//! # Example
//!
//! ```rust,ignore
//! #![no_std]
//! #![no_main]
//!
//! use zp1_zkvm::prelude::*;
//!
//! #[no_mangle]
//! fn main() {
//!     // Read inputs from host
//!     let a: u32 = read();
//!     let b: u32 = read();
//!     
//!     // Compute using syscall
//!     let data = [a.to_le_bytes(), b.to_le_bytes()].concat();
//!     let hash = keccak256(&data);
//!     
//!     // Commit output
//!     commit(&hash);
//! }
//!
//! zp1_zkvm::entry!(main);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod io;
pub mod syscalls;
pub mod prelude;

// Re-export main items
pub use io::{read, commit, hint, commit_slice, hint_slice};

// Conditionally export riscv32-only functions
#[cfg(target_arch = "riscv32")]
pub use io::{read_slice, peek_input_size};

pub use syscalls::*;

/// Entry point macro for guest programs
///
/// This macro sets up the necessary entry point for a guest program.
/// Use it to wrap your main function:
///
/// ```rust,ignore
/// zp1_zkvm::entry!(main);
/// ```
#[macro_export]
macro_rules! entry {
    ($main:expr) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            $main();
            
            // Exit with code 0
            unsafe {
                core::arch::asm!(
                    "li a7, 0x00",  // HALT syscall
                    "li a0, 0",      // exit code 0
                    "ecall",
                    options(noreturn)
                );
            }
        }
        
        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo) -> ! {
            // Exit with code 1 on panic
            unsafe {
                core::arch::asm!(
                    "li a7, 0x00",  // HALT syscall
                    "li a0, 1",      // exit code 1
                    "ecall",
                    options(noreturn)
                );
            }
        }
    };
}
