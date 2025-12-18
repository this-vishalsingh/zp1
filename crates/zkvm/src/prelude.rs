//! Commonly used imports for guest programs

pub use crate::io::{commit, commit_slice, hint, hint_slice, print, read};

// Export riscv32-only functions when on that target
#[cfg(target_arch = "riscv32")]
pub use crate::io::{peek_input_size, read_slice};

pub use crate::syscalls::{blake2b, ecrecover, keccak256, modexp, ripemd160, sha256};
