//! Commonly used imports for guest programs

pub use crate::io::{read, commit, hint, print, commit_slice, hint_slice};

// Export riscv32-only functions when on that target
#[cfg(target_arch = "riscv32")]
pub use crate::io::{read_slice, peek_input_size};

pub use crate::syscalls::{
    keccak256, sha256, ecrecover, ripemd160, blake2b, modexp
};
