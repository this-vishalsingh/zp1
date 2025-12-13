//! Syscall wrappers for cryptographic precompiles
//!
//! These functions invoke hardware-accelerated cryptographic operations
//! that are delegated to specialized circuits for efficient proving.

/// Compute Keccak-256 hash
///
/// # Arguments
/// * `data` - Input data to hash
///
/// # Returns
/// 32-byte hash digest
///
/// # Example
/// ```rust,ignore
/// let hash = keccak256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let output = [0u8; 32];

    #[cfg(target_arch = "riscv32")]
    {
        unsafe {
            core::arch::asm!(
                "li a7, 0x1000",  // KECCAK256 syscall (CPU implementation)
                "mv a0, {data_ptr}",
                "mv a1, {data_len}",
                "mv a2, {output_ptr}",
                "ecall",
                data_ptr = in(reg) data.as_ptr(),
                data_len = in(reg) data.len(),
                output_ptr = in(reg) output.as_mut_ptr(),
                out("a0") _,  // clobber return value
            );
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        // For testing outside zkVM, use the actual implementation
        #[cfg(feature = "testing")]
        {
            use tiny_keccak::{Hasher, Keccak};
            let mut hasher = Keccak::v256();
            hasher.update(data);
            hasher.finalize(&mut output);
        }
    }

    output
}

/// Compute SHA-256 hash
///
/// # Arguments
/// * `data` - Input data to hash
///
/// # Returns
/// 32-byte hash digest
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let output = [0u8; 32];

    #[cfg(target_arch = "riscv32")]
    {
        unsafe {
            core::arch::asm!(
                "li a7, 0x1002",  // SHA256 syscall (CPU implementation)
                "mv a0, {data_ptr}",
                "mv a1, {data_len}",
                "mv a2, {output_ptr}",
                "ecall",
                data_ptr = in(reg) data.as_ptr(),
                data_len = in(reg) data.len(),
                output_ptr = in(reg) output.as_mut_ptr(),
                out("a0") _,
            );
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        // For testing outside zkVM
        #[cfg(feature = "testing")]
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            output.copy_from_slice(&hasher.finalize());
        }
    }

    output
}

/// Recover Ethereum address from signature (ECRECOVER)
///
/// # Arguments
/// * `hash` - 32-byte message hash
/// * `v` - Recovery ID (27 or 28)
/// * `r` - 32-byte r component of signature
/// * `s` - 32-byte s component of signature
///
/// # Returns
/// * `Some(address)` - 20-byte Ethereum address if signature is valid
/// * `None` - If signature is invalid
pub fn ecrecover(hash: &[u8; 32], v: u8, r: &[u8; 32], s: &[u8; 32]) -> Option<[u8; 20]> {
    let address = [0u8; 20];

    #[cfg(target_arch = "riscv32")]
    {
        let result: u32;
        unsafe {
            core::arch::asm!(
                "li a7, 0x1001",  // ECRECOVER syscall (CPU implementation)
                "mv a0, {hash_ptr}",
                "mv a1, {v}",
                "mv a2, {r_ptr}",
                "mv a3, {s_ptr}",
                "mv a4, {addr_ptr}",
                "ecall",
                "mv {result}, a0",
                hash_ptr = in(reg) hash.as_ptr(),
                v = in(reg) v as u32,
                r_ptr = in(reg) r.as_ptr(),
                s_ptr = in(reg) s.as_ptr(),
                addr_ptr = in(reg) address.as_ptr(),
                result = out(reg) result,
            );
        }

        if result == 0 {
            Some(address)
        } else {
            None
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        // Silence unused warnings
        let _ = (hash, v, r, s);
        // For testing, return None (requires secp256k1 implementation)
        None
    }
}

/// Compute RIPEMD-160 hash
///
/// Used in Bitcoin address generation.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let output = [0u8; 20];

    #[cfg(target_arch = "riscv32")]
    {
        unsafe {
            core::arch::asm!(
                "li a7, 0x1003",  // RIPEMD160 syscall (CPU implementation)
                "mv a0, {data_ptr}",
                "mv a1, {data_len}",
                "mv a2, {output_ptr}",
                "ecall",
                data_ptr = in(reg) data.as_ptr(),
                data_len = in(reg) data.len(),
                output_ptr = in(reg) output.as_mut_ptr(),
                out("a0") _,
            );
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        // Placeholder for testing
        #[cfg(feature = "testing")]
        {
            use ripemd160::{Digest, Ripemd160};
            let mut hasher = Ripemd160::new();
            hasher.update(data);
            output.copy_from_slice(&hasher.finalize());
        }
    }

    output
}

/// Compute Blake2b hash (64-byte output)
pub fn blake2b(data: &[u8]) -> [u8; 64] {
    let output = [0u8; 64];

    #[cfg(target_arch = "riscv32")]
    {
        unsafe {
            core::arch::asm!(
                "li a7, 0x1005",  // BLAKE2B syscall (CPU implementation)
                "mv a0, {data_ptr}",
                "mv a1, {data_len}",
                "mv a2, {output_ptr}",
                "ecall",
                data_ptr = in(reg) data.as_ptr(),
                data_len = in(reg) data.len(),
                output_ptr = in(reg) output.as_mut_ptr(),
                out("a0") _,
            );
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        #[cfg(feature = "testing")]
        {
            use blake2::{Blake2b512, Digest};
            let mut hasher = Blake2b512::new();
            hasher.update(data);
            output.copy_from_slice(&hasher.finalize());
        }
    }

    output
}

/// Modular exponentiation (for Ethereum MODEXP precompile)
///
/// Computes base^exponent mod modulus
pub fn modexp(base: &[u8; 32], exponent: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    let result = [0u8; 32];

    #[cfg(target_arch = "riscv32")]
    {
        unsafe {
            core::arch::asm!(
                "li a7, 0x1004",  // MODEXP syscall (CPU implementation)
                "mv a0, {base_ptr}",
                "mv a1, {exp_ptr}",
                "mv a2, {mod_ptr}",
                "mv a3, {result_ptr}",
                "ecall",
                base_ptr = in(reg) base.as_ptr(),
                exp_ptr = in(reg) exponent.as_ptr(),
                mod_ptr = in(reg) modulus.as_ptr(),
                result_ptr = in(reg) result.as_mut_ptr(),
                out("a0") _,
            );
        }
    }

    #[cfg(not(target_arch = "riscv32"))]
    {
        #[cfg(feature = "testing")]
        {
            use num_bigint::BigUint;
            let b = BigUint::from_bytes_be(base);
            let e = BigUint::from_bytes_be(exponent);
            let m = BigUint::from_bytes_be(modulus);
            let res = b.modpow(&e, &m);
            let bytes = res.to_bytes_be();
            if bytes.len() <= 32 {
                result[32 - bytes.len()..].copy_from_slice(&bytes);
            }
        }
    }

    result
}
