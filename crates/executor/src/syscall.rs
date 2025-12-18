//! Syscall definitions for guest programs.
//!
//! This module defines the syscall interface that guest programs use to invoke
//! special operations like I/O, precompiles, and system functions.
//!
//! # Standard Syscalls
//!
//! Guest programs invoke syscalls using the ECALL instruction with:
//! - `a7` (x17): Syscall code
//! - `a0-a6` (x10-x16): Arguments
//! - Return value in `a0` (x10)
//!
//! # Example
//!
//! ```rust,ignore
//! // Compute Keccak256 hash (syscall 0x10)
//! let syscall_code = 0x10; // KECCAK256
//! let data_ptr = 0x1000;
//! let data_len = 64;
//! let output_ptr = 0x2000;
//!
//! // Set up registers
//! regs[17] = syscall_code;  // a7
//! regs[10] = data_ptr;      // a0
//! regs[11] = data_len;      // a1
//! regs[12] = output_ptr;    // a2
//!
//! // Execute ECALL
//! // CPU will call appropriate handler
//! ```

/// Syscall codes for guest program invocations.
///
/// These codes are placed in register a7 (x17) before executing ECALL.
/// Compatible with SP1 syscall numbering where applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SyscallCode {
    // === I/O Syscalls ===
    /// Halt execution (normal program exit)
    /// - a0: exit code
    HALT = 0x00,

    /// Write data to host output
    /// - a0: file descriptor (1=stdout, 2=stderr)
    /// - a1: pointer to data
    /// - a2: length in bytes
    /// Returns: bytes written in a0
    WRITE = 0x01,

    /// Read data from host input
    /// - a0: pointer to input buffer
    /// - a1: maximum bytes to read
    /// Returns: bytes read in a0
    READ = 0x02,

    /// Commit value to public outputs (journal)
    /// - a0: pointer to data
    /// - a1: length in bytes
    COMMIT = 0x03,

    /// Hint data to prover (not verified, for optimization)
    /// - a0: pointer to hint data
    /// - a1: length in bytes
    HINT = 0x04,

    // === Cryptographic Hash Functions ===
    /// Keccak-256 hash
    /// - a0: input pointer
    /// - a1: input length
    /// - a2: output pointer (32 bytes)
    /// Returns: 0 on success
    KECCAK256 = 0x10,

    /// SHA-256 hash
    /// - a0: input pointer
    /// - a1: input length
    /// - a2: output pointer (32 bytes)
    /// Returns: 0 on success
    SHA256 = 0x11,

    /// RIPEMD-160 hash
    /// - a0: input pointer
    /// - a1: input length
    /// - a2: output pointer (20 bytes)
    /// Returns: 0 on success
    RIPEMD160 = 0x12,

    /// Blake2b hash (64-byte output)
    /// - a0: input pointer
    /// - a1: input length
    /// - a2: output pointer (64 bytes)
    /// Returns: 0 on success
    BLAKE2B = 0x13,

    /// Blake3 hash (32-byte output)
    /// - a0: input pointer
    /// - a1: input length
    /// - a2: output pointer (32 bytes)
    /// Returns: 0 on success
    BLAKE3 = 0x14,

    // === Ethereum Precompiles ===
    /// ECRECOVER signature recovery
    /// - a0: message hash pointer (32 bytes)
    /// - a1: v value (recovery id)
    /// - a2: r pointer (32 bytes)
    /// - a3: s pointer (32 bytes)
    /// - a4: output pointer (20 bytes - address)
    /// Returns: 0 on success, 1 on invalid signature
    ECRECOVER = 0x20,

    /// Modular exponentiation (for RSA, Ethereum MODEXP precompile)
    /// - a0: base pointer (32 bytes)
    /// - a1: exponent pointer (32 bytes)
    /// - a2: modulus pointer (32 bytes)
    /// - a3: result pointer (32 bytes)
    /// Returns: 0 on success
    MODEXP = 0x21,

    // === Elliptic Curve Operations ===
    /// BN254 G1 point addition
    /// - a0: point A pointer (64 bytes: x, y)
    /// - a1: point B pointer (64 bytes: x, y)
    /// - a2: result pointer (64 bytes: x, y)
    /// Returns: 0 on success
    BN254_G1_ADD = 0x30,

    /// BN254 G1 scalar multiplication
    /// - a0: point pointer (64 bytes: x, y)
    /// - a1: scalar pointer (32 bytes)
    /// - a2: result pointer (64 bytes: x, y)
    /// Returns: 0 on success
    BN254_G1_MUL = 0x31,

    /// BN254 pairing check
    /// - a0: G1 points array pointer
    /// - a1: G2 points array pointer
    /// - a2: number of pairs
    /// Returns: 1 if pairing equals 1, 0 otherwise
    BN254_PAIRING = 0x32,

    /// BLS12-381 G1 point addition
    /// - a0: point A pointer (96 bytes: x, y)
    /// - a1: point B pointer (96 bytes: x, y)
    /// - a2: result pointer (96 bytes: x, y)
    /// Returns: 0 on success
    BLS12381_G1_ADD = 0x40,

    /// BLS12-381 aggregate signatures
    /// - a0: signatures array pointer
    /// - a1: number of signatures
    /// - a2: result pointer
    /// Returns: 0 on success
    BLS12381_AGGREGATE = 0x41,

    // === Ed25519 Signatures ===
    /// Ed25519 signature verification
    /// - a0: message pointer
    /// - a1: message length
    /// - a2: signature pointer (64 bytes)
    /// - a3: public key pointer (32 bytes)
    /// Returns: 1 if valid, 0 if invalid
    ED25519_VERIFY = 0x50,

    // === Legacy Compatibility ===
    /// Linux exit syscall (for compatibility with standard RISC-V programs)
    /// - a0: exit code
    EXIT = 93,
}

impl SyscallCode {
    /// Convert from raw u32 syscall code
    pub fn from_u32(code: u32) -> Option<Self> {
        match code {
            0x00 => Some(Self::HALT),
            0x01 => Some(Self::WRITE),
            0x02 => Some(Self::READ),
            0x03 => Some(Self::COMMIT),
            0x04 => Some(Self::HINT),
            0x10 => Some(Self::KECCAK256),
            0x11 => Some(Self::SHA256),
            0x12 => Some(Self::RIPEMD160),
            0x13 => Some(Self::BLAKE2B),
            0x14 => Some(Self::BLAKE3),
            0x20 => Some(Self::ECRECOVER),
            0x21 => Some(Self::MODEXP),
            0x30 => Some(Self::BN254_G1_ADD),
            0x31 => Some(Self::BN254_G1_MUL),
            0x32 => Some(Self::BN254_PAIRING),
            0x40 => Some(Self::BLS12381_G1_ADD),
            0x41 => Some(Self::BLS12381_AGGREGATE),
            0x50 => Some(Self::ED25519_VERIFY),
            93 => Some(Self::EXIT),
            _ => None,
        }
    }

    /// Get the syscall code as u32
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// Get the name of the syscall
    pub fn name(self) -> &'static str {
        match self {
            Self::HALT => "HALT",
            Self::WRITE => "WRITE",
            Self::READ => "READ",
            Self::COMMIT => "COMMIT",
            Self::HINT => "HINT",
            Self::KECCAK256 => "KECCAK256",
            Self::SHA256 => "SHA256",
            Self::RIPEMD160 => "RIPEMD160",
            Self::BLAKE2B => "BLAKE2B",
            Self::BLAKE3 => "BLAKE3",
            Self::ECRECOVER => "ECRECOVER",
            Self::MODEXP => "MODEXP",
            Self::BN254_G1_ADD => "BN254_G1_ADD",
            Self::BN254_G1_MUL => "BN254_G1_MUL",
            Self::BN254_PAIRING => "BN254_PAIRING",
            Self::BLS12381_G1_ADD => "BLS12381_G1_ADD",
            Self::BLS12381_AGGREGATE => "BLS12381_AGGREGATE",
            Self::ED25519_VERIFY => "ED25519_VERIFY",
            Self::EXIT => "EXIT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_roundtrip() {
        let codes = [
            SyscallCode::HALT,
            SyscallCode::WRITE,
            SyscallCode::KECCAK256,
            SyscallCode::ECRECOVER,
            SyscallCode::BN254_PAIRING,
            SyscallCode::EXIT,
        ];

        for code in codes.iter() {
            let raw = code.as_u32();
            let parsed = SyscallCode::from_u32(raw);
            assert_eq!(Some(*code), parsed);
        }
    }

    #[test]
    fn test_unknown_syscall() {
        assert_eq!(None, SyscallCode::from_u32(0xFFFF));
    }

    #[test]
    fn test_syscall_names() {
        assert_eq!(SyscallCode::KECCAK256.name(), "KECCAK256");
        assert_eq!(SyscallCode::ECRECOVER.name(), "ECRECOVER");
        assert_eq!(SyscallCode::HALT.name(), "HALT");
    }
}
