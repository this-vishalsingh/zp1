//! Password Hash Example
//!
//! Demonstrates zero-knowledge password verification.
//! Prove you know the preimage of a hash without revealing it.
//!
//! Use case: Authenticate without exposing password

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// SHA256 syscall number (matches CPU implementation)
const SHA256: u32 = 0x1002;

/// Syscall to compute SHA-256 hash
#[inline(always)]
unsafe fn sha256_syscall(msg_ptr: u32, msg_len: u32, out_ptr: u32) {
    core::arch::asm!(
        "mv a0, {msg_ptr}",
        "mv a1, {msg_len}",
        "mv a2, {out_ptr}",
        "li a7, {syscall}",
        "ecall",
        msg_ptr = in(reg) msg_ptr,
        msg_len = in(reg) msg_len,
        out_ptr = in(reg) out_ptr,
        syscall = const SHA256,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a7") _,
    );
}

/// Compute SHA256 hash
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut result: [u8; 32] = [0u8; 32];
    unsafe {
        sha256_syscall(
            data.as_ptr() as u32,
            data.len() as u32,
            result.as_mut_ptr() as u32,
        );
    }
    result
}

/// Compare two hashes
fn hashes_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Secret password (private input - not revealed in proof)
    let secret_password = b"my_super_secret_password_123";
    
    // Expected hash (public input - this is what we verify against)
    // Pre-computed SHA256("my_super_secret_password_123")
    let expected_hash: [u8; 32] = [
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
        0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
        0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69,
    ];
    
    // Compute hash of secret password
    let computed_hash = sha256(secret_password);
    
    // Check if hashes match
    let is_valid = hashes_equal(&computed_hash, &expected_hash);
    
    // Store result: 1 = authenticated, 0 = failed
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    // Store first 4 bytes of computed hash for debugging
    let hash_addr = 0x80000004 as *mut u32;
    unsafe {
        let hash_word = u32::from_le_bytes([
            computed_hash[0], computed_hash[1], 
            computed_hash[2], computed_hash[3]
        ]);
        core::ptr::write_volatile(hash_addr, hash_word);
    }
    
    loop {}
}
