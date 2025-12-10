//! Nullifier Example
//!
//! Demonstrates double-spend prevention using nullifiers.
//! A nullifier is a unique hash derived from a secret that can only be used once.
//!
//! Pattern used in: Zcash, Tornado Cash, Semaphore
//!
//! Input: Secret (Private), Nonce (Private)
//! Output: Nullifier Hash (Public)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const SHA256: u32 = 0x1002;

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

/// Compute nullifier = H(secret || nonce)
fn compute_nullifier(secret: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    // Concatenate secret and nonce
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(secret);
    input[32..].copy_from_slice(nonce);
    
    let mut nullifier = [0u8; 32];
    unsafe {
        sha256_syscall(
            input.as_ptr() as u32,
            64,
            nullifier.as_mut_ptr() as u32,
        );
    }
    nullifier
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Private inputs (never revealed)
    let secret: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    
    let nonce: [u8; 32] = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    ];
    
    // Compute nullifier (public output)
    let nullifier = compute_nullifier(&secret, &nonce);
    
    // Store nullifier hash (first 8 bytes as 2 words)
    let out1 = 0x80000000 as *mut u32;
    let out2 = 0x80000004 as *mut u32;
    unsafe {
        let word1 = u32::from_le_bytes([nullifier[0], nullifier[1], nullifier[2], nullifier[3]]);
        let word2 = u32::from_le_bytes([nullifier[4], nullifier[5], nullifier[6], nullifier[7]]);
        core::ptr::write_volatile(out1, word1);
        core::ptr::write_volatile(out2, word2);
    }
    
    loop {}
}
