//! Commitment Scheme Example
//!
//! Demonstrates hash-based commitment: commit = H(value || blinding)
//! User can later reveal value and blinding to prove the commitment.
//!
//! Pattern used in: Pedersen commitments, sealed-bid auctions, coin flips
//!
//! Input: Value (Private), Blinding Factor (Private)
//! Output: Commitment Hash (Public)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const KECCAK256: u32 = 0x1000;

#[inline(always)]
unsafe fn keccak256_syscall(msg_ptr: u32, msg_len: u32, out_ptr: u32) {
    core::arch::asm!(
        "mv a0, {msg_ptr}",
        "mv a1, {msg_len}",
        "mv a2, {out_ptr}",
        "li a7, {syscall}",
        "ecall",
        msg_ptr = in(reg) msg_ptr,
        msg_len = in(reg) msg_len,
        out_ptr = in(reg) out_ptr,
        syscall = const KECCAK256,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a7") _,
    );
}

fn hashes_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Compute commitment = H(value || blinding)
fn compute_commitment(value: u32, blinding: &[u8; 32]) -> [u8; 32] {
    // Encode value as 4 bytes + 32 byte blinding = 36 bytes
    let mut input = [0u8; 36];
    input[..4].copy_from_slice(&value.to_le_bytes());
    input[4..].copy_from_slice(blinding);
    
    let mut commitment = [0u8; 32];
    unsafe {
        keccak256_syscall(
            input.as_ptr() as u32,
            36,
            commitment.as_mut_ptr() as u32,
        );
    }
    commitment
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Private inputs
    let secret_value: u32 = 42; // e.g., a bid amount
    let blinding: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    ];
    
    // Compute commitment (public)
    let commitment = compute_commitment(secret_value, &blinding);
    
    // In a real scenario, we'd verify:
    // 1. commitment matches a previously published value
    // 2. value satisfies some constraint (e.g., bid > min)
    
    // For demo: verify self-computed commitment matches
    let expected = compute_commitment(secret_value, &blinding);
    let is_valid = hashes_equal(&commitment, &expected);
    
    // Store result
    let out_valid = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(out_valid, if is_valid { 1 } else { 0 });
    }
    
    // Store first 4 bytes of commitment
    let out_commit = 0x80000004 as *mut u32;
    unsafe {
        let word = u32::from_le_bytes([commitment[0], commitment[1], commitment[2], commitment[3]]);
        core::ptr::write_volatile(out_commit, word);
    }
    
    loop {}
}
