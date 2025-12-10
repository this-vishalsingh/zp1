//! Blake2b Example - Zcash-compatible hashing
//!
//! Demonstrates the BLAKE2B-512 precompile syscall.
//! Blake2b is used by Zcash for transaction hashing.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Blake2b syscall number (matches CPU implementation)
const BLAKE2B: u32 = 0x1005;

/// Syscall to compute Blake2b-512 hash
/// a0 = message pointer
/// a1 = message length
/// a2 = output pointer (64 bytes)
#[inline(always)]
unsafe fn blake2b_syscall(msg_ptr: u32, msg_len: u32, out_ptr: u32) {
    core::arch::asm!(
        "mv a0, {msg_ptr}",
        "mv a1, {msg_len}",
        "mv a2, {out_ptr}",
        "li a7, {syscall}",
        "ecall",
        msg_ptr = in(reg) msg_ptr,
        msg_len = in(reg) msg_len,
        out_ptr = in(reg) out_ptr,
        syscall = const BLAKE2B,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a7") _,
    );
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Test message: "zcash" (Zcash-themed example)
    let message = b"zcash";
    
    // Output buffer for 64-byte Blake2b hash
    let mut hash: [u8; 64] = [0u8; 64];
    
    // Compute Blake2b hash
    unsafe {
        blake2b_syscall(
            message.as_ptr() as u32,
            message.len() as u32,
            hash.as_mut_ptr() as u32,
        );
    }
    
    // Store first 8 bytes of hash at output address for verification
    let output_addr = 0x80000000 as *mut u64;
    unsafe {
        let first_eight = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);
        core::ptr::write_volatile(output_addr, first_eight);
    }
    
    loop {}
}
