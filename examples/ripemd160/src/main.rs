//! Bitcoin RIPEMD-160 Example
//!
//! Demonstrates Bitcoin address generation logic using RIPEMD-160.
//!
//! Bitcoin Address = RIPEMD160(SHA256(public_key))
//!
//! Syscalls:
//! - 0x1002 (SHA256)
//! - 0x1003 (RIPEMD160)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const SHA256: u32 = 0x1002;
const RIPEMD160: u32 = 0x1003;

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

#[inline(always)]
unsafe fn ripemd160_syscall(msg_ptr: u32, msg_len: u32, out_ptr: u32) {
    core::arch::asm!(
        "mv a0, {msg_ptr}",
        "mv a1, {msg_len}",
        "mv a2, {out_ptr}",
        "li a7, {syscall}",
        "ecall",
        msg_ptr = in(reg) msg_ptr,
        msg_len = in(reg) msg_len,
        out_ptr = in(reg) out_ptr,
        syscall = const RIPEMD160,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a7") _,
    );
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Example Public Key (compressed, 33 bytes)
    let pubkey = [
        0x03, 0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 
        0x40, 0x99, 0x5d, 0x3e, 0xd5, 0xa, 0xb0, 0x5d, 
        0x18, 0x1a, 0x8c, 0xc2, 0x78, 0x66, 0xa5, 0x19, 
        0x72, 0xe1, 0x06, 0x3e, 0x91, 0x3ca, 0x95, 0xd6, 0xeb
    ];

    // Step 1: SHA256(pubkey)
    let mut sha256_hash = [0u8; 32];
    unsafe {
        sha256_syscall(
            pubkey.as_ptr() as u32,
            pubkey.len() as u32,
            sha256_hash.as_mut_ptr() as u32,
        );
    }
    
    // Step 2: RIPEMD160(sha256_hash)
    let mut ripemd_hash = [0u8; 20]; // RIPEMD160 output is 20 bytes
    unsafe {
        ripemd160_syscall(
            sha256_hash.as_ptr() as u32,
            sha256_hash.len() as u32,
            ripemd_hash.as_mut_ptr() as u32,
        );
    }
    
    // Store result (first 4 bytes of RIPEMD160 hash)
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        let hash_word = u32::from_le_bytes([
            ripemd_hash[0], ripemd_hash[1], 
            ripemd_hash[2], ripemd_hash[3]
        ]);
        core::ptr::write_volatile(output_addr, hash_word);
    }
    
    loop {}
}
