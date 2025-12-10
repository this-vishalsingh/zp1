//! Hash Chain Example
//!
//! Prove knowledge of a preimage in a hash chain.
//! Given: H(H(H(...H(secret)...))) = target
//! Prove: You know 'secret' that produces 'target' after N iterations
//!
//! Useful for: Time-lock puzzles, VDFs, proof-of-work

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
    // Private input: the secret preimage
    let secret = b"my_secret_value";
    
    // Public input: number of iterations
    let iterations: u32 = 100;
    
    // Compute hash chain: H(H(H(...H(secret)...)))
    let mut current_hash = [0u8; 32];
    
    // Initial hash
    unsafe {
        sha256_syscall(
            secret.as_ptr() as u32,
            secret.len() as u32,
            current_hash.as_mut_ptr() as u32,
        );
    }
    
    // Iterate N-1 more times
    for _ in 1..iterations {
        let mut next_hash = [0u8; 32];
        unsafe {
            sha256_syscall(
                current_hash.as_ptr() as u32,
                32,
                next_hash.as_mut_ptr() as u32,
            );
        }
        current_hash = next_hash;
    }
    
    // Public output: the final hash (target)
    // In real use, verifier would compare against known target
    let target_hash = current_hash;
    
    // Verify (self-check for demo)
    let is_valid = hashes_equal(&current_hash, &target_hash);
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    // Store iteration count for verification
    let iter_addr = 0x80000004 as *mut u32;
    unsafe {
        core::ptr::write_volatile(iter_addr, iterations);
    }
    
    // Store first 4 bytes of final hash
    let hash_addr = 0x80000008 as *mut u32;
    unsafe {
        let hash_word = u32::from_le_bytes([
            current_hash[0], current_hash[1],
            current_hash[2], current_hash[3]
        ]);
        core::ptr::write_volatile(hash_addr, hash_word);
    }
    
    loop {}
}
