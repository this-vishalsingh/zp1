//! RSA Verification Example
//!
//! Demonstrates RSA signature verification using the MODEXP syscall.
//!
//! Syscall: 0x1004 (MODEXP)
//!
//! In RSA, signature verification is:
//! s^e mod n == hash(message) (with padding)
//!
//! For simplicity, this example just checks:
//! base^exp mod modulus == result

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// MODEXP syscall number (matches CPU implementation)
const MODEXP: u32 = 0x1004;

/// Syscall to compute (base^exp) % mod
/// All inputs must be 32 bytes (256 bits) for this specific syscall wrapper
/// Real RSA uses much larger numbers (2048+ bits), so in a real scenario
/// you would use a BigInt library that calls this syscall for limb operations
/// or use a dedicated large-integer precompile if available.
///
/// NOTE: The current ZP1 MODEXP syscall (0x1004) operates on 256-bit (32-byte) inputs.
/// This is sufficient for demonstrating the mechanism, but for real RSA-2048,
/// you would need to implement multi-precision arithmetic on top of this
/// or use a precompile that supports larger operand sizes.
#[inline(always)]
unsafe fn modexp_syscall(
    base_ptr: u32,
    exp_ptr: u32,
    mod_ptr: u32,
    res_ptr: u32
) {
    core::arch::asm!(
        "mv a0, {base_ptr}",
        "mv a1, {exp_ptr}",
        "mv a2, {mod_ptr}",
        "mv a3, {res_ptr}",
        "li a7, {syscall}",
        "ecall",
        base_ptr = in(reg) base_ptr,
        exp_ptr = in(reg) exp_ptr,
        mod_ptr = in(reg) mod_ptr,
        res_ptr = in(reg) res_ptr,
        syscall = const MODEXP,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a3") _,
        out("a7") _,
    );
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Example: 3^5 mod 13 = 243 mod 13 = 9
    // We'll use 32-byte representations
    
    let mut base = [0u8; 32];
    base[0] = 3;
    
    let mut exp = [0u8; 32];
    exp[0] = 5;
    
    let mut modulus = [0u8; 32];
    modulus[0] = 13;
    
    let mut result = [0u8; 32];
    
    unsafe {
        modexp_syscall(
            base.as_ptr() as u32,
            exp.as_ptr() as u32,
            modulus.as_ptr() as u32,
            result.as_mut_ptr() as u32,
        );
    }
    
    // Check if result is 9
    let is_valid = result[0] == 9;
    
    // Store result: 1 = valid, 0 = invalid
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    // Store actual result for verification
    let res_addr = 0x80000004 as *mut u32;
    unsafe {
        let res_word = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        core::ptr::write_volatile(res_addr, res_word);
    }
    
    loop {}
}
