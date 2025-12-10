#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Keccak-256 syscall number (matches CPU implementation)
const KECCAK256: u32 = 0x1000;

/// Syscall to compute Keccak-256
/// a0 = syscall number (0x10)
/// a1 = input pointer
/// a2 = input length
/// a3 = output pointer (32 bytes)
#[inline(always)]
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") KECCAK256,
            in("a0") input.as_ptr(),
            in("a1") input.len(),
            in("a2") output.as_mut_ptr(),
            options(nostack)
        );
    }
    output
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Test vector: "hello world"
    let input = b"hello world";
    
    // Compute Keccak-256 using delegated precompile
    let hash = keccak256(input);
    
    // Expected: 0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
    
    // Store first word of hash at 0x80000000 for verification
    unsafe {
        let hash_ptr = hash.as_ptr() as *const u32;
        let first_word = core::ptr::read(hash_ptr);
        core::ptr::write_volatile(0x80000000 as *mut u32, first_word);
    }
    
    // Demonstrate multiple hashes
    let input2 = b"zkVM proving";
    let hash2 = keccak256(input2);
    
    // Store second hash first word at 0x80000004
    unsafe {
        let hash_ptr = hash2.as_ptr() as *const u32;
        let first_word = core::ptr::read(hash_ptr);
        core::ptr::write_volatile(0x80000004 as *mut u32, first_word);
    }
    
    loop {}
}
