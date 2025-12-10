#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// SHA-256 syscall number (matches CPU implementation)
const SHA256: u32 = 0x1002;

/// Syscall to compute SHA-256
#[inline(always)]
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SHA256,
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
    // Test vector: "abc"
    let input = b"abc";
    
    // Compute SHA-256 using delegated precompile
    let hash = sha256(input);
    
    // Expected: 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    
    // Store first 4 words of hash for verification
    unsafe {
        let hash_ptr = hash.as_ptr() as *const u32;
        for i in 0..4 {
            let word = core::ptr::read(hash_ptr.add(i));
            core::ptr::write_volatile((0x80000000 + i * 4) as *mut u32, word);
        }
    }
    
    // Demonstrate hashing longer message
    let long_message = b"The quick brown fox jumps over the lazy dog";
    let hash2 = sha256(long_message);
    
    // Store second hash
    unsafe {
        let hash_ptr = hash2.as_ptr() as *const u32;
        for i in 0..4 {
            let word = core::ptr::read(hash_ptr.add(i));
            core::ptr::write_volatile((0x80000010 + i * 4) as *mut u32, word);
        }
    }
    
    loop {}
}
