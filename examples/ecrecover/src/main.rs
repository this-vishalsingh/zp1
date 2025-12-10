#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// ECRECOVER syscall number (matches CPU implementation)
const ECRECOVER: u32 = 0x1001;

/// ECRECOVER signature recovery
/// Recovers Ethereum address from signature
#[inline(always)]
fn ecrecover(hash: &[u8; 32], v: u8, r: &[u8; 32], s: &[u8; 32]) -> [u8; 20] {
    let mut address = [0u8; 20];
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") ECRECOVER,
            in("a0") hash.as_ptr(),
            in("a1") v,
            in("a2") r.as_ptr(),
            in("a3") s.as_ptr(),
            in("a4") address.as_mut_ptr(),
            options(nostack)
        );
    }
    address
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Example transaction hash
    let hash = [
        0x47, 0x17, 0x32, 0x85, 0xa8, 0xd7, 0x34, 0x1e,
        0x5e, 0x97, 0x2f, 0xc6, 0x77, 0x28, 0x63, 0x84,
        0xf8, 0x02, 0xf8, 0xef, 0x42, 0xa5, 0xec, 0x5f,
        0x03, 0xbb, 0xfa, 0x25, 0x4c, 0xb0, 0x1f, 0xad,
    ];
    
    // Signature components (example values)
    let v = 28u8;
    let r = [
        0x9d, 0x4b, 0xaa, 0xa0, 0xc5, 0xd7, 0x63, 0x0c,
        0x5b, 0xcd, 0x01, 0x50, 0x2d, 0x50, 0x58, 0x2f,
        0x88, 0x2e, 0x33, 0x61, 0xf7, 0xa8, 0x18, 0x7d,
        0x44, 0x74, 0xa2, 0x10, 0x57, 0xe7, 0x99, 0x5a,
    ];
    let s = [
        0x7a, 0xeb, 0x50, 0x14, 0xd8, 0x03, 0x49, 0xe7,
        0xcd, 0xa4, 0x1e, 0x9c, 0x8e, 0x76, 0x45, 0x04,
        0x23, 0x81, 0x0e, 0x95, 0x3c, 0xd2, 0xcd, 0x4e,
        0x33, 0x68, 0xd5, 0xe9, 0xaa, 0xaa, 0xb1, 0x1b,
    ];
    
    // Recover address using delegated precompile
    let address = ecrecover(&hash, v, &r, &s);
    
    // Store recovered address at 0x80000000 (20 bytes)
    unsafe {
        let addr_ptr = address.as_ptr();
        for i in 0..5 {
            let word = core::ptr::read((addr_ptr as *const u32).add(i));
            core::ptr::write_volatile((0x80000000 + i * 4) as *mut u32, word);
        }
    }
    
    loop {}
}
