//! Range Proof Example
//!
//! Demonstrates proving a secret value lies within a public range [min, max].
//!
//! Input: Public Range (min, max), Private Value
//! Output: Boolean (true if in range)
//!
//! This is a building block for many ZK applications (e.g., age verification, credit score).

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Public Inputs (Range)
    // e.g., Minimum age 18, Maximum age 150
    let min_val: u32 = 18;
    let max_val: u32 = 150;
    
    // Private Input (Value)
    // e.g., User is 25 years old
    let secret_val: u32 = 25;
    
    // Logic: min <= val <= max
    let in_range = secret_val >= min_val && secret_val <= max_val;
    
    // Store result (1 for valid, 0 for invalid)
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if in_range { 1 } else { 0 });
    }
    
    // Store the range check bounds for verification (optional)
    let min_addr = 0x80000004 as *mut u32;
    let max_addr = 0x80000008 as *mut u32;
    unsafe {
        core::ptr::write_volatile(min_addr, min_val);
        core::ptr::write_volatile(max_addr, max_val);
    }
    
    loop {}
}
