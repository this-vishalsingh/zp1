//! Age Proof Example
//!
//! Prove you are over a certain age without revealing your date of birth.
//!
//! Input: Birth Year (Private), Current Year (Public), Min Age (Public)
//! Output: Boolean (true if age >= min_age)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Public inputs
    let current_year: u32 = 2024;
    let min_age: u32 = 18;
    
    // Private input (date of birth - not revealed)
    let birth_year: u32 = 2000;
    
    // Compute age
    let age = current_year - birth_year;
    
    // Check if age meets requirement
    let is_old_enough = age >= min_age;
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_old_enough { 1 } else { 0 });
    }
    
    // Store min_age for verification (public)
    let min_age_addr = 0x80000004 as *mut u32;
    unsafe {
        core::ptr::write_volatile(min_age_addr, min_age);
    }
    
    loop {}
}
