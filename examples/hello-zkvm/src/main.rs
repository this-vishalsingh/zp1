//! Hello zkVM Example
//!
//! The simplest possible ZP1 guest program.
//! Demonstrates the basic structure for guest programs.
//!
//! This is the starting template for new developers.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Store "Hello, zkVM!" indicator at output address
    // 0x48656C6C = "Hell" in ASCII (little endian: "lleH")
    let hello_word: u32 = 0x6C6C6548; // "Hell" little-endian
    
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, hello_word);
    }
    
    // Store magic number to indicate success
    let magic_addr = 0x80000004 as *mut u32;
    unsafe {
        core::ptr::write_volatile(magic_addr, 0xDEADBEEF);
    }
    
    loop {}
}
