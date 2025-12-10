//! Regex Match Example
//!
//! Prove a string matches a pattern without revealing the string.
//! Implements simplified regex for email format: *@*.* 
//!
//! This demonstrates private data validation.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Check if byte is alphanumeric or allowed char
fn is_local_char(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || 
    (c >= b'A' && c <= b'Z') || 
    (c >= b'0' && c <= b'9') ||
    c == b'.' || c == b'_' || c == b'-'
}

/// Check if byte is alphanumeric
fn is_domain_char(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || 
    (c >= b'A' && c <= b'Z') || 
    (c >= b'0' && c <= b'9') ||
    c == b'-'
}

/// Simplified email regex: local@domain.tld
fn matches_email_pattern(input: &[u8]) -> bool {
    // Find @ position
    let mut at_pos = None;
    for i in 0..input.len() {
        if input[i] == b'@' {
            at_pos = Some(i);
            break;
        }
    }
    
    let at_idx = match at_pos {
        Some(idx) => idx,
        None => return false,
    };
    
    // Local part must have at least 1 char
    if at_idx == 0 {
        return false;
    }
    
    // Validate local part
    for i in 0..at_idx {
        if !is_local_char(input[i]) {
            return false;
        }
    }
    
    // Find . in domain part
    let domain_part = &input[at_idx + 1..];
    let mut dot_pos = None;
    for i in 0..domain_part.len() {
        if domain_part[i] == b'.' {
            dot_pos = Some(i);
            // Take the last dot
        }
    }
    
    let dot_idx = match dot_pos {
        Some(idx) => idx,
        None => return false,
    };
    
    // Domain must have at least 1 char before dot
    if dot_idx == 0 {
        return false;
    }
    
    // TLD must have at least 2 chars
    if domain_part.len() - dot_idx - 1 < 2 {
        return false;
    }
    
    // Validate domain part before dot
    for i in 0..dot_idx {
        if !is_domain_char(domain_part[i]) && domain_part[i] != b'.' {
            return false;
        }
    }
    
    // Validate TLD
    for i in (dot_idx + 1)..domain_part.len() {
        if !(domain_part[i] >= b'a' && domain_part[i] <= b'z') &&
           !(domain_part[i] >= b'A' && domain_part[i] <= b'Z') {
            return false;
        }
    }
    
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Private input: email address
    let secret_email = b"user@example.com";
    
    // Check if it matches email pattern
    let is_valid = matches_email_pattern(secret_email);
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    loop {}
}
