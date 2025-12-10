//! JSON Parser Example
//!
//! Demonstrates proving JSON field extraction.
//! Inspired by RISC Zero's JSON example.
//!
//! Use case: Prove you know some field in a JSON document
//! without revealing the rest of the document.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Simple JSON field extractor (minimal no_std implementation)
/// Returns the value for a given key, or None if not found.
fn extract_json_field<'a>(json: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    // Search for the key pattern: "key":
    let mut i = 0;
    while i + key.len() + 3 < json.len() {
        // Look for opening quote
        if json[i] == b'"' {
            // Check if key matches
            let mut matches = true;
            for j in 0..key.len() {
                if i + 1 + j >= json.len() || json[i + 1 + j] != key[j] {
                    matches = false;
                    break;
                }
            }
            
            if matches && i + 1 + key.len() < json.len() {
                let end_quote = i + 1 + key.len();
                if json[end_quote] == b'"' && end_quote + 1 < json.len() && json[end_quote + 1] == b':' {
                    // Found key, now extract value
                    let value_start = end_quote + 2;
                    
                    // Skip whitespace
                    let mut vs = value_start;
                    while vs < json.len() && (json[vs] == b' ' || json[vs] == b'\n' || json[vs] == b'\t') {
                        vs += 1;
                    }
                    
                    if vs < json.len() {
                        // Handle string value
                        if json[vs] == b'"' {
                            let str_start = vs + 1;
                            let mut str_end = str_start;
                            while str_end < json.len() && json[str_end] != b'"' {
                                str_end += 1;
                            }
                            return Some(&json[str_start..str_end]);
                        }
                        // Handle number value
                        else if json[vs].is_ascii_digit() {
                            let num_start = vs;
                            let mut num_end = num_start;
                            while num_end < json.len() && (json[num_end].is_ascii_digit() || json[num_end] == b'.') {
                                num_end += 1;
                            }
                            return Some(&json[num_start..num_end]);
                        }
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Compare two byte slices
fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Sample JSON document (private data)
    let json = br#"{"name":"Alice","age":30,"secret":"zkvm-rocks"}"#;
    
    // Extract the "name" field
    let name_value = extract_json_field(json, b"name");
    
    // Verify the extracted value matches expected
    let expected = b"Alice";
    let result = match name_value {
        Some(value) => bytes_equal(value, expected),
        None => false,
    };
    
    // Store result: 1 = success, 0 = failure
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if result { 1 } else { 0 });
    }
    
    // Also store the length of extracted value
    let len_addr = 0x80000004 as *mut u32;
    unsafe {
        let len = name_value.map(|v| v.len()).unwrap_or(0) as u32;
        core::ptr::write_volatile(len_addr, len);
    }
    
    loop {}
}
