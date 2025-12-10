//! Wordle ZK Proof Example
//!
//! Demonstrates proving knowledge of a valid Wordle solution
//! given a guess and a pattern, without revealing the solution.
//!
//! Input: Guess (Public), Solution (Private)
//! Output: Pattern (Public)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Color {
    Green,  // Correct letter, correct position
    Yellow, // Correct letter, wrong position
    Gray,   // Letter not in word
}

/// Compute Wordle pattern for a guess against a secret solution
fn compute_pattern(guess: &[u8; 5], solution: &[u8; 5]) -> [Color; 5] {
    let mut pattern = [Color::Gray; 5];
    let mut solution_chars_count = [0u8; 26];
    
    // Count frequencies in solution
    for &c in solution.iter() {
        if c >= b'a' && c <= b'z' {
            solution_chars_count[(c - b'a') as usize] += 1;
        }
    }
    
    // First pass: Find Greens
    for i in 0..5 {
        if guess[i] == solution[i] {
            pattern[i] = Color::Green;
            if guess[i] >= b'a' && guess[i] <= b'z' {
                solution_chars_count[(guess[i] - b'a') as usize] -= 1;
            }
        }
    }
    
    // Second pass: Find Yellows
    for i in 0..5 {
        if pattern[i] == Color::Gray {
            if guess[i] >= b'a' && guess[i] <= b'z' {
                let idx = (guess[i] - b'a') as usize;
                if solution_chars_count[idx] > 0 {
                    pattern[i] = Color::Yellow;
                    solution_chars_count[idx] -= 1;
                }
            }
        }
    }
    
    pattern
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Public Input: Guess
    let guess = b"crane";
    
    // Private Input: Secret Solution (not revealed)
    let secret_solution = b"cache";
    
    // Expected Public Output: Pattern
    // c -> Green (first c)
    // r -> Gray
    // a -> Yellow (in solution but different pos)
    // n -> Gray
    // e -> Green
    let expected_pattern = [
        Color::Green, 
        Color::Gray, 
        Color::Yellow, 
        Color::Gray, 
        Color::Green
    ];
    
    // Compute actual pattern inside zkVM
    let computed_pattern = compute_pattern(guess, secret_solution);
    
    // Verify it matches expected public output
    let mut is_valid = true;
    for i in 0..5 {
        if computed_pattern[i] != expected_pattern[i] {
            is_valid = false;
            break;
        }
    }
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    loop {}
}
