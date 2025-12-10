//! Waldo Search Proof (Image Sub-grid)
//!
//! Demonstrates proving that a specific small image pattern (Waldo)
//! exists within a larger image grid, without revealing *where* he is.
//!
//! Image is represented as a 2D byte array (grayscale).

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const GRID_SIZE: usize = 10;
const PATTERN_SIZE: usize = 3;

/// Search for pattern in grid
fn find_pattern(grid: &[[u8; GRID_SIZE]; GRID_SIZE], pattern: &[[u8; PATTERN_SIZE]; PATTERN_SIZE]) -> bool {
    // Simple sliding window search
    for r in 0..=(GRID_SIZE - PATTERN_SIZE) {
        for c in 0..=(GRID_SIZE - PATTERN_SIZE) {
            let mut match_found = true;
            for pr in 0..PATTERN_SIZE {
                for pc in 0..PATTERN_SIZE {
                    if grid[r + pr][c + pc] != pattern[pr][pc] {
                        match_found = false;
                        break;
                    }
                }
                if !match_found { break; }
            }
            if match_found {
                return true; // Found it!
            }
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Public: The large "Where's Waldo" image (simplified 10x10)
    let mut grid = [[0u8; GRID_SIZE]; GRID_SIZE];
    
    // Private: Waldo's face pattern (3x3)
    let waldo_pattern = [
        [1, 2, 1],
        [3, 4, 3],
        [1, 2, 1],
    ];
    
    // Hide Waldo at position (5, 5)
    for r in 0..PATTERN_SIZE {
        for c in 0..PATTERN_SIZE {
            grid[5 + r][5 + c] = waldo_pattern[r][c];
        }
    }
    
    // Verify Waldo exists in the image
    let found = find_pattern(&grid, &waldo_pattern);
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if found { 1 } else { 0 });
    }
    
    loop {}
}
