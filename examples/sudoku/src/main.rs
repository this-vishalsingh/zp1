//! Sudoku ZK Proof Example
//!
//! Prove you know a valid Sudoku solution without revealing it.
//! 
//! Input: Puzzle (Public), Solution (Private)
//! Output: Boolean (valid/invalid)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Check if a 9x9 Sudoku solution is valid
fn is_valid_sudoku(grid: &[[u8; 9]; 9]) -> bool {
    // Check each row
    for row in 0..9 {
        if !is_valid_set(&grid[row]) {
            return false;
        }
    }
    
    // Check each column
    for col in 0..9 {
        let mut column = [0u8; 9];
        for row in 0..9 {
            column[row] = grid[row][col];
        }
        if !is_valid_set(&column) {
            return false;
        }
    }
    
    // Check each 3x3 box
    for box_row in 0..3 {
        for box_col in 0..3 {
            let mut box_vals = [0u8; 9];
            let mut idx = 0;
            for r in 0..3 {
                for c in 0..3 {
                    box_vals[idx] = grid[box_row * 3 + r][box_col * 3 + c];
                    idx += 1;
                }
            }
            if !is_valid_set(&box_vals) {
                return false;
            }
        }
    }
    
    true
}

/// Check if array contains exactly 1-9 (no duplicates)
fn is_valid_set(arr: &[u8; 9]) -> bool {
    let mut seen = [false; 10];
    for &val in arr {
        if val < 1 || val > 9 {
            return false;
        }
        if seen[val as usize] {
            return false;
        }
        seen[val as usize] = true;
    }
    true
}

/// Check that solution matches puzzle (puzzle has 0 for unknowns)
fn solution_matches_puzzle(puzzle: &[[u8; 9]; 9], solution: &[[u8; 9]; 9]) -> bool {
    for r in 0..9 {
        for c in 0..9 {
            if puzzle[r][c] != 0 && puzzle[r][c] != solution[r][c] {
                return false;
            }
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Public: The puzzle (0 = unknown)
    let puzzle: [[u8; 9]; 9] = [
        [5, 3, 0, 0, 7, 0, 0, 0, 0],
        [6, 0, 0, 1, 9, 5, 0, 0, 0],
        [0, 9, 8, 0, 0, 0, 0, 6, 0],
        [8, 0, 0, 0, 6, 0, 0, 0, 3],
        [4, 0, 0, 8, 0, 3, 0, 0, 1],
        [7, 0, 0, 0, 2, 0, 0, 0, 6],
        [0, 6, 0, 0, 0, 0, 2, 8, 0],
        [0, 0, 0, 4, 1, 9, 0, 0, 5],
        [0, 0, 0, 0, 8, 0, 0, 7, 9],
    ];
    
    // Private: The complete solution
    let solution: [[u8; 9]; 9] = [
        [5, 3, 4, 6, 7, 8, 9, 1, 2],
        [6, 7, 2, 1, 9, 5, 3, 4, 8],
        [1, 9, 8, 3, 4, 2, 5, 6, 7],
        [8, 5, 9, 7, 6, 1, 4, 2, 3],
        [4, 2, 6, 8, 5, 3, 7, 9, 1],
        [7, 1, 3, 9, 2, 4, 8, 5, 6],
        [9, 6, 1, 5, 3, 7, 2, 8, 4],
        [2, 8, 7, 4, 1, 9, 6, 3, 5],
        [3, 4, 5, 2, 8, 6, 1, 7, 9],
    ];
    
    // Verify solution
    let valid_sudoku = is_valid_sudoku(&solution);
    let matches_puzzle = solution_matches_puzzle(&puzzle, &solution);
    let is_valid = valid_sudoku && matches_puzzle;
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    loop {}
}
