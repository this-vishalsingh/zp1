//! Test programs for the RISC-V prover.

use crate::encode;

/// Build a simple counting program.
///
/// This program counts from 0 to 4 in register x1:
/// ```asm
/// addi x1, x0, 0      # x1 = 0
/// addi x2, x0, 5      # x2 = 5 (loop limit)
/// loop:
///     addi x1, x1, 1  # x1 += 1
///     bne x1, x2, loop  # if x1 != 5, loop
/// ecall               # halt
/// ```
pub fn counting_program() -> Vec<u32> {
    vec![
        encode::addi(1, 0, 0), // x1 = 0
        encode::addi(2, 0, 5), // x2 = 5
        encode::addi(1, 1, 1), // x1 += 1 (loop body)
        encode::bne(1, 2, -4), // if x1 != x2, jump back 4 bytes
        encode::ecall(),       // halt
    ]
}

/// Build a Fibonacci-like program.
///
/// Computes fib(n) where n is small:
/// ```asm
/// addi x1, x0, 0      # x1 = fib(0) = 0
/// addi x2, x0, 1      # x2 = fib(1) = 1
/// addi x3, x0, 6      # x3 = iterations
/// loop:
///     add x4, x1, x2  # x4 = x1 + x2
///     add x1, x2, x0  # x1 = x2
///     add x2, x4, x0  # x2 = x4
///     addi x3, x3, -1 # x3 -= 1
///     bne x3, x0, loop
/// ecall
/// ```
pub fn fibonacci_program() -> Vec<u32> {
    vec![
        encode::addi(1, 0, 0),  // x1 = 0 (fib_prev)
        encode::addi(2, 0, 1),  // x2 = 1 (fib_curr)
        encode::addi(3, 0, 6),  // x3 = 6 iterations
        encode::add(4, 1, 2),   // x4 = x1 + x2
        encode::add(1, 2, 0),   // x1 = x2 (shift)
        encode::add(2, 4, 0),   // x2 = x4 (shift)
        encode::addi(3, 3, -1), // x3 -= 1
        encode::bne(3, 0, -16), // if x3 != 0, loop back 16 bytes
        encode::ecall(),        // halt
    ]
}

/// Simple arithmetic program.
pub fn arithmetic_program() -> Vec<u32> {
    vec![
        encode::addi(1, 0, 10), // x1 = 10
        encode::addi(2, 0, 20), // x2 = 20
        encode::add(3, 1, 2),   // x3 = x1 + x2 = 30
        encode::sub(4, 2, 1),   // x4 = x2 - x1 = 10
        encode::ecall(),        // halt
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counting_program_structure() {
        let prog = counting_program();
        assert_eq!(prog.len(), 5);
        // Last instruction is ecall
        assert_eq!(prog[4] & 0x7F, 0b1110011);
    }

    #[test]
    fn test_fibonacci_program_structure() {
        let prog = fibonacci_program();
        assert_eq!(prog.len(), 9);
    }

    #[test]
    fn test_arithmetic_program_structure() {
        let prog = arithmetic_program();
        assert_eq!(prog.len(), 5);
    }
}
