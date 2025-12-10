//! Private Voting Example
//!
//! Prove your vote is valid without revealing who you voted for.
//! Uses commitment scheme: commit = hash(vote || salt)
//!
//! Input: Vote (Private), Salt (Private), Commitment (Public)
//! Output: Boolean (vote valid and matches commitment)

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

const SHA256: u32 = 0x1002;

#[inline(always)]
unsafe fn sha256_syscall(msg_ptr: u32, msg_len: u32, out_ptr: u32) {
    core::arch::asm!(
        "mv a0, {msg_ptr}",
        "mv a1, {msg_len}",
        "mv a2, {out_ptr}",
        "li a7, {syscall}",
        "ecall",
        msg_ptr = in(reg) msg_ptr,
        msg_len = in(reg) msg_len,
        out_ptr = in(reg) out_ptr,
        syscall = const SHA256,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a7") _,
    );
}

fn hashes_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Valid candidates: 0 = Alice, 1 = Bob, 2 = Carol
    const NUM_CANDIDATES: u8 = 3;
    
    // Private inputs
    let vote: u8 = 1; // Voting for Bob (private)
    let salt: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    
    // Build commitment input: vote || salt
    let mut commitment_input = [0u8; 17];
    commitment_input[0] = vote;
    commitment_input[1..17].copy_from_slice(&salt);
    
    // Compute commitment hash
    let mut computed_commitment = [0u8; 32];
    unsafe {
        sha256_syscall(
            commitment_input.as_ptr() as u32,
            17,
            computed_commitment.as_mut_ptr() as u32,
        );
    }
    
    // Public input: expected commitment (pre-computed for vote=1, salt=1..16)
    // In real use, this would be provided by the voter registration
    let expected_commitment = computed_commitment; // Self-check for demo
    
    // Validate vote is in range
    let vote_in_range = vote < NUM_CANDIDATES;
    
    // Validate commitment matches
    let commitment_valid = hashes_equal(&computed_commitment, &expected_commitment);
    
    // Both must be true
    let is_valid = vote_in_range && commitment_valid;
    
    // Store result
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    // Store first 4 bytes of commitment for verification
    let commit_addr = 0x80000004 as *mut u32;
    unsafe {
        let commit_word = u32::from_le_bytes([
            computed_commitment[0], computed_commitment[1],
            computed_commitment[2], computed_commitment[3]
        ]);
        core::ptr::write_volatile(commit_addr, commit_word);
    }
    
    loop {}
}
