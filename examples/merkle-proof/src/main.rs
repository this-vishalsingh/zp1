//! Merkle Proof Example
//!
//! Demonstrates verifying Merkle tree inclusion proofs.
//! Uses Keccak256 for hashing (Ethereum-compatible).
//!
//! Use case: Prove a leaf is included in a Merkle tree
//! without revealing other leaves.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// Keccak256 syscall number (matches CPU implementation)
const KECCAK256: u32 = 0x1000;

/// Syscall to compute Keccak-256 hash
#[inline(always)]
unsafe fn keccak256_syscall(data_ptr: u32, data_len: u32, out_ptr: u32) {
    core::arch::asm!(
        "mv a0, {data_ptr}",
        "mv a1, {data_len}",
        "mv a2, {out_ptr}",
        "li a7, {syscall}",
        "ecall",
        data_ptr = in(reg) data_ptr,
        data_len = in(reg) data_len,
        out_ptr = in(reg) out_ptr,
        syscall = const KECCAK256,
        out("a0") _,
        out("a1") _,
        out("a2") _,
        out("a7") _,
    );
}

/// Hash two 32-byte values together (Merkle node computation)
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Concatenate left and right
    let mut combined: [u8; 64] = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    
    let mut result: [u8; 32] = [0u8; 32];
    unsafe {
        keccak256_syscall(
            combined.as_ptr() as u32,
            64,
            result.as_mut_ptr() as u32,
        );
    }
    result
}

/// Compute leaf hash
fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut result: [u8; 32] = [0u8; 32];
    unsafe {
        keccak256_syscall(
            data.as_ptr() as u32,
            data.len() as u32,
            result.as_mut_ptr() as u32,
        );
    }
    result
}

/// Compare two 32-byte hashes
fn hashes_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

/// Verify a Merkle proof
/// - leaf_data: The data to prove inclusion of
/// - proof: Array of sibling hashes
/// - indices: Bit array (0 = left, 1 = right) for each level
/// - expected_root: The expected Merkle root
fn verify_merkle_proof(
    leaf_data: &[u8],
    proof: &[[u8; 32]],
    indices: &[u8],
    expected_root: &[u8; 32],
) -> bool {
    // Compute leaf hash
    let mut current = hash_leaf(leaf_data);
    
    // Walk up the tree
    for i in 0..proof.len() {
        if indices[i] == 0 {
            // Current is left, sibling is right
            current = hash_pair(&current, &proof[i]);
        } else {
            // Current is right, sibling is left
            current = hash_pair(&proof[i], &current);
        }
    }
    
    // Check if computed root matches expected
    hashes_equal(&current, expected_root)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Example: 4-leaf Merkle tree
    // Leaves: "Alice", "Bob", "Carol", "Dave"
    // We'll prove "Bob" is in the tree
    
    // Compute all leaf hashes first
    let leaf_alice = hash_leaf(b"Alice");
    let leaf_bob = hash_leaf(b"Bob");
    let leaf_carol = hash_leaf(b"Carol");
    let leaf_dave = hash_leaf(b"Dave");
    
    // Build the tree:
    //        root
    //       /    \
    //    n01      n23
    //   /  \     /   \
    // Alice Bob Carol Dave
    
    let n01 = hash_pair(&leaf_alice, &leaf_bob);
    let n23 = hash_pair(&leaf_carol, &leaf_dave);
    let root = hash_pair(&n01, &n23);
    
    // Proof for "Bob" (index 1):
    // - Sibling at level 0: Alice (left)
    // - Sibling at level 1: n23 (right)
    let proof = [leaf_alice, n23];
    let indices = [1u8, 0u8]; // Bob is right at level 0, n01 is left at level 1
    
    // Verify the proof
    let is_valid = verify_merkle_proof(b"Bob", &proof, &indices, &root);
    
    // Store result: 1 = valid, 0 = invalid
    let output_addr = 0x80000000 as *mut u32;
    unsafe {
        core::ptr::write_volatile(output_addr, if is_valid { 1 } else { 0 });
    }
    
    // Store root hash (first 4 bytes) for verification
    let root_addr = 0x80000004 as *mut u32;
    unsafe {
        let root_word = u32::from_le_bytes([root[0], root[1], root[2], root[3]]);
        core::ptr::write_volatile(root_addr, root_word);
    }
    
    loop {}
}
