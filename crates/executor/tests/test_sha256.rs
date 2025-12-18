//! Integration tests for SHA-256 syscall

use zp1_executor::Cpu;

const SHA256_SYSCALL: u32 = 0x1002;

#[test]
fn test_sha256_syscall_empty() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;
    let message = b"";

    // Write message to memory (empty in this case)
    // (no writes needed for empty message)

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, 0); // a1 = message_len
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, SHA256_SYSCALL); // a7 = SHA256 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (sha256)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until SHA-256 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            // After first ecall
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 32).unwrap();

    // Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let expected = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    assert_eq!(digest, expected, "SHA-256 empty string mismatch");

    // Check return value (a0 should be 0 for success)
    assert_eq!(cpu.get_reg(10), 0, "SHA-256 should return success");
}

#[test]
fn test_sha256_syscall_hello() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;
    let message = b"hello world";

    // Write message to memory
    for (i, &byte) in message.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, message.len() as u32); // a1 = message_len
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, SHA256_SYSCALL); // a7 = SHA256 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (sha256)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until SHA-256 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 32).unwrap();

    // Expected: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    let expected = [
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab,
        0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef,
        0xcd, 0xe9,
    ];

    assert_eq!(digest, expected, "SHA-256 'hello world' mismatch");
    assert_eq!(cpu.get_reg(10), 0, "SHA-256 should return success");
}

#[test]
fn test_sha256_syscall_abc() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;
    let message = b"abc";

    // Write message to memory
    for (i, &byte) in message.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, message.len() as u32); // a1 = message_len
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, SHA256_SYSCALL); // a7 = SHA256 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (sha256)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until SHA-256 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 32).unwrap();

    // Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    assert_eq!(digest, expected, "SHA-256 'abc' mismatch");
    assert_eq!(cpu.get_reg(10), 0, "SHA-256 should return success");
}

#[test]
fn test_sha256_syscall_long_message() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;
    // Test with a message longer than 64 bytes to exercise multiple blocks
    let message = b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

    // Write message to memory
    for (i, &byte) in message.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, message.len() as u32); // a1 = message_len
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, SHA256_SYSCALL); // a7 = SHA256 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (sha256)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until SHA-256 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 32).unwrap();

    // Verify it's deterministic
    let expected_digest = zp1_delegation::sha256::sha256(message);
    assert_eq!(digest, expected_digest, "SHA-256 long message mismatch");
    assert_eq!(cpu.get_reg(10), 0, "SHA-256 should return success");
}
