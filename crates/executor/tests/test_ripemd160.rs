//! Integration tests for RIPEMD-160 syscall

use zp1_executor::Cpu;

const RIPEMD160_SYSCALL: u32 = 0x1003;

#[test]
fn test_ripemd160_syscall_empty() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;
    let message = b"";

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, 0); // a1 = message_len
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, RIPEMD160_SYSCALL); // a7 = RIPEMD-160 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (ripemd160)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until RIPEMD-160 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            // After first ecall
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 20).unwrap();

    // Expected: 9c1185a5c5e9fc54612808977ee8f548b2258d31
    let expected = [
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5,
        0x48, 0xb2, 0x25, 0x8d, 0x31,
    ];

    assert_eq!(digest, expected, "RIPEMD-160 empty string mismatch");
    assert_eq!(cpu.get_reg(10), 0, "RIPEMD-160 should return success");
}

#[test]
fn test_ripemd160_syscall_hello() {
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
    cpu.set_reg(17, RIPEMD160_SYSCALL); // a7 = RIPEMD-160 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (ripemd160)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until RIPEMD-160 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 20).unwrap();

    // Expected: 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
    let expected = [
        0x98, 0xc6, 0x15, 0x78, 0x4c, 0xcb, 0x5f, 0xe5, 0x93, 0x6f, 0xbc, 0x0c, 0xbe, 0x9d, 0xfd,
        0xb4, 0x08, 0xd9, 0x2f, 0x0f,
    ];

    assert_eq!(digest, expected, "RIPEMD-160 'hello world' mismatch");
    assert_eq!(cpu.get_reg(10), 0, "RIPEMD-160 should return success");
}

#[test]
fn test_ripemd160_syscall_abc() {
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
    cpu.set_reg(17, RIPEMD160_SYSCALL); // a7 = RIPEMD-160 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (ripemd160)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until RIPEMD-160 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 20).unwrap();

    // Expected: 8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
    let expected = [
        0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04, 0x4a, 0x8e, 0x98, 0xc6, 0xb0,
        0x87, 0xf1, 0x5a, 0x0b, 0xfc,
    ];

    assert_eq!(digest, expected, "RIPEMD-160 'abc' mismatch");
    assert_eq!(cpu.get_reg(10), 0, "RIPEMD-160 should return success");
}

#[test]
fn test_ripemd160_syscall_bitcoin_address() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Simulate a Bitcoin address generation: RIPEMD-160(SHA-256(pubkey))
    // This test uses a known SHA-256 output as input
    let sha256_output: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff,
    ];

    // Write SHA-256 output to memory
    for (i, &byte) in sha256_output.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, 32); // a1 = message_len (32 bytes from SHA-256)
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, RIPEMD160_SYSCALL); // a7 = RIPEMD-160 syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (ripemd160)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until RIPEMD-160 syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 20).unwrap();

    // Verify it produces a valid 20-byte output
    assert_eq!(digest.len(), 20);

    // Verify success
    assert_eq!(cpu.get_reg(10), 0, "RIPEMD-160 should return success");
}
