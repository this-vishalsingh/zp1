//! Integration tests for Blake2b syscall

use zp1_executor::Cpu;

const BLAKE2B_SYSCALL: u32 = 0x1005;

#[test]
fn test_blake2b_syscall_empty() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = message_ptr
    cpu.set_reg(11, 0); // a1 = message_len (empty)
    cpu.set_reg(12, output_ptr); // a2 = digest_ptr
    cpu.set_reg(17, BLAKE2B_SYSCALL); // a7 = Blake2b syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (blake2b)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until Blake2b syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 64).unwrap();

    // Expected Blake2b-512 of empty string
    let expected = hex::decode(
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
         d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
    )
    .unwrap();

    assert_eq!(digest, expected, "Blake2b empty string mismatch");
    assert_eq!(cpu.get_reg(10), 0, "Blake2b should return success");
}

#[test]
fn test_blake2b_syscall_abc() {
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
    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, message.len() as u32);
    cpu.set_reg(12, output_ptr);
    cpu.set_reg(17, BLAKE2B_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (blake2b)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until Blake2b syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 64).unwrap();

    // Expected Blake2b-512 of "abc"
    let expected = hex::decode(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
         7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    )
    .unwrap();

    assert_eq!(digest, expected, "Blake2b 'abc' mismatch");
    assert_eq!(cpu.get_reg(10), 0, "Blake2b should return success");
}

#[test]
fn test_blake2b_syscall_hello() {
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
    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, message.len() as u32);
    cpu.set_reg(12, output_ptr);
    cpu.set_reg(17, BLAKE2B_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (blake2b)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until Blake2b syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest - just verify it's 64 bytes and deterministic
    let digest = cpu.memory.slice(output_ptr, 64).unwrap();
    assert_eq!(digest.len(), 64);

    // Run again to verify determinism
    let mut cpu2 = Cpu::new();
    cpu2.enable_tracing();
    for (i, &byte) in message.iter().enumerate() {
        cpu2.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }
    cpu2.set_reg(10, input_ptr);
    cpu2.set_reg(11, message.len() as u32);
    cpu2.set_reg(12, output_ptr);
    cpu2.set_reg(17, BLAKE2B_SYSCALL);
    cpu2.memory.load_program(0, &program_bytes).unwrap();
    for _ in 0..5 {
        if cpu2.pc == 4 {
            break;
        }
        let _ = cpu2.step();
    }
    let digest2 = cpu2.memory.slice(output_ptr, 64).unwrap();

    assert_eq!(digest, digest2, "Blake2b should be deterministic");
    assert_eq!(cpu.get_reg(10), 0, "Blake2b should return success");
}

#[test]
fn test_blake2b_syscall_long() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x3000;

    // Create a longer message (1KB)
    let message = vec![0x42u8; 1024];

    // Write message to memory
    for (i, &byte) in message.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, message.len() as u32);
    cpu.set_reg(12, output_ptr);
    cpu.set_reg(17, BLAKE2B_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (blake2b)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until Blake2b syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 64).unwrap();
    assert_eq!(digest.len(), 64);

    // Verify it's not all zeros
    let is_nonzero = digest.iter().any(|&b| b != 0);
    assert!(is_nonzero, "Hash should not be all zeros");

    assert_eq!(cpu.get_reg(10), 0, "Blake2b should return success");
}

#[test]
fn test_blake2b_syscall_zcash() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Simulate Zcash transaction data
    let message = b"zcash_transaction_example";

    // Write message to memory
    for (i, &byte) in message.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, message.len() as u32);
    cpu.set_reg(12, output_ptr);
    cpu.set_reg(17, BLAKE2B_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (blake2b)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until Blake2b syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the digest
    let digest = cpu.memory.slice(output_ptr, 64).unwrap();

    // Should produce valid 64-byte hash for Zcash compatibility
    assert_eq!(digest.len(), 64);

    assert_eq!(cpu.get_reg(10), 0, "Blake2b should return success");
}
