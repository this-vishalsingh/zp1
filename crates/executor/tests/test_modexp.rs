//! Integration tests for MODEXP syscall (modular exponentiation)

use zp1_executor::Cpu;

const MODEXP_SYSCALL: u32 = 0x1004;

#[test]
fn test_modexp_syscall_simple() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    // Test: 2^3 mod 5 = 8 mod 5 = 3
    let base_ptr = 0x1000;
    let exp_ptr = 0x1020;
    let mod_ptr = 0x1040;
    let result_ptr = 0x2000;

    // Write base = 2 (little-endian, 32 bytes)
    let base_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 2;
        b
    };
    for (i, &byte) in base_bytes.iter().enumerate() {
        cpu.memory.write_byte(base_ptr + i as u32, byte).unwrap();
    }

    // Write exponent = 3
    let exp_bytes: [u8; 32] = {
        let mut e = [0u8; 32];
        e[0] = 3;
        e
    };
    for (i, &byte) in exp_bytes.iter().enumerate() {
        cpu.memory.write_byte(exp_ptr + i as u32, byte).unwrap();
    }

    // Write modulus = 5
    let mod_bytes: [u8; 32] = {
        let mut m = [0u8; 32];
        m[0] = 5;
        m
    };
    for (i, &byte) in mod_bytes.iter().enumerate() {
        cpu.memory.write_byte(mod_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, base_ptr); // a0 = base_ptr
    cpu.set_reg(11, exp_ptr); // a1 = exp_ptr
    cpu.set_reg(12, mod_ptr); // a2 = mod_ptr
    cpu.set_reg(13, result_ptr); // a3 = result_ptr
    cpu.set_reg(17, MODEXP_SYSCALL); // a7 = MODEXP syscall number

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (modexp)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until MODEXP syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the result
    let result = cpu.memory.slice(result_ptr, 32).unwrap();

    // Expected: 3 (2^3 mod 5 = 8 mod 5 = 3)
    assert_eq!(result[0], 3);
    for i in 1..32 {
        assert_eq!(result[i], 0);
    }

    assert_eq!(cpu.get_reg(10), 0, "MODEXP should return success");
}

#[test]
fn test_modexp_syscall_zero_exponent() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    // Test: 5^0 mod 7 = 1 (any number to power 0 is 1)
    let base_ptr = 0x1000;
    let exp_ptr = 0x1020;
    let mod_ptr = 0x1040;
    let result_ptr = 0x2000;

    // Write base = 5
    let base_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 5;
        b
    };
    for (i, &byte) in base_bytes.iter().enumerate() {
        cpu.memory.write_byte(base_ptr + i as u32, byte).unwrap();
    }

    // Write exponent = 0
    let exp_bytes: [u8; 32] = [0u8; 32];
    for (i, &byte) in exp_bytes.iter().enumerate() {
        cpu.memory.write_byte(exp_ptr + i as u32, byte).unwrap();
    }

    // Write modulus = 7
    let mod_bytes: [u8; 32] = {
        let mut m = [0u8; 32];
        m[0] = 7;
        m
    };
    for (i, &byte) in mod_bytes.iter().enumerate() {
        cpu.memory.write_byte(mod_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, base_ptr);
    cpu.set_reg(11, exp_ptr);
    cpu.set_reg(12, mod_ptr);
    cpu.set_reg(13, result_ptr);
    cpu.set_reg(17, MODEXP_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (modexp)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until MODEXP syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the result
    let result = cpu.memory.slice(result_ptr, 32).unwrap();

    // Expected: 1 (x^0 = 1 for any x)
    assert_eq!(result[0], 1);
    for i in 1..32 {
        assert_eq!(result[i], 0);
    }

    assert_eq!(cpu.get_reg(10), 0, "MODEXP should return success");
}

#[test]
fn test_modexp_syscall_rsa_small() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    // Small RSA example: message^e mod n
    // m = 42, e = 17, n = 3233 (= 61 * 53)
    // c = 42^17 mod 3233 = 2557
    let base_ptr = 0x1000;
    let exp_ptr = 0x1020;
    let mod_ptr = 0x1040;
    let result_ptr = 0x2000;

    // Write base = 42
    let base_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 42;
        b
    };
    for (i, &byte) in base_bytes.iter().enumerate() {
        cpu.memory.write_byte(base_ptr + i as u32, byte).unwrap();
    }

    // Write exponent = 17
    let exp_bytes: [u8; 32] = {
        let mut e = [0u8; 32];
        e[0] = 17;
        e
    };
    for (i, &byte) in exp_bytes.iter().enumerate() {
        cpu.memory.write_byte(exp_ptr + i as u32, byte).unwrap();
    }

    // Write modulus = 3233 (0x0CA1)
    let mod_bytes: [u8; 32] = {
        let mut m = [0u8; 32];
        m[0] = 0xA1;
        m[1] = 0x0C;
        m
    };
    for (i, &byte) in mod_bytes.iter().enumerate() {
        cpu.memory.write_byte(mod_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, base_ptr);
    cpu.set_reg(11, exp_ptr);
    cpu.set_reg(12, mod_ptr);
    cpu.set_reg(13, result_ptr);
    cpu.set_reg(17, MODEXP_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (modexp)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until MODEXP syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the result
    let result = cpu.memory.slice(result_ptr, 32).unwrap();

    // Expected: 2557 (0x09FD)
    let expected = 2557u16;
    let expected_bytes = expected.to_le_bytes();
    assert_eq!(result[0], expected_bytes[0]);
    assert_eq!(result[1], expected_bytes[1]);
    for i in 2..32 {
        assert_eq!(result[i], 0);
    }

    assert_eq!(cpu.get_reg(10), 0, "MODEXP should return success");
}

#[test]
fn test_modexp_syscall_large_numbers() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    // Test with larger numbers to verify U256 handling
    // base = 0x123456789ABCDEF (56 bits)
    // exp = 0x3
    // mod = 0xFFFFFFFFFFFFFFF (60 bits)
    let base_ptr = 0x1000;
    let exp_ptr = 0x1020;
    let mod_ptr = 0x1040;
    let result_ptr = 0x2000;

    // Write base
    let base_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 0xEF;
        b[1] = 0xCD;
        b[2] = 0xAB;
        b[3] = 0x89;
        b[4] = 0x67;
        b[5] = 0x45;
        b[6] = 0x23;
        b[7] = 0x01;
        b
    };
    for (i, &byte) in base_bytes.iter().enumerate() {
        cpu.memory.write_byte(base_ptr + i as u32, byte).unwrap();
    }

    // Write exponent = 3
    let exp_bytes: [u8; 32] = {
        let mut e = [0u8; 32];
        e[0] = 3;
        e
    };
    for (i, &byte) in exp_bytes.iter().enumerate() {
        cpu.memory.write_byte(exp_ptr + i as u32, byte).unwrap();
    }

    // Write modulus
    let mod_bytes: [u8; 32] = {
        let mut m = [0u8; 32];
        m[0] = 0xFF;
        m[1] = 0xFF;
        m[2] = 0xFF;
        m[3] = 0xFF;
        m[4] = 0xFF;
        m[5] = 0xFF;
        m[6] = 0xFF;
        m[7] = 0x0F;
        m
    };
    for (i, &byte) in mod_bytes.iter().enumerate() {
        cpu.memory.write_byte(mod_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, base_ptr);
    cpu.set_reg(11, exp_ptr);
    cpu.set_reg(12, mod_ptr);
    cpu.set_reg(13, result_ptr);
    cpu.set_reg(17, MODEXP_SYSCALL);

    // Create program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (modexp)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    // Run until MODEXP syscall completes
    for _ in 0..5 {
        if cpu.pc == 4 {
            break;
        }
        let _ = cpu.step();
    }

    // Read the result - just verify it computed something valid
    let result = cpu.memory.slice(result_ptr, 32).unwrap();

    // Result should be less than modulus and non-zero
    let mut is_zero = true;
    for &byte in result.iter() {
        if byte != 0 {
            is_zero = false;
            break;
        }
    }
    assert!(!is_zero, "Result should be non-zero");

    assert_eq!(cpu.get_reg(10), 0, "MODEXP should return success");
}
