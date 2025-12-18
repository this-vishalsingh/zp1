//! Tests for Keccak256 delegation.

use zp1_executor::Cpu;

/// Test Keccak256 syscall with known test vectors.
#[test]
fn test_keccak256_syscall() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    // Allocate memory for input and output
    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Test vector: "hello" -> hash
    let input = b"hello";
    let expected_hash =
        hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8").unwrap();

    // Write input to memory
    for (i, &byte) in input.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers directly for the syscall
    cpu.set_reg(10, input_ptr); // a0 = input_ptr
    cpu.set_reg(11, 5); // a1 = input_len
    cpu.set_reg(12, output_ptr); // a2 = output_ptr
    cpu.set_reg(17, 0x1000); // a7 = keccak syscall number

    // Create a simple program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (keccak)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    // Load program at address 0
    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();

    cpu.load_program(0, &program_bytes).unwrap();

    // Run until exit
    let mut steps = 0;
    let max_steps = 100;
    loop {
        match cpu.step() {
            Ok(None) => {
                steps += 1;
                if steps >= max_steps {
                    panic!("Program didn't terminate within {} steps", max_steps);
                }
            }
            Ok(Some(_)) => break, // Halted normally
            Err(e) => {
                // Check if it's the exit syscall
                if let zp1_executor::ExecutorError::Ecall { syscall_id, .. } = e {
                    if syscall_id == 93 {
                        break; // Normal exit
                    }
                }
                panic!("Execution error: {}", e);
            }
        }
    }

    // Verify the output
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
    }

    assert_eq!(
        &output[..],
        &expected_hash[..],
        "Keccak256 hash mismatch!\nExpected: {:?}\nGot: {:?}",
        expected_hash,
        output
    );

    // Verify the trace contains the Keccak delegation
    let trace = cpu.take_trace().unwrap();
    let keccak_ops: Vec<_> = trace
        .rows
        .iter()
        .filter(|row| matches!(row.mem_op, zp1_executor::trace::MemOp::Keccak256 { .. }))
        .collect();

    assert_eq!(
        keccak_ops.len(),
        1,
        "Should have exactly one Keccak256 operation in trace"
    );
}

/// Test Keccak256 with empty input.
#[test]
fn test_keccak256_empty() {
    let mut cpu = Cpu::new();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    let expected_hash =
        hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").unwrap();

    // Load registers directly
    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, 0); // length = 0
    cpu.set_reg(12, output_ptr);
    cpu.set_reg(17, 0x1000); // a7 = keccak syscall

    // Create minimal program: ecall
    cpu.load_program(0, &0x00000073u32.to_le_bytes()).unwrap();

    // Execute the syscall
    match cpu.step() {
        Err(zp1_executor::ExecutorError::Ecall { syscall_id: 93, .. }) | Ok(_) => {
            // Check output
            let mut output = [0u8; 32];
            for i in 0..32 {
                output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
            }

            assert_eq!(&output[..], &expected_hash[..]);
        }
        other => panic!("Unexpected result: {:?}", other),
    }
}

/// Test Keccak256 with longer input (tests multi-block absorption).
#[test]
fn test_keccak256_long_input() {
    let mut cpu = Cpu::new();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // 200 bytes of input (requires 2 absorption rounds)
    let input = vec![0x42u8; 200];
    let expected_hash = zp1_delegation::keccak::keccak256(&input);

    // Write input to memory
    for (i, &byte) in input.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Load registers
    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, 200);
    cpu.set_reg(12, output_ptr);
    cpu.set_reg(17, 0x1000);

    // Create program: ecall
    cpu.load_program(0, &0x00000073u32.to_le_bytes()).unwrap();

    // Execute
    let _ = cpu.step();

    // Verify output
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
    }

    assert_eq!(&output[..], &expected_hash[..]);
}
