//! Tests for ECRECOVER delegation.

use zp1_executor::Cpu;

/// Test ECRECOVER syscall with a valid signature.
#[test]
fn test_ecrecover_syscall_valid() {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Create a test signature (we'll use generated data)
    // For a real test, we'd use a known Ethereum signature
    use secp256k1::ecdsa::RecoverableSignature;
    use secp256k1::{Message, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xCD; 32]).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

    // Create message and sign it
    let message = [0xAA; 32];
    let msg = Message::from_digest_slice(&message).unwrap();
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &secret_key);

    let (recovery_id, sig_bytes) = sig.serialize_compact();
    let v = recovery_id.to_i32() as u8;

    // Prepare input: hash || v || r || s
    let mut input = vec![0u8; 97];
    input[0..32].copy_from_slice(&message);
    input[32] = v;
    input[33..65].copy_from_slice(&sig_bytes[0..32]); // r
    input[65..97].copy_from_slice(&sig_bytes[32..64]); // s

    // Write input to memory
    for (i, &byte) in input.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    // Set up registers for the syscall
    cpu.set_reg(10, input_ptr); // a0 = input_ptr
    cpu.set_reg(11, output_ptr); // a1 = output_ptr
    cpu.set_reg(17, 0x1001); // a7 = ecrecover syscall number

    // Create a simple program: ecall, then exit ecall
    let program: Vec<u32> = vec![
        0x00000073, // ecall (ecrecover)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

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
            Ok(Some(_)) => break,
            Err(e) => {
                if let zp1_executor::ExecutorError::Ecall { syscall_id, .. } = e {
                    if syscall_id == 93 {
                        break; // Normal exit
                    }
                }
                panic!("Execution error: {}", e);
            }
        }
    }

    // Verify the output address is non-zero (valid signature)
    let mut output = [0u8; 20];
    for i in 0..20 {
        output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
    }

    // Should recover to a valid address (not all zeros)
    assert_ne!(
        &output[..],
        &[0u8; 20],
        "ECRECOVER should recover a valid address"
    );

    // Compute expected address manually
    let pubkey_bytes = public_key.serialize_uncompressed();
    let hash = zp1_delegation::keccak::keccak256(&pubkey_bytes[1..]);
    let expected_address = &hash[12..];

    assert_eq!(
        &output[..],
        expected_address,
        "ECRECOVER address mismatch!\nExpected: {:?}\nGot: {:?}",
        expected_address,
        output
    );

    // Verify the trace contains the ECRECOVER delegation
    let trace = cpu.take_trace().unwrap();
    let ecrecover_ops: Vec<_> = trace
        .rows
        .iter()
        .filter(|row| matches!(row.mem_op, zp1_executor::trace::MemOp::Ecrecover { .. }))
        .collect();

    assert_eq!(
        ecrecover_ops.len(),
        1,
        "Should have exactly one ECRECOVER operation in trace"
    );
}

/// Test ECRECOVER with invalid signature (should return zero address).
#[test]
fn test_ecrecover_invalid_signature() {
    let mut cpu = Cpu::new();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Create invalid signature (all zeros)
    let input = vec![0u8; 97];

    for (i, &byte) in input.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, output_ptr);
    cpu.set_reg(17, 0x1001);

    cpu.load_program(0, &0x00000073u32.to_le_bytes()).unwrap();

    let _ = cpu.step();

    // Verify output is zero address (invalid signature)
    let mut output = [0u8; 20];
    for i in 0..20 {
        output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
    }

    assert_eq!(
        &output[..],
        &[0u8; 20],
        "Invalid signature should produce zero address"
    );

    // Check return value (a0 should be 1 for failure)
    assert_eq!(cpu.get_reg(10), 1, "Return value should indicate failure");
}

/// Test ECRECOVER with invalid recovery ID.
#[test]
fn test_ecrecover_invalid_v() {
    let mut cpu = Cpu::new();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Create signature with invalid v (99)
    let mut input = vec![0u8; 97];
    input[32] = 99; // Invalid v
    input[33] = 0x01; // Some non-zero r
    input[65] = 0x01; // Some non-zero s

    for (i, &byte) in input.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, output_ptr);
    cpu.set_reg(17, 0x1001);

    cpu.load_program(0, &0x00000073u32.to_le_bytes()).unwrap();

    let _ = cpu.step();

    // Verify zero address
    let mut output = [0u8; 20];
    for i in 0..20 {
        output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
    }

    assert_eq!(&output[..], &[0u8; 20]);
    assert_eq!(cpu.get_reg(10), 1); // Failure
}

/// Test ECRECOVER with EIP-155 v values.
#[test]
fn test_ecrecover_eip155() {
    let mut cpu = Cpu::new();

    let input_ptr = 0x1000;
    let output_ptr = 0x2000;

    // Create a valid signature with EIP-155 v (chainId=1, v=37 or 38)
    use secp256k1::{Message, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xAB; 32]).unwrap();
    let message = [0xBB; 32];
    let msg = Message::from_digest_slice(&message).unwrap();
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret_key);

    let (recovery_id, sig_bytes) = sig.serialize_compact();

    // Convert to EIP-155: v = chainId * 2 + 35 + recovery_id
    let chain_id = 1u32;
    let v = (chain_id * 2 + 35 + recovery_id.to_i32() as u32) as u8;

    let mut input = vec![0u8; 97];
    input[0..32].copy_from_slice(&message);
    input[32] = v;
    input[33..65].copy_from_slice(&sig_bytes[0..32]);
    input[65..97].copy_from_slice(&sig_bytes[32..64]);

    for (i, &byte) in input.iter().enumerate() {
        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
    }

    cpu.set_reg(10, input_ptr);
    cpu.set_reg(11, output_ptr);
    cpu.set_reg(17, 0x1001);

    cpu.load_program(0, &0x00000073u32.to_le_bytes()).unwrap();

    let _ = cpu.step();

    // Verify valid address recovered
    let mut output = [0u8; 20];
    for i in 0..20 {
        output[i] = cpu.memory.read_byte(output_ptr + i as u32).unwrap();
    }

    assert_ne!(&output[..], &[0u8; 20], "EIP-155 signature should be valid");
    assert_eq!(cpu.get_reg(10), 0); // Success
}
