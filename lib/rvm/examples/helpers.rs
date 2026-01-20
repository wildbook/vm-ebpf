//! Helper functions example: Register and call host functions from eBPF.
//!
//! This example demonstrates how to register type-safe helper functions
//! that eBPF programs can call.
//!
//! Run with: cargo run --example helpers

use rvm::{HelperRegistry, VmMemory};

fn main() {
    println!("=== Helper Functions ===\n");

    // Create a helper registry and register some functions
    let mut helpers = HelperRegistry::new();

    // Helper 1: Double a value
    helpers.register(1, |x: u64| {
        println!("  helper_double({}) called", x);
        x * 2
    });

    // Helper 2: Add two values
    helpers.register(2, |(a, b): (u64, u64)| {
        println!("  helper_add({}, {}) called", a, b);
        a + b
    });

    // Helper 3: Return a constant (no args)
    helpers.register(3, |_: ()| {
        println!("  helper_magic() called");
        0xCAFEBABEu64
    });

    // Build a program that calls helpers:
    //   r1 = 21
    //   r0 = helper_1(r1)     ; r0 = 42
    //   r1 = r0
    //   r2 = 8
    //   r0 = helper_2(r1, r2) ; r0 = 50
    //   exit
    let program = build_program(&[
        insn_mov_imm(1, 21), // r1 = 21
        insn_call(1),        // r0 = helper_1(r1)
        insn_mov_reg(1, 0),  // r1 = r0
        insn_mov_imm(2, 8),  // r2 = 8
        insn_call(2),        // r0 = helper_2(r1, r2)
        insn_exit(),         // return r0
    ]);

    // Create memory and load program
    let mut memory = VmMemory::new(program.len() + 512);
    memory.write_bytes(0, &program).unwrap();

    // Execute
    let stack_top = (program.len() + 512) as u64;
    let mut executor = rvm::Executor::new(&mut memory, &helpers, stack_top);

    println!("Executing program...\n");
    let result = executor.call(0, &[]).unwrap();

    println!("\nResult: {} (expected: 50)", result);
    assert_eq!(result, 50);

    // Test helper 3 (no args)
    println!("\n--- Testing helper with no args ---\n");
    let program2 = build_program(&[
        insn_call(3), // r0 = helper_3()
        insn_exit(),
    ]);

    let mut memory2 = VmMemory::new(program2.len() + 512);
    memory2.write_bytes(0, &program2).unwrap();

    let mut executor2 = rvm::Executor::new(&mut memory2, &helpers, (program2.len() + 512) as u64);
    let result2 = executor2.call(0, &[]).unwrap();

    println!("\nResult: 0x{:X} (expected: 0xCAFEBABE)", result2);
    assert_eq!(result2, 0xCAFEBABE);

    println!("\nSuccess!");
}

// ============================================================================
// Instruction builders
// ============================================================================

fn insn_mov_imm(dst: u8, imm: i32) -> u64 {
    let opc = 0xb7u64; // ALU64 | MOV | SRC_IMM
    let dst = (dst as u64) << 8;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | imm
}

fn insn_mov_reg(dst: u8, src: u8) -> u64 {
    let opc = 0xbfu64;
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    opc | dst | src
}

fn insn_call(helper_id: i32) -> u64 {
    // opcode 0x85 = JMP | CALL
    let opc = 0x85u64;
    let imm = ((helper_id as u32) as u64) << 32;
    opc | imm
}

fn insn_exit() -> u64 {
    0x95
}

fn build_program(insns: &[u64]) -> Vec<u8> {
    insns.iter().flat_map(|i| i.to_le_bytes()).collect()
}
