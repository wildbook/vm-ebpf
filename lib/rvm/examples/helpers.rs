//! Helper functions example: Register and call host functions from eBPF.
//!
//! This example demonstrates how to register type-safe helper functions
//! that eBPF programs can call.
//!
//! Run with: cargo run --example helpers

use ebpf_asm::{Assembler, R0, R1, R2};
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
    let mut asm = Assembler::new();
    asm.mov64_imm(R1, 21).unwrap(); // r1 = 21
    asm.call(1).unwrap(); // r0 = helper_1(r1)
    asm.mov64(R1, R0).unwrap(); // r1 = r0
    asm.mov64_imm(R2, 8).unwrap(); // r2 = 8
    asm.call(2).unwrap(); // r0 = helper_2(r1, r2)
    asm.exit().unwrap(); // return r0

    let program = asm.assemble().unwrap();

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
    let mut asm2 = Assembler::new();
    asm2.call(3).unwrap(); // r0 = helper_3()
    asm2.exit().unwrap();

    let program2 = asm2.assemble().unwrap();
    let mut memory2 = VmMemory::new(program2.len() + 512);
    memory2.write_bytes(0, &program2).unwrap();

    let mut executor2 = rvm::Executor::new(&mut memory2, &helpers, (program2.len() + 512) as u64);
    let result2 = executor2.call(0, &[]).unwrap();

    println!("\nResult: 0x{:X} (expected: 0xCAFEBABE)", result2);
    assert_eq!(result2, 0xCAFEBABE);

    println!("\nSuccess!");
}
