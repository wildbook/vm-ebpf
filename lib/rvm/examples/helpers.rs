//! Helper functions example: Register and call host functions from eBPF.
//!
//! This example demonstrates how to register type-safe helper functions
//! that eBPF programs can call.
//!
//! Run with: cargo run --example helpers

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{HelperRegistry, Perms, VmMemory};

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
    asm.mov64_imm(R1, 21); // r1 = 21
    asm.call(1); // r0 = helper_1(r1)
    asm.mov64(R1, R0); // r1 = r0
    asm.mov64_imm(R2, 8); // r2 = 8
    asm.call(2); // r0 = helper_2(r1, r2)
    asm.exit(); // return r0

    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);

    // Create memory with a stack region
    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;

    // Execute
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);

    println!("Executing program...\n");
    let result = executor.call(0, &[]).unwrap();

    println!("\nResult: {} (expected: 50)", result);
    assert_eq!(result, 50);

    // Test helper 3 (no args)
    println!("\n--- Testing helper with no args ---\n");
    let mut asm2 = Assembler::new();
    asm2.call(3); // r0 = helper_3()
    asm2.exit();

    let bytes2 = asm2.assemble().unwrap();
    let code2 = rvm::instructions_from_bytes(&bytes2);
    let mut memory2 = VmMemory::new();
    let stack_top2 = memory2.map(rvm::STACK_REGION, 512, Perms::RW) + 512;

    let mut executor2 = rvm::Executor::new(&code2, &mut memory2, &helpers, stack_top2);
    let result2 = executor2.call(0, &[]).unwrap();

    println!("\nResult: 0x{:X} (expected: 0xCAFEBABE)", result2);
    assert_eq!(result2, 0xCAFEBABE);

    println!("\nSuccess!");
}
