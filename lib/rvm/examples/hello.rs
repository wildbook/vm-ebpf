//! Basic example: Execute a simple eBPF program.
//!
//! This example demonstrates the minimal setup needed to run eBPF bytecode.
//! We use the ebpf-asm crate to construct the bytecode.
//!
//! Run with: cargo run --example hello

use ebpf_asm::{Assembler, R0, R1};
use rvm::{Perms, VmMemory};

fn main() {
    println!("=== Hello rvm ===\n");

    // Create a simple program that computes: r0 = r1 + 10
    //
    // Instructions:
    //   mov r0, r1      ; r0 = arg1
    //   add r0, 10      ; r0 += 10
    //   exit            ; return r0
    let mut asm = Assembler::new();
    asm.mov64(R0, R1); // r0 = r1
    asm.add64_imm(R0, 10); // r0 += 10
    asm.exit(); // exit

    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);

    // Code stays outside guest memory, so only the stack is mapped.
    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;

    // Create executor and run
    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);

    // Call with argument r1 = 32
    let result = executor.call(0, &[32]).unwrap();

    println!("Input:  32");
    println!("Output: {} (expected: 42)", result);
    assert_eq!(result, 42);

    println!("\nSuccess!");
}
