//! Calls typed host helpers from hand-assembled bytecode.
//!
//! Run with: cargo run -p rvm --example helpers

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{HelperRegistry, Perms, VmMemory};

fn main() {
    println!("=== Helper Functions ===\n");

    let mut helpers = HelperRegistry::new();
    helpers.register(1, |x: u64| {
        println!("  helper_double({}) called", x);
        x * 2
    });
    helpers.register(2, |(a, b): (u64, u64)| {
        println!("  helper_add({}, {}) called", a, b);
        a + b
    });
    helpers.register(3, |_: ()| {
        println!("  helper_magic() called");
        0xCAFEBABEu64
    });

    // helper_2(helper_1(21), 8)
    let mut asm = Assembler::new();
    asm.mov64_imm(R1, 21);
    asm.call(1);
    asm.mov64(R1, R0);
    asm.mov64_imm(R2, 8);
    asm.call(2);
    asm.exit();

    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);
    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);

    println!("Executing program...\n");
    let result = executor.call(0, &[]).unwrap();

    println!("\nResult: {} (expected: 50)", result);
    assert_eq!(result, 50);

    println!("\n--- Testing helper with no args ---\n");
    let mut asm2 = Assembler::new();
    asm2.call(3);
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
