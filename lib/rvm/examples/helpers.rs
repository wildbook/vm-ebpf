//! Calls typed host helpers from hand-assembled bytecode.
//!
//! Run with: cargo run -p rvm --example helpers

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{HelperRegistry, Perms, VmMemory};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut helpers = HelperRegistry::new();
    helpers.register(1, |x: u64| {
        println!("  helper_double({x}) called");
        x * 2
    });
    helpers.register(2, |(a, b): (u64, u64)| {
        println!("  helper_add({a}, {b}) called");
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
    let result = run(asm, &helpers)?;
    println!("Result: {result}");
    if result != 50 {
        return Err(format!("expected 50, got {result}").into());
    }

    let mut asm = Assembler::new();
    asm.call(3);
    asm.exit();
    let result = run(asm, &helpers)?;
    println!("Result: 0x{result:X}");
    if result != 0xCAFEBABE {
        return Err(format!("expected 0xCAFEBABE, got 0x{result:X}").into());
    }
    Ok(())
}

fn run(mut asm: Assembler, helpers: &HelperRegistry) -> Result<u64, Box<dyn std::error::Error>> {
    let bytes = asm.assemble()?;
    let code = rvm::instructions_from_bytes(&bytes);
    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;
    let mut executor = rvm::Executor::new(&code, &mut memory, helpers, stack_top);
    Ok(executor.call(0, &[])?)
}
