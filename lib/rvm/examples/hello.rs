//! Runs hand-assembled bytecode directly on an `Executor`, without a `Vm`.
//!
//! Run with: cargo run -p rvm --example hello

use ebpf_asm::{Assembler, R0, R1};
use rvm::{Perms, VmMemory};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // r0 = r1 + 10
    let mut asm = Assembler::new();
    asm.mov64(R0, R1);
    asm.add64_imm(R0, 10);
    asm.exit();

    let bytes = asm.assemble()?;
    let code = rvm::instructions_from_bytes(&bytes);

    // Code stays outside guest memory, so only the stack is mapped.
    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;

    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);
    let result = executor.call(0, &[32])?;

    println!("32 + 10 = {result}");
    if result != 42 {
        return Err(format!("expected 42, got {result}").into());
    }
    Ok(())
}
