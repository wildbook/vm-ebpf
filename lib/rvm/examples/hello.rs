//! Runs hand-assembled bytecode, loaded as an `Image` without ELF or linker, that calls typed host helpers.
//!
//! Run with: cargo run -p rvm --example hello

use ebpf_asm::{Assembler, R0, R1, R2};
use rvm::{Image, Vm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // these replace the map helpers, which also use IDs 1 to 3
    let vm = Vm::new();
    vm.register_helper(1, |x: u64| {
        println!("  helper_double({x}) called");
        x * 2
    });
    vm.register_helper(2, |(a, b): (u64, u64)| {
        println!("  helper_add({a}, {b}) called");
        a + b
    });
    vm.register_helper(3, |_: ()| {
        println!("  helper_magic() called");
        0xCAFEBABEu64
    });

    // r0 = r1 + 10
    let mut asm = Assembler::new();
    asm.mov64(R0, R1);
    asm.add64_imm(R0, 10);
    asm.exit();
    let result = run(asm, &vm, &[32])?;
    println!("32 + 10 = {result}");
    if result != 42 {
        return Err(format!("expected 42, got {result}").into());
    }

    // helper_add(helper_double(21), 8)
    let mut asm = Assembler::new();
    asm.mov64_imm(R1, 21);
    asm.call(1);
    asm.mov64(R1, R0);
    asm.mov64_imm(R2, 8);
    asm.call(2);
    asm.exit();
    let result = run(asm, &vm, &[])?;
    println!("Result: {result}");
    if result != 50 {
        return Err(format!("expected 50, got {result}").into());
    }

    let mut asm = Assembler::new();
    asm.call(3);
    asm.exit();
    let result = run(asm, &vm, &[])?;
    println!("Result: 0x{result:X}");
    if result != 0xCAFEBABE {
        return Err(format!("expected 0xCAFEBABE, got 0x{result:X}").into());
    }
    Ok(())
}

/// Load `asm` as the program's `main` and call it with `args`.
fn run(mut asm: Assembler, vm: &Vm, args: &[u64]) -> Result<u64, Box<dyn std::error::Error>> {
    let image = Image::from_code(asm.assemble()?);
    Ok(vm.load(image)?.call("main", args)?)
}
