//! Runs hand-assembled bytecode, loaded as an `Image` without ELF or linker.
//!
//! Run with: cargo run -p rvm --example hello

use ebpf_asm::{Assembler, R0, R1};
use rvm::{FunctionInfo, Image, Vm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // r0 = r1 + 10
    let mut asm = Assembler::new();
    asm.mov64(R0, R1);
    asm.add64_imm(R0, 10);
    asm.exit();

    let code = asm.assemble()?;
    let main = FunctionInfo {
        pc: 0,
        size: code.len() as u64,
        borrows: Vec::new(),
    };
    let image = Image {
        code,
        functions: vec![("main".into(), main)],
        ..Image::default()
    };
    let mut program = Vm::new().load(image)?;
    let result = program.call("main", &[32])?;

    println!("32 + 10 = {result}");
    if result != 42 {
        return Err(format!("expected 42, got {result}").into());
    }
    Ok(())
}
