//! Assembles a few small eBPF programs and prints their bytecode.
//!
//! Run with: cargo run --example basic_assembly

use ebpf_asm::{AsmError, Assembler, R0, R1, R10, R2, R3};

fn main() -> Result<(), AsmError> {
    simple_arithmetic()?;
    memory_operations()?;
    load_immediate()?;
    bitwise_operations()
}

/// (10 + 5) * 2
fn simple_arithmetic() -> Result<(), AsmError> {
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 10);
    asm.add64_imm(R0, 5);
    asm.mul64_imm(R0, 2);
    asm.exit();
    print_program("(10 + 5) * 2", &asm.assemble()?);
    Ok(())
}

/// Store a value to the stack and load it back.
fn memory_operations() -> Result<(), AsmError> {
    let mut asm = Assembler::new();
    asm.mov64_imm(R1, 0x12345678);
    asm.stxdw(R10, -8, R1); // r10 is the read-only frame pointer
    asm.ldxdw(R0, R10, -8);
    asm.exit();
    print_program("store to the stack and load back", &asm.assemble()?);
    Ok(())
}

/// Load a full 64-bit immediate; `lddw` takes two 8-byte slots.
fn load_immediate() -> Result<(), AsmError> {
    let mut asm = Assembler::new();
    asm.lddw(R0, 0xDEADBEEFCAFEBABEu64 as i64);
    asm.exit();
    print_program("lddw r0, 0xDEADBEEFCAFEBABE", &asm.assemble()?);
    Ok(())
}

/// AND, OR and a logical right shift.
fn bitwise_operations() -> Result<(), AsmError> {
    let mut asm = Assembler::new();
    // the 32-bit move zero-extends; `mov64_imm` would sign-extend to 0xFFFFFFFF_FF00FF00
    asm.mov32_imm(R0, 0xFF00FF00u32 as i32);
    asm.mov64_imm(R1, 0x00FF00FF);
    asm.mov64(R2, R0);
    asm.and64(R2, R1); // 0x00000000
    asm.mov64(R3, R0);
    asm.or64(R3, R1); // 0xFFFFFFFF
    asm.rsh64_imm(R0, 8); // 0x00FF00FF
    asm.exit();
    print_program("AND, OR and RSH", &asm.assemble()?);
    Ok(())
}

/// Print bytecode one 8-byte slot per line.
fn print_program(title: &str, bytecode: &[u8]) {
    let len = bytecode.len();
    println!("{title}: {len} bytes");
    for (i, chunk) in bytecode.chunks(8).enumerate() {
        let offset = i * 8;
        print!("  {offset:04x}: ");
        for byte in chunk {
            print!("{byte:02x} ");
        }
        println!();
    }
    println!();
}
