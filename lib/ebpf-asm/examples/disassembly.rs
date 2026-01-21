//! eBPF Disassembly Example
//!
//! Demonstrates how to decode eBPF bytecode back into readable instructions.
//! Shows different formatter styles and instruction inspection.
//!
//! Run with: cargo run --example disassembly

use ebpf_asm::{
    decode_all, Assembler, Decoder, DefaultFormatter, Formatter, IntelFormatter, Mnemonic, Operand, R0, R1, R10,
};

fn main() {
    println!("=== eBPF Disassembly Example ===\n");

    // Example 1: Basic disassembly with default formatter
    basic_disassembly();

    // Example 2: Intel-style formatter
    intel_style();

    // Example 3: Inspect instruction details
    inspect_instructions();

    // Example 4: Disassemble raw bytecode
    disassemble_raw();
}

/// Assemble then disassemble with default formatting
fn basic_disassembly() {
    println!("--- Example 1: Basic Disassembly ---\n");

    // First, create some bytecode
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 42);
    asm.add64(R0, R1);
    asm.ldxdw(R0, R10, -8);
    asm.exit();

    let bytecode = asm.assemble().unwrap();

    // Now disassemble it
    let formatter = DefaultFormatter::new();

    println!("Offset  Instruction");
    println!("------  -----------");
    for insn in Decoder::new(&bytecode) {
        println!("{:04x}    {}", insn.offset(), formatter.format_to_string(&insn));
    }
    println!();
}

/// Use Intel-style syntax
fn intel_style() {
    println!("--- Example 2: Intel-Style Formatting ---\n");

    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0x100);
    asm.stxdw(R10, -16, R0);
    asm.ldxw(R1, R0, 4);
    asm.exit();

    let bytecode = asm.assemble().unwrap();

    // Compare default vs Intel style
    let default_fmt = DefaultFormatter::new();
    let intel_fmt = IntelFormatter::new();

    println!("Default style:");
    for insn in Decoder::new(&bytecode) {
        println!("  {}", default_fmt.format_to_string(&insn));
    }

    println!("\nIntel style:");
    for insn in Decoder::new(&bytecode) {
        println!("  {}", intel_fmt.format_to_string(&insn));
    }
    println!();
}

/// Inspect instruction fields programmatically
fn inspect_instructions() {
    println!("--- Example 3: Instruction Inspection ---\n");

    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 42);
    asm.add64(R0, R1);
    asm.lddw(R0, 0xCAFEBABE);
    asm.exit();

    let bytecode = asm.assemble().unwrap();

    // Use decode_all for convenient vector
    let instructions = decode_all(&bytecode);

    for (i, insn) in instructions.iter().enumerate() {
        println!("Instruction {}:", i);
        println!("  Mnemonic: {:?}", insn.mnemonic);
        println!("  Size: {} bytes", insn.size);
        println!("  Offset: 0x{:04x}", insn.offset());

        // Inspect destination operand
        match &insn.dst {
            Operand::Reg(r) => println!("  Destination: register {}", r),
            Operand::None => println!("  Destination: none"),
            _ => println!("  Destination: {:?}", insn.dst),
        }

        // Inspect source operand
        match &insn.src {
            Operand::Reg(r) => println!("  Source: register {}", r),
            Operand::Imm(v) => println!("  Source: immediate 0x{:x}", v),
            Operand::Imm64(v) => println!("  Source: immediate64 0x{:x}", v),
            Operand::Mem { base, offset } => {
                println!("  Source: memory [{}{:+}]", base, offset)
            }
            Operand::Off(off) => println!("  Source: offset {:+}", off),
            Operand::None => println!("  Source: none"),
        }

        // Check for specific instruction types
        if insn.mnemonic == Mnemonic::Exit {
            println!("  (This is a program exit point)");
        }

        println!();
    }
}

/// Disassemble raw bytecode bytes
fn disassemble_raw() {
    println!("--- Example 4: Disassemble Raw Bytecode ---\n");

    // Raw eBPF bytecode for: mov64 r0, 42; exit
    let raw_bytecode: [u8; 16] = [
        0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r0, 42
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    println!("Raw bytecode:");
    for (i, byte) in raw_bytecode.iter().enumerate() {
        if i % 8 == 0 {
            print!("  {:04x}: ", i);
        }
        print!("{:02x} ", byte);
        if i % 8 == 7 {
            println!();
        }
    }

    println!("\nDisassembled:");
    let formatter = DefaultFormatter::new();
    for insn in Decoder::new(&raw_bytecode) {
        println!("  {:04x}: {}", insn.offset(), formatter.format_to_string(&insn));
    }
    println!();
}
