//! Decodes eBPF bytecode and prints it with `DefaultFormatter`, and inspects the
//! decoded fields.
//!
//! Run with: cargo run --example disassembly

use ebpf_asm::{decode_all, Assembler, Decoder, DefaultFormatter, Mnemonic, Operand, R0, R1, R10};

fn main() {
    println!("=== eBPF Disassembly Example ===\n");

    basic_disassembly();
    with_raw_bytes();
    inspect_instructions();
    disassemble_raw();
}

/// Assemble a program, then disassemble it.
fn basic_disassembly() {
    println!("--- Example 1: Basic Disassembly ---\n");

    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 42);
    asm.add64(R0, R1);
    asm.ldxdw(R0, R10, -8);
    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let formatter = DefaultFormatter::new();

    println!("Offset  Instruction");
    println!("------  -----------");
    for insn in Decoder::new(&bytecode) {
        let offset = insn.offset;
        println!("{offset:04x}    {}", formatter.format_to_string(&insn));
    }
    println!();
}

/// Compare the default formatter with raw bytes enabled.
fn with_raw_bytes() {
    println!("--- Example 2: Formatter with Raw Bytes ---\n");

    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0x100);
    asm.stxdw(R10, -16, R0);
    asm.ldxw(R1, R0, 4);
    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let default_fmt = DefaultFormatter::new();
    let bytes_fmt = DefaultFormatter::new().with_bytes();

    println!("Default:");
    for insn in Decoder::new(&bytecode) {
        println!("  {}", default_fmt.format_to_string(&insn));
    }

    println!("\nWith raw bytes:");
    for insn in Decoder::new(&bytecode) {
        println!("  {}", bytes_fmt.format_to_string(&insn));
    }
    println!();
}

/// Inspect decoded instruction fields.
fn inspect_instructions() {
    println!("--- Example 3: Instruction Inspection ---\n");

    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 42);
    asm.add64(R0, R1);
    asm.lddw(R0, 0xCAFEBABE);
    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let instructions = decode_all(&bytecode);

    for (i, insn) in instructions.iter().enumerate() {
        println!("Instruction {i}:");
        println!("  Mnemonic: {:?}", insn.mnemonic);
        let size = insn.size;
        let offset = insn.offset;
        println!("  Size: {size} bytes");
        println!("  Offset: 0x{offset:04x}");

        match &insn.dst {
            Operand::Reg(r) => println!("  Destination: register {r}"),
            Operand::None => println!("  Destination: none"),
            _ => println!("  Destination: {:?}", insn.dst),
        }

        match &insn.src {
            Operand::Reg(r) => println!("  Source: register {r}"),
            Operand::Imm(v) => println!("  Source: immediate 0x{v:x}"),
            Operand::Imm64(v) => println!("  Source: immediate64 0x{v:x}"),
            Operand::Mem { base, offset } => {
                println!("  Source: memory [{base}{offset:+}]")
            }
            Operand::Off(off) => println!("  Source: offset {off:+}"),
            Operand::None => println!("  Source: none"),
        }

        if insn.mnemonic == Mnemonic::Exit {
            println!("  (This is a program exit point)");
        }

        println!();
    }
}

/// Disassemble hand-written bytecode.
fn disassemble_raw() {
    println!("--- Example 4: Disassemble Raw Bytecode ---\n");

    let raw_bytecode: [u8; 16] = [
        0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r0, 42
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    println!("Raw bytecode:");
    for (i, byte) in raw_bytecode.iter().enumerate() {
        if i % 8 == 0 {
            print!("  {i:04x}: ");
        }
        print!("{byte:02x} ");
        if i % 8 == 7 {
            println!();
        }
    }

    println!("\nDisassembled:");
    let formatter = DefaultFormatter::new();
    for insn in Decoder::new(&raw_bytecode) {
        let offset = insn.offset;
        println!("  {offset:04x}: {}", formatter.format_to_string(&insn));
    }
    println!();
}
