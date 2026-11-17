//! Assembles a few small eBPF programs and prints their bytecode.
//!
//! Run with: cargo run --example basic_assembly

use ebpf_asm::{Assembler, R0, R1, R10, R2, R3};

fn main() {
    println!("=== Basic eBPF Assembly Example ===\n");

    simple_arithmetic();
    memory_operations();
    load_immediate();
    bitwise_operations();
}

/// Compute (10 + 5) * 2 = 30
fn simple_arithmetic() {
    println!("--- Example 1: Simple Arithmetic ---");
    println!("Computing (10 + 5) * 2 = 30\n");

    let mut asm = Assembler::new();

    // r0 = 10
    asm.mov64_imm(R0, 10);

    // r0 = r0 + 5 = 15
    asm.add64_imm(R0, 5);

    // r0 = r0 * 2 = 30
    asm.mul64_imm(R0, 2);

    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let len = bytecode.len();
    println!("Generated {len} bytes of bytecode:");
    print_bytecode(&bytecode);
    println!();
}

/// Store a value to the stack and load it back.
fn memory_operations() {
    println!("--- Example 2: Memory Operations ---");
    println!("Store value to stack and load it back\n");

    let mut asm = Assembler::new();

    // r1 = 0x12345678
    asm.mov64_imm(R1, 0x12345678);

    // r10 is the read-only frame pointer
    asm.stxdw(R10, -8, R1);

    // r0 = *(u64 *)(r10 - 8)
    asm.ldxdw(R0, R10, -8);

    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let len = bytecode.len();
    println!("Generated {len} bytes of bytecode:");
    print_bytecode(&bytecode);
    println!();
}

/// Load a full 64-bit immediate.
fn load_immediate() {
    println!("--- Example 3: 64-bit Immediate Loading ---");
    println!("Loading 0xDEADBEEFCAFEBABE into r0\n");

    let mut asm = Assembler::new();

    asm.lddw(R0, 0xDEADBEEFCAFEBABEu64 as i64);

    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let len = bytecode.len();
    println!("Generated {len} bytes of bytecode:");
    println!("(Note: lddw is a 16-byte wide instruction)\n");
    print_bytecode(&bytecode);
    println!();
}

/// AND, OR and a logical right shift.
fn bitwise_operations() {
    println!("--- Example 4: Bitwise Operations ---");
    println!("Extract bits using AND, shift with LSH/RSH\n");

    let mut asm = Assembler::new();

    // r0 = 0xFF00FF00
    asm.mov64_imm(R0, 0xFF00FF00u32 as i32);

    // r1 = 0x00FF00FF
    asm.mov64_imm(R1, 0x00FF00FF);

    // r2 = r0 & r1 = 0x00000000
    asm.mov64(R2, R0);
    asm.and64(R2, R1);

    // r3 = r0 | r1 = 0xFFFFFFFF
    asm.mov64(R3, R0);
    asm.or64(R3, R1);

    // r0 = r0 >> 8 (logical right shift)
    asm.rsh64_imm(R0, 8);

    asm.exit();

    let bytecode = asm.assemble().unwrap();

    let len = bytecode.len();
    println!("Generated {len} bytes of bytecode:");
    print_bytecode(&bytecode);
    println!();
}

/// Print bytecode one 8-byte slot per line.
fn print_bytecode(bytecode: &[u8]) {
    for (i, chunk) in bytecode.chunks(8).enumerate() {
        let offset = i * 8;
        print!("  {offset:04x}: ");
        for byte in chunk {
            print!("{byte:02x} ");
        }
        println!();
    }
}
