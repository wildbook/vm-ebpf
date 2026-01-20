//! Arithmetic example: Demonstrate various ALU operations.
//!
//! This example shows different arithmetic and logical operations
//! available in eBPF.
//!
//! Run with: cargo run --example arithmetic

use ebpf_asm::{Assembler, R0};
use rvm::VmMemory;

fn main() {
    println!("=== Arithmetic Operations ===\n");

    // Test various operations
    test_add();
    test_sub();
    test_mul();
    test_div();
    test_bitwise();
    test_shift();
    test_neg();

    println!("All tests passed!");
}

fn test_add() {
    // r0 = 100 + 23 = 123
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 100).unwrap();
    asm.add64_imm(R0, 23).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("ADD: 100 + 23 = {} (expected: 123)", result);
    assert_eq!(result, 123);
}

fn test_sub() {
    // r0 = 100 - 58 = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 100).unwrap();
    asm.sub64_imm(R0, 58).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("SUB: 100 - 58 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_mul() {
    // r0 = 6 * 7 = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 6).unwrap();
    asm.mul64_imm(R0, 7).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("MUL: 6 * 7 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_div() {
    // r0 = 84 / 2 = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 84).unwrap();
    asm.div64_imm(R0, 2).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("DIV: 84 / 2 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_bitwise() {
    // r0 = (0xFF & 0x0F) | 0x30 = 0x3F = 63
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0xFF).unwrap();
    asm.and64_imm(R0, 0x0F).unwrap();
    asm.or64_imm(R0, 0x30).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("BITWISE: (0xFF & 0x0F) | 0x30 = {} (expected: 63)", result);
    assert_eq!(result, 63);

    // XOR: 0xFF ^ 0xAA = 0x55 = 85
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0xFF).unwrap();
    asm.xor64_imm(R0, 0xAA).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("XOR: 0xFF ^ 0xAA = {} (expected: 85)", result);
    assert_eq!(result, 85);
}

fn test_shift() {
    // r0 = 1 << 5 = 32
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 1).unwrap();
    asm.lsh64_imm(R0, 5).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("LSH: 1 << 5 = {} (expected: 32)", result);
    assert_eq!(result, 32);

    // r0 = 256 >> 3 = 32
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 256).unwrap();
    asm.rsh64_imm(R0, 3).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("RSH: 256 >> 3 = {} (expected: 32)", result);
    assert_eq!(result, 32);
}

fn test_neg() {
    // r0 = -(-42) = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, -42).unwrap();
    asm.neg64(R0).unwrap();
    asm.exit().unwrap();

    let result = run(&mut asm);
    println!("NEG: -(-42) = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

// ============================================================================
// Runner
// ============================================================================

fn run(asm: &mut Assembler) -> u64 {
    let program = asm.assemble().unwrap();
    let mut memory = VmMemory::new(program.len() + 512);
    memory.write_bytes(0, &program).unwrap();

    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&mut memory, &helpers, (program.len() + 512) as u64);
    executor.call(0, &[]).unwrap()
}
