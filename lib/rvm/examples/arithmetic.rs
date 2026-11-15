//! Arithmetic example: Demonstrate various ALU operations.
//!
//! This example shows different arithmetic and logical operations
//! available in eBPF.
//!
//! Run with: cargo run --example arithmetic

use ebpf_asm::{Assembler, R0};
use rvm::{Perms, VmMemory};

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
    asm.mov64_imm(R0, 100);
    asm.add64_imm(R0, 23);
    asm.exit();

    let result = run(&mut asm);
    println!("ADD: 100 + 23 = {} (expected: 123)", result);
    assert_eq!(result, 123);
}

fn test_sub() {
    // r0 = 100 - 58 = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 100);
    asm.sub64_imm(R0, 58);
    asm.exit();

    let result = run(&mut asm);
    println!("SUB: 100 - 58 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_mul() {
    // r0 = 6 * 7 = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 6);
    asm.mul64_imm(R0, 7);
    asm.exit();

    let result = run(&mut asm);
    println!("MUL: 6 * 7 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_div() {
    // r0 = 84 / 2 = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 84);
    asm.div64_imm(R0, 2);
    asm.exit();

    let result = run(&mut asm);
    println!("DIV: 84 / 2 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_bitwise() {
    // r0 = (0xFF & 0x0F) | 0x30 = 0x3F = 63
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0xFF);
    asm.and64_imm(R0, 0x0F);
    asm.or64_imm(R0, 0x30);
    asm.exit();

    let result = run(&mut asm);
    println!("BITWISE: (0xFF & 0x0F) | 0x30 = {} (expected: 63)", result);
    assert_eq!(result, 63);

    // XOR: 0xFF ^ 0xAA = 0x55 = 85
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0xFF);
    asm.xor64_imm(R0, 0xAA);
    asm.exit();

    let result = run(&mut asm);
    println!("XOR: 0xFF ^ 0xAA = {} (expected: 85)", result);
    assert_eq!(result, 85);
}

fn test_shift() {
    // r0 = 1 << 5 = 32
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 1);
    asm.lsh64_imm(R0, 5);
    asm.exit();

    let result = run(&mut asm);
    println!("LSH: 1 << 5 = {} (expected: 32)", result);
    assert_eq!(result, 32);

    // r0 = 256 >> 3 = 32
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 256);
    asm.rsh64_imm(R0, 3);
    asm.exit();

    let result = run(&mut asm);
    println!("RSH: 256 >> 3 = {} (expected: 32)", result);
    assert_eq!(result, 32);
}

fn test_neg() {
    // r0 = -(-42) = 42
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, -42);
    asm.neg64(R0);
    asm.exit();

    let result = run(&mut asm);
    println!("NEG: -(-42) = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

// ============================================================================
// Runner
// ============================================================================

fn run(asm: &mut Assembler) -> u64 {
    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);
    let mut memory = VmMemory::new();
    let stack_top = memory.map(rvm::STACK_REGION, 512, Perms::RW) + 512;

    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&code, &mut memory, &helpers, stack_top);
    executor.call(0, &[]).unwrap()
}
