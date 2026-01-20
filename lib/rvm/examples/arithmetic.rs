//! Arithmetic example: Demonstrate various ALU operations.
//!
//! This example shows different arithmetic and logical operations
//! available in eBPF.
//!
//! Run with: cargo run --example arithmetic

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
    let result = run(&[insn_mov_imm(0, 100), insn_add_imm(0, 23), insn_exit()]);
    println!("ADD: 100 + 23 = {} (expected: 123)", result);
    assert_eq!(result, 123);
}

fn test_sub() {
    // r0 = 100 - 58 = 42
    let result = run(&[insn_mov_imm(0, 100), insn_sub_imm(0, 58), insn_exit()]);
    println!("SUB: 100 - 58 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_mul() {
    // r0 = 6 * 7 = 42
    let result = run(&[insn_mov_imm(0, 6), insn_mul_imm(0, 7), insn_exit()]);
    println!("MUL: 6 * 7 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_div() {
    // r0 = 84 / 2 = 42
    let result = run(&[insn_mov_imm(0, 84), insn_div_imm(0, 2), insn_exit()]);
    println!("DIV: 84 / 2 = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

fn test_bitwise() {
    // r0 = (0xFF & 0x0F) | 0x30 = 0x3F = 63
    let result = run(&[
        insn_mov_imm(0, 0xFF),
        insn_and_imm(0, 0x0F),
        insn_or_imm(0, 0x30),
        insn_exit(),
    ]);
    println!("BITWISE: (0xFF & 0x0F) | 0x30 = {} (expected: 63)", result);
    assert_eq!(result, 63);

    // XOR: 0xFF ^ 0xAA = 0x55 = 85
    let result = run(&[insn_mov_imm(0, 0xFF), insn_xor_imm(0, 0xAA), insn_exit()]);
    println!("XOR: 0xFF ^ 0xAA = {} (expected: 85)", result);
    assert_eq!(result, 85);
}

fn test_shift() {
    // r0 = 1 << 5 = 32
    let result = run(&[insn_mov_imm(0, 1), insn_lsh_imm(0, 5), insn_exit()]);
    println!("LSH: 1 << 5 = {} (expected: 32)", result);
    assert_eq!(result, 32);

    // r0 = 256 >> 3 = 32
    let result = run(&[insn_mov_imm(0, 256), insn_rsh_imm(0, 3), insn_exit()]);
    println!("RSH: 256 >> 3 = {} (expected: 32)", result);
    assert_eq!(result, 32);
}

fn test_neg() {
    // r0 = -(-42) = 42
    let result = run(&[insn_mov_imm(0, -42), insn_neg(0), insn_exit()]);
    println!("NEG: -(-42) = {} (expected: 42)", result);
    assert_eq!(result, 42);
}

// ============================================================================
// Runner
// ============================================================================

fn run(insns: &[u64]) -> u64 {
    let program: Vec<u8> = insns.iter().flat_map(|i| i.to_le_bytes()).collect();
    let mut memory = VmMemory::new(program.len() + 512);
    memory.write_bytes(0, &program).unwrap();

    let helpers = rvm::HelperRegistry::new();
    let mut executor = rvm::Executor::new(&mut memory, &helpers, (program.len() + 512) as u64);
    executor.call(0, &[]).unwrap()
}

// ============================================================================
// Instruction builders
// ============================================================================

fn insn_mov_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0xb7, dst, imm) // MOV
}

fn insn_add_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x07, dst, imm) // ADD
}

fn insn_sub_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x17, dst, imm) // SUB
}

fn insn_mul_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x27, dst, imm) // MUL
}

fn insn_div_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x37, dst, imm) // DIV
}

fn insn_or_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x47, dst, imm) // OR
}

fn insn_and_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x57, dst, imm) // AND
}

fn insn_lsh_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x67, dst, imm) // LSH
}

fn insn_rsh_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0x77, dst, imm) // RSH
}

fn insn_xor_imm(dst: u8, imm: i32) -> u64 {
    alu64_imm(0xa7, dst, imm) // XOR
}

fn insn_neg(dst: u8) -> u64 {
    alu64_imm(0x87, dst, 0) // NEG
}

fn alu64_imm(opc: u8, dst: u8, imm: i32) -> u64 {
    let opc = opc as u64;
    let dst = (dst as u64) << 8;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | imm
}

fn insn_exit() -> u64 {
    0x95
}
