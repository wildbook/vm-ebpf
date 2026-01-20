//! Memory access example: Read and write memory from eBPF.
//!
//! This example demonstrates load/store operations with different sizes.
//!
//! Run with: cargo run --example memory

use rvm::VmMemory;

fn main() {
    println!("=== Memory Access ===\n");

    test_store_load_byte();
    test_store_load_half();
    test_store_load_word();
    test_store_load_dword();
    test_memory_with_offset();

    println!("All tests passed!");
}

fn test_store_load_byte() {
    // Store byte and load it back
    // r1 = data_ptr, store 0x42 at [r1], load it to r0
    let result = run_with_data(&[
        insn_mov_imm(2, 0x42), // r2 = 0x42
        insn_stxb(1, 0, 2),    // *(u8*)(r1+0) = r2
        insn_ldxb(0, 1, 0),    // r0 = *(u8*)(r1+0)
        insn_exit(),
    ]);
    println!("BYTE: store 0x42, load = 0x{:02X} (expected: 0x42)", result);
    assert_eq!(result, 0x42);
}

fn test_store_load_half() {
    // Store halfword (16-bit)
    let result = run_with_data(&[
        insn_mov_imm(2, 0x1234),
        insn_stxh(1, 0, 2), // *(u16*)(r1+0) = r2
        insn_ldxh(0, 1, 0), // r0 = *(u16*)(r1+0)
        insn_exit(),
    ]);
    println!("HALF: store 0x1234, load = 0x{:04X} (expected: 0x1234)", result);
    assert_eq!(result, 0x1234);
}

fn test_store_load_word() {
    // Store word (32-bit)
    let result = run_with_data(&[
        insn_mov_imm(2, 0x12345678u32 as i32),
        insn_stxw(1, 0, 2), // *(u32*)(r1+0) = r2
        insn_ldxw(0, 1, 0), // r0 = *(u32*)(r1+0)
        insn_exit(),
    ]);
    println!("WORD: store 0x12345678, load = 0x{:08X} (expected: 0x12345678)", result);
    assert_eq!(result, 0x12345678);
}

fn test_store_load_dword() {
    // Store doubleword (64-bit) using LD_IMM64
    // LD_IMM64 takes TWO 8-byte instruction slots
    let imm: u64 = 0xDEADBEEFCAFEBABE;
    let (first, second) = insn_ld_imm64_pair(2, imm);

    let result = run_with_data(&[
        first,               // LD_IMM64 first half
        second,              // LD_IMM64 second half (imm_hi)
        insn_stxdw(1, 0, 2), // *(u64*)(r1+0) = r2
        insn_ldxdw(0, 1, 0), // r0 = *(u64*)(r1+0)
        insn_exit(),
    ]);
    println!("DWORD: store 0xDEADBEEFCAFEBABE, load = 0x{:016X}", result);
    assert_eq!(result, 0xDEADBEEFCAFEBABE);
}

fn test_memory_with_offset() {
    // Store at offset and load back
    let result = run_with_data(&[
        insn_mov_imm(2, 0xAA),
        insn_stxb(1, 5, 2), // *(u8*)(r1+5) = r2
        insn_mov_imm(2, 0xBB),
        insn_stxb(1, 10, 2), // *(u8*)(r1+10) = r2
        insn_ldxb(0, 1, 5),  // r0 = *(u8*)(r1+5)
        insn_ldxb(3, 1, 10), // r3 = *(u8*)(r1+10)
        insn_add_reg(0, 3),  // r0 += r3
        insn_exit(),
    ]);
    println!("OFFSET: [5]=0xAA, [10]=0xBB, sum = 0x{:02X} (expected: 0x165)", result);
    assert_eq!(result, 0xAA + 0xBB);
}

// ============================================================================
// Runner with data area
// ============================================================================

fn run_with_data(insns: &[u64]) -> u64 {
    let program: Vec<u8> = insns.iter().flat_map(|i| i.to_le_bytes()).collect();

    // Layout: [code][gap][data area][stack]
    let code_size = program.len();
    let data_offset = ((code_size + 7) / 8) * 8 + 64; // Align and add gap
    let data_size = 128;
    let stack_size = 512;
    let total_size = data_offset + data_size + stack_size;

    let mut memory = VmMemory::new(total_size);
    memory.write_bytes(0, &program).unwrap();

    let helpers = rvm::HelperRegistry::new();
    let stack_top = total_size as u64;
    let mut executor = rvm::Executor::new(&mut memory, &helpers, stack_top);

    // Pass data area pointer in r1
    executor.call(0, &[data_offset as u64]).unwrap()
}

// ============================================================================
// Instruction builders
// ============================================================================

fn insn_mov_imm(dst: u8, imm: i32) -> u64 {
    let opc = 0xb7u64;
    let dst = (dst as u64) << 8;
    let imm = ((imm as u32) as u64) << 32;
    opc | dst | imm
}

fn insn_add_reg(dst: u8, src: u8) -> u64 {
    let opc = 0x0fu64; // ALU64 | ADD | SRC_REG
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    opc | dst | src
}

/// LD_IMM64 - loads 64-bit immediate (takes 2 instruction slots)
/// Returns (first_insn, second_insn) - both must be emitted in order
fn insn_ld_imm64_pair(dst: u8, imm: u64) -> (u64, u64) {
    // First instruction: opcode 0x18 (LD | IMM | DW), dst, src=0, off=0, imm_lo
    let opc = 0x18u64; // LD | IMM | DW
    let dst_bits = (dst as u64) << 8;
    let imm_lo = ((imm as u32) as u64) << 32;
    let first = opc | dst_bits | imm_lo;

    // Second instruction: imm_hi in the imm field (other fields are 0)
    let imm_hi = ((imm >> 32) as u32 as u64) << 32;
    let second = imm_hi; // opcode=0, dst=0, src=0, off=0, imm=imm_hi

    (first, second)
}

// Store instructions: STX = store from register
fn insn_stxb(dst: u8, off: i16, src: u8) -> u64 {
    stx(0x73, dst, off, src) // STX | MEM | B
}

fn insn_stxh(dst: u8, off: i16, src: u8) -> u64 {
    stx(0x6b, dst, off, src) // STX | MEM | H
}

fn insn_stxw(dst: u8, off: i16, src: u8) -> u64 {
    stx(0x63, dst, off, src) // STX | MEM | W
}

fn insn_stxdw(dst: u8, off: i16, src: u8) -> u64 {
    stx(0x7b, dst, off, src) // STX | MEM | DW
}

fn stx(opc: u8, dst: u8, off: i16, src: u8) -> u64 {
    let opc = opc as u64;
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    let off = ((off as u16) as u64) << 16;
    opc | dst | src | off
}

// Load instructions: LDX = load to register
fn insn_ldxb(dst: u8, src: u8, off: i16) -> u64 {
    ldx(0x71, dst, src, off) // LDX | MEM | B
}

fn insn_ldxh(dst: u8, src: u8, off: i16) -> u64 {
    ldx(0x69, dst, src, off) // LDX | MEM | H
}

fn insn_ldxw(dst: u8, src: u8, off: i16) -> u64 {
    ldx(0x61, dst, src, off) // LDX | MEM | W
}

fn insn_ldxdw(dst: u8, src: u8, off: i16) -> u64 {
    ldx(0x79, dst, src, off) // LDX | MEM | DW
}

fn ldx(opc: u8, dst: u8, src: u8, off: i16) -> u64 {
    let opc = opc as u64;
    let dst = (dst as u64) << 8;
    let src = (src as u64) << 12;
    let off = ((off as u16) as u64) << 16;
    opc | dst | src | off
}

fn insn_exit() -> u64 {
    0x95
}
