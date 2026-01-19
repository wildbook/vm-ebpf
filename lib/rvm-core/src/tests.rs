//! Comprehensive test harness for eBPF instruction execution.
//!
//! Tests each supported instruction with various inputs to verify correct behavior.

use std::ops::ControlFlow;

use crate::opcode::{AluEnd, AluOpc, JmpOpc, MemMode, MemSize, OpCode, Source};
use crate::{step, step_ld64, Context, Flow, Instruction, Memory, OpCode as OC};

/// Simple memory implementation for testing
#[derive(Debug)]
struct TestMem {
    data: [u8; 4096],
}

impl TestMem {
    fn new() -> Self {
        Self { data: [0; 4096] }
    }

    fn with_data(offset: usize, bytes: &[u8]) -> Self {
        let mut mem = Self::new();
        mem.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        mem
    }
}

impl Memory for TestMem {
    type Err = ();

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Err> {
        self.data.get(addr as usize).copied().ok_or(())
    }

    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
        if (addr as usize) < self.data.len() {
            self.data[addr as usize] = value;
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Helper to create an instruction from parts
fn instr(opc: OpCode, dst: u8, src: u8, off: i16, imm: i32) -> Instruction {
    Instruction::from_parts(opc, dst, src, off, imm)
}

/// Execute a single instruction and return the result
fn exec(ctx: &mut Context<TestMem>, instruction: Instruction) -> Flow<TestMem> {
    match step(ctx, instruction) {
        ControlFlow::Break(flow) => flow,
        ControlFlow::Continue(_) => panic!("Unexpected LD_IMM64 first half"),
    }
}

/// Execute a LD_IMM64 instruction pair
fn exec_ld64(ctx: &mut Context<TestMem>, first: Instruction, second: Instruction) -> Flow<TestMem> {
    match step(ctx, first) {
        ControlFlow::Continue(_) => step_ld64(ctx, first, second),
        ControlFlow::Break(flow) => flow,
    }
}

// ============================================================================
// ALU64 Tests (64-bit arithmetic)
// ============================================================================

#[test]
fn test_alu64_add_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;

    let i = instr(AluOpc::add_64(Source::Imm), 0, 0, 0, 50);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 150);
}

#[test]
fn test_alu64_add_reg() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;
    ctx.regs[1] = 50;

    let i = instr(AluOpc::add_64(Source::Reg), 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 150);
}

#[test]
fn test_alu64_add_overflow() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = u64::MAX;

    let i = instr(AluOpc::add_64(Source::Imm), 0, 0, 0, 1);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0); // wraps around
}

#[test]
fn test_alu64_sub_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;

    let i = instr(AluOpc::sub_64(Source::Imm), 0, 0, 0, 30);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 70);
}

#[test]
fn test_alu64_sub_underflow() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0;

    let i = instr(AluOpc::sub_64(Source::Imm), 0, 0, 0, 1);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], u64::MAX); // wraps around
}

#[test]
fn test_alu64_mul_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 7;

    let i = instr(AluOpc::mul_64(Source::Imm), 0, 0, 0, 6);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 42);
}

#[test]
fn test_alu64_div_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;

    let i = instr(AluOpc::div_64(Source::Imm), 0, 0, 0, 10);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 10);
}

#[test]
fn test_alu64_div_by_zero() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;

    let i = instr(AluOpc::div_64(Source::Imm), 0, 0, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0); // div by zero returns 0
}

#[test]
fn test_alu64_sdiv_positive() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;

    // SDIV uses offset=1
    let i = instr(AluOpc::div_64(Source::Imm), 0, 0, 1, 10);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 10);
}

#[test]
fn test_alu64_sdiv_negative() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = (-100i64) as u64;

    // SDIV: -100 / 10 = -10
    let i = instr(AluOpc::div_64(Source::Imm), 0, 0, 1, 10);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0] as i64, -10);
}

#[test]
fn test_alu64_sdiv_min_by_neg1() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = i64::MIN as u64;

    // SDIV: LLONG_MIN / -1 = LLONG_MIN (special case to avoid overflow)
    let i = instr(AluOpc::div_64(Source::Imm), 0, 0, 1, -1);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0] as i64, i64::MIN);
}

#[test]
fn test_alu64_mod_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 17;

    let i = instr(AluOpc::mod_64(Source::Imm), 0, 0, 0, 5);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 2);
}

#[test]
fn test_alu64_mod_by_zero() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 17;

    let i = instr(AluOpc::mod_64(Source::Imm), 0, 0, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 17); // mod by zero returns dst unchanged
}

#[test]
fn test_alu64_smod_negative() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = (-13i64) as u64;

    // SMOD: -13 % 3 = -1 (truncated division)
    let i = instr(AluOpc::mod_64(Source::Imm), 0, 0, 1, 3);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0] as i64, -1);
}

#[test]
fn test_alu64_or() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0b1010;
    ctx.regs[1] = 0b1100;

    let i = instr(AluOpc::or_64(Source::Reg), 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0b1110);
}

#[test]
fn test_alu64_and() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0b1010;
    ctx.regs[1] = 0b1100;

    let i = instr(AluOpc::and_64(Source::Reg), 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0b1000);
}

#[test]
fn test_alu64_xor() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0b1010;
    ctx.regs[1] = 0b1100;

    let i = instr(AluOpc::xor_64(Source::Reg), 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0b0110);
}

#[test]
fn test_alu64_lsh() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 1;

    let i = instr(AluOpc::lsh_64(Source::Imm), 0, 0, 0, 32);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 1u64 << 32);
}

#[test]
fn test_alu64_lsh_mask() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 1;

    // Shift by 64 should be masked to 0 (64 & 63 = 0)
    let i = instr(AluOpc::lsh_64(Source::Imm), 0, 0, 0, 64);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 1); // no shift
}

#[test]
fn test_alu64_rsh() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x8000_0000_0000_0000;

    let i = instr(AluOpc::rsh_64(Source::Imm), 0, 0, 0, 63);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 1); // logical shift, no sign extension
}

#[test]
fn test_alu64_arsh() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x8000_0000_0000_0000; // negative in signed

    let i = instr(AluOpc::arsh_64(Source::Imm), 0, 0, 0, 63);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], u64::MAX); // sign extended
}

#[test]
fn test_alu64_neg() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 42;

    let i = instr(AluOpc::neg_64(Source::Imm), 0, 0, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0] as i64, -42);
}

#[test]
fn test_alu64_mov_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 999;

    let i = instr(AluOpc::mov_64(Source::Imm), 0, 0, 0, 42);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 42);
}

#[test]
fn test_alu64_mov_imm_negative() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 999;

    // MOV with negative imm should sign-extend to 64 bits
    let i = instr(AluOpc::mov_64(Source::Imm), 0, 0, 0, -1);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], u64::MAX); // -1 sign-extended
}

#[test]
fn test_alu64_mov_reg() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 999;
    ctx.regs[1] = 0x1234_5678_9ABC_DEF0;

    let i = instr(AluOpc::mov_64(Source::Reg), 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x1234_5678_9ABC_DEF0);
}

// ============================================================================
// ALU32 Tests (32-bit arithmetic with zero extension)
// ============================================================================

#[test]
fn test_alu32_add_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0xFFFF_FFFF_0000_0064; // upper bits set, lower = 100

    let i = instr(AluOpc::add_32(Source::Imm), 0, 0, 0, 50);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 150); // upper 32 bits zeroed
}

#[test]
fn test_alu32_add_overflow() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0xFFFF_FFFF;

    let i = instr(AluOpc::add_32(Source::Imm), 0, 0, 0, 1);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0); // 32-bit wrap, zero-extended
}

#[test]
fn test_alu32_lsh() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 1;

    // 32-bit shift by 31
    let i = instr(AluOpc::lsh_32(Source::Imm), 0, 0, 0, 31);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x8000_0000);
}

#[test]
fn test_alu32_lsh_mask() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 1;

    // Shift by 32 should be masked to 0 (32 & 31 = 0)
    let i = instr(AluOpc::lsh_32(Source::Imm), 0, 0, 0, 32);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 1); // no shift
}

#[test]
fn test_alu32_arsh() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x8000_0000; // negative in 32-bit signed

    let i = instr(AluOpc::arsh_32(Source::Imm), 0, 0, 0, 31);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0xFFFF_FFFF); // sign extended within 32 bits, then zero-extended to 64
}

#[test]
fn test_alu32_mov_reg() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0xDEAD_BEEF_CAFE_BABE;
    ctx.regs[1] = 0x1234_5678_9ABC_DEF0;

    let i = instr(AluOpc::mov_32(Source::Reg), 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x9ABC_DEF0); // lower 32 bits, zero-extended
}

#[test]
fn test_alu32_sdiv() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = (-100i32) as u32 as u64;

    // SDIV32: -100 / 10 = -10
    let i = instr(AluOpc::div_32(Source::Imm), 0, 0, 1, 10);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    // Result is -10 as i32, zero-extended to u64
    assert_eq!(ctx.regs[0], (-10i32) as u32 as u64);
}

// ============================================================================
// Byte Swap Tests
// ============================================================================

#[test]
fn test_end_le16() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x1234;

    let i = instr(AluOpc::end_32(AluEnd::ToLE), 0, 0, 0, 16);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    // On little-endian, this is a no-op for the value
    assert_eq!(ctx.regs[0] & 0xFFFF, 0x1234u16.to_le() as u64);
}

#[test]
fn test_end_be16() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x1234;

    let i = instr(AluOpc::end_32(AluEnd::ToBE), 0, 0, 0, 16);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x1234u16.to_be() as u64);
}

#[test]
fn test_end_be32() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x12345678;

    let i = instr(AluOpc::end_32(AluEnd::ToBE), 0, 0, 0, 32);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x12345678u32.to_be() as u64);
}

#[test]
fn test_end_be64() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0x123456789ABCDEF0;

    let i = instr(AluOpc::end_32(AluEnd::ToBE), 0, 0, 0, 64);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x123456789ABCDEF0u64.to_be());
}

// ============================================================================
// JMP64 Tests (64-bit jumps)
// ============================================================================

#[test]
fn test_jmp64_ja() {
    let mut ctx = Context::new(TestMem::new());

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Ja, Source::Imm), 0, 0, 5, 0);
    match exec(&mut ctx, i) {
        Flow::Jump(off) => assert_eq!(off, 5),
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_ja_negative() {
    let mut ctx = Context::new(TestMem::new());

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Ja, Source::Imm), 0, 0, -3, 0);
    match exec(&mut ctx, i) {
        Flow::Jump(off) => assert_eq!(off, -3),
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jeq_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 42;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jeq, Source::Imm), 0, 0, 10, 42);
    match exec(&mut ctx, i) {
        Flow::Jump(off) => assert_eq!(off, 10),
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jeq_not_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 42;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jeq, Source::Imm), 0, 0, 10, 43);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
}

#[test]
fn test_jmp64_jgt_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 100;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jgt, Source::Imm), 0, 0, 5, 50);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jgt_not_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 50;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jgt, Source::Imm), 0, 0, 5, 100);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
}

#[test]
fn test_jmp64_jge_equal() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 50;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jge, Source::Imm), 0, 0, 5, 50);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jlt_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 10;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jlt, Source::Imm), 0, 0, 5, 50);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jle_equal() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 50;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jle, Source::Imm), 0, 0, 5, 50);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jne_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 42;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jne, Source::Imm), 0, 0, 5, 43);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jset_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0b1010;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jset, Source::Imm), 0, 0, 5, 0b1000);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jset_not_taken() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0b1010;

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jset, Source::Imm), 0, 0, 5, 0b0100);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
}

#[test]
fn test_jmp64_jsgt_signed() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 1; // positive

    // Compare 1 > -1 (signed)
    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jsgt, Source::Imm), 0, 0, 5, -1);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_jslt_signed() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = (-10i64) as u64;

    // Compare -10 < -5 (signed)
    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Jslt, Source::Imm), 0, 0, 5, -5);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp64_exit() {
    let mut ctx = Context::new(TestMem::new());

    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Exit));
}

#[test]
fn test_jmp64_call_helper() {
    let mut ctx = Context::new(TestMem::new());

    // Call helper function with static ID (src_reg = 0)
    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Call, Source::Imm), 0, 0, 0, 1);
    match exec(&mut ctx, i) {
        Flow::CallExt(id) => assert_eq!(id, 1),
        other => panic!("Expected CallExt, got {:?}", other),
    }
}

#[test]
fn test_jmp64_call_local() {
    let mut ctx = Context::new(TestMem::new());

    // Call program-local function (src_reg = 1)
    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Call, Source::Imm), 0, 1, 0, 5);
    match exec(&mut ctx, i) {
        Flow::Call(off) => assert_eq!(off, 5),
        other => panic!("Expected Call, got {:?}", other),
    }
}

// ============================================================================
// JMP32 Tests (32-bit comparisons)
// ============================================================================

#[test]
fn test_jmp32_ja_uses_imm() {
    let mut ctx = Context::new(TestMem::new());

    // JMP32 JA uses imm field (32-bit offset), not offset field
    let i = instr(OpCode::jmp32_from_parts(JmpOpc::Ja, Source::Imm), 0, 0, 99, 12345);
    match exec(&mut ctx, i) {
        Flow::Jump(off) => assert_eq!(off, 12345), // uses imm, not offset
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp32_jeq_32bit_comparison() {
    let mut ctx = Context::new(TestMem::new());
    // Upper bits differ, but lower 32 bits match
    ctx.regs[0] = 0xDEAD_BEEF_0000_002A;

    let i = instr(OpCode::jmp32_from_parts(JmpOpc::Jeq, Source::Imm), 0, 0, 5, 42);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {} // Should match on lower 32 bits
        other => panic!("Expected Jump, got {:?}", other),
    }
}

#[test]
fn test_jmp32_jsgt_signed_32bit() {
    let mut ctx = Context::new(TestMem::new());
    // 0xFFFFFFFF as u32 = -1 as i32
    ctx.regs[0] = 0x0000_0000_FFFF_FFFF;

    // -1 > -2 in signed 32-bit
    let i = instr(OpCode::jmp32_from_parts(JmpOpc::Jsgt, Source::Imm), 0, 0, 5, -2);
    match exec(&mut ctx, i) {
        Flow::Jump(_) => {}
        other => panic!("Expected Jump, got {:?}", other),
    }
}

// ============================================================================
// Memory Load Tests
// ============================================================================

#[test]
fn test_ldx_b() {
    let mut ctx = Context::new(TestMem::with_data(100, &[0xAB]));
    ctx.regs[1] = 100;

    let opc = OpCode::ldreg_from_parts(MemSize::Byte, MemMode::Mem);
    let i = instr(opc, 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0xAB);
}

#[test]
fn test_ldx_h() {
    let mut ctx = Context::new(TestMem::with_data(100, &[0x34, 0x12]));
    ctx.regs[1] = 100;

    let opc = OpCode::ldreg_from_parts(MemSize::Half, MemMode::Mem);
    let i = instr(opc, 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x1234);
}

#[test]
fn test_ldx_w() {
    let mut ctx = Context::new(TestMem::with_data(100, &[0x78, 0x56, 0x34, 0x12]));
    ctx.regs[1] = 100;

    let opc = OpCode::ldreg_from_parts(MemSize::Word, MemMode::Mem);
    let i = instr(opc, 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x12345678);
}

#[test]
fn test_ldx_dw() {
    let mut ctx = Context::new(TestMem::with_data(100, &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]));
    ctx.regs[1] = 100;

    let opc = OpCode::ldreg_from_parts(MemSize::DWord, MemMode::Mem);
    let i = instr(opc, 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x123456789ABCDEF0);
}

#[test]
fn test_ldx_with_offset() {
    let mut ctx = Context::new(TestMem::with_data(110, &[0xCD]));
    ctx.regs[1] = 100;

    let opc = OpCode::ldreg_from_parts(MemSize::Byte, MemMode::Mem);
    let i = instr(opc, 0, 1, 10, 0); // offset = 10
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0xCD);
}

// ============================================================================
// Memory Store Tests
// ============================================================================

#[test]
fn test_stx_b() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100; // address
    ctx.regs[2] = 0xAB; // value

    let opc = OpCode::streg_from_parts(MemSize::Byte, MemMode::Mem);
    let i = instr(opc, 1, 2, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.data.data[100], 0xAB);
}

#[test]
fn test_stx_h() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;
    ctx.regs[2] = 0x1234;

    let opc = OpCode::streg_from_parts(MemSize::Half, MemMode::Mem);
    let i = instr(opc, 1, 2, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.data.data[100], 0x34);
    assert_eq!(ctx.data.data[101], 0x12);
}

#[test]
fn test_stx_w() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;
    ctx.regs[2] = 0x12345678;

    let opc = OpCode::streg_from_parts(MemSize::Word, MemMode::Mem);
    let i = instr(opc, 1, 2, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(&ctx.data.data[100..104], &[0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn test_stx_dw() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;
    ctx.regs[2] = 0x123456789ABCDEF0;

    let opc = OpCode::streg_from_parts(MemSize::DWord, MemMode::Mem);
    let i = instr(opc, 1, 2, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(&ctx.data.data[100..108], &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn test_st_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;

    let opc = OpCode::stimm_from_parts(MemSize::Word, MemMode::Mem);
    let i = instr(opc, 1, 0, 0, 0x12345678u32 as i32);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(&ctx.data.data[100..104], &[0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn test_stx_with_offset() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;
    ctx.regs[2] = 0xEF;

    let opc = OpCode::streg_from_parts(MemSize::Byte, MemMode::Mem);
    let i = instr(opc, 1, 2, 20, 0); // offset = 20
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.data.data[120], 0xEF);
}

// ============================================================================
// LD_IMM64 Tests
// ============================================================================

#[test]
fn test_ld_imm64() {
    let mut ctx = Context::new(TestMem::new());

    // LD_IMM64: opcode = 0x18 (LD | IMM | DW)
    let first = Instruction::from_parts(OC(0x18), 0, 0, 0, 0xDEADBEEFu32 as i32);
    let second = Instruction::from_parts(OC(0x00), 0, 0, 0, 0x12345678u32 as i32);

    assert!(matches!(exec_ld64(&mut ctx, first, second), Flow::Next));
    assert_eq!(ctx.regs[0], 0x12345678_DEADBEEF);
}

#[test]
fn test_ld_imm64_to_different_reg() {
    let mut ctx = Context::new(TestMem::new());

    let first = Instruction::from_parts(OC(0x18), 5, 0, 0, 0x11111111u32 as i32);
    let second = Instruction::from_parts(OC(0x00), 0, 0, 0, 0x22222222u32 as i32);

    assert!(matches!(exec_ld64(&mut ctx, first, second), Flow::Next));
    assert_eq!(ctx.regs[5], 0x22222222_11111111);
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

#[test]
fn test_memory_out_of_bounds_load() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 10000; // out of bounds

    let opc = OpCode::ldreg_from_parts(MemSize::Byte, MemMode::Mem);
    let i = instr(opc, 0, 1, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::FailMem(())));
}

#[test]
fn test_memory_out_of_bounds_store() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 10000; // out of bounds
    ctx.regs[2] = 0xFF;

    let opc = OpCode::streg_from_parts(MemSize::Byte, MemMode::Mem);
    let i = instr(opc, 1, 2, 0, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::FailMem(())));
}

#[test]
fn test_all_registers() {
    // Verify operations work with all 11 registers (r0-r10)
    for reg in 0..=10u8 {
        let mut ctx = Context::new(TestMem::new());
        ctx.regs[reg as usize] = 100;

        let i = instr(AluOpc::add_64(Source::Imm), reg, 0, 0, 50);
        assert!(matches!(exec(&mut ctx, i), Flow::Next));
        assert_eq!(ctx.regs[reg as usize], 150, "Failed for register r{}", reg);
    }
}
