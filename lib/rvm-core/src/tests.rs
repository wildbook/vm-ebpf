//! Single-instruction semantics of [`step`], with the edge cases the eBPF spec (RFC 9669) defines.

use std::ops::ControlFlow;

use crate::opcode::{AluEnd, AluOpc, JmpOpc, MemMode, MemSize, OpCode, Source};
use crate::{step, step_ld64, Context, Flow, Instruction, Memory};

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
        mem.data[offset..][..bytes.len()].copy_from_slice(bytes);
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

fn instr(opc: OpCode, dst: u8, src: u8, off: i16, imm: i32) -> Instruction {
    Instruction::from_parts(opc, dst, src, off, imm)
}

fn exec(ctx: &mut Context<TestMem>, instruction: Instruction) -> Flow<TestMem> {
    match step(ctx, instruction) {
        ControlFlow::Break(flow) => flow,
        ControlFlow::Continue(_) => panic!("unexpected LD_IMM64 first half"),
    }
}

fn exec_ld64(ctx: &mut Context<TestMem>, first: Instruction, second: Instruction) -> Flow<TestMem> {
    match step(ctx, first) {
        ControlFlow::Continue(_) => {
            step_ld64(ctx, first, second);
            Flow::Next
        }
        ControlFlow::Break(flow) => flow,
    }
}

#[test]
fn alu_edges() {
    // (dst register's initial value, opcode, off, imm, expected result)
    for (dst_in, opc, off, imm, want) in [
        (100u64, AluOpc::div_64(Source::Imm), 0, 0, 0u64), // div by zero returns 0
        (i64::MIN as u64, AluOpc::div_64(Source::Imm), 1, -1, i64::MIN as u64), // MIN / -1 avoids overflow
        (17u64, AluOpc::mod_64(Source::Imm), 0, 0, 17u64), // mod by zero leaves dst unchanged
        ((-13i64) as u64, AluOpc::mod_64(Source::Imm), 1, 3, (-1i64) as u64), // smod (off=1), truncated division
        (1u64, AluOpc::lsh_64(Source::Imm), 0, 64, 1u64),  // shift amount masked to 0 (64 & 63)
        (999u64, AluOpc::mov_64(Source::Imm), 0, -1, u64::MAX), // imm sign-extended to 64 bits
        (0xFFFF_FFFF_0000_0064, AluOpc::add_32(Source::Imm), 0, 50, 150u64), // upper 32 bits zeroed
        (0xFFFF_FFFF, AluOpc::add_32(Source::Imm), 0, 1, 0u64), // 32-bit wrap, zero-extended
        (1u64, AluOpc::lsh_32(Source::Imm), 0, 32, 1u64),  // shift amount masked to 0 (32 & 31)
        (0x8000_0000, AluOpc::arsh_32(Source::Imm), 0, 31, 0xFFFF_FFFF), // sign extended within 32 bits
    ] {
        let mut ctx = Context::new(TestMem::new());
        ctx.regs[0] = dst_in;
        assert!(matches!(exec(&mut ctx, instr(opc, 0, 0, off, imm)), Flow::Next));
        assert_eq!(ctx.regs[0], want, "{opc:?} off={off} imm={imm}");
    }

    // ALU32 with a register source truncates to the lower 32 bits, then zero-extends.
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[0] = 0xDEAD_BEEF_CAFE_BABE;
    ctx.regs[1] = 0x1234_5678_9ABC_DEF0;
    assert!(matches!(exec(&mut ctx, instr(AluOpc::mov_32(Source::Reg), 0, 1, 0, 0)), Flow::Next));
    assert_eq!(ctx.regs[0], 0x9ABC_DEF0);
}

#[test]
fn jmp_conditions() {
    // (dst register value, opcode, off, imm, whether the jump is taken)
    for (reg, opc, off, imm, taken) in [
        (1u64, OpCode::jmp64_from_parts(JmpOpc::Jsgt, Source::Imm), 5, -1, true), // imm sign-extended
        // JMP32 compares the lower 32 bits
        (0xDEAD_BEEF_0000_002A, OpCode::jmp32_from_parts(JmpOpc::Jeq, Source::Imm), 5, 42, true),
        // -1 > -2 signed 32-bit
        (0x0000_0000_FFFF_FFFF, OpCode::jmp32_from_parts(JmpOpc::Jsgt, Source::Imm), 5, -2, true),
    ] {
        let mut ctx = Context::new(TestMem::new());
        ctx.regs[0] = reg;
        match exec(&mut ctx, instr(opc, 0, 0, off, imm)) {
            Flow::Jump(got) if taken => assert_eq!(got, off as i64),
            Flow::Next if !taken => {}
            other => panic!("{opc:?} off={off} imm={imm}: expected taken={taken}, got {other:?}"),
        }
    }

    // JMP32 JA uses the imm field for the offset, not the 16-bit offset field.
    let mut ctx = Context::new(TestMem::new());
    let i = instr(OpCode::jmp32_from_parts(JmpOpc::Ja, Source::Imm), 0, 0, 99, 12345);
    assert!(matches!(exec(&mut ctx, i), Flow::Jump(12345)));

    // CALL distinguishes a helper call (src=0, imm is the helper id) from a local call (src=1, imm is the branch
    // offset).
    let mut ctx = Context::new(TestMem::new());
    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Call, Source::Imm), 0, 0, 0, 1);
    assert!(matches!(exec(&mut ctx, i), Flow::CallHelper(1)));
    let i = instr(OpCode::jmp64_from_parts(JmpOpc::Call, Source::Imm), 0, 1, 0, 5);
    assert!(matches!(exec(&mut ctx, i), Flow::Call(5)));
}

#[test]
fn load_store_sizes() {
    for (size, bytes, want) in [
        (MemSize::Byte, &[0xABu8][..], 0xABu64),
        (MemSize::Half, &[0x34, 0x12][..], 0x1234u64),
        (MemSize::Word, &[0x78, 0x56, 0x34, 0x12][..], 0x1234_5678u64),
        (MemSize::DWord, &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12][..], 0x1234_5678_9ABC_DEF0u64),
    ] {
        let mut ctx = Context::new(TestMem::with_data(100, bytes));
        ctx.regs[1] = 100;
        let i = instr(OpCode::ldreg_from_parts(size, MemMode::Mem), 0, 1, 0, 0);
        assert!(matches!(exec(&mut ctx, i), Flow::Next));
        assert_eq!(ctx.regs[0], want, "{size:?} load");

        let mut ctx = Context::new(TestMem::new());
        ctx.regs[1] = 100;
        ctx.regs[2] = want;
        let i = instr(OpCode::streg_from_parts(size, MemMode::Mem), 1, 2, 0, 0);
        assert!(matches!(exec(&mut ctx, i), Flow::Next));
        assert_eq!(&ctx.data.data[100..][..bytes.len()], bytes, "{size:?} store");
    }

    // ST stores an immediate value instead of a register.
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;
    let i = instr(OpCode::stimm_from_parts(MemSize::Word, MemMode::Mem), 1, 0, 0, 0x1234_5678u32 as i32);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(&ctx.data.data[100..104], &[0x78, 0x56, 0x34, 0x12]);

    // Non-zero offsets address base + off, for loads and stores alike.
    let mut ctx = Context::new(TestMem::with_data(110, &[0xCD]));
    ctx.regs[1] = 100;
    let i = instr(OpCode::ldreg_from_parts(MemSize::Byte, MemMode::Mem), 0, 1, 10, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0xCD);

    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 100;
    ctx.regs[2] = 0xEF;
    let i = instr(OpCode::streg_from_parts(MemSize::Byte, MemMode::Mem), 1, 2, 20, 0);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.data.data[120], 0xEF);
}

#[test]
fn load_acquire_zero_extends() {
    let mut ctx = Context::new(TestMem::with_data(100, &[0x80, 0x7F]));
    ctx.regs[0] = u64::MAX;
    ctx.regs[1] = 100;
    let i = instr(OpCode::streg_from_parts(MemSize::Byte, MemMode::Atomic), 0, 1, 0, 0x100);
    assert!(matches!(exec(&mut ctx, i), Flow::Next));
    assert_eq!(ctx.regs[0], 0x80);
}

#[test]
fn ld_imm64() {
    let mut ctx = Context::new(TestMem::new());

    let first = instr(OpCode(0x18), 0, 0, 0, 0xDEADBEEFu32 as i32);
    let second = instr(OpCode(0x00), 0, 0, 0, 0x12345678u32 as i32);

    assert!(matches!(exec_ld64(&mut ctx, first, second), Flow::Next));
    assert_eq!(ctx.regs[0], 0x12345678_DEADBEEF);

    // a pseudo load (map fd and the like) stops at its first slot
    let pseudo = instr(OpCode(0x18), 0, 1, 0, 7);
    assert!(matches!(exec(&mut ctx, pseudo), Flow::Missing));
}

#[test]
fn reserved_encodings() {
    for opc in [
        OpCode::jmp32_from_parts(JmpOpc::Call, Source::Imm),
        OpCode::jmp32_from_parts(JmpOpc::Exit, Source::Imm),
        OpCode::jmp64_from_parts(JmpOpc::Exit, Source::Reg),
        OpCode::jmp32_from_parts(JmpOpc::Ja, Source::Reg),
        OpCode::ldreg_from_parts(MemSize::DWord, MemMode::MemSX),
        OpCode::ldreg_from_parts(MemSize::Word, MemMode::Imm),
        OpCode::ldreg_from_parts(MemSize::Word, MemMode::Abs),
        OpCode::ldreg_from_parts(MemSize::Word, MemMode::Ind),
        OpCode::ldreg_from_parts(MemSize::Word, MemMode::Atomic),
        OpCode::stimm_from_parts(MemSize::Word, MemMode::Imm),
        OpCode::stimm_from_parts(MemSize::Word, MemMode::Abs),
        OpCode::streg_from_parts(MemSize::Word, MemMode::Ind),
    ] {
        let mut ctx = Context::new(TestMem::new());
        assert!(matches!(exec(&mut ctx, instr(opc, 0, 1, 0, 1)), Flow::FailCpu), "{opc:?}");
    }
}

#[test]
fn mem_fault() {
    // (base address in r1, offset) pairs that must fault for both loads and stores.
    for (addr, off) in [
        (10000u64, 0i16), // out of bounds
        (0u64, -8i16),    // 0 - 8 wraps to a huge address
    ] {
        let mut ctx = Context::new(TestMem::new());
        ctx.regs[1] = addr;
        let load = instr(OpCode::ldreg_from_parts(MemSize::Byte, MemMode::Mem), 0, 1, off, 0);
        assert!(matches!(exec(&mut ctx, load), Flow::FailMem(())), "load at {addr}+{off}");

        let mut ctx = Context::new(TestMem::new());
        ctx.regs[1] = addr;
        ctx.regs[2] = 0xFF;
        let store = instr(OpCode::streg_from_parts(MemSize::Byte, MemMode::Mem), 1, 2, off, 0);
        assert!(matches!(exec(&mut ctx, store), Flow::FailMem(())), "store at {addr}+{off}");
    }
}

#[test]
fn alu32_imm_is_unsigned_32bit() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 0xFFFF_FFFF;
    exec(&mut ctx, instr(AluOpc::div_32(Source::Imm), 1, 0, 0, -1));
    assert_eq!(ctx.regs[1], 1);

    ctx.regs[1] = 0xFFFF_FFFF;
    exec(&mut ctx, instr(AluOpc::mod_32(Source::Imm), 1, 0, 0, -1));
    assert_eq!(ctx.regs[1], 0);
}

#[test]
fn jmp32_unsigned_compare_negative_imm() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[1] = 0xFFFF_FFFF;
    let jeq = instr(OpCode::jmp32_from_parts(JmpOpc::Jeq, Source::Imm), 1, 0, 3, -1);
    assert!(matches!(exec(&mut ctx, jeq), Flow::Jump(3)));
    let jgt = instr(OpCode::jmp32_from_parts(JmpOpc::Jgt, Source::Imm), 1, 0, 3, -2);
    assert!(matches!(exec(&mut ctx, jgt), Flow::Jump(3)));
}

#[test]
fn movsx() {
    let mut ctx = Context::new(TestMem::new());
    ctx.regs[2] = 0x1234_5678_8000_8080;
    for (off, want) in [
        (8, 0xFFFF_FFFF_FFFF_FF80),
        (16, 0xFFFF_FFFF_FFFF_8080),
        (32, 0xFFFF_FFFF_8000_8080),
    ] {
        exec(&mut ctx, instr(AluOpc::mov_64(Source::Reg), 1, 2, off, 0));
        assert_eq!(ctx.regs[1], want, "movsx64 off={off}");
    }
    // ALU32: sign-extend to 32 bits, then zero-extend.
    exec(&mut ctx, instr(AluOpc::mov_32(Source::Reg), 1, 2, 8, 0));
    assert_eq!(ctx.regs[1], 0xFFFF_FF80);
    // Reserved: ALU32 offset 32, immediate source.
    assert!(matches!(exec(&mut ctx, instr(AluOpc::mov_32(Source::Reg), 1, 2, 32, 0)), Flow::FailCpu));
    assert!(matches!(exec(&mut ctx, instr(AluOpc::mov_64(Source::Imm), 1, 0, 8, 1)), Flow::FailCpu));
}

#[test]
fn bswap_and_endianness() {
    let v = 0x1122_3344_5566_7788;
    for (input, opc, imm, want) in [
        (v, AluOpc::end_64(AluEnd::ToLE), 16, 0x8877),
        (v, AluOpc::end_64(AluEnd::ToLE), 32, 0x8877_6655),
        (v, AluOpc::end_64(AluEnd::ToLE), 64, 0x8877_6655_4433_2211),
        (v, AluOpc::end_32(AluEnd::ToLE), 16, 0x7788),
        (v, AluOpc::end_32(AluEnd::ToLE), 64, v),
        (v, AluOpc::end_32(AluEnd::ToBE), 32, 0x8877_6655),
        (0x1234, AluOpc::end_32(AluEnd::ToBE), 16, 0x3412),
        (0x1234_5678_9ABC_DEF0, AluOpc::end_32(AluEnd::ToBE), 64, 0xF0DE_BC9A_7856_3412),
    ] {
        let mut ctx = Context::new(TestMem::new());
        ctx.regs[1] = input;
        exec(&mut ctx, instr(opc, 1, 0, 0, imm));
        assert_eq!(ctx.regs[1], want, "{opc:?} imm={imm}");
    }
    let mut ctx = Context::new(TestMem::new());
    assert!(matches!(exec(&mut ctx, instr(AluOpc::end_64(AluEnd::ToBE), 1, 0, 0, 16)), Flow::FailCpu));
}
