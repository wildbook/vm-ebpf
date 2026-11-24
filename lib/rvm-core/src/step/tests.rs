//! Single-instruction semantics of [`step`], with the edge cases the eBPF spec (RFC 9669) defines.

use super::{ld_imm64, step, Step};
use crate::opcode::{call, AluEnd, AluOpc, JmpOpc, MemMode, MemSize, OpCode, Source, LD_IMM64};
use crate::{Instruction, Memory, Reason};

const INVALID: Step<()> = Step::Stop(Reason::InvalidInstruction);

/// Registers and 4096 bytes of memory at address 0.
struct Machine {
    regs: [u64; 16],
    memory: TestMem,
}

struct TestMem {
    data: [u8; 4096],
}

// SAFETY: the default `window` reports no windows
unsafe impl Memory for TestMem {
    type Error = ();

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Error> {
        self.data.get(addr as usize).copied().ok_or(())
    }

    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Error> {
        *self.data.get_mut(addr as usize).ok_or(())? = value;
        Ok(())
    }

    fn native_ptr(&self, _: u64, _: u64, _: bool) -> Result<u64, ()> {
        Err(())
    }
}

impl Machine {
    fn new() -> Self {
        Self {
            regs: [0; 16],
            memory: TestMem { data: [0; 4096] },
        }
    }

    fn with_data(offset: usize, bytes: &[u8]) -> Self {
        let mut machine = Self::new();
        machine.memory.data[offset..][..bytes.len()].copy_from_slice(bytes);
        machine
    }

    fn exec(&mut self, insn: Instruction) -> Step<()> {
        step(&mut self.regs, &mut self.memory, insn)
    }

    fn exec_ld_imm64(&mut self, first: Instruction, second: Instruction) -> Step<()> {
        match self.exec(first) {
            Step::LdImm64 => {
                ld_imm64(&mut self.regs, first, second.imm());
                Step::Next
            }
            step => step,
        }
    }
}

fn instr(opc: OpCode, dst: u8, src: u8, off: i16, imm: i32) -> Instruction {
    Instruction::new(opc, dst, src, off, imm)
}

#[test]
fn alu_edges() {
    let (alu32, alu64) = (OpCode::alu32, OpCode::alu64);
    // (dst register's initial value, opcode, off, imm, expected result)
    for (dst_in, opc, off, imm, want) in [
        (100u64, alu64(AluOpc::Div, Source::Imm), 0, 0, 0u64), // div by zero returns 0
        (i64::MIN as u64, alu64(AluOpc::Div, Source::Imm), 1, -1, i64::MIN as u64), // MIN / -1 avoids overflow
        (17u64, alu64(AluOpc::Mod, Source::Imm), 0, 0, 17u64), // mod by zero leaves dst unchanged
        ((-13i64) as u64, alu64(AluOpc::Mod, Source::Imm), 1, 3, (-1i64) as u64), // smod (off=1), truncated division
        (1u64, alu64(AluOpc::Lsh, Source::Imm), 0, 64, 1u64),  // shift amount masked to 0 (64 & 63)
        (999u64, alu64(AluOpc::Mov, Source::Imm), 0, -1, u64::MAX), // imm sign-extended to 64 bits
        (0xFFFF_FFFF_0000_0064, alu32(AluOpc::Add, Source::Imm), 0, 50, 150u64), // upper 32 bits zeroed
        (0xFFFF_FFFF, alu32(AluOpc::Add, Source::Imm), 0, 1, 0u64), // 32-bit wrap, zero-extended
        (1u64, alu32(AluOpc::Lsh, Source::Imm), 0, 32, 1u64),  // shift amount masked to 0 (32 & 31)
        (0x8000_0000, alu32(AluOpc::Arsh, Source::Imm), 0, 31, 0xFFFF_FFFF), // sign extended within 32 bits
    ] {
        let mut m = Machine::new();
        m.regs[0] = dst_in;
        assert_eq!(m.exec(instr(opc, 0, 0, off, imm)), Step::Next);
        assert_eq!(m.regs[0], want, "{opc:?} off={off} imm={imm}");
    }

    // ALU32 with a register source truncates to the lower 32 bits, then zero-extends.
    let mut m = Machine::new();
    m.regs[0] = 0xDEAD_BEEF_CAFE_BABE;
    m.regs[1] = 0x1234_5678_9ABC_DEF0;
    assert_eq!(m.exec(instr(alu32(AluOpc::Mov, Source::Reg), 0, 1, 0, 0)), Step::Next);
    assert_eq!(m.regs[0], 0x9ABC_DEF0);
}

#[test]
fn jmp_conditions() {
    // (dst register value, opcode, off, imm, whether the jump is taken)
    for (reg, opc, off, imm, taken) in [
        (1u64, OpCode::jmp64(JmpOpc::Jsgt, Source::Imm), 5, -1, true), // imm sign-extended
        // JMP32 compares the lower 32 bits
        (0xDEAD_BEEF_0000_002A, OpCode::jmp32(JmpOpc::Jeq, Source::Imm), 5, 42, true),
        // -1 > -2 signed 32-bit
        (0x0000_0000_FFFF_FFFF, OpCode::jmp32(JmpOpc::Jsgt, Source::Imm), 5, -2, true),
    ] {
        let mut m = Machine::new();
        m.regs[0] = reg;
        let want = if taken { Step::Jump(off as i64) } else { Step::Next };
        assert_eq!(m.exec(instr(opc, 0, 0, off, imm)), want, "{opc:?} off={off} imm={imm}");
    }

    // JMP32 JA uses the imm field for the offset, not the 16-bit offset field.
    let mut m = Machine::new();
    assert_eq!(m.exec(instr(OpCode::jmp32(JmpOpc::Ja, Source::Imm), 0, 0, 99, 12345)), Step::Jump(12345));

    // CALL distinguishes a helper call (imm is the helper id) from a local call (imm is the branch offset).
    let call = OpCode::jmp64(JmpOpc::Call, Source::Imm);
    assert_eq!(m.exec(instr(call, 0, call::HELPER, 0, 1)), Step::CallHelper);
    assert_eq!(m.exec(instr(call, 0, call::LOCAL, 0, 5)), Step::Call(5));
}

#[test]
fn load_store_sizes() {
    for (size, bytes, want) in [
        (MemSize::Byte, &[0xABu8][..], 0xABu64),
        (MemSize::Half, &[0x34, 0x12][..], 0x1234u64),
        (MemSize::Word, &[0x78, 0x56, 0x34, 0x12][..], 0x1234_5678u64),
        (MemSize::DWord, &[0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12][..], 0x1234_5678_9ABC_DEF0u64),
    ] {
        let mut m = Machine::with_data(100, bytes);
        m.regs[1] = 100;
        assert_eq!(m.exec(instr(OpCode::ldx(size, MemMode::Mem), 0, 1, 0, 0)), Step::Next);
        assert_eq!(m.regs[0], want, "{size:?} load");

        let mut m = Machine::new();
        m.regs[1] = 100;
        m.regs[2] = want;
        assert_eq!(m.exec(instr(OpCode::stx(size, MemMode::Mem), 1, 2, 0, 0)), Step::Next);
        assert_eq!(&m.memory.data[100..][..bytes.len()], bytes, "{size:?} store");
    }

    // ST stores an immediate value instead of a register.
    let mut m = Machine::new();
    m.regs[1] = 100;
    let st = instr(OpCode::st(MemSize::Word, MemMode::Mem), 1, 0, 0, 0x1234_5678u32 as i32);
    assert_eq!(m.exec(st), Step::Next);
    assert_eq!(&m.memory.data[100..104], &[0x78, 0x56, 0x34, 0x12]);

    // Non-zero offsets address base + off, for loads and stores alike.
    let mut m = Machine::with_data(110, &[0xCD]);
    m.regs[1] = 100;
    assert_eq!(m.exec(instr(OpCode::ldx(MemSize::Byte, MemMode::Mem), 0, 1, 10, 0)), Step::Next);
    assert_eq!(m.regs[0], 0xCD);

    let mut m = Machine::new();
    m.regs[1] = 100;
    m.regs[2] = 0xEF;
    assert_eq!(m.exec(instr(OpCode::stx(MemSize::Byte, MemMode::Mem), 1, 2, 20, 0)), Step::Next);
    assert_eq!(m.memory.data[120], 0xEF);
}

#[test]
fn load_acquire_zero_extends() {
    let mut m = Machine::with_data(100, &[0x80, 0x7F]);
    m.regs[0] = u64::MAX;
    m.regs[1] = 100;
    assert_eq!(m.exec(instr(OpCode::stx(MemSize::Byte, MemMode::Atomic), 0, 1, 0, 0x100)), Step::Next);
    assert_eq!(m.regs[0], 0x80);
}

#[test]
fn ld_imm64_halves() {
    let mut m = Machine::new();

    let first = instr(OpCode(LD_IMM64), 0, 0, 0, 0xDEADBEEFu32 as i32);
    let second = instr(OpCode(0x00), 0, 0, 0, 0x12345678u32 as i32);

    assert_eq!(m.exec_ld_imm64(first, second), Step::Next);
    assert_eq!(m.regs[0], 0x12345678_DEADBEEF);

    // a pseudo load (map fd and the like) stops at its first slot
    let pseudo = instr(OpCode(LD_IMM64), 0, 1, 0, 7);
    assert_eq!(m.exec(pseudo), Step::Stop(Reason::Unsupported));
}

#[test]
fn reserved_encodings() {
    for opc in [
        OpCode::jmp32(JmpOpc::Call, Source::Imm),
        OpCode::jmp32(JmpOpc::Exit, Source::Imm),
        OpCode::jmp64(JmpOpc::Exit, Source::Reg),
        OpCode::jmp32(JmpOpc::Ja, Source::Reg),
        OpCode::ldx(MemSize::DWord, MemMode::MemSX),
        OpCode::ldx(MemSize::Word, MemMode::Imm),
        OpCode::ldx(MemSize::Word, MemMode::Abs),
        OpCode::ldx(MemSize::Word, MemMode::Ind),
        OpCode::ldx(MemSize::Word, MemMode::Atomic),
        OpCode::st(MemSize::Word, MemMode::Imm),
        OpCode::st(MemSize::Word, MemMode::Abs),
        OpCode::stx(MemSize::Word, MemMode::Ind),
    ] {
        assert_eq!(Machine::new().exec(instr(opc, 0, 1, 0, 1)), INVALID, "{opc:?}");
    }
}

#[test]
fn may_goto() {
    // the kernel verifier accepts only JMP | JCOND | K with `dst_reg`, `src_reg` and `imm` 0 (`src_reg` 1 is the
    // newer `unwind_goto`); the jump is never taken
    let k = OpCode::jmp64(JmpOpc::Jcond, Source::Imm);
    let mut m = Machine::new();
    assert_eq!(m.exec(instr(k, 0, 0, 5, 0)), Step::Next);
    for insn in [
        instr(k, 1, 0, 5, 0),
        instr(k, 0, 1, 5, 0),
        instr(k, 0, 0, 5, 1),
        instr(OpCode::jmp64(JmpOpc::Jcond, Source::Reg), 0, 0, 5, 0),
        instr(OpCode::jmp32(JmpOpc::Jcond, Source::Imm), 0, 0, 5, 0),
    ] {
        assert_eq!(m.exec(insn), INVALID, "{insn:?}");
    }
}

#[test]
fn alu32_imm_is_unsigned_32bit() {
    let mut m = Machine::new();
    m.regs[1] = 0xFFFF_FFFF;
    m.exec(instr(OpCode::alu32(AluOpc::Div, Source::Imm), 1, 0, 0, -1));
    assert_eq!(m.regs[1], 1);

    m.regs[1] = 0xFFFF_FFFF;
    m.exec(instr(OpCode::alu32(AluOpc::Mod, Source::Imm), 1, 0, 0, -1));
    assert_eq!(m.regs[1], 0);
}

#[test]
fn jmp32_unsigned_compare_negative_imm() {
    let mut m = Machine::new();
    m.regs[1] = 0xFFFF_FFFF;
    assert_eq!(m.exec(instr(OpCode::jmp32(JmpOpc::Jeq, Source::Imm), 1, 0, 3, -1)), Step::Jump(3));
    assert_eq!(m.exec(instr(OpCode::jmp32(JmpOpc::Jgt, Source::Imm), 1, 0, 3, -2)), Step::Jump(3));
}

#[test]
fn movsx() {
    let (alu32, alu64) = (OpCode::alu32, OpCode::alu64);
    let mut m = Machine::new();
    m.regs[2] = 0x1234_5678_8000_8080;
    for (off, want) in [
        (8, 0xFFFF_FFFF_FFFF_FF80),
        (16, 0xFFFF_FFFF_FFFF_8080),
        (32, 0xFFFF_FFFF_8000_8080),
    ] {
        m.exec(instr(alu64(AluOpc::Mov, Source::Reg), 1, 2, off, 0));
        assert_eq!(m.regs[1], want, "movsx64 off={off}");
    }
    // ALU32: sign-extend to 32 bits, then zero-extend.
    m.exec(instr(alu32(AluOpc::Mov, Source::Reg), 1, 2, 8, 0));
    assert_eq!(m.regs[1], 0xFFFF_FF80);
    // Reserved: ALU32 offset 32, immediate source.
    assert_eq!(m.exec(instr(alu32(AluOpc::Mov, Source::Reg), 1, 2, 32, 0)), INVALID);
    assert_eq!(m.exec(instr(alu64(AluOpc::Mov, Source::Imm), 1, 0, 8, 1)), INVALID);
}

#[test]
fn bswap_and_endianness() {
    let (end32, end64) = (OpCode::end32, OpCode::end64);
    let v = 0x1122_3344_5566_7788;
    for (input, opc, imm, want) in [
        (v, end64(AluEnd::ToLE), 16, 0x8877),
        (v, end64(AluEnd::ToLE), 32, 0x8877_6655),
        (v, end64(AluEnd::ToLE), 64, 0x8877_6655_4433_2211),
        (v, end32(AluEnd::ToLE), 16, 0x7788),
        (v, end32(AluEnd::ToLE), 64, v),
        (v, end32(AluEnd::ToBE), 32, 0x8877_6655),
        (0x1234, end32(AluEnd::ToBE), 16, 0x3412),
        (0x1234_5678_9ABC_DEF0, end32(AluEnd::ToBE), 64, 0xF0DE_BC9A_7856_3412),
    ] {
        let mut m = Machine::new();
        m.regs[1] = input;
        m.exec(instr(opc, 1, 0, 0, imm));
        assert_eq!(m.regs[1], want, "{opc:?} imm={imm}");
    }
    assert_eq!(Machine::new().exec(instr(end64(AluEnd::ToBE), 1, 0, 0, 16)), INVALID);
}
