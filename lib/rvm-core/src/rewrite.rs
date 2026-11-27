//! The first pass of [`Code::new`](crate::Code::new): gives each instruction that can't run as it stands the opcode
//! byte of what it does instead.
//!
//! - An instruction that always runs the same gets its [`canonical`] byte.
//! - An instruction that would write r10, or that sets a field the kernel verifier reserves, gets [`INVALID`].
//! - A pseudo LD_IMM64 gets [`MISSING`], and a `mov` from a register with an offset its MOVSX byte.
//! - An 8-byte load or store through r11 gets the byte of the stack argument it loads or stores ([`args`]), or
//!   [`INVALID`] if its offset names none. In code with such a store, every `callx` gets [`args::CALLX`].
//!
//! Only opcode bytes change. The pass tests each instruction against one entry of [`REWRITES`], and most pass
//! without a call.

use crate::bytes::{canonical, INVALID, LDX_DW, MISSING, MOV32_REG, MOV64_REG, MOVSX32, MOVSX64, STX_DW, ST_DW};
use crate::context::FP;
use crate::handler::{CALL_HELPER, CALL_KFUNC, TO_GUEST, TO_HOST};
use crate::opcode::atomic::{CMPXCHG, FETCH, LOAD_ACQ};
use crate::opcode::{call, AluOpc, Class, JmpOpc, MemMode, OpCode, Source, CALL, CALLX, LD_IMM64};
use crate::{args, Instruction};

/// `imm` of `addr_space_cast` (`MOV64_REG` with `offset = 1`): `dst_as << 16 | src_as`.
const ADDR_SPACE_TO_HOST: i32 = 1 << 16;
const ADDR_SPACE_TO_GUEST: i32 = 1;

/// Runs the pass on `code`.
pub fn rewrite(code: &mut [Instruction]) {
    let mut stores = false;
    for i in 0..code.len() {
        let insn = code[i];
        let rewrite = &REWRITES[usize::from(insn.byte())];
        // most instructions pass all three tests
        if insn.0 & rewrite.screen != 0 || insn.dst_reg() == rewrite.dst || insn.src_reg() == rewrite.src {
            stores |= rewrite.apply(code, i);
        }
    }

    // Nothing says which `callx` passes stack arguments, so each one hands them on.
    if stores {
        for insn in code.iter_mut().filter(|insn| insn.byte() == CALLX) {
            *insn = insn.with_byte(args::CALLX);
        }
    }
}

const R10: u8 = FP as u8;
/// The base register of stack arguments.
const R11: u8 = 11;
/// No register number, in [`Rewrite::dst`] and [`Rewrite::src`].
const NO_REG: u8 = 0xff;

/// Whether [`Code::new`](crate::Code::new) leaves the opcode byte `byte` only where `offset` is 0: that of `mov` and
/// `mov32`, which with an offset run as MOVSX or fail, and those whose `offset` the verifier reserves.
#[inline(always)]
pub const fn offset_is_zero(byte: u8) -> bool {
    let rewrite = REWRITES[byte as usize];
    (rewrite.nonzero | rewrite.reserved) & OFFSET != 0
}

/// Why the pass may rewrite an instruction with a given opcode byte.
#[derive(Clone, Copy)]
struct Rewrite {
    /// The [`canonical`] byte.
    canonical: Option<u8>,
    /// The `dst_reg` that sends an instruction to [`Rewrite::apply`]: r10 in one that writes `dst_reg`, r11 in an
    /// 8-byte store, whose base register it is. [`NO_REG`] for none.
    dst: u8,
    /// The `src_reg` that does: r11 in the 8-byte load, whose base register it is.
    src: u8,
    /// The byte is an atomic's: [`atomic_writes_r10`] decides whether it writes r10.
    atomic: bool,
    /// The fields that give the instruction `nonzero_byte` where they aren't 0: `src_reg` of LD_IMM64, a pseudo load,
    /// which runs as [`MISSING`] does, and `offset` of `mov` from a register, which runs as MOVSX or fails.
    nonzero: u8,
    nonzero_byte: u8,
    /// The fields the verifier reserves (see [`Code::new`](crate::Code::new)), which give the instruction [`INVALID`]
    /// where they aren't 0.
    reserved: u8,
    /// The bits of an instruction that send it to [`Rewrite::apply`] where they aren't 0: those of `nonzero` and
    /// `reserved`, and the opcode byte if the byte has a `canonical` one, is an atomic's, `call` or LD_IMM64. No such
    /// byte is 0.
    screen: u64,
}

impl Rewrite {
    /// Gives the instruction in slot `i` of `code`, whose opcode byte has this rewrite, the opcode byte of the pass,
    /// and returns whether that byte stores a stack argument. The pass has rewritten only the slots before `i`, so
    /// slot `i + 1` is as loaded, and the second slot of LD_IMM64 keeps its `imm`.
    #[cold]
    #[inline(never)]
    fn apply(&self, code: &mut [Instruction], i: usize) -> bool {
        let insn = code[i];
        let r10 = (self.dst == R10 && insn.dst_reg() == R10) || (self.atomic && atomic_writes_r10(insn));
        let reserved = (insn.0 & field_bits(self.reserved) != 0)
            || (insn.byte() == CALL && call_reserved(insn))
            || (insn.byte() == LD_IMM64 && code.get(i + 1).is_some_and(|second| second.0 as u32 != 0));
        let byte = match (self.canonical, r10 || reserved, stack_arg(insn)) {
            (Some(byte), ..) => byte,
            (None, true, _) => INVALID,
            (None, false, Some(byte)) => byte,
            (None, false, None) if insn.byte() == CALL => match insn.src_reg() {
                call::HELPER => CALL_HELPER,
                call::KFUNC => CALL_KFUNC,
                _ => return false,
            },
            (None, false, None) if insn.byte() == MOV64_REG => mov64_reg(insn),
            (None, false, None) if insn.0 & field_bits(self.nonzero) != 0 => self.nonzero_byte,
            // an atomic, local `call` or LD_IMM64 that needs no rewrite
            (None, false, None) => return false,
        };
        code[i] = insn.with_byte(byte);
        byte == args::STORE || byte == args::STORE_IMM
    }
}

/// The byte of a `MOV64_REG` with a non-zero `offset` or `imm`: an `addr_space_cast` between spaces 0 and 1, a
/// `MOVSX64`, or [`INVALID`].
fn mov64_reg(insn: Instruction) -> u8 {
    match (insn.offset(), insn.imm()) {
        (1, ADDR_SPACE_TO_HOST) => TO_HOST,
        (1, ADDR_SPACE_TO_GUEST) => TO_GUEST,
        (8 | 16 | 32, 0) => MOVSX64,
        _ => INVALID,
    }
}

/// The byte of the load or store of a stack argument `insn`, if it is an 8-byte load or store through r11:
/// [`INVALID`] for one whose offset names no stack argument.
fn stack_arg(insn: Instruction) -> Option<u8> {
    // a store names the slot at the negated offset, which wraps to a negative one for `i16::MIN`
    let (byte, base, offset) = match insn.byte() {
        LDX_DW => (args::LOAD, insn.src_reg(), insn.offset()),
        STX_DW => (args::STORE, insn.dst_reg(), insn.offset().wrapping_neg()),
        ST_DW => (args::STORE_IMM, insn.dst_reg(), insn.offset().wrapping_neg()),
        _ => return None,
    };
    (base == R11).then_some(if args::is_slot(offset) { byte } else { INVALID })
}

/// The fields of an [`Instruction`] but the opcode byte, one bit each in a set of fields.
const DST: u8 = 1;
const SRC: u8 = 2;
const OFFSET: u8 = 4;
const IMM: u8 = 8;

/// The bits of the fields in the set `fields`.
const fn field_bits(fields: u8) -> u64 {
    let field_bits = [
        (DST, Instruction::DST_REG),
        (SRC, Instruction::SRC_REG),
        (OFFSET, Instruction::OFFSET),
        (IMM, Instruction::IMM),
    ];
    let mut bits = 0;
    const_for!((field, field_bits) in field_bits => {
        if fields & field != 0 {
            bits |= field_bits;
        }
    });
    bits
}

const REWRITES: [Rewrite; 256] = {
    const NONE: Rewrite = Rewrite {
        canonical: None,
        dst: NO_REG,
        src: NO_REG,
        atomic: false,
        nonzero: 0,
        nonzero_byte: 0,
        reserved: 0,
        screen: 0,
    };

    byte_table!(|byte| {
        let opc = OpCode(byte);
        let reserved = reserved(opc);
        let rewrite = match opc.class() {
            _ if canonical(byte).is_some() => Rewrite {
                canonical: canonical(byte),
                ..NONE
            },
            Class::Alu32 | Class::Alu64 => {
                let (nonzero, nonzero_byte) = match byte {
                    MOV32_REG => (OFFSET, MOVSX32),
                    MOV64_REG => (OFFSET | IMM, MOVSX64),
                    _ => (0, 0),
                };
                Rewrite {
                    dst: R10,
                    nonzero,
                    nonzero_byte,
                    reserved,
                    ..NONE
                }
            }
            Class::Ldx => Rewrite {
                dst: R10,
                src: if byte == LDX_DW { R11 } else { NO_REG },
                reserved,
                ..NONE
            },
            Class::Ld if byte == LD_IMM64 => Rewrite {
                dst: R10,
                nonzero: SRC,
                nonzero_byte: MISSING,
                reserved,
                ..NONE
            },
            Class::Stx => Rewrite {
                dst: if byte == STX_DW { R11 } else { NO_REG },
                atomic: matches!(opc.mem_mode(), MemMode::Atomic),
                reserved,
                ..NONE
            },
            Class::St => Rewrite {
                dst: if byte == ST_DW { R11 } else { NO_REG },
                reserved,
                ..NONE
            },
            Class::Ld | Class::Jmp32 | Class::Jmp64 => Rewrite { reserved, ..NONE },
        };
        let always = rewrite.canonical.is_some() || rewrite.atomic || byte == CALL || byte == LD_IMM64;
        assert!(!always || byte != 0, "a rewritten byte 0, which `screen` can't catch");
        Rewrite {
            screen: field_bits(rewrite.nonzero | rewrite.reserved) | if always { Instruction::OPCODE } else { 0 },
            ..rewrite
        }
    })
};

/// The fields that the verifier reserves in every instruction with opcode `opc` that runs, as `check_insn_fields`
/// checks them; [`call_reserved`] and [`Rewrite::apply`] check those that depend on other fields.
const fn reserved(opc: OpCode) -> u8 {
    let reg = matches!(opc.source(), Source::Reg);
    // the field that doesn't name the source
    let unused = if reg { IMM } else { SRC };
    let jmp64 = matches!(opc.class(), Class::Jmp64);
    match opc.class() {
        Class::Alu32 | Class::Alu64 => match opc.alu_opc() {
            // `INVALID`, which keeps every field
            AluOpc::UndefE | AluOpc::UndefF => 0,
            AluOpc::Neg => SRC | OFFSET | IMM,
            AluOpc::End => SRC | OFFSET,
            // the offset of DIV and MOD makes them signed, and that of `mov` from a register MOVSX or addr_space_cast
            AluOpc::Div | AluOpc::Mod => unused,
            AluOpc::Mov if reg && matches!(opc.class(), Class::Alu64) => 0,
            AluOpc::Mov if reg => IMM,
            _ => unused | OFFSET,
        },
        Class::Jmp32 | Class::Jmp64 => match opc.jmp_opc() {
            // `gotox` and `callx`
            JmpOpc::Ja | JmpOpc::Call if reg => SRC | OFFSET | IMM,
            JmpOpc::Ja if jmp64 => SRC | DST | IMM,
            JmpOpc::Ja => SRC | DST | OFFSET,
            JmpOpc::Exit => SRC | DST | OFFSET | IMM,
            JmpOpc::Call => DST,
            JmpOpc::Jcond => DST | SRC | IMM,
            _ => unused,
        },
        Class::Ldx => IMM,
        Class::St => SRC,
        Class::Stx if matches!(opc.mem_mode(), MemMode::Mem) => IMM,
        Class::Ld if opc.0 == LD_IMM64 => OFFSET,
        Class::Stx | Class::Ld => 0,
    }
}

/// Whether the `call` with an immediate `insn` sets a field that the verifier reserves where it depends on the kind of
/// call in `src_reg`: a kind other than a helper, local or kfunc call, or an `offset` in a call that isn't a kfunc's.
fn call_reserved(insn: Instruction) -> bool {
    match insn.src_reg() {
        call::HELPER | call::LOCAL => insn.offset() != 0,
        call::KFUNC => false,
        _ => true,
    }
}

/// Whether the atomic `insn` writes r10.
fn atomic_writes_r10(insn: Instruction) -> bool {
    match insn.imm() {
        LOAD_ACQ => insn.dst_reg() == R10,
        // CMPXCHG fetches into r0
        imm => insn.src_reg() == R10 && imm & FETCH != 0 && imm != CMPXCHG,
    }
}

/// Each kind of field the verifier reserves, set where it is reserved and where an instruction uses it.
#[cfg(test)]
#[test]
fn reserved_fields() {
    use crate::opcode::MemSize;
    use crate::Code;

    let insn = Instruction::new;
    let (alu, jmp) = (OpCode::alu64, OpCode::jmp64);
    let exit = insn(jmp(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0);
    let fails = |slots: &[Instruction]| Code::new(slots).raw_slot(0).unwrap().byte() == INVALID;
    for (slot, reserved) in [
        (insn(alu(AluOpc::Add, Source::Imm), 1, 2, 0, 1), true),
        (insn(alu(AluOpc::Add, Source::Reg), 1, 2, 0, 1), true),
        (insn(alu(AluOpc::Add, Source::Reg), 1, 2, 1, 0), true),
        (insn(alu(AluOpc::Div, Source::Reg), 1, 2, 1, 0), false),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 8, 0), false),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 8, 1), true),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 0, 1), true),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 1, ADDR_SPACE_TO_HOST), false),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 1, ADDR_SPACE_TO_GUEST), false),
        (insn(alu(AluOpc::Mov, Source::Reg), 10, 2, 1, ADDR_SPACE_TO_HOST), true),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 1, 0), true),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 1, 2 << 16), true),
        (insn(OpCode::alu32(AluOpc::Mov, Source::Reg), 1, 2, 1, ADDR_SPACE_TO_HOST), true),
        (insn(alu(AluOpc::Neg, Source::Reg), 1, 0, 0, 0), true),
        (insn(alu(AluOpc::Neg, Source::Imm), 1, 0, 0, 1), true),
        (insn(jmp(JmpOpc::Exit, Source::Imm), 0, 1, 0, 0), true),
        (insn(jmp(JmpOpc::Exit, Source::Imm), 0, 0, 1, 0), true),
        (insn(jmp(JmpOpc::Jcond, Source::Imm), 0, 0, 5, 0), false),
        (insn(jmp(JmpOpc::Jcond, Source::Imm), 1, 0, 5, 0), true),
        (insn(jmp(JmpOpc::Jcond, Source::Imm), 0, 1, 5, 0), true),
        (insn(jmp(JmpOpc::Jcond, Source::Imm), 0, 0, 5, 1), true),
        (insn(jmp(JmpOpc::Ja, Source::Imm), 1, 0, 0, 0), true),
        (insn(jmp(JmpOpc::Jeq, Source::Imm), 1, 2, 0, 0), true),
        (insn(jmp(JmpOpc::Call, Source::Imm), 0, 0, 1, 1), true),
        (insn(jmp(JmpOpc::Call, Source::Imm), 0, call::KFUNC, 1, 1), false),
        (insn(jmp(JmpOpc::Call, Source::Imm), 0, 3, 0, 1), true),
        (insn(OpCode::ldx(MemSize::Word, MemMode::Mem), 1, 2, 0, 1), true),
        (insn(OpCode::st(MemSize::Word, MemMode::Mem), 1, 2, 0, 1), true),
        (insn(OpCode(LD_IMM64), 1, 0, 1, 7), true),
    ] {
        assert_eq!(fails(&[slot, exit]), reserved, "{slot:?}");
    }

    // the second slot of LD_IMM64 holds the upper half of the immediate and nothing else
    let lddw = insn(OpCode(LD_IMM64), 1, 0, 0, 7);
    assert!(!fails(&[lddw, insn(OpCode(0), 0, 0, 0, 5)]));
    assert!(fails(&[lddw, insn(OpCode(0), 1, 0, 0, 5)]));
    assert!(fails(&[lddw, insn(OpCode(LD_IMM64), 0, 0, 0, 5)]));
}
