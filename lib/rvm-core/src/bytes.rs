//! The opcode bytes of slots.
//!
//! A slot keeps the opcode byte of its instruction, with two kinds of exceptions that [`Code::new`](crate::Code::new)
//! makes. It gives every instruction that runs the same whatever its fields hold one byte ([`canonical`]), which
//! frees the other bytes of such instructions. And it gives some slots one of the freed bytes, which then has a
//! handler of its own: the first slot of a superinstruction ([`fuse`](crate::fuse)), a load or store through r10
//! ([`windows`](crate::windows)), a `mov` with an offset ([`MOVSX32`], [`MOVSX64`]), the slots that
//! [`transfer`](crate::transfer) makes, and native calls ([`native`](crate::native)). [`usual`] gives the opcode that
//! a slot with such a byte runs as.

use crate::fuse::{Super, SUPERS};
use crate::native;
use crate::opcode::{AluEnd, AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, CALL, LD_IMM64};
use crate::transfer::{FAR, GUARD};
use crate::windows::STACK_ACCESSES;

/// The byte of every LD-class instruction but LD_IMM64, the legacy packet loads among them, which all run as the same
/// unsupported instruction ([`Reason::Unsupported`](crate::Reason::Unsupported)).
pub const MISSING: u8 = Class::Ld as u8;

/// An undefined ALU64 operation: the byte of every instruction that always fails with
/// [`Reason::InvalidInstruction`](crate::Reason::InvalidInstruction), and of every instruction that would write r10.
pub const INVALID: u8 = OpCode::alu64(AluOpc::UndefE, Source::Imm).0;

pub const MOV32_REG: u8 = OpCode::alu32(AluOpc::Mov, Source::Reg).0;
pub const MOV64_REG: u8 = OpCode::alu64(AluOpc::Mov, Source::Reg).0;

/// The bytes of `mov32` and `mov` from a register with an offset: MOVSX, or a reserved offset, which fails.
pub const MOVSX32: u8 = 0xf0;
pub const MOVSX64: u8 = 0xf8;

/// The byte [`Code::new`](crate::Code::new) gives an instruction with opcode byte `byte` in its place, if it gives it
/// another: one that runs the same whatever the other fields hold. No slot holds `byte` afterwards, which frees it for
/// a handler of its own.
pub const fn canonical(byte: u8) -> Option<u8> {
    match byte {
        MISSING | LD_IMM64 | INVALID => None,
        _ if byte & 0b111 == Class::Ld as u8 => Some(MISSING),
        _ if always_fails(OpCode(byte)) => Some(INVALID),
        _ => None,
    }
}

/// Whether every instruction with opcode `opc` fails with
/// [`Reason::InvalidInstruction`](crate::Reason::InvalidInstruction), whatever its other fields hold, as
/// [`step`](crate::step) runs it or as the verifier rejects it (NEG from a register).
const fn always_fails(opc: OpCode) -> bool {
    let jmp32 = matches!(opc.class(), Class::Jmp32);
    let imm = matches!(opc.source(), Source::Imm);
    match opc.class() {
        Class::Alu32 | Class::Alu64 => match opc.alu_opc() {
            AluOpc::UndefE | AluOpc::UndefF => true,
            AluOpc::Neg => !imm,
            AluOpc::End => matches!((opc.class(), opc.alu_end()), (Class::Alu64, AluEnd::ToBE)),
            _ => false,
        },
        Class::Jmp32 | Class::Jmp64 => match opc.jmp_opc() {
            JmpOpc::Call => jmp32,
            JmpOpc::Ja => jmp32 && !imm,
            JmpOpc::Exit | JmpOpc::Jcond => jmp32 || !imm,
            JmpOpc::UndefF => true,
            _ => false,
        },
        Class::Ldx => match opc.mem_mode() {
            MemMode::Mem => false,
            MemMode::MemSX => matches!(opc.mem_size(), MemSize::DWord),
            _ => true,
        },
        Class::St => !matches!(opc.mem_mode(), MemMode::Mem),
        Class::Stx => !matches!(opc.mem_mode(), MemMode::Mem | MemMode::Atomic),
        Class::Ld => false,
    }
}

/// The opcode that the instruction in a slot with opcode byte `byte` runs as: for the first slot of a superinstruction
/// or r10 access, which holds a free byte in its place, the first instruction of the sequence or the load or store, for
/// a `mov` from a register with an offset, the `mov`, and for a native call, `call`.
pub const fn usual(byte: u8) -> u8 {
    const_for!((stack, opcode) in STACK_ACCESSES => {
        if stack == byte {
            return opcode;
        }
    });
    const_for!(native in native::PLAIN => {
        if native == byte {
            return CALL;
        }
    });
    const_for!(native in native::CHECKED => {
        if native == byte {
            return CALL;
        }
    });
    match (byte, Super::with_byte(byte)) {
        (MOVSX32, _) => MOV32_REG,
        (MOVSX64, _) => MOV64_REG,
        (_, Some(sup)) => sup.opcode(0),
        (_, None) => byte,
    }
}

// Every byte with a handler of its own is a free one and has one use.
const _: () = {
    const fn claim(used: &mut [bool; 256], byte: u8) {
        assert!(canonical(byte).is_some(), "a byte that slots hold");
        assert!(!used[byte as usize], "two uses of one opcode byte");
        used[byte as usize] = true;
    }

    let mut used = [false; 256];
    const_for!((byte, ..) in SUPERS => claim(&mut used, byte));
    const_for!((byte, _) in STACK_ACCESSES => claim(&mut used, byte));
    claim(&mut used, GUARD);
    claim(&mut used, FAR);
    claim(&mut used, MOVSX32);
    claim(&mut used, MOVSX64);
    const_for!(byte in native::PLAIN => claim(&mut used, byte));
    const_for!(byte in native::CHECKED => claim(&mut used, byte));
};
