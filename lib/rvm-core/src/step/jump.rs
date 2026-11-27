//! The JMP and JMP32 classes: jumps, calls and `exit`.

use std::cmp::Ordering;

use super::{operands, Regs, Step, BITS_32, BITS_64};
use crate::opcode::{call, JmpOpc, Source};
use crate::slot::Fields;
use crate::Reason;

/// Runs the jump-class instruction `insn` on `BITS` bits. It writes no register: its [`Step`] says where execution
/// goes on.
#[inline(always)]
pub fn jump<E, R: Regs, const BITS: bool>(regs: &R, insn: impl Fields) -> Step<E> {
    let opc = insn.opcode();
    let jmp_opc = opc.jmp_opc();
    let jmp_src = opc.source();

    let src_reg = insn.src_reg().get();
    let imm = insn.imm();
    let (d, s) = operands::<R, BITS>(regs, insn);

    let cond = match jmp_opc {
        // RFC 9669 defines CALL and EXIT only in the JMP class, EXIT only with source K, and JMP32 JA only with K
        JmpOpc::Call | JmpOpc::Exit if BITS == BITS_32 => return Step::INVALID,
        JmpOpc::Exit if jmp_src == Source::Reg => return Step::INVALID,
        JmpOpc::Ja if jmp_src == Source::Reg && BITS == BITS_32 => return Step::INVALID,
        // `gotox`: JMP64 class only, target in dst_reg
        JmpOpc::Ja if jmp_src == Source::Reg => return Step::Stop(Reason::JumpIndirect(d)),
        // JA in JMP64 class uses offset field, JA in JMP32 class uses imm field
        JmpOpc::Ja => {
            return match BITS {
                BITS_64 => Step::Jump(insn.offset() as i64),
                BITS_32 => Step::Jump(imm as i64),
            }
        }
        JmpOpc::Jeq => d == s,
        JmpOpc::Jgt => d > s,
        JmpOpc::Jge => d >= s,
        JmpOpc::Jset => (d & s) != 0,
        JmpOpc::Jne => d != s,
        JmpOpc::Jsgt => signed_cmp::<BITS>(d, s).is_gt(),
        JmpOpc::Jsge => signed_cmp::<BITS>(d, s).is_ge(),
        JmpOpc::Jlt => d < s,
        JmpOpc::Jle => d <= s,
        JmpOpc::Jslt => signed_cmp::<BITS>(d, s).is_lt(),
        JmpOpc::Jsle => signed_cmp::<BITS>(d, s).is_le(),

        JmpOpc::Call if jmp_src == Source::Reg => return Step::CallIndirect,
        JmpOpc::Call if src_reg == call::LOCAL => return Step::Call(i64::from(imm)),
        JmpOpc::Call if src_reg == call::KFUNC => return Step::CallKfunc,
        JmpOpc::Call if src_reg == call::HELPER => {
            // Tested last. A runtime that binds helpers when it loads a program turns their calls into kfunc calls,
            // as rvm does, so a helper ID is the rare kind of call. Without the hint LLVM tests for it first and for
            // a local call last, which then takes two instructions more.
            core::hint::cold_path();
            return Step::CallHelper;
        }
        JmpOpc::Call => return Step::Stop(Reason::Unsupported),

        JmpOpc::Exit => return Step::Exit,

        // `may_goto`: the kernel takes the jump once a loop's budget runs out; rvm never does and bounds loops with
        // fuel. `rewrite` rejects nonzero `dst_reg`, `src_reg` or `imm`.
        JmpOpc::Jcond if BITS == BITS_64 && jmp_src == Source::Imm => return Step::Next,
        JmpOpc::Jcond | JmpOpc::UndefF => return Step::INVALID,
    };

    match cond {
        true => Step::Jump(insn.offset() as i64),
        false => Step::Next,
    }
}

/// `d` compared with `s` as signed values of `BITS` bits.
#[inline(always)]
fn signed_cmp<const BITS: bool>(d: u64, s: u64) -> Ordering {
    match BITS {
        BITS_64 => (d as i64).cmp(&(s as i64)),
        BITS_32 => (d as i32).cmp(&(s as i32)),
    }
}
