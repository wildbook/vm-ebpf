use std::cmp::Ordering;

use crate::opcode::{AluEnd, AluOpc, JmpOpc, Source};
use crate::{Flow, Instruction, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL};

pub const BITS_32: bool = false;
pub const BITS_64: bool = true;

/// The registers an instruction reads and writes, by the number in its `dst_reg` or `src_reg` field.
pub trait Regs {
    fn get(&self, reg: u8) -> u64;
    fn set(&mut self, reg: u8, value: u64);
}

impl Regs for [u64; 16] {
    #[inline(always)]
    fn get(&self, reg: u8) -> u64 {
        self[usize::from(reg)]
    }

    #[inline(always)]
    fn set(&mut self, reg: u8, value: u64) {
        self[usize::from(reg)] = value;
    }
}

/// SDIV or SMOD (`$op` is `/` or `%`) of `$d` by `$s` as `$ty`, with the results RFC 9669 gives where Rust's would
/// panic: `$by_zero` for a divisor of 0, and `$overflow` for the smallest value divided by -1.
macro_rules! signed_div_rem {
    ($ty:ty: $d:ident $op:tt $s:ident, by_zero: $by_zero:expr, overflow: $overflow:expr) => {{
        let (ds, ss) = ($d as $ty, $s as $ty);
        if ss == 0 {
            $by_zero
        } else if ss == -1 && ds == <$ty>::MIN {
            $overflow
        } else {
            (ds $op ss) as u64
        }
    }};
}

#[inline(always)]
pub fn math<E, R: Regs, const BITS: bool>(regs: &mut R, insn: Instruction) -> Flow<E> {
    let opc = insn.opcode();
    let alu_opc = opc.alu_opc();
    let alu_src = opc.alu_src();
    let alu_end = opc.alu_end();

    let dst_reg = insn.dst_reg();
    let imm = insn.imm();
    let offset = insn.offset();
    let (d, s) = operands::<R, BITS>(regs, insn);

    let result = match alu_opc {
        AluOpc::Add => d.wrapping_add(s),
        AluOpc::Sub => d.wrapping_sub(s),
        AluOpc::Mul => d.wrapping_mul(s),
        // DIV (offset=0) or SDIV (offset=1)
        AluOpc::Div => match (offset, BITS) {
            (0, _) => d.checked_div(s).unwrap_or(0),
            (1, BITS_64) => signed_div_rem!(i64: d / s, by_zero: 0, overflow: i64::MIN as u64),
            (1, BITS_32) => signed_div_rem!(i32: d / s, by_zero: 0, overflow: i32::MIN as u64),
            _ => return Flow::FailCpu,
        },
        AluOpc::Or => d | s,
        AluOpc::And => d & s,
        AluOpc::Lsh => d << shift::<BITS>(s),
        AluOpc::Rsh => d >> shift::<BITS>(s),
        AluOpc::Neg => d.wrapping_neg(),
        // MOD (offset=0) or SMOD (offset=1)
        AluOpc::Mod => match (offset, BITS) {
            (0, _) => d.checked_rem(s).unwrap_or(d),
            (1, BITS_64) => signed_div_rem!(i64: d % s, by_zero: d, overflow: 0),
            (1, BITS_32) => signed_div_rem!(i32: d % s, by_zero: d, overflow: 0),
            _ => return Flow::FailCpu,
        },
        AluOpc::Xor => d ^ s,
        // MOV (offset=0) or MOVSX (offset=8/16/32, register source only; 32 is ALU64-only). Without the cold path,
        // LLVM merges the `offset == 0` test into the movsx switch and lowers all of it to a jump table on
        // `offset`.
        AluOpc::Mov if offset == 0 => s,
        AluOpc::Mov => {
            core::hint::cold_path();
            match (offset, alu_src, BITS) {
                (8, Source::Reg, _) => s as i8 as i64 as u64,
                (16, Source::Reg, _) => s as i16 as i64 as u64,
                (32, Source::Reg, BITS_64) => s as i32 as i64 as u64,
                _ => return Flow::FailCpu,
            }
        }
        AluOpc::Arsh => match BITS {
            BITS_64 => ((d as i64) >> shift::<BITS>(s)) as u64,
            BITS_32 => ((d as i32) >> shift::<BITS>(s)) as u64,
        },
        // END: width comes from imm and the result is not zero-extended by class. Guest memory is little-endian, so
        // LE truncates and BE swaps; ALU64 TO_LE is the unconditional BSWAP and ALU64 TO_BE is reserved.
        AluOpc::End => {
            let full_d = regs.get(dst_reg);
            let swap = match (BITS, alu_end) {
                (BITS_32, AluEnd::ToLE) => false,
                (BITS_32, AluEnd::ToBE) | (BITS_64, AluEnd::ToLE) => true,
                (BITS_64, AluEnd::ToBE) => return Flow::FailCpu,
            };
            let result = match (swap, imm) {
                (false, 16) => full_d as u16 as u64,
                (false, 32) => full_d as u32 as u64,
                (false, 64) => full_d,
                (true, 16) => (full_d as u16).swap_bytes() as u64,
                (true, 32) => (full_d as u32).swap_bytes() as u64,
                (true, 64) => full_d.swap_bytes(),
                _ => return Flow::FailCpu,
            };
            regs.set(dst_reg, result);
            return Flow::Next;
        }
        AluOpc::UndefE | AluOpc::UndefF => return Flow::FailCpu,
    };
    regs.set(dst_reg, truncate::<BITS>(result));

    Flow::Next
}

#[inline(always)]
pub fn jump<E, R: Regs, const BITS: bool>(regs: &R, insn: Instruction) -> Flow<E> {
    let opc = insn.opcode();
    let jmp_opc = opc.jmp_opc();
    let jmp_src = opc.alu_src();

    let src_reg = insn.src_reg();
    let dst_reg = insn.dst_reg();
    let imm = insn.imm();
    let (d, s) = operands::<R, BITS>(regs, insn);

    let cond = match jmp_opc {
        // RFC 9669 defines CALL and EXIT only in the JMP class, EXIT only with source K, and JMP32 JA only with K
        JmpOpc::Call | JmpOpc::Exit if BITS == BITS_32 => return Flow::FailCpu,
        JmpOpc::Exit if jmp_src == Source::Reg => return Flow::FailCpu,
        JmpOpc::Ja if jmp_src == Source::Reg && BITS == BITS_32 => return Flow::FailCpu,
        // `gotox`: JMP64 class only, target in dst_reg
        JmpOpc::Ja if jmp_src == Source::Reg => return Flow::JumpIndirect(d),
        // JA in JMP64 class uses offset field, JA in JMP32 class uses imm field
        JmpOpc::Ja => {
            return match BITS {
                BITS_64 => Flow::Jump(insn.offset() as i64),
                BITS_32 => Flow::Jump(imm as i64),
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

        JmpOpc::Call if jmp_src == Source::Reg => return Flow::CallIndirect(d),
        JmpOpc::Call if insn.src_reg() == 0 => return Flow::CallHelper(imm as u32),
        JmpOpc::Call if insn.src_reg() == BPF_PSEUDO_CALL => return Flow::Call(i64::from(imm)),
        JmpOpc::Call if insn.src_reg() == BPF_PSEUDO_KFUNC_CALL => return Flow::CallKfunc(imm as u32),
        JmpOpc::Call => return Flow::Missing,

        JmpOpc::Exit => return Flow::Exit,

        // `may_goto`: the kernel takes the jump once a loop's budget runs out; rvm never does and bounds loops with
        // fuel. The kernel verifier rejects JMP32, source X and nonzero `dst_reg`, `src_reg` or `imm`.
        JmpOpc::Jcond if BITS == BITS_64 && jmp_src == Source::Imm && dst_reg == 0 && src_reg == 0 && imm == 0 => {
            return Flow::Next
        }
        JmpOpc::Jcond | JmpOpc::UndefF => return Flow::FailCpu,
    };

    match cond {
        true => Flow::Jump(insn.offset() as i64),
        false => Flow::Next,
    }
}

/// The operands of the ALU or jump instruction `insn` on `BITS` bits: `dst_reg`, and `src_reg` or `imm` as its
/// source bit selects, cut to `BITS` bits.
#[inline(always)]
fn operands<R: Regs, const BITS: bool>(regs: &R, insn: Instruction) -> (u64, u64) {
    let d = truncate::<BITS>(regs.get(insn.dst_reg()));
    let s = match (insn.opcode().alu_src(), BITS) {
        (Source::Imm, BITS_64) => insn.imm() as i64 as u64,
        (Source::Imm, BITS_32) => insn.imm() as u32 as u64,
        (Source::Reg, _) => truncate::<BITS>(regs.get(insn.src_reg())),
    };
    (d, s)
}

/// `x` cut to `BITS` bits.
#[inline(always)]
fn truncate<const BITS: bool>(x: u64) -> u64 {
    match BITS {
        BITS_64 => x,
        BITS_32 => x as u32 as u64,
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

/// The shift amount of a shift by `s` on `BITS` bits.
#[inline(always)]
fn shift<const BITS: bool>(s: u64) -> u64 {
    match BITS {
        BITS_64 => s & 63,
        BITS_32 => s & 31,
    }
}
