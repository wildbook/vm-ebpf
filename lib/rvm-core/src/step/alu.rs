//! The ALU and ALU64 classes.

use super::{operands, truncate, Regs, BITS_32, BITS_64};
use crate::opcode::{AluEnd, AluOpc, Source};
use crate::slot::Fields;
use crate::Reason;

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

/// Runs the ALU instruction `insn` on `BITS` bits.
#[inline(always)]
pub fn alu<E, R: Regs, const BITS: bool>(regs: &mut R, insn: impl Fields) -> Result<(), Reason<E>> {
    let opc = insn.opcode();
    let alu_opc = opc.alu_opc();
    let alu_src = opc.source();
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
            _ => return Err(Reason::InvalidInstruction),
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
            _ => return Err(Reason::InvalidInstruction),
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
                _ => return Err(Reason::InvalidInstruction),
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
                (BITS_64, AluEnd::ToBE) => return Err(Reason::InvalidInstruction),
            };
            let result = match (swap, imm) {
                (false, 16) => full_d as u16 as u64,
                (false, 32) => full_d as u32 as u64,
                (false, 64) => full_d,
                (true, 16) => (full_d as u16).swap_bytes() as u64,
                (true, 32) => (full_d as u32).swap_bytes() as u64,
                (true, 64) => full_d.swap_bytes(),
                _ => return Err(Reason::InvalidInstruction),
            };
            regs.set(dst_reg, result);
            return Ok(());
        }
        AluOpc::UndefE | AluOpc::UndefF => return Err(Reason::InvalidInstruction),
    };
    regs.set(dst_reg, truncate::<BITS>(result));

    Ok(())
}

/// The shift amount of a shift by `s` on `BITS` bits.
#[inline(always)]
fn shift<const BITS: bool>(s: u64) -> u64 {
    match BITS {
        BITS_64 => s & 63,
        BITS_32 => s & 31,
    }
}
