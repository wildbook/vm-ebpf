use crate::opcode::{AluEnd, AluOpc, JmpOpc, Source};
use crate::{Context, Flow, Instruction, Memory, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL};

pub const BITS_32: bool = false;
pub const BITS_64: bool = true;

#[inline(always)]
pub fn math<M: Memory, const BITS: bool>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M> {
    let opc = insn.opcode();
    let alu_opc = opc.alu_opc();
    let alu_src = opc.alu_src();
    let alu_end = opc.alu_end();

    let src_reg = insn.src_reg() as usize;
    let dst_reg = insn.dst_reg() as usize;

    let imm = insn.imm();
    let offset = insn.offset();

    let d = match BITS {
        BITS_64 => ctx.regs[dst_reg],
        BITS_32 => ctx.regs[dst_reg] & 0xFFFFFFFF,
    };

    let s = match (alu_src, BITS) {
        (Source::Imm, BITS_64) => imm as i64 as u64,
        // ALU32 treats the immediate as a 32-bit value.
        (Source::Imm, BITS_32) => imm as u32 as u64,
        (Source::Reg, BITS_64) => ctx.regs[src_reg],
        (Source::Reg, BITS_32) => ctx.regs[src_reg] & 0xFFFFFFFF,
    };

    let result = match alu_opc {
        AluOpc::Add => d.wrapping_add(s),
        AluOpc::Sub => d.wrapping_sub(s),
        AluOpc::Mul => d.wrapping_mul(s),
        // DIV (offset=0) or SDIV (offset=1)
        AluOpc::Div => match (offset, BITS) {
            (0, _) => d.checked_div(s).unwrap_or(0),
            (1, BITS_64) => {
                let ds = d as i64;
                let ss = s as i64;
                if ss == 0 {
                    0
                } else if ss == -1 && ds == i64::MIN {
                    i64::MIN as u64
                } else {
                    (ds / ss) as u64
                }
            }
            (1, BITS_32) => {
                let ds = d as i32;
                let ss = s as i32;
                if ss == 0 {
                    0
                } else if ss == -1 && ds == i32::MIN {
                    i32::MIN as u64
                } else {
                    (ds / ss) as u64
                }
            }
            _ => return Flow::FailCpu,
        },
        AluOpc::Or => d | s,
        AluOpc::And => d & s,
        AluOpc::Lsh => match BITS {
            BITS_64 => d << (s & 63),
            BITS_32 => d << (s & 31),
        },
        AluOpc::Rsh => match BITS {
            BITS_64 => d >> (s & 63),
            BITS_32 => d >> (s & 31),
        },
        AluOpc::Neg => d.wrapping_neg(),
        // MOD (offset=0) or SMOD (offset=1)
        AluOpc::Mod => match (offset, BITS) {
            (0, BITS_64) => d.checked_rem(s).unwrap_or(d),
            (0, BITS_32) => {
                // the upper 32 bits are zeroed below
                if s == 0 {
                    d
                } else {
                    d % s
                }
            }
            (1, BITS_64) => {
                let ds = d as i64;
                let ss = s as i64;
                if ss == 0 {
                    d
                } else if ss == -1 && ds == i64::MIN {
                    0u64
                } else {
                    (ds % ss) as u64
                }
            }
            (1, BITS_32) => {
                let ds = d as i32;
                let ss = s as i32;
                if ss == 0 {
                    d // zero-extended below
                } else if ss == -1 && ds == i32::MIN {
                    0u64
                } else {
                    (ds % ss) as u64
                }
            }
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
            BITS_64 => ((d as i64) >> (s & 63)) as u64,
            BITS_32 => ((d as i32) >> (s & 31)) as u64,
        },
        // END: width comes from imm and the result is not zero-extended by class. Guest memory is little-endian, so
        // LE truncates and BE swaps; ALU64 TO_LE is the unconditional BSWAP and ALU64 TO_BE is reserved.
        AluOpc::End => {
            let full_d = ctx.regs[dst_reg];
            let swap = match (BITS, alu_end) {
                (BITS_32, AluEnd::ToLE) => false,
                (BITS_32, AluEnd::ToBE) | (BITS_64, AluEnd::ToLE) => true,
                (BITS_64, AluEnd::ToBE) => return Flow::FailCpu,
            };
            ctx.regs[dst_reg] = match (swap, imm) {
                (false, 16) => full_d as u16 as u64,
                (false, 32) => full_d as u32 as u64,
                (false, 64) => full_d,
                (true, 16) => (full_d as u16).swap_bytes() as u64,
                (true, 32) => (full_d as u32).swap_bytes() as u64,
                (true, 64) => full_d.swap_bytes(),
                _ => return Flow::FailCpu,
            };
            return Flow::Next;
        }
        AluOpc::UndefE | AluOpc::UndefF => return Flow::FailCpu,
    };

    ctx.regs[dst_reg] = match BITS {
        BITS_64 => result,
        BITS_32 => result & 0xFFFFFFFF,
    };

    Flow::Next
}

#[inline(always)]
pub fn jump<M: Memory, const BITS: bool>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M> {
    let opc = insn.opcode();
    let jmp_opc = opc.jmp_opc();
    let jmp_src = opc.alu_src();

    let src_reg = insn.src_reg() as usize;
    let dst_reg = insn.dst_reg() as usize;

    let imm = insn.imm();

    let d = match BITS {
        BITS_64 => ctx.regs[dst_reg],
        BITS_32 => ctx.regs[dst_reg] & 0xFFFFFFFF,
    };

    let s = match (jmp_src, BITS) {
        (Source::Imm, BITS_64) => imm as i64 as u64,
        (Source::Imm, BITS_32) => imm as u32 as u64,
        (Source::Reg, BITS_64) => ctx.regs[src_reg],
        (Source::Reg, BITS_32) => ctx.regs[src_reg] & 0xFFFFFFFF,
    };

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
        JmpOpc::Jsgt => match BITS {
            BITS_64 => (d as i64) > (s as i64),
            BITS_32 => (d as i32) > (s as i32),
        },
        JmpOpc::Jsge => match BITS {
            BITS_64 => (d as i64) >= (s as i64),
            BITS_32 => (d as i32) >= (s as i32),
        },
        JmpOpc::Jlt => d < s,
        JmpOpc::Jle => d <= s,
        JmpOpc::Jslt => match BITS {
            BITS_64 => (d as i64) < (s as i64),
            BITS_32 => (d as i32) < (s as i32),
        },
        JmpOpc::Jsle => match BITS {
            BITS_64 => (d as i64) <= (s as i64),
            BITS_32 => (d as i32) <= (s as i32),
        },

        JmpOpc::Call if jmp_src == Source::Reg => return Flow::CallIndirect(d),
        JmpOpc::Call if insn.src_reg() == 0 => return Flow::CallHelper(imm as u32),
        JmpOpc::Call if insn.src_reg() == BPF_PSEUDO_CALL => return Flow::Call(i64::from(imm)),
        JmpOpc::Call if insn.src_reg() == BPF_PSEUDO_KFUNC_CALL => return Flow::CallKfunc(imm as u32),
        JmpOpc::Call => return Flow::Missing,

        JmpOpc::Exit => return Flow::Exit,

        JmpOpc::UndefE | JmpOpc::UndefF => return Flow::FailCpu,
    };

    match cond {
        true => Flow::Jump(insn.offset() as i64),
        false => Flow::Next,
    }
}
