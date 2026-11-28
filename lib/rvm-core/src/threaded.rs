//! Threaded-only folded handlers: multi-instruction sequences packed into a single 8-byte [`Slot`] in
//! [`compile_threaded`](crate::code) without consuming portable opcode bytes.

use crate::bytes::{MOV32_REG, MOV64_REG};
use crate::code::{Slots, ThreadedSlot};
use crate::context::FP;
use crate::dispatch::{DispatchTable, Handler, Spare, SPARE};
use crate::fuel::{Fuel, RestsPtr};
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source};
use crate::slot::{Reg, Slot};
use crate::step::Regs;
use crate::transfer::Ip;
use crate::{windows, Context, Host, Interpreter, Memory};

const JEQ32_IMM: u8 = OpCode::jmp32(JmpOpc::Jeq, Source::Imm).0;
const JEQ64_IMM: u8 = OpCode::jmp64(JmpOpc::Jeq, Source::Imm).0;
const JNE32_IMM: u8 = OpCode::jmp32(JmpOpc::Jne, Source::Imm).0;
const JNE64_IMM: u8 = OpCode::jmp64(JmpOpc::Jne, Source::Imm).0;

const LDX_B: u8 = OpCode::ldx(MemSize::Byte, MemMode::Mem).0;
const LDX_W: u8 = OpCode::ldx(MemSize::Word, MemMode::Mem).0;
const LDX_DW: u8 = OpCode::ldx(MemSize::DWord, MemMode::Mem).0;
const STX_B: u8 = OpCode::stx(MemSize::Byte, MemMode::Mem).0;
const STX_W: u8 = OpCode::stx(MemSize::Word, MemMode::Mem).0;
const STX_DW: u8 = OpCode::stx(MemSize::DWord, MemMode::Mem).0;
const ST_B: u8 = OpCode::st(MemSize::Byte, MemMode::Mem).0;
const ST_W: u8 = OpCode::st(MemSize::Word, MemMode::Mem).0;
const ST_DW: u8 = OpCode::st(MemSize::DWord, MemMode::Mem).0;

const ADD32_REG: u8 = OpCode::alu32(AluOpc::Add, Source::Reg).0;
const ADD64_REG: u8 = OpCode::alu64(AluOpc::Add, Source::Reg).0;
const ADD64_IMM: u8 = OpCode::alu64(AluOpc::Add, Source::Imm).0;
const MUL32_REG: u8 = OpCode::alu32(AluOpc::Mul, Source::Reg).0;
const MUL64_REG: u8 = OpCode::alu64(AluOpc::Mul, Source::Reg).0;
const MUL64_IMM: u8 = OpCode::alu64(AluOpc::Mul, Source::Imm).0;
const AND32_IMM: u8 = OpCode::alu32(AluOpc::And, Source::Imm).0;
const AND64_IMM: u8 = OpCode::alu64(AluOpc::And, Source::Imm).0;
const XOR32_REG: u8 = OpCode::alu32(AluOpc::Xor, Source::Reg).0;
const XOR64_REG: u8 = OpCode::alu64(AluOpc::Xor, Source::Reg).0;
const MOV32_IMM: u8 = OpCode::alu32(AluOpc::Mov, Source::Imm).0;
const MOV64_IMM: u8 = OpCode::alu64(AluOpc::Mov, Source::Imm).0;
const LSH32_IMM: u8 = OpCode::alu32(AluOpc::Lsh, Source::Imm).0;
const RSH32_IMM: u8 = OpCode::alu32(AluOpc::Rsh, Source::Imm).0;
const OR32_REG: u8 = OpCode::alu32(AluOpc::Or, Source::Reg).0;
const LSH64_IMM: u8 = OpCode::alu64(AluOpc::Lsh, Source::Imm).0;
const RSH64_IMM: u8 = OpCode::alu64(AluOpc::Rsh, Source::Imm).0;
const OR64_REG: u8 = OpCode::alu64(AluOpc::Or, Source::Reg).0;

const SHIFT_OP_XOR: u8 = 0;
const SHIFT_OP_OR: u8 = 1;
const SHIFT_OP_ADD: u8 = 2;

const SRC_OP_ADD: u8 = 0;
const SRC_OP_MUL: u8 = 1;
const SRC_OP_XOR: u8 = 2;

const CMP_EQ: u8 = 0;
const CMP_LT: u8 = 1;
const CMP_SLT: u8 = 2;

/// Handler table for threaded folded sequences.
pub struct FoldTable<M: Memory, H> {
    pub mov_ja_imm: [Handler<M, H>; 2],
    pub mov_ja_reg: [Handler<M, H>; 2],
    /// Branchless `jcc_reg +1; mov` handlers indexed by `[bits64]`.
    pub select_reg_imm: [Handler<M, H>; 2],
    pub select_reg_reg: [Handler<M, H>; 2],
    pub rot: [[Handler<M, H>; 2]; 2],
    /// Shifted register ALU handlers indexed by `[bits64][lsh][op]` (`op`: 0=xor, 1=or, 2=add).
    pub shift_alu: [[[Handler<M, H>; 3]; 2]; 2],
    /// Bitfield extract (`(src >> k) & imm`) indexed by `[bits64]`.
    pub rsh_and_imm: [Handler<M, H>; 2],
    /// `dst = s1 * imm + s2` (`[1]`) and `dst = s1 + imm + s2` (`[0]`).
    pub imm_add_reg: [Handler<M, H>; 2],
    /// Register move pairs (`mov d0, s0; mov d1, s1`) across `r0..r47`, indexed by `[bits64_0][bits64_1]`.
    pub mov_mov_reg: [[Handler<M, H>; 2]; 2],
    /// Immediate move followed by register move (`mov d0, imm; mov d1, s1`), indexed by `[imm64][reg64]`.
    pub mov_imm_mov_reg: [[Handler<M, H>; 2]; 2],
    /// Reload into source ALU (`mov t, s1; op dst, t`) indexed by `[bits64][op]` (`op`: 0=add, 1=mul, 2=xor).
    pub mov_alu_src: [[Handler<M, H>; 3]; 2],
    pub add_ldx: [Handler<M, H>; 3],
    pub add_stx: [Handler<M, H>; 3],
    pub mov_add_ldx: [Handler<M, H>; 3],
    pub mov_add_stx: [Handler<M, H>; 3],
    pub mov_add_st: [Handler<M, H>; 3],
    /// Global array load (`lddw a, ptr; add64 a, idx; ldx{b,w,dw} dst, [a + off]`).
    pub lddw_add_ldx: [Handler<M, H>; 3],
    /// Global array register store (`lddw a, ptr; add64 a, idx; stx{b,w,dw} [a + off], val`).
    pub lddw_add_stx: [Handler<M, H>; 3],
    /// Global array immediate store (`lddw a, ptr; add64 a, idx; st{b,w,dw} [a + off], imm`).
    pub lddw_add_st: [Handler<M, H>; 3],
    /// Byte load and `u8` equality or inequality branch (`[0]` = `jne`, `[1]` = `jeq`).
    pub ldxb_jcc_u8: [Handler<M, H>; 2],
}

pub const fn table<M: Memory, H: Host<M>, F: Fuel>() -> FoldTable<M, H> {
    FoldTable {
        mov_ja_imm: [mov_ja_imm::<M, H, F, false>, mov_ja_imm::<M, H, F, true>],
        mov_ja_reg: [mov_ja_reg::<M, H, F, false>, mov_ja_reg::<M, H, F, true>],
        select_reg_imm: [select_reg_imm::<M, H, F, false>, select_reg_imm::<M, H, F, true>],
        select_reg_reg: [select_reg_reg::<M, H, F, false>, select_reg_reg::<M, H, F, true>],
        rot: [
            [rot::<M, H, false, false>, rot::<M, H, false, true>],
            [rot::<M, H, true, false>, rot::<M, H, true, true>],
        ],
        shift_alu: [
            [
                [
                    shift_alu::<M, H, false, false, SHIFT_OP_XOR>,
                    shift_alu::<M, H, false, false, SHIFT_OP_OR>,
                    shift_alu::<M, H, false, false, SHIFT_OP_ADD>,
                ],
                [
                    shift_alu::<M, H, false, true, SHIFT_OP_XOR>,
                    shift_alu::<M, H, false, true, SHIFT_OP_OR>,
                    shift_alu::<M, H, false, true, SHIFT_OP_ADD>,
                ],
            ],
            [
                [
                    shift_alu::<M, H, true, false, SHIFT_OP_XOR>,
                    shift_alu::<M, H, true, false, SHIFT_OP_OR>,
                    shift_alu::<M, H, true, false, SHIFT_OP_ADD>,
                ],
                [
                    shift_alu::<M, H, true, true, SHIFT_OP_XOR>,
                    shift_alu::<M, H, true, true, SHIFT_OP_OR>,
                    shift_alu::<M, H, true, true, SHIFT_OP_ADD>,
                ],
            ],
        ],
        rsh_and_imm: [rsh_and_imm::<M, H, false>, rsh_and_imm::<M, H, true>],
        imm_add_reg: [imm_add_reg::<M, H, false>, imm_add_reg::<M, H, true>],
        mov_mov_reg: [
            [mov_mov_reg::<M, H, false, false>, mov_mov_reg::<M, H, false, true>],
            [mov_mov_reg::<M, H, true, false>, mov_mov_reg::<M, H, true, true>],
        ],
        mov_imm_mov_reg: [
            [
                mov_imm_mov_reg::<M, H, false, false>,
                mov_imm_mov_reg::<M, H, false, true>,
            ],
            [
                mov_imm_mov_reg::<M, H, true, false>,
                mov_imm_mov_reg::<M, H, true, true>,
            ],
        ],
        mov_alu_src: [
            [
                mov_alu_src::<M, H, false, SRC_OP_ADD>,
                mov_alu_src::<M, H, false, SRC_OP_MUL>,
                mov_alu_src::<M, H, false, SRC_OP_XOR>,
            ],
            [
                mov_alu_src::<M, H, true, SRC_OP_ADD>,
                mov_alu_src::<M, H, true, SRC_OP_MUL>,
                mov_alu_src::<M, H, true, SRC_OP_XOR>,
            ],
        ],
        add_ldx: [add_ldx::<M, H, LDX_B>, add_ldx::<M, H, LDX_W>, add_ldx::<M, H, LDX_DW>],
        add_stx: [add_stx::<M, H, STX_B>, add_stx::<M, H, STX_W>, add_stx::<M, H, STX_DW>],
        mov_add_ldx: [
            mov_add_ldx::<M, H, LDX_B>,
            mov_add_ldx::<M, H, LDX_W>,
            mov_add_ldx::<M, H, LDX_DW>,
        ],
        mov_add_stx: [
            mov_add_stx::<M, H, STX_B>,
            mov_add_stx::<M, H, STX_W>,
            mov_add_stx::<M, H, STX_DW>,
        ],
        mov_add_st: [
            mov_add_st::<M, H, ST_B>,
            mov_add_st::<M, H, ST_W>,
            mov_add_st::<M, H, ST_DW>,
        ],
        lddw_add_ldx: [
            lddw_add_ldx::<M, H, LDX_B>,
            lddw_add_ldx::<M, H, LDX_W>,
            lddw_add_ldx::<M, H, LDX_DW>,
        ],
        lddw_add_stx: [
            lddw_add_stx::<M, H, STX_B>,
            lddw_add_stx::<M, H, STX_W>,
            lddw_add_stx::<M, H, STX_DW>,
        ],
        lddw_add_st: [
            lddw_add_st::<M, H, ST_B>,
            lddw_add_st::<M, H, ST_W>,
            lddw_add_st::<M, H, ST_DW>,
        ],
        ldxb_jcc_u8: [ldxb_jcc_u8::<M, H, F, false>, ldxb_jcc_u8::<M, H, F, true>],
    }
}

/// Try to extend superinstruction `0xf7` (`lddw a, ptr; add64 a, idx`) with a following `ldx`, `stx`, or `st`.
pub fn try_fold_0xf7<M: Memory, H: Host<M>>(
    slots: &[Slot],
    i: usize,
    len: usize,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    if i + 3 >= len {
        return None;
    }
    let s0 = slots[i];
    let s2 = slots[i + 2];
    let s3 = slots[i + 3];
    let a = s0.dst_reg_decoded();
    let idx = s2.src_reg_decoded();
    if idx == a {
        return None;
    }
    let off = i8::try_from(s3.offset_raw()).ok()?;
    let b3 = s3.byte();
    match b3 {
        LDX_B | LDX_W | LDX_DW => {
            if s3.src_reg_decoded() != a {
                return None;
            }
            let dst = s3.dst_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.lddw_add_ldx[size_idx(b3)] as *const (),
                slot: Slot::pack_bytes(a.get(), idx.get(), dst.get(), off as u8, s0.imm()),
            })
        }
        STX_B | STX_W | STX_DW => {
            if s3.dst_reg_decoded() != a {
                return None;
            }
            let val = s3.src_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.lddw_add_stx[size_idx(b3)] as *const (),
                slot: Slot::pack_bytes(a.get(), idx.get(), val.get(), off as u8, s0.imm()),
            })
        }
        ST_B | ST_W | ST_DW => {
            if s3.dst_reg_decoded() != a {
                return None;
            }
            Some(ThreadedSlot {
                handler: table.folds.lddw_add_st[size_idx(b3)] as *const (),
                slot: Slot::pack_bytes(a.get(), idx.get(), 0, off as u8, s0.imm()),
            })
        }
        _ => None,
    }
}

/// Try to fold a sequence starting at `i` in `slots[..len]` into one [`ThreadedSlot`].
///
/// Returns `(folded, protect_len)` where `protect_len > 0` keeps slots `[i + 1 .. i + protect_len)` unfolded so
/// window miss fallbacks can tail call them directly.
pub fn try_fold<M: Memory, H: Host<M>>(
    slots: &[Slot],
    i: usize,
    len: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<(ThreadedSlot, usize)> {
    if i + 3 < len {
        if let Some(folded) = fold_rot(slots[i], slots[i + 1], slots[i + 2], slots[i + 3], table) {
            return Some((folded, 0));
        }
    }
    if i + 2 < len {
        let (a, b, c) = (slots[i], slots[i + 1], slots[i + 2]);
        if let Some(folded) = fold_mov_add_mem(a, b, c, table) {
            return Some((folded, 3));
        }
        if let Some(folded) = fold_mov_shift_alu(a, b, c, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_mov_rsh_and(a, b, c, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_mov_imm_add_reg(a, b, c, table) {
            return Some((folded, 0));
        }
    }
    if i + 1 < len {
        let a = slots[i];
        let b = slots[i + 1];
        if let Some(folded) = fold_mov_ja(a, b, i, table, rests) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_select(a, b, i, table, rests) {
            return Some((folded, 2));
        }
        if let Some(folded) = fold_add_mem(a, b, table) {
            return Some((folded, 2));
        }
        if let Some(folded) = fold_ldxb_jcc(a, b, i, table, rests) {
            return Some((folded, 2));
        }
        if let Some(folded) = fold_shift_alu(a, b, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_rsh_and(a, b, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_imm_add_reg(a, b, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_mov_mov_reg(slots, i, len, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_mov_imm_mov_reg(slots, i, len, table) {
            return Some((folded, 0));
        }
        if let Some(folded) = fold_mov_alu_src(a, b, table) {
            return Some((folded, 0));
        }
    }
    None
}

// --- Matchers ---

fn fold_rot<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    s2: Slot,
    s3: Slot,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let (bits64, lsh_first) = match (s0.byte(), s1.byte(), s2.byte(), s3.byte()) {
        (MOV32_REG, RSH32_IMM, LSH32_IMM, OR32_REG) => (false, false),
        (MOV32_REG, LSH32_IMM, RSH32_IMM, OR32_REG) => (false, true),
        (MOV64_REG, RSH64_IMM, LSH64_IMM, OR64_REG) => (true, false),
        (MOV64_REG, LSH64_IMM, RSH64_IMM, OR64_REG) => (true, true),
        _ => return None,
    };
    let t = s0.dst_reg_decoded();
    let x = s0.src_reg_decoded();
    if t == x
        || s1.dst_reg_decoded() != t
        || s2.dst_reg_decoded() != x
        || s3.dst_reg_decoded() != x
        || s3.src_reg_decoded() != t
    {
        return None;
    }
    let mask = if bits64 { 63u8 } else { 31u8 };
    let k1 = (s1.imm() as u8) & mask;
    let k2 = (s2.imm() as u8) & mask;
    let handler = table.folds.rot[usize::from(bits64)][usize::from(lsh_first)] as *const ();
    Some(ThreadedSlot {
        handler,
        slot: Slot::pack_bytes(x.get(), t.get(), k1, k2, 0),
    })
}

fn fold_mov_add_mem<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    s2: Slot,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    if s0.byte() != MOV64_REG || s1.byte() != ADD64_REG {
        return None;
    }
    let a = s0.dst_reg_decoded();
    if s1.dst_reg_decoded() != a {
        return None;
    }
    let base = s0.src_reg_decoded();
    let mut idx = s1.src_reg_decoded();
    if idx == a {
        idx = base;
    }
    let b2 = s2.byte();
    let off = s2.offset_raw();
    match b2 {
        LDX_B | LDX_W | LDX_DW => {
            if s2.src_reg_decoded() != a {
                return None;
            }
            let sz = size_idx(b2);
            let dst = s2.dst_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.mov_add_ldx[sz] as *const (),
                slot: Slot::pack_bytes(a.get(), base.get(), idx.get(), dst.get(), i32::from(off)),
            })
        }
        STX_B | STX_W | STX_DW => {
            if s2.dst_reg_decoded() != a {
                return None;
            }
            let sz = size_idx(b2);
            let val = s2.src_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.mov_add_stx[sz] as *const (),
                slot: Slot::pack_bytes(a.get(), base.get(), idx.get(), val.get(), i32::from(off)),
            })
        }
        ST_B | ST_W | ST_DW if off == 0 => {
            if s2.dst_reg_decoded() != a {
                return None;
            }
            let sz = size_idx(b2);
            Some(ThreadedSlot {
                handler: table.folds.mov_add_st[sz] as *const (),
                slot: Slot::pack_bytes(a.get(), base.get(), idx.get(), 0, s2.imm()),
            })
        }
        _ => None,
    }
}

fn fold_mov_ja<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    i: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<ThreadedSlot> {
    let ja_opc = OpCode(s1.byte());
    if !matches!(ja_opc.jmp_opc(), JmpOpc::Ja) || !matches!(ja_opc.source(), Source::Imm) {
        return None;
    }
    let ja_off = match ja_opc.class() {
        Class::Jmp64 => i64::from(s1.offset_raw()),
        Class::Jmp32 => i64::from(s1.imm()),
        _ => return None,
    };
    let byte_off = (ja_off + 2).checked_mul(size_of::<ThreadedSlot>() as i64)?;
    let target_pc = (i as i64 + 2 + ja_off) as usize;
    let rest = rests.map_or(0, |r| r[target_pc]);
    match s0.byte() {
        MOV32_IMM | MOV64_IMM => {
            let bits64 = s0.byte() == MOV64_IMM;
            let off16 = i16::try_from(byte_off).ok()?;
            let rest8 = u8::try_from(rest).ok()?;
            let dst = s0.dst_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.mov_ja_imm[usize::from(bits64)] as *const (),
                slot: Slot::pack(dst.get(), rest8, off16, s0.imm()),
            })
        }
        MOV32_REG | MOV64_REG => {
            let bits64 = s0.byte() == MOV64_REG;
            let off32 = i32::try_from(byte_off).ok()?;
            let rest16 = u16::try_from(rest).ok()?;
            let dst = s0.dst_reg_decoded();
            let src = s0.src_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.mov_ja_reg[usize::from(bits64)] as *const (),
                slot: Slot::pack(dst.get(), src.get(), rest16 as i16, off32),
            })
        }
        _ => None,
    }
}

fn normalize_reg_cmp(op: JmpOpc) -> Option<(u8, bool, bool)> {
    // Returns `(kind, invert, swap_operands)` so all 10 register comparisons reduce to `EQ`, `LT`, or `SLT`.
    match op {
        JmpOpc::Jeq => Some((CMP_EQ, false, false)),
        JmpOpc::Jne => Some((CMP_EQ, true, false)),
        JmpOpc::Jlt => Some((CMP_LT, false, false)),
        JmpOpc::Jge => Some((CMP_LT, true, false)),
        JmpOpc::Jgt => Some((CMP_LT, false, true)),
        JmpOpc::Jle => Some((CMP_LT, true, true)),
        JmpOpc::Jslt => Some((CMP_SLT, false, false)),
        JmpOpc::Jsge => Some((CMP_SLT, true, false)),
        JmpOpc::Jsgt => Some((CMP_SLT, false, true)),
        JmpOpc::Jsle => Some((CMP_SLT, true, true)),
        _ => None,
    }
}

fn fold_select<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    i: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<ThreadedSlot> {
    let opc = OpCode(s0.byte());
    let bits64 = match opc.class() {
        Class::Jmp32 => false,
        Class::Jmp64 => true,
        _ => return None,
    };
    if !matches!(opc.source(), Source::Reg) || s0.offset_raw() != 1 {
        return None;
    }
    let (mov_is_reg, mov64) = match s1.byte() {
        MOV32_IMM => (false, false),
        MOV64_IMM => (false, true),
        MOV32_REG => (true, false),
        MOV64_REG => (true, true),
        _ => return None,
    };
    let (kind, invert, swap) = normalize_reg_cmp(opc.jmp_opc())?;
    let (mut a, mut b) = (s0.dst_reg_decoded(), s0.src_reg_decoded());
    if swap {
        core::mem::swap(&mut a, &mut b);
    }
    let dst = s1.dst_reg_decoded();
    let fall_rest8 = u8::try_from(rests.map_or(0, |r| r[i + 2])).ok()?;
    let meta = kind | (u8::from(invert) << 2) | (u8::from(mov64) << 3);
    if mov_is_reg {
        let src = s1.src_reg_decoded();
        let payload = i32::from_le_bytes([meta, fall_rest8, 0, 0]);
        Some(ThreadedSlot {
            handler: table.folds.select_reg_reg[usize::from(bits64)] as *const (),
            slot: Slot::pack_bytes(a.get(), b.get(), dst.get(), src.get(), payload),
        })
    } else {
        Some(ThreadedSlot {
            handler: table.folds.select_reg_imm[usize::from(bits64)] as *const (),
            slot: Slot::pack_bytes(a.get(), b.get(), dst.get(), meta, i32::from(fall_rest8)),
        })
    }
}

fn fold_add_mem<M: Memory, H: Host<M>>(s0: Slot, s1: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    if s0.byte() != ADD64_REG {
        return None;
    }
    let a = s0.dst_reg_decoded();
    let b = s0.src_reg_decoded();
    let b1 = s1.byte();
    let off = s1.offset_raw();
    match b1 {
        LDX_B | LDX_W | LDX_DW => {
            if s1.src_reg_decoded() != a {
                return None;
            }
            let sz = size_idx(b1);
            let dst = s1.dst_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.add_ldx[sz] as *const (),
                slot: Slot::pack_bytes(a.get(), b.get(), dst.get(), 0, i32::from(off)),
            })
        }
        STX_B | STX_W | STX_DW => {
            if s1.dst_reg_decoded() != a {
                return None;
            }
            let sz = size_idx(b1);
            let val = s1.src_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.add_stx[sz] as *const (),
                slot: Slot::pack_bytes(a.get(), b.get(), val.get(), 0, i32::from(off)),
            })
        }
        _ => None,
    }
}

fn fold_ldxb_jcc<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    i: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<ThreadedSlot> {
    if s0.byte() != LDX_B {
        return None;
    }
    let eq = match s1.byte() {
        JEQ32_IMM | JEQ64_IMM => true,
        JNE32_IMM | JNE64_IMM => false,
        _ => return None,
    };
    let dst = s0.dst_reg_decoded();
    let base = s0.src_reg_decoded();
    if usize::from(base.get()) == FP || s1.dst_reg_decoded() != dst {
        return None;
    }
    let imm8 = u8::try_from(s1.imm()).ok()?;
    let off8 = i8::try_from(s0.offset_raw()).ok()?;
    let byte_off = i16::try_from((i32::from(s1.offset_raw()) + 2) * (size_of::<ThreadedSlot>() as i32)).ok()?;
    let target_pc = (i as i64 + 2 + i64::from(s1.offset_raw())) as usize;
    let taken_rest = u8::try_from(rests.map_or(0, |r| r[target_pc])).ok()?;
    let fall_rest = u8::try_from(rests.map_or(0, |r| r[i + 2])).ok()?;
    let [bo0, bo1] = byte_off.to_le_bytes();
    let payload = i32::from_le_bytes([bo0, bo1, taken_rest, fall_rest]);
    Some(ThreadedSlot {
        handler: table.folds.ldxb_jcc_u8[usize::from(eq)] as *const (),
        slot: Slot::pack_bytes(dst.get(), base.get(), imm8, off8 as u8, payload),
    })
}

fn fold_shift_alu_inner<M: Memory, H: Host<M>>(
    s_shift: Slot,
    s_alu: Slot,
    dst: Reg,
    s1: Reg,
    byte_adv: i32,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let (bits64, lsh) = match s_shift.byte() {
        LSH32_IMM => (false, true),
        RSH32_IMM => (false, false),
        LSH64_IMM => (true, true),
        RSH64_IMM => (true, false),
        _ => return None,
    };
    let op_idx = match (bits64, s_alu.byte()) {
        (false, XOR32_REG) | (true, XOR64_REG) => SHIFT_OP_XOR,
        (false, OR32_REG) | (true, OR64_REG) => SHIFT_OP_OR,
        (false, ADD32_REG) | (true, ADD64_REG) => SHIFT_OP_ADD,
        _ => return None,
    };
    if s_shift.dst_reg_decoded() != dst || s_alu.dst_reg_decoded() != dst {
        return None;
    }
    let s2 = s_alu.src_reg_decoded();
    if s2 == dst {
        return None;
    }
    let mask = if bits64 { 63u8 } else { 31u8 };
    let k = (s_shift.imm() as u8) & mask;
    let handler = table.folds.shift_alu[usize::from(bits64)][usize::from(lsh)][usize::from(op_idx)] as *const ();
    Some(ThreadedSlot {
        handler,
        slot: Slot::pack_bytes(dst.get(), s1.get(), s2.get(), k, byte_adv),
    })
}

fn fold_mov_shift_alu<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    s2: Slot,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let mov64 = match s0.byte() {
        MOV64_REG => true,
        MOV32_REG => false,
        _ => return None,
    };
    if !mov64 && matches!(s1.byte(), LSH64_IMM | RSH64_IMM) {
        return None;
    }
    let dst = s0.dst_reg_decoded();
    let src1 = s0.src_reg_decoded();
    fold_shift_alu_inner(s1, s2, dst, src1, (3 * size_of::<ThreadedSlot>()) as i32, table)
}

fn fold_shift_alu<M: Memory, H: Host<M>>(s0: Slot, s1: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    if !matches!(s0.byte(), LSH32_IMM | RSH32_IMM | LSH64_IMM | RSH64_IMM) {
        return None;
    }
    let dst = s0.dst_reg_decoded();
    fold_shift_alu_inner(s0, s1, dst, dst, (2 * size_of::<ThreadedSlot>()) as i32, table)
}

fn fold_rsh_and_inner<M: Memory, H: Host<M>>(
    s_rsh: Slot,
    s_and: Slot,
    dst: Reg,
    s1: Reg,
    byte_adv: u8,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let bits64 = match (s_rsh.byte(), s_and.byte()) {
        (RSH32_IMM, AND32_IMM) => false,
        (RSH64_IMM, AND64_IMM) => true,
        _ => return None,
    };
    if s_rsh.dst_reg_decoded() != dst || s_and.dst_reg_decoded() != dst {
        return None;
    }
    let mask = if bits64 { 63u8 } else { 31u8 };
    let k = (s_rsh.imm() as u8) & mask;
    Some(ThreadedSlot {
        handler: table.folds.rsh_and_imm[usize::from(bits64)] as *const (),
        slot: Slot::pack_bytes(dst.get(), s1.get(), k, byte_adv, s_and.imm()),
    })
}

fn fold_mov_rsh_and<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    s2: Slot,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let mov64 = match s0.byte() {
        MOV64_REG => true,
        MOV32_REG => false,
        _ => return None,
    };
    if !mov64 && s1.byte() == RSH64_IMM {
        return None;
    }
    let dst = s0.dst_reg_decoded();
    let src1 = s0.src_reg_decoded();
    fold_rsh_and_inner(s1, s2, dst, src1, (3 * size_of::<ThreadedSlot>()) as u8, table)
}

fn fold_rsh_and<M: Memory, H: Host<M>>(s0: Slot, s1: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    if !matches!(s0.byte(), RSH32_IMM | RSH64_IMM) {
        return None;
    }
    let dst = s0.dst_reg_decoded();
    fold_rsh_and_inner(s0, s1, dst, dst, (2 * size_of::<ThreadedSlot>()) as u8, table)
}

fn fold_imm_add_reg_inner<M: Memory, H: Host<M>>(
    s_imm: Slot,
    s_add: Slot,
    dst: Reg,
    s1: Reg,
    byte_adv: u8,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let is_mul = match s_imm.byte() {
        ADD64_IMM => false,
        MUL64_IMM => true,
        _ => return None,
    };
    if s_add.byte() != ADD64_REG || s_imm.dst_reg_decoded() != dst || s_add.dst_reg_decoded() != dst {
        return None;
    }
    let s2 = s_add.src_reg_decoded();
    if s2 == dst {
        return None;
    }
    Some(ThreadedSlot {
        handler: table.folds.imm_add_reg[usize::from(is_mul)] as *const (),
        slot: Slot::pack_bytes(dst.get(), s1.get(), s2.get(), byte_adv, s_imm.imm()),
    })
}

fn fold_mov_imm_add_reg<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    s2: Slot,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    if s0.byte() != MOV64_REG {
        return None;
    }
    let dst = s0.dst_reg_decoded();
    let src1 = s0.src_reg_decoded();
    fold_imm_add_reg_inner(s1, s2, dst, src1, (3 * size_of::<ThreadedSlot>()) as u8, table)
}

fn fold_imm_add_reg<M: Memory, H: Host<M>>(s0: Slot, s1: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    if !matches!(s0.byte(), ADD64_IMM | MUL64_IMM) {
        return None;
    }
    let dst = s0.dst_reg_decoded();
    fold_imm_add_reg_inner(s0, s1, dst, dst, (2 * size_of::<ThreadedSlot>()) as u8, table)
}

/// Whether `mov_slot` (`MOV32_REG` or `MOV64_REG`) feeds directly into a fold with `next` (`alu3`, `rot`,
/// `mov_add_*`, `mov_shift_alu`, `mov_ja`, `mov_alu_src`), so a preceding `mov` should not steal it into `mov_mov_reg`.
fn mov_feeds_next(mov_slot: Slot, next: Slot) -> bool {
    let mov64 = mov_slot.byte() == MOV64_REG;
    let d = mov_slot.dst_reg_decoded();
    let opc = OpCode(next.byte());
    match opc.class() {
        Class::Jmp32 | Class::Jmp64 => matches!(opc.jmp_opc(), JmpOpc::Ja) && matches!(opc.source(), Source::Imm),
        Class::Alu32 | Class::Alu64 => {
            if matches!(opc.class(), Class::Alu64) && !mov64 {
                return false;
            }
            let alu_ok = matches!(
                opc.alu_opc(),
                AluOpc::Add
                    | AluOpc::Sub
                    | AluOpc::Mul
                    | AluOpc::Or
                    | AluOpc::And
                    | AluOpc::Xor
                    | AluOpc::Lsh
                    | AluOpc::Rsh
                    | AluOpc::Arsh
            );
            if !alu_ok {
                return false;
            }
            if next.dst_reg_decoded() == d {
                return true;
            }
            let same_width = matches!(opc.class(), Class::Alu64) == mov64;
            same_width
                && matches!(opc.source(), Source::Reg)
                && matches!(opc.alu_opc(), AluOpc::Add | AluOpc::Mul | AluOpc::Xor)
                && next.src_reg_decoded() == d
        }
        _ => false,
    }
}

fn fold_mov_mov_reg<M: Memory, H: Host<M>>(
    slots: &[Slot],
    i: usize,
    len: usize,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let s0 = slots[i];
    let s1 = slots[i + 1];
    let bits64_0 = match s0.byte() {
        MOV32_REG => false,
        MOV64_REG => true,
        _ => return None,
    };
    let bits64_1 = match s1.byte() {
        MOV32_REG => false,
        MOV64_REG => true,
        _ => return None,
    };
    if i + 2 < len && mov_feeds_next(s1, slots[i + 2]) {
        return None;
    }
    let d0 = s0.dst_reg_decoded();
    let src0 = s0.src_reg_decoded();
    let d1 = s1.dst_reg_decoded();
    let mut src1 = s1.src_reg_decoded();
    if src1 == d0 {
        if bits64_0 || !bits64_1 {
            src1 = src0;
        } else {
            return None;
        }
    }
    let handler = table.folds.mov_mov_reg[usize::from(bits64_0)][usize::from(bits64_1)] as *const ();
    Some(ThreadedSlot {
        handler,
        slot: Slot::pack_bytes(d0.get(), src0.get(), d1.get(), src1.get(), 0),
    })
}

fn fold_mov_imm_mov_reg<M: Memory, H: Host<M>>(
    slots: &[Slot],
    i: usize,
    len: usize,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let s0 = slots[i];
    let s1 = slots[i + 1];
    let imm64 = match s0.byte() {
        MOV32_IMM => false,
        MOV64_IMM => true,
        _ => return None,
    };
    let reg64 = match s1.byte() {
        MOV32_REG => false,
        MOV64_REG => true,
        _ => return None,
    };
    if i + 2 < len && mov_feeds_next(s1, slots[i + 2]) {
        return None;
    }
    let d0 = s0.dst_reg_decoded();
    let d1 = s1.dst_reg_decoded();
    let src1 = s1.src_reg_decoded();
    if src1 == d0 {
        return None;
    }
    let handler = table.folds.mov_imm_mov_reg[usize::from(imm64)][usize::from(reg64)] as *const ();
    Some(ThreadedSlot {
        handler,
        slot: Slot::pack_bytes(d0.get(), d1.get(), src1.get(), 0, s0.imm()),
    })
}

fn fold_mov_alu_src<M: Memory, H: Host<M>>(s0: Slot, s1: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    let (bits64, op_idx) = match (s0.byte(), s1.byte()) {
        (MOV32_REG, ADD32_REG) => (false, SRC_OP_ADD),
        (MOV32_REG, MUL32_REG) => (false, SRC_OP_MUL),
        (MOV32_REG, XOR32_REG) => (false, SRC_OP_XOR),
        (MOV64_REG, ADD64_REG) => (true, SRC_OP_ADD),
        (MOV64_REG, MUL64_REG) => (true, SRC_OP_MUL),
        (MOV64_REG, XOR64_REG) => (true, SRC_OP_XOR),
        _ => return None,
    };
    let t = s0.dst_reg_decoded();
    let dst = s1.dst_reg_decoded();
    if s1.src_reg_decoded() != t || dst == t {
        return None;
    }
    let src1 = s0.src_reg_decoded();
    let handler = table.folds.mov_alu_src[usize::from(bits64)][usize::from(op_idx)] as *const ();
    Some(ThreadedSlot {
        handler,
        slot: Slot::pack_bytes(t.get(), src1.get(), dst.get(), 0, 0),
    })
}

#[inline(always)]
fn size_idx(op: u8) -> usize {
    match OpCode(op).mem_size() {
        MemSize::Byte => 0,
        MemSize::Word => 1,
        MemSize::DWord => 2,
        MemSize::Half => unreachable!(),
    }
}

// --- Handlers ---

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_ja_imm<M: Memory, H: Host<M>, F: Fuel, const BITS64: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_ja` packed `dst` into byte 0.
    let dst = unsafe { slot.reg0() };
    let val = match BITS64 {
        true => slot.imm_i32() as i64 as u64,
        false => slot.imm_i32() as u32 as u64,
    };
    ctx.reg_set(dst, val);
    let byte_off = slot.offset_raw() as isize;
    let rest = u64::from(slot.byte1());
    become_enter_rest!(ctx, code, ip.byte_offset(byte_off), interp, rests, rest)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_ja_reg<M: Memory, H: Host<M>, F: Fuel, const BITS64: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_ja` packed `dst` into byte 0 and `src` into byte 1.
    let dst = unsafe { slot.reg0() };
    let src = unsafe { slot.reg1() };
    let raw = ctx.reg_get(src);
    let val = if BITS64 { raw } else { raw as u32 as u64 };
    ctx.reg_set(dst, val);
    let byte_off = slot.imm_i32() as isize;
    let rest = u64::from(slot.offset_raw() as u16);
    become_enter_rest!(ctx, code, ip.byte_offset(byte_off), interp, rests, rest)
}

#[inline(always)]
fn eval_select_cmp<const BITS64: bool>(lhs: u64, rhs: u64, meta: u8) -> bool {
    let kind = meta & 3;
    let invert = (meta & 4) != 0;
    let (eq, lt, slt) = if BITS64 {
        (lhs == rhs, lhs < rhs, (lhs as i64) < (rhs as i64))
    } else {
        let a = lhs as u32;
        let b = rhs as u32;
        (a == b, a < b, (a as i32) < (b as i32))
    };
    let lt_or_slt = core::hint::select_unpredictable(kind == CMP_LT, lt, slt);
    let raw = core::hint::select_unpredictable(kind == CMP_EQ, eq, lt_or_slt);
    raw ^ invert
}

macro_rules! finish_select {
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $rests:expr, $dst:expr, $rhs:expr, $skip:expr, $fall_rest:expr) => {{
        let skip = $skip;
        let cur = $ctx.reg_get($dst);
        let new_val = core::hint::select_unpredictable(skip, cur, $rhs);
        let rest = $fall_rest + u64::from(!skip);
        if !F::enter_rest($interp, rest) {
            core::hint::cold_path();
            let stop_ip = $ip.offset(1 + i64::from(skip));
            become F::step::<M, H>($ctx, $code, stop_ip, $interp, $rests, SPARE, Slot::UNREAD)
        }
        $ctx.reg_set($dst, new_val);
        become_at!($ctx, $code, $ip.offset(2), $interp, $rests)
    }};
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn select_reg_imm<M: Memory, H: Host<M>, F: Fuel, const BITS64: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_select` packed `a`, `b`, `dst` into bytes 0..3 and kept `mov_imm` in `ip.offset(1)`.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let meta = slot.byte3();
    let fall_rest = u64::from(slot.imm_i32() as u32);
    let skip = eval_select_cmp::<BITS64>(ctx.reg_get(a), ctx.reg_get(b), meta);
    // SAFETY: `ip.offset(1)` is the intact `mov_imm` slot.
    let raw_imm = unsafe { ip.offset(1).get() }.imm_i32();
    let mov_rhs =
        core::hint::select_unpredictable((meta & 8) != 0, i64::from(raw_imm) as u64, u64::from(raw_imm as u32));
    finish_select!(ctx, code, ip, interp, rests, dst, mov_rhs, skip, fall_rest)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn select_reg_reg<M: Memory, H: Host<M>, F: Fuel, const BITS64: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_select` packed `a`, `b`, `dst`, `src` into bytes 0..4.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let src = unsafe { slot.reg3() };
    let payload = slot.imm_i32() as u32;
    let meta = payload as u8;
    let fall_rest = u64::from((payload >> 8) as u8);
    let skip = eval_select_cmp::<BITS64>(ctx.reg_get(a), ctx.reg_get(b), meta);
    let raw = ctx.reg_get(src);
    let mov_rhs = core::hint::select_unpredictable((meta & 8) != 0, raw, raw as u32 as u64);
    finish_select!(ctx, code, ip, interp, rests, dst, mov_rhs, skip, fall_rest)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn rot<M: Memory, H: Host<M>, const BITS64: bool, const LSH_FIRST: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_rot` packed `x` into byte 0 and `t` into byte 1.
    let x_reg = unsafe { slot.reg0() };
    let t_reg = unsafe { slot.reg1() };
    let k1 = u32::from(slot.byte2());
    let k2 = u32::from(slot.byte3());
    if BITS64 {
        let x = ctx.regs.get(x_reg);
        let (t, out) = if LSH_FIRST {
            let t = x << k1;
            (t, (x >> k2) | t)
        } else {
            let t = x >> k1;
            (t, (x << k2) | t)
        };
        ctx.regs.set(t_reg, t);
        ctx.regs.set(x_reg, out);
    } else {
        let x = ctx.regs.get(x_reg) as u32;
        let (t, out) = if LSH_FIRST {
            let t = x << k1;
            (t, (x >> k2) | t)
        } else {
            let t = x >> k1;
            (t, (x << k2) | t)
        };
        ctx.regs.set(t_reg, u64::from(t));
        ctx.regs.set(x_reg, u64::from(out));
    }
    become_at!(ctx, code, ip.offset(4), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn shift_alu<M: Memory, H: Host<M>, const BITS64: bool, const LSH: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_shift_alu_inner` packed `dst`, `s1`, `s2` into bytes 0..3.
    let dst = unsafe { slot.reg0() };
    let s1 = unsafe { slot.reg1() };
    let s2 = unsafe { slot.reg2() };
    let k = u32::from(slot.byte3());
    let out = if BITS64 {
        let v1 = ctx.reg_get(s1);
        let shifted = if LSH { v1 << k } else { v1 >> k };
        let v2 = ctx.reg_get(s2);
        match OP {
            SHIFT_OP_XOR => shifted ^ v2,
            SHIFT_OP_OR => shifted | v2,
            SHIFT_OP_ADD => shifted.wrapping_add(v2),
            _ => unreachable!(),
        }
    } else {
        let v1 = ctx.reg_get(s1) as u32;
        let shifted = if LSH { v1 << k } else { v1 >> k };
        let v2 = ctx.reg_get(s2) as u32;
        u64::from(match OP {
            SHIFT_OP_XOR => shifted ^ v2,
            SHIFT_OP_OR => shifted | v2,
            SHIFT_OP_ADD => shifted.wrapping_add(v2),
            _ => unreachable!(),
        })
    };
    ctx.reg_set(dst, out);
    become_at!(ctx, code, ip.byte_offset(slot.imm_i32() as isize), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn rsh_and_imm<M: Memory, H: Host<M>, const BITS64: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_rsh_and_inner` packed `dst` and `s1` into bytes 0..2.
    let dst = unsafe { slot.reg0() };
    let s1 = unsafe { slot.reg1() };
    let k = u32::from(slot.byte2());
    let adv = isize::from(slot.byte3());
    let out = if BITS64 {
        (ctx.reg_get(s1) >> k) & (i64::from(slot.imm_i32()) as u64)
    } else {
        u64::from(((ctx.reg_get(s1) as u32) >> k) & (slot.imm_i32() as u32))
    };
    ctx.reg_set(dst, out);
    become_at!(ctx, code, ip.byte_offset(adv), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn imm_add_reg<M: Memory, H: Host<M>, const IS_MUL: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_imm_add_reg_inner` packed `dst`, `s1`, `s2` into bytes 0..3.
    let dst = unsafe { slot.reg0() };
    let s1 = unsafe { slot.reg1() };
    let s2 = unsafe { slot.reg2() };
    let adv = isize::from(slot.byte3());
    let imm = i64::from(slot.imm_i32()) as u64;
    let lhs = if IS_MUL {
        ctx.reg_get(s1).wrapping_mul(imm)
    } else {
        ctx.reg_get(s1).wrapping_add(imm)
    };
    ctx.reg_set(dst, lhs.wrapping_add(ctx.reg_get(s2)));
    become_at!(ctx, code, ip.byte_offset(adv), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_mov_reg<M: Memory, H: Host<M>, const BITS64_0: bool, const BITS64_1: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_mov_reg` packed `d0`, `src0`, `d1`, `src1` into bytes 0..4 with `src1 != d0`.
    let d0 = unsafe { slot.reg0() };
    let src0 = unsafe { slot.reg1() };
    let d1 = unsafe { slot.reg2() };
    let src1 = unsafe { slot.reg3() };
    let v0 = if BITS64_0 {
        ctx.reg_get(src0)
    } else {
        ctx.reg_get(src0) as u32 as u64
    };
    let v1 = if BITS64_1 {
        ctx.reg_get(src1)
    } else {
        ctx.reg_get(src1) as u32 as u64
    };
    ctx.reg_set(d0, v0);
    ctx.reg_set(d1, v1);
    become_at!(ctx, code, ip.offset(2), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_imm_mov_reg<M: Memory, H: Host<M>, const IMM64: bool, const REG64: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_imm_mov_reg` packed `d0`, `d1`, `src1` into bytes 0..3 with `src1 != d0`.
    let d0 = unsafe { slot.reg0() };
    let d1 = unsafe { slot.reg1() };
    let src1 = unsafe { slot.reg2() };
    let v0 = if IMM64 {
        i64::from(slot.imm_i32()) as u64
    } else {
        slot.imm_i32() as u32 as u64
    };
    let v1 = if REG64 {
        ctx.reg_get(src1)
    } else {
        ctx.reg_get(src1) as u32 as u64
    };
    ctx.reg_set(d0, v0);
    ctx.reg_set(d1, v1);
    become_at!(ctx, code, ip.offset(2), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_alu_src<M: Memory, H: Host<M>, const BITS64: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_alu_src` packed `t`, `src1`, `dst` into bytes 0..3 with `dst != t`.
    let t = unsafe { slot.reg0() };
    let src1 = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    if BITS64 {
        let v = ctx.reg_get(src1);
        let cur = ctx.reg_get(dst);
        ctx.reg_set(t, v);
        let out = match OP {
            SRC_OP_ADD => cur.wrapping_add(v),
            SRC_OP_MUL => cur.wrapping_mul(v),
            SRC_OP_XOR => cur ^ v,
            _ => unreachable!(),
        };
        ctx.reg_set(dst, out);
    } else {
        let v = ctx.reg_get(src1) as u32;
        let cur = ctx.reg_get(dst) as u32;
        ctx.reg_set(t, u64::from(v));
        let out = match OP {
            SRC_OP_ADD => cur.wrapping_add(v),
            SRC_OP_MUL => cur.wrapping_mul(v),
            SRC_OP_XOR => cur ^ v,
            _ => unreachable!(),
        };
        ctx.reg_set(dst, u64::from(out));
    }
    become_at!(ctx, code, ip.offset(2), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn add_ldx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_add_mem` packed `a`, `b`, `dst` into bytes 0..3.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let addr_reg = ctx.regs.get(a).wrapping_add(ctx.regs.get(b));
    ctx.regs.set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(i64::from(slot.imm_i32()));
    let Some(loaded) = interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, 0)
    else {
        let next = ip.offset(1);
        // SAFETY: `ip.offset(1)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    };
    ctx.regs.set(dst, loaded);
    become_at!(ctx, code, ip.offset(2), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn add_stx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_add_mem` packed `a`, `b`, `val` into bytes 0..3.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let val_reg = unsafe { slot.reg2() };
    let addr_reg = ctx.regs.get(a).wrapping_add(ctx.regs.get(b));
    ctx.regs.set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(i64::from(slot.imm_i32()));
    let val = ctx.regs.get(val_reg);
    if interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, val)
        .is_none()
    {
        let next = ip.offset(1);
        // SAFETY: `ip.offset(1)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(2), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_add_ldx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_add_mem` packed `a`, `base`, `idx`, `dst` into bytes 0..4.
    let a = unsafe { slot.reg0() };
    let base = unsafe { slot.reg1() };
    let idx = unsafe { slot.reg2() };
    let dst = unsafe { slot.reg3() };
    let addr_reg = ctx.reg_get(base).wrapping_add(ctx.reg_get(idx));
    ctx.reg_set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(i64::from(slot.imm_i32()));
    let Some(loaded) = interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, 0)
    else {
        let next = ip.offset(2);
        // SAFETY: `ip.offset(2)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    };
    ctx.reg_set(dst, loaded);
    become_at!(ctx, code, ip.offset(3), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_add_stx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_add_mem` packed `a`, `base`, `idx`, `val` into bytes 0..4.
    let a = unsafe { slot.reg0() };
    let base = unsafe { slot.reg1() };
    let idx = unsafe { slot.reg2() };
    let val_reg = unsafe { slot.reg3() };
    let addr_reg = ctx.reg_get(base).wrapping_add(ctx.reg_get(idx));
    ctx.reg_set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(i64::from(slot.imm_i32()));
    let val = ctx.reg_get(val_reg);
    if interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, val)
        .is_none()
    {
        let next = ip.offset(2);
        // SAFETY: `ip.offset(2)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(3), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn mov_add_st<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_mov_add_mem` packed `a`, `base`, `idx` into bytes 0..3.
    let a = unsafe { slot.reg0() };
    let base = unsafe { slot.reg1() };
    let idx = unsafe { slot.reg2() };
    let addr_reg = ctx.reg_get(base).wrapping_add(ctx.reg_get(idx));
    ctx.reg_set(a, addr_reg);
    let val = i64::from(slot.imm_i32()) as u64;
    if interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr_reg, val)
        .is_none()
    {
        let next = ip.offset(2);
        // SAFETY: `ip.offset(2)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(3), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn lddw_add_ldx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `try_fold_0xf7` packed `a`, `idx`, `dst` into bytes 0..3.
    let a = unsafe { slot.reg0() };
    let idx = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let off = i64::from(slot.byte3() as i8);
    let imm_lo = u64::from(slot.imm_i32() as u32);
    // SAFETY: `ip.offset(1)` is the intact upper half slot of `LD_IMM64`.
    let imm_hi = u64::from(unsafe { ip.offset(1).get() }.imm_i32() as u32);
    let ptr = imm_lo | (imm_hi << 32);
    let addr_reg = ptr.wrapping_add(ctx.regs.get(idx));
    ctx.regs.set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(off);
    let Some(loaded) = interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, 0)
    else {
        let next = ip.offset(3);
        // SAFETY: `ip.offset(3)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    };
    ctx.regs.set(dst, loaded);
    become_at!(ctx, code, ip.offset(4), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn lddw_add_stx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `try_fold_0xf7` packed `a`, `idx`, `val` into bytes 0..3.
    let a = unsafe { slot.reg0() };
    let idx = unsafe { slot.reg1() };
    let val_reg = unsafe { slot.reg2() };
    let off = i64::from(slot.byte3() as i8);
    let imm_lo = u64::from(slot.imm_i32() as u32);
    // SAFETY: `ip.offset(1)` is the intact upper half slot of `LD_IMM64`.
    let imm_hi = u64::from(unsafe { ip.offset(1).get() }.imm_i32() as u32);
    let ptr = imm_lo | (imm_hi << 32);
    let addr_reg = ptr.wrapping_add(ctx.regs.get(idx));
    ctx.regs.set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(off);
    let val = ctx.regs.get(val_reg);
    if interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, val)
        .is_none()
    {
        let next = ip.offset(3);
        // SAFETY: `ip.offset(3)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(4), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn lddw_add_st<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `try_fold_0xf7` packed `a` and `idx` into bytes 0..2.
    let a = unsafe { slot.reg0() };
    let idx = unsafe { slot.reg1() };
    let off = i64::from(slot.byte3() as i8);
    let imm_lo = u64::from(slot.imm_i32() as u32);
    // SAFETY: `ip.offset(1)` is the intact upper half slot of `LD_IMM64` and `ip.offset(3)` is the intact `st` slot.
    let imm_hi = u64::from(unsafe { ip.offset(1).get() }.imm_i32() as u32);
    let val = i64::from(unsafe { ip.offset(3).get() }.imm_i32()) as u64;
    let ptr = imm_lo | (imm_hi << 32);
    let addr_reg = ptr.wrapping_add(ctx.regs.get(idx));
    ctx.regs.set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(off);
    if interp
        .windows
        .run_data(OpCode(OP), const { windows::kind(OpCode(OP)) }, addr, val)
        .is_none()
    {
        let next = ip.offset(3);
        // SAFETY: `ip.offset(3)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(4), interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn ldxb_jcc_u8<M: Memory, H: Host<M>, F: Fuel, const EQ: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `fold_ldxb_jcc` packed `dst` and `base` into bytes 0..2.
    let dst = unsafe { slot.reg0() };
    let base = unsafe { slot.reg1() };
    let off = i64::from(slot.byte3() as i8);
    let addr = ctx.regs.get(base).wrapping_add_signed(off);
    let Some(loaded) = interp
        .windows
        .run_data(OpCode(LDX_B), const { windows::kind(OpCode(LDX_B)) }, addr, 0)
    else {
        become windows::byte_load_miss::<M, H>(ctx, code, ip, interp, rests, SPARE, slot)
    };
    ctx.regs.set(dst, loaded);
    let imm = u64::from(slot.byte2());
    let payload = slot.imm_i32() as u32;
    let taken = if EQ { loaded == imm } else { loaded != imm };
    if taken {
        let byte_off = payload as i16 as isize;
        let taken_rest = u64::from((payload >> 16) as u8);
        become_enter_rest!(ctx, code, ip.byte_offset(byte_off), interp, rests, taken_rest)
    } else {
        let fall_rest = u64::from((payload >> 24) as u8);
        become_enter_rest!(ctx, code, ip.offset(2), interp, rests, fall_rest)
    }
}
