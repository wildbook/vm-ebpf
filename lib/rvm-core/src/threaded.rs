//! Threaded-only folded handlers: multi-instruction sequences and virtual-register helpers packed into 8-byte
//! [`Slot`]s by [`compile`](crate::compile) without consuming portable opcode bytes.

use crate::code::Slots;
use crate::dispatch::{Handler, Spare, SPARE};
use crate::fuel::{Fuel, RestsPtr};
use crate::opcode::{JmpOpc, MemMode, MemSize, OpCode};
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{windows, Context, Host, Interpreter, Memory};

pub const LDX_B: u8 = OpCode::ldx(MemSize::Byte, MemMode::Mem).0;
pub const LDX_W: u8 = OpCode::ldx(MemSize::Word, MemMode::Mem).0;
pub const LDX_DW: u8 = OpCode::ldx(MemSize::DWord, MemMode::Mem).0;
pub const STX_B: u8 = OpCode::stx(MemSize::Byte, MemMode::Mem).0;
pub const STX_W: u8 = OpCode::stx(MemSize::Word, MemMode::Mem).0;
pub const STX_DW: u8 = OpCode::stx(MemSize::DWord, MemMode::Mem).0;
pub const ST_B: u8 = OpCode::st(MemSize::Byte, MemMode::Mem).0;
pub const ST_W: u8 = OpCode::st(MemSize::Word, MemMode::Mem).0;
pub const ST_DW: u8 = OpCode::st(MemSize::DWord, MemMode::Mem).0;

pub const SHIFT_OP_XOR: u8 = 0;
pub const SHIFT_OP_OR: u8 = 1;
pub const SHIFT_OP_ADD: u8 = 2;

pub const SRC_OP_ADD: u8 = 0;
pub const SRC_OP_MUL: u8 = 1;
pub const SRC_OP_XOR: u8 = 2;

pub const CMP_EQ: u8 = 0;
pub const CMP_LT: u8 = 1;
pub const CMP_SLT: u8 = 2;

/// Handler table for threaded folded sequences and virtual-register helpers.
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
    /// Low-32-bit partial writes preserving the high 32 bits of a mixed-width promoted stack slot.
    pub store_lo32_reg: Handler<M, H>,
    pub store_lo32_imm: Handler<M, H>,
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
        store_lo32_reg: store_lo32_reg::<M, H>,
        store_lo32_imm: store_lo32_imm::<M, H>,
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

/// Normalize any of the 10 register comparisons to `(kind, invert, swap_operands)` over `EQ`, `LT`, or `SLT`.
pub fn normalize_reg_cmp(op: JmpOpc) -> Option<(u8, bool, bool)> {
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

#[inline(always)]
pub fn size_idx(op: u8) -> usize {
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
extern "rust-preserve-none" fn store_lo32_reg<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile` packed `dst` and `src` into bytes 0..2.
    let dst = unsafe { slot.reg0() };
    let src = unsafe { slot.reg1() };
    let hi = ctx.reg_get(dst) & !0xffff_ffffu64;
    let lo = u64::from(ctx.reg_get(src) as u32);
    ctx.reg_set(dst, hi | lo);
    become_next!(ctx, code, ip, interp, rests)
}

#[rustc_align(64)]
#[inline(never)]
extern "rust-preserve-none" fn store_lo32_imm<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile` packed `dst` into byte 0.
    let dst = unsafe { slot.reg0() };
    let hi = ctx.reg_get(dst) & !0xffff_ffffu64;
    let lo = u64::from(slot.imm_i32() as u32);
    ctx.reg_set(dst, hi | lo);
    become_next!(ctx, code, ip, interp, rests)
}

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
    // SAFETY: `compile` packed `dst` into byte 0.
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
    // SAFETY: `compile` packed `dst` into byte 0 and `src` into byte 1.
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
    ($ctx:expr, $code:expr, $ip:expr, $interp:expr, $rests:expr, $dst:expr, $rhs:expr, $skip:expr, $fall_rest:expr, $next_slots:expr) => {{
        let skip = $skip;
        let cur = $ctx.reg_get($dst);
        let new_val = core::hint::select_unpredictable(skip, cur, $rhs);
        let rest = $fall_rest + u64::from(!skip);
        if !F::enter_rest($interp, rest) {
            core::hint::cold_path();
            let delta = Slot::pack_bytes(u8::from(skip), 0, 0, 0, 0);
            become F::step_delta::<M, H>($ctx, $code, $ip, $interp, $rests, SPARE, delta)
        }
        $ctx.reg_set($dst, new_val);
        become_at!($ctx, $code, $ip.offset($next_slots), $interp, $rests)
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
    // SAFETY: `compile` packed `a`, `b`, `dst` into bytes 0..3 and stored the `mov_imm` immediate at `ip.offset(1)`.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let meta = slot.byte3();
    let fall_rest = u64::from(slot.imm_i32() as u32);
    let skip = eval_select_cmp::<BITS64>(ctx.reg_get(a), ctx.reg_get(b), meta);
    // SAFETY: `ip.offset(1)` holds the trailing immediate slot for `select_reg_imm`.
    let raw_imm = unsafe { ip.offset(1).get() }.imm_i32();
    let mov_rhs =
        core::hint::select_unpredictable((meta & 8) != 0, i64::from(raw_imm) as u64, u64::from(raw_imm as u32));
    finish_select!(ctx, code, ip, interp, rests, dst, mov_rhs, skip, fall_rest, 2)
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
    // SAFETY: `compile` packed `a`, `b`, `dst`, `src` into bytes 0..4.
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
    finish_select!(ctx, code, ip, interp, rests, dst, mov_rhs, skip, fall_rest, 1)
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
    // SAFETY: `compile` packed `x` into byte 0 and `t` into byte 1.
    let x_reg = unsafe { slot.reg0() };
    let t_reg = unsafe { slot.reg1() };
    let k1 = u32::from(slot.byte2());
    let k2 = u32::from(slot.byte3());
    if BITS64 {
        let x = ctx.reg_get(x_reg);
        let (t, out) = if LSH_FIRST {
            let t = x << k1;
            (t, (x >> k2) | t)
        } else {
            let t = x >> k1;
            (t, (x << k2) | t)
        };
        ctx.reg_set(t_reg, t);
        ctx.reg_set(x_reg, out);
    } else {
        let x = ctx.reg_get(x_reg) as u32;
        let (t, out) = if LSH_FIRST {
            let t = x << k1;
            (t, (x >> k2) | t)
        } else {
            let t = x >> k1;
            (t, (x << k2) | t)
        };
        ctx.reg_set(t_reg, u64::from(t));
        ctx.reg_set(x_reg, u64::from(out));
    }
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `dst`, `s1`, `s2` into bytes 0..3.
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
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `dst` and `s1` into bytes 0..2.
    let dst = unsafe { slot.reg0() };
    let s1 = unsafe { slot.reg1() };
    let k = u32::from(slot.byte2());
    let out = if BITS64 {
        (ctx.reg_get(s1) >> k) & (i64::from(slot.imm_i32()) as u64)
    } else {
        u64::from(((ctx.reg_get(s1) as u32) >> k) & (slot.imm_i32() as u32))
    };
    ctx.reg_set(dst, out);
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `dst`, `s1`, `s2` into bytes 0..3.
    let dst = unsafe { slot.reg0() };
    let s1 = unsafe { slot.reg1() };
    let s2 = unsafe { slot.reg2() };
    let imm = i64::from(slot.imm_i32()) as u64;
    let lhs = if IS_MUL {
        ctx.reg_get(s1).wrapping_mul(imm)
    } else {
        ctx.reg_get(s1).wrapping_add(imm)
    };
    ctx.reg_set(dst, lhs.wrapping_add(ctx.reg_get(s2)));
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `d0`, `src0`, `d1`, `src1` into bytes 0..4 with `src1 != d0`.
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
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `d0`, `d1`, `src1` into bytes 0..3 with `src1 != d0`.
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
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `t`, `src1`, `dst` into bytes 0..3 with `dst != t`.
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
    become_next!(ctx, code, ip, interp, rests)
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
    // SAFETY: `compile` packed `a`, `b`, `dst` into bytes 0..3 and placed the intact `data_access` slot at `ip + 1`.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let addr_reg = ctx.reg_get(a).wrapping_add(ctx.reg_get(b));
    ctx.reg_set(a, addr_reg);
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
    ctx.reg_set(dst, loaded);
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
    // SAFETY: `compile` packed `a`, `b`, `val` into bytes 0..3 and placed the intact `data_access` slot at `ip + 1`.
    let a = unsafe { slot.reg0() };
    let b = unsafe { slot.reg1() };
    let val_reg = unsafe { slot.reg2() };
    let addr_reg = ctx.reg_get(a).wrapping_add(ctx.reg_get(b));
    ctx.reg_set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(i64::from(slot.imm_i32()));
    let val = ctx.reg_get(val_reg);
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
    // SAFETY: `compile` packed `a`, `base`, `idx`, `dst` into bytes 0..4 and placed `data_access` at `ip + 1`.
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
        let next = ip.offset(1);
        // SAFETY: `ip.offset(1)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    };
    ctx.reg_set(dst, loaded);
    become_at!(ctx, code, ip.offset(2), interp, rests)
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
    // SAFETY: `compile` packed `a`, `base`, `idx`, `val` into bytes 0..4 and placed `data_access` at `ip + 1`.
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
        let next = ip.offset(1);
        // SAFETY: `ip.offset(1)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(2), interp, rests)
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
    // SAFETY: `compile` packed `a`, `base`, `idx` into bytes 0..3 and placed `data_access` at `ip + 1`.
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
        let next = ip.offset(1);
        // SAFETY: `ip.offset(1)` holds the intact `data_access` slot for `OP`.
        let next_slot = unsafe { next.get() };
        become windows::data_access::<M, H, OP>(ctx, code, next, interp, rests, SPARE, next_slot)
    }
    become_at!(ctx, code, ip.offset(2), interp, rests)
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
    // SAFETY: `compile` packed `a`, `idx`, `dst` into bytes 0..3, `imm_hi` at `ip + 1`, and `data_access` at `ip + 2`.
    let a = unsafe { slot.reg0() };
    let idx = unsafe { slot.reg1() };
    let dst = unsafe { slot.reg2() };
    let off = i64::from(slot.byte3() as i8);
    let imm_lo = u64::from(slot.imm_i32() as u32);
    // SAFETY: `ip.offset(1)` is the upper half slot of `LD_IMM64`.
    let imm_hi = u64::from(unsafe { ip.offset(1).get() }.imm_i32() as u32);
    let ptr = imm_lo | (imm_hi << 32);
    let addr_reg = ptr.wrapping_add(ctx.reg_get(idx));
    ctx.reg_set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(off);
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
extern "rust-preserve-none" fn lddw_add_stx<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile` packed `a`, `idx`, `val` into bytes 0..3, `imm_hi` at `ip + 1`, and `data_access` at `ip + 2`.
    let a = unsafe { slot.reg0() };
    let idx = unsafe { slot.reg1() };
    let val_reg = unsafe { slot.reg2() };
    let off = i64::from(slot.byte3() as i8);
    let imm_lo = u64::from(slot.imm_i32() as u32);
    // SAFETY: `ip.offset(1)` is the upper half slot of `LD_IMM64`.
    let imm_hi = u64::from(unsafe { ip.offset(1).get() }.imm_i32() as u32);
    let ptr = imm_lo | (imm_hi << 32);
    let addr_reg = ptr.wrapping_add(ctx.reg_get(idx));
    ctx.reg_set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(off);
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
extern "rust-preserve-none" fn lddw_add_st<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile` packed `a`, `idx` into bytes 0..2, `imm_hi` at `ip + 1`, and `data_access` at `ip + 2`.
    let a = unsafe { slot.reg0() };
    let idx = unsafe { slot.reg1() };
    let off = i64::from(slot.byte3() as i8);
    let imm_lo = u64::from(slot.imm_i32() as u32);
    // SAFETY: `ip.offset(1)` is the upper half slot of `LD_IMM64` and `ip.offset(2)` is the intact `st` slot.
    let imm_hi = u64::from(unsafe { ip.offset(1).get() }.imm_i32() as u32);
    let val = i64::from(unsafe { ip.offset(2).get() }.imm_i32()) as u64;
    let ptr = imm_lo | (imm_hi << 32);
    let addr_reg = ptr.wrapping_add(ctx.reg_get(idx));
    ctx.reg_set(a, addr_reg);
    let addr = addr_reg.wrapping_add_signed(off);
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
extern "rust-preserve-none" fn ldxb_jcc_u8<M: Memory, H: Host<M>, F: Fuel, const EQ: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile` packed `dst` and `base` into bytes 0..2 and placed the intact `jcc` slot at `ip + 1`.
    let dst = unsafe { slot.reg0() };
    let base = unsafe { slot.reg1() };
    let off = i64::from(slot.byte3() as i8);
    let addr = ctx.reg_get(base).wrapping_add_signed(off);
    let Some(loaded) = interp
        .windows
        .run_data(OpCode(LDX_B), const { windows::kind(OpCode(LDX_B)) }, addr, 0)
    else {
        become windows::byte_load_miss::<M, H>(ctx, code, ip, interp, rests, SPARE, slot)
    };
    ctx.reg_set(dst, loaded);
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
