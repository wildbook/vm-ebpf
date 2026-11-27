//! Threaded-only folded handlers: multi-instruction sequences packed into a single 8-byte [`Slot`] in
//! [`compile_threaded`](crate::code) without consuming portable opcode bytes.

use crate::bytes::{MOV32_REG, MOV64_REG};
use crate::code::{Slots, ThreadedSlot};
use crate::dispatch::{DispatchTable, Handler, Spare, SPARE};
use crate::fuel::{Fuel, RestsPtr};
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source};
use crate::slot::Slot;
use crate::step::Regs;
use crate::transfer::Ip;
use crate::{windows, Context, Host, Interpreter, Memory};

const LDX_B: u8 = OpCode::ldx(MemSize::Byte, MemMode::Mem).0;
const LDX_W: u8 = OpCode::ldx(MemSize::Word, MemMode::Mem).0;
const LDX_DW: u8 = OpCode::ldx(MemSize::DWord, MemMode::Mem).0;
const STX_B: u8 = OpCode::stx(MemSize::Byte, MemMode::Mem).0;
const STX_W: u8 = OpCode::stx(MemSize::Word, MemMode::Mem).0;
const STX_DW: u8 = OpCode::stx(MemSize::DWord, MemMode::Mem).0;
const ST_B: u8 = OpCode::st(MemSize::Byte, MemMode::Mem).0;
const ST_W: u8 = OpCode::st(MemSize::Word, MemMode::Mem).0;
const ST_DW: u8 = OpCode::st(MemSize::DWord, MemMode::Mem).0;

const ADD64_REG: u8 = OpCode::alu64(AluOpc::Add, Source::Reg).0;
const MOV32_IMM: u8 = OpCode::alu32(AluOpc::Mov, Source::Imm).0;
const MOV64_IMM: u8 = OpCode::alu64(AluOpc::Mov, Source::Imm).0;
const LSH32_IMM: u8 = OpCode::alu32(AluOpc::Lsh, Source::Imm).0;
const RSH32_IMM: u8 = OpCode::alu32(AluOpc::Rsh, Source::Imm).0;
const OR32_REG: u8 = OpCode::alu32(AluOpc::Or, Source::Reg).0;
const LSH64_IMM: u8 = OpCode::alu64(AluOpc::Lsh, Source::Imm).0;
const RSH64_IMM: u8 = OpCode::alu64(AluOpc::Rsh, Source::Imm).0;
const OR64_REG: u8 = OpCode::alu64(AluOpc::Or, Source::Reg).0;

/// Handler table for threaded-only folded sequences.
pub struct FoldTable<M: Memory, H> {
    pub mov_ja_imm: [Handler<M, H>; 2],
    pub mov_ja_reg: [Handler<M, H>; 2],
    pub rot: [[Handler<M, H>; 2]; 2],
    pub add_ldx: [Handler<M, H>; 3],
    pub add_stx: [Handler<M, H>; 3],
    pub mov_add_ldx: [Handler<M, H>; 3],
    pub mov_add_stx: [Handler<M, H>; 3],
    pub mov_add_st: [Handler<M, H>; 3],
}

pub const fn table<M: Memory, H: Host<M>, F: Fuel>() -> FoldTable<M, H> {
    FoldTable {
        mov_ja_imm: [mov_ja_imm::<M, H, F, false>, mov_ja_imm::<M, H, F, true>],
        mov_ja_reg: [mov_ja_reg::<M, H, F, false>, mov_ja_reg::<M, H, F, true>],
        rot: [
            [rot::<M, H, false, false>, rot::<M, H, false, true>],
            [rot::<M, H, true, false>, rot::<M, H, true, true>],
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
    }
}

/// Try to fold a multi-instruction sequence starting at `i` in `slots[..len]` into one [`ThreadedSlot`].
///
/// Leaves subsequent slots intact for mid-sequence jump targets and window-miss fallbacks.
pub fn try_fold<M: Memory, H: Host<M>>(
    slots: &[Slot],
    i: usize,
    len: usize,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    if i + 3 < len {
        if let Some(folded) = fold_rot(slots[i], slots[i + 1], slots[i + 2], slots[i + 3], table) {
            return Some(folded);
        }
    }
    if i + 2 < len {
        if let Some(folded) = fold_mov_add_mem(slots[i], slots[i + 1], slots[i + 2], table) {
            return Some(folded);
        }
    }
    if i + 1 < len {
        let a = slots[i];
        let b = slots[i + 1];
        if let Some(folded) = fold_mov_ja(a, b, table) {
            return Some(folded);
        }
        if let Some(folded) = fold_add_mem(a, b, table) {
            return Some(folded);
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

fn fold_mov_ja<M: Memory, H: Host<M>>(s0: Slot, s1: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
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
    match s0.byte() {
        MOV32_IMM | MOV64_IMM => {
            let bits64 = s0.byte() == MOV64_IMM;
            let off16 = i16::try_from(byte_off).ok()?;
            let dst = s0.dst_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.mov_ja_imm[usize::from(bits64)] as *const (),
                slot: Slot::pack(dst.get(), 0, off16, s0.imm()),
            })
        }
        MOV32_REG | MOV64_REG => {
            let bits64 = s0.byte() == MOV64_REG;
            let off32 = i32::try_from(byte_off).ok()?;
            let dst = s0.dst_reg_decoded();
            let src = s0.src_reg_decoded();
            Some(ThreadedSlot {
                handler: table.folds.mov_ja_reg[usize::from(bits64)] as *const (),
                slot: Slot::pack(dst.get(), src.get(), 0, off32),
            })
        }
        _ => None,
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
    become_enter!(ctx, code, ip.byte_offset(byte_off), interp, rests)
}

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
    become_enter!(ctx, code, ip.byte_offset(byte_off), interp, rests)
}

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
