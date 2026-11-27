//! Promotion of non-escaping `r10` stack slots to virtual registers.
//!
//! Leaf functions that never let `r10` escape into another register or memory and contain no calls or indirect jumps
//! can keep disjoint 4-byte and 8-byte stack spill slots in `Context::regs` virtual registers (`r16..r47`). The
//! threaded compiler rewrites those loads and stores into `mov` instructions, which fold into 3-operand ALU handlers
//! with no extra hot handlers. Entry loads the slots from the validated stack window and exit, short-fuel stepping,
//! or an aliasing data window miss flushes them back to stack memory.

use std::ptr;

use crate::bytes::{INVALID, MISSING};
use crate::context::{FP, VIRT_REGS};
use crate::fuse::Super;
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, CALL, LD_IMM64};
use crate::slot::{Layout, Reg, Slot, LAYOUTS};
use crate::transfer::{FAR, GUARD};
use crate::{args, bytes, windows, Context, Memory};

/// Maximum frame span below `r10` eligible for stack-slot promotion.
pub const PROMOTE_FRAME: u64 = 512;

/// One promoted `r10` stack slot within `[-PROMOTE_FRAME, 0)`.
#[derive(Clone, Copy, Debug)]
pub struct PromotedSlot {
    pub off: i16,
    /// True for an 8-byte slot, false for a 4-byte slot.
    pub wide: bool,
}

/// A closed leaf function `[start..end)` whose disjoint scalar `r10` spill slots map to virtual registers.
#[derive(Debug)]
pub struct PromotedRegion {
    pub start: u32,
    pub end: u32,
    pub slots: Box<[PromotedSlot]>,
}

impl PromotedRegion {
    /// Virtual register assigned to `(off, wide)`, if promoted in this region.
    #[inline]
    pub fn find(&self, off: i16, wide: bool) -> Option<Reg> {
        self.slots
            .iter()
            .position(|s| s.off == off && s.wide == wide)
            .map(|idx| Reg::virt(idx as u8))
    }

    /// Load every promoted slot from the validated stack frame at `fp_host` into `ctx` virtual registers.
    ///
    /// # Safety
    ///
    /// `[fp_host - PROMOTE_FRAME .. fp_host)` must be valid readable host memory with exposed provenance.
    #[inline(always)]
    pub unsafe fn load<M: Memory>(&self, ctx: &mut Context<M>, fp_host: usize) {
        for (i, slot) in self.slots.iter().enumerate() {
            let host = ptr::with_exposed_provenance::<u8>(fp_host.wrapping_add_signed(isize::from(slot.off)));
            let val = unsafe {
                if slot.wide {
                    u64::from_le(host.cast::<u64>().read_unaligned())
                } else {
                    u64::from(u32::from_le(host.cast::<u32>().read_unaligned()))
                }
            };
            ctx.set_virt(i, val);
        }
    }

    /// Flush every promoted slot from `ctx` virtual registers back to the stack frame at `fp_host`.
    ///
    /// # Safety
    ///
    /// `[fp_host - PROMOTE_FRAME .. fp_host)` must be valid writable host memory with exposed provenance, and every
    /// virtual register in `0..self.slots.len()` must have been initialized by [`Self::load`].
    #[inline(always)]
    pub unsafe fn flush<M: Memory>(&self, ctx: &Context<M>, fp_host: usize) {
        for (i, slot) in self.slots.iter().enumerate() {
            let host = ptr::with_exposed_provenance_mut::<u8>(fp_host.wrapping_add_signed(isize::from(slot.off)));
            let val = unsafe { ctx.get_virt(i) };
            unsafe {
                if slot.wide {
                    host.cast::<u64>().write_unaligned(val.to_le());
                } else {
                    host.cast::<u32>().write_unaligned((val as u32).to_le());
                }
            }
        }
    }
}

/// Find closed non-escaping leaf functions in `slots[..len]` and select up to [`VIRT_REGS`] disjoint scalar `r10`
/// spill slots per function.
pub fn analyze(slots: &[Slot], len: usize) -> Box<[PromotedRegion]> {
    if len == 0 {
        return Box::new([]);
    }

    // Partition `0..len` into maximal intervals with no crossing jumps, fallthroughs, or internal local calls.
    let mut reach: Vec<usize> = (0..len).collect();
    let mut bad = vec![false; len];

    let mut i = 0;
    while i < len {
        let slot = slots[i];
        let byte = slot.byte();
        let usual = bytes::usual(byte);
        let opc = OpCode(usual);

        let step = if usual == LD_IMM64 && i + 1 < len { 2 } else { 1 };
        if step == 2 {
            reach[i] = reach[i].max(i + 1);
        }

        if byte == FAR || byte == GUARD {
            bad[i] = true;
            i += step;
            continue;
        }

        if opc.is_jump() {
            match opc.jmp_opc() {
                JmpOpc::Ja if matches!(opc.source(), Source::Reg) => {
                    // Indirect `gotox` can jump to any pc in the program.
                    return Box::new([]);
                }
                JmpOpc::Ja => {
                    let off = match opc.class() {
                        Class::Jmp64 => i64::from(slot.offset_raw()),
                        Class::Jmp32 => i64::from(slot.imm()),
                        _ => 0,
                    };
                    record_edge(i, i as i64 + 1 + off, len, &mut reach, &mut bad);
                }
                JmpOpc::Exit => {}
                JmpOpc::Call => {
                    bad[i] = true;
                    if byte == CALL {
                        let target = i as i64 + 1 + i64::from(slot.instruction().imm());
                        if target >= 0 && (target as usize) < len {
                            bad[target as usize] = true;
                        }
                    }
                    if i + step < len {
                        reach[i] = reach[i].max(i + step);
                    }
                }
                JmpOpc::Jcond | JmpOpc::UndefF => {
                    bad[i] = true;
                    if i + step < len {
                        reach[i] = reach[i].max(i + step);
                    }
                }
                _ => {
                    let target = i as i64 + 1 + i64::from(slot.offset_raw());
                    record_edge(i, target, len, &mut reach, &mut bad);
                    if i + step < len {
                        reach[i] = reach[i].max(i + step);
                    }
                }
            }
        } else {
            let falls_through = !matches!(byte, INVALID | MISSING) && i + step < len;
            if falls_through {
                reach[i] = reach[i].max(i + step);
            }
        }

        i += step;
    }

    let mut regions = Vec::new();
    let mut start = 0;
    while start < len {
        let mut end = reach[start];
        let mut j = start;
        let mut has_bad = false;
        while j <= end {
            end = end.max(reach[j]);
            has_bad |= bad[j];
            j += 1;
        }
        let region_end = end + 1;
        if !has_bad {
            if let Some(region) = analyze_region(slots, start, region_end) {
                regions.push(region);
            }
        }
        start = region_end;
    }

    regions.into_boxed_slice()
}

fn record_edge(from: usize, target: i64, len: usize, reach: &mut [usize], bad: &mut [bool]) {
    if target < 0 || target as usize >= len {
        bad[from] = true;
        return;
    }
    let to = target as usize;
    let lo = from.min(to);
    let hi = from.max(to);
    reach[lo] = reach[lo].max(hi);
}

fn analyze_region(slots: &[Slot], start: usize, end: usize) -> Option<PromotedRegion> {
    // Byte ownership over `[-PROMOTE_FRAME .. 0)`: size 0 is untouched, `u8::MAX` is overlapping, else `(off, size)`.
    let mut owners = [(0i16, 0u8); PROMOTE_FRAME as usize];
    // `(off, size, total_accesses, folded_dispatches)`
    let mut counts: Vec<(i16, u8, u32, u32)> = Vec::new();

    let mut i = start;
    while i < end {
        let slot = slots[i];
        let byte = slot.byte();
        let usual = bytes::usual(byte);
        let opc = OpCode(usual);

        if matches!(
            byte,
            FAR | GUARD | MISSING | INVALID | args::LOAD | args::STORE | args::STORE_IMM | args::CALL | args::CALLX
        ) {
            return None;
        }

        let step = if usual == LD_IMM64 && i + 1 < end { 2 } else { 1 };

        // Keep `0x19` (`ldxdw fp; mul64`), `0x1a` (`ldxw fp; add32`), and `0x1b` (`ldxw mem; stxw fp`) fused by
        // leaving their `r10` slots unpromoted because unfusing them splits 1 dispatch into 2.
        match byte {
            0x19 => mark_fp_conflict(slot.offset_raw(), MemSize::DWord, &mut owners)?,
            0x1a => mark_fp_conflict(slot.offset_raw(), MemSize::Word, &mut owners)?,
            0x1b if i + 1 < end => mark_fp_conflict(slots[i + 1].offset_raw(), MemSize::Word, &mut owners)?,
            _ => {}
        }

        match opc.class() {
            Class::Ld if usual == LD_IMM64 => {
                if usize::from(slot.dst_reg_decoded().get()) == FP {
                    return None;
                }
            }
            Class::Ld => return None,
            Class::Ldx => {
                if !matches!(opc.mem_mode(), MemMode::Mem | MemMode::MemSX) {
                    return None;
                }
                let dst = usize::from(slot.dst_reg_decoded().get());
                let src = usize::from(slot.src_reg_decoded().get());
                if dst == FP {
                    return None;
                }
                if src == FP {
                    if matches!(opc.mem_mode(), MemMode::MemSX) {
                        mark_fp_conflict(slot.offset_raw(), opc.mem_size(), &mut owners)?;
                    } else {
                        let folds = ldx_folds(slots, i, end, opc.mem_size(), slot.dst_reg_decoded());
                        record_fp_access(slot.offset_raw(), opc.mem_size(), folds, &mut owners, &mut counts)?;
                    }
                }
            }
            Class::Stx => {
                if !matches!(opc.mem_mode(), MemMode::Mem) {
                    return None;
                }
                let dst = usize::from(slot.dst_reg_decoded().get());
                let src = usize::from(slot.src_reg_decoded().get());
                if src == FP {
                    return None;
                }
                if dst == FP {
                    let folds = st_folds(slots, i, end, opc.mem_size());
                    record_fp_access(slot.offset_raw(), opc.mem_size(), folds, &mut owners, &mut counts)?;
                }
            }
            Class::St => {
                if !matches!(opc.mem_mode(), MemMode::Mem) {
                    return None;
                }
                let dst = usize::from(slot.dst_reg_decoded().get());
                if dst == FP {
                    let folds = st_folds(slots, i, end, opc.mem_size());
                    record_fp_access(slot.offset_raw(), opc.mem_size(), folds, &mut owners, &mut counts)?;
                }
            }
            Class::Alu32 | Class::Alu64 => match LAYOUTS[usize::from(usual)] {
                Layout::Dst => {
                    if usize::from(slot.dst_reg_decoded().get()) == FP {
                        return None;
                    }
                }
                Layout::DstSrc => {
                    if usize::from(slot.dst_reg_decoded().get()) == FP
                        || usize::from(slot.src_reg_decoded().get()) == FP
                    {
                        return None;
                    }
                }
                Layout::Raw => return None,
            },
            Class::Jmp32 | Class::Jmp64 => match opc.jmp_opc() {
                JmpOpc::Exit => {}
                JmpOpc::Ja if matches!(opc.source(), Source::Imm) => {}
                JmpOpc::Call | JmpOpc::Jcond | JmpOpc::UndefF | JmpOpc::Ja => return None,
                _ => match LAYOUTS[usize::from(usual)] {
                    Layout::Dst => {
                        if usize::from(slot.dst_reg_decoded().get()) == FP {
                            return None;
                        }
                    }
                    Layout::DstSrc => {
                        if usize::from(slot.dst_reg_decoded().get()) == FP
                            || usize::from(slot.src_reg_decoded().get()) == FP
                        {
                            return None;
                        }
                    }
                    Layout::Raw => return None,
                },
            },
        }

        i += step;
    }

    // Keep disjoint 4- and 8-byte slots accessed at least twice.
    let mut candidates: Vec<(i16, bool, u32, u32)> = Vec::new();
    for (off, size, count, folds) in counts {
        if count < 2 || !matches!(size, 4 | 8) {
            continue;
        }
        let base = (i32::from(off) + PROMOTE_FRAME as i32) as usize;
        let disjoint = (0..usize::from(size)).all(|k| owners[base + k] == (off, size));
        if disjoint {
            candidates.push((off, size == 8, folds, count));
        }
    }

    if candidates.is_empty() {
        return None;
    }

    // Rank by folded dispatches descending, then total accesses descending, then closer to `r10`.
    candidates.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.3.cmp(&a.3)).then_with(|| b.0.cmp(&a.0)));
    candidates.truncate(VIRT_REGS);

    let promoted_slots: Box<[PromotedSlot]> = candidates
        .into_iter()
        .map(|(off, wide, _, _)| PromotedSlot { off, wide })
        .collect();

    Some(PromotedRegion {
        start: start as u32,
        end: end as u32,
        slots: promoted_slots,
    })
}

fn ldx_folds(slots: &[Slot], i: usize, end: usize, size: MemSize, dst: Reg) -> bool {
    let mov64 = match size {
        MemSize::DWord => true,
        MemSize::Word => false,
        _ => return false,
    };
    if i + 1 >= end {
        return false;
    }
    let next = slots[i + 1];
    let opc = OpCode(next.byte());
    match opc.class() {
        Class::Alu32 => is_foldable_alu(opc.alu_opc()) && next.dst_reg_decoded() == dst,
        Class::Alu64 if mov64 => is_foldable_alu(opc.alu_opc()) && next.dst_reg_decoded() == dst,
        Class::Jmp32 | Class::Jmp64 => matches!(opc.jmp_opc(), JmpOpc::Ja) && matches!(opc.source(), Source::Imm),
        _ => false,
    }
}

fn is_foldable_alu(op: AluOpc) -> bool {
    matches!(
        op,
        AluOpc::Add
            | AluOpc::Sub
            | AluOpc::Mul
            | AluOpc::Or
            | AluOpc::And
            | AluOpc::Xor
            | AluOpc::Lsh
            | AluOpc::Rsh
            | AluOpc::Arsh
    )
}

fn st_folds(slots: &[Slot], i: usize, end: usize, size: MemSize) -> bool {
    if !matches!(size, MemSize::Word | MemSize::DWord) || i + 1 >= end {
        return false;
    }
    let opc = OpCode(slots[i + 1].byte());
    matches!(opc.jmp_opc(), JmpOpc::Ja) && matches!(opc.source(), Source::Imm)
}

fn mark_fp_conflict(off: i16, mem_size: MemSize, owners: &mut [(i16, u8); PROMOTE_FRAME as usize]) -> Option<()> {
    let size = mem_size.bytes() as u8;
    if off < -(PROMOTE_FRAME as i16) || i32::from(off) + i32::from(size) > 0 {
        return None;
    }
    let base = (i32::from(off) + PROMOTE_FRAME as i32) as usize;
    for k in 0..usize::from(size) {
        owners[base + k] = (0, u8::MAX);
    }
    Some(())
}

fn record_fp_access(
    off: i16,
    mem_size: MemSize,
    folds: bool,
    owners: &mut [(i16, u8); PROMOTE_FRAME as usize],
    counts: &mut Vec<(i16, u8, u32, u32)>,
) -> Option<()> {
    let size = mem_size.bytes() as u8;
    if off < -(PROMOTE_FRAME as i16) || i32::from(off) + i32::from(size) > 0 {
        return None;
    }
    let base = (i32::from(off) + PROMOTE_FRAME as i32) as usize;
    for k in 0..usize::from(size) {
        let entry = &mut owners[base + k];
        if entry.1 == 0 {
            *entry = (off, size);
        } else if *entry != (off, size) {
            *entry = (0, u8::MAX);
        }
    }
    let add_fold = u32::from(folds);
    if let Some(existing) = counts.iter_mut().find(|(o, s, _, _)| *o == off && *s == size) {
        existing.2 += 1;
        existing.3 += add_fold;
    } else {
        counts.push((off, size, 1, add_fold));
    }
    Some(())
}

/// Produce a rewritten portable slot copy of `region` with `fp` superinstructions unfused and promoted `r10`
/// loads/stores replaced by `mov` instructions referencing virtual registers `r16..r47`.
pub fn rewrite_region(slots: &[Slot], region: &PromotedRegion) -> Vec<Slot> {
    let start = region.start as usize;
    let end = region.end as usize;
    let mut out = slots[start..end].to_vec();

    // Unfuse `0x41` (`ldxw a, [fp + off]; add32 a, imm`) only when its `r10` slot is promoted so `fold_alu3` folds it
    // into `alu3_imm`. Slots of `0x19`, `0x1a`, and `0x1b` are excluded from promotion and stay fused.
    for slot in &mut out {
        let byte = slot.byte();
        if let Some(sup) = Super::with_byte(byte) {
            if sup.has_fp() && byte == 0x41 && region.find(slot.offset_raw(), false).is_some() {
                *slot = slot.with_byte(sup.opcode(0));
            }
        }
    }

    let mut i = 0;
    while i < out.len() {
        let slot = out[i];
        let byte = slot.byte();
        let usual = bytes::usual(byte);
        if usual == LD_IMM64 && i + 1 < out.len() {
            i += 2;
            continue;
        }
        if let Some(sup) = Super::with_byte(byte) {
            i += sup.len();
            continue;
        }
        if windows::windowed(usual) && matches!(OpCode(usual).mem_mode(), MemMode::Mem) {
            let opc = OpCode(usual);
            let wide = match opc.mem_size() {
                MemSize::DWord => Some(true),
                MemSize::Word => Some(false),
                _ => None,
            };
            if let Some(wide) = wide {
                let off = slot.offset_raw();
                match opc.class() {
                    Class::Ldx if usize::from(slot.src_reg_decoded().get()) == FP => {
                        if let Some(vreg) = region.find(off, wide) {
                            out[i] = Slot::mov_reg(wide, slot.dst_reg_decoded(), vreg);
                        }
                    }
                    Class::Stx if usize::from(slot.dst_reg_decoded().get()) == FP => {
                        if let Some(vreg) = region.find(off, wide) {
                            out[i] = Slot::mov_reg(wide, vreg, slot.src_reg_decoded());
                        }
                    }
                    Class::St if usize::from(slot.dst_reg_decoded().get()) == FP => {
                        if let Some(vreg) = region.find(off, wide) {
                            out[i] = Slot::mov_imm(wide, vreg, slot.imm());
                        }
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }

    out
}
