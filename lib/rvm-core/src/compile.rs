//! Basic-block 3-address IR optimizer and compacting direct-threaded compiler.
//!
//! [`compile_compacted`] splits each basic block into fault-free pure ALU/move segments, performs forward copy
//! propagation, spill/copy destination retargeting, and backward dead-write elimination over `r0..r47`, folds
//! multi-instruction idioms into single compacted [`ThreadedSlot`] entries, and resolves branch byte offsets in a
//! second pass. [`compile_uncompacted`] builds a 1:1 unfused fallback stream for promoted bailouts and arbitrary
//! mid-block entry points.

use crate::bytes::{MOV32_REG, MOV64_REG, MOVSX32, MOVSX64};
use crate::code::{CompiledStream, StreamMaps, ThreadedSlot, NO_SLOT};
use crate::context::{FP, TOTAL_REGS};
use crate::dispatch::DispatchTable;
use crate::fuse::Super;
use crate::handler::{is_cond_dst_jump, TO_GUEST, TO_HOST};
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, CALL, LD_IMM64};
use crate::promote::{PromotedRegion, SlotWidth};
use crate::slot::{Layout, Reg, Slot, LAYOUTS};
use crate::threaded::{
    normalize_reg_cmp, size_idx, LDX_B, LDX_DW, LDX_W, SHIFT_OP_ADD, SHIFT_OP_OR, SHIFT_OP_XOR, SRC_OP_ADD, SRC_OP_MUL,
    SRC_OP_XOR, STX_B, STX_DW, STX_W, ST_B, ST_DW, ST_W,
};
use crate::transfer::{FAR, GUARD};
use crate::{bytes, windows, Host, Memory};

const STRIDE: i64 = size_of::<ThreadedSlot>() as i64;

const JEQ32_IMM: u8 = OpCode::jmp32(JmpOpc::Jeq, Source::Imm).0;
const JEQ64_IMM: u8 = OpCode::jmp64(JmpOpc::Jeq, Source::Imm).0;
const JNE32_IMM: u8 = OpCode::jmp32(JmpOpc::Jne, Source::Imm).0;
const JNE64_IMM: u8 = OpCode::jmp64(JmpOpc::Jne, Source::Imm).0;

const MOV32_IMM: u8 = OpCode::alu32(AluOpc::Mov, Source::Imm).0;
const MOV64_IMM: u8 = OpCode::alu64(AluOpc::Mov, Source::Imm).0;

const OP_ADD: u8 = 0;
const OP_SUB: u8 = 1;
const OP_MUL: u8 = 2;
const OP_OR: u8 = 3;
const OP_AND: u8 = 4;
const OP_XOR: u8 = 5;
const OP_LSH: u8 = 6;
const OP_RSH: u8 = 7;
const OP_ARSH: u8 = 8;

/// Build a 1:1 unfused fallback stream with every original BPF pc present at the same slot index.
pub fn compile_uncompacted<M: Memory, H: Host<M>>(
    raw_slots: &[Slot],
    len: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> CompiledStream {
    let total = raw_slots.len();
    let mut out = Vec::with_capacity(total);
    let mut pc_to_idx = Vec::with_capacity(total);
    let mut idx_to_pc = Vec::with_capacity(total);

    for i in 0..total {
        pc_to_idx.push(i as u32);
        idx_to_pc.push(i as u32);
        let mut slot = raw_slots[i];
        let mut byte = slot.byte();
        if let Some(sup) = Super::with_byte(byte) {
            byte = sup.opcode(0);
            slot = slot.with_byte(byte);
        }
        if i < len {
            if let Some(scaled) = scale_branch_or_call_1to1(slot, byte, i, table, rests) {
                out.push(scaled);
                continue;
            }
            if is_cond_dst_jump(byte) {
                let target_pc = (i as i64 + 1 + i64::from(slot.offset_raw())) as usize;
                let taken_rest = rests.map_or(0, |r| r[target_pc]);
                if let (Ok(byte_off), Ok(taken_rest8)) =
                    (i16::try_from((i32::from(slot.offset_raw()) + 1) * (STRIDE as i32)), u8::try_from(taken_rest))
                {
                    out.push(ThreadedSlot {
                        handler: table.handlers[usize::from(byte)] as *const (),
                        slot: slot.with_offset(byte_off).with_byte(taken_rest8),
                    });
                } else {
                    out.push(ThreadedSlot {
                        handler: table.jump_unscaled as *const (),
                        slot,
                    });
                }
                continue;
            }
            if LAYOUTS[usize::from(byte)] == Layout::DstSrc && OpCode(bytes::usual(byte)).is_jump() {
                let target_pc = (i as i64 + 1 + i64::from(slot.offset_raw())) as usize;
                let taken_rest = rests.map_or(0, |r| r[target_pc]);
                let fall_rest = rests.map_or(0, |r| r[i + 1]);
                if let (Ok(taken_rest8), Ok(fall_rest8)) = (u8::try_from(taken_rest), u8::try_from(fall_rest)) {
                    let byte_off = (i32::from(slot.offset_raw()) + 1) * (STRIDE as i32);
                    out.push(ThreadedSlot {
                        handler: table.handlers[usize::from(byte)] as *const (),
                        slot: slot.to_threaded_dst_src_with_rests(byte_off, taken_rest8, fall_rest8),
                    });
                } else {
                    out.push(ThreadedSlot {
                        handler: table.jump_unscaled as *const (),
                        slot,
                    });
                }
                continue;
            }
        }
        out.push(emit_plain(slot, byte, table));
    }

    #[cfg(feature = "fuel")]
    let idx_rests = rests.map_or_else(Box::default, |r| r.to_vec().into_boxed_slice());

    CompiledStream::new(
        out,
        StreamMaps {
            pc_to_idx: pc_to_idx.into_boxed_slice(),
            idx_to_pc: idx_to_pc.into_boxed_slice(),
            #[cfg(feature = "fuel")]
            idx_rests,
        },
    )
}

/// Compile portable slots into a compacted direct-threaded stream with basic-block 3-address optimization.
pub fn compile_compacted<M: Memory, H: Host<M>>(
    raw_slots: &[Slot],
    len: usize,
    table: &DispatchTable<M, H>,
    promote: Option<&[PromotedRegion]>,
    rests: Option<&[u32]>,
) -> CompiledStream {
    let total = raw_slots.len();
    let leaders = compute_leaders(raw_slots, len);

    let mut out = Vec::with_capacity(total);
    let mut pc_to_idx = vec![NO_SLOT; total];
    let mut idx_to_pc = Vec::with_capacity(total);
    let mut patches: Vec<BranchPatch> = Vec::new();
    let mut pure: Vec<PureInst> = Vec::new();
    let mut pure_leader: Option<usize> = None;

    let mut i = 0usize;
    while i < len {
        if leaders[i] {
            if !pure.is_empty() {
                flush_pure(&mut pure, pure_leader.take(), &mut out, &mut pc_to_idx, &mut idx_to_pc, table);
            }
            pure_leader = Some(i);
        }

        let region = promote.and_then(|regions| find_region(regions, i));
        let mut slot = raw_slots[i];
        let mut byte = slot.byte();

        // Decide whether an existing superinstruction stays fused or unfuses for promotion/BB optimization.
        if let Some(sup) = Super::with_byte(byte) {
            let interior_leader = (1..sup.len()).any(|k| i + k < len && leaders[i + k]);
            let unfuse_for_promo = region.is_some_and(|reg| sup_fp_promoted(byte, raw_slots, i, reg));
            let unfuse = interior_leader || byte == 0xf5 || unfuse_for_promo;
            if !unfuse {
                if !pure.is_empty() {
                    flush_pure(&mut pure, pure_leader.take(), &mut out, &mut pc_to_idx, &mut idx_to_pc, table);
                }
                let start_leader = pure_leader.take();

                // Try extending `0xf7` (`lddw; add64`) with a following `ldx`/`stx`/`st`.
                if byte == 0xf7 && i + 3 < len && !leaders[i + 1] && !leaders[i + 2] && !leaders[i + 3] {
                    if let Some((head, mem_slot, mem_byte)) = try_fold_0xf7(raw_slots, i, table) {
                        let base_idx = out.len();
                        if let Some(lpc) = start_leader {
                            pc_to_idx[lpc] = base_idx as u32;
                        }
                        pc_to_idx[i] = base_idx as u32;
                        out.push(head);
                        idx_to_pc.push(i as u32);
                        out.push(emit_plain(raw_slots[i + 1], raw_slots[i + 1].byte(), table));
                        idx_to_pc.push((i + 1) as u32);
                        out.push(emit_plain(mem_slot, mem_byte, table));
                        idx_to_pc.push((i + 3) as u32);
                        i += 4;
                        continue;
                    }
                }

                if super_branch_fits(sup, raw_slots, i, rests) {
                    let base_idx = out.len();
                    if let Some(lpc) = start_leader {
                        pc_to_idx[lpc] = base_idx as u32;
                    }
                    let encoded0 = if sup.branches() {
                        let fall_rest = rests.map_or(0, |r| r[i + sup.len()]) as u8;
                        match LAYOUTS[usize::from(sup.opcode(0))] {
                            Layout::Dst => slot.with_byte(fall_rest),
                            Layout::DstSrc => {
                                slot.to_threaded_dst_src_with_rests(i32::from(slot.offset_raw()), fall_rest, 0)
                            }
                            Layout::Raw => encode_threaded_slot(slot, byte),
                        }
                    } else {
                        encode_threaded_slot(slot, byte)
                    };
                    pc_to_idx[i] = base_idx as u32;
                    out.push(ThreadedSlot {
                        handler: table.handlers[usize::from(byte)] as *const (),
                        slot: encoded0,
                    });
                    idx_to_pc.push(i as u32);

                    for k in 1..sup.len() {
                        let pc = i + k;
                        let s = raw_slots[pc];
                        let b = s.byte();
                        let emit_idx = out.len();
                        pc_to_idx[pc] = emit_idx as u32;
                        if k == sup.len() - 1 && sup.branches() {
                            emit_branch_in_super(s, b, pc, &mut out, &mut patches, table, rests);
                        } else {
                            out.push(emit_plain(s, b, table));
                        }
                        idx_to_pc.push(pc as u32);
                    }
                    i += sup.len();
                    continue;
                }

                // Branch doesn't fit inline fields: unfuse slot 0 and continue normally.
                byte = sup.opcode(0);
                slot = slot.with_byte(byte);
                pure_leader = start_leader;
            } else {
                byte = sup.opcode(0);
                slot = slot.with_byte(byte);
            }
        }

        // Try classifying `slot` as a pure ALU/mov/promoted-r10 instruction.
        if let Some((op, step)) = classify_pure(raw_slots, i, len, &leaders, slot, byte, region) {
            pure.push(PureInst { op, pc: i as u32 });
            i += step;
            continue;
        }

        // Non-pure instruction: optimize the pending pure segment and check cross-boundary folds.
        if !pure.is_empty() {
            let saved_first = pure[0];
            optimize_pure_segment(&mut pure);
            if pure_leader.is_some() && pure.is_empty() {
                pure.push(saved_first);
            }

            // Cross-boundary fold 1: trailing `mov` + unconditional `ja`.
            let opc = OpCode(byte);
            if matches!(opc.jmp_opc(), JmpOpc::Ja) && matches!(opc.source(), Source::Imm) {
                if let Some(last) = pure.last().copied() {
                    if let Some((folded, patch_kind, target_pc)) = try_fold_mov_ja(last, slot, i, table, rests) {
                        pure.pop();
                        let is_first = pure.is_empty();
                        let seg_leader = if is_first { pure_leader.take() } else { None };
                        if !pure.is_empty() {
                            emit_pure_slice(&pure, pure_leader.take(), &mut out, &mut pc_to_idx, &mut idx_to_pc, table);
                            pure.clear();
                        }
                        let emit_idx = out.len();
                        let record_pc = seg_leader.unwrap_or(last.pc as usize);
                        if let Some(lpc) = seg_leader {
                            pc_to_idx[lpc] = emit_idx as u32;
                        }
                        out.push(folded);
                        idx_to_pc.push(record_pc as u32);
                        patches.push(BranchPatch {
                            emit_idx,
                            base_idx: emit_idx,
                            target_pc,
                            kind: patch_kind,
                        });
                        i += 1;
                        continue;
                    }
                }
            }

            // Cross-boundary fold 2: trailing 64-bit `add` (`Alu3Reg`) + `ldx`/`stx`/`st` (non-`r10`).
            if matches!(byte, LDX_B | LDX_W | LDX_DW | STX_B | STX_W | STX_DW | ST_B | ST_W | ST_DW) {
                if let Some(last) = pure.last().copied() {
                    if let Some(head) = try_fold_add_mem(last, slot, byte, table) {
                        pure.pop();
                        let is_first = pure.is_empty();
                        let seg_leader = if is_first { pure_leader.take() } else { None };
                        if !pure.is_empty() {
                            emit_pure_slice(&pure, pure_leader.take(), &mut out, &mut pc_to_idx, &mut idx_to_pc, table);
                            pure.clear();
                        }
                        let emit_idx = out.len();
                        let record_pc = seg_leader.unwrap_or(last.pc as usize);
                        if let Some(lpc) = seg_leader {
                            pc_to_idx[lpc] = emit_idx as u32;
                        }
                        out.push(head);
                        idx_to_pc.push(record_pc as u32);
                        // Intact fallback `data_access` slot at `emit_idx + 1` with exact faulting pc `i`.
                        out.push(emit_plain(slot, byte, table));
                        idx_to_pc.push(i as u32);
                        i += 1;
                        continue;
                    }
                }
            }

            // Otherwise emit the optimized pure segment before the non-pure instruction.
            emit_pure_slice(&pure, pure_leader.take(), &mut out, &mut pc_to_idx, &mut idx_to_pc, table);
            pure.clear();
        }

        let start_leader = pure_leader.take();

        // Fold `jcc_reg +1; mov` into branchless `select_reg_{reg,imm}`.
        if i + 1 < len && !leaders[i + 1] {
            if let Some((head, trailing_imm)) = try_fold_select(raw_slots, i, len, &leaders, region, table, rests) {
                let emit_idx = out.len();
                if let Some(lpc) = start_leader {
                    pc_to_idx[lpc] = emit_idx as u32;
                }
                pc_to_idx[i] = emit_idx as u32;
                out.push(head);
                idx_to_pc.push(i as u32);
                if let Some(imm_val) = trailing_imm {
                    out.push(ThreadedSlot {
                        handler: table.handlers[usize::from(bytes::INVALID)] as *const (),
                        slot: Slot::pack_bytes(0, 0, 0, 0, imm_val),
                    });
                    idx_to_pc.push((i + 1) as u32);
                }
                i += 2;
                continue;
            }
        }

        // Fold `ldxb dst, [base + off]; jeq/jne_imm dst, imm8` into `ldxb_jcc_u8`.
        if byte == LDX_B && i + 1 < len && !leaders[i + 1] {
            let next = raw_slots[i + 1];
            if let Some((head, target_pc, taken_rest, fall_rest)) = try_fold_ldxb_jcc(slot, next, i, table, rests) {
                let emit_idx = out.len();
                if let Some(lpc) = start_leader {
                    pc_to_idx[lpc] = emit_idx as u32;
                }
                pc_to_idx[i] = emit_idx as u32;
                out.push(head);
                idx_to_pc.push(i as u32);
                patches.push(BranchPatch {
                    emit_idx,
                    base_idx: emit_idx,
                    target_pc,
                    kind: PatchKind::LdxbJcc { taken_rest, fall_rest },
                });
                // Intact fallback `jcc` slot at `emit_idx + 1` for `windows::byte_load_miss`.
                emit_standalone_branch_or_call(next, next.byte(), i + 1, &mut out, &mut patches, table, rests);
                idx_to_pc.push((i + 1) as u32);
                i += 2;
                continue;
            }
        }

        // Standalone non-pure instruction (memory access, branch, call, exit, gotox, far, invalid, etc.).
        let emit_idx = out.len();
        if let Some(lpc) = start_leader {
            pc_to_idx[lpc] = emit_idx as u32;
        }
        pc_to_idx[i] = emit_idx as u32;
        if emit_standalone_branch_or_call(slot, byte, i, &mut out, &mut patches, table, rests) {
            idx_to_pc.push(i as u32);
        } else {
            out.push(emit_plain(slot, byte, table));
            idx_to_pc.push(i as u32);
        }
        i += 1;
    }

    if !pure.is_empty() {
        flush_pure(&mut pure, pure_leader.take(), &mut out, &mut pc_to_idx, &mut idx_to_pc, table);
    }

    // Emit the guard and moved `FAR` slots at `len..total` (all leaders).
    for pc in len..total {
        let emit_idx = out.len();
        pc_to_idx[pc] = emit_idx as u32;
        let slot = raw_slots[pc];
        out.push(emit_plain(slot, slot.byte(), table));
        idx_to_pc.push(pc as u32);
    }

    // Pass 4: patch all branch/call byte displacements from compacted indices.
    apply_patches(&mut out, &pc_to_idx, &patches, table);

    #[cfg(feature = "fuel")]
    let idx_rests = match rests {
        Some(raw_rests) => idx_to_pc
            .iter()
            .map(|&pc| raw_rests[pc as usize])
            .collect::<Vec<u32>>()
            .into_boxed_slice(),
        None => Box::default(),
    };

    CompiledStream::new(
        out,
        StreamMaps {
            pc_to_idx: pc_to_idx.into_boxed_slice(),
            idx_to_pc: idx_to_pc.into_boxed_slice(),
            #[cfg(feature = "fuel")]
            idx_rests,
        },
    )
}

// --- Leaders & Promotion helpers ---

fn compute_leaders(raw_slots: &[Slot], len: usize) -> Vec<bool> {
    let mut leaders = vec![false; raw_slots.len()];
    if len > 0 {
        leaders[0] = true;
    }
    for leader in &mut leaders[len..] {
        *leader = true;
    }

    let mut i = 0;
    while i < len {
        let slot = raw_slots[i];
        let byte = slot.byte();
        let usual = bytes::usual(byte);
        if usual == LD_IMM64 && i + 1 < len && raw_slots[i + 1].byte() == bytes::MISSING {
            i += 2;
            continue;
        }
        let opc = OpCode(usual);
        if byte == FAR || byte == GUARD || opc.is_jump() {
            if i + 1 < len {
                leaders[i + 1] = true;
            }
            if let Some(target) = static_jump_target(slot, byte, usual, i) {
                if target >= 0 && (target as usize) < raw_slots.len() {
                    leaders[target as usize] = true;
                }
            }
        }
        i += 1;
    }
    leaders
}

fn static_jump_target(slot: Slot, byte: u8, usual: u8, pc: usize) -> Option<i64> {
    if byte == FAR || byte == GUARD {
        return None;
    }
    let opc = OpCode(usual);
    if !opc.is_jump() {
        return None;
    }
    let disp = match opc.jmp_opc() {
        JmpOpc::Ja if matches!(opc.source(), Source::Imm) => match opc.class() {
            Class::Jmp64 => i64::from(slot.offset_raw()),
            Class::Jmp32 => i64::from(slot.imm()),
            _ => return None,
        },
        JmpOpc::Call if byte == CALL => i64::from(slot.instruction().imm()),
        JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit | JmpOpc::Jcond | JmpOpc::UndefF => return None,
        _ => i64::from(slot.offset_raw()),
    };
    Some(pc as i64 + 1 + disp)
}

fn find_region(regions: &[PromotedRegion], pc: usize) -> Option<&PromotedRegion> {
    let pc32 = pc as u32;
    regions.iter().find(|r| pc32 >= r.start && pc32 < r.end)
}

fn sup_fp_promoted(byte: u8, raw_slots: &[Slot], i: usize, reg: &PromotedRegion) -> bool {
    match byte {
        0x19 => reg.find(raw_slots[i].offset_raw(), true).is_some(),
        0x1a | 0x41 => reg.find(raw_slots[i].offset_raw(), false).is_some(),
        _ => false,
    }
}

// --- Pure-Segment 3-Address IR ---

#[derive(Clone, Copy)]
struct PureInst {
    op: PureOp,
    pc: u32,
}

#[derive(Clone, Copy)]
enum PureOp {
    Alu3Imm {
        bits64: bool,
        op: u8,
        dst: Reg,
        src1: Reg,
        imm: i32,
    },
    Alu3Reg {
        bits64: bool,
        op: u8,
        dst: Reg,
        src1: Reg,
        src2: Reg,
    },
    MovReg {
        bits64: bool,
        dst: Reg,
        src: Reg,
    },
    MovImm {
        bits64: bool,
        dst: Reg,
        imm: i32,
    },
    StoreLo32Reg {
        dst: Reg,
        src: Reg,
    },
    StoreLo32Imm {
        dst: Reg,
        imm: i32,
    },
    Other {
        slot: Slot,
        hi_slot: Option<Slot>,
        dst: Option<Reg>,
        read1: Option<Reg>,
        read2: Option<Reg>,
        zext32: bool,
    },
}

impl PureOp {
    /// Register overwritten completely (all 64 bits) by this op, if any.
    fn full_dst(self) -> Option<Reg> {
        match self {
            Self::Alu3Imm { dst, .. }
            | Self::Alu3Reg { dst, .. }
            | Self::MovReg { dst, .. }
            | Self::MovImm { dst, .. } => Some(dst),
            Self::StoreLo32Reg { .. } | Self::StoreLo32Imm { .. } => None,
            Self::Other { dst, .. } => dst,
        }
    }

    /// Any register written (full or partial) by this op.
    fn any_dst(self) -> Option<Reg> {
        match self {
            Self::StoreLo32Reg { dst, .. } | Self::StoreLo32Imm { dst, .. } => Some(dst),
            _ => self.full_dst(),
        }
    }

    fn produces_zext32(self) -> bool {
        match self {
            Self::Alu3Imm { bits64, .. }
            | Self::Alu3Reg { bits64, .. }
            | Self::MovReg { bits64, .. }
            | Self::MovImm { bits64, .. } => !bits64,
            Self::StoreLo32Reg { .. } | Self::StoreLo32Imm { .. } => false,
            Self::Other { zext32, .. } => zext32,
        }
    }

    fn is_retargetable(self) -> bool {
        matches!(self, Self::Alu3Imm { .. } | Self::Alu3Reg { .. } | Self::MovReg { .. } | Self::MovImm { .. })
    }

    fn set_dst(&mut self, new_dst: Reg) {
        match self {
            Self::Alu3Imm { dst, .. }
            | Self::Alu3Reg { dst, .. }
            | Self::MovReg { dst, .. }
            | Self::MovImm { dst, .. } => *dst = new_dst,
            _ => unreachable!("only retargetable ops change dst"),
        }
    }

    fn reads_reg(self, r: Reg) -> bool {
        match self {
            Self::Alu3Imm { src1, .. } => src1 == r,
            Self::Alu3Reg { src1, src2, .. } => src1 == r || src2 == r,
            Self::MovReg { src, .. } | Self::StoreLo32Reg { src, .. } => src == r,
            Self::MovImm { .. } | Self::StoreLo32Imm { .. } => false,
            Self::Other { read1, read2, .. } => read1 == Some(r) || read2 == Some(r),
        }
    }

    fn reads_mask(self) -> u64 {
        let bit = |r: Reg| 1u64 << r.get();
        match self {
            Self::Alu3Imm { src1, .. } => bit(src1),
            Self::Alu3Reg { src1, src2, .. } => bit(src1) | bit(src2),
            Self::MovReg { src, .. } => bit(src),
            Self::StoreLo32Reg { dst, src } => bit(dst) | bit(src),
            Self::StoreLo32Imm { dst, .. } => bit(dst),
            Self::MovImm { .. } => 0,
            Self::Other { read1, read2, .. } => read1.map_or(0, bit) | read2.map_or(0, bit),
        }
    }

    fn replace_reads(&mut self, old: Reg, new: Reg) {
        match self {
            Self::Alu3Imm { src1, .. } => {
                if *src1 == old {
                    *src1 = new;
                }
            }
            Self::Alu3Reg { src1, src2, .. } => {
                if *src1 == old {
                    *src1 = new;
                }
                if *src2 == old {
                    *src2 = new;
                }
            }
            Self::MovReg { src, .. } | Self::StoreLo32Reg { src, .. } => {
                if *src == old {
                    *src = new;
                }
            }
            Self::MovImm { .. } | Self::StoreLo32Imm { .. } | Self::Other { .. } => {}
        }
    }
}

fn alu_op_idx(op: AluOpc) -> Option<u8> {
    match op {
        AluOpc::Add => Some(OP_ADD),
        AluOpc::Sub => Some(OP_SUB),
        AluOpc::Mul => Some(OP_MUL),
        AluOpc::Or => Some(OP_OR),
        AluOpc::And => Some(OP_AND),
        AluOpc::Xor => Some(OP_XOR),
        AluOpc::Lsh => Some(OP_LSH),
        AluOpc::Rsh => Some(OP_RSH),
        AluOpc::Arsh => Some(OP_ARSH),
        _ => None,
    }
}

fn alu_opc_from_idx(idx: u8) -> AluOpc {
    match idx {
        OP_ADD => AluOpc::Add,
        OP_SUB => AluOpc::Sub,
        OP_MUL => AluOpc::Mul,
        OP_OR => AluOpc::Or,
        OP_AND => AluOpc::And,
        OP_XOR => AluOpc::Xor,
        OP_LSH => AluOpc::Lsh,
        OP_RSH => AluOpc::Rsh,
        OP_ARSH => AluOpc::Arsh,
        _ => unreachable!(),
    }
}

fn is_commutative(op: u8) -> bool {
    matches!(op, OP_ADD | OP_MUL | OP_OR | OP_AND | OP_XOR)
}

fn classify_pure(
    raw_slots: &[Slot],
    i: usize,
    len: usize,
    leaders: &[bool],
    slot: Slot,
    byte: u8,
    region: Option<&PromotedRegion>,
) -> Option<(PureOp, usize)> {
    let usual = bytes::usual(byte);
    let opc = OpCode(usual);

    // Promoted `r10` loads/stores inside a leaf region become pure virtual-register moves or low-32 writes.
    if let Some(reg) = region {
        if windows::windowed(usual) && matches!(opc.mem_mode(), MemMode::Mem) {
            let wide = match opc.mem_size() {
                MemSize::DWord => Some(true),
                MemSize::Word => Some(false),
                _ => None,
            };
            if let Some(wide) = wide {
                let off = slot.offset_raw();
                match opc.class() {
                    Class::Ldx if usize::from(slot.src_reg_decoded().get()) == FP => {
                        if let Some((vreg, _)) = reg.find(off, wide) {
                            return Some((
                                PureOp::MovReg {
                                    bits64: wide,
                                    dst: slot.dst_reg_decoded(),
                                    src: vreg,
                                },
                                1,
                            ));
                        }
                    }
                    Class::Stx if usize::from(slot.dst_reg_decoded().get()) == FP => {
                        if let Some((vreg, width)) = reg.find(off, wide) {
                            let op = if !wide && width == SlotWidth::Mixed {
                                PureOp::StoreLo32Reg {
                                    dst: vreg,
                                    src: slot.src_reg_decoded(),
                                }
                            } else {
                                PureOp::MovReg {
                                    bits64: wide,
                                    dst: vreg,
                                    src: slot.src_reg_decoded(),
                                }
                            };
                            return Some((op, 1));
                        }
                    }
                    Class::St if usize::from(slot.dst_reg_decoded().get()) == FP => {
                        if let Some((vreg, width)) = reg.find(off, wide) {
                            let op = if !wide && width == SlotWidth::Mixed {
                                PureOp::StoreLo32Imm {
                                    dst: vreg,
                                    imm: slot.imm(),
                                }
                            } else {
                                PureOp::MovImm {
                                    bits64: wide,
                                    dst: vreg,
                                    imm: slot.imm(),
                                }
                            };
                            return Some((op, 1));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if byte == LD_IMM64 {
        if i + 1 < len && !leaders[i + 1] && raw_slots[i + 1].byte() != GUARD {
            return Some((
                PureOp::Other {
                    slot,
                    hi_slot: Some(raw_slots[i + 1]),
                    dst: Some(slot.dst_reg_decoded()),
                    read1: None,
                    read2: None,
                    zext32: false,
                },
                2,
            ));
        }
        return None;
    }

    if byte == bytes::INVALID || byte == bytes::MISSING || byte == FAR || byte == GUARD {
        return None;
    }

    if matches!(byte, MOVSX32 | MOVSX64 | TO_HOST | TO_GUEST) {
        return Some((
            PureOp::Other {
                slot,
                hi_slot: None,
                dst: Some(slot.dst_reg_decoded()),
                read1: Some(slot.src_reg_decoded()),
                read2: None,
                zext32: byte == MOVSX32,
            },
            1,
        ));
    }

    let bits64 = match opc.class() {
        Class::Alu64 => true,
        Class::Alu32 => false,
        _ => return None,
    };

    if matches!(opc.alu_opc(), AluOpc::UndefE | AluOpc::UndefF) {
        return None;
    }

    if byte == MOV32_REG || byte == MOV64_REG {
        return Some((
            PureOp::MovReg {
                bits64,
                dst: slot.dst_reg_decoded(),
                src: slot.src_reg_decoded(),
            },
            1,
        ));
    }
    if byte == MOV32_IMM || byte == MOV64_IMM {
        return Some((
            PureOp::MovImm {
                bits64,
                dst: slot.dst_reg_decoded(),
                imm: slot.imm(),
            },
            1,
        ));
    }

    if let Some(op_idx) = alu_op_idx(opc.alu_opc()) {
        let dst = slot.dst_reg_decoded();
        return match opc.source() {
            Source::Imm => Some((
                PureOp::Alu3Imm {
                    bits64,
                    op: op_idx,
                    dst,
                    src1: dst,
                    imm: slot.imm(),
                },
                1,
            )),
            Source::Reg => Some((
                PureOp::Alu3Reg {
                    bits64,
                    op: op_idx,
                    dst,
                    src1: dst,
                    src2: slot.src_reg_decoded(),
                },
                1,
            )),
        };
    }

    // Remaining pure ALU ops (`Div`, `Mod`, `Neg`, `End`): never fault in eBPF.
    let dst = slot.dst_reg_decoded();
    let (read1, read2) = match LAYOUTS[usize::from(byte)] {
        Layout::DstSrc => (Some(dst), Some(slot.src_reg_decoded())),
        Layout::Dst => (Some(dst), None),
        Layout::Raw => return None,
    };
    Some((
        PureOp::Other {
            slot,
            hi_slot: None,
            dst: Some(dst),
            read1,
            read2,
            zext32: !bits64,
        },
        1,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alias {
    None,
    Exact(Reg),
    Zext32(Reg),
}

fn optimize_pure_segment(ops: &mut Vec<PureInst>) {
    if ops.len() <= 1 {
        if ops.len() == 1 {
            if let PureOp::MovReg { bits64: true, dst, src } = ops[0].op {
                if dst == src {
                    ops.clear();
                }
            }
        }
        return;
    }

    pass_copy_prop(ops);
    if pass_retarget_copies(ops) {
        pass_copy_prop(ops);
        pass_retarget_copies(ops);
        pass_copy_prop(ops);
    }
    pass_dead_writes(ops);
}

fn pass_copy_prop(ops: &mut Vec<PureInst>) {
    let mut alias = [Alias::None; TOTAL_REGS];
    let mut zext32 = [false; TOTAL_REGS];
    let mut keep = vec![true; ops.len()];

    let resolve = |r: Reg, need64: bool, alias: &[Alias; TOTAL_REGS], zext32: &[bool; TOTAL_REGS]| -> Reg {
        match alias[usize::from(r.get())] {
            Alias::Exact(s) => s,
            Alias::Zext32(s) if !need64 || zext32[usize::from(s.get())] => s,
            _ => r,
        }
    };
    let kill = |r: Reg, alias: &mut [Alias; TOTAL_REGS]| {
        alias[usize::from(r.get())] = Alias::None;
        for entry in alias.iter_mut() {
            match *entry {
                Alias::Exact(s) | Alias::Zext32(s) if s == r => *entry = Alias::None,
                _ => {}
            }
        }
    };

    for (idx, inst) in ops.iter_mut().enumerate() {
        match &mut inst.op {
            PureOp::Alu3Imm { bits64, dst, src1, .. } => {
                *src1 = resolve(*src1, *bits64, &alias, &zext32);
                let d = *dst;
                kill(d, &mut alias);
                zext32[usize::from(d.get())] = !*bits64;
            }
            PureOp::Alu3Reg {
                bits64,
                dst,
                src1,
                src2,
                ..
            } => {
                *src1 = resolve(*src1, *bits64, &alias, &zext32);
                *src2 = resolve(*src2, *bits64, &alias, &zext32);
                let d = *dst;
                kill(d, &mut alias);
                zext32[usize::from(d.get())] = !*bits64;
            }
            PureOp::MovReg { bits64, dst, src } => {
                *src = resolve(*src, *bits64, &alias, &zext32);
                let d = *dst;
                let s = *src;
                if d == s && (*bits64 || zext32[usize::from(d.get())]) {
                    keep[idx] = false;
                    continue;
                }
                let src_z = !*bits64 || zext32[usize::from(s.get())];
                kill(d, &mut alias);
                zext32[usize::from(d.get())] = src_z;
                if d != s {
                    alias[usize::from(d.get())] = if *bits64 || zext32[usize::from(s.get())] {
                        Alias::Exact(s)
                    } else {
                        Alias::Zext32(s)
                    };
                }
            }
            PureOp::MovImm { bits64, dst, .. } => {
                let d = *dst;
                kill(d, &mut alias);
                zext32[usize::from(d.get())] = !*bits64;
            }
            PureOp::StoreLo32Reg { dst, src } => {
                *src = resolve(*src, false, &alias, &zext32);
                let d = *dst;
                kill(d, &mut alias);
                zext32[usize::from(d.get())] = false;
            }
            PureOp::StoreLo32Imm { dst, .. } => {
                let d = *dst;
                kill(d, &mut alias);
                zext32[usize::from(d.get())] = false;
            }
            PureOp::Other { dst, zext32: z, .. } => {
                if let Some(d) = *dst {
                    kill(d, &mut alias);
                    zext32[usize::from(d.get())] = *z;
                }
            }
        }
    }

    let mut i = 0;
    ops.retain(|_| {
        let k = keep[i];
        i += 1;
        k
    });
}

/// Retarget a producer's destination directly into `d` when followed by `mov d, t` and `t` is unconditionally
/// overwritten later in the same pure segment.
fn pass_retarget_copies(ops: &mut Vec<PureInst>) -> bool {
    let mut changed = false;
    let mut deleted = vec![false; ops.len()];

    for m in 0..ops.len() {
        if deleted[m] {
            continue;
        }
        let PureOp::MovReg {
            bits64: m64,
            dst: d,
            src: t,
        } = ops[m].op
        else {
            continue;
        };
        if d == t {
            continue;
        }

        // Find producer `i < m` writing `t` with no intervening read or write of `d` and no `Other` reading `t`.
        let mut prod = None;
        let mut ok_back = true;
        for k in (0..m).rev() {
            if deleted[k] {
                continue;
            }
            let op = ops[k].op;
            if op.any_dst() == Some(t) {
                prod = Some(k);
                break;
            }
            if op.reads_reg(d) || op.any_dst() == Some(d) {
                ok_back = false;
                break;
            }
            if matches!(op, PureOp::Other { .. }) && op.reads_reg(t) {
                ok_back = false;
                break;
            }
        }
        if !ok_back {
            continue;
        }
        let Some(i) = prod else {
            continue;
        };
        let prod_op = ops[i].op;
        if !prod_op.is_retargetable() || (!m64 && !prod_op.produces_zext32()) {
            continue;
        }

        // Find `kill > m` in the same pure segment that unconditionally overwrites `t` before `d` is modified.
        let mut kill_idx = None;
        for k in (m + 1)..ops.len() {
            if deleted[k] {
                continue;
            }
            let op = ops[k].op;
            if matches!(op, PureOp::Other { .. }) && op.reads_reg(t) {
                break;
            }
            if op.full_dst() == Some(t) {
                kill_idx = Some(k);
                break;
            }
            if op.any_dst() == Some(d) || op.any_dst() == Some(t) {
                break;
            }
        }
        let Some(kill) = kill_idx else {
            continue;
        };

        ops[i].op.set_dst(d);
        for k in (i + 1)..m {
            if !deleted[k] {
                ops[k].op.replace_reads(t, d);
            }
        }
        for k in (m + 1)..=kill {
            if !deleted[k] {
                ops[k].op.replace_reads(t, d);
            }
        }
        deleted[m] = true;
        changed = true;
    }

    if changed {
        let mut i = 0;
        ops.retain(|_| {
            let keep = !deleted[i];
            i += 1;
            keep
        });
    }
    changed
}

fn pass_dead_writes(ops: &mut Vec<PureInst>) {
    let mut live: u64 = (1u64 << TOTAL_REGS) - 1;
    let mut keep = vec![true; ops.len()];

    for k in (0..ops.len()).rev() {
        let op = ops[k].op;
        if let Some(dst) = op.full_dst() {
            let bit = 1u64 << dst.get();
            if (live & bit) == 0 {
                keep[k] = false;
                continue;
            }
            live &= !bit;
            live |= op.reads_mask();
        } else {
            live |= op.reads_mask();
        }
    }

    let mut i = 0;
    ops.retain(|_| {
        let k = keep[i];
        i += 1;
        k
    });
}

// --- Pure-segment emission & peepholes ---

fn flush_pure<M: Memory, H: Host<M>>(
    pure: &mut Vec<PureInst>,
    seg_leader: Option<usize>,
    out: &mut Vec<ThreadedSlot>,
    pc_to_idx: &mut [u32],
    idx_to_pc: &mut Vec<u32>,
    table: &DispatchTable<M, H>,
) {
    let saved_first = pure[0];
    optimize_pure_segment(pure);
    if seg_leader.is_some() && pure.is_empty() {
        pure.push(saved_first);
    }
    emit_pure_slice(pure, seg_leader, out, pc_to_idx, idx_to_pc, table);
    pure.clear();
}

fn emit_pure_slice<M: Memory, H: Host<M>>(
    ops: &[PureInst],
    seg_leader: Option<usize>,
    out: &mut Vec<ThreadedSlot>,
    pc_to_idx: &mut [u32],
    idx_to_pc: &mut Vec<u32>,
    table: &DispatchTable<M, H>,
) {
    let mut leader_pending = seg_leader;
    let mut k = 0usize;
    while k < ops.len() {
        let emit_idx = out.len();
        let record_pc = match leader_pending.take() {
            Some(lpc) => {
                pc_to_idx[lpc] = emit_idx as u32;
                lpc as u32
            }
            None => ops[k].pc,
        };

        // 3-op rotate: `t = x >> k1; x = x << k2; x = x | t` (or `<<` then `>>`).
        if k + 2 < ops.len() {
            if let Some(folded) = fold_pure_rot(ops[k].op, ops[k + 1].op, ops[k + 2].op, table) {
                out.push(folded);
                idx_to_pc.push(record_pc);
                k += 3;
                continue;
            }
        }

        if k + 1 < ops.len() {
            if let Some(folded) = fold_pure_shift_alu(ops[k].op, ops[k + 1].op, table) {
                out.push(folded);
                idx_to_pc.push(record_pc);
                k += 2;
                continue;
            }
            if let Some(folded) = fold_pure_rsh_and(ops[k].op, ops[k + 1].op, table) {
                out.push(folded);
                idx_to_pc.push(record_pc);
                k += 2;
                continue;
            }
            if let Some(folded) = fold_pure_imm_add_reg(ops[k].op, ops[k + 1].op, table) {
                out.push(folded);
                idx_to_pc.push(record_pc);
                k += 2;
                continue;
            }
            if let Some(folded) = fold_pure_mov_alu_src(ops[k].op, ops[k + 1].op, table) {
                out.push(folded);
                idx_to_pc.push(record_pc);
                k += 2;
                continue;
            }
            let feeds_next = k + 2 < ops.len() && pure_mov_feeds(ops[k + 1].op, ops[k + 2].op);
            if !feeds_next {
                if let Some(folded) = fold_pure_mov_mov_reg(ops[k].op, ops[k + 1].op, table) {
                    out.push(folded);
                    idx_to_pc.push(record_pc);
                    k += 2;
                    continue;
                }
                if let Some(folded) = fold_pure_mov_imm_mov_reg(ops[k].op, ops[k + 1].op, table) {
                    out.push(folded);
                    idx_to_pc.push(record_pc);
                    k += 2;
                    continue;
                }
            }
        }

        emit_single_pure(ops[k].op, record_pc, out, idx_to_pc, table);
        k += 1;
    }
}

fn fold_pure_rot<M: Memory, H: Host<M>>(
    a: PureOp,
    b: PureOp,
    c: PureOp,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::Alu3Imm {
        bits64: b0,
        op: op0,
        dst: t,
        src1: x0,
        imm: imm1,
    } = a
    else {
        return None;
    };
    let PureOp::Alu3Imm {
        bits64: b1,
        op: op1,
        dst: x1,
        src1: x2,
        imm: imm2,
    } = b
    else {
        return None;
    };
    let PureOp::Alu3Reg {
        bits64: b2,
        op: OP_OR,
        dst: x3,
        src1: o1,
        src2: o2,
    } = c
    else {
        return None;
    };
    if b0 != b1 || b0 != b2 || t == x0 || x1 != x0 || x2 != x0 || x3 != x0 {
        return None;
    }
    if !((o1 == x0 && o2 == t) || (o1 == t && o2 == x0)) {
        return None;
    }
    let lsh_first = match (op0, op1) {
        (OP_RSH, OP_LSH) => false,
        (OP_LSH, OP_RSH) => true,
        _ => return None,
    };
    let mask = if b0 { 63u8 } else { 31u8 };
    let k1 = (imm1 as u8) & mask;
    let k2 = (imm2 as u8) & mask;
    Some(ThreadedSlot {
        handler: table.folds.rot[usize::from(b0)][usize::from(lsh_first)] as *const (),
        slot: Slot::pack_bytes(x0.get(), t.get(), k1, k2, 0),
    })
}

fn fold_pure_shift_alu<M: Memory, H: Host<M>>(
    a: PureOp,
    b: PureOp,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::Alu3Imm {
        bits64: b0,
        op: op0,
        dst,
        src1: s1,
        imm,
    } = a
    else {
        return None;
    };
    let lsh = match op0 {
        OP_LSH => true,
        OP_RSH => false,
        _ => return None,
    };
    let PureOp::Alu3Reg {
        bits64: b1,
        op: op1,
        dst: dst1,
        src1: r1,
        src2: r2,
    } = b
    else {
        return None;
    };
    if b0 != b1 || dst1 != dst {
        return None;
    }
    let shift_op = match op1 {
        OP_XOR => SHIFT_OP_XOR,
        OP_OR => SHIFT_OP_OR,
        OP_ADD => SHIFT_OP_ADD,
        _ => return None,
    };
    let s2 = if r1 == dst && r2 != dst {
        r2
    } else if r2 == dst && r1 != dst {
        r1
    } else {
        return None;
    };
    let mask = if b0 { 63u8 } else { 31u8 };
    let k = (imm as u8) & mask;
    Some(ThreadedSlot {
        handler: table.folds.shift_alu[usize::from(b0)][usize::from(lsh)][usize::from(shift_op)] as *const (),
        slot: Slot::pack_bytes(dst.get(), s1.get(), s2.get(), k, 0),
    })
}

fn fold_pure_rsh_and<M: Memory, H: Host<M>>(a: PureOp, b: PureOp, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    let PureOp::Alu3Imm {
        bits64: b0,
        op: OP_RSH,
        dst,
        src1: s1,
        imm: k_imm,
    } = a
    else {
        return None;
    };
    let PureOp::Alu3Imm {
        bits64: b1,
        op: OP_AND,
        dst: dst1,
        src1: s2,
        imm: mask_imm,
    } = b
    else {
        return None;
    };
    if b0 != b1 || dst1 != dst || s2 != dst {
        return None;
    }
    let mask = if b0 { 63u8 } else { 31u8 };
    let k = (k_imm as u8) & mask;
    Some(ThreadedSlot {
        handler: table.folds.rsh_and_imm[usize::from(b0)] as *const (),
        slot: Slot::pack_bytes(dst.get(), s1.get(), k, 0, mask_imm),
    })
}

fn fold_pure_imm_add_reg<M: Memory, H: Host<M>>(
    a: PureOp,
    b: PureOp,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::Alu3Imm {
        bits64: true,
        op: op0,
        dst,
        src1: s1,
        imm,
    } = a
    else {
        return None;
    };
    let is_mul = match op0 {
        OP_ADD => false,
        OP_MUL => true,
        _ => return None,
    };
    let PureOp::Alu3Reg {
        bits64: true,
        op: OP_ADD,
        dst: dst1,
        src1: r1,
        src2: r2,
    } = b
    else {
        return None;
    };
    if dst1 != dst {
        return None;
    }
    let s2 = if r1 == dst && r2 != dst {
        r2
    } else if r2 == dst && r1 != dst {
        r1
    } else {
        return None;
    };
    Some(ThreadedSlot {
        handler: table.folds.imm_add_reg[usize::from(is_mul)] as *const (),
        slot: Slot::pack_bytes(dst.get(), s1.get(), s2.get(), 0, imm),
    })
}

fn fold_pure_mov_alu_src<M: Memory, H: Host<M>>(
    a: PureOp,
    b: PureOp,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::MovReg {
        bits64: b0,
        dst: t,
        src: src1,
    } = a
    else {
        return None;
    };
    let PureOp::Alu3Reg {
        bits64: b1,
        op: op1,
        dst,
        src1: r1,
        src2: r2,
    } = b
    else {
        return None;
    };
    if b0 != b1 || dst == t {
        return None;
    }
    let src_op = match op1 {
        OP_ADD => SRC_OP_ADD,
        OP_MUL => SRC_OP_MUL,
        OP_XOR => SRC_OP_XOR,
        _ => return None,
    };
    if !((r1 == dst && r2 == t) || (r2 == dst && r1 == t)) {
        return None;
    }
    Some(ThreadedSlot {
        handler: table.folds.mov_alu_src[usize::from(b0)][usize::from(src_op)] as *const (),
        slot: Slot::pack_bytes(t.get(), src1.get(), dst.get(), 0, 0),
    })
}

fn pure_mov_feeds(mov_op: PureOp, next_op: PureOp) -> bool {
    let PureOp::MovReg { bits64, dst: t, .. } = mov_op else {
        return false;
    };
    let PureOp::Alu3Reg {
        bits64: b1,
        op: op1,
        dst,
        src1: r1,
        src2: r2,
    } = next_op
    else {
        return false;
    };
    b1 == bits64
        && dst != t
        && matches!(op1, OP_ADD | OP_MUL | OP_XOR)
        && ((r1 == dst && r2 == t) || (r2 == dst && r1 == t))
}

fn fold_pure_mov_mov_reg<M: Memory, H: Host<M>>(
    a: PureOp,
    b: PureOp,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::MovReg {
        bits64: b0,
        dst: d0,
        src: s0,
    } = a
    else {
        return None;
    };
    let PureOp::MovReg {
        bits64: b1,
        dst: d1,
        src: mut s1,
    } = b
    else {
        return None;
    };
    if s1 == d0 {
        if b0 || !b1 {
            s1 = s0;
        } else {
            return None;
        }
    }
    Some(ThreadedSlot {
        handler: table.folds.mov_mov_reg[usize::from(b0)][usize::from(b1)] as *const (),
        slot: Slot::pack_bytes(d0.get(), s0.get(), d1.get(), s1.get(), 0),
    })
}

fn fold_pure_mov_imm_mov_reg<M: Memory, H: Host<M>>(
    a: PureOp,
    b: PureOp,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::MovImm {
        bits64: b0,
        dst: d0,
        imm,
    } = a
    else {
        return None;
    };
    let PureOp::MovReg {
        bits64: b1,
        dst: d1,
        src: s1,
    } = b
    else {
        return None;
    };
    if s1 == d0 {
        return None;
    }
    Some(ThreadedSlot {
        handler: table.folds.mov_imm_mov_reg[usize::from(b0)][usize::from(b1)] as *const (),
        slot: Slot::pack_bytes(d0.get(), d1.get(), s1.get(), 0, imm),
    })
}

fn emit_single_pure<M: Memory, H: Host<M>>(
    op: PureOp,
    record_pc: u32,
    out: &mut Vec<ThreadedSlot>,
    idx_to_pc: &mut Vec<u32>,
    table: &DispatchTable<M, H>,
) {
    match op {
        PureOp::Alu3Imm {
            bits64,
            op,
            dst,
            src1,
            imm,
        } => {
            if dst == src1 {
                let opc = if bits64 {
                    OpCode::alu64(alu_opc_from_idx(op), Source::Imm).0
                } else {
                    OpCode::alu32(alu_opc_from_idx(op), Source::Imm).0
                };
                out.push(ThreadedSlot {
                    handler: table.handlers[usize::from(opc)] as *const (),
                    slot: Slot::pack(opc, dst.get(), 0, imm),
                });
            } else {
                out.push(ThreadedSlot {
                    handler: table.alu3.imm[usize::from(bits64)][usize::from(op)] as *const (),
                    slot: Slot::alu3_imm(dst, src1, imm),
                });
            }
            idx_to_pc.push(record_pc);
        }
        PureOp::Alu3Reg {
            bits64,
            op,
            dst,
            src1,
            src2,
        } => {
            let two_addr_rhs = if dst == src1 {
                Some(src2)
            } else if dst == src2 && is_commutative(op) {
                Some(src1)
            } else {
                None
            };
            if let Some(rhs) = two_addr_rhs {
                let opc = if bits64 {
                    OpCode::alu64(alu_opc_from_idx(op), Source::Reg).0
                } else {
                    OpCode::alu32(alu_opc_from_idx(op), Source::Reg).0
                };
                out.push(ThreadedSlot {
                    handler: table.handlers[usize::from(opc)] as *const (),
                    slot: Slot::pack_bytes(dst.get(), rhs.get(), 0, 0, 0),
                });
            } else {
                out.push(ThreadedSlot {
                    handler: table.alu3.reg[usize::from(bits64)][usize::from(op)] as *const (),
                    slot: Slot::alu3_reg(dst, src1, src2),
                });
            }
            idx_to_pc.push(record_pc);
        }
        PureOp::MovReg { bits64, dst, src } => {
            let opc = if bits64 { MOV64_REG } else { MOV32_REG };
            out.push(ThreadedSlot {
                handler: table.handlers[usize::from(opc)] as *const (),
                slot: Slot::pack_bytes(dst.get(), src.get(), 0, 0, 0),
            });
            idx_to_pc.push(record_pc);
        }
        PureOp::MovImm { bits64, dst, imm } => {
            let opc = if bits64 { MOV64_IMM } else { MOV32_IMM };
            out.push(ThreadedSlot {
                handler: table.handlers[usize::from(opc)] as *const (),
                slot: Slot::mov_imm(bits64, dst, imm),
            });
            idx_to_pc.push(record_pc);
        }
        PureOp::StoreLo32Reg { dst, src } => {
            out.push(ThreadedSlot {
                handler: table.folds.store_lo32_reg as *const (),
                slot: Slot::pack_bytes(dst.get(), src.get(), 0, 0, 0),
            });
            idx_to_pc.push(record_pc);
        }
        PureOp::StoreLo32Imm { dst, imm } => {
            out.push(ThreadedSlot {
                handler: table.folds.store_lo32_imm as *const (),
                slot: Slot::pack_bytes(dst.get(), 0, 0, 0, imm),
            });
            idx_to_pc.push(record_pc);
        }
        PureOp::Other { slot, hi_slot, .. } => {
            out.push(emit_plain(slot, slot.byte(), table));
            idx_to_pc.push(record_pc);
            if let Some(hi) = hi_slot {
                out.push(emit_plain(hi, hi.byte(), table));
                idx_to_pc.push(record_pc + 1);
            }
        }
    }
}

// --- Cross-boundary folds & Super helpers ---

fn try_fold_0xf7<M: Memory, H: Host<M>>(
    slots: &[Slot],
    i: usize,
    table: &DispatchTable<M, H>,
) -> Option<(ThreadedSlot, Slot, u8)> {
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
    let head = match b3 {
        LDX_B | LDX_W | LDX_DW => {
            if s3.src_reg_decoded() != a {
                return None;
            }
            let dst = s3.dst_reg_decoded();
            ThreadedSlot {
                handler: table.folds.lddw_add_ldx[size_idx(b3)] as *const (),
                slot: Slot::pack_bytes(a.get(), idx.get(), dst.get(), off as u8, s0.imm()),
            }
        }
        STX_B | STX_W | STX_DW => {
            if s3.dst_reg_decoded() != a {
                return None;
            }
            let val = s3.src_reg_decoded();
            ThreadedSlot {
                handler: table.folds.lddw_add_stx[size_idx(b3)] as *const (),
                slot: Slot::pack_bytes(a.get(), idx.get(), val.get(), off as u8, s0.imm()),
            }
        }
        ST_B | ST_W | ST_DW => {
            if s3.dst_reg_decoded() != a {
                return None;
            }
            ThreadedSlot {
                handler: table.folds.lddw_add_st[size_idx(b3)] as *const (),
                slot: Slot::pack_bytes(a.get(), idx.get(), 0, off as u8, s0.imm()),
            }
        }
        _ => return None,
    };
    Some((head, s3, b3))
}

fn try_fold_mov_ja<M: Memory, H: Host<M>>(
    mov_inst: PureInst,
    ja_slot: Slot,
    ja_pc: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<(ThreadedSlot, PatchKind, usize)> {
    let ja_opc = OpCode(ja_slot.byte());
    let ja_off = match ja_opc.class() {
        Class::Jmp64 => i64::from(ja_slot.offset_raw()),
        Class::Jmp32 => i64::from(ja_slot.imm()),
        _ => return None,
    };
    let target_pc = (ja_pc as i64 + 1 + ja_off) as usize;
    let raw_byte_off = (ja_off + 2).checked_mul(STRIDE)?;
    let rest = rests.map_or(0, |r| r[target_pc]);
    match mov_inst.op {
        PureOp::MovImm { bits64, dst, imm } => {
            i16::try_from(raw_byte_off).ok()?;
            let rest8 = u8::try_from(rest).ok()?;
            Some((
                ThreadedSlot {
                    handler: table.folds.mov_ja_imm[usize::from(bits64)] as *const (),
                    slot: Slot::pack(dst.get(), rest8, 0, imm),
                },
                PatchKind::MovJaImm,
                target_pc,
            ))
        }
        PureOp::MovReg { bits64, dst, src } => {
            i32::try_from(raw_byte_off).ok()?;
            let rest16 = u16::try_from(rest).ok()?;
            Some((
                ThreadedSlot {
                    handler: table.folds.mov_ja_reg[usize::from(bits64)] as *const (),
                    slot: Slot::pack(dst.get(), src.get(), rest16 as i16, 0),
                },
                PatchKind::MovJaReg,
                target_pc,
            ))
        }
        _ => None,
    }
}

fn try_fold_add_mem<M: Memory, H: Host<M>>(
    add_inst: PureInst,
    mem_slot: Slot,
    mem_byte: u8,
    table: &DispatchTable<M, H>,
) -> Option<ThreadedSlot> {
    let PureOp::Alu3Reg {
        bits64: true,
        op: OP_ADD,
        dst: a,
        src1,
        src2,
    } = add_inst.op
    else {
        return None;
    };
    if usize::from(a.get()) == FP {
        return None;
    }
    let off = mem_slot.offset_raw();
    let sz = size_idx(mem_byte);

    let in_place_rhs = if src1 == a {
        Some(src2)
    } else if src2 == a {
        Some(src1)
    } else {
        None
    };

    match mem_byte {
        LDX_B | LDX_W | LDX_DW => {
            if mem_slot.src_reg_decoded() != a {
                return None;
            }
            let dst = mem_slot.dst_reg_decoded();
            if let Some(b) = in_place_rhs {
                Some(ThreadedSlot {
                    handler: table.folds.add_ldx[sz] as *const (),
                    slot: Slot::pack_bytes(a.get(), b.get(), dst.get(), 0, i32::from(off)),
                })
            } else {
                Some(ThreadedSlot {
                    handler: table.folds.mov_add_ldx[sz] as *const (),
                    slot: Slot::pack_bytes(a.get(), src1.get(), src2.get(), dst.get(), i32::from(off)),
                })
            }
        }
        STX_B | STX_W | STX_DW => {
            if mem_slot.dst_reg_decoded() != a {
                return None;
            }
            let val = mem_slot.src_reg_decoded();
            if let Some(b) = in_place_rhs {
                Some(ThreadedSlot {
                    handler: table.folds.add_stx[sz] as *const (),
                    slot: Slot::pack_bytes(a.get(), b.get(), val.get(), 0, i32::from(off)),
                })
            } else {
                Some(ThreadedSlot {
                    handler: table.folds.mov_add_stx[sz] as *const (),
                    slot: Slot::pack_bytes(a.get(), src1.get(), src2.get(), val.get(), i32::from(off)),
                })
            }
        }
        ST_B | ST_W | ST_DW if off == 0 => {
            if mem_slot.dst_reg_decoded() != a {
                return None;
            }
            Some(ThreadedSlot {
                handler: table.folds.mov_add_st[sz] as *const (),
                slot: Slot::pack_bytes(a.get(), src1.get(), src2.get(), 0, mem_slot.imm()),
            })
        }
        _ => None,
    }
}

fn try_fold_select<M: Memory, H: Host<M>>(
    raw_slots: &[Slot],
    i: usize,
    len: usize,
    leaders: &[bool],
    region: Option<&PromotedRegion>,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<(ThreadedSlot, Option<i32>)> {
    let s0 = raw_slots[i];
    let opc = OpCode(s0.byte());
    let bits64 = match opc.class() {
        Class::Jmp32 => false,
        Class::Jmp64 => true,
        _ => return None,
    };
    if !matches!(opc.source(), Source::Reg) || s0.offset_raw() != 1 {
        return None;
    }
    let (kind, invert, swap) = normalize_reg_cmp(opc.jmp_opc())?;

    let mut s1 = raw_slots[i + 1];
    let mut b1 = s1.byte();
    if let Some(sup) = Super::with_byte(b1) {
        b1 = sup.opcode(0);
        s1 = s1.with_byte(b1);
    }

    // Match plain `mov` or promoted `r10` load/store that lowers to a full `MovReg`/`MovImm`.
    let mov_op = if b1 == MOV32_IMM || b1 == MOV64_IMM {
        PureOp::MovImm {
            bits64: b1 == MOV64_IMM,
            dst: s1.dst_reg_decoded(),
            imm: s1.imm(),
        }
    } else if b1 == MOV32_REG || b1 == MOV64_REG {
        PureOp::MovReg {
            bits64: b1 == MOV64_REG,
            dst: s1.dst_reg_decoded(),
            src: s1.src_reg_decoded(),
        }
    } else {
        let reg = region?;
        match classify_pure(raw_slots, i + 1, len, leaders, s1, b1, Some(reg)) {
            Some((op @ (PureOp::MovReg { .. } | PureOp::MovImm { .. }), 1)) => op,
            _ => return None,
        }
    };

    let (mut a, mut b) = (s0.dst_reg_decoded(), s0.src_reg_decoded());
    if swap {
        core::mem::swap(&mut a, &mut b);
    }
    let fall_rest8 = u8::try_from(rests.map_or(0, |r| r[i + 2])).ok()?;
    match mov_op {
        PureOp::MovReg {
            bits64: mov64,
            dst,
            src,
        } => {
            let meta = kind | (u8::from(invert) << 2) | (u8::from(mov64) << 3);
            let payload = i32::from_le_bytes([meta, fall_rest8, 0, 0]);
            Some((
                ThreadedSlot {
                    handler: table.folds.select_reg_reg[usize::from(bits64)] as *const (),
                    slot: Slot::pack_bytes(a.get(), b.get(), dst.get(), src.get(), payload),
                },
                None,
            ))
        }
        PureOp::MovImm {
            bits64: mov64,
            dst,
            imm,
        } => {
            let meta = kind | (u8::from(invert) << 2) | (u8::from(mov64) << 3);
            Some((
                ThreadedSlot {
                    handler: table.folds.select_reg_imm[usize::from(bits64)] as *const (),
                    slot: Slot::pack_bytes(a.get(), b.get(), dst.get(), meta, i32::from(fall_rest8)),
                },
                Some(imm),
            ))
        }
        _ => None,
    }
}

fn try_fold_ldxb_jcc<M: Memory, H: Host<M>>(
    s0: Slot,
    s1: Slot,
    i: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<(ThreadedSlot, usize, u8, u8)> {
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
    i16::try_from((i32::from(s1.offset_raw()) + 2) * (STRIDE as i32)).ok()?;
    let target_pc = (i as i64 + 2 + i64::from(s1.offset_raw())) as usize;
    let taken_rest = u8::try_from(rests.map_or(0, |r| r[target_pc])).ok()?;
    let fall_rest = u8::try_from(rests.map_or(0, |r| r[i + 2])).ok()?;
    let payload = i32::from_le_bytes([0, 0, taken_rest, fall_rest]);
    Some((
        ThreadedSlot {
            handler: table.folds.ldxb_jcc_u8[usize::from(eq)] as *const (),
            slot: Slot::pack_bytes(dst.get(), base.get(), imm8, off8 as u8, payload),
        },
        target_pc,
        taken_rest,
        fall_rest,
    ))
}

fn super_branch_fits(sup: &Super, raw_slots: &[Slot], i: usize, rests: Option<&[u32]>) -> bool {
    if !sup.branches() {
        return true;
    }
    let last_pc = i + sup.len() - 1;
    let last = raw_slots[last_pc];
    let lb = last.byte();
    let target_pc = (last_pc as i64 + 1 + i64::from(last.offset_raw())) as usize;
    let fall_ok = rests.is_none_or(|r| r[last_pc + 1] <= u32::from(u8::MAX));
    if is_cond_dst_jump(lb) {
        fall_ok
            && i16::try_from((i32::from(last.offset_raw()) + 1) * (STRIDE as i32)).is_ok()
            && rests.is_none_or(|r| r[target_pc] <= u32::from(u8::MAX))
    } else if LAYOUTS[usize::from(lb)] == Layout::DstSrc {
        fall_ok && rests.is_none_or(|r| r[target_pc] <= u32::from(u8::MAX))
    } else {
        fall_ok
    }
}

// --- Branch emission & Pass 4 patching ---

struct BranchPatch {
    emit_idx: usize,
    base_idx: usize,
    target_pc: usize,
    kind: PatchKind,
}

enum PatchKind {
    JaScaled {
        rest: u32,
    },
    LocalCallScaled {
        rest: u32,
    },
    CondDst {
        taken_rest: u8,
        raw_slot: Slot,
    },
    CondDstSrc {
        taken_rest: u8,
        fall_rest: u8,
        raw_slot: Slot,
    },
    MovJaImm,
    MovJaReg,
    LdxbJcc {
        taken_rest: u8,
        fall_rest: u8,
    },
}

fn emit_branch_in_super<M: Memory, H: Host<M>>(
    slot: Slot,
    byte: u8,
    pc: usize,
    out: &mut Vec<ThreadedSlot>,
    patches: &mut Vec<BranchPatch>,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) {
    let emit_idx = out.len();
    let target_pc = (pc as i64 + 1 + i64::from(slot.offset_raw())) as usize;
    if is_cond_dst_jump(byte) {
        let taken_rest = rests.map_or(0, |r| r[target_pc]) as u8;
        out.push(ThreadedSlot {
            handler: table.handlers[usize::from(byte)] as *const (),
            slot: slot.with_offset(0).with_byte(taken_rest),
        });
        patches.push(BranchPatch {
            emit_idx,
            base_idx: emit_idx,
            target_pc,
            kind: PatchKind::CondDst {
                taken_rest,
                raw_slot: slot,
            },
        });
    } else if LAYOUTS[usize::from(byte)] == Layout::DstSrc && OpCode(bytes::usual(byte)).is_jump() {
        let taken_rest = rests.map_or(0, |r| r[target_pc]) as u8;
        let fall_rest = rests.map_or(0, |r| r[pc + 1]) as u8;
        out.push(ThreadedSlot {
            handler: table.handlers[usize::from(byte)] as *const (),
            slot: slot.to_threaded_dst_src_with_rests(0, taken_rest, fall_rest),
        });
        patches.push(BranchPatch {
            emit_idx,
            base_idx: emit_idx,
            target_pc,
            kind: PatchKind::CondDstSrc {
                taken_rest,
                fall_rest,
                raw_slot: slot,
            },
        });
    } else {
        out.push(emit_plain(slot, byte, table));
    }
}

fn emit_standalone_branch_or_call<M: Memory, H: Host<M>>(
    slot: Slot,
    byte: u8,
    pc: usize,
    out: &mut Vec<ThreadedSlot>,
    patches: &mut Vec<BranchPatch>,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> bool {
    let emit_idx = out.len();
    let opc = OpCode(byte);
    if byte == CALL {
        let off = i64::from(slot.instruction().imm());
        if (off + 1)
            .checked_mul(STRIDE)
            .and_then(|v| i32::try_from(v).ok())
            .is_some()
        {
            let target_pc = (pc as i64 + 1 + off) as usize;
            let rest = rests.map_or(0, |r| r[target_pc]);
            out.push(ThreadedSlot {
                handler: table.local_call_scaled as *const (),
                slot: Slot::scaled_jump(0, rest),
            });
            patches.push(BranchPatch {
                emit_idx,
                base_idx: emit_idx,
                target_pc,
                kind: PatchKind::LocalCallScaled { rest },
            });
            return true;
        }
        return false;
    }
    if matches!(opc.jmp_opc(), JmpOpc::Ja) && matches!(opc.source(), Source::Imm) {
        let off = match opc.class() {
            Class::Jmp64 => i64::from(slot.offset_raw()),
            Class::Jmp32 => i64::from(slot.imm()),
            _ => return false,
        };
        if (off + 1)
            .checked_mul(STRIDE)
            .and_then(|v| i32::try_from(v).ok())
            .is_some()
        {
            let target_pc = (pc as i64 + 1 + off) as usize;
            let rest = rests.map_or(0, |r| r[target_pc]);
            out.push(ThreadedSlot {
                handler: table.ja_scaled as *const (),
                slot: Slot::scaled_jump(0, rest),
            });
            patches.push(BranchPatch {
                emit_idx,
                base_idx: emit_idx,
                target_pc,
                kind: PatchKind::JaScaled { rest },
            });
            return true;
        }
        return false;
    }
    if is_cond_dst_jump(byte) {
        let target_pc = (pc as i64 + 1 + i64::from(slot.offset_raw())) as usize;
        let taken_rest = rests.map_or(0, |r| r[target_pc]);
        if let (Ok(_), Ok(taken_rest8)) =
            (i16::try_from((i32::from(slot.offset_raw()) + 1) * (STRIDE as i32)), u8::try_from(taken_rest))
        {
            out.push(ThreadedSlot {
                handler: table.handlers[usize::from(byte)] as *const (),
                slot: slot.with_offset(0).with_byte(taken_rest8),
            });
            patches.push(BranchPatch {
                emit_idx,
                base_idx: emit_idx,
                target_pc,
                kind: PatchKind::CondDst {
                    taken_rest: taken_rest8,
                    raw_slot: slot,
                },
            });
        } else {
            out.push(ThreadedSlot {
                handler: table.jump_unscaled as *const (),
                slot,
            });
        }
        return true;
    }
    if LAYOUTS[usize::from(byte)] == Layout::DstSrc && OpCode(bytes::usual(byte)).is_jump() {
        let target_pc = (pc as i64 + 1 + i64::from(slot.offset_raw())) as usize;
        let taken_rest = rests.map_or(0, |r| r[target_pc]);
        let fall_rest = rests.map_or(0, |r| r[pc + 1]);
        if let (Ok(taken_rest8), Ok(fall_rest8)) = (u8::try_from(taken_rest), u8::try_from(fall_rest)) {
            out.push(ThreadedSlot {
                handler: table.handlers[usize::from(byte)] as *const (),
                slot: slot.to_threaded_dst_src_with_rests(0, taken_rest8, fall_rest8),
            });
            patches.push(BranchPatch {
                emit_idx,
                base_idx: emit_idx,
                target_pc,
                kind: PatchKind::CondDstSrc {
                    taken_rest: taken_rest8,
                    fall_rest: fall_rest8,
                    raw_slot: slot,
                },
            });
        } else {
            out.push(ThreadedSlot {
                handler: table.jump_unscaled as *const (),
                slot,
            });
        }
        return true;
    }
    false
}

fn apply_patches<M: Memory, H: Host<M>>(
    out: &mut [ThreadedSlot],
    pc_to_idx: &[u32],
    patches: &[BranchPatch],
    table: &DispatchTable<M, H>,
) {
    for patch in patches {
        let target_idx = pc_to_idx[patch.target_pc];
        debug_assert_ne!(target_idx, NO_SLOT, "branch target {} must be a leader", patch.target_pc);
        let byte_off = (target_idx as i64 - patch.base_idx as i64) * STRIDE;
        let entry = &mut out[patch.emit_idx];
        match patch.kind {
            PatchKind::JaScaled { rest } | PatchKind::LocalCallScaled { rest } => {
                entry.slot = Slot::scaled_jump(byte_off as i32, rest);
            }
            PatchKind::CondDst { taken_rest, raw_slot } => {
                if let Ok(off16) = i16::try_from(byte_off) {
                    entry.slot = raw_slot.with_offset(off16).with_byte(taken_rest);
                } else {
                    entry.handler = table.jump_unscaled as *const ();
                    entry.slot = raw_slot;
                }
            }
            PatchKind::CondDstSrc {
                taken_rest,
                fall_rest,
                raw_slot,
            } => {
                if let Ok(off32) = i32::try_from(byte_off) {
                    entry.slot = raw_slot.to_threaded_dst_src_with_rests(off32, taken_rest, fall_rest);
                } else {
                    entry.handler = table.jump_unscaled as *const ();
                    entry.slot = raw_slot;
                }
            }
            PatchKind::MovJaImm => {
                let off16 = i16::try_from(byte_off).expect("compacted mov_ja_imm displacement fits in i16");
                entry.slot = entry.slot.with_offset(off16);
            }
            PatchKind::MovJaReg => {
                let s = entry.slot;
                entry.slot = Slot::pack(s.byte(), s.byte1(), s.offset_raw(), byte_off as i32);
            }
            PatchKind::LdxbJcc { taken_rest, fall_rest } => {
                let off16 = i16::try_from(byte_off).expect("compacted ldxb_jcc displacement fits in i16");
                let [bo0, bo1] = off16.to_le_bytes();
                let payload = i32::from_le_bytes([bo0, bo1, taken_rest, fall_rest]);
                let s = entry.slot;
                entry.slot = Slot::pack_bytes(s.byte(), s.byte1(), s.byte2(), s.byte3(), payload);
            }
        }
    }
}

// --- Shared plain-slot encoding helpers ---

#[inline(always)]
fn emit_plain<M: Memory, H: Host<M>>(slot: Slot, byte: u8, table: &DispatchTable<M, H>) -> ThreadedSlot {
    let handler = stack_access_override::<M, H>(slot, byte).unwrap_or(table.handlers[usize::from(byte)]) as *const ();
    ThreadedSlot {
        handler,
        slot: encode_threaded_slot(slot, byte),
    }
}

#[inline(always)]
fn encode_threaded_slot(slot: Slot, byte: u8) -> Slot {
    if LAYOUTS[usize::from(byte)] != Layout::DstSrc {
        return slot;
    }
    let usual = bytes::usual(byte);
    let extra = if OpCode(usual).is_jump() {
        (i32::from(slot.offset_raw()) + 1) * (STRIDE as i32)
    } else {
        i32::from(slot.offset_raw())
    };
    slot.to_threaded_dst_src(extra)
}

#[inline(always)]
fn scale_branch_or_call_1to1<M: Memory, H: Host<M>>(
    slot: Slot,
    byte: u8,
    i: usize,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<ThreadedSlot> {
    let opc = OpCode(byte);
    if byte == CALL {
        let off = i64::from(slot.instruction().imm());
        let byte_off = i32::try_from((off + 1).checked_mul(STRIDE)?).ok()?;
        let rest = rests.map_or(0, |r| r[(i as i64 + 1 + off) as usize]);
        return Some(ThreadedSlot {
            handler: table.local_call_scaled as *const (),
            slot: Slot::scaled_jump(byte_off, rest),
        });
    }
    if matches!(opc.jmp_opc(), JmpOpc::Ja) && matches!(opc.source(), Source::Imm) {
        let off = match opc.class() {
            Class::Jmp64 => i64::from(slot.offset_raw()),
            Class::Jmp32 => i64::from(slot.imm()),
            _ => return None,
        };
        let byte_off = i32::try_from((off + 1).checked_mul(STRIDE)?).ok()?;
        let rest = rests.map_or(0, |r| r[(i as i64 + 1 + off) as usize]);
        return Some(ThreadedSlot {
            handler: table.ja_scaled as *const (),
            slot: Slot::scaled_jump(byte_off, rest),
        });
    }
    None
}

#[inline(always)]
fn stack_access_override<M: Memory, H: Host<M>>(slot: Slot, byte: u8) -> Option<crate::dispatch::Handler<M, H>> {
    if !windows::windowed(byte) {
        return None;
    }
    let base = match OpCode(byte).class() {
        Class::Ldx => slot.src_reg_decoded(),
        _ => slot.dst_reg_decoded(),
    };
    (usize::from(base.get()) == FP)
        .then(|| windows::access_handler::<M, H>(byte, true))
        .flatten()
}
