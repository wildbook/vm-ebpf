//! Prepared code: [`Code`], the passes of [`Code::new`] that turn instructions into portable slots, and lazy
//! compilation into 16-byte direct-threaded [`ThreadedSlot`] streams with 3-operand ALU folding.

use std::fmt::{self, Debug, Formatter};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::bytes::{MOV32_REG, MOV64_REG};
use crate::context::FP;
use crate::dispatch::DispatchTable;
#[cfg(feature = "fuel")]
use crate::fuel::Rests;
use crate::handler::{CALL_HELPER, CALL_KFUNC};
#[cfg(feature = "ffi")]
use crate::native::GeneralProto;
use crate::native::{NativeBind, NativeMode};
use crate::opcode::{AluOpc, Class, JmpOpc, OpCode, Source, CALL};
use crate::promote::{self, PromotedRegion};
use crate::slot::{Layout, Slot, LAYOUTS};
use crate::{
    args, bytes, fuse, native, rewrite, threaded, transfer, windows, Host, Instruction, Memory, MAX_NATIVE_ARGS,
};

/// One entry of a direct-threaded code stream: the handler pointer and its 8-byte pre-decoded [`Slot`].
///
/// Kept at 16 bytes (`align(16)`) so `Ip::offset(n)` scales by 16, `pc_at` is a right shift by 4, and loading `slot`
/// into `RCX` runs in parallel with the memory-indirect tail jump through `handler`.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct ThreadedSlot {
    pub handler: *const (),
    pub slot: Slot,
}

const _: () = assert!(size_of::<ThreadedSlot>() == 16);

/// Fast lock-free cache slots for compiled threaded streams, keyed by static dispatch table address.
const CACHE_SLOTS: usize = 4;

struct CacheEntry {
    key: AtomicUsize,
    ptr: AtomicPtr<ThreadedSlot>,
}

impl CacheEntry {
    fn empty() -> Self {
        Self {
            key: AtomicUsize::new(0),
            ptr: AtomicPtr::new(ptr::null_mut()),
        }
    }
}

/// Lock-free cache of compiled [`ThreadedSlot`] streams for one [`Code`], keyed by `&DispatchTable` address.
struct CompiledCache {
    fast: [CacheEntry; CACHE_SLOTS],
    /// Serialises first-time compilation and holds any entries past [`CACHE_SLOTS`].
    overflow: Mutex<Vec<(usize, *mut ThreadedSlot)>>,
}

// SAFETY: compiled streams are immutable once published and owned exclusively by `Code` until dropped.
unsafe impl Send for CompiledCache {}
unsafe impl Sync for CompiledCache {}

impl Default for CompiledCache {
    fn default() -> Self {
        Self {
            fast: std::array::from_fn(|_| CacheEntry::empty()),
            overflow: Mutex::new(Vec::new()),
        }
    }
}

impl CompiledCache {
    /// Free all compiled streams, each of length `total_len`.
    fn clear(&mut self, total_len: usize) {
        for entry in &mut self.fast {
            let ptr = *entry.ptr.get_mut();
            *entry.key.get_mut() = 0;
            *entry.ptr.get_mut() = ptr::null_mut();
            if !ptr.is_null() {
                // SAFETY: `ptr` came from `Box::into_raw` on a slice of length `total_len`.
                drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, total_len)) });
            }
        }
        let overflow = self.overflow.get_mut().unwrap_or_else(|e| e.into_inner());
        for (_, ptr) in overflow.drain(..) {
            // SAFETY: as above.
            drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, total_len)) });
        }
    }
}

/// Bytecode prepared for an [`Interpreter`](crate::Interpreter).
pub struct Code {
    /// Portable slots, then the guard and moved instructions [`transfer::bound`] appends.
    slots: Box<[Slot]>,
    len: usize,
    /// Lazily compiled 16-byte direct-threaded streams per dispatch table (`PLAIN`, `METERED`, `FLAT_*`).
    compiled: CompiledCache,
    /// Non-escaping leaf functions eligible for stack-slot promotion to virtual registers.
    promoted: Box<[PromotedRegion]>,
    #[cfg(feature = "ffi")]
    general: Box<[GeneralProto]>,
    #[cfg(feature = "fuel")]
    rests: Rests,
}

impl Drop for Code {
    fn drop(&mut self) {
        self.compiled.clear(self.slots.len());
    }
}

impl Code {
    /// Prepare `insns`: fail what can't run, and fuse the sequences that have a superinstruction.
    ///
    /// r10 is read-only, so an instruction that would write it fails with
    /// [`Reason::InvalidInstruction`](crate::Reason::InvalidInstruction): an ALU, ALU64 or LDX instruction, LD_IMM64
    /// or a load-acquire with `dst_reg` 10, and an atomic that fetches into `src_reg` 10.
    ///
    /// An instruction that sets a field the kernel verifier reserves fails the same way, as the verifier rejects it
    /// (`check_insn_fields` and the LD_IMM64 check in `check_and_resolve_insns`, kernel/bpf/verifier.c):
    /// - `src_reg` of ALU operations and conditional jumps with an immediate, END, ST, `ja`, `gotox`, `callx` and
    ///   `exit`, and `dst_reg` of `ja`, `exit` and `call` with an immediate;
    /// - `offset` of ALU operations but DIV, MOD and `mov` from a register, of `gotox`, `callx`, JMP32 `ja`,
    ///   LD_IMM64, and `call` but a kfunc's;
    /// - `imm` of ALU operations but END and of conditional jumps from a register, of LDX, STX, NEG, JMP `ja`,
    ///   `gotox`, `callx` and `exit`;
    /// - NEG from a register, `call` with a `src_reg` other than 0, 1 and 2, and LD_IMM64 whose second slot holds
    ///   anything but the upper half of the immediate.
    ///
    /// The verifier accepts `exit` with `src_reg` 1, which unwinds; `Code::new` fails it, as it does `may_goto` with
    /// that `src_reg`.
    ///
    /// The code keeps the allocation of `insns` if it has room for one more slot.
    ///
    /// # Panics
    ///
    /// Panics if `insns` has 2^31 slots or more.
    pub fn new(insns: impl Into<Vec<Instruction>>) -> Self {
        // SAFETY: no native bindings
        unsafe { Self::with_natives(insns, &[]) }.expect("no native bindings")
    }

    /// [`Code::new`] with native call bindings applied before fusion.
    ///
    /// Each entry of `natives` binds the helper or kfunc `call` at `bind.pc` to `Host::natives()[bind.index]`. Fails
    /// with the offending `pc` if `bind.pc` is out of bounds, holds no helper or kfunc `call`, or `bind.args` exceeds
    /// [`MAX_NATIVE_ARGS`].
    ///
    /// # Safety
    ///
    /// For every run of this code, each bound `bind.index` in the host's `natives` must be callable as `bind.mode`
    /// invokes it (`unsafe extern "C" fn(u64, ...) -> u64` with `bind.args` arguments, or through `rvm_call_regs` for
    /// [`NativeMode::Raw`]), with a matching [`NativeSig`](crate::NativeSig), and sound for any argument values not
    /// checked by [`NativeMode::Checked`]. It must not unwind.
    pub unsafe fn with_natives(insns: impl Into<Vec<Instruction>>, natives: &[NativeBind]) -> Result<Self, usize> {
        let mut insns = insns.into();
        let len = insns.len();
        i32::try_from(len).expect("fewer than 2^31 slots");

        rewrite::rewrite(&mut insns);
        #[cfg(feature = "ffi")]
        let mut general: Vec<GeneralProto> = Vec::new();
        for &bind in natives {
            let Some(insn) = insns.get_mut(bind.pc) else {
                return Err(bind.pc);
            };
            let args = usize::from(bind.args);
            let unlimited = matches!(bind.mode, NativeMode::Raw);
            #[cfg(feature = "ffi")]
            let unlimited = unlimited || matches!(bind.mode, NativeMode::General(_));
            if !matches!(insn.byte(), CALL_HELPER | CALL_KFUNC) || (!unlimited && args > MAX_NATIVE_ARGS) {
                return Err(bind.pc);
            }
            let byte = native::byte(args, bind.mode);
            let offset = match bind.mode {
                #[cfg(feature = "ffi")]
                NativeMode::General(proto) => {
                    let idx = match general.iter().position(|existing| existing == &proto) {
                        Some(idx) => idx,
                        None => {
                            let idx = general.len();
                            if idx > usize::from(u16::MAX) {
                                return Err(bind.pc);
                            }
                            general.push(proto);
                            idx
                        }
                    };
                    idx as u16 as i16
                }
                _ => 0,
            };
            *insn = Instruction::new(OpCode(byte), 0, 0, offset, bind.index as i32);
        }
        fuse::fuse(&mut insns);
        transfer::bound(&mut insns);

        // in place, as `Slot` and `Instruction` have the same size and alignment
        let slots: Vec<Slot> = insns.into_iter().map(Slot::new).collect();
        let promoted = promote::analyze(&slots, len);
        Ok(Self {
            slots: slots.into_boxed_slice(),
            len,
            compiled: CompiledCache::default(),
            promoted,
            #[cfg(feature = "ffi")]
            general: general.into_boxed_slice(),
            #[cfg(feature = "fuel")]
            rests: Rests::default(),
        })
    }

    /// The number of instruction slots.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Make the kfunc `call` in slot `pc` pass the stack arguments of its frame to the host, which then runs it in
    /// [`Host::call_kfunc_stack`](crate::Host::call_kfunc_stack).
    ///
    /// Returns false and leaves the code as it is if slot `pc` holds no kfunc `call`.
    pub fn pass_stack_args(&mut self, pc: usize) -> bool {
        let Some(slot) = self.slots[..self.len].get_mut(pc) else {
            return false;
        };
        if slot.byte() != CALL_KFUNC {
            return false;
        }
        let insn = slot.instruction();
        *slot = Slot::new(insn.with_byte(args::CALL));
        self.compiled.clear(self.slots.len());
        true
    }

    /// Whether slot `pc` holds a `call` that [`pass_stack_args`](Self::pass_stack_args) marked.
    pub fn passes_stack_args(&self, pc: u64) -> bool {
        self.raw_slot(pc).is_some_and(|slot| slot.byte() == args::CALL)
    }

    /// Bytes the load or store in slot `pc` accesses, or `None` if the slot holds none, for reporting a
    /// [`Reason::MemoryFault`](crate::Reason::MemoryFault) at `pc`.
    #[cold]
    pub fn access_size(&self, pc: u64) -> Option<usize> {
        let opc = OpCode(bytes::usual(self.raw_slot(pc)?.byte()));
        opc.is_access().then(|| opc.mem_size().bytes())
    }

    /// Portable slot at `pc`, if in bounds of `self.slots`.
    #[inline(always)]
    pub(crate) fn raw_slot(&self, pc: u64) -> Option<Slot> {
        self.slots.get(pc as usize).copied()
    }

    /// All portable slots, including the guard and moved instructions behind it.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub(crate) fn raw_slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Non-escaping leaf functions eligible for stack-slot promotion.
    #[inline(always)]
    pub(crate) fn promoted(&self) -> &[PromotedRegion] {
        &self.promoted
    }

    /// Promoted region containing `pc`, if any.
    #[inline(always)]
    pub(crate) fn promoted_at(&self, pc: u64) -> Option<&PromotedRegion> {
        for region in &self.promoted {
            let start = u64::from(region.start);
            let end = u64::from(region.end);
            if pc >= start && pc < end {
                return Some(region);
            }
        }
        None
    }

    /// The direct-threaded [`Slots`] for `table`, compiling and caching them on first use.
    #[inline(always)]
    pub(crate) fn threaded<M: Memory, H: Host<M>>(&self, table: &DispatchTable<M, H>) -> Slots<'_> {
        self.threaded_by_key(ptr::from_ref(table).addr(), table)
    }

    /// The direct-threaded [`Slots`] for `table` with stack-slot promotion applied to [`Self::promoted`].
    #[inline(always)]
    pub(crate) fn threaded_promoted<M: Memory, H: Host<M>>(&self, table: &DispatchTable<M, H>) -> Slots<'_> {
        self.threaded_by_key(ptr::from_ref(table).addr() | 1, table)
    }

    #[inline(always)]
    fn threaded_by_key<M: Memory, H: Host<M>>(&self, key: usize, table: &DispatchTable<M, H>) -> Slots<'_> {
        let first = if self.compiled.fast[0].key.load(Ordering::Acquire) == key {
            self.compiled.fast[0].ptr.load(Ordering::Relaxed)
        } else if self.compiled.fast[1].key.load(Ordering::Acquire) == key {
            self.compiled.fast[1].ptr.load(Ordering::Relaxed)
        } else {
            self.compile_or_find(key, table)
        };
        Slots { first, code: self }
    }

    #[cold]
    #[inline(never)]
    fn compile_or_find<M: Memory, H: Host<M>>(&self, key: usize, table: &DispatchTable<M, H>) -> *const ThreadedSlot {
        for entry in &self.compiled.fast[2..] {
            if entry.key.load(Ordering::Acquire) == key {
                return entry.ptr.load(Ordering::Relaxed);
            }
        }

        let mut overflow = self.compiled.overflow.lock().expect("compile cache lock");
        for entry in &self.compiled.fast {
            if entry.key.load(Ordering::Acquire) == key {
                return entry.ptr.load(Ordering::Relaxed);
            }
        }
        if let Some(&(_, ptr)) = overflow.iter().find(|&&(k, _)| k == key) {
            return ptr;
        }

        let promote = (key & 1 != 0).then_some(self.promoted.as_ref());
        #[cfg(feature = "fuel")]
        let rests = table.metered.then(|| self.rests.slice(&self.slots));
        #[cfg(not(feature = "fuel"))]
        let rests: Option<&[u32]> = None;
        let compiled = compile_threaded(&self.slots, self.len, table, promote, rests);
        let ptr = Box::into_raw(compiled).cast::<ThreadedSlot>();
        for entry in &self.compiled.fast {
            if entry.key.load(Ordering::Relaxed) == 0 {
                entry.ptr.store(ptr, Ordering::Relaxed);
                entry.key.store(key, Ordering::Release);
                return ptr;
            }
        }
        overflow.push((key, ptr));
        ptr
    }

    /// The `rest` of each slot, which metered runs read.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub(crate) fn rests(&self) -> &Rests {
        &self.rests
    }
}

/// Compile portable slots into a 16-byte direct-threaded stream:
/// - folds `mov dst, src1; alu dst, rhs` into single 3-operand ALU entries (leaving slot `i + 1` intact for mid-pair
///   jump targets);
/// - re-encodes [`Layout::DstSrc`] slots so `dst`, `src`, and `offset` (or pre-scaled jump byte offset) decode from
///   `RCX` with no extra code-stream loads;
/// - pre-scales unconditional `ja` and local `call` displacements into byte offsets;
/// - routes all plain `r10` loads/stores (including 1- and 2-byte) to `windows::stack_access`.
fn compile_threaded<M: Memory, H: Host<M>>(
    raw_slots: &[Slot],
    len: usize,
    table: &DispatchTable<M, H>,
    promote: Option<&[PromotedRegion]>,
    rests: Option<&[u32]>,
) -> Box<[ThreadedSlot]> {
    let rewritten;
    let slots: &[Slot] = match promote {
        Some(regions) if !regions.is_empty() => {
            let mut buf = raw_slots.to_vec();
            for region in regions {
                let start = region.start as usize;
                let end = region.end as usize;
                let patched = promote::rewrite_region(raw_slots, region);
                buf[start..end].copy_from_slice(&patched);
            }
            rewritten = buf;
            &rewritten
        }
        _ => raw_slots,
    };
    const STRIDE: i64 = size_of::<ThreadedSlot>() as i64;
    let mut out = Vec::with_capacity(slots.len());
    // Slots inside an active superinstruction must keep their opcode's threaded layout intact because `fuse::handler`
    // reads `sequence[1..sup.len()]` directly from the threaded stream.
    let mut protected_until = 0usize;
    for i in 0..slots.len() {
        let slot = slots[i];
        let byte = slot.byte();
        if let Some(sup) = fuse::Super::with_byte(byte) {
            let branch_fits = if sup.branches() {
                let last_pc = i + sup.len() - 1;
                let last = slots[last_pc];
                let lb = last.byte();
                let target_pc = (last_pc as i64 + 1 + i64::from(last.offset_raw())) as usize;
                let fall_ok = rests.is_none_or(|r| r[last_pc + 1] <= u32::from(u8::MAX));
                if crate::handler::is_cond_dst_jump(lb) {
                    fall_ok
                        && i16::try_from((i32::from(last.offset_raw()) + 1) * (STRIDE as i32)).is_ok()
                        && rests.is_none_or(|r| r[target_pc] <= u32::from(u8::MAX))
                } else if LAYOUTS[usize::from(lb)] == Layout::DstSrc {
                    fall_ok && rests.is_none_or(|r| r[target_pc] <= u32::from(u8::MAX))
                } else {
                    fall_ok
                }
            } else {
                true
            };
            if branch_fits {
                protected_until = protected_until.max(i + sup.len());
                let encoded = if sup.branches() {
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
                out.push(ThreadedSlot {
                    handler: table.handlers[usize::from(byte)] as *const (),
                    slot: encoded,
                });
                continue;
            }
            let first_byte = sup.opcode(0);
            let unfused = slot.with_byte(first_byte);
            let handler = stack_access_override::<M, H>(unfused, first_byte)
                .unwrap_or(table.handlers[usize::from(first_byte)]) as *const ();
            out.push(ThreadedSlot {
                handler,
                slot: encode_threaded_slot(unfused, first_byte),
            });
            continue;
        }
        if i >= protected_until {
            if let Some(folded) = threaded::try_fold(slots, i, len, table, rests) {
                out.push(folded);
                continue;
            }
            if i + 1 < len {
                if let Some(folded) = fold_alu3(slot, slots[i + 1], table) {
                    out.push(folded);
                    continue;
                }
            }
            if i < len {
                if let Some(scaled) = scale_branch_or_call(slot, byte, i, STRIDE, table, rests) {
                    out.push(scaled);
                    continue;
                }
            }
        }
        if i < len && crate::handler::is_cond_dst_jump(byte) {
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
        if i < len && LAYOUTS[usize::from(byte)] == Layout::DstSrc && OpCode(bytes::usual(byte)).is_jump() {
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
        let handler =
            stack_access_override::<M, H>(slot, byte).unwrap_or(table.handlers[usize::from(byte)]) as *const ();
        out.push(ThreadedSlot {
            handler,
            slot: encode_threaded_slot(slot, byte),
        });
    }
    out.into_boxed_slice()
}

/// Re-encode a portable `slot` into the threaded layout of `byte`.
#[inline(always)]
fn encode_threaded_slot(slot: Slot, byte: u8) -> Slot {
    if LAYOUTS[usize::from(byte)] != Layout::DstSrc {
        return slot;
    }
    let usual = bytes::usual(byte);
    let extra = if OpCode(usual).is_jump() {
        (i32::from(slot.offset_raw()) + 1) * (size_of::<ThreadedSlot>() as i32)
    } else {
        i32::from(slot.offset_raw())
    };
    slot.to_threaded_dst_src(extra)
}

/// Pre-scale unconditional `ja` (`0x05`/`0x06`) and local `call` into a single byte-offset slot when it fits in `i32`.
#[inline(always)]
fn scale_branch_or_call<M: Memory, H: Host<M>>(
    slot: Slot,
    byte: u8,
    i: usize,
    stride: i64,
    table: &DispatchTable<M, H>,
    rests: Option<&[u32]>,
) -> Option<ThreadedSlot> {
    let opc = OpCode(byte);
    if byte == CALL {
        let off = i64::from(slot.instruction().imm());
        let byte_off = i32::try_from((off + 1).checked_mul(stride)?).ok()?;
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
        let byte_off = i32::try_from((off + 1).checked_mul(stride)?).ok()?;
        let rest = rests.map_or(0, |r| r[(i as i64 + 1 + off) as usize]);
        return Some(ThreadedSlot {
            handler: table.ja_scaled as *const (),
            slot: Slot::scaled_jump(byte_off, rest),
        });
    }
    None
}

/// Route plain 1- and 2-byte `r10` loads/stores (which don't have dedicated opcode bytes) straight to `stack_access`.
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

/// Fold `mov32/64 dst, src1; alu32/64 dst, rhs` into one 3-operand [`ThreadedSlot`].
#[inline(always)]
fn fold_alu3<M: Memory, H: Host<M>>(first: Slot, second: Slot, table: &DispatchTable<M, H>) -> Option<ThreadedSlot> {
    let mov64 = match first.byte() {
        MOV64_REG => true,
        MOV32_REG => false,
        _ => return None,
    };
    let op_byte = second.byte();
    let opc = OpCode(op_byte);
    let alu64 = match opc.class() {
        Class::Alu64 => {
            if !mov64 {
                return None;
            }
            true
        }
        Class::Alu32 => false,
        _ => return None,
    };
    let op_idx = match opc.alu_opc() {
        AluOpc::Add => 0,
        AluOpc::Sub => 1,
        AluOpc::Mul => 2,
        AluOpc::Or => 3,
        AluOpc::And => 4,
        AluOpc::Xor => 5,
        AluOpc::Lsh => 6,
        AluOpc::Rsh => 7,
        AluOpc::Arsh => 8,
        _ => return None,
    };

    let dst = first.dst_reg_decoded();
    if second.dst_reg_decoded() != dst {
        return None;
    }
    let src1 = first.src_reg_decoded();

    let (handler, slot) = match opc.source() {
        Source::Imm => {
            let h = table.alu3.imm[usize::from(alu64)][op_idx];
            (h as *const (), Slot::alu3_imm(dst, src1, second.imm()))
        }
        Source::Reg => {
            let mut src2 = second.src_reg_decoded();
            if src2 == dst {
                src2 = src1;
            }
            let h = table.alu3.reg[usize::from(alu64)][op_idx];
            (h as *const (), Slot::alu3_reg(dst, src1, src2))
        }
    };
    Some(ThreadedSlot { handler, slot })
}

impl Debug for Code {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("slots", &self.slots)
            .field("len", &self.len)
            .finish()
    }
}

/// The direct-threaded slots of a [`Code`] as handlers receive them: the pointer to the first [`ThreadedSlot`], and
/// the code, for handlers that check a pc or read metadata. They take two registers.
#[derive(Clone, Copy)]
pub struct Slots<'a> {
    /// Base pointer of the active compiled [`ThreadedSlot`] stream.
    first: *const ThreadedSlot,
    code: &'a Code,
}

impl<'a> Slots<'a> {
    /// The pointer to the first threaded slot, valid while the code is borrowed.
    #[inline(always)]
    pub fn first(self) -> *const ThreadedSlot {
        self.first
    }

    /// The code these slots belong to.
    #[inline(always)]
    pub fn code(self) -> &'a Code {
        self.code
    }

    /// The number of instruction slots, excluding the guard and moved instructions behind it.
    #[inline(always)]
    pub fn len(self) -> usize {
        self.code.len
    }

    /// Total number of slots including the guard and moved instructions behind it.
    #[inline(always)]
    pub fn total_len(self) -> usize {
        self.code.slots.len()
    }

    /// Portable slot at `pc`, if in bounds.
    #[inline(always)]
    pub fn raw_slot(self, pc: u64) -> Option<Slot> {
        self.code.raw_slot(pc)
    }

    /// All portable slots.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub fn raw_slots(self) -> &'a [Slot] {
        &self.code.slots
    }

    /// The pc of the threaded slot at address `addr`, which lies in this stream.
    #[inline(always)]
    pub fn pc_at(self, addr: usize) -> u64 {
        ((addr - self.first.addr()) / size_of::<ThreadedSlot>()) as u64
    }

    /// The [`GeneralProto`] at `index` recorded by [`Code::with_natives`].
    #[cfg(feature = "ffi")]
    #[inline(always)]
    pub fn general(self, index: u16) -> &'a GeneralProto {
        // SAFETY: `index` came from a `GENERAL` slot written by `Code::with_natives`
        unsafe { self.code.general.get_unchecked(usize::from(index)) }
    }

    /// The `rest` of each slot, which metered runs read.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub fn rests(self) -> &'a Rests {
        &self.code.rests
    }
}
