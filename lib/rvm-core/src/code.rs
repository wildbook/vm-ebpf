//! Prepared code: [`Code`], the passes of [`Code::new`] that turn instructions into portable slots, and lazy
//! compilation into compacted 16-byte direct-threaded [`ThreadedSlot`] streams.

use std::fmt::{self, Debug, Formatter};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::dispatch::DispatchTable;
#[cfg(feature = "fuel")]
use crate::fuel::Rests;
use crate::fuel::RestsPtr;
use crate::handler::{CALL_HELPER, CALL_KFUNC};
#[cfg(feature = "ffi")]
use crate::native::GeneralProto;
use crate::native::{NativeBind, NativeMode};
use crate::opcode::OpCode;
use crate::promote::{self, PromotedRegion};
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{args, bytes, compile, fuse, native, rewrite, transfer, Host, Instruction, Memory, MAX_NATIVE_ARGS};

/// One entry of a direct-threaded code stream: the handler pointer and its 8-byte pre-decoded [`Slot`].
///
/// Kept at 16 bytes (`align(16)`) so `Ip::offset(n)` scales by 16, `slot_idx` is a right shift by 4, and loading
/// `slot` into `RCX` runs in parallel with the memory-indirect tail jump through `handler`.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct ThreadedSlot {
    pub handler: *const (),
    pub slot: Slot,
}

const _: () = assert!(size_of::<ThreadedSlot>() == 16);

/// Sentinel in [`StreamMaps::pc_to_idx`] for an original BPF pc that was folded or eliminated mid-block.
pub const NO_SLOT: u32 = u32::MAX;

/// Cold side tables mapping between compacted threaded slot indices and original BPF pcs.
pub struct StreamMaps {
    /// Original BPF pc (`0..total_len`) to compacted slot index, or [`NO_SLOT`] if compacted away mid-block.
    pub pc_to_idx: Box<[u32]>,
    /// Compacted slot index (`0..slot_count`) to original BPF pc.
    pub idx_to_pc: Box<[u32]>,
    /// Per-compacted-slot block length for metered runs (empty when unmetered).
    #[cfg(feature = "fuel")]
    pub idx_rests: Box<[u32]>,
}

/// Owned compiled direct-threaded stream and its cold PC/fuel mapping tables.
///
/// `base[0].handler` stores `maps` and `base[0].slot` stores `maps.idx_to_pc.as_ptr()` while `base[1..len]` holds the
/// executable [`ThreadedSlot`] stream. Stored as raw pointers from `Box::into_raw` so moving `CompiledStream` inside
/// [`CompiledCache`] never retags the allocations.
pub struct CompiledStream {
    base: *mut ThreadedSlot,
    len: usize,
    maps: *mut StreamMaps,
}

// SAFETY: compiled streams and their maps are immutable once published and owned exclusively by `Code` until dropped.
unsafe impl Send for CompiledStream {}
unsafe impl Sync for CompiledStream {}

const _: () = assert!(size_of::<(*const StreamMaps, *const u32)>() == size_of::<ThreadedSlot>());

impl CompiledStream {
    pub fn new(slots: Vec<ThreadedSlot>, maps: StreamMaps) -> Self {
        let is_identity = maps.idx_to_pc.iter().enumerate().all(|(i, &pc)| pc as usize == i);
        let maps = Box::into_raw(Box::new(maps));
        // SAFETY: `maps` is live and will not be moved again until `Drop`.
        let idx_to_pc_ptr = if is_identity {
            ptr::null()
        } else {
            unsafe { (*maps).idx_to_pc.as_ptr() }
        };
        let mut buf = Vec::with_capacity(1 + slots.len());
        buf.push(ThreadedSlot {
            handler: ptr::null(),
            slot: Slot::UNREAD,
        });
        buf.extend(slots);
        let len = buf.len();
        let base = Box::into_raw(buf.into_boxed_slice()).cast::<ThreadedSlot>();
        // SAFETY: `base[0]` is 16-byte aligned and 16 bytes wide, matching `(*const StreamMaps, *const u32)`.
        unsafe {
            base.cast::<(*const StreamMaps, *const u32)>()
                .write((maps, idx_to_pc_ptr));
        }
        Self { base, len, maps }
    }

    /// Pointer to `base[1]`, the first executable [`ThreadedSlot`], keeping provenance over `base[0]`.
    #[inline(always)]
    pub fn first(&self) -> *const ThreadedSlot {
        // SAFETY: `new` always inserts the header at `base[0]`, so `base.add(1)` is in bounds.
        unsafe { self.base.add(1) }
    }
}

impl Drop for CompiledStream {
    fn drop(&mut self) {
        // SAFETY: `new` produced `base` from `Box::into_raw` with length `self.len`, and `maps` from `Box::into_raw`.
        unsafe {
            drop(Box::from_raw(ptr::slice_from_raw_parts_mut(self.base, self.len)));
            drop(Box::from_raw(self.maps));
        }
    }
}

/// Fast lock-free cache slots for compiled threaded streams, keyed by dispatch table address and mode bits.
const CACHE_SLOTS: usize = 4;

/// Mode tag bits ORed into the aligned `&DispatchTable` key.
const KEY_PROMOTED: usize = 1;
const KEY_UNCOMPACTED: usize = 2;

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

#[derive(Default)]
struct CacheOverflow {
    entries: Vec<(usize, *const ThreadedSlot)>,
    owned: Vec<CompiledStream>,
}

/// Lock-free cache of compiled [`CompiledStream`]s for one [`Code`], keyed by `&DispatchTable` address and mode bits.
struct CompiledCache {
    fast: [CacheEntry; CACHE_SLOTS],
    /// Serialises first-time compilation, owns every [`CompiledStream`], and holds keys past [`CACHE_SLOTS`].
    overflow: Mutex<CacheOverflow>,
}

// SAFETY: compiled streams are immutable once published and owned exclusively by `Code` until dropped.
unsafe impl Send for CompiledCache {}
unsafe impl Sync for CompiledCache {}

impl Default for CompiledCache {
    fn default() -> Self {
        Self {
            fast: std::array::from_fn(|_| CacheEntry::empty()),
            overflow: Mutex::new(CacheOverflow::default()),
        }
    }
}

impl CompiledCache {
    fn clear(&mut self) {
        for entry in &mut self.fast {
            *entry.key.get_mut() = 0;
            *entry.ptr.get_mut() = ptr::null_mut();
        }
        let overflow = self.overflow.get_mut().unwrap_or_else(|e| e.into_inner());
        overflow.entries.clear();
        overflow.owned.clear();
    }
}

/// Bytecode prepared for an [`Interpreter`](crate::Interpreter).
pub struct Code {
    /// Portable slots, then the guard and moved instructions [`transfer::bound`] appends.
    slots: Box<[Slot]>,
    len: usize,
    /// Lazily compiled 16-byte direct-threaded streams per dispatch table and mode.
    compiled: CompiledCache,
    /// Non-escaping leaf functions eligible for stack-slot promotion to virtual registers.
    promoted: Box<[PromotedRegion]>,
    #[cfg(feature = "ffi")]
    general: Box<[GeneralProto]>,
    #[cfg(feature = "fuel")]
    rests: Rests,
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
        self.compiled.clear();
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

    /// The compacted direct-threaded [`Slots`] for `table`, compiling and caching them on first use.
    #[inline(always)]
    pub(crate) fn threaded<M: Memory, H: Host<M>>(&self, table: &DispatchTable<M, H>) -> Slots<'_> {
        self.threaded_by_key(ptr::from_ref(table).addr(), table)
    }

    /// The compacted direct-threaded [`Slots`] for `table` with stack-slot promotion applied to [`Self::promoted`].
    #[inline(always)]
    pub(crate) fn threaded_promoted<M: Memory, H: Host<M>>(&self, table: &DispatchTable<M, H>) -> Slots<'_> {
        self.threaded_by_key(ptr::from_ref(table).addr() | KEY_PROMOTED, table)
    }

    /// The 1:1 uncompacted fallback [`Slots`] for `table`, used on promoted bailout or mid-block indirect entry.
    #[cold]
    #[inline(never)]
    pub(crate) fn threaded_uncompacted<M: Memory, H: Host<M>>(&self, table: &DispatchTable<M, H>) -> Slots<'_> {
        self.threaded_by_key(ptr::from_ref(table).addr() | KEY_UNCOMPACTED, table)
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
        if let Some(&(_, ptr)) = overflow.entries.iter().find(|&&(k, _)| k == key) {
            return ptr;
        }

        #[cfg(feature = "fuel")]
        let rests = table.metered.then(|| self.rests.slice(&self.slots));
        #[cfg(not(feature = "fuel"))]
        let rests: Option<&[u32]> = None;

        let stream = if key & KEY_UNCOMPACTED != 0 {
            compile::compile_uncompacted(&self.slots, self.len, table, rests)
        } else {
            let promote = (key & KEY_PROMOTED != 0).then_some(self.promoted.as_ref());
            compile::compile_compacted(&self.slots, self.len, table, promote, rests)
        };
        let first = stream.first();
        overflow.owned.push(stream);

        for entry in &self.compiled.fast {
            if entry.key.load(Ordering::Relaxed) == 0 {
                entry.ptr.store(first.cast_mut(), Ordering::Relaxed);
                entry.key.store(key, Ordering::Release);
                return first;
            }
        }
        overflow.entries.push((key, first));
        first
    }

    /// The `rest` of each slot, which metered runs read.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub(crate) fn rests(&self) -> &Rests {
        &self.rests
    }
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
    /// Base pointer of the active compiled [`ThreadedSlot`] stream (`buf[1]`, with `&StreamMaps` in `buf[0].handler`).
    first: *const ThreadedSlot,
    code: &'a Code,
}

impl<'a> Slots<'a> {
    /// Pointer to the first executable [`ThreadedSlot`] (`pc == 0`).
    #[inline(always)]
    pub fn first_ip(self) -> Ip {
        Ip(self.first)
    }

    /// The cold mapping tables for the active compiled stream.
    #[inline(always)]
    fn maps(self) -> &'a StreamMaps {
        // SAFETY: `self.first` points to `base[1]` of a live `CompiledStream` whose `base[0]` holds `(maps, idx_to_pc)`.
        unsafe { &*(*self.first.sub(1).cast::<(*const StreamMaps, *const u32)>()).0 }
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

    /// Total number of portable slots including the guard and moved instructions behind it.
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

    /// Compacted slot index for an address `addr` lying in this stream.
    #[inline(always)]
    pub fn slot_idx(self, addr: usize) -> usize {
        (addr - self.first.addr()) / size_of::<ThreadedSlot>()
    }

    /// Original BPF pc of the threaded slot at address `addr`, which lies in this stream.
    #[inline(always)]
    pub fn pc_at(self, addr: usize) -> u64 {
        let idx = self.slot_idx(addr);
        // SAFETY: `base[0]` holds `(maps, idx_to_pc_ptr)`, null when `idx_to_pc` is the identity mapping.
        let ptr = unsafe { (*self.first.sub(1).cast::<(*const StreamMaps, *const u32)>()).1 };
        if ptr.is_null() {
            idx as u64
        } else {
            // SAFETY: `idx < idx_to_pc.len()` for any slot address in this stream.
            u64::from(unsafe { *ptr.add(idx) })
        }
    }

    /// Resolve an original BPF `pc` (`< total_len`) to its [`Ip`] in this stream, or `None` if compacted away.
    #[inline(always)]
    pub fn ip_at(self, pc: u64) -> Option<Ip> {
        let idx = *self.maps().pc_to_idx.get(pc as usize)?;
        (idx != NO_SLOT).then(|| Ip(self.first.wrapping_add(idx as usize)))
    }

    /// Resolve an original BPF `pc` known to be a valid slot boundary in this stream.
    #[inline(always)]
    pub fn ip_at_unchecked(self, pc: u64) -> Ip {
        let idx = self.maps().pc_to_idx[pc as usize];
        debug_assert_ne!(idx, NO_SLOT, "expected block leader or uncompacted pc {pc}");
        Ip(self.first.wrapping_add(idx as usize))
    }

    /// Pointer to the per-compacted-slot `rest` array for metered runs, or [`RestsPtr::NULL`] when unmetered.
    #[inline(always)]
    pub fn rests_ptr(self) -> RestsPtr {
        #[cfg(feature = "fuel")]
        {
            let rests = &self.maps().idx_rests;
            if rests.is_empty() {
                RestsPtr::NULL
            } else {
                RestsPtr(rests.as_ptr())
            }
        }
        #[cfg(not(feature = "fuel"))]
        {
            RestsPtr::NULL
        }
    }

    /// The [`GeneralProto`] at `index` recorded by [`Code::with_natives`].
    #[cfg(feature = "ffi")]
    #[inline(always)]
    pub fn general(self, index: u16) -> &'a GeneralProto {
        // SAFETY: `index` came from a `GENERAL` slot written by `Code::with_natives`
        unsafe { self.code.general.get_unchecked(usize::from(index)) }
    }

    /// The `rest` of each portable slot, which metered runs read on cold paths.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub fn rests(self) -> &'a Rests {
        &self.code.rests
    }
}
