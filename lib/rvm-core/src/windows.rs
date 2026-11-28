//! Loads and stores that skip the [`Memory`] methods.
//!
//! The handlers here check the address of a plain `ldx`, `stx` or `st` against a [`Window`] that the memory reported
//! and access the host memory directly. An address outside the windows takes the usual handler of the instruction, so
//! the access behaves exactly as it does there.
//!
//! - [`stack_access`] runs the 4 and 8 byte accesses with base register r10, which [`Code::new`](crate::Code::new)
//!   gives an opcode byte of their own. It checks the window around r10. Guest code can't write r10, so it stays in
//!   the stack, inside the window of the stack.
//! - [`data_access`] runs the accesses through any other register, and those of 1 and 2 bytes through r10, which keep
//!   their opcode byte ([`install`]). It checks the window around the last address of its size class that missed (1
//!   and 2 byte accesses also the one before) and then, for pointers into the stack, the window around r10.
//! - [`data_step`] runs the accesses of superinstructions: those through r10 in the window around r10, the others in
//!   the data window of their size class. A superinstruction continues unfused at an access that misses it.

use std::num::NonZeroU8;
use std::ptr;

use crate::code::Slots;
use crate::context::FP;
use crate::dispatch::{Handler, Spare, SPARE};
use crate::fuel::RestsPtr;
use crate::handler::handler;
use crate::memory::Window;
use crate::opcode::{Class, MemMode, MemSize, OpCode};
use crate::promote::PROMOTE_FRAME;
use crate::slot::{Fields, Reg, Shape, Slot, View};
use crate::step::{self, Regs};
use crate::transfer::Ip;
use crate::{Context, Host, Instruction, Interpreter, Memory, Reason};

/// The windows that [`stack_access`] and [`data_access`] check addresses against, kept in the [`Interpreter`].
///
/// Each cache that isn't empty holds a window of epoch `epoch`, which [`Windows::take`] ensures. The interpreter calls
/// [`Windows::revalidate`] whenever code outside the chain of handlers may have changed the memory, and the methods of
/// [`Memory`] leave its epoch alone, so inside the chain the memory is at `epoch` whenever a cache isn't empty.
#[repr(C)]
pub struct Windows {
    /// The window around r10.
    stack: Cache,
    /// The window around the last address that a 4 or 8 byte [`data_access`] found in no window.
    data: Cache,
    /// The window around the last address that a 1 or 2 byte [`data_access`] found in no window.
    small: Cache,
    /// The window `small` held before.
    spare: Cache,
    /// 0 while all caches are empty.
    epoch: u64,
}

/// A [`Window`] as the handlers check it.
// `repr(C)` keeps `base`, `bias` and the 4/8 byte `fits` entries first so every `stack_access` handler reaches all of
// them within one-byte displacement of `Interpreter`.
#[repr(C)]
struct Cache {
    base: u64,
    /// `window.ptr.expose_provenance().wrapping_sub(base)`, so `addr + bias` gives the host address in parallel with
    /// the bounds check `addr - base`.
    bias: usize,
    /// By [`kind`]: the number of offsets from `base` at which the access fits in the window. All 0 when empty.
    fits: [u64; 8],
}

impl Windows {
    pub const EMPTY: Self = Self {
        stack: Cache::EMPTY,
        data: Cache::EMPTY,
        small: Cache::EMPTY,
        spare: Cache::EMPTY,
        epoch: 0,
    };

    /// Host address of `fp` (`r10`) when `[fp - PROMOTE_FRAME .. fp)` lies inside the RW stack window, else `0`.
    #[inline(always)]
    pub fn stack_fp_host(&self, fp: u64) -> usize {
        if fp < PROMOTE_FRAME {
            return 0;
        }
        // `fits[4]` holds `read_len` and `fits[6]` holds `write_len` (1-byte accesses).
        let rw_len = self.stack.fits[4].min(self.stack.fits[6]);
        let limit = rw_len.saturating_sub(PROMOTE_FRAME - 1);
        let at = fp.wrapping_sub(self.stack.base);
        if at.wrapping_sub(PROMOTE_FRAME) < limit {
            (fp as usize).wrapping_add(self.stack.bias)
        } else {
            0
        }
    }

    /// Populate the stack window around `addr` when empty or stale.
    #[inline(never)]
    pub fn take_stack<M: Memory>(&mut self, memory: &M, addr: u64) {
        self.take::<M, false>(memory, addr, MemSize::DWord);
    }

    /// Clear any cached data window whose address span overlaps `[lo .. hi)`.
    #[inline(always)]
    pub fn clear_overlapping(&mut self, lo: u64, hi: u64) {
        if self.data.overlaps(lo, hi) {
            self.data = Cache::EMPTY;
        }
        if self.small.overlaps(lo, hi) {
            self.small = Cache::EMPTY;
        }
        if self.spare.overlaps(lo, hi) {
            self.spare = Cache::EMPTY;
        }
    }

    /// Install a data window around `addr` only if it is non-empty and disjoint from `[lo .. hi)`.
    /// Returns `true` if the caller must bail out of promoted mode (empty or overlapping window).
    #[cold]
    #[inline(never)]
    pub fn take_checked<M: Memory>(&mut self, memory: &M, addr: u64, size: MemSize, lo: u64, hi: u64) -> bool {
        self.revalidate(memory);
        let window = memory.window(addr);
        if window.epoch == 0 || window.epoch != memory.epoch() {
            return true;
        }
        let span = window.read_len.max(window.write_len);
        if range_overlaps(window.base, span, lo, hi) {
            return true;
        }
        self.epoch = window.epoch;
        let cache = match small(size) {
            true => {
                self.spare = std::mem::replace(&mut self.small, Cache::EMPTY);
                &mut self.small
            }
            false => &mut self.data,
        };
        cache.fill(window);
        false
    }

    /// Forget the windows unless `memory` is still at their epoch.
    #[inline(always)]
    pub fn revalidate<M: Memory>(&mut self, memory: &M) {
        if memory.epoch() != self.epoch && self.epoch != 0 {
            core::hint::cold_path();
            *self = Self::EMPTY;
        }
    }

    /// Put the window that `memory` reports around `addr` in the stack cache, or with `DATA` in the data cache of
    /// accesses of `size` bytes, which for 1 and 2 bytes hands its window to the spare one.
    // one copy per memory and cache, not one per miss handler
    #[inline(never)]
    fn take<M: Memory, const DATA: bool>(&mut self, memory: &M, addr: u64, size: MemSize) {
        self.revalidate(memory);
        let window = memory.window(addr);
        // a window is valid only while the memory is at its epoch, and one of epoch 0 is empty
        if window.epoch == 0 || window.epoch != memory.epoch() {
            return;
        }
        // the other caches are empty or hold windows of this epoch, as `revalidate` left `self.epoch` 0 or here
        self.epoch = window.epoch;
        let cache = match (DATA, small(size)) {
            (true, true) => {
                self.spare = std::mem::replace(&mut self.small, Cache::EMPTY);
                &mut self.small
            }
            (true, false) => &mut self.data,
            (false, _) => &mut self.stack,
        };
        cache.fill(window);
    }

    /// The data cache of the access `opc`: that of its size.
    #[inline(always)]
    fn data_for(&self, opc: OpCode) -> &Cache {
        match small(opc.mem_size()) {
            true => &self.small,
            false => &self.data,
        }
    }

    /// Run a load or store in the data window for `opc` at `addr`, returning `None` on a miss.
    #[inline(always)]
    pub fn run_data(&self, opc: OpCode, kind: usize, addr: u64, value: u64) -> Option<u64> {
        self.data_for(opc).run(opc, kind, addr, value)
    }
}

/// Whether accesses of `size` take the cache of 1 and 2 byte accesses, so that byte streams don't evict the window of
/// the words a program loads alongside them.
const fn small(size: MemSize) -> bool {
    matches!(size, MemSize::Byte | MemSize::Half)
}

impl Cache {
    const EMPTY: Self = Self {
        base: 0,
        bias: 0,
        fits: [0; 8],
    };

    fn fill(&mut self, window: Window) {
        let fits = |len: u64, size: u64| len.saturating_sub(size - 1);
        self.base = window.base;
        self.bias = window.ptr.expose_provenance().wrapping_sub(window.base as usize);
        self.fits = [
            fits(window.read_len, 4),
            fits(window.read_len, 8),
            fits(window.write_len, 4),
            fits(window.write_len, 8),
            fits(window.read_len, 1),
            fits(window.read_len, 2),
            fits(window.write_len, 1),
            fits(window.write_len, 2),
        ];
    }

    #[inline(always)]
    fn overlaps(&self, lo: u64, hi: u64) -> bool {
        let len = self.fits[4].max(self.fits[6]);
        range_overlaps(self.base, len, lo, hi)
    }

    /// Run the load or store `OP` of `insn` at `addr` on the host memory, or return false if it doesn't fit in the
    /// window.
    #[inline(always)]
    fn access<const OP: u8>(&self, regs: &mut impl Regs, insn: View<'_, true>, addr: u64) -> bool {
        let opc = OpCode(OP);
        let value = match opc.class() {
            Class::Stx => regs.get(insn.src_reg()),
            _ => i64::from(insn.imm()) as u64,
        };
        let Some(loaded) = self.run(opc, const { kind(OpCode(OP)) }, addr, value) else {
            return false;
        };
        if let Class::Ldx = opc.class() {
            regs.set(insn.dst_reg(), loaded);
        }
        true
    }

    /// Run the load or store `opc`, whose [`kind`] is `kind`, at `addr` on the host memory: the value it loads, or 0
    /// once it stored `value`. `None` if it doesn't fit in the window.
    #[inline(always)]
    fn run(&self, opc: OpCode, kind: usize, addr: u64, value: u64) -> Option<u64> {
        let at = addr.wrapping_sub(self.base);
        if at >= self.fits[kind] {
            return None;
        }

        // from the exposed address, not a derived pointer: a window over raw host addresses has no allocation its
        // `ptr` points into (see `Window::new`), and `addr + bias` computes the host address in parallel with `at`
        let host = ptr::with_exposed_provenance_mut::<u8>((addr as usize).wrapping_add(self.bias));
        // SAFETY: the access fits in the window at `at`, and the memory is at the window's epoch (see `Windows`), so
        // the host bytes there are the guest bytes and valid for the access
        Some(unsafe { access_raw(host, opc, value) })
    }
}

/// Perform the raw host load or store for `opc` at `host`.
///
/// # Safety
///
/// `host` must be valid for a read or write of `opc.mem_size()` bytes.
#[inline(always)]
unsafe fn access_raw(host: *mut u8, opc: OpCode, value: u64) -> u64 {
    unsafe {
        match (opc.class(), opc.mem_size()) {
            (Class::Ldx, MemSize::Byte) => host.read().into(),
            (Class::Ldx, MemSize::Half) => u16::from_le(host.cast::<u16>().read_unaligned()).into(),
            (Class::Ldx, MemSize::Word) => u32::from_le(host.cast::<u32>().read_unaligned()).into(),
            (Class::Ldx, MemSize::DWord) => u64::from_le(host.cast::<u64>().read_unaligned()),
            (_, MemSize::Byte) => {
                host.write(value as u8);
                0
            }
            (_, MemSize::Half) => {
                host.cast::<u16>().write_unaligned((value as u16).to_le());
                0
            }
            (_, MemSize::Word) => {
                host.cast::<u32>().write_unaligned((value as u32).to_le());
                0
            }
            (_, MemSize::DWord) => {
                host.cast::<u64>().write_unaligned(value.to_le());
                0
            }
        }
    }
}

/// The index into [`Cache::fits`] for the access `opc`. 4 and 8 byte accesses sit first so every `stack_access`
/// handler reaches them within one-byte displacement.
pub const fn kind(opc: OpCode) -> usize {
    let store = !matches!(opc.class(), Class::Ldx);
    match (opc.mem_size(), store) {
        (MemSize::Word, false) => 0,
        (MemSize::DWord, false) => 1,
        (MemSize::Word, true) => 2,
        (MemSize::DWord, true) => 3,
        (MemSize::Byte, false) => 4,
        (MemSize::Half, false) => 5,
        (MemSize::Byte, true) => 6,
        (MemSize::Half, true) => 7,
    }
}

/// Whether the opcode byte `op` is a plain `ldx`, `stx` or `st`, which the windows run.
pub const fn windowed(op: u8) -> bool {
    let opc = OpCode(op);
    opc.is_access() && matches!(opc.mem_mode(), MemMode::Mem)
}

/// Runs the [`windowed`] load or store `insn` of a superinstruction on the registers `regs`, as [`stack_access`] runs
/// one through r10 and [`data_access`] one through another register that hits the data window. Returns false,
/// changing nothing, if the access doesn't fit there: the superinstruction then continues unfused at the access, whose
/// handler tries the other windows.
#[inline(always)]
pub fn data_step<R: Regs>(windows: &Windows, regs: &mut R, insn: impl Fields) -> bool {
    let opc = insn.opcode();
    let (base, value) = match opc.class() {
        Class::Ldx => (insn.src_reg(), 0),
        Class::Stx => (insn.dst_reg(), regs.get(insn.src_reg())),
        _ => (insn.dst_reg(), i64::from(insn.imm()) as u64),
    };
    let addr = step::address(regs.get(base), insn);
    // a superinstruction names r10 only as a constant base (`fp`), so this folds
    let cache = match usize::from(base.get()) == FP {
        true => &windows.stack,
        false => windows.data_for(opc),
    };
    let Some(loaded) = cache.run(opc, kind(opc), addr, value) else {
        return false;
    };
    if let Class::Ldx = opc.class() {
        regs.set(insn.dst_reg(), loaded);
    }
    true
}

/// The direct fuel-independent handler for a windowed load or store `op`, through r10 if `fp` else through another
/// register, or `None` for any other opcode.
pub const fn access_handler<M: Memory, H: Host<M>>(op: u8, fp: bool) -> Option<Handler<M, H>> {
    macro_rules! dispatch {
        ($($opc:expr),*) => {
            match (fp, op) {
                $((true, x) if x == $opc => Some(stack_access::<M, H, { $opc }>),)*
                $((false, x) if x == $opc => Some(data_access::<M, H, { $opc }>),)*
                _ => None,
            }
        };
    }
    dispatch!(
        OpCode::ldx(MemSize::Byte, MemMode::Mem).0,
        OpCode::ldx(MemSize::Half, MemMode::Mem).0,
        OpCode::ldx(MemSize::Word, MemMode::Mem).0,
        OpCode::ldx(MemSize::DWord, MemMode::Mem).0,
        OpCode::stx(MemSize::Byte, MemMode::Mem).0,
        OpCode::stx(MemSize::Half, MemMode::Mem).0,
        OpCode::stx(MemSize::Word, MemMode::Mem).0,
        OpCode::stx(MemSize::DWord, MemMode::Mem).0,
        OpCode::st(MemSize::Byte, MemMode::Mem).0,
        OpCode::st(MemSize::Half, MemMode::Mem).0,
        OpCode::st(MemSize::Word, MemMode::Mem).0,
        OpCode::st(MemSize::DWord, MemMode::Mem).0
    )
}

/// Make [`data_access`] the handler of the plain `ldx`, `stx` and `st` of every size, and [`stack_access`] that of
/// the r10 access bytes.
pub const fn install<M: Memory, H: Host<M>>(table: &mut [Handler<M, H>; 256]) {
    install_stack(table);
    macro_rules! install {
        ($($op:expr),*) => {
            $(table[$op as usize] = data_access::<M, H, { $op }>;)*
        };
    }
    install!(
        OpCode::ldx(MemSize::Byte, MemMode::Mem).0,
        OpCode::ldx(MemSize::Half, MemMode::Mem).0,
        OpCode::ldx(MemSize::Word, MemMode::Mem).0,
        OpCode::ldx(MemSize::DWord, MemMode::Mem).0,
        OpCode::stx(MemSize::Byte, MemMode::Mem).0,
        OpCode::stx(MemSize::Half, MemMode::Mem).0,
        OpCode::stx(MemSize::Word, MemMode::Mem).0,
        OpCode::stx(MemSize::DWord, MemMode::Mem).0,
        OpCode::st(MemSize::Byte, MemMode::Mem).0,
        OpCode::st(MemSize::Half, MemMode::Mem).0,
        OpCode::st(MemSize::Word, MemMode::Mem).0,
        OpCode::st(MemSize::DWord, MemMode::Mem).0
    );
}

macro_rules! stack_accesses {
    ($($byte:literal: $opcode:expr;)*) => {
        /// The opcode bytes of the loads and stores through r10 that [`stack_access`] runs, each with the opcode it
        /// stands for.
        pub const STACK_ACCESSES: &[(u8, u8)] = &[$(($byte, $opcode.0)),*];

        /// Give each r10 access byte its handler.
        const fn install_stack<M: Memory, H: Host<M>>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = stack_access::<M, H, { $opcode.0 }>;)*
        }
    };
}

stack_accesses! {
    0xa0: OpCode::ldx(MemSize::Word, MemMode::Mem);
    0xa8: OpCode::ldx(MemSize::DWord, MemMode::Mem);
    0xb0: OpCode::stx(MemSize::Word, MemMode::Mem);
    0xb8: OpCode::stx(MemSize::DWord, MemMode::Mem);
    0xc0: OpCode::st(MemSize::Word, MemMode::Mem);
    0xc8: OpCode::st(MemSize::DWord, MemMode::Mem);
}

/// For each opcode byte, the byte of the r10 access with that opcode, if there is one.
const STACK_BYTES: [Option<NonZeroU8>; 256] = {
    let mut table = [None; 256];
    const_for!((byte, opcode) in STACK_ACCESSES => table[opcode as usize] = NonZeroU8::new(byte));
    table
};

/// The r10 access byte for `insn`, if it is a load or store through r10 that has one.
pub fn stack_byte(insn: Instruction) -> Option<u8> {
    let byte = STACK_BYTES[usize::from(insn.byte())]?;
    let base = match insn.opcode().class() {
        Class::Ldx => insn.src_reg(),
        _ => insn.dst_reg(),
    };
    (usize::from(base) == FP).then_some(byte.get())
}

/// The handler of the r10 access that stands for the load or store `OP`.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn stack_access<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and an r10 access has the threaded layout of its load or store
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let addr = step::address(ctx.regs[FP], insn);
    let mut regs = ctx.regs_view_mut();
    if !interp.windows.stack.access::<OP>(&mut regs, insn, addr) {
        become miss::<M, H, OP, false>(ctx, code, ip, interp, rests, SPARE, slot)
    }
    become_next!(ctx, code, ip, interp, rests)
}

/// The handler of the load or store `OP` through a register other than r10.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn data_access<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `handler`
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let addr = step::address(ctx.reg_get(base_reg::<OP>(insn)), insn);
    let mut regs = ctx.regs_view_mut();
    if interp.windows.data_for(OpCode(OP)).access::<OP>(&mut regs, insn, addr) {
        become_next!(ctx, code, ip, interp, rests)
    }
    // Keep the primary window hit straight-line by placing the spare check after its dispatch.
    core::hint::cold_path();
    if small(OpCode(OP).mem_size()) && interp.windows.spare.access::<OP>(&mut regs, insn, addr) {
        become_next!(ctx, code, ip, interp, rests)
    }
    become data_miss::<M, H, OP>(ctx, code, ip, interp, rests, SPARE, slot)
}

/// Whether `[base .. base + len)` overlaps `[lo .. hi)`, conservatively returning `true` on `u64` wraparound.
#[inline(always)]
pub fn range_overlaps(base: u64, len: u64, lo: u64, hi: u64) -> bool {
    if len == 0 {
        return false;
    }
    match base.checked_add(len) {
        Some(end) => base < hi && lo < end,
        None => true,
    }
}

/// Runs a load or store that missed the data window through the window around r10 if it fits there, as one through
/// a pointer into the stack does, and in [`miss`] otherwise.
// out of line from `miss`, whose call of `Windows::take` needs a stack frame
#[inline(never)]
extern "rust-preserve-none" fn data_miss<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `data_access`, which continues here
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let addr = step::address(ctx.reg_get(base_reg::<OP>(insn)), insn);
    if interp.promo_overlaps(addr, const { OpCode(OP).mem_size().bytes() as u64 }) {
        let (unpromoted, new_ip, new_rests) = interp.bail_promoted(ctx, code, ip);
        // SAFETY: `new_ip` points at the same in-bounds pc in the uncompacted stream.
        let new_slot = unsafe { new_ip.get() };
        become handler::<M, H, OP>(ctx, unpromoted, new_ip, interp, new_rests, SPARE, new_slot)
    }
    let mut regs = ctx.regs_view_mut();
    if !interp.windows.stack.access::<OP>(&mut regs, insn, addr) {
        become miss::<M, H, OP, true>(ctx, code, ip, interp, rests, SPARE, slot)
    }
    become_next!(ctx, code, ip, interp, rests)
}

/// Takes the window around the address of the access, or without `DATA` around r10, and runs the access with its
/// usual handler.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn miss<M: Memory, H: Host<M>, const OP: u8, const DATA: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `stack_access` and `data_access`, which continue here
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let around = match DATA {
        true => step::address(ctx.reg_get(base_reg::<OP>(insn)), insn),
        // the frame is the bytes below r10
        false => ctx.regs[FP].wrapping_sub(1),
    };
    let (mut code, mut ip, mut rests, mut slot) = (code, ip, rests, slot);
    if interp.is_promoted() {
        let size = const { OpCode(OP).mem_size().bytes() as u64 };
        let (lo, hi) = interp.promo_range();
        let need_bail = !DATA
            || range_overlaps(around, size, lo, hi)
            || interp
                .windows
                .take_checked(ctx.memory, around, OpCode(OP).mem_size(), lo, hi);
        if need_bail {
            (code, ip, rests) = interp.bail_promoted(ctx, code, ip);
            // SAFETY: `ip` points at the same in-bounds pc in the uncompacted stream.
            slot = unsafe { ip.get() };
            interp
                .windows
                .take::<M, DATA>(ctx.memory, around, OpCode(OP).mem_size());
        }
    } else {
        interp
            .windows
            .take::<M, DATA>(ctx.memory, around, OpCode(OP).mem_size());
    }
    become handler::<M, H, OP>(ctx, code, ip, interp, rests, SPARE, slot)
}

/// Cold fallback for a fused byte load at `ip` that missed the primary small data window.
///
/// Completes the byte load through `spare`, `stack`, or `ctx.memory`, writes `dst`, and continues at the intact slot
/// `ip.offset(1)`.
#[cold]
#[inline(never)]
pub extern "rust-preserve-none" fn byte_load_miss<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    const LDX_B: u8 = OpCode::ldx(MemSize::Byte, MemMode::Mem).0;
    // SAFETY: caller packed `dst` in byte 0, `base` in byte 1, and signed `off` in byte 3.
    let dst = unsafe { slot.reg0() };
    let base = unsafe { slot.reg1() };
    let off = i64::from(slot.byte3() as i8);
    let addr = ctx.reg_get(base).wrapping_add_signed(off);
    let (mut code, mut ip, mut rests) = (code, ip, rests);

    if let Some(loaded) = interp
        .windows
        .spare
        .run(OpCode(LDX_B), const { kind(OpCode(LDX_B)) }, addr, 0)
    {
        ctx.reg_set(dst, loaded);
        become_next!(ctx, code, ip, interp, rests)
    }

    if interp.promo_overlaps(addr, 1) {
        (code, ip, rests) = interp.bail_promoted(ctx, code, ip);
    }
    if let Some(loaded) = interp
        .windows
        .stack
        .run(OpCode(LDX_B), const { kind(OpCode(LDX_B)) }, addr, 0)
    {
        ctx.reg_set(dst, loaded);
        become_next!(ctx, code, ip, interp, rests)
    }

    if interp.is_promoted() {
        let (lo, hi) = interp.promo_range();
        let need_bail =
            range_overlaps(addr, 1, lo, hi) || interp.windows.take_checked(ctx.memory, addr, MemSize::Byte, lo, hi);
        if need_bail {
            (code, ip, rests) = interp.bail_promoted(ctx, code, ip);
            interp.windows.take::<M, true>(ctx.memory, addr, MemSize::Byte);
        }
    } else {
        interp.windows.take::<M, true>(ctx.memory, addr, MemSize::Byte);
    }

    match ctx.memory.load_u8(addr) {
        Ok(byte) => {
            ctx.reg_set(dst, u64::from(byte));
            become_next!(ctx, code, ip, interp, rests)
        }
        Err(err) => interp.stop.at(ip, Reason::MemoryFault(err)),
    }
}

/// The register that holds the base address of the load or store `OP`.
#[inline(always)]
fn base_reg<const OP: u8>(insn: View<'_, true>) -> Reg {
    match OpCode(OP).class() {
        Class::Ldx => insn.src_reg(),
        _ => insn.dst_reg(),
    }
}
