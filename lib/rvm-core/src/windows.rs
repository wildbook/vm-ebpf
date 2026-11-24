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
use crate::dispatch::{Handler, Spare, Table, SPARE};
use crate::handler::handler;
use crate::memory::Window;
use crate::opcode::{Class, MemMode, MemSize, OpCode};
use crate::slot::{Fields, Reg, Shape, Slot, View};
use crate::step::{self, Regs};
use crate::transfer::Ip;
use crate::{Context, Host, Instruction, Interpreter, Memory};

/// The windows that [`stack_access`] and [`data_access`] check addresses against, kept in the [`Interpreter`].
///
/// Each cache that isn't empty holds a window of epoch `epoch`, which [`Windows::take`] ensures. The interpreter calls
/// [`Windows::revalidate`] whenever code outside the chain of handlers may have changed the memory, and the methods of
/// [`Memory`] leave its epoch alone, so inside the chain the memory is at `epoch` whenever a cache isn't empty.
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
struct Cache {
    base: u64,
    ptr: *mut u8,
    /// By [`kind`]: the number of offsets from `base` at which the access fits in the window. All 0 when empty.
    fits: [u64; 8],
}

// SAFETY: the handlers dereference the pointers only through `&mut Interpreter`, while the memory that the run was
// given is at `epoch`. Only one memory ever takes an epoch (see `Memory`), so the pointers are only used together with
// the memory they point into, on whichever thread holds that memory.
unsafe impl Send for Windows {}
unsafe impl Sync for Windows {}

impl Windows {
    pub const EMPTY: Self = Self {
        stack: Cache::EMPTY,
        data: Cache::EMPTY,
        small: Cache::EMPTY,
        spare: Cache::EMPTY,
        epoch: 0,
    };

    /// Forget the windows unless `memory` is still at their epoch.
    #[inline(always)]
    pub fn revalidate<M: Memory>(&mut self, memory: &M) {
        if self.epoch != 0 && memory.epoch() != self.epoch {
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
}

/// Whether accesses of `size` take the cache of 1 and 2 byte accesses, so that byte streams don't evict the window of
/// the words a program loads alongside them.
const fn small(size: MemSize) -> bool {
    matches!(size, MemSize::Byte | MemSize::Half)
}

impl Cache {
    const EMPTY: Self = Self {
        base: 0,
        ptr: ptr::null_mut(),
        fits: [0; 8],
    };

    fn fill(&mut self, window: Window) {
        let fits = |len: u64, size: u64| len.saturating_sub(size - 1);
        self.base = window.base;
        self.ptr = window.ptr;
        self.fits = [
            fits(window.read_len, 1),
            fits(window.read_len, 2),
            fits(window.read_len, 4),
            fits(window.read_len, 8),
            fits(window.write_len, 1),
            fits(window.write_len, 2),
            fits(window.write_len, 4),
            fits(window.write_len, 8),
        ];
    }

    /// Run the load or store `OP` of `insn` at `addr` on the host memory, or return false if it doesn't fit in the
    /// window.
    #[inline(always)]
    fn access<const OP: u8>(&self, regs: &mut [u64; 16], insn: View, addr: u64, ip: Ip) -> bool {
        let opc = OpCode(OP);
        let value = match opc.class() {
            Class::Stx => regs.get(insn.src_reg()),
            _ => i64::from(insn.imm()) as u64,
        };
        let Some(loaded) = self.run::<0>(opc, const { kind(OpCode(OP)) }, addr, value, ip) else {
            return false;
        };
        if let Class::Ldx = opc.class() {
            regs.set(insn.dst_reg(), loaded);
        }
        true
    }

    /// Run the load or store `opc`, whose [`kind`] is `kind`, at `addr` on the host memory: the value it loads, or 0
    /// once it stored `value`. `None` if it doesn't fit in the window. The access belongs to the instruction `DELTA`
    /// slots after `ip`, the ip of the handler that runs it.
    #[inline(always)]
    fn run<const DELTA: usize>(&self, opc: OpCode, kind: usize, addr: u64, value: u64, ip: Ip) -> Option<u64> {
        let at = addr.wrapping_sub(self.base);
        if at >= self.fits[kind] {
            return None;
        }

        // With the feature, as one instruction that `seh::enter` catches an access violation of: a window over raw
        // host addresses may cover unmapped memory.
        // SAFETY: as below. `ip` is the ip of the handler that runs the access, and the instruction of the access
        // lies `DELTA` slots after it (see the callers).
        #[cfg(feature = "seh")]
        return Some(unsafe {
            match opc.class() {
                Class::Ldx => crate::seh::load::<DELTA>(opc.mem_size(), self.ptr, at, ip),
                _ => {
                    crate::seh::store::<DELTA>(opc.mem_size(), self.ptr, at, value, ip);
                    0
                }
            }
        });

        #[cfg(not(feature = "seh"))]
        {
            let _ = ip;
            // from the address, not `self.ptr`: a window over raw host addresses has no allocation `self.ptr` points
            // into (see `Window::new`)
            let host = ptr::with_exposed_provenance_mut::<u8>(self.ptr.expose_provenance() + at as usize);
            // SAFETY: the access fits in the window at `at`, and the memory is at the window's epoch (see
            // `Windows`), so the host bytes there are the guest bytes and valid for the access
            unsafe {
                match (opc.class(), opc.mem_size()) {
                    (Class::Ldx, MemSize::Byte) => return Some(host.read().into()),
                    (Class::Ldx, MemSize::Half) => {
                        return Some(u16::from_le(host.cast::<u16>().read_unaligned()).into())
                    }
                    (Class::Ldx, MemSize::Word) => {
                        return Some(u32::from_le(host.cast::<u32>().read_unaligned()).into())
                    }
                    (Class::Ldx, MemSize::DWord) => return Some(u64::from_le(host.cast::<u64>().read_unaligned())),
                    (_, MemSize::Byte) => host.write(value as u8),
                    (_, MemSize::Half) => host.cast::<u16>().write_unaligned((value as u16).to_le()),
                    (_, MemSize::Word) => host.cast::<u32>().write_unaligned((value as u32).to_le()),
                    (_, MemSize::DWord) => host.cast::<u64>().write_unaligned(value.to_le()),
                }
            }
            Some(0)
        }
    }
}

/// The index into [`Cache::fits`] for the access `opc`.
const fn kind(opc: OpCode) -> usize {
    let store = !matches!(opc.class(), Class::Ldx);
    let size = match opc.mem_size() {
        MemSize::Byte => 0,
        MemSize::Half => 1,
        MemSize::Word => 2,
        MemSize::DWord => 3,
    };
    4 * store as usize + size
}

/// Whether the opcode byte `op` is a plain `ldx`, `stx` or `st`, which the windows run.
pub const fn windowed(op: u8) -> bool {
    let opc = OpCode(op);
    opc.is_access() && matches!(opc.mem_mode(), MemMode::Mem)
}

/// Runs the [`windowed`] load or store `insn` of a superinstruction on the registers `regs`, as [`stack_access`] runs
/// one through r10 and [`data_access`] one through another register that hits the data window. Returns false,
/// changing nothing, if the access doesn't fit there: the superinstruction then continues unfused at the access, whose
/// handler tries the other windows. `insn` is `K` slots after `ip`, the ip of the superinstruction's handler.
#[inline(always)]
pub fn data_step<R: Regs, I: Fields, const K: usize>(windows: &Windows, regs: &mut R, insn: I, ip: Ip) -> bool {
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
    let Some(loaded) = cache.run::<K>(opc, kind(opc), addr, value, ip) else {
        return false;
    };
    if let Class::Ldx = opc.class() {
        regs.set(insn.dst_reg(), loaded);
    }
    true
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

/// The byte of the r10 access with opcode `op`.
pub const fn stack_byte_of(op: u8) -> u8 {
    match STACK_BYTES[op as usize] {
        Some(byte) => byte.get(),
        None => panic!("an access through r10 without a byte of its own"),
    }
}

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
#[inline(never)]
pub extern "rust-preserve-none" fn stack_access<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and an r10 access has the layout of its load or store
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let addr = step::address(ctx.regs[FP], insn);
    if !interp.windows.stack.access::<OP>(&mut ctx.regs, insn, addr, ip) {
        become miss::<M, H, OP, false>(ctx, code, ip, interp, table, SPARE, slot)
    }
    become_next!(ctx, code, ip, interp, table)
}

/// The handler of the load or store `OP` through a register other than r10.
#[inline(never)]
pub extern "rust-preserve-none" fn data_access<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `handler`
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let addr = step::address(ctx.regs.get(base_reg::<OP>(insn)), insn);
    if interp
        .windows
        .data_for(OpCode(OP))
        .access::<OP>(&mut ctx.regs, insn, addr, ip)
    {
        become_next!(ctx, code, ip, interp, table)
    }
    // a dispatch of its own, so that the hit above keeps its instructions
    if small(OpCode(OP).mem_size()) && interp.windows.spare.access::<OP>(&mut ctx.regs, insn, addr, ip) {
        become_next!(ctx, code, ip, interp, table)
    }
    become data_miss::<M, H, OP>(ctx, code, ip, interp, table, SPARE, slot)
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
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `data_access`, which continues here
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let addr = step::address(ctx.regs.get(base_reg::<OP>(insn)), insn);
    if !interp.windows.stack.access::<OP>(&mut ctx.regs, insn, addr, ip) {
        become miss::<M, H, OP, true>(ctx, code, ip, interp, table, SPARE, slot)
    }
    become_next!(ctx, code, ip, interp, table)
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
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `stack_access` and `data_access`, which continue here
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let around = match DATA {
        true => step::address(ctx.regs.get(base_reg::<OP>(insn)), insn),
        // the frame is the bytes below r10
        false => ctx.regs[FP].wrapping_sub(1),
    };
    interp
        .windows
        .take::<M, DATA>(ctx.memory, around, OpCode(OP).mem_size());
    // With the feature, through the window if it now covers the access. An access at a raw host address then runs
    // where `seh::enter` catches its fault, and not in the memory's own load or store.
    #[cfg(feature = "seh")]
    {
        let (cache, addr) = match DATA {
            true => (interp.windows.data_for(OpCode(OP)), around),
            false => (&interp.windows.stack, step::address(ctx.regs[FP], insn)),
        };
        if cache.access::<OP>(&mut ctx.regs, insn, addr, ip) {
            become_next!(ctx, code, ip, interp, table)
        }
    }
    become handler::<M, H, OP>(ctx, code, ip, interp, table, SPARE, slot)
}

/// The register that holds the base address of the load or store `OP`.
#[inline(always)]
fn base_reg<const OP: u8>(insn: View) -> Reg {
    match OpCode(OP).class() {
        Class::Ldx => insn.src_reg(),
        _ => insn.dst_reg(),
    }
}

#[cfg(feature = "seh")]
macro_rules! guarded_accesses {
    ($($byte:literal: $opcode:expr;)*) => {
        /// The opcode bytes of the accesses that [`guarded_access`] runs, each with the opcode it stands for: the
        /// sign-extending loads and the atomics, which the plain handlers don't run in windows.
        /// [`Code::guard_accesses`](crate::Code::guard_accesses) gives them these bytes.
        pub const GUARDED_ACCESSES: &[(u8, u8)] = &[$(($byte, $opcode.0)),*];

        /// Give each guarded access byte its handler.
        pub const fn install_guarded<M: Memory, H: Host<M>>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = guarded_access::<M, H, { $opcode.0 }>;)*
        }
    };
}

#[cfg(feature = "seh")]
guarded_accesses! {
    0x01: OpCode::ldx(MemSize::Byte, MemMode::MemSX);
    0x02: OpCode::ldx(MemSize::Half, MemMode::MemSX);
    0x03: OpCode::ldx(MemSize::Word, MemMode::MemSX);
    0x09: OpCode::stx(MemSize::Byte, MemMode::Atomic);
    0x0a: OpCode::stx(MemSize::Half, MemMode::Atomic);
    0x0b: OpCode::stx(MemSize::Word, MemMode::Atomic);
    0x11: OpCode::stx(MemSize::DWord, MemMode::Atomic);
}

/// The byte of the guarded access with opcode `op`, if there is one.
#[cfg(feature = "seh")]
pub const fn guarded_byte(op: u8) -> Option<u8> {
    const_for!((byte, opcode) in GUARDED_ACCESSES => {
        if opcode == op {
            return Some(byte);
        }
    });
    None
}

/// The handler of the sign-extending load or atomic `OP` in guarded code. It runs the access in a window if one
/// covers it: the window of data accesses of its size, the one around r10, or the one the memory reports around its
/// address, which becomes the data window. So in a run inside [`seh::enter`](crate::seh::enter) the access runs as
/// an instruction whose access violation the guard catches, and not in a method of the memory. Where no window
/// covers it, or its address isn't aligned as a host atomic needs, it continues in [`handler`].
#[cfg(feature = "seh")]
#[inline(never)]
extern "rust-preserve-none" fn guarded_access<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    use crate::step::Step;
    use crate::Reason;

    // SAFETY: a handler's ip lies below `len`, and a guarded access has the layout of its opcode
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let opc = OpCode(OP);
    for attempt in 0..3 {
        let cache = match attempt {
            1 => &interp.windows.stack,
            _ => interp.windows.data_for(opc),
        };
        // a miss changes neither the registers nor memory: an instruction has one access, and it comes first
        let missed = match step::step(&mut ctx.regs, &mut InWindow { cache, ip }, insn) {
            Step::Next => become_next!(ctx, code, ip, interp, table),
            Step::Stop(Reason::MemoryFault(addr)) => addr,
            // an instruction that fails otherwise, which `handler` reports
            _ => break,
        };
        if attempt == 1 {
            interp.windows.take::<M, true>(ctx.memory, missed, opc.mem_size());
        }
    }
    become handler::<M, H, OP>(ctx, code, ip, interp, table, SPARE, slot)
}

/// A window as a [`Memory`], for [`guarded_access`]. An access that fits in the window runs there as an instruction
/// of [`seh`](crate::seh), for the handler at `ip`; an atomic or ordered access also needs an aligned address, as a
/// host atomic does. Any other access fails with its address.
#[cfg(feature = "seh")]
struct InWindow<'a> {
    cache: &'a Cache,
    ip: Ip,
}

#[cfg(feature = "seh")]
impl InWindow<'_> {
    /// The offset in the window of the address `addr`, if it is one of the first `fits` and its host address is a
    /// multiple of `align`.
    #[inline(always)]
    fn offset(&self, addr: u64, fits: u64, align: u64) -> Result<u64, u64> {
        let at = addr.wrapping_sub(self.cache.base);
        let host = (self.cache.ptr.addr() as u64).wrapping_add(at);
        match at < fits && host.is_multiple_of(align) {
            true => Ok(at),
            false => Err(addr),
        }
    }

    /// The number of offsets at which a load of `size` bytes fits in the window, or with `store` a store.
    #[inline(always)]
    fn fits(&self, store: bool, size: MemSize) -> u64 {
        let size = match size {
            MemSize::Byte => 0,
            MemSize::Half => 1,
            MemSize::Word => 2,
            MemSize::DWord => 3,
        };
        self.cache.fits[4 * usize::from(store) + size]
    }

    #[inline(always)]
    fn load(&self, addr: u64, size: MemSize, align: u64) -> Result<u64, u64> {
        let at = self.offset(addr, self.fits(false, size), align)?;
        // SAFETY: the load fits in the window at `at`, which holds for the handler at `ip` as for `Cache::run`
        Ok(unsafe { crate::seh::load::<0>(size, self.cache.ptr, at, self.ip) })
    }

    #[inline(always)]
    fn store(&self, addr: u64, size: MemSize, align: u64, value: u64) -> Result<(), u64> {
        let at = self.offset(addr, self.fits(true, size), align)?;
        // SAFETY: as in `load`
        unsafe { crate::seh::store::<0>(size, self.cache.ptr, at, value, self.ip) };
        Ok(())
    }
}

#[cfg(feature = "seh")]
macro_rules! window_access {
    ($ty:ty, $size:expr, $load:ident, $store:ident, $load_acquire:ident, $store_release:ident) => {
        #[inline(always)]
        fn $load(&self, addr: u64) -> Result<$ty, u64> {
            self.load(addr, $size, 1).map(|value| value as $ty)
        }

        #[inline(always)]
        fn $store(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            self.store(addr, $size, 1, value.into())
        }

        // On x86-64 a plain load and store have acquire and release ordering.
        #[inline(always)]
        fn $load_acquire(&self, addr: u64) -> Result<$ty, u64> {
            self.load(addr, $size, size_of::<$ty>() as u64)
                .map(|value| value as $ty)
        }

        #[inline(always)]
        fn $store_release(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            self.store(addr, $size, size_of::<$ty>() as u64, value.into())
        }
    };
}

#[cfg(feature = "seh")]
macro_rules! window_atomic {
    ($name:ident, $ty:ty, $size:expr, $wide:expr) => {
        #[inline(always)]
        fn $name(&mut self, addr: u64, op: crate::AtomicOp<$ty>) -> Result<$ty, u64> {
            let fits = self.fits(false, $size).min(self.fits(true, $size));
            let at = self.offset(addr, fits, size_of::<$ty>() as u64)?;
            let (ptr, ip) = (self.cache.ptr, self.ip);
            // SAFETY: as in `load`, for a read and a write
            let swap = |expected: $ty, new: $ty| unsafe {
                crate::seh::compare_swap($wide, ptr, at, expected.into(), new.into(), ip) as $ty
            };
            if let crate::AtomicOp::CmpXchg { expected, new } = op {
                return Ok(swap(expected, new));
            }
            loop {
                // SAFETY: as in `load`
                let old = unsafe { crate::seh::load::<0>($size, ptr, at, ip) } as $ty;
                let Some(new) = op.apply(old) else {
                    unreachable!("every operation but CMPXCHG stores a value")
                };
                if swap(old, new) == old {
                    return Ok(old);
                }
            }
        }
    };
}

// SAFETY: it keeps the defaults of `window` and `epoch`
#[cfg(feature = "seh")]
unsafe impl Memory for InWindow<'_> {
    /// The address of an access the window doesn't run.
    type Error = u64;

    window_access!(u8, MemSize::Byte, load_u8, store_u8, load_acquire_u8, store_release_u8);
    window_access!(u16, MemSize::Half, load_u16, store_u16, load_acquire_u16, store_release_u16);
    window_access!(u32, MemSize::Word, load_u32, store_u32, load_acquire_u32, store_release_u32);
    window_access!(u64, MemSize::DWord, load_u64, store_u64, load_acquire_u64, store_release_u64);

    window_atomic!(atomic_u32, u32, MemSize::Word, false);
    window_atomic!(atomic_u64, u64, MemSize::DWord, true);

    fn native_ptr(&self, addr: u64, _: u64, _: bool) -> Result<u64, u64> {
        Err(addr)
    }
}
