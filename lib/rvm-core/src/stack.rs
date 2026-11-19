//! Loads and stores that skip the [`Memory`] methods.
//!
//! [`Code::new`](crate::Code::new) gives each 4 and 8 byte `ldx`, `stx` and `st` with base register r10 an opcode byte
//! of its own, whose handler is [`access`]. Through any other register, and at every size, they keep their opcode byte,
//! whose handler [`install`] makes [`data_access`]. Both check the address against a [`Window`] that the memory
//! reported and access the host memory directly: [`access`] against the window around r10, [`data_access`] against
//! the window around the last address of its size class that missed (1 and 2 byte accesses also the one before) and
//! then, for pointers into the stack, the window around r10. An address outside the windows takes the usual handler of
//! the instruction, so the access behaves exactly as it does there. The accesses of superinstructions try the data
//! window of their size class through [`data_step`] and continue unfused at an access that misses it. Guest code can't
//! write r10, so it stays in the stack, inside the window of the stack.

use std::ptr;

use crate::op::{Fields, Op, Reg, Shape, View};
use crate::opcode::{Class, MemMode, MemSize, OpCode};
use crate::ops::Regs;
use crate::transfer::Slot;
use crate::{handler, mem, CallStack, Context, Handler, Host, Memory, Table};

/// Host memory that guest loads and stores near some address reach directly; see [`Memory::window`].
#[derive(Clone, Copy, Debug)]
pub struct Window {
    base: u64,
    ptr: *mut u8,
    read_len: u64,
    write_len: u64,
    epoch: u64,
}

impl Window {
    /// No window: every access goes through the [`Memory`] methods.
    pub const NONE: Self = Self {
        base: 0,
        ptr: ptr::null_mut(),
        read_len: 0,
        write_len: 0,
        epoch: 0,
    };

    /// The `read_len` readable and `write_len` writable bytes at guest address `base`, which are the host bytes at
    /// `ptr`, valid while the memory's [`Memory::epoch`] is `epoch`.
    ///
    /// # Safety
    ///
    /// Whenever the memory that reports the window is at epoch `epoch`, `ptr` must be valid for reads of `read_len`
    /// bytes and for writes of `write_len` bytes, and a guest load (store) of `n` bytes at `base + i` with
    /// `i + n <= read_len` (`write_len`) on that memory must do nothing but read (write) the `n` bytes at `ptr + i`,
    /// unaligned and little-endian. `ptr` must not come from a reference to the memory, which a call of a [`Memory`]
    /// method would invalidate. [`Memory`] states the rules for epochs.
    pub const unsafe fn new(base: u64, ptr: *mut u8, read_len: u64, write_len: u64, epoch: u64) -> Self {
        Self {
            base,
            ptr,
            read_len,
            write_len,
            epoch,
        }
    }
}

/// The windows that [`access`] and [`data_access`] check addresses against, kept in the [`CallStack`].
///
/// Each cache that isn't empty holds a window of epoch `epoch`, which [`Windows::take`] ensures. [`run`](crate::run)
/// calls [`Windows::revalidate`] whenever code outside the handler chain may have changed the memory, and the methods of
/// [`Memory`] leave its epoch alone, so inside the handler chain the memory is at `epoch` whenever a cache isn't empty.
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

// SAFETY: the handlers dereference the pointers only through `&mut CallStack`, while the memory that `run` was given
// is at `epoch`. Only one memory ever takes an epoch (see `Memory`), so the pointers are only used together with the
// memory they point into, on whichever thread holds that memory.
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
    fn access<const OP: u8>(&self, regs: &mut [u64; 16], insn: View, addr: u64) -> bool {
        let opc = OpCode(OP);
        let value = match opc.class() {
            Class::StReg => regs.get(insn.src_reg()),
            _ => i64::from(insn.imm()) as u64,
        };
        let Some(loaded) = self.run(opc, const { kind(OpCode(OP)) }, addr, value) else {
            return false;
        };
        if let Class::LdReg = opc.class() {
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

        // SAFETY: the access fits in the window at `at`, and the memory is at the window's epoch (see `Windows`), so
        // the host bytes there are the guest bytes and valid for the access
        let host = unsafe { self.ptr.add(at as usize) };
        // SAFETY: as above
        unsafe {
            match (opc.class(), opc.mem_size()) {
                (Class::LdReg, MemSize::Byte) => return Some(host.read().into()),
                (Class::LdReg, MemSize::Half) => return Some(u16::from_le(host.cast::<u16>().read_unaligned()).into()),
                (Class::LdReg, MemSize::Word) => return Some(u32::from_le(host.cast::<u32>().read_unaligned()).into()),
                (Class::LdReg, MemSize::DWord) => return Some(u64::from_le(host.cast::<u64>().read_unaligned())),
                (_, MemSize::Byte) => host.write(value as u8),
                (_, MemSize::Half) => host.cast::<u16>().write_unaligned((value as u16).to_le()),
                (_, MemSize::Word) => host.cast::<u32>().write_unaligned((value as u32).to_le()),
                (_, MemSize::DWord) => host.cast::<u64>().write_unaligned(value.to_le()),
            }
        }
        Some(0)
    }
}

/// The index into [`Cache::fits`] for the access `opc`.
const fn kind(opc: OpCode) -> usize {
    let store = !matches!(opc.class(), Class::LdReg);
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
    let access = matches!(opc.class(), Class::LdReg | Class::StReg | Class::StImm);
    access && matches!(opc.mem_mode(), MemMode::Mem)
}

/// Runs the [`windowed`] load or store `insn` of a superinstruction on the registers `regs` in the data window, as
/// [`data_access`] runs one that hits it. Returns false, changing nothing, if the access doesn't fit there: the
/// superinstruction then continues unfused at the access, whose handler tries the other windows.
#[inline(always)]
pub fn data_step<R: Regs>(windows: &Windows, regs: &mut R, insn: impl Fields) -> bool {
    let opc = insn.opcode();
    let (base, value) = match opc.class() {
        Class::LdReg => (insn.src_reg(), 0),
        Class::StReg => (insn.dst_reg(), regs.get(insn.src_reg())),
        _ => (insn.dst_reg(), i64::from(insn.imm()) as u64),
    };
    let addr = mem::address(regs.get(base), insn);
    let Some(loaded) = windows.data_for(opc).run(opc, kind(opc), addr, value) else {
        return false;
    };
    if let Class::LdReg = opc.class() {
        regs.set(insn.dst_reg(), loaded);
    }
    true
}

/// Make [`data_access`] the handler of the plain `ldx`, `stx` and `st` of every size.
pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
    macro_rules! install {
        ($($op:expr),*) => {
            $(table[$op as usize] = data_access::<M, H, FUEL, { $op }>;)*
        };
    }
    install!(
        OpCode::ldreg_from_parts(MemSize::Byte, MemMode::Mem).0,
        OpCode::ldreg_from_parts(MemSize::Half, MemMode::Mem).0,
        OpCode::ldreg_from_parts(MemSize::Word, MemMode::Mem).0,
        OpCode::ldreg_from_parts(MemSize::DWord, MemMode::Mem).0,
        OpCode::streg_from_parts(MemSize::Byte, MemMode::Mem).0,
        OpCode::streg_from_parts(MemSize::Half, MemMode::Mem).0,
        OpCode::streg_from_parts(MemSize::Word, MemMode::Mem).0,
        OpCode::streg_from_parts(MemSize::DWord, MemMode::Mem).0,
        OpCode::stimm_from_parts(MemSize::Byte, MemMode::Mem).0,
        OpCode::stimm_from_parts(MemSize::Half, MemMode::Mem).0,
        OpCode::stimm_from_parts(MemSize::Word, MemMode::Mem).0,
        OpCode::stimm_from_parts(MemSize::DWord, MemMode::Mem).0
    );
}

/// The handler of the r10 access that stands for the load or store `OP`.
#[inline(never)]
pub extern "rust-preserve-none" fn access<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    // SAFETY: a handler's slot lies below `len`, and an r10 access has the layout of its load or store
    let insn = unsafe { slot.view(op, const { Shape::of(OP) }) };
    let addr = mem::address(ctx.regs[10], insn);
    if !calls.windows.stack.access::<OP>(&mut ctx.regs, insn, addr) {
        become miss::<M, H, FUEL, OP, false>(ctx, code, slot, fuel, calls, table, op)
    }
    become_next!(ctx, code, slot, fuel, calls, table)
}

/// The handler of the load or store `OP` through a register other than r10.
#[inline(never)]
pub extern "rust-preserve-none" fn data_access<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    // SAFETY: as in `handler`
    let insn = unsafe { slot.view(op, const { Shape::of(OP) }) };
    let addr = mem::address(ctx.regs.get(base_reg::<OP>(insn)), insn);
    if calls
        .windows
        .data_for(OpCode(OP))
        .access::<OP>(&mut ctx.regs, insn, addr)
    {
        become_next!(ctx, code, slot, fuel, calls, table)
    }
    // a dispatch of its own, so that the hit above keeps its instructions
    if small(OpCode(OP).mem_size()) && calls.windows.spare.access::<OP>(&mut ctx.regs, insn, addr) {
        become_next!(ctx, code, slot, fuel, calls, table)
    }
    become data_miss::<M, H, FUEL, OP>(ctx, code, slot, fuel, calls, table, op)
}

/// Runs a load or store that missed the data window through the window around r10 if it fits there, as one through
/// a pointer into the stack does, and in [`miss`] otherwise.
// out of line from `miss`, whose call of `Windows::take` needs a stack frame
#[inline(never)]
extern "rust-preserve-none" fn data_miss<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    // SAFETY: as in `data_access`, which continues here
    let insn = unsafe { slot.view(op, const { Shape::of(OP) }) };
    let addr = mem::address(ctx.regs.get(base_reg::<OP>(insn)), insn);
    if !calls.windows.stack.access::<OP>(&mut ctx.regs, insn, addr) {
        become miss::<M, H, FUEL, OP, true>(ctx, code, slot, fuel, calls, table, op)
    }
    become_next!(ctx, code, slot, fuel, calls, table)
}

/// Takes the window around the address of the access, or without `DATA` around r10, and runs the access with its
/// usual handler.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn miss<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8, const DATA: bool>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    // SAFETY: as in `access` and `data_access`, which continue here
    let insn = unsafe { slot.view(op, const { Shape::of(OP) }) };
    let around = match DATA {
        true => mem::address(ctx.regs.get(base_reg::<OP>(insn)), insn),
        // the frame is the bytes below r10
        false => ctx.regs[10].wrapping_sub(1),
    };
    calls.windows.take::<M, DATA>(&ctx.data, around, OpCode(OP).mem_size());
    become handler::<M, H, FUEL, OP>(ctx, code, slot, fuel, calls, table, op)
}

/// The register that holds the base address of the load or store `OP`.
#[inline(always)]
fn base_reg<const OP: u8>(insn: View) -> Reg {
    match OpCode(OP).class() {
        Class::LdReg => insn.src_reg(),
        _ => insn.dst_reg(),
    }
}
