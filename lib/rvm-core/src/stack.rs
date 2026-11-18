//! Loads and stores through r10 that skip the [`Memory`] methods.
//!
//! [`Code::new`](crate::Code::new) gives each 4 and 8 byte `ldx`, `stx` and `st` with base register r10 an opcode byte
//! of its own. Its handler, [`access`], checks the address against the [`Window`] that the memory reports around r10
//! and accesses the host memory directly. An address outside the window takes the usual handler of the instruction, so
//! the access behaves exactly as it does there. Guest code can't write r10, so it stays in the stack, inside the window
//! of the stack.

use std::ptr;

use crate::opcode::{Class, MemSize, OpCode};
use crate::transfer::Slot;
use crate::{fetch, CallStack, Context, Flow, Handlers, Host, Instruction, Memory, Table};

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

/// The [`Window`] that [`access`] checks addresses against, kept in the [`CallStack`].
pub struct Cache {
    base: u64,
    ptr: *mut u8,
    /// By [`kind`]: the number of offsets from `base` at which the access fits in the window. All 0 when `epoch` is 0.
    fits: [u64; 4],
    epoch: u64,
}

// SAFETY: `access` dereferences `ptr` only through `&mut CallStack`, while the memory that `run` was given is at
// `epoch`. Only one memory ever takes an epoch (see `Memory`), so the pointer is only used together with the memory it
// points into, on whichever thread holds that memory.
unsafe impl Send for Cache {}
unsafe impl Sync for Cache {}

impl Cache {
    pub const STALE: Self = Self {
        base: 0,
        ptr: ptr::null_mut(),
        fits: [0; 4],
        epoch: 0,
    };

    /// Forget the window unless `memory` is still at its epoch; [`run`](crate::run) calls this whenever code outside
    /// the handler chain may have changed the memory.
    #[inline(always)]
    pub fn revalidate<M: Memory>(&mut self, memory: &M) {
        // a window of epoch 0 is empty
        if self.epoch != 0 && memory.epoch() != self.epoch {
            core::hint::cold_path();
            *self = Self::STALE;
        }
    }

    fn refresh(&mut self, window: Window) {
        let fits = |len: u64, size: u64| len.saturating_sub(size - 1);
        self.base = window.base;
        self.ptr = window.ptr;
        self.fits = [
            fits(window.read_len, 4),
            fits(window.read_len, 8),
            fits(window.write_len, 4),
            fits(window.write_len, 8),
        ];
        self.epoch = window.epoch;
    }
}

/// The index into [`Cache::fits`] for the access `opc`.
const fn kind(opc: OpCode) -> usize {
    let store = !matches!(opc.class(), Class::LdReg);
    let size = match opc.mem_size() {
        MemSize::Word => 0,
        MemSize::DWord => 1,
        MemSize::Byte | MemSize::Half => panic!("no r10 access of this size"),
    };
    2 * store as usize + size
}

/// The handler of the r10 access that stands for the load or store `OP`.
#[inline(never)]
pub extern "rust-preserve-none" fn access<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    insn: Instruction,
    code: &[Instruction],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
) {
    let opc = OpCode(OP);
    let kind = const { kind(OpCode(OP)) };

    let addr = ctx.regs[10].wrapping_add_signed(i64::from(insn.offset()));
    let at = addr.wrapping_sub(calls.stack.base);
    if at >= calls.stack.fits[kind] {
        become miss::<M, H, FUEL, OP>(ctx, insn, code, slot, fuel, calls, table)
    }

    // SAFETY: the access fits in the window at `at`, and the window is still valid
    let host = unsafe { calls.stack.ptr.add(at as usize) };
    let value = match opc.class() {
        Class::StReg => ctx.regs[usize::from(insn.src_reg())],
        _ => i64::from(insn.imm()) as u64,
    };
    let dst = usize::from(insn.dst_reg());
    // SAFETY: as above
    unsafe {
        match (opc.class(), opc.mem_size()) {
            (Class::LdReg, MemSize::Word) => ctx.regs[dst] = u32::from_le(host.cast::<u32>().read_unaligned()).into(),
            (Class::LdReg, _) => ctx.regs[dst] = u64::from_le(host.cast::<u64>().read_unaligned()),
            (_, MemSize::Word) => host.cast::<u32>().write_unaligned((value as u32).to_le()),
            (_, _) => host.cast::<u64>().write_unaligned(value.to_le()),
        }
    }

    let slot = slot.offset(1);
    // SAFETY: the slots from `len` on hold the guard, so this handler ran below `len` (see `Slot`)
    match unsafe { fetch::<M, H, FUEL>(table, slot, fuel) } {
        Some((next, insn, fuel)) => become next(ctx, insn, code, slot, fuel, calls, table),
        None => calls.stop.at(slot, 0, Flow::OutOfFuel),
    }
}

/// Takes the window around r10 and runs the access with its usual handler.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn miss<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    insn: Instruction,
    code: &[Instruction],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
) {
    // the frame is the bytes below r10
    calls.stack.refresh(ctx.data.window(ctx.regs[10].wrapping_sub(1)));
    let usual = const { Handlers::<M, H, FUEL>::TABLE.0[OP as usize] };
    become usual(ctx, insn, code, slot, fuel, calls, table)
}
