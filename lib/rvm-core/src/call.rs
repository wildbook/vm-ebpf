use std::mem::MaybeUninit;

use crate::op::Op;
use crate::transfer::{self, Slot};
use crate::{stack, Context, Flow, Memory};

/// Host functions the `call` and `callx` handlers run without leaving [`run`](crate::run).
///
/// Each method gets the arguments in `ctx.regs[1..=5]` and returns the new r0. It returns `None` to stop
/// [`run`](crate::run) at the call with [`Flow::CallHelper`], [`Flow::CallKfunc`] or [`Flow::CallIndirect`], having
/// recorded whatever its caller needs to handle that. `fuel` is what the caller has left, with the call charged; a host
/// function that runs guest code takes what that code ran from it, and `run` continues with the rest. Without the
/// `fuel` feature it means nothing.
pub trait Host<M: Memory> {
    /// Call helper `id` (`src_reg = 0`).
    fn helper(&mut self, ctx: &mut Context<M>, id: u32, fuel: &mut u64) -> Option<u64>;
    /// Call external function `id` (`src_reg = BPF_PSEUDO_KFUNC_CALL`).
    fn kfunc(&mut self, ctx: &mut Context<M>, id: u32, fuel: &mut u64) -> Option<u64>;
    /// Call through `target`, the address in the `dst_reg` of a `callx`: name the guest function it addresses, or run
    /// the host function it addresses.
    fn callx(&mut self, ctx: &mut Context<M>, target: u64, fuel: &mut u64) -> Option<Callee>;
}

/// What a `callx` calls, as [`Host::callx`] resolves its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Callee {
    /// The guest function at this pc, which [`run`](crate::run) enters as it does a local call. A pc outside the code
    /// stops `run` at the `callx` with [`Flow::CallIndirect`].
    Local(u64),
    /// A host function that [`Host::callx`] ran, which returned this r0.
    Host(u64),
}

/// Maximum nesting of BPF-to-BPF calls below the entry frame.
pub const MAX_CALL_DEPTH: usize = 8;

/// The BPF-to-BPF calls in progress, which [`run`](crate::run) pushes and pops, the record of where and why it stopped,
/// the windows that 4 and 8 byte loads and stores use, and the [`Host`] that runs its helper, kfunc and `callx` calls.
/// `E` is the error type of the memory, [`Memory::Err`].
// `repr(C)` keeps the scalars ahead of the frames, so every handler reaches all of them but the last fields of the
// windows with a one-byte displacement.
#[repr(C)]
pub struct CallStack<H, E> {
    depth: usize,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
    pub(crate) stop: Stop<E>,
    pub(crate) windows: stack::Windows,
    pub host: H,

    /// `frames[..depth]` are initialised.
    frames: [MaybeUninit<Frame>; MAX_CALL_DEPTH],
}

/// Caller state saved across a BPF-to-BPF call.
struct Frame {
    /// r6-r9 (callee-saved) and r10 (frame pointer).
    regs: [u64; 5],
    /// The pc of the `call`.
    call_pc: u64,
}

impl<H, E> CallStack<H, E> {
    /// An empty call stack giving each callee `frame_size` bytes below its caller's r10.
    #[inline]
    pub fn new(frame_size: u64, host: H) -> Self {
        Self {
            depth: 0,
            frame_size,
            stop: Stop {
                slot: 0,
                pc: 0,
                fuel: 0,
                flow: Flow::Next,
            },
            windows: stack::Windows::EMPTY,
            host,
            frames: [const { MaybeUninit::uninit() }; MAX_CALL_DEPTH],
        }
    }

    /// Drop the frames of local calls in progress, which a call that stopped inside a callee leaves behind, so that
    /// the next [`run`](crate::run) starts in the entry frame.
    #[inline]
    pub fn clear(&mut self) {
        self.depth = 0;
    }

    /// Save the caller's state for the call at `call_pc` and give the callee its stack frame. Returns false, changing
    /// nothing, on a [`Flow::StackOverflow`].
    #[inline(always)]
    #[must_use]
    pub(crate) fn push(&mut self, regs: &mut [u64; 16], call_pc: u64) -> bool {
        let Some(frame) = self.frames.get_mut(self.depth) else {
            return false;
        };
        let Some(callee_fp) = regs[10].checked_sub(self.frame_size) else {
            return false;
        };
        frame.write(Frame {
            regs: [regs[6], regs[7], regs[8], regs[9], regs[10]],
            call_pc,
        });
        self.depth += 1;
        regs[10] = callee_fp;
        true
    }

    /// Restore the caller's state and return the pc of its `call`, or `None` in the entry frame.
    #[inline(always)]
    pub(crate) fn pop(&mut self, regs: &mut [u64; 16]) -> Option<u64> {
        // depth 0 wraps and fails the bounds check
        let depth = self.depth.wrapping_sub(1);
        let frame = self.frames.get(depth)?;
        // SAFETY: `depth` is below `self.depth`, and `push` wrote every frame up to it
        let frame = unsafe { frame.assume_init_ref() };
        regs[6..=10].copy_from_slice(&frame.regs);
        self.depth = depth;
        Some(frame.call_pc)
    }
}

/// Where and why [`run`](crate::run) stopped, written once when execution leaves the handler chain.
pub struct Stop<E> {
    /// The address of the slot it stopped at, or 0 if it stopped at `pc`.
    slot: usize,
    pc: u64,
    pub fuel: u64,
    pub flow: Flow<E>,
}

impl<E> Stop<E> {
    #[inline(always)]
    pub fn at(&mut self, slot: Slot, fuel: u64, flow: Flow<E>) {
        core::hint::cold_path();
        (self.slot, self.fuel, self.flow) = (slot.addr(), fuel, flow);
    }

    /// Stop at `pc`, which may lie outside the code.
    #[inline(always)]
    pub fn at_pc(&mut self, pc: u64, fuel: u64, flow: Flow<E>) {
        core::hint::cold_path();
        (self.slot, self.pc, self.fuel, self.flow) = (0, pc, fuel, flow);
    }

    /// The pc it stopped at, in the slots `code` of the code it ran.
    #[inline(always)]
    pub fn pc(&self, code: &[Op]) -> u64 {
        match self.slot {
            0 => self.pc,
            slot => transfer::pc_at(slot, code),
        }
    }
}
