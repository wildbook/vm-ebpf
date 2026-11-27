//! The [`Interpreter`]: what runs a [`Code`] on a [`Context`], and what it keeps from one run to the next.

use std::mem::MaybeUninit;
use std::ptr;

use crate::args::{self, Row, StackArgs};
use crate::code::{Slots, ThreadedSlot};
use crate::context::FP;
use crate::dispatch::SPARE;
#[cfg(not(feature = "fuel"))]
use crate::fuel::RestsPtr;
#[cfg(feature = "fuel")]
use crate::fuel::{Fuel, Metered};
use crate::fuel::{FuelLeft, Meter};
use crate::native::NativeCall;
#[cfg(feature = "ffi")]
use crate::native::NativeFail;
#[cfg(feature = "fuel")]
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::windows::Windows;
use crate::{Code, Context, Host, Memory};

/// Maximum nesting of local calls below the entry frame.
pub const MAX_CALL_DEPTH: usize = 8;

/// Sentinel return pc pushed by [`Interpreter::begin_nested`] / [`Interpreter::call_nested`].
/// Every real code has fewer than 2^31 slots, so `exit` popping `RETURN_PC - 1` stops at `RETURN_PC`.
#[cfg(feature = "callbacks")]
pub const RETURN_PC: u64 = u64::MAX;

/// Whether an [`Interpreter`] can meter fuel (`Interpreter::set_limit`), which the `fuel` feature decides.
pub const METERED: bool = cfg!(feature = "fuel");

/// Where and why a run stopped; `E` is the error type of the memory, [`Memory::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Stop<E> {
    pub reason: Reason<E>,
    /// The instruction that stopped the run, or that could not run ([`Reason::OutOfFuel`], [`Reason::BadPc`]).
    pub pc: u64,
}

/// Why a run stopped; `E` is the error type of the memory, [`Memory::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason<E> {
    /// `exit` in the entry frame, with the result in r0.
    Exit,

    /// A call of the helper with this ID, which [`Host::call_helper`] declined.
    CallHelper(u32),
    /// A call of the external function with this ID, which [`Host::call_kfunc`] declined, or a native call of this
    /// index past the end of [`Host::natives`].
    CallKfunc(u32),
    /// `callx`: a call through this address, which [`Host::call_indirect`] declined or resolved to a pc outside the
    /// code.
    CallIndirect(u64),
    /// `gotox`: a jump to this address, which the caller of the run decodes. The run continues where it resumes.
    JumpIndirect(u64),

    /// An invalid or reserved instruction, or one that [`Code::new`] fails.
    InvalidInstruction,
    /// A valid instruction that the interpreter doesn't implement.
    Unsupported,
    /// A load or store, or a pointer argument of a checked native call, that the memory failed with this error.
    MemoryFault(E),
    /// The fuel ran out before the instruction at `pc`. Only a metered run stops with it.
    OutOfFuel,
    /// A pc outside the code.
    BadPc,
    /// A local call found all [`MAX_CALL_DEPTH`] frames in use, or r10 below the frame size.
    StackOverflow,
    /// An aware native call failed via [`fail_code`](crate::fail_code) or [`fail_error`](crate::fail_error).
    #[cfg(feature = "ffi")]
    NativeFailed,
}

/// Runs code, and keeps what lasts from one run to the next: the frames of the local calls in progress, their stack
/// arguments, the [`Host`], the fuel, and the windows into the memory of `M` that plain loads and stores use.
///
/// [`run`](Self::run) starts a call and [`resume`](Self::resume) continues it after a stop that the caller handled.
/// Both stay inside the chain of handlers through ALU, memory and jump instructions, local calls and their returns,
/// and the helper, kfunc and `callx` calls that the host runs or resolves, so each of those costs a single dispatch.
/// They stop at the instruction that needs the caller: a call that the host declined, a `gotox`, the `exit` of the
/// entry frame, or a fault.
// `repr(C)` puts the hot fuel counter at offset 0 (zero displacement in `Fuel::enter`), followed by `depth`,
// `frame_size`, `stop` and `windows.stack` within one byte displacement (0..128), then `meter` and `host` ahead of
// `frames` and `args`.
#[repr(C)]
pub struct Interpreter<M: Memory, H> {
    /// The fuel left in the run in progress (zero-sized without the `fuel` feature).
    pub(crate) fuel: FuelLeft,
    depth: usize,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
    pub(crate) stop: StopRecord<M::Error>,
    pub(crate) windows: Windows,
    /// The fuel limit configuration and dispatch table.
    pub(crate) meter: Meter<M, H>,
    /// The host that runs the guest's calls of host functions.
    pub host: H,

    /// `frames[..depth]` are initialised.
    frames: [MaybeUninit<Frame>; MAX_CALL_DEPTH],
    /// The stack arguments by call depth: the frame at `depth` received those in `args[depth]`, and stores those of
    /// the calls it makes in `args[depth + 1]`. The entry frame is at depth 0, and `push` keeps `depth` at or below
    /// [`MAX_CALL_DEPTH`].
    args: [Row; MAX_CALL_DEPTH + 2],
    /// Failure payload from an aware native call that stopped with [`Reason::NativeFailed`].
    #[cfg(feature = "ffi")]
    native_fail: Option<NativeFail>,
    /// Base slot address of the `Code` that `frames[..depth]` point into, recorded whenever live frames outlive a run.
    frame_code_first: usize,
}

/// Caller state saved across a local call.
// Aligned to 16 bytes: `call` and `exit` move the registers 16 bytes at a time, and a move that crosses a cache line
// costs them several cycles.
#[repr(align(16))]
struct Frame {
    /// r6-r9 (callee-saved) and r10 (frame pointer).
    regs: [u64; 5],
    /// Return slot in `0..=len` of the code, or a tagged odd sentinel for `RETURN_PC` or an out-of-range pc.
    return_ip: ReturnIp,
}

/// A saved return [`Ip`] in [`Frame`].
#[derive(Clone, Copy)]
#[repr(transparent)]
struct ReturnIp(Ip);

// SAFETY: a `ReturnIp` is only dereferenced while `&Code` is borrowed during `run`/`resume`, and `resume` re-derives
// every live frame pointer from the current `&Code`.
unsafe impl Send for ReturnIp {}
unsafe impl Sync for ReturnIp {}

/// Odd sentinel return ip pushed by `begin_nested`; `exit_special` decodes `addr >> 1 == 0` as [`RETURN_PC`].
#[cfg(feature = "callbacks")]
const NESTED_RETURN: Ip = Ip(ptr::without_provenance(1));

impl<M: Memory, H: Host<M>> Interpreter<M, H> {
    /// An interpreter that gives each callee of a local call `frame_size` bytes below its caller's r10, and whose
    /// runs have no fuel limit.
    #[inline]
    pub fn new(frame_size: u64, host: H) -> Self {
        Self {
            fuel: FuelLeft::default(),
            depth: 0,
            frame_size,
            stop: StopRecord::NONE,
            windows: Windows::EMPTY,
            meter: Meter::default(),
            host,
            frames: [const { MaybeUninit::uninit() }; MAX_CALL_DEPTH],
            args: [[0; args::MAX_STACK_ARGS + 1]; MAX_CALL_DEPTH + 2],
            #[cfg(feature = "ffi")]
            native_fail: None,
            frame_code_first: 0,
        }
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn set_native_fail(&mut self, fail: NativeFail) {
        self.native_fail = Some(fail);
    }

    /// Take the failure recorded by an aware native call that stopped with [`Reason::NativeFailed`].
    #[cfg(feature = "ffi")]
    pub fn take_native_fail(&mut self) -> Option<NativeFail> {
        self.native_fail.take()
    }

    /// Starts a call at `pc` of `code`, in the entry frame, and runs until an instruction that the caller must
    /// handle. With a limit ([`limit`](Self::limit)), the call starts with that much fuel.
    ///
    /// A call that stopped inside a local call leaves its frames behind; `run` drops them.
    #[inline]
    pub fn run(&mut self, ctx: &mut Context<M>, code: &Code, pc: u64) -> Stop<M::Error> {
        self.depth = 0;
        self.meter.start(&mut self.fuel);
        self.enter(ctx, code, pc, true)
    }

    /// Continues the call at `pc` of `code`, with the frames and the fuel that the last stop left.
    #[inline]
    pub fn resume(&mut self, ctx: &mut Context<M>, code: &Code, pc: u64) -> Stop<M::Error> {
        self.enter(ctx, code, pc, false)
    }

    /// Push a nested callback frame returning to [`RETURN_PC`], copy `args` into r1 to r5, and return the previous
    /// call depth, or `None` on [`Reason::StackOverflow`].
    #[cfg(feature = "callbacks")]
    pub fn begin_nested(&mut self, ctx: &mut Context<M>, args: &[u64; 5]) -> Option<usize> {
        let entry_depth = self.depth;
        if !self.push(&mut ctx.regs, NESTED_RETURN) {
            return None;
        }
        ctx.regs[1..=5].copy_from_slice(args);
        Some(entry_depth)
    }

    /// Restore call frames and callee-saved registers back to `entry_depth` after a nested callback stops early.
    #[cfg(feature = "callbacks")]
    pub fn abort_nested(&mut self, ctx: &mut Context<M>, entry_depth: usize) {
        while self.depth > entry_depth {
            self.pop(&mut ctx.regs);
        }
    }

    /// Run the guest function at `pc` of `code` inside a run that is already in progress, sharing its registers,
    /// stack, and fuel. Returns the callee's r0 on normal `exit`, or restores frames to entry depth and returns the
    /// stop on any fault, fuel exhaustion, or host stop.
    #[cfg(feature = "callbacks")]
    pub fn call_nested(
        &mut self,
        ctx: &mut Context<M>,
        code: &Code,
        pc: u64,
        args: &[u64; 5],
    ) -> Result<u64, Stop<M::Error>> {
        let Some(entry_depth) = self.begin_nested(ctx, args) else {
            return Err(Stop {
                reason: Reason::StackOverflow,
                pc,
            });
        };
        if pc == RETURN_PC {
            self.abort_nested(ctx, entry_depth);
            return Err(Stop {
                reason: Reason::BadPc,
                pc,
            });
        }
        let stop = self.resume(ctx, code, pc);
        if stop.pc == RETURN_PC && matches!(stop.reason, Reason::BadPc | Reason::OutOfFuel) {
            return Ok(ctx.regs[0]);
        }
        self.abort_nested(ctx, entry_depth);
        Err(stop)
    }

    /// Runs `code` from `pc`, for a call that starts there if `fresh` and one that resumes if not.
    #[inline(always)]
    fn enter(&mut self, ctx: &mut Context<M>, code: &Code, pc: u64, fresh: bool) -> Stop<M::Error> {
        self.windows.revalidate(ctx.memory);
        let table = self.meter.table();
        let slots = code.threaded(table);
        if !fresh && self.depth != 0 {
            self.rebase_frames(slots);
        }

        if pc >= slots.total_len() as u64 {
            return self.outside(pc, fresh);
        }
        let ip = Ip::at(slots, pc);

        #[cfg(feature = "fuel")]
        let (rests, is_short) = self
            .meter
            .enter_block(&mut self.fuel, code.raw_slots(), code.rests(), pc);
        #[cfg(not(feature = "fuel"))]
        let (rests, is_short) = (RestsPtr::NULL, false);

        if is_short {
            #[cfg(feature = "fuel")]
            Metered::step(ctx, slots, ip, self, rests, SPARE, Slot::UNREAD);
        } else {
            // SAFETY: `pc < slots.total_len()`, so `ip` lies in `slots`, built for `<M, H>`.
            let (next, slot) = unsafe { ip.fetch::<M, H>() };
            next(ctx, slots, ip, self, rests, SPARE, slot);
        }

        // Test the tag alone first: the handler stored the reason one field at a time, and a single load of the whole
        // reason can't take its bytes from several stores, so it waits for them to reach the cache. Each arm builds
        // its own `Stop`, so that a caller that only tests for `Exit` runs no more of this function than the test.
        match self.stop.reason {
            Reason::Exit => Stop {
                reason: Reason::Exit,
                pc: self.stop.pc(slots),
            },
            _ => self.stopped(code),
        }
    }

    /// The stop of a run of `code` that didn't end with [`Reason::Exit`].
    // Out of line and from the code, not its slots: a caller then keeps nothing of the slots across the chain of
    // handlers, which saves no registers.
    #[cold]
    #[inline(never)]
    fn stopped(&mut self, code: &Code) -> Stop<M::Error> {
        let slots = code.threaded(self.meter.table());
        if self.depth != 0 {
            self.frame_code_first = slots.first().addr();
        }
        self.meter
            .settle(&mut self.fuel, slots, self.stop.ip(slots), &mut self.stop.reason);
        Stop {
            pc: self.stop.pc(slots),
            // moved out, as the error of the memory needn't be `Copy`
            reason: std::mem::replace(&mut self.stop.reason, Reason::Exit),
        }
    }

    /// Record the base address of `code` before an aware native call that may re-enter through `resume`.
    #[cfg(feature = "callbacks")]
    #[inline(always)]
    pub(crate) fn record_frame_code(&mut self, code: Slots) {
        if self.depth != 0 {
            self.frame_code_first = code.first().addr();
        }
    }

    /// Re-derive live return pointers from `code` so `resume` stays sound across `&mut Code` or a different `Code`.
    #[cold]
    #[inline(never)]
    fn rebase_frames(&mut self, code: Slots) {
        let new_first = code.first();
        let new_len = code.len();
        let old_first = self.frame_code_first;
        for frame in &mut self.frames[..self.depth] {
            // SAFETY: `frames[..self.depth]` are initialised.
            let frame = unsafe { frame.assume_init_mut() };
            let addr = frame.return_ip.0.addr();
            if addr & 1 != 0 {
                continue;
            }
            let pc = addr.wrapping_sub(old_first) / size_of::<ThreadedSlot>();
            frame.return_ip = if pc <= new_len {
                ReturnIp(Ip(new_first.wrapping_add(pc)))
            } else {
                ReturnIp(Ip(ptr::without_provenance((pc << 1) | 1)))
            };
        }
        self.frame_code_first = new_first.addr();
    }

    /// Stop at a tagged sentinel return ip (`RETURN_PC` from `begin_nested`, or an out-of-range pc after a code swap).
    // Inlined into `jump<EXIT>` so the hot return path calls no function and needs no stack frame.
    #[inline(always)]
    pub(crate) fn exit_special(&mut self, return_ip: Ip) {
        let pc = match return_ip.addr() >> 1 {
            #[cfg(feature = "callbacks")]
            0 => RETURN_PC,
            pc => pc as u64,
        };
        self.stop.at_pc(pc, Reason::BadPc);
    }

    /// The stop of a call that starts or resumes at a `pc` outside the code.
    #[cold]
    fn outside(&mut self, pc: u64, fresh: bool) -> Stop<M::Error> {
        let reason = self.meter.outside(&mut self.fuel, fresh);
        Stop { reason, pc }
    }

    /// Meter every [`run`](Self::run) from now on with `limit` units of fuel, at most `i64::MAX`, or none: each
    /// instruction it runs takes one unit, LD_IMM64 one per slot, and it stops with [`Reason::OutOfFuel`] at the
    /// first instruction it has no unit for. LD_IMM64 with one unit left stops with that unit.
    ///
    /// The handlers charge the units of a whole basic block as they enter it, but a run stops and reports its fuel
    /// exactly where charging each instruction would.
    #[cfg(feature = "fuel")]
    pub fn set_limit(&mut self, limit: Option<u64>) {
        (self.meter, self.fuel) = Meter::new(limit);
    }

    /// The fuel each [`run`](Self::run) starts with, if runs are metered.
    pub fn limit(&self) -> Option<u64> {
        self.meter.limit()
    }

    /// The fuel that the last stop left, if runs are metered.
    pub fn fuel(&self) -> Option<u64> {
        self.meter.left(&self.fuel)
    }

    /// Set the fuel that the next [`resume`](Self::resume) continues with, at most `i64::MAX`. It has no effect on
    /// runs that aren't metered.
    pub fn set_fuel(&mut self, fuel: u64) {
        self.meter.set_left(&mut self.fuel, fuel);
    }

    /// Save the caller's state with `return_ip` (the slot after `call`, in `0..=len`, or a tagged odd sentinel) and
    /// give the callee its stack frame. Returns false, changing nothing, on a [`Reason::StackOverflow`].
    #[inline(always)]
    #[must_use]
    pub(crate) fn push(&mut self, regs: &mut [u64; 16], return_ip: Ip) -> bool {
        let Some(frame) = self.frames.get_mut(self.depth) else {
            return false;
        };
        let Some(callee_fp) = regs[FP].checked_sub(self.frame_size) else {
            return false;
        };
        frame.write(Frame {
            regs: [regs[6], regs[7], regs[8], regs[9], regs[FP]],
            return_ip: ReturnIp(return_ip),
        });
        self.depth += 1;
        regs[FP] = callee_fp;
        true
    }

    /// Restore the caller's state and return its saved return ip, or `None` in the entry frame.
    #[inline(always)]
    pub(crate) fn pop(&mut self, regs: &mut [u64; 16]) -> Option<Ip> {
        // depth 0 wraps and fails the bounds check
        let depth = self.depth.wrapping_sub(1);
        let frame = self.frames.get(depth)?;
        // SAFETY: `depth` is below `self.depth`, and `push` wrote every frame up to it
        let frame = unsafe { frame.assume_init_ref() };
        regs[6..=FP].copy_from_slice(&frame.regs);
        self.depth = depth;
        Some(frame.return_ip.0)
    }

    /// The stack arguments that the entry frame of each [`run`](Self::run) receives: argument `5 + k` at index
    /// `k - 1`. A new interpreter holds 0 in each, and no run changes them.
    pub fn entry_args(&mut self) -> &mut StackArgs {
        args::slots_mut(&mut self.args[0])
    }

    /// The stack arguments of the frame in progress as it stored them last, for the caller of a run that stopped at a
    /// call of that frame.
    pub fn stack_args(&self) -> &StackArgs {
        args::slots(&self.args[self.depth + 1])
    }

    /// The stack arguments that the frame in progress received.
    #[inline(always)]
    pub(crate) fn incoming(&self) -> &Row {
        &self.args[self.depth]
    }

    /// The stack arguments of the calls that the frame in progress makes.
    #[inline(always)]
    pub(crate) fn outgoing(&mut self) -> &mut Row {
        &mut self.args[self.depth + 1]
    }

    /// [`stack_args`](Self::stack_args), with the host that takes them.
    #[inline(always)]
    pub(crate) fn stack_args_and_host(&mut self) -> (&StackArgs, &mut H) {
        (args::slots(&self.args[self.depth + 1]), &mut self.host)
    }

    /// The host and what it calls a native function with, for the `callx` at `ip`: with the stack arguments of the
    /// frame in progress if `stack`.
    #[inline(always)]
    pub(crate) fn callx(&mut self, ip: Ip, stack: bool) -> (&mut H, NativeCall<'_, M::Error>) {
        let stack = stack.then(|| args::slots(&self.args[self.depth + 1]));
        (&mut self.host, NativeCall::new(&mut self.stop, ip, stack))
    }
}

/// Where and why the chain of handlers stopped. The handler that ends the chain writes it, and the interpreter makes
/// the [`Stop`] of the run from it. A `callx` of a native function writes it too, before the call.
pub struct StopRecord<E> {
    /// The address of the slot it stopped at, or 0 if it stopped at `pc`.
    slot: usize,
    pc: u64,
    /// [`Reason::Exit`] where no chain has stopped since the interpreter took the last one, unless a `callx` called a
    /// native function since.
    reason: Reason<E>,
}

impl<E> StopRecord<E> {
    const NONE: Self = Self {
        slot: 0,
        pc: 0,
        reason: Reason::Exit,
    };

    /// Stop at `ip`, the ip of the handler.
    #[inline(always)]
    pub fn at(&mut self, ip: Ip, reason: Reason<E>) {
        core::hint::cold_path();
        (self.slot, self.reason) = (ip.addr(), reason);
    }

    /// Record the `callx` at `ip` that is about to call the native function at `target`. Only a debugger reads the
    /// record, to find the guest instruction behind a call that crashed: the handler that ends the chain replaces it.
    #[inline(always)]
    pub fn calling(&mut self, ip: Ip, target: u64) {
        (self.slot, self.reason) = (ip.addr(), Reason::CallIndirect(target));
    }

    /// Stop at `pc`, which may lie outside the code.
    #[inline(always)]
    pub fn at_pc(&mut self, pc: u64, reason: Reason<E>) {
        core::hint::cold_path();
        (self.slot, self.pc, self.reason) = (0, pc, reason);
    }

    /// The pc it stopped at, in the slots `code` of the code it ran.
    #[inline(always)]
    fn pc(&self, code: Slots) -> u64 {
        match self.slot {
            0 => self.pc,
            slot => code.pc_at(slot),
        }
    }

    /// The ip it stopped at in `code`, unless it stopped at a pc.
    fn ip(&self, code: Slots) -> Option<Ip> {
        (self.slot != 0).then(|| Ip::at(code, code.pc_at(self.slot)))
    }
}
