//! Fuel: the instruction budget of a metered run.
//!
//! A run is metered if the [`Interpreter`] has a limit. It then reports fuel as if it charged one unit per slot
//! before running it, and stops with [`Reason::OutOfFuel`](crate::Reason::OutOfFuel) at the first slot it has no unit
//! for. A run without a limit runs through [`Tables::PLAIN`](crate::dispatch::Tables::PLAIN) (or
//! [`Tables::FLAT_PLAIN`](crate::dispatch::Tables::FLAT_PLAIN)), and nothing in it or in its [`Code`](crate::Code) is
//! there for fuel.
//!
//! # Fuel charged per block
//!
//! The handlers charge the units per block. A block ends at the first slot at or after it whose handler may continue
//! at a slot other than the next one: a jump-class instruction (jumps, calls, `exit`, `gotox`, `may_goto`), a
//! [`FAR`](crate::transfer::FAR) jump, or the [`GUARD`](crate::transfer::GUARD). Every other handler continues at the
//! next slot of its block, or after the second slot of LD_IMM64, which lies in it too. A superinstruction or folded
//! 3-operand ALU pair lies in one block, and a block may hold jump targets. The `rest` of a slot is the number of
//! slots from it to the end of its block, inclusive; the first metered run of a code computes the `rest` of each of
//! its slots (`Rests`).
//!
//! If the fuel before `t` is at least `rest(t)`, the fuel stays at or above 0 up to the end of the block, and no
//! handler tests it. Otherwise [`Fuel::step`] runs the original unfused slots from `t` on one at a time in a cold loop
//! and stops where charging per slot runs out. That happens before the last slot of the block, whose `rest` is 1, so
//! no handler that ends a block runs this way.

use std::ptr;

use crate::code::Slots;
use crate::dispatch::Spare;
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{Context, Host, Interpreter, Memory};

/// Pointer to a code's `rest` array carried in `RSI` during a metered run (null when unmetered). Kept at pointer size
/// even without the `fuel` feature so `Slot` stays in `RCX` under `rust-preserve-none`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct RestsPtr(pub *const u32);

impl RestsPtr {
    pub const NULL: Self = Self(ptr::null());
}

/// What a handler that ends a block does for fuel where it continues.
pub trait Fuel {
    /// Enters the block of `ip` in `code` there: charges it to the fuel of `interp`. False if the fuel can't pay for
    /// the block; [`step`](Self::step) then runs the block one instruction at a time until fuel runs out.
    fn enter<M: Memory, H>(interp: &mut Interpreter<M, H>, code: Slots, ip: Ip, rests: RestsPtr) -> bool;

    /// A [`Handler`](crate::dispatch::Handler) that steps unfused instructions from `ip` in a block entered with too
    /// little fuel for it, stopping where fuel runs out or an instruction stops.
    extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
        ctx: &mut Context<M>,
        code: Slots,
        ip: Ip,
        interp: &mut Interpreter<M, H>,
        rests: RestsPtr,
        spare: Spare,
        slot: Slot,
    );
}

/// No fuel: the handlers of a run without a limit.
pub struct Unmetered;

impl Fuel for Unmetered {
    #[inline(always)]
    fn enter<M: Memory, H>(_: &mut Interpreter<M, H>, _: Slots, _: Ip, _: RestsPtr) -> bool {
        true
    }

    extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
        _: &mut Context<M>,
        _: Slots,
        _: Ip,
        _: &mut Interpreter<M, H>,
        _: RestsPtr,
        _: Spare,
        _: Slot,
    ) {
        unreachable!("no block is short of fuel")
    }
}

#[cfg(feature = "fuel")]
pub use metered::{FuelLeft, Meter, Metered, Rests};
#[cfg(not(feature = "fuel"))]
pub use unmetered::{FuelLeft, Meter};

#[cfg(feature = "fuel")]
mod metered {
    use std::ptr::{self, NonNull};
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    use super::*;
    use crate::dispatch::{self, DispatchTable, Tables};
    use crate::handler::{TO_GUEST, TO_HOST};
    use crate::opcode::{OpCode, LD_IMM64};
    use crate::slot::{Fields, Shape, View};
    use crate::step::{self, Regs, Step};
    use crate::transfer::{self, FAR, GUARD};
    use crate::{args, bytes, fuse, Reason};

    /// The fuel left in the run in progress, placed at offset 0 of [`Interpreter`] so `Fuel::enter` reaches it with
    /// zero displacement while `windows.stack` stays within one-byte displacement.
    #[repr(transparent)]
    #[derive(Default)]
    pub struct FuelLeft(pub(super) u64);

    impl<M: Memory, H: Host<M>> Tables<M, H> {
        /// The metered dispatch table.
        pub const METERED: DispatchTable<M, H> = dispatch::table::<M, H, Metered>();
    }

    /// Exact fuel, charged per block as the [module](super) describes.
    pub struct Metered;

    impl Fuel for Metered {
        #[inline(always)]
        fn enter<M: Memory, H>(interp: &mut Interpreter<M, H>, code: Slots, ip: Ip, rests: RestsPtr) -> bool {
            let pc = ip.pc(code) as usize;
            // SAFETY: `ip` lies in `code`, and `rests` points to `code.total_len()` entries initialised before entry.
            let rest = u64::from(unsafe { *rests.0.add(pc) });
            interp.fuel.0 = interp.fuel.0.wrapping_sub(rest);
            !short(interp.fuel.0)
        }

        /// Steps unfused instructions from `ip` until fuel runs out or an instruction faults/stops.
        ///
        /// Because `before < rest(ip)` and `rest` counts to the block-ending instruction inclusive (whose `rest` is 1),
        /// fuel is guaranteed to exhaust before any block-ending instruction can run.
        #[cold]
        #[inline(never)]
        extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
            ctx: &mut Context<M>,
            code: Slots,
            ip: Ip,
            interp: &mut Interpreter<M, H>,
            rests: RestsPtr,
            _: Spare,
            _: Slot,
        ) {
            if interp.is_promoted() {
                interp.flush_promoted(ctx);
            }
            let mut pc = ip.pc(code);
            // SAFETY: `ip` lies in `code`, and `rests` points to `code.total_len()` entries.
            let mut fuel = interp
                .fuel
                .0
                .wrapping_add(u64::from(unsafe { *rests.0.add(pc as usize) }));
            loop {
                let raw = code.raw_slot(pc).expect("short-block pc lies in code");
                let alone = ALONE[usize::from(raw.byte())];
                let units = match alone {
                    LD_IMM64 => 2,
                    _ => 1,
                };
                if fuel < units {
                    // LD_IMM64 with one unit left keeps it
                    interp.fuel.0 = fuel;
                    return interp.stop.at(Ip::at(code, pc), Reason::OutOfFuel);
                }

                let stop_reason = match alone {
                    TO_HOST => {
                        // SAFETY: `raw` has byte `TO_HOST`, whose layout matches `Shape::of(TO_HOST)`.
                        let insn = unsafe { View::new(&raw, Some(raw), const { Shape::of(TO_HOST) }) };
                        let dst = ctx.memory.host_address(ctx.regs.get(insn.src_reg()));
                        ctx.regs.set(insn.dst_reg(), dst);
                        None
                    }
                    TO_GUEST => {
                        // SAFETY: `raw` has byte `TO_GUEST`, whose layout matches `Shape::of(TO_GUEST)`.
                        let insn = unsafe { View::new(&raw, Some(raw), const { Shape::of(TO_GUEST) }) };
                        let dst = ctx.memory.guest_address(ctx.regs.get(insn.src_reg()));
                        ctx.regs.set(insn.dst_reg(), dst);
                        None
                    }
                    args::LOAD | args::STORE | args::STORE_IMM => {
                        args::step_arg(interp, &mut ctx.regs, raw);
                        None
                    }
                    _ => {
                        // SAFETY: `alone` has the same layout as `raw.byte()` (see `bytes::usual`).
                        let insn = unsafe { View::new(&raw, Some(raw), Shape::of(alone)) };
                        match step::step(&mut ctx.regs, ctx.memory, insn) {
                            Step::Next => None,
                            Step::LdImm64 => {
                                let second = code.raw_slot(pc + 1).expect("slot after LD_IMM64 lies in code");
                                let Some(upper) = transfer::second_half(second) else {
                                    // SAFETY: `pc` lies in `code`.
                                    let r = u64::from(unsafe { *rests.0.add(pc as usize) });
                                    interp.fuel.0 = fuel.wrapping_sub(r);
                                    return interp.stop.at(Ip::at(code, pc), Reason::BadPc);
                                };
                                step::ld_imm64(&mut ctx.regs, insn, upper);
                                fuel -= 2;
                                pc += 2;
                                continue;
                            }
                            Step::Stop(reason) => Some(reason),
                            _ => unreachable!("short block stops before any block-ending instruction"),
                        }
                    }
                };
                if let Some(reason) = stop_reason {
                    // SAFETY: `pc` lies in `code`.
                    let r = u64::from(unsafe { *rests.0.add(pc as usize) });
                    interp.fuel.0 = fuel.wrapping_sub(r);
                    return interp.stop.at(Ip::at(code, pc), reason);
                }
                fuel -= 1;
                pc += 1;
            }
        }
    }

    /// Whether `left`, the fuel after a block was charged, couldn't pay for it: it is negative as an `i64`.
    #[inline(always)]
    pub fn short(left: u64) -> bool {
        (left as i64) < 0
    }

    /// For each opcode byte, the byte whose handler runs a slot with that byte one instruction at a time: for a
    /// superinstruction, that of its first instruction.
    const ALONE: [u8; 256] = byte_table!(|byte| match fuse::Super::with_byte(byte) {
        Some(sup) => sup.opcode(0),
        None => byte,
    });

    /// The fuel configuration of an [`Interpreter`] and the dispatch table its runs use. The mutable counter lives in
    /// [`FuelLeft`] at offset 0 of `Interpreter`.
    pub struct Meter<M: Memory, H> {
        table: NonNull<DispatchTable<M, H>>,
        /// 0 without a limit.
        limit: u64,
        metered: bool,
    }

    // SAFETY: `table` points to a constant `DispatchTable` in static memory.
    unsafe impl<M: Memory, H> Send for Meter<M, H> {}
    unsafe impl<M: Memory, H> Sync for Meter<M, H> {}

    impl<M: Memory, H: Host<M>> Default for Meter<M, H> {
        fn default() -> Self {
            Self::new(None).0
        }
    }

    impl<M: Memory, H: Host<M>> Meter<M, H> {
        /// `limit` units of fuel per run, at most `i64::MAX`, or none for runs without fuel, and its initial counter.
        pub fn new(limit: Option<u64>) -> (Self, FuelLeft) {
            // Each is a reference to a constant without interior mutability or drop glue, placed in static memory.
            // Storing the pointer here ensures `enter` and `stopped` always see the exact same table address as the
            // `Code` cache key, even if LLVM does not deduplicate promoted constants across functions.
            let table: &DispatchTable<M, H> = match limit {
                Some(_) => &Tables::<M, H>::METERED,
                None => &Tables::<M, H>::PLAIN,
            };
            let fuel = limit.unwrap_or(0).min(i64::MAX as u64);
            (
                Self {
                    table: NonNull::from(table),
                    limit: fuel,
                    metered: limit.is_some(),
                },
                FuelLeft(fuel),
            )
        }

        /// The dispatch table for this meter configuration.
        #[inline(always)]
        pub fn table<'a>(&self) -> &'a DispatchTable<M, H> {
            // SAFETY: `new` took the pointer from a `Tables::*` constant in read-only static memory.
            unsafe { self.table.as_ref() }
        }

        /// Reset `left` to `limit` for a fresh [`Interpreter::run`].
        #[inline(always)]
        pub fn start(&self, left: &mut FuelLeft) {
            left.0 = self.limit;
        }

        /// Charge the block at `pc` before entering handlers; returns `(rests_ptr, short)`.
        #[inline(always)]
        pub fn enter_block(&self, left: &mut FuelLeft, raw: &[Slot], rests: &Rests, pc: u64) -> (RestsPtr, bool) {
            if !self.metered {
                return (RestsPtr::NULL, false);
            }
            let ptr = rests.ptr(raw);
            // SAFETY: caller checked `pc < raw.len()`, and `ptr` points to `raw.len()` entries.
            let rest = u64::from(unsafe { *ptr.0.add(pc as usize) });
            left.0 = left.0.wrapping_sub(rest);
            (ptr, short(left.0))
        }

        /// Why a call can't start, if `fresh`, or resume at a pc outside the code. A fresh call has the fuel of the
        /// limit, and a metered one without fuel is out of it, as an instruction there would be charged first.
        pub fn outside<E>(&self, left: &mut FuelLeft, fresh: bool) -> Reason<E> {
            if fresh {
                left.0 = self.limit;
            }
            match self.metered && left.0 == 0 {
                true => Reason::OutOfFuel,
                false => Reason::BadPc,
            }
        }

        /// The limit, if runs are metered.
        pub fn limit(&self) -> Option<u64> {
            self.metered.then_some(self.limit)
        }

        /// The fuel left, if runs are metered.
        pub fn left(&self, left: &FuelLeft) -> Option<u64> {
            self.metered.then_some(left.0)
        }

        /// Sets the fuel left, at most `i64::MAX`.
        pub fn set_left(&self, left: &mut FuelLeft, fuel: u64) {
            left.0 = fuel.min(i64::MAX as u64);
        }

        /// Turns the fuel that the handlers of a metered run of `code` kept into what charging per slot leaves
        /// where the run stopped with `reason`: at `ip`, or with `None` at a pc outside the code.
        pub fn settle<E>(&self, left: &mut FuelLeft, code: Slots, ip: Option<Ip>, reason: &mut Reason<E>) {
            if !self.metered {
                return;
            }
            let Some(ip) = ip else {
                // the handler that continued there ended its block, so the fuel is charged up to it
                if left.0 == 0 {
                    *reason = Reason::OutOfFuel;
                }
                return;
            };
            // SAFETY: a handler stops at its own ip, which lies in the slots of its code (see `Ip`)
            let before = left.0.wrapping_add(unsafe { code.rests().of(code, ip) });
            left.0 = match reason {
                // `Metered::step` left the fuel before the slot
                Reason::OutOfFuel => left.0,
                // the guard, or an LD_IMM64 that the code ends in: no instruction ran, so it keeps its unit
                Reason::BadPc => before,
                _ => before - 1,
            };
        }
    }

    /// The `rest` of each slot of a [`Code`](crate::Code), stored as `u32` (code has fewer than 2^31 slots) and
    /// computed on the first metered run.
    #[derive(Default)]
    pub struct Rests {
        rests: AtomicPtr<u32>,
        len: AtomicUsize,
    }

    impl Rests {
        /// Pointer to the `rest` array, computing it on the first metered run.
        #[inline(always)]
        pub fn ptr(&self, raw: &[Slot]) -> RestsPtr {
            let ptr = self.rests.load(Ordering::Acquire);
            if !ptr.is_null() {
                return RestsPtr(ptr);
            }
            RestsPtr(self.compute(raw))
        }

        /// The `rest` of the slot at `ip` of `code`, whose rests these are.
        ///
        /// # Safety
        ///
        /// `ip` must lie in the slots of `code`.
        pub unsafe fn of(&self, code: Slots, ip: Ip) -> u64 {
            let ptr = self.ptr(code.raw_slots());
            // SAFETY: the caller's, and `ptr` has `code.total_len()` entries.
            u64::from(unsafe { *ptr.0.add(ip.pc(code) as usize) })
        }

        /// Computes and publishes the `rest` array for `slots`.
        #[cold]
        #[inline(never)]
        fn compute(&self, slots: &[Slot]) -> *const u32 {
            /// Whether a slot with opcode byte `byte` ends its block.
            const ENDS: [bool; 256] =
                byte_table!(|byte| OpCode(bytes::usual(byte)).is_jump() || byte == FAR || byte == GUARD);

            let mut rests: Box<[u32]> = vec![0; slots.len()].into_boxed_slice();
            // backwards, as each `rest` follows from the next; the last slot holds `GUARD`, which ends a block
            let mut rest = 0u32;
            for (slot, at) in slots.iter().zip(&mut rests).rev() {
                rest = match ENDS[usize::from(slot.byte())] {
                    true => 1,
                    false => rest + 1,
                };
                *at = rest;
            }

            let len = rests.len();
            let new = Box::into_raw(rests).cast::<u32>();
            // every thread that computes them stores this length
            self.len.store(len, Ordering::Relaxed);
            match self
                .rests
                .compare_exchange(ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => new,
                Err(existing) => {
                    // SAFETY: another thread published first, so this one alone owns `new`
                    drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(new, len)) });
                    existing
                }
            }
        }
    }

    impl Drop for Rests {
        fn drop(&mut self) {
            let (rests, len) = (*self.rests.get_mut(), *self.len.get_mut());
            if !rests.is_null() {
                // SAFETY: `compute` took `rests` from a box of `len` entries, which nothing else frees
                drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(rests, len)) });
            }
        }
    }
}

#[cfg(not(feature = "fuel"))]
mod unmetered {
    use std::ptr::NonNull;

    use super::*;
    use crate::dispatch::{DispatchTable, Tables};
    use crate::Reason;

    /// The fuel counter of a build that can't meter: it holds nothing.
    #[derive(Default)]
    pub struct FuelLeft;

    /// The meter of a build that can't meter: holds only the constant plain dispatch table pointer.
    pub struct Meter<M: Memory, H>(NonNull<DispatchTable<M, H>>);

    // SAFETY: points to a constant `DispatchTable` in static memory.
    unsafe impl<M: Memory, H> Send for Meter<M, H> {}
    unsafe impl<M: Memory, H> Sync for Meter<M, H> {}

    impl<M: Memory, H: Host<M>> Default for Meter<M, H> {
        fn default() -> Self {
            Self(NonNull::from(&Tables::<M, H>::PLAIN))
        }
    }

    impl<M: Memory, H: Host<M>> Meter<M, H> {
        #[inline(always)]
        pub fn table<'a>(&self) -> &'a DispatchTable<M, H> {
            // SAFETY: `default` took the pointer from `Tables::PLAIN` in read-only static memory.
            unsafe { self.0.as_ref() }
        }

        #[inline(always)]
        pub fn start(&self, _: &mut FuelLeft) {}

        pub fn outside<E>(&self, _: &mut FuelLeft, _: bool) -> Reason<E> {
            Reason::BadPc
        }

        pub fn limit(&self) -> Option<u64> {
            None
        }

        pub fn left(&self, _: &FuelLeft) -> Option<u64> {
            None
        }

        pub fn set_left(&self, _: &mut FuelLeft, _: u64) {}

        pub fn settle<E>(&self, _: &mut FuelLeft, _: Slots, _: Option<Ip>, _: &mut Reason<E>) {}
    }
}

#[cfg(all(test, feature = "fuel"))]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use crate::{Callee, Code, Context, Host, Instruction, Interpreter, Memory, NativeCall, Reason};

    struct PanicMemory {
        panic_on_load: bool,
    }

    // SAFETY: uses default `window` (`Window::NONE`) and `epoch` (`0`).
    unsafe impl Memory for PanicMemory {
        type Error = ();

        fn load_u8(&self, _addr: u64) -> Result<u8, ()> {
            assert!(!self.panic_on_load, "memory load panicked");
            Ok(0)
        }

        fn store_u8(&mut self, _addr: u64, _value: u8) -> Result<(), ()> {
            Ok(())
        }

        fn native_ptr(&self, _: u64, _: u64, _: bool) -> Result<u64, ()> {
            Err(())
        }
    }

    struct NoHost;
    impl Host<PanicMemory> for NoHost {
        fn call_helper(&mut self, _: &mut Context<PanicMemory>, _: u32) -> Option<u64> {
            None
        }
        fn call_kfunc(&mut self, _: &mut Context<PanicMemory>, _: u32) -> Option<u64> {
            None
        }
        fn call_indirect(&mut self, _: &mut Context<PanicMemory>, _: u64, _: NativeCall<'_, ()>) -> Option<Callee> {
            None
        }
    }

    /// A caught panic inside a custom `Memory` during a short-fuel block must not leave `meter.left` negative and
    /// bypass the fuel limit on the next `run()`.
    #[test]
    fn panic_in_short_block_does_not_bypass_fuel() {
        // 5-instruction single basic block:
        //   0: r0 = *(u8 *)(r1 + 0)   (ldxb)
        //   1: r0 += 1
        //   2: r0 += 1
        //   3: r0 += 1
        //   4: exit
        let insns = [
            Instruction(u64::from_le_bytes([0x71, 0x10, 0, 0, 0, 0, 0, 0])),
            Instruction(u64::from_le_bytes([0x07, 0x00, 0, 0, 1, 0, 0, 0])),
            Instruction(u64::from_le_bytes([0x07, 0x00, 0, 0, 1, 0, 0, 0])),
            Instruction(u64::from_le_bytes([0x07, 0x00, 0, 0, 1, 0, 0, 0])),
            Instruction(u64::from_le_bytes([0x95, 0x00, 0, 0, 0, 0, 0, 0])),
        ];
        let code = Code::new(insns);
        let mut interp = Interpreter::new(512, NoHost);
        interp.set_limit(Some(2));

        let mut mem = PanicMemory { panic_on_load: true };
        let res = catch_unwind(AssertUnwindSafe(|| {
            let mut ctx = Context::new(&mut mem);
            interp.run(&mut ctx, &code, 0)
        }));
        assert!(res.is_err());

        mem.panic_on_load = false;
        let mut ctx = Context::new(&mut mem);
        let stop = interp.run(&mut ctx, &code, 0);
        assert_eq!(stop.reason, Reason::OutOfFuel);
        assert_eq!(stop.pc, 2);
    }
}
