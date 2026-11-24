//! Fuel: the instruction budget of a metered run.
//!
//! A run is metered if the [`Interpreter`] has a limit. It then reports fuel as if it charged one unit per slot
//! before running it, and stops with [`Reason::OutOfFuel`](crate::Reason::OutOfFuel) at the first slot it has no unit
//! for. A run without a limit takes the plain table ([`Tables::PLAIN`](crate::dispatch::Tables::PLAIN)), and nothing
//! in it or in its [`Code`](crate::Code) is there for fuel.
//!
//! # Fuel charged per block
//!
//! The handlers charge the units per block. A block ends at the first slot at or after it whose handler may continue
//! at a slot other than the next one: a jump-class instruction (jumps, calls, `exit`, `gotox`, `may_goto`), a
//! [`FAR`](crate::transfer::FAR) jump, or the [`GUARD`](crate::transfer::GUARD). Every other handler continues at the
//! next slot of its block, or after the second slot of LD_IMM64, which lies in it too. A superinstruction lies in one
//! block, and a block may hold jump targets. The `rest` of a slot is the number of slots from it to the end of its
//! block, inclusive; the first metered run of a code computes the `rest` of each of its slots (`Rests`).
//!
//! The interpreter keeps the fuel in its [`Meter`]. Invariant: while the handler of slot `s` runs in a metered run,
//! that fuel is what charging per slot leaves before `s`, less `rest(s)`, in wrapping arithmetic. A handler that
//! continues in its block needn't touch it, as `rest` drops by the slots that charging per slot charges in between.
//! One that ends its block continues at a slot `t` by entering the block there ([`Fuel::enter`]): it subtracts
//! `rest(t)`, wherever `t` lies in that block. So control may enter a block at any slot: at a jump target, after a
//! call, or where a run starts.
//!
//! Only the handlers that end a block differ between a metered run and a plain one, so only they take a [`Fuel`]:
//! the metered table (`Tables::METERED`) holds their metered instances and shares every other handler with the plain
//! one.
//!
//! If the fuel before `t` is at least `rest(t)`, the fuel stays at or above 0 up to the end of the block, and no
//! handler tests it. Otherwise [`Fuel::step`] runs the slots from `t` on one at a time and stops where charging per
//! slot runs out. That happens before the last slot of the block, whose `rest` is 1, so no handler that ends a block
//! runs this way.
//!
//! Where a run stops, `Meter::settle` turns the fuel into what charging per slot leaves there. The invariant decides
//! only what a run reports, not where a handler reads or continues, so a wrong `rest` can't break memory safety.

use crate::code::Slots;
use crate::dispatch::{Spare, Table};
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{Context, Host, Interpreter, Memory};

/// What a handler that ends a block does for fuel where it continues.
pub trait Fuel {
    /// Enters the block of `ip` in `code` there: charges it to the fuel of `interp`. False if the fuel can't pay for
    /// the block; [`step`](Self::step) then runs the slot in place of its handler.
    fn enter<M: Memory, H>(interp: &mut Interpreter<M, H>, code: Slots, ip: Ip) -> bool;

    /// A [`Handler`](crate::dispatch::Handler) that runs the instruction at `ip` alone, in a block entered with too
    /// little fuel for it, and stops where the fuel runs out.
    extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
        ctx: &mut Context<M>,
        code: Slots,
        ip: Ip,
        interp: &mut Interpreter<M, H>,
        table: &Table<M, H>,
        spare: Spare,
        slot: Slot,
    );
}

/// No fuel: the handlers of a run without a limit.
pub struct Unmetered;

impl Fuel for Unmetered {
    #[inline(always)]
    fn enter<M: Memory, H>(_: &mut Interpreter<M, H>, _: Slots, _: Ip) -> bool {
        true
    }

    extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
        _: &mut Context<M>,
        _: Slots,
        _: Ip,
        _: &mut Interpreter<M, H>,
        _: &Table<M, H>,
        _: Spare,
        _: Slot,
    ) {
        unreachable!("no block is short of fuel")
    }
}

#[cfg(feature = "fuel")]
pub use metered::{Meter, Rests};
#[cfg(not(feature = "fuel"))]
pub use unmetered::Meter;

#[cfg(feature = "fuel")]
mod metered {
    use std::ptr::{self, NonNull};
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

    use super::*;
    use crate::dispatch::{self, Handler, Tables, SPARE};
    use crate::opcode::{OpCode, LD_IMM64};
    use crate::transfer::{FAR, GUARD};
    use crate::{bytes, fuse, Reason};

    impl<M: Memory, H: Host<M>> Tables<M, H> {
        /// The table of a metered run.
        pub const METERED: Table<M, H> = dispatch::table::<M, H, Metered>();

        /// The table through which [`Metered::step`] runs the slots of a block one at a time: each dispatch returns
        /// to it. A metered run also starts through it.
        pub const STEPS: Table<M, H> = {
            let step = Metered::step::<M, H> as Handler<M, H>;
            Table([step; 256], [step; 256])
        };
    }

    /// Exact fuel, charged per block as the [module](super) describes.
    pub struct Metered;

    impl Fuel for Metered {
        #[inline(always)]
        fn enter<M: Memory, H>(interp: &mut Interpreter<M, H>, code: Slots, ip: Ip) -> bool {
            // SAFETY: the ip a handler continues at lies in the slots of its code (see `Ip`), and a handler of
            // `Tables::METERED` runs only after `step` or `Meter::resume` read the code's rests
            let rest = unsafe { code.rests().at(ip) };
            let meter = &mut interp.meter;
            meter.left = meter.left.wrapping_sub(rest);
            !short(meter.left)
        }

        /// Runs the instruction if charging per slot leaves a unit for it (two for LD_IMM64), and stops with
        /// [`Reason::OutOfFuel`] otherwise. The handler of the instruction continues here, through
        /// [`Tables::STEPS`].
        ///
        /// [`Interpreter::run`] starts here too. The fuel then isn't short, as every stop leaves it so
        /// ([`Meter::settle`]): this handler gives the run the fuel of the limit, enters the block, and continues
        /// through [`Tables::METERED`] if the fuel pays for it.
        ///
        /// But for a start, it reads the slot from the code, so that the handlers that enter a block needn't load
        /// it before they branch here.
        #[cold]
        #[inline(never)]
        extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
            ctx: &mut Context<M>,
            code: Slots,
            ip: Ip,
            interp: &mut Interpreter<M, H>,
            table: &Table<M, H>,
            _: Spare,
            slot: Slot,
        ) {
            // SAFETY: a handler's ip lies in the slots of its code (see `Ip`)
            let Some(rest) = (unsafe { code.rests().get(ip) }) else {
                become first_run::<M, H>(ctx, code, ip, interp, table, SPARE, slot)
            };
            let metered = &Tables::<M, H>::METERED;
            let meter = &mut interp.meter;
            if !short(meter.left) {
                meter.left = meter.limit.wrapping_sub(rest);
                if !short(meter.left) {
                    become metered.of(slot)(ctx, code, ip, interp, metered, SPARE, slot)
                }
            }

            // SAFETY: as above
            let slot = unsafe { ip.get() };
            let alone = ALONE[usize::from(slot.byte())];
            let before = meter.left.wrapping_add(rest);
            let units = match alone {
                LD_IMM64 => 2,
                _ => 1,
            };
            if before < units {
                // LD_IMM64 with one unit left keeps it
                meter.left = before;
                return interp.stop.at(ip, Reason::OutOfFuel);
            }
            // a slot with the first fused instruction alone keeps the layout of its superinstruction (see
            // `bytes::usual`)
            let handler = metered.0[usize::from(alone)];
            become handler(ctx, code, ip, interp, &Tables::<M, H>::STEPS, SPARE, slot)
        }
    }

    /// Computes the rests of `code`, which no metered run has read yet, and continues in [`Metered::step`].
    // a handler of its own, so that `step` calls no function and needs no stack frame
    #[cold]
    #[inline(never)]
    extern "rust-preserve-none" fn first_run<M: Memory, H: Host<M>>(
        ctx: &mut Context<M>,
        code: Slots,
        ip: Ip,
        interp: &mut Interpreter<M, H>,
        table: &Table<M, H>,
        _: Spare,
        slot: Slot,
    ) {
        code.rests().compute(code);
        become Metered::step::<M, H>(ctx, code, ip, interp, table, SPARE, slot)
    }

    /// Whether `left`, the fuel after a block was charged, couldn't pay for it: it is negative as an `i64`.
    #[inline(always)]
    fn short(left: u64) -> bool {
        (left as i64) < 0
    }

    /// For each opcode byte, the byte whose handler runs a slot with that byte one instruction at a time: for a
    /// superinstruction, that of its first instruction.
    const ALONE: [u8; 256] = byte_table!(|byte| match fuse::Super::with_byte(byte) {
        Some(sup) => sup.opcode(0),
        None => byte,
    });

    /// The fuel of an [`Interpreter`]: the limit of its runs, the table they start through, and what the run in
    /// progress has left.
    pub struct Meter<M: Memory, H> {
        start: NonNull<Table<M, H>>,
        /// 0 without a limit.
        limit: u64,
        /// The fuel as the handlers of a run keep it (see the [module](super)), and between runs what the last one
        /// left, which isn't short.
        left: u64,
        metered: bool,
    }

    // SAFETY: `start` points to a constant table of functions
    unsafe impl<M: Memory, H> Send for Meter<M, H> {}
    unsafe impl<M: Memory, H> Sync for Meter<M, H> {}

    impl<M: Memory, H: Host<M>> Default for Meter<M, H> {
        fn default() -> Self {
            Self::new(None)
        }
    }

    impl<M: Memory, H: Host<M>> Meter<M, H> {
        /// `limit` units of fuel per run, at most `i64::MAX`, or none for runs without fuel.
        pub fn new(limit: Option<u64>) -> Self {
            // Each is a reference to a constant without interior mutability or drop glue, which the compiler places
            // in static memory. It has no `'static` type, because `M` and `H` needn't be `'static`.
            let start: &Table<M, H> = match limit {
                Some(_) => &Tables::<M, H>::STEPS,
                None => &Tables::<M, H>::PLAIN,
            };
            let fuel = limit.unwrap_or(0).min(i64::MAX as u64);
            Self {
                start: NonNull::from(start),
                limit: fuel,
                left: fuel,
                metered: limit.is_some(),
            }
        }

        /// The table [`Interpreter::run`] starts through. The reference outlives the borrow of the meter, as the
        /// table lives in static memory.
        #[inline(always)]
        pub fn start<'a>(&self) -> &'a Table<M, H> {
            // SAFETY: `new` took the pointer from a table in static memory
            unsafe { self.start.as_ref() }
        }

        /// The table [`Interpreter::resume`] continues through at `pc` of `code`, with the fuel left: a metered run
        /// enters the block there.
        pub fn resume<'a>(&mut self, code: Slots, pc: u64) -> &'a Table<M, H> {
            if !self.metered || code.get(pc).is_none() {
                return self.start();
            }
            // SAFETY: the code has a slot at `pc`
            let rest = unsafe { code.rests().of(code, Ip::at(code, pc)) };
            self.left = self.left.wrapping_sub(rest);
            match short(self.left) {
                true => &Tables::<M, H>::STEPS,
                false => &Tables::<M, H>::METERED,
            }
        }

        /// Why a call can't start, if `fresh`, or resume at a pc outside the code. A fresh call has the fuel of the
        /// limit, and a metered one without fuel is out of it, as an instruction there would be charged first.
        pub fn outside<E>(&mut self, fresh: bool) -> Reason<E> {
            if fresh {
                self.left = self.limit;
            }
            match self.metered && self.left == 0 {
                true => Reason::OutOfFuel,
                false => Reason::BadPc,
            }
        }

        /// The limit, if runs are metered.
        pub fn limit(&self) -> Option<u64> {
            self.metered.then_some(self.limit)
        }

        /// The fuel left, if runs are metered.
        pub fn left(&self) -> Option<u64> {
            self.metered.then_some(self.left)
        }

        /// Sets the fuel left, at most `i64::MAX`.
        pub fn set_left(&mut self, fuel: u64) {
            self.left = fuel.min(i64::MAX as u64);
        }

        /// Turns the fuel that the handlers of a metered run of `code` kept into what charging per slot leaves
        /// where the run stopped with `reason`: at `ip`, or with `None` at a pc outside the code. There, a run
        /// without fuel stops with [`Reason::OutOfFuel`], as an instruction would be charged first.
        pub fn settle<E>(&mut self, code: Slots, ip: Option<Ip>, reason: &mut Reason<E>) {
            if !self.metered {
                return;
            }
            let Some(ip) = ip else {
                // the handler that continued there ended its block, so the fuel is charged up to it
                if self.left == 0 {
                    *reason = Reason::OutOfFuel;
                }
                return;
            };
            // SAFETY: a handler stops at its own ip, which lies in the slots of its code (see `Ip`)
            let before = self.left.wrapping_add(unsafe { code.rests().of(code, ip) });
            self.left = match reason {
                // `Metered::step` left the fuel before the slot
                Reason::OutOfFuel => self.left,
                // the guard, or an LD_IMM64 that the code ends in: no instruction ran, so it keeps its unit
                Reason::BadPc => before,
                _ => before - 1,
            };
        }
    }

    /// The `rest` of each slot of a [`Code`](crate::Code), which its first metered run computes.
    #[derive(Default)]
    pub struct Rests {
        /// A box of `len` rests, one per slot, which the first of the threads that compute them sets. Null until then.
        rests: AtomicPtr<u64>,
        len: AtomicUsize,
        /// The address of `rests` less that of the code's first slot, so that it and an ip add up to the address of
        /// the `rest` of the slot there. Null until `rests` is set.
        biased: AtomicPtr<u64>,
    }

    impl Rests {
        /// The `rest` of the slot at `ip` of `code`, whose rests these are.
        ///
        /// # Safety
        ///
        /// `ip` must lie in the slots of `code`.
        pub unsafe fn of(&self, code: Slots, ip: Ip) -> u64 {
            // SAFETY: the caller's
            if let Some(rest) = unsafe { self.get(ip) } {
                return rest;
            }
            self.compute(code);
            // SAFETY: the caller's, and `compute` set `biased`
            unsafe { self.at(ip) }
        }

        /// The `rest` of the slot at `ip`, or `None` if no metered run has read the rests yet.
        ///
        /// # Safety
        ///
        /// `ip` must lie in the slots of the code whose rests these are.
        #[inline(always)]
        pub unsafe fn get(&self, ip: Ip) -> Option<u64> {
            let biased = self.biased.load(Ordering::Acquire);
            // SAFETY: the caller's: with the address of a slot, a set `biased` gives the address of its `rest`
            (!biased.is_null()).then(|| unsafe { biased.wrapping_byte_add(ip.addr()).read() })
        }

        /// The `rest` of the slot at `ip`.
        ///
        /// # Safety
        ///
        /// As for [`get`](Self::get), and a metered run must have read the rests.
        #[inline(always)]
        pub unsafe fn at(&self, ip: Ip) -> u64 {
            // SAFETY: the caller's
            unsafe { self.biased.load(Ordering::Acquire).wrapping_byte_add(ip.addr()).read() }
        }

        /// Sets the rests, for the slots of `code`, whose rests these are.
        #[cold]
        #[inline(never)]
        pub fn compute(&self, code: Slots) {
            /// Whether a slot with opcode byte `byte` ends its block.
            const ENDS: [bool; 256] =
                byte_table!(|byte| OpCode(bytes::usual(byte)).is_jump() || byte == FAR || byte == GUARD);
            const _: () = assert!(size_of::<Slot>() == size_of::<u64>());

            let slots = code.all();
            let mut rests: Box<[u64]> = vec![0; slots.len()].into_boxed_slice();
            // backwards, as each `rest` follows from the next; the last slot holds `GUARD`, which ends a block
            let mut rest = 0;
            for (slot, at) in slots.iter().zip(&mut rests).rev() {
                rest = match ENDS[usize::from(slot.byte())] {
                    true => 1,
                    false => rest + 1,
                };
                *at = rest;
            }

            let len = rests.len();
            let new = Box::into_raw(rests).cast::<u64>();
            // every thread that computes them stores this length
            self.len.store(len, Ordering::Relaxed);
            let set = self
                .rests
                .compare_exchange(ptr::null_mut(), new, Ordering::AcqRel, Ordering::Acquire);
            let rests = match set {
                Ok(_) => new,
                Err(rests) => {
                    // SAFETY: another thread set the rests first, so this one alone has the box of `new`
                    drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(new, len)) });
                    rests
                }
            };
            let biased = rests.wrapping_byte_sub(code.first().addr());
            self.biased.store(biased, Ordering::Release);
        }
    }

    impl Drop for Rests {
        fn drop(&mut self) {
            let (rests, len) = (*self.rests.get_mut(), *self.len.get_mut());
            if !rests.is_null() {
                // SAFETY: `compute` took `rests` from a box of `len` rests, which nothing else frees
                drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(rests, len)) });
            }
        }
    }
}

#[cfg(not(feature = "fuel"))]
mod unmetered {
    use std::marker::PhantomData;

    use super::*;
    use crate::dispatch::Tables;
    use crate::Reason;

    /// The meter of a build that can't meter: it holds nothing.
    pub struct Meter<M, H>(PhantomData<fn(M, H)>);

    impl<M, H> Default for Meter<M, H> {
        fn default() -> Self {
            Self(PhantomData)
        }
    }

    impl<M: Memory, H: Host<M>> Meter<M, H> {
        #[inline(always)]
        pub fn start<'a>(&self) -> &'a Table<M, H> {
            &Tables::<M, H>::PLAIN
        }

        #[inline(always)]
        pub fn resume<'a>(&mut self, _: Slots, _: u64) -> &'a Table<M, H> {
            self.start()
        }

        pub fn outside<E>(&mut self, _: bool) -> Reason<E> {
            Reason::BadPc
        }

        pub fn limit(&self) -> Option<u64> {
            None
        }

        pub fn left(&self) -> Option<u64> {
            None
        }

        pub fn set_left(&mut self, _: u64) {}

        pub fn settle<E>(&mut self, _: Slots, _: Option<Ip>, _: &mut Reason<E>) {}
    }
}
