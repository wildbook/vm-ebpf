//! Fuel: the instruction budget of a metered run.
//!
//! A run is metered if the [`Interpreter`] has a limit. It then reports fuel as if it charged one unit per slot
//! before running it, and stops with [`Reason::OutOfFuel`](crate::Reason::OutOfFuel) at the first slot it has no unit
//! for. A run without a limit takes the plain table ([`Tables::PLAIN`](crate::dispatch::Tables::PLAIN)), in which no
//! handler reads the fuel, so it pays nothing for the metered runs' existence.
//!
//! # Fuel charged per block
//!
//! The handlers charge the units per block. A block ends at the first slot at or after it whose handler may continue
//! at a slot other than the next one: a jump-class instruction (jumps, calls, `exit`, `gotox`, `may_goto`), a
//! [`FAR`](crate::transfer::FAR) jump, or the [`GUARD`](crate::transfer::GUARD). Every other handler continues at the
//! next slot of its block, or after the second slot of LD_IMM64, which lies in it too. A superinstruction lies in one
//! block, and a block may hold jump targets. The `rest` of a slot is the number of slots from it to the end of its
//! block, inclusive; with the `fuel` feature, every [`Code`](crate::Code) keeps the `rest` of each slot.
//!
//! Invariant: the handler that runs slot `s` in a metered run receives the fuel that charging per slot leaves before
//! `s`, less `rest(s)`, in wrapping arithmetic. A handler that continues in its block passes the fuel on unread, as
//! `rest` drops by the slots that charging per slot charges in between. One that ends its block continues at a slot
//! `t` by entering the block there ([`Fuel::enter`]): it subtracts `rest(t)`, wherever `t` lies in that block. The
//! checked fetches do the same, so control may enter a block at any slot: at a jump target, after a call, or where a
//! run starts.
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
//! A handler that stops records the fuel it received. `settled` turns that into the fuel that charging per slot
//! leaves at the stop. The invariant decides only what a run reports, not where a handler reads or continues, so a
//! wrong `rest` can't break memory safety.

use crate::code::Slots;
use crate::dispatch::Table;
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{Context, Host, Instruction, Interpreter, Memory};

/// What a handler that ends a block does for fuel where it continues.
pub trait Fuel {
    /// Enters the block of `ip` in `code` there: the fuel the handler at `ip` receives, from the `fuel` before it.
    fn enter(code: Slots, ip: Ip, fuel: u64) -> u64;

    /// Whether the fuel `left` that [`enter`](Self::enter) returned can't pay for the block. [`step`](Self::step)
    /// then runs the slot in place of its handler.
    fn short(left: u64) -> bool;

    /// Whether `fuel`, before a slot is charged, has no unit for it.
    fn spent(fuel: u64) -> bool;

    /// A [`Handler`](crate::dispatch::Handler) that runs the instruction at `ip` alone, in a block entered with too
    /// little fuel for it, and stops where the fuel runs out.
    extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
        ctx: &mut Context<M>,
        code: Slots,
        ip: Ip,
        fuel: u64,
        interp: &mut Interpreter<M, H>,
        table: &Table<M, H>,
        slot: Slot,
    );
}

/// No fuel: the handlers of a run without a limit, which pass the `fuel` they receive on unread.
pub struct Unmetered;

impl Fuel for Unmetered {
    #[inline(always)]
    fn enter(_: Slots, _: Ip, fuel: u64) -> u64 {
        fuel
    }

    #[inline(always)]
    fn short(_: u64) -> bool {
        false
    }

    #[inline(always)]
    fn spent(_: u64) -> bool {
        false
    }

    extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
        _: &mut Context<M>,
        _: Slots,
        _: Ip,
        _: u64,
        _: &mut Interpreter<M, H>,
        _: &Table<M, H>,
        _: Slot,
    ) {
        unreachable!("no block is short of fuel")
    }
}

#[cfg(not(feature = "fuel"))]
mod storage {
    use super::*;

    /// Makes room in `insns` for what [`store`] and the passes of [`Code::new`](crate::Code::new) before it append.
    #[inline(always)]
    pub fn reserve(_: &mut Vec<Instruction>) {}

    /// The storage of a code: the slots of `insns`.
    #[inline(always)]
    pub fn store(insns: Vec<Instruction>) -> Box<[Slot]> {
        // in place, as `Slot` and `Instruction` have the same size and alignment
        let slots: Vec<Slot> = insns.into_iter().map(Slot::new).collect();
        slots.into_boxed_slice()
    }
}

#[cfg(feature = "fuel")]
mod storage {
    use super::*;

    /// Makes room in `insns` for what [`store`] and the passes of [`Code::new`](crate::Code::new) before it append:
    /// the guard and the `rest` of each slot. So neither reallocates unless a pass moves instructions behind the
    /// guard.
    #[inline(always)]
    pub fn reserve(insns: &mut Vec<Instruction>) {
        insns.reserve_exact(insns.len() + 2);
    }

    /// The storage of a code: the slots of `insns`, then the `rest` of each as a `u64`, which only
    /// [`rest`](super::metered::rest) reads.
    // boxed here and not in `with_rests`, so that the shrink compiles with the caller
    #[inline(always)]
    pub fn store(insns: Vec<Instruction>) -> Box<[Slot]> {
        super::metered::with_rests(insns).into_boxed_slice()
    }
}

#[cfg(feature = "fuel")]
pub use metered::{settled, Limit};
pub use storage::{reserve, store};

/// The `rest` of the slot at `pc` of `code`, if the code keeps it.
pub fn rest_at(code: Slots, pc: u64) -> Option<u64> {
    #[cfg(feature = "fuel")]
    // SAFETY: the ip of a pc that holds a slot lies in the slots
    return code.get(pc).map(|_| unsafe { metered::rest(code, Ip::at(code, pc)) });
    #[cfg(not(feature = "fuel"))]
    return code.get(pc).and(None);
}

#[cfg(feature = "fuel")]
mod metered {
    use std::mem::ManuallyDrop;
    use std::ptr::NonNull;

    use super::*;
    use crate::dispatch::{self, Handler, Tables};
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
        /// The fuel left is `fuel` less the `rest` of the slot.
        #[inline(always)]
        fn enter(code: Slots, ip: Ip, fuel: u64) -> u64 {
            // SAFETY: the ip a handler continues at lies in the slots of its code (see `Ip`)
            fuel.wrapping_sub(unsafe { rest(code, ip) })
        }

        /// Negative as an `i64`.
        #[inline(always)]
        fn short(left: u64) -> bool {
            (left as i64) < 0
        }

        #[inline(always)]
        fn spent(fuel: u64) -> bool {
            fuel == 0
        }

        /// Runs the instruction if charging per slot leaves a unit for it (two for LD_IMM64), and stops with
        /// [`Reason::OutOfFuel`] otherwise. The handler of the instruction continues here, through
        /// [`Tables::STEPS`], with the fuel its own handler would get.
        ///
        /// A run starts here too, with fuel that isn't short: fuel that no block is charged to yet. This handler
        /// then enters the block and continues through [`Tables::METERED`] if the fuel pays for it.
        ///
        /// It reads the slot from the code, so that the handlers that enter a block needn't load it before they
        /// branch here.
        #[cold]
        #[inline(never)]
        extern "rust-preserve-none" fn step<M: Memory, H: Host<M>>(
            ctx: &mut Context<M>,
            code: Slots,
            ip: Ip,
            mut fuel: u64,
            interp: &mut Interpreter<M, H>,
            _table: &Table<M, H>,
            _slot: Slot,
        ) {
            // SAFETY: a handler's ip lies in the slots of its code (see `Ip`)
            let (slot, rest) = unsafe { (ip.get(), rest(code, ip)) };
            let metered = &Tables::<M, H>::METERED;
            if !Self::short(fuel) {
                fuel = fuel.wrapping_sub(rest);
                if !Self::short(fuel) {
                    become metered.of(slot)(ctx, code, ip, fuel, interp, metered, slot)
                }
            }

            let alone = ALONE[usize::from(slot.byte())];
            let before = fuel.wrapping_add(rest);
            let units = match alone {
                LD_IMM64 => 2,
                _ => 1,
            };
            if before < units {
                // LD_IMM64 with one unit left keeps it
                return interp.stop.at(ip, before, Reason::OutOfFuel);
            }
            // a slot with the first fused instruction alone keeps the layout of its superinstruction (see
            // `bytes::usual`)
            let handler = metered.0[usize::from(alone)];
            become handler(ctx, code, ip, fuel, interp, &Tables::<M, H>::STEPS, slot)
        }
    }

    /// The `rest` of the slot at `ip`.
    ///
    /// # Safety
    ///
    /// `ip` must lie in the slots of `code`.
    #[inline(always)]
    pub unsafe fn rest(code: Slots, ip: Ip) -> u64 {
        // SAFETY: the caller's; the storage of a code holds the `rest` of a slot as many slots after it as the code
        // has slots (see `storage::store`)
        unsafe { ip.0.add(code.len()).cast::<u64>().read() }
    }

    /// The fuel that charging per slot leaves where a metered run stopped with `reason`, from the `fuel` that the
    /// handler recorded: at `ip`, or with `None` at a pc that a checked fetch refused.
    pub fn settled<E>(code: Slots, ip: Option<Ip>, reason: &Reason<E>, fuel: u64) -> u64 {
        let Some(ip) = ip else {
            // the handler that continued there ended its block, so the fuel was charged up to it
            return fuel;
        };
        // SAFETY: a handler stops at its own ip, which lies in the slots of its code (see `Ip`)
        let before = fuel.wrapping_add(unsafe { rest(code, ip) });
        match reason {
            // `Metered::step` recorded the fuel before the slot
            Reason::OutOfFuel => fuel,
            // the guard, or an LD_IMM64 that the code ends in: no instruction ran, so it keeps its unit
            Reason::BadPc => before,
            _ => before - 1,
        }
    }

    /// The fuel that each run of an [`Interpreter`] starts with, and the table it starts through. Both are data, so
    /// that a run needs no test for whether it is metered.
    pub struct Limit<M: Memory, H> {
        start: NonNull<Table<M, H>>,
        /// 0 without a limit.
        fuel: u64,
        metered: bool,
    }

    // SAFETY: `start` points to a constant table of functions
    unsafe impl<M: Memory, H> Send for Limit<M, H> {}
    unsafe impl<M: Memory, H> Sync for Limit<M, H> {}

    impl<M: Memory, H: Host<M>> Limit<M, H> {
        /// `limit` units of fuel, at most `i64::MAX`, or none for runs without fuel.
        pub fn new(limit: Option<u64>) -> Self {
            // Each is a reference to a constant without interior mutability or drop glue, which the compiler places
            // in static memory. It has no `'static` type, because `M` and `H` needn't be `'static`.
            let start: &Table<M, H> = match limit {
                Some(_) => &Tables::<M, H>::STEPS,
                None => &Tables::<M, H>::PLAIN,
            };
            Self {
                start: NonNull::from(start),
                fuel: limit.unwrap_or(0).min(i64::MAX as u64),
                metered: limit.is_some(),
            }
        }

        /// The table a run starts through. The reference outlives the borrow of the limit, as the table lives in
        /// static memory.
        #[inline(always)]
        pub fn start<'a>(&self) -> &'a Table<M, H> {
            // SAFETY: `new` took the pointer from a table in static memory
            unsafe { self.start.as_ref() }
        }

        /// The fuel a run starts with.
        #[inline(always)]
        pub fn fuel(&self) -> u64 {
            self.fuel
        }

        /// The limit, if runs are metered.
        pub fn get(&self) -> Option<u64> {
            self.metered.then_some(self.fuel)
        }
    }

    /// The slots of the code `insns`, then the `rest` of each. They keep the allocation of `insns` if it has room for
    /// them.
    pub fn with_rests(insns: Vec<Instruction>) -> Vec<Slot> {
        /// Whether a slot with opcode byte `byte` ends its block.
        const ENDS: [bool; 256] =
            byte_table!(|byte| OpCode(bytes::usual(byte)).is_jump() || byte == FAR || byte == GUARD);
        const _: () = assert!(size_of::<Slot>() == size_of::<Instruction>() && size_of::<Slot>() == size_of::<u64>());
        const _: () =
            assert!(align_of::<Slot>() == align_of::<Instruction>() && align_of::<Slot>() == align_of::<u64>());

        let n = insns.len();
        let mut insns = ManuallyDrop::new(insns);
        insns.reserve_exact(n);
        let (slots, capacity) = (insns.as_mut_ptr().cast::<Slot>(), insns.capacity());
        // backwards, as each `rest` follows from the next; the last slot holds `GUARD`, which ends a block
        let mut rest = 0;
        let (mut slot, mut rests) = (slots.wrapping_add(n), slots.wrapping_add(2 * n));
        while slot != slots {
            // SAFETY: the loop has written only the slots after `slot`, so `slot` still holds its instruction, and
            // the allocation has room for `2 * n` slots
            unsafe {
                (slot, rests) = (slot.sub(1), rests.sub(1));
                let insn = slot.cast::<Instruction>().read();
                // a slot keeps the opcode byte of its instruction
                rest = match ENDS[usize::from(insn.byte())] {
                    true => 1,
                    false => rest + 1,
                };
                slot.write(Slot::new(insn));
                rests.cast::<u64>().write(rest);
            }
        }
        // SAFETY: `slots` is the allocation of `insns`, whose elements have the size and alignment of `Slot`, and the
        // loop wrote its first `2 * n`
        unsafe { Vec::from_raw_parts(slots, 2 * n, capacity) }
    }

    /// For each opcode byte, the byte whose handler runs a slot with that byte one instruction at a time: for a
    /// superinstruction, that of its first instruction.
    const ALONE: [u8; 256] = byte_table!(|byte| match fuse::Super::with_byte(byte) {
        Some(sup) => sup.opcode(0),
        None => byte,
    });
}
