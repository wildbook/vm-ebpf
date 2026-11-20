//! Fuel: the instruction budget of [`run`](crate::run).
//!
//! Everything the interpreter does for fuel is a method of [`Fuel`]. [`BlockFuel`] meters; the methods of [`NoFuel`]
//! do nothing, so an interpreter built with it carries its budget from `run` to `run` untouched. The `fuel` feature
//! chooses between them ([`Active`]), and nothing else tests it.
//!
//! # Fuel charged per block
//!
//! `run` reports fuel as if it charged one unit per slot before running it, and stops with [`Flow::OutOfFuel`] at the
//! first slot it has no unit for. The handlers charge the same units per block. A block ends at the first slot at or
//! after it whose handler may continue at a slot other than the next one: a jump-class instruction (jumps, calls,
//! `exit`, `gotox`, `may_goto`), a [`FAR`](crate::transfer::FAR) jump, or the [`GUARD`](crate::transfer::GUARD). Every
//! other handler continues at the next slot of its block, or after the second slot of LD_IMM64, which lies in it too.
//! A superinstruction lies in one block, and a block may hold jump targets. [`Rests`] gives each op its `rest`: the
//! number of slots from it to the end of its block, inclusive.
//!
//! Invariant: the handler that runs slot `s` receives the fuel that charging per slot leaves before `s`, less
//! `rest(s)`, in wrapping arithmetic. A handler that continues in its block passes the fuel on unchanged, as `rest`
//! drops by the slots that charging per slot charges in between. One that ends its block continues at a slot `t` by
//! entering the block there ([`Fuel::enter`]): it subtracts `rest(t)`, wherever `t` lies in that block. `run` and the
//! checked fetches do the same, so control may enter a block at any slot: at a jump target, after a call, or where
//! `run` starts after `gotox` or a declined host call.
//!
//! If the fuel before `t` is at least `rest(t)`, the fuel stays at or above 0 up to the end of the block, and no
//! handler tests it. Otherwise [`BlockFuel::single_step`] runs the slots from `t` on one at a time and stops where
//! charging per slot runs out. That happens before the last slot of the block, whose `rest` is 1, so no handler that
//! ends a block runs this way.
//!
//! A handler that stops at slot `s` reports the fuel that charging per slot leaves there ([`Fuel::unspent`]), plus the
//! unit of `s` where that slot gives it back ([`Fuel::refund`]). The invariant decides only what `run` reports, not
//! where a handler reads or continues, so a wrong `rest` can't break memory safety.

// a build uses one `Fuel` and leaves the other unused
#![allow(dead_code)]

use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

use crate::op::Op;
use crate::opcode::LD_IMM64;
use crate::transfer::Slot;
use crate::{fuse, CallStack, Context, Flow, Handler, Handlers, Host, Instruction, Memory, Table};

/// The [`Fuel`] that [`run`](crate::run) and [`Code`](crate::Code) use.
#[cfg(feature = "fuel")]
pub type Active = BlockFuel;
#[cfg(not(feature = "fuel"))]
pub type Active = NoFuel;

/// What the interpreter does for fuel. The handlers carry the fuel as a `u64` that only these methods read.
pub trait Fuel {
    /// Whether `run` counts instructions.
    const METERED: bool;

    /// The slots of a [`Code`](crate::Code): its ops first, then what the metering keeps for them.
    type Slots: Deref<Target = [Op]> + fmt::Debug;

    /// Makes room in `insns` for [`slots`](Self::slots) to convert them in place, before
    /// [`Code::new`](crate::Code::new) appends to them.
    fn reserve(insns: &mut Vec<Instruction>);

    /// The slots for the code `insns`.
    fn slots(insns: Vec<Instruction>) -> Self::Slots;

    /// The number of `slots` that hold an op.
    fn ops(slots: &[Op]) -> usize;

    /// Enters the block of `slot` in `code` there: the fuel the handler of `slot` receives, from the `fuel` before it.
    fn enter(code: &[Op], slot: Slot, fuel: u64) -> u64;

    /// Whether the fuel `left` that [`enter`](Self::enter) returned can't pay for the block.
    /// [`single_step`](Self::single_step) then runs the slot in place of its handler.
    fn short(left: u64) -> bool;

    /// A [`Handler`] that runs the instruction in `slot` alone, in a block entered with too little fuel for it, and
    /// stops where the fuel runs out.
    extern "rust-preserve-none" fn single_step<M: Memory, H: Host<M>>(
        ctx: &mut Context<M>,
        code: &[Op],
        slot: Slot,
        fuel: u64,
        calls: &mut CallStack<H, M::Err>,
        table: &Table<M, H>,
        op: Op,
    );

    /// The fuel to report once the instruction in `slot` of `code` is charged, from the `fuel` its handler received.
    fn unspent(code: &[Op], slot: Slot, fuel: u64) -> u64;

    /// `fuel` with the unit of a charged slot that didn't run.
    fn refund(fuel: u64) -> u64;

    /// Whether `fuel`, before a slot is charged, has no unit for it.
    fn spent(fuel: u64) -> bool;
}

/// No fuel: the handlers pass the budget on unread, so `run` leaves it as it was.
pub struct NoFuel;

impl Fuel for NoFuel {
    const METERED: bool = false;

    type Slots = Box<[Op]>;

    #[inline(always)]
    fn reserve(_: &mut Vec<Instruction>) {}

    #[inline(always)]
    fn slots(insns: Vec<Instruction>) -> Box<[Op]> {
        // in place, as `Op` and `Instruction` have the same size and alignment
        let slots: Vec<Op> = insns.into_iter().map(Op::new).collect();
        slots.into_boxed_slice()
    }

    #[inline(always)]
    fn ops(slots: &[Op]) -> usize {
        slots.len()
    }

    #[inline(always)]
    fn enter(_: &[Op], _: Slot, fuel: u64) -> u64 {
        fuel
    }

    #[inline(always)]
    fn short(_: u64) -> bool {
        false
    }

    extern "rust-preserve-none" fn single_step<M: Memory, H: Host<M>>(
        _: &mut Context<M>,
        _: &[Op],
        _: Slot,
        _: u64,
        _: &mut CallStack<H, M::Err>,
        _: &Table<M, H>,
        _: Op,
    ) {
        unreachable!("no block is short of fuel")
    }

    #[inline(always)]
    fn unspent(_: &[Op], _: Slot, fuel: u64) -> u64 {
        fuel
    }

    #[inline(always)]
    fn refund(fuel: u64) -> u64 {
        fuel
    }

    #[inline(always)]
    fn spent(_: u64) -> bool {
        false
    }
}

/// Exact fuel, charged per block as the [module](self) describes.
pub struct BlockFuel;

impl Fuel for BlockFuel {
    const METERED: bool = true;

    type Slots = Rests;

    // room for the guard and the `rest` of each slot, so that neither `bound` nor `slots` reallocates unless `bound`
    // moves instructions behind the guard
    #[inline(always)]
    fn reserve(insns: &mut Vec<Instruction>) {
        insns.reserve_exact(insns.len() + 2);
    }

    // boxed here and not in `with_rests`, so that the shrink compiles with the caller
    #[inline(always)]
    fn slots(insns: Vec<Instruction>) -> Rests {
        Rests(with_rests(insns).into_boxed_slice())
    }

    #[inline(always)]
    fn ops(slots: &[Op]) -> usize {
        slots.len() / 2
    }

    /// The fuel left is `fuel` less the `rest` of `slot`.
    #[inline(always)]
    fn enter(code: &[Op], slot: Slot, fuel: u64) -> u64 {
        // SAFETY: the slot a handler continues at lies in the ops of its code (see `Slot`)
        fuel.wrapping_sub(unsafe { rest(code, slot) })
    }

    /// Negative as an `i64`.
    #[inline(always)]
    fn short(left: u64) -> bool {
        (left as i64) < 0
    }

    /// Runs the instruction if charging per slot leaves a unit for it (two for LD_IMM64), and stops with
    /// [`Flow::OutOfFuel`] otherwise. The handler of the instruction continues here, through the table
    /// [`Steps::TABLE`], with the fuel its own handler would get. It reads the op from the slot, so that the handlers
    /// that enter a block needn't load it before they branch here.
    #[cold]
    #[inline(never)]
    extern "rust-preserve-none" fn single_step<M: Memory, H: Host<M>>(
        ctx: &mut Context<M>,
        code: &[Op],
        slot: Slot,
        fuel: u64,
        calls: &mut CallStack<H, M::Err>,
        _table: &Table<M, H>,
        _op: Op,
    ) {
        // SAFETY: a handler's slot lies in the ops of its code (see `Slot`)
        let (op, rest) = unsafe { (slot.get(), rest(code, slot)) };
        let alone = ALONE[usize::from(op.byte())];
        let before = fuel.wrapping_add(rest);
        let units = match alone {
            LD_IMM64 => 2,
            _ => 1,
        };
        if before < units {
            // LD_IMM64 with one unit left keeps it
            return calls.stop.at(slot, before, Flow::OutOfFuel);
        }
        // a slot with the first fused instruction alone keeps the layout of its superinstruction (see `fuse::usual`)
        let handler = Handlers::<M, H, Self>::TABLE.0[usize::from(alone)];
        become handler(ctx, code, slot, fuel, calls, &Steps::<M, H>::TABLE, op)
    }

    /// The fuel that charging per slot leaves once the slot is charged.
    #[inline(always)]
    fn unspent(code: &[Op], slot: Slot, fuel: u64) -> u64 {
        // SAFETY: a handler's slot lies in the ops of its code (see `Slot`)
        fuel.wrapping_add(unsafe { rest(code, slot) }).wrapping_sub(1)
    }

    #[inline(always)]
    fn refund(fuel: u64) -> u64 {
        fuel + 1
    }

    #[inline(always)]
    fn spent(fuel: u64) -> bool {
        fuel == 0
    }
}

/// The slots of a code that [`BlockFuel`] meters: twice as many as ops. The ops come first, and the slot as many
/// slots after each op holds the `rest` of its block as a `u64`. Those slots hold no op; only [`rest`] reads them.
pub struct Rests(Box<[Op]>);

impl Deref for Rests {
    type Target = [Op];

    #[inline(always)]
    fn deref(&self) -> &[Op] {
        &self.0
    }
}

/// Shows each op with the `rest` of its block.
impl fmt::Debug for Rests {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ops = (0..BlockFuel::ops(self) as u64).map(|pc| {
            let slot = Slot::at(self, pc);
            // SAFETY: the slot lies in the ops of these slots
            let (op, rest) = unsafe { (slot.get(), rest(self, slot)) };
            fmt::from_fn(move |f| write!(f, "{op:?} rest {rest}"))
        });
        f.debug_list().entries(ops).finish()
    }
}

/// The ops of the code `insns`, then the `rest` of each. They keep the allocation of `insns` if it has room for them.
fn with_rests(insns: Vec<Instruction>) -> Vec<Op> {
    use std::mem::ManuallyDrop;

    use crate::opcode::{Class, OpCode};
    use crate::transfer::{FAR, GUARD};

    /// Whether a slot with opcode byte `byte` ends its block.
    const ENDS: [bool; 256] = byte_table!(|byte| {
        let jumps = matches!(OpCode(fuse::usual(byte)).class(), Class::Jmp32 | Class::Jmp64);
        jumps || byte == FAR || byte == GUARD
    });
    const _: () = assert!(size_of::<Op>() == size_of::<Instruction>() && size_of::<Op>() == size_of::<u64>());
    const _: () = assert!(align_of::<Op>() == align_of::<Instruction>() && align_of::<Op>() == align_of::<u64>());

    let n = insns.len();
    let mut insns = ManuallyDrop::new(insns);
    insns.reserve_exact(n);
    let (slots, capacity) = (insns.as_mut_ptr().cast::<Op>(), insns.capacity());
    // backwards, as each `rest` follows from the next; the last slot holds `GUARD`, which ends a block
    let mut rest = 0;
    let (mut op, mut rests) = (slots.wrapping_add(n), slots.wrapping_add(2 * n));
    while op != slots {
        // SAFETY: the loop has written only the slots after `op`, so slot `op` still holds its instruction, and the
        // allocation has room for `2 * n` slots
        unsafe {
            (op, rests) = (op.sub(1), rests.sub(1));
            let insn = op.cast::<Instruction>().read();
            // an op keeps the opcode byte of its instruction
            rest = match ENDS[usize::from(insn.byte())] {
                true => 1,
                false => rest + 1,
            };
            op.write(Op::new(insn));
            rests.cast::<u64>().write(rest);
        }
    }
    // SAFETY: `slots` is the allocation of `insns`, whose elements have the size and alignment of `Op`, and the loop
    // wrote its first `2 * n`
    unsafe { Vec::from_raw_parts(slots, 2 * n, capacity) }
}

/// The `rest` of the op in `slot`.
///
/// # Safety
///
/// The slot must lie in the ops of `code`, the slots of a [`Rests`].
#[inline(always)]
unsafe fn rest(code: &[Op], slot: Slot) -> u64 {
    let rests = code.len() * (size_of::<Op>() / 2);
    // SAFETY: the caller's; the slot as many slots after an op as there are ops holds its `rest`
    unsafe { slot.0.byte_add(rests).cast::<u64>().read() }
}

struct Steps<M, H>(PhantomData<(M, H)>);

impl<M: Memory, H: Host<M>> Steps<M, H> {
    /// The table [`BlockFuel::single_step`] runs a block's slots with: each dispatch returns to it.
    const TABLE: Table<M, H> = {
        let single_step = BlockFuel::single_step::<M, H> as Handler<M, H>;
        Table([single_step; 256], [single_step; 256])
    };
}

/// For each opcode byte, the byte whose handler runs a slot with that byte one instruction at a time: for a
/// superinstruction, that of its first instruction.
const ALONE: [u8; 256] = byte_table!(|byte| match fuse::Super::with_byte(byte) {
    Some(sup) => sup.op(0),
    None => byte,
});
