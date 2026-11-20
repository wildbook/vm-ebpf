//! Fuel charged per block.
//!
//! [`run`](crate::run) reports fuel as if it charged one unit per slot before running it, and stops with
//! [`Flow::OutOfFuel`] at the first slot it has no unit for. The handlers charge the same units per block. A block ends
//! at the first slot at or after it whose handler may continue at a slot other than the next one: a jump-class
//! instruction (jumps, calls, `exit`, `gotox`, `may_goto`), a [`FAR`](crate::transfer::FAR) jump, or the
//! [`GUARD`](crate::transfer::GUARD). Every other handler continues at the next slot of its block, or after the second
//! slot of LD_IMM64, which lies in it too. A superinstruction lies in one block, and a block may hold jump targets.
//! [`slots`] gives each op its `rest`: the number of slots from it to the end of its block, inclusive.
//!
//! Invariant: the handler that runs slot `s` receives the fuel that charging per slot leaves before `s`, less
//! `rest(s)`, in wrapping arithmetic. A handler that continues in its block passes the fuel on unchanged, as `rest`
//! drops by the slots that charging per slot charges in between. One that ends its block continues at a slot `t` by
//! entering the block there ([`enter`]): it subtracts `rest(t)`, wherever `t` lies in that block. `run` and the
//! checked fetches do the same, so control may enter a block at any slot: at a jump target, after a call, or where
//! `run` starts after `gotox` or a declined host call.
//!
//! If the fuel before `t` is at least `rest(t)`, the fuel stays at or above 0 up to the end of the block, and no
//! handler tests it. Otherwise [`single_step`] runs the slots from `t` on one at a time and stops where charging per
//! slot runs out. That happens before the last slot of the block, whose `rest` is 1, so no handler that ends a block
//! runs this way.
//!
//! A handler that stops at slot `s` reports the fuel that charging per slot leaves there ([`unspent`]), plus the unit
//! of `s` where that slot gives it back. The invariant decides only what `run` reports, not where a handler reads or
//! continues, so a wrong `rest` can't break memory safety.
//!
//! The functions here read a `rest` only with `FUEL`, which is [`METERED`](crate::METERED): only a code built with the
//! `fuel` feature has them.

use crate::op::Op;
use crate::opcode::LD_IMM64;
use crate::transfer::Slot;
use crate::{fuse, CallStack, Context, Flow, Handlers, Host, Memory, Table};

/// The slots of a [`Code`](crate::Code) for the code `insns`: their ops, then the `rest` of each. They keep the
/// allocation of `insns` if it has room for them.
#[cfg(feature = "fuel")]
pub fn slots(insns: Vec<crate::Instruction>) -> Vec<Op> {
    use std::mem::ManuallyDrop;

    use crate::opcode::{Class, OpCode};
    use crate::transfer::{FAR, GUARD};
    use crate::Instruction;

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

/// The fuel the handler of `slot` in `code` receives where control enters its block there: `fuel` less the `rest` of
/// `slot`. Where it is negative as an `i64`, the fuel can't pay for the block, which then runs in [`single_step`]. The
/// callers test `FUEL` before the sign, so that rustc instantiates `single_step` only with `FUEL`.
#[inline(always)]
pub fn enter<const FUEL: bool>(code: &[Op], slot: Slot, fuel: u64) -> u64 {
    if !FUEL {
        return fuel;
    }
    // SAFETY: the slot a handler continues at lies in the ops of its code (see `Slot`)
    fuel.wrapping_sub(unsafe { slot.rest(code) })
}

/// The fuel that charging per slot leaves once the instruction in `slot` of `code` is charged, from the `fuel` its
/// handler received.
#[inline(always)]
pub fn unspent<const FUEL: bool>(code: &[Op], slot: Slot, fuel: u64) -> u64 {
    if !FUEL {
        return fuel;
    }
    // SAFETY: a handler's slot lies in the ops of its code (see `Slot`)
    fuel.wrapping_add(unsafe { slot.rest(code) }).wrapping_sub(1)
}

/// Runs the instruction in `slot` alone, in a block entered with too little fuel for it, if charging per slot leaves
/// a unit for it (two for LD_IMM64), and stops with [`Flow::OutOfFuel`] otherwise. Its handler continues here, through
/// the table [`Handlers::STEPS`], with the fuel its own handler would get. It reads the op from the slot, so that
/// [`enter`]'s callers needn't load it before they branch here.
#[cold]
#[inline(never)]
pub extern "rust-preserve-none" fn single_step<M: Memory, H: Host<M>, const FUEL: bool>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    _table: &Table<M, H>,
    _op: Op,
) {
    // SAFETY: a handler's slot lies in the ops of its code (see `Slot`)
    let (op, rest) = unsafe { (slot.get(), slot.rest(code)) };
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
    let handler = Handlers::<M, H, FUEL>::TABLE.0[usize::from(alone)];
    become handler(ctx, code, slot, fuel, calls, &Handlers::<M, H, FUEL>::STEPS, op)
}

/// For each opcode byte, the byte whose handler runs a slot with that byte one instruction at a time: for a
/// superinstruction, that of its first instruction.
const ALONE: [u8; 256] = byte_table!(|byte| match fuse::Super::with_byte(byte) {
    Some(sup) => sup.op(0),
    None => byte,
});
