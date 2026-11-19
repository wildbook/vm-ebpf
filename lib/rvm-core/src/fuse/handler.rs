//! The handler that runs a superinstruction.

use std::ops::ControlFlow;

use super::supers::{Super, MAX_LEN, MAX_ROLES};
use crate::op::{Fields, Op, Reg, View};
use crate::ops::Regs;
use crate::transfer::Slot;
use crate::{charge, stack, step, step_ld64, CallStack, Context, Flow, Handlers, Host, Memory, Table};

/// The handler of superinstruction `S`. It runs the sequence as the handlers of its instructions would, one after
/// another, but keeps each role in a variable of its own: it loads the roles the sequence reads before it writes them,
/// and stores the written ones back once, after the last instruction that writes one or before an instruction that
/// stops.
#[inline(never)]
pub extern "rust-preserve-none" fn fused<M: Memory, H: Host<M>, const FUEL: bool, const S: u8>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    let sup = const { Super::of(S) };
    let len = const { Super::of(S).len() };

    // the fuel runs out inside the sequence, which takes one unit per slot
    if FUEL && fuel < len as u64 - 1 {
        let alone = const { Handlers::<M, H, FUEL>::TABLE.0[Super::of(S).op(0) as usize] };
        become alone(ctx, code, slot, fuel, calls, table, op)
    }
    // SAFETY: `transfer::bound` leaves a superinstruction only where its sequence lies in the code, and the guard slot
    // follows the code (see `Slot`)
    let window = unsafe { slot.window(code, len + 1) };
    // SAFETY: `encode` found the opcode of each instruction of the sequence in its first slot, and the bytes `Code::new`
    // gives such a slot afterwards stand for the same opcode (see `usual`), so they have its layout
    let slot_of = |k: usize| unsafe { View::new(&window[k], None, sup.op(k)) };

    let registers = sup.registers(slot_of);
    let free = sup.free_at.map_or(Reg::R0, |k| slot_of(usize::from(k)).dst_reg());
    let mut roles = Roles {
        values: [0; MAX_ROLES],
        regs: &mut ctx.regs,
        free,
    };
    roles.load(registers, sup.loads);

    // Continue at `$next`, whose op is `$op`, once the sequence is charged. A branch dispatches on each side, so that it
    // stays a branch: a `cmov` of the next slot's address would make the next fetch wait for the registers the branch
    // compares.
    macro_rules! dispatch {
        ($next:expr, $op:expr) => {{
            let next = $next;
            let Some(left) = charge::<FUEL>(fuel - (len as u64 - 1) * u64::from(FUEL)) else {
                return calls.stop.at(next, 0, Flow::OutOfFuel);
            };
            let next_op = $op;
            become table.of(next_op)(ctx, code, next, left, calls, table, next_op)
        }};
    }

    // one block per instruction, so that each `step` sees a constant opcode and constant register indexes
    macro_rules! exec {
        ($($k:literal),*) => {$(
            if $k < len && !const { Super::of(S).is_data($k) } {
                if $k == sup.save_at as usize {
                    roles.save(registers, sup.writes);
                }
                let at = slot.offset($k);
                let decoded = sup.decode($k, slot_of($k), ROLE_INDEXES, Some(FREE));
                let flow = match const { stack::windowed(Super::of(S).op($k)) } {
                    true => ControlFlow::Break(stack::data_step(&mut calls.windows, &mut roles, &mut ctx.data, decoded)),
                    false => step(&mut roles, &mut ctx.data, decoded),
                };
                match flow {
                    ControlFlow::Break(Flow::Next) => {}
                    // only the last instruction branches, after `save_at`
                    ControlFlow::Break(Flow::Jump(offset)) if const { Super::of(S).branches_at($k) } => {
                        let target = slot.offset($k + 1 + offset);
                        // SAFETY: `transfer::bound` leaves a superinstruction only where its branch target lies in
                        // `0..=len` (see `Slot`)
                        dispatch!(target, unsafe { target.get() })
                    }
                    ControlFlow::Break(flow) => {
                        roles.save(registers, sup.unsaved[$k]);
                        return calls.stop.at(at, fuel - $k * u64::from(FUEL), flow);
                    }
                    ControlFlow::Continue(()) => step_ld64(&mut roles, decoded, window[$k + 1].imm()),
                }
            }
        )*};
    }
    // one block per slot a sequence may fill
    const _: () = assert!(MAX_LEN == 5);
    exec!(0, 1, 2, 3, 4);
    if sup.save_at as usize == len {
        roles.save(registers, sup.writes);
    }
    dispatch!(slot.offset(len as i64), window[len])
}

/// The registers of a superinstruction's sequence as [`fused`] runs it: its instructions name role `r` as register
/// `r`, kept in `values`, and the register operand `_` as [`FREE`], which is register `free` in `regs`.
struct Roles<'a> {
    values: [u64; MAX_ROLES],
    regs: &'a mut [u64; 16],
    free: Reg,
}

/// The register indexes [`fused`] gives the roles.
const ROLE_INDEXES: [Reg; MAX_ROLES] = [Reg::low(0), Reg::low(1), Reg::low(2), Reg::low(3)];

/// The register index [`fused`] gives the register operand `_`.
const FREE: Reg = Reg::low(15);

impl Roles<'_> {
    /// Load the roles in the bit set `roles` from their registers `registers`.
    #[inline(always)]
    fn load(&mut self, registers: [Reg; MAX_ROLES], roles: u8) {
        for role in 0..MAX_ROLES {
            if roles & 1 << role != 0 {
                self.values[role] = self.regs.get(registers[role]);
            }
        }
    }

    /// Store the roles in the bit set `roles` to their registers `registers`.
    #[inline(always)]
    fn save(&mut self, registers: [Reg; MAX_ROLES], roles: u8) {
        for role in 0..MAX_ROLES {
            if roles & 1 << role != 0 {
                self.regs.set(registers[role], self.values[role]);
            }
        }
    }
}

// The instructions name no fixed register: `Step::parse` makes no atomics, of which `CMPXCHG` names r0.
impl Regs for Roles<'_> {
    #[inline(always)]
    fn get(&self, reg: Reg) -> u64 {
        match reg {
            FREE => self.regs.get(self.free),
            role => self.values[usize::from(role.get())],
        }
    }

    #[inline(always)]
    fn set(&mut self, reg: Reg, value: u64) {
        match reg {
            FREE => self.regs.set(self.free, value),
            role => self.values[usize::from(role.get())] = value,
        }
    }
}
