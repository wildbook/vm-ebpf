//! The handler that runs a superinstruction.

use super::supers::{Super, MAX_LEN, MAX_ROLES};
use crate::code::Slots;
use crate::dispatch::{Spare, Table, SPARE};
use crate::fuel::Fuel;
use crate::slot::{Fields, Reg, Shape, Slot, View};
use crate::step::{self, Regs, Step};
use crate::transfer::Ip;
use crate::{windows, Context, Host, Interpreter, Memory};

/// The handler of superinstruction `S`. It runs the sequence as the handlers of its instructions would, one after
/// another, but keeps each role in a variable of its own: it loads the roles the sequence reads before it writes them,
/// and stores the written ones back once, after the last instruction that writes one or before an instruction that
/// stops. The sequence lies in one block, which it ends if its last instruction branches; only then does `F` matter.
#[inline(never)]
pub extern "rust-preserve-none" fn fused<M: Memory, H: Host<M>, F: Fuel, const S: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    _slot: Slot,
) {
    let sup = const { Super::of(S) };
    let len = const { Super::of(S).len() };

    // SAFETY: `transfer::bound` leaves a superinstruction only where its sequence lies in the code, and the guard slot
    // follows the code (see `Ip`)
    let sequence = unsafe { ip.slots(code, len + 1) };
    // SAFETY: `encode` found the opcode of each instruction of the sequence in its first slot, and the bytes
    // `Code::new` gives such a slot afterwards stand for the same opcode (see `bytes::usual`), so they have its
    // layout. Each slot's shape is a constant, so that the views fold for the constant `k` every caller passes.
    let slot_of = |k: usize| {
        macro_rules! view {
            ($($k:literal),*) => {
                match k {
                    $($k => unsafe { View::new(&sequence[$k], None, const { Shape::of(Super::of(S).opcode($k)) }) },)*
                    _ => unreachable!("a slot past `MAX_LEN`"),
                }
            };
        }
        const _: () = assert!(MAX_LEN == 5);
        view!(0, 1, 2, 3, 4)
    };

    let registers = sup.registers(slot_of);
    let free = sup.free_at.map_or(Reg::R0, |k| slot_of(usize::from(k)).dst_reg());
    let mut roles = Roles {
        values: [0; MAX_ROLES],
        regs: &mut ctx.regs,
        free,
    };
    roles.load(registers, sup.loads);

    // Continue at `$next`: enter its block if the sequence ends one, or carry on in the block. A branch dispatches on
    // each side, so that it stays a branch: a `cmov` of the next ip would make the next fetch wait for the registers
    // the branch compares.
    macro_rules! become_after {
        ($next:expr) => {{
            let next = $next;
            match const { Super::of(S).branches() } {
                true => become_enter!(ctx, code, next, interp, table),
                // the slot after the sequence lies in `0..=len` (see `sequence`)
                false => become_at!(ctx, code, next, interp, table, false),
            }
        }};
    }

    // one block per instruction, so that each `step` sees a constant opcode and constant register indexes
    macro_rules! run {
        ($($k:literal),*) => {$(
            if $k < len && !const { Super::of(S).is_data($k) } {
                if $k == sup.save_at as usize {
                    roles.save(registers, sup.writes);
                }
                let at = ip.offset($k);
                let decoded = sup.decode($k, slot_of($k), ROLE_INDEXES, Some(FREE));
                let step = match const { windows::windowed(Super::of(S).opcode($k)) } {
                    true if windows::data_step(&interp.windows, &mut roles, decoded) => Step::Next,
                    // the access missed the data window: the sequence continues unfused from it, as a jump into its
                    // middle would
                    true => {
                        roles.save(registers, sup.unsaved[$k]);
                        let slot = sequence[$k];
                        become table.of(slot)(ctx, code, at, interp, table, SPARE, slot)
                    }
                    false => step::step(&mut roles, ctx.memory, decoded),
                };
                match step {
                    Step::Next => {}
                    // only the last instruction branches, after `save_at`; `transfer::bound` leaves a
                    // superinstruction only where its branch target lies in `0..=len` (see `Ip`)
                    Step::Jump(offset) => become_after!(ip.offset($k + 1 + offset)),
                    Step::LdImm64 => step::ld_imm64(&mut roles, decoded, sequence[$k + 1].imm()),
                    Step::Stop(reason) => {
                        roles.save(registers, sup.unsaved[$k]);
                        return interp.stop.at(at, reason);
                    }
                    _ => unreachable!("a sequence holds no call and no `exit`"),
                }
            }
        )*};
    }
    // one block per slot a sequence may fill
    const _: () = assert!(MAX_LEN == 5);
    run!(0, 1, 2, 3, 4);
    if sup.save_at as usize == len {
        roles.save(registers, sup.writes);
    }
    become_after!(ip.offset(len as i64))
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
