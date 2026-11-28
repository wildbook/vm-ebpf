//! The handler that runs a superinstruction.

use super::supers::{Super, MAX_LEN, MAX_ROLES};
use crate::code::Slots;
use crate::context::FP;
use crate::dispatch::{Spare, SPARE};
use crate::fuel::{Fuel, RestsPtr};
use crate::slot::{Fields, Layout, Reg, Shape, Slot, View, LAYOUTS};
use crate::step::{self, Regs, Step};
use crate::transfer::Ip;
use crate::{windows, Context, Host, Interpreter, Memory};

/// The handler of superinstruction `S`. It runs the sequence as the handlers of its instructions would, one after
/// another, but keeps each role in a variable of its own: it loads the roles the sequence reads before it writes them,
/// and stores the written ones back once, after the last instruction that writes one or before an instruction that
/// stops. A sequence that names each role once runs on the registers themselves ([`Super::direct`]). The sequence lies
/// in one block, which it ends if its last instruction branches; only then does `F` matter.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn fused<M: Memory, H: Host<M>, F: Fuel, const S: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    let sup = const { Super::of(S) };
    let len = const { Super::of(S).len() };

    // SAFETY: `transfer::bound` leaves a superinstruction only where its sequence lies in the code, and the guard slot
    // follows the code (see `Ip`)
    let sequence = unsafe { ip.slots(code, len + 1) };
    // SAFETY: `encode` found the opcode of each instruction of the sequence in its first slot, and `compile_threaded`
    // encodes each slot in the threaded layout of its opcode without 3-op folding inside a superinstruction.
    let slot_of = |k: usize| {
        macro_rules! view {
            ($($k:literal),*) => {
                match k {
                    $($k => unsafe {
                        let cached = if $k == 0 { Some(slot) } else { None };
                        View::threaded(&sequence[$k].slot, cached, const { Shape::of(Super::of(S).opcode($k)) })
                    },)*
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
        registers,
        direct: sup.direct,
    };
    roles.load(registers, sup.loads);

    // Continue at `$next`: enter its block if the sequence ends one, or carry on in the block. A branch dispatches on
    // each side, so that it stays a branch: a `cmov` of the next ip would make the next fetch wait for the registers
    // the branch compares.
    macro_rules! become_after {
        ($next:expr) => {{
            let next = $next;
            match const { Super::of(S).branches() } {
                true => become_enter!(ctx, code, next, interp, rests),
                // the slot after the sequence lies in `0..=len` (see `sequence`)
                false => become_at!(ctx, code, next, interp, rests),
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
                    // the access missed its window: continue unfused from it, directly to its window handler
                    true => {
                        roles.save(registers, sup.unsaved[$k]);
                        let miss_slot = if $k == 0 { slot } else { sequence[$k].slot };
                        let Some(access) = (const {
                            let sup = Super::of(S);
                            windows::access_handler::<M, H>(sup.opcode($k), sup.is_fp_access($k))
                        }) else {
                            unreachable!("windowed opcode has a window handler")
                        };
                        become access(ctx, code, at, interp, rests, SPARE, miss_slot)
                    }
                    false => step::step(&mut roles, ctx.memory, decoded),
                };
                match step {
                    Step::Next => {}
                    // only the last instruction branches, after `save_at`; `transfer::bound` leaves a
                    // superinstruction only where its branch target lies in `0..=len` (see `Ip`)
                    Step::Jump(offset) => {
                        if const { matches!(LAYOUTS[Super::of(S).opcode($k) as usize], Layout::DstSrc) } {
                            let byte_off = sequence[$k].slot.imm_i32() as isize;
                            let taken_rest = u64::from(sequence[$k].slot.byte2());
                            become_enter_rest!(ctx, code, ip.offset($k).byte_offset(byte_off), interp, rests, taken_rest)
                        } else if const { crate::handler::is_cond_dst_jump(Super::of(S).opcode($k)) } {
                            let byte_off = sequence[$k].slot.offset_raw() as isize;
                            let taken_rest = u64::from(sequence[$k].slot.byte());
                            become_enter_rest!(ctx, code, ip.offset($k).byte_offset(byte_off), interp, rests, taken_rest)
                        } else {
                            become_after!(ip.offset($k + 1 + offset))
                        }
                    }
                    Step::LdImm64 => step::ld_imm64(&mut roles, decoded, sequence[$k + 1].slot.imm()),
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
    if const { Super::of(S).branches() } {
        let fall_rest = match const { LAYOUTS[Super::of(S).opcode(0) as usize] } {
            Layout::Dst => u64::from(slot.byte()),
            Layout::DstSrc => u64::from(slot.byte2()),
            Layout::Raw => unreachable!("no branching superinstruction starts with Layout::Raw"),
        };
        become_enter_rest!(ctx, code, ip.offset(len as i64), interp, rests, fall_rest)
    }
    become_at!(ctx, code, ip.offset(len as i64), interp, rests)
}

/// The registers of a superinstruction's sequence as [`fused`] runs it: its instructions name role `r` as register
/// `r`, kept in `values` or with `direct` in its register `registers[r]`, the register operand `_` as [`FREE`], which
/// is register `free` in `regs`, and `fp` as r10.
struct Roles<'a> {
    values: [u64; MAX_ROLES],
    regs: &'a mut [u64; 16],
    free: Reg,
    registers: [Reg; MAX_ROLES],
    direct: bool,
}

/// The register indexes [`fused`] gives the roles.
const ROLE_INDEXES: [Reg; MAX_ROLES] = [Reg::low(0), Reg::low(1), Reg::low(2), Reg::low(3)];

/// The register index [`fused`] gives the register operand `_`.
const FREE: Reg = Reg::low(15);

/// r10, which a sequence only reads, as the base of `fp`.
const FP_REG: Reg = Reg::low(FP as u8);

impl Roles<'_> {
    /// Load the roles in the bit set `roles` from their registers `registers`.
    // Unrolled so constant role masks fold at `opt-level = "s"`.
    #[inline(always)]
    fn load(&mut self, registers: [Reg; MAX_ROLES], roles: u8) {
        macro_rules! step {
            ($($role:literal),*) => {$(
                if roles & 1 << $role != 0 {
                    self.values[$role] = self.regs.get(registers[$role]);
                }
            )*};
        }
        const _: () = assert!(MAX_ROLES == 4);
        step!(0, 1, 2, 3);
    }

    /// Store the roles in the bit set `roles` to their registers `registers`.
    #[inline(always)]
    fn save(&mut self, registers: [Reg; MAX_ROLES], roles: u8) {
        macro_rules! step {
            ($($role:literal),*) => {$(
                if roles & 1 << $role != 0 {
                    self.regs.set(registers[$role], self.values[$role]);
                }
            )*};
        }
        const _: () = assert!(MAX_ROLES == 4);
        step!(0, 1, 2, 3);
    }
}

// The instructions name no other fixed register: `Step::parse` makes no atomics, of which `CMPXCHG` names r0.
impl Regs for Roles<'_> {
    #[inline(always)]
    fn get(&self, reg: Reg) -> u64 {
        match reg {
            FREE => self.regs.get(self.free),
            FP_REG => self.regs.get(FP_REG),
            role if self.direct => self.regs.get(self.registers[usize::from(role.get())]),
            role => self.values[usize::from(role.get())],
        }
    }

    #[inline(always)]
    fn set(&mut self, reg: Reg, value: u64) {
        match reg {
            FREE => self.regs.set(self.free, value),
            role if self.direct => self.regs.set(self.registers[usize::from(role.get())], value),
            role => self.values[usize::from(role.get())] = value,
        }
    }
}
