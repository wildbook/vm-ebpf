//! The handlers of the eBPF opcodes: [`handler`] for the instructions that continue with the next one, and [`jump`]
//! for the jump classes, with the host calls it hands on to.

use crate::code::Slots;
use crate::dispatch::{self, Spare, Table, SPARE};
use crate::fuel::Fuel;
use crate::host::Callee;
use crate::native::NativeCall;
use crate::opcode::{CALL, CALLX};
use crate::slot::{Fields, Shape, Slot};
use crate::step::{self, Regs, Step};
use crate::transfer::{self, Ip};
use crate::{Context, Host, Interpreter, Memory, Reason};

/// The [`Handler`](dispatch::Handler) of opcode `OP` of the ALU, load and store classes.
#[inline(never)]
pub extern "rust-preserve-none" fn handler<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    mut ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its opcode (see `Handler`)
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    match step::step(&mut ctx.regs, ctx.memory, insn) {
        Step::Next => {}
        Step::LdImm64 => {
            // SAFETY: this handler runs a slot below `len` (see `Ip`), so the next one lies in `0..=len`
            let second = unsafe { ip.offset(1).get() };
            let Some(upper) = transfer::second_half(second) else {
                // the code ends inside LD_IMM64
                return interp.stop.at(ip, Reason::BadPc);
            };
            ip = ip.offset(1);
            step::ld_imm64(&mut ctx.regs, insn, upper);
        }
        Step::Stop(reason) => return interp.stop.at(ip, reason),
        _ => unreachable!("only the jump classes jump, call or exit"),
    }

    // `ip` is at `insn` or at the second half of LD_IMM64, which `second_half` found below `len`
    become_next!(ctx, code, ip, interp, table, dispatch::splits(OP))
}

/// The [`Handler`](dispatch::Handler) of opcode `OP` of the jump classes. Every such instruction ends its block.
#[inline(never)]
pub extern "rust-preserve-none" fn jump<M: Memory, H: Host<M>, F: Fuel, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    mut ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `handler`
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    match step::step(&mut ctx.regs, ctx.memory, insn) {
        Step::Next => {}
        Step::Jump(offset) => ip = ip.offset(offset),
        Step::Call(offset) => {
            if !interp.push(&mut ctx.regs, ip.pc(code)) {
                return interp.stop.at(ip, Reason::StackOverflow);
            }
            ip = ip.offset(offset);
        }
        Step::Exit => match interp.pop(&mut ctx.regs) {
            // `Interpreter::push` takes any pc, so this one has no proof
            Some(call_pc) => become_at_pc!(ctx, code, call_pc.wrapping_add(1), interp, table),
            None => return interp.stop.at(ip, Reason::Exit),
        },
        Step::CallHelper => become host_call::<M, H, F, false>(ctx, code, ip, interp, table, SPARE, slot),
        Step::CallKfunc => become host_call::<M, H, F, true>(ctx, code, ip, interp, table, SPARE, slot),
        Step::CallIndirect => become indirect_call::<M, H, F>(ctx, code, ip, interp, table, SPARE, slot),
        Step::Stop(reason) => return interp.stop.at(ip, reason),
        Step::LdImm64 => unreachable!("LD_IMM64 is of the LD class"),
    }

    // `ip` is at `insn` or precedes the target of a jump or local call
    become_enter!(ctx, code, ip.offset(1), interp, table)
}

/// The rest of the handler of a helper `call`, or with `KFUNC` a kfunc `call`: runs it on the host and continues with
/// the next instruction.
// Out of line, so that `jump`, which also runs local calls, calls no function and needs no stack frame.
#[inline(never)]
extern "rust-preserve-none" fn host_call<M: Memory, H: Host<M>, F: Fuel, const KFUNC: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in the handler of `call`, which continues here
    let id = unsafe { ip.view(slot, const { Shape::of(CALL) }) }.imm() as u32;
    let (r0, declined) = match KFUNC {
        true => (interp.host.call_kfunc(ctx, id), Reason::CallKfunc(id)),
        false => (interp.host.call_helper(ctx, id), Reason::CallHelper(id)),
    };
    let Some(r0) = r0 else {
        return interp.stop.at(ip, declined);
    };
    interp.windows.revalidate(ctx.memory);
    ctx.regs[0] = r0;

    become_enter!(ctx, code, ip.offset(1), interp, table)
}

/// The rest of the handler of `callx`: enters the guest function that [`Host::call_indirect`] names, as a local call
/// does, or continues with the next instruction after the host function it ran.
// Out of line for the reason `host_call` is.
#[inline(never)]
extern "rust-preserve-none" fn indirect_call<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in the handler of `callx`, which continues here
    let target = ctx
        .regs
        .get(unsafe { ip.view(slot, const { Shape::of(CALLX) }) }.dst_reg());
    let native = NativeCall::new(&mut interp.stop, ip);
    let callee = interp.host.call_indirect(ctx, target, native);
    interp.windows.revalidate(ctx.memory);
    match callee {
        Some(Callee::Local(pc)) => {
            // the slots from `len` on all hold the guard, and no slot below it does
            let in_code = code.get(pc).is_some_and(|slot| slot.byte() != transfer::GUARD);
            if !in_code {
                return interp.stop.at(ip, Reason::CallIndirect(target));
            }
            if !interp.push(&mut ctx.regs, ip.pc(code)) {
                return interp.stop.at(ip, Reason::StackOverflow);
            }
            become_at_pc!(ctx, code, pc, interp, table)
        }
        Some(Callee::Host(r0)) => {
            ctx.regs[0] = r0;
            become_enter!(ctx, code, ip.offset(1), interp, table)
        }
        None => interp.stop.at(ip, Reason::CallIndirect(target)),
    }
}
