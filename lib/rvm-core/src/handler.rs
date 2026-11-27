//! The handlers of the eBPF opcodes: [`handler`] for the instructions that continue with the next one, [`jump`] for
//! the jump classes, [`alu3_imm`] / [`alu3_reg`] for folded 3-operand ALU pairs, and the host calls.

use crate::code::Slots;
use crate::dispatch::{Handler, Spare};
use crate::fuel::{Fuel, RestsPtr};
use crate::host::Callee;
use crate::opcode::{Class, MemMode, MemSize, OpCode, CALL, CALLX};
use crate::slot::{Fields, Layout, Shape, Slot, LAYOUTS};
use crate::step::{self, Regs, Step, BITS_32, BITS_64};
use crate::transfer::{self, Ip};
use crate::{Context, Host, Interpreter, Memory, Reason};

/// Dedicated opcode byte for `call <helper id>` (`src_reg == 0`), dispatched straight to [`host_call`].
pub const CALL_HELPER: u8 = 0x22;
/// Dedicated opcode byte for `call <kfunc slot>` (`src_reg == 2`), dispatched straight to [`host_call`].
pub const CALL_KFUNC: u8 = 0x23;
/// Dedicated opcode byte for `addr_space_cast` to address space 1 (guest to host address).
pub const TO_HOST: u8 = 0x2a;
/// Dedicated opcode byte for `addr_space_cast` to address space 0 (host to guest address).
pub const TO_GUEST: u8 = 0x2b;

/// Install direct handlers for local, helper, kfunc and indirect calls and address-space casts.
pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
    table[CALL as usize] = local_call::<M, H, F>;
    table[CALL_HELPER as usize] = host_call::<M, H, F, false>;
    table[CALL_KFUNC as usize] = host_call::<M, H, F, true>;
    table[CALLX as usize] = indirect_call::<M, H, F, false>;
    table[TO_HOST as usize] = addr_space_cast::<M, H, true>;
    table[TO_GUEST as usize] = addr_space_cast::<M, H, false>;
}

/// Apply one of the nine foldable ALU operations (`0..=8`: add, sub, mul, or, and, xor, lsh, rsh, arsh).
#[inline(always)]
fn eval_alu3<const ALU64: bool, const OP: u8>(a: u64, b: u64) -> u64 {
    let a = if ALU64 { a } else { a as u32 as u64 };
    let b = if ALU64 { b } else { b as u32 as u64 };
    let sh = if ALU64 { b & 63 } else { b & 31 };
    let res = match OP {
        0 => a.wrapping_add(b),
        1 => a.wrapping_sub(b),
        2 => a.wrapping_mul(b),
        3 => a | b,
        4 => a & b,
        5 => a ^ b,
        6 => a << sh,
        7 => a >> sh,
        8 => match ALU64 {
            true => ((a as i64) >> sh) as u64,
            false => ((a as i32) >> sh) as u64,
        },
        _ => unreachable!(),
    };
    if ALU64 {
        res
    } else {
        res as u32 as u64
    }
}

/// Folded 3-operand ALU with immediate: `dst = src1 op imm` (replaces `mov dst, src1; op dst, imm`).
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn alu3_imm<M: Memory, H: Host<M>, const ALU64: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile_threaded` built `slot` with `Slot::alu3_imm`.
    let src1 = unsafe { slot.alu3_src1() };
    let dst = unsafe { slot.alu3_dst() };
    let imm = match ALU64 {
        true => slot.alu3_imm_val() as i64 as u64,
        false => slot.alu3_imm_val() as u32 as u64,
    };
    let res = eval_alu3::<ALU64, OP>(ctx.reg_get(src1), imm);
    ctx.reg_set(dst, res);

    become_at!(ctx, code, ip.offset(2), interp, rests)
}

/// Folded 3-operand ALU with register: `dst = src1 op src2` (replaces `mov dst, src1; op dst, src2`).
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn alu3_reg<M: Memory, H: Host<M>, const ALU64: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `compile_threaded` built `slot` with `Slot::alu3_reg`.
    let src1 = unsafe { slot.alu3_src1() };
    let dst = unsafe { slot.alu3_dst() };
    let src2 = unsafe { slot.alu3_src2() };
    let res = eval_alu3::<ALU64, OP>(ctx.reg_get(src1), ctx.reg_get(src2));
    ctx.reg_set(dst, res);

    become_at!(ctx, code, ip.offset(2), interp, rests)
}

/// The [`Handler`](crate::dispatch::Handler) of opcode `OP` of the ALU, load and store classes.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn handler<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    mut ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its opcode (see `Handler`)
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let res: Step<M::Error> = match const { OpCode(crate::bytes::usual(OP)).class() } {
        Class::Alu32 => {
            let mut regs = ctx.regs_view_mut();
            step::alu::<M::Error, _, BITS_32>(&mut regs, insn).into()
        }
        Class::Alu64 => {
            let mut regs = ctx.regs_view_mut();
            step::alu::<M::Error, _, BITS_64>(&mut regs, insn).into()
        }
        Class::Ld => step::ld(insn),
        Class::Ldx
            if const {
                let opc = OpCode(crate::bytes::usual(OP));
                matches!(opc.mem_mode(), MemMode::MemSX) && !matches!(opc.mem_size(), MemSize::DWord)
            } =>
        {
            let opc = const { OpCode(crate::bytes::usual(OP)) };
            let addr = step::address(ctx.reg_get(insn.src_reg()), insn);
            if let Some(raw) =
                interp
                    .windows
                    .run_data(opc, const { crate::windows::kind(OpCode(crate::bytes::usual(OP))) }, addr, 0)
            {
                let val = match const { OpCode(crate::bytes::usual(OP)).mem_size() } {
                    MemSize::Byte => raw as u8 as i8 as i64 as u64,
                    MemSize::Half => raw as u16 as i16 as i64 as u64,
                    MemSize::Word => raw as u32 as i32 as i64 as u64,
                    MemSize::DWord => unreachable!(),
                };
                ctx.reg_set(insn.dst_reg(), val);
                become_next!(ctx, code, ip, interp, rests)
            }
            core::hint::cold_path();
            let size = const { OpCode(crate::bytes::usual(OP)).mem_size().bytes() as u64 };
            if interp.promo_overlaps(addr, size) {
                become ldx_memsx_bail::<M, H, OP>(ctx, code, ip, interp, rests, crate::dispatch::SPARE, slot)
            }
            let (mut regs, memory) = ctx.split_mut();
            step::step(&mut regs, memory, insn)
        }
        _ => {
            let (mut regs, memory) = ctx.split_mut();
            step::step(&mut regs, memory, insn)
        }
    };
    match res {
        Step::Next => {}
        Step::LdImm64 => {
            // SAFETY: this handler runs a slot below `len` (see `Ip`), so the next one lies in `0..=len`
            let second = unsafe { ip.offset(1).get() };
            let Some(upper) = transfer::second_half(second) else {
                // the code ends inside LD_IMM64
                return interp.stop.at(ip, Reason::BadPc);
            };
            ip = ip.offset(1);
            let mut regs = ctx.regs_view_mut();
            step::ld_imm64(&mut regs, insn, upper);
        }
        Step::Stop(reason) => return interp.stop.at(ip, reason),
        _ => unreachable!("only the jump classes jump, call or exit"),
    }

    // `ip` is at `insn` or at the second half of LD_IMM64, which `second_half` found below `len`
    become_next!(ctx, code, ip, interp, rests)
}

/// Cold bailout path for an `LDX_MEMSX` whose address overlaps the active promoted stack frame.
// Out of line so `handler::<LDX_MEMSX>` calls no function and needs no stack frame.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn ldx_memsx_bail<M: Memory, H: Host<M>, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    _slot: Slot,
) {
    let (unpromoted, new_ip) = interp.bail_promoted(ctx, code, ip);
    // SAFETY: `new_ip` points at the same in-bounds pc in the unpromoted stream.
    let new_slot = unsafe { new_ip.get() };
    become handler::<M, H, OP>(ctx, unpromoted, new_ip, interp, rests, crate::dispatch::SPARE, new_slot)
}

/// The [`Handler`](crate::dispatch::Handler) of opcode `OP` of the jump classes. Every such instruction ends its block.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn jump<M: Memory, H: Host<M>, F: Fuel, const OP: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `handler`
    let insn = unsafe { ip.view(slot, const { Shape::of(OP) }) };
    let step: Step<M::Error> = match const { OpCode(crate::bytes::usual(OP)).class() } {
        Class::Jmp32 => step::jump::<M::Error, _, BITS_32>(&ctx.regs_view(), insn),
        Class::Jmp64 => step::jump::<M::Error, _, BITS_64>(&ctx.regs_view(), insn),
        _ => unreachable!("only the jump classes use `jump`"),
    };
    match step {
        Step::Next => become_enter!(ctx, code, ip.offset(1), interp, rests),
        Step::Jump(offset) => {
            if const { matches!(LAYOUTS[OP as usize], Layout::DstSrc) } {
                let byte_off = slot.imm_i32() as isize;
                become_enter!(ctx, code, ip.byte_offset(byte_off), interp, rests)
            } else {
                become_enter!(ctx, code, ip.offset(offset + 1), interp, rests)
            }
        }
        Step::Exit => match interp.pop(&mut ctx.regs) {
            Some(ret_ip) => {
                if ret_ip.addr() & 1 != 0 {
                    core::hint::cold_path();
                    return interp.exit_special(ret_ip);
                }
                become_enter!(ctx, code, ret_ip, interp, rests)
            }
            None => interp.stop.at(ip, Reason::Exit),
        },
        Step::Stop(reason) => interp.stop.at(ip, reason),
        Step::Call(_) | Step::CallHelper | Step::CallKfunc | Step::CallIndirect | Step::LdImm64 => {
            unreachable!("calls and LD_IMM64 have their own handlers")
        }
    }
}

/// Direct handler for unconditional `ja` whose byte displacement `(offset + 1) * 16` was pre-scaled into `slot`.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn ja_scaled<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    let byte_off = slot.imm_i32() as isize;
    become_enter!(ctx, code, ip.byte_offset(byte_off), interp, rests)
}

/// Direct handler for local `call` whose byte displacement `(offset + 1) * 16` was pre-scaled into `slot`.
#[rustc_align(64)]
#[inline(never)]
pub extern "rust-preserve-none" fn local_call_scaled<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    if !interp.push(&mut ctx.regs, ip.offset(1)) {
        return interp.stop.at(ip, Reason::StackOverflow);
    }
    let byte_off = slot.imm_i32() as isize;
    become_enter!(ctx, code, ip.byte_offset(byte_off), interp, rests)
}

/// Direct handler for local `call` (`src_reg == 1`): pushes the caller frame and enters the target without checking
/// `src_reg`.
#[inline(never)]
extern "rust-preserve-none" fn local_call<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: `rewrite` leaves `CALL` only for local calls, and `transfer::bound` proves the target lies in `0..=len`
    let offset = unsafe { ip.view(slot, const { Shape::of(CALL) }) }.imm();
    if !interp.push(&mut ctx.regs, ip.offset(1)) {
        return interp.stop.at(ip, Reason::StackOverflow);
    }
    become_enter!(ctx, code, ip.offset(i64::from(offset) + 1), interp, rests)
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
    rests: RestsPtr,
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

    become_enter!(ctx, code, ip.offset(1), interp, rests)
}

/// The rest of the handler of `callx`: enters the guest function that [`Host::call_indirect`] names, as a local call
/// does, or continues with the next instruction after the host function it ran. With `STACK`, the handler of a
/// `callx` in a program that stores stack arguments ([`args::CALLX`](crate::args::CALLX)), where a native function
/// that the host calls gets those of the frame.
// Out of line for the reason `host_call` is.
#[inline(never)]
pub extern "rust-preserve-none" fn indirect_call<M: Memory, H: Host<M>, F: Fuel, const STACK: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in the handler of `callx`, which continues here; the slot of a `callx` with stack arguments has the
    // same layout
    let target = ctx
        .regs
        .get(unsafe { ip.view(slot, const { Shape::of(CALLX) }) }.dst_reg());
    let (host, native) = interp.callx(ip, STACK);
    let callee = host.call_indirect(ctx, target, native);
    interp.windows.revalidate(ctx.memory);
    match callee {
        Some(Callee::Local(pc)) => {
            // the slots from `len` on all hold the guard, and no slot below it does
            let in_code = code.raw_slot(pc).is_some_and(|slot| slot.byte() != transfer::GUARD);
            if !in_code {
                return interp.stop.at(ip, Reason::CallIndirect(target));
            }
            if !interp.push(&mut ctx.regs, ip.offset(1)) {
                return interp.stop.at(ip, Reason::StackOverflow);
            }
            become_at_pc!(ctx, code, pc, interp, rests)
        }
        Some(Callee::Host(r0)) => {
            ctx.regs[0] = r0;
            become_enter!(ctx, code, ip.offset(1), interp, rests)
        }
        None => interp.stop.at(ip, Reason::CallIndirect(target)),
    }
}

/// The handler of [`TO_HOST`] (`TO_HOST_DIR`) and [`TO_GUEST`]: converts a pointer between address spaces 0 and 1.
#[inline(never)]
extern "rust-preserve-none" fn addr_space_cast<M: Memory, H: Host<M>, const TO_HOST_DIR: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its byte
    let insn = unsafe { ip.view(slot, const { Shape::of(if TO_HOST_DIR { TO_HOST } else { TO_GUEST }) }) };
    let src = ctx.regs.get(insn.src_reg());
    let dst = match TO_HOST_DIR {
        true => ctx.memory.host_address(src),
        false => ctx.memory.guest_address(src),
    };
    ctx.regs.set(insn.dst_reg(), dst);

    become_next!(ctx, code, ip, interp, rests)
}
