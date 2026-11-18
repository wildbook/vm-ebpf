#![feature(explicit_tail_calls, rust_preserve_none_cc)]
#![allow(incomplete_features)]

use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::ControlFlow;

use opcode::{Class, MemMode, MemSize, OpCode};
use transfer::Slot;

mod call;
mod debug;
mod fuse;
mod instruction;
mod mem;
mod memory;
mod ops;
mod stack;
mod transfer;

pub mod opcode;

pub use call::{CallStack, Host, MAX_CALL_DEPTH};
pub use fuse::Code;
pub use instruction::{instructions_from_bytes, Instruction, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL};
pub use memory::{AtomicOp, Memory};
pub use stack::Window;

#[cfg(test)]
mod tests;

// https://www.rfc-editor.org/rfc/rfc9669.html

/// Why [`run`] stopped, or what an instruction does next; `E` is the error type of the memory, [`Memory::Err`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Flow<E> {
    Next,

    Jump(i64),
    /// A program-local call, with the offset of the callee.
    Call(i64),
    Exit,

    /// Call a helper by its numeric ID (`src_reg = 0`).
    CallHelper(u32),
    /// Call an external function by ID (`src_reg = BPF_PSEUDO_KFUNC_CALL`); the runtime defines what the ID indexes
    /// (rvm: the program's extern table).
    CallKfunc(u32),

    /// An invalid or reserved instruction.
    FailCpu,
    FailMem(E),

    /// A valid instruction that rvm doesn't implement.
    Missing,
    /// [`run`] used up its instruction budget before the next instruction. Only with the `fuel` feature.
    OutOfFuel,
    /// [`run`] reached a `pc` outside the code slice.
    BadPc,
    /// A local call found all [`MAX_CALL_DEPTH`] frames in use, or `r10` below the frame size.
    StackOverflow,

    /// `callx`: call through the address in `dst_reg`, which the runtime decodes.
    CallIndirect(u64),
    /// `gotox`: jump to the address in `dst_reg`, which the runtime decodes.
    JumpIndirect(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<M: Memory> {
    // R0: return value from function calls, and exit value for eBPF programs
    // R1 - R5: arguments for function calls
    // R6 - R9: callee saved registers that function calls will preserve
    // R10: read-only frame pointer to access stack
    // R11 - R15: unused; a 4-bit register index into 16 slots needs no bounds check
    pub regs: [u64; 16],
    pub data: M,
}

impl<M: Memory> Context<M> {
    pub const fn new(data: M) -> Self {
        Self { regs: [0; 16], data }
    }
}

#[inline(always)]
pub(crate) fn step<M: Memory>(ctx: &mut Context<M>, insn: Instruction) -> ControlFlow<Flow<M::Err>, Instruction> {
    use mem::{WITH_IMM, WITH_REG};
    use ops::{BITS_32, BITS_64};

    match insn.opcode().class() {
        Class::Alu32 => ControlFlow::Break(ops::math::<_, BITS_32>(ctx, insn)),
        Class::Alu64 => ControlFlow::Break(ops::math::<_, BITS_64>(ctx, insn)),

        Class::Jmp32 => ControlFlow::Break(ops::jump::<_, BITS_32>(ctx, insn)),
        Class::Jmp64 => ControlFlow::Break(ops::jump::<_, BITS_64>(ctx, insn)),

        Class::LdImm => mem::ld64(insn),
        Class::LdReg => ControlFlow::Break(mem::load(ctx, insn)),

        Class::StImm => ControlFlow::Break(mem::save::<_, WITH_IMM>(ctx, insn)),
        Class::StReg => ControlFlow::Break(mem::save::<_, WITH_REG>(ctx, insn)),
    }
}

/// Runs the instruction `insn` in `slot` of `code` and continues with the next one, until it stops in `calls.stop`. A
/// metering handler receives `fuel` already charged for `insn`; the others pass it on as is. `table` is the [`Table`]
/// the handler belongs to, which dispatch indexes from a register.
///
/// `preserve_none` passes all arguments in registers (the Windows x64 C convention has four) and saves no registers, so
/// a tail call between handlers is a jump. It passes them in R12, R13, R14, R15, RDI, RSI, ... in order; `insn` comes
/// before `code` because an address with base R13 needs a displacement, which makes LLVM split the `lea` of a slot
/// address in two.
type Handler<M, H> = extern "rust-preserve-none" fn(
    &mut Context<M>,
    Instruction,
    &[Instruction],
    Slot,
    u64,
    &mut CallStack<H, <M as Memory>::Err>,
    &Table<M, H>,
);

/// The handler of every opcode byte.
struct Table<M: Memory, H>([Handler<M, H>; 256]);

/// The [`Table`] of the handlers with and without `FUEL`. Each handler runs [`step`] with its opcode as a constant, so
/// the class, operation, source, mode and size matches fold away; the bytes of superinstructions and r10 accesses get
/// theirs from [`fuse::install`]. With `FUEL`, the handlers meter fuel; without it, they never read it.
struct Handlers<M, H, const FUEL: bool>(PhantomData<(M, H)>);

impl<M: Memory, H: Host<M>, const FUEL: bool> Handlers<M, H, FUEL> {
    const TABLE: Table<M, H> = {
        macro_rules! table {
            ($($op:literal)*) => {
                [$(handler::<M, H, FUEL, $op> as Handler<M, H>,)*]
            };
        }

        let mut table = table!(
            0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
            0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f
            0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28 0x29 0x2a 0x2b 0x2c 0x2d 0x2e 0x2f
            0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x39 0x3a 0x3b 0x3c 0x3d 0x3e 0x3f
            0x40 0x41 0x42 0x43 0x44 0x45 0x46 0x47 0x48 0x49 0x4a 0x4b 0x4c 0x4d 0x4e 0x4f
            0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x59 0x5a 0x5b 0x5c 0x5d 0x5e 0x5f
            0x60 0x61 0x62 0x63 0x64 0x65 0x66 0x67 0x68 0x69 0x6a 0x6b 0x6c 0x6d 0x6e 0x6f
            0x70 0x71 0x72 0x73 0x74 0x75 0x76 0x77 0x78 0x79 0x7a 0x7b 0x7c 0x7d 0x7e 0x7f
            0x80 0x81 0x82 0x83 0x84 0x85 0x86 0x87 0x88 0x89 0x8a 0x8b 0x8c 0x8d 0x8e 0x8f
            0x90 0x91 0x92 0x93 0x94 0x95 0x96 0x97 0x98 0x99 0x9a 0x9b 0x9c 0x9d 0x9e 0x9f
            0xa0 0xa1 0xa2 0xa3 0xa4 0xa5 0xa6 0xa7 0xa8 0xa9 0xaa 0xab 0xac 0xad 0xae 0xaf
            0xb0 0xb1 0xb2 0xb3 0xb4 0xb5 0xb6 0xb7 0xb8 0xb9 0xba 0xbb 0xbc 0xbd 0xbe 0xbf
            0xc0 0xc1 0xc2 0xc3 0xc4 0xc5 0xc6 0xc7 0xc8 0xc9 0xca 0xcb 0xcc 0xcd 0xce 0xcf
            0xd0 0xd1 0xd2 0xd3 0xd4 0xd5 0xd6 0xd7 0xd8 0xd9 0xda 0xdb 0xdc 0xdd 0xde 0xdf
            0xe0 0xe1 0xe2 0xe3 0xe4 0xe5 0xe6 0xe7 0xe8 0xe9 0xea 0xeb 0xec 0xed 0xee 0xef
            0xf0 0xf1 0xf2 0xf3 0xf4 0xf5 0xf6 0xf7 0xf8 0xf9 0xfa 0xfb 0xfc 0xfd 0xfe 0xff
        );
        fuse::install::<M, H, FUEL>(&mut table);
        transfer::install::<M, H, FUEL>(&mut table);
        Table(table)
    };
}

/// The [`Handler`] of opcode `OP`. Each handler fetches the next instruction itself and ends in its own indirect jump,
/// so the branch predictor tracks the successors of every opcode separately.
#[inline(never)]
extern "rust-preserve-none" fn handler<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    insn: Instruction,
    code: &[Instruction],
    mut slot: Slot,
    mut fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
) {
    // Only jump-class opcodes jump, call or exit. Without the guards, a handler whose `step` returns from an outlined
    // call (atomics) would test for those flows too.
    let jumps = matches!(OpCode(OP).class(), Class::Jmp32 | Class::Jmp64);
    match step(ctx, Instruction(insn.0 & !0xFF | OP as u64)) {
        ControlFlow::Break(Flow::Next) => {}
        ControlFlow::Break(Flow::Jump(offset)) if jumps => slot = slot.offset(offset),
        ControlFlow::Break(Flow::Call(offset)) if jumps => {
            if !calls.push(&mut ctx.regs, slot.pc(code)) {
                return calls.stop.at(slot, fuel, Flow::StackOverflow);
            }
            slot = slot.offset(offset);
        }
        ControlFlow::Break(Flow::Exit) if jumps => match calls.pop(&mut ctx.regs) {
            // `CallStack::push` takes any pc, so this one has no proof
            Some(call_pc) => {
                let pc = call_pc.wrapping_add(1);
                match fetch_checked::<M, H, FUEL>(table, code, pc, fuel) {
                    Ok((next, insn, slot, fuel)) => become next(ctx, insn, code, slot, fuel, calls, table),
                    Err(flow) => return calls.stop.at_pc(pc, fuel, flow),
                }
            }
            None => return calls.stop.at(slot, fuel, Flow::Exit),
        },
        ControlFlow::Break(Flow::CallHelper(_)) if jumps => {
            become host_call::<M, H, FUEL, false>(ctx, insn, code, slot, fuel, calls, table)
        }
        ControlFlow::Break(Flow::CallKfunc(_)) if jumps => {
            become host_call::<M, H, FUEL, true>(ctx, insn, code, slot, fuel, calls, table)
        }
        ControlFlow::Continue(first) => {
            // without a unit for the second slot, LD_IMM64 doesn't run and gets its unit back
            if FUEL && fuel == 0 {
                return calls.stop.at(slot, 1, Flow::OutOfFuel);
            }
            slot = slot.offset(1);
            // SAFETY: this handler runs a slot below `len` (see `Slot`), so the next one lies in `0..=len`
            let second = unsafe { slot.get() };
            let Some(second) = transfer::second_half(code, second) else {
                return calls.stop.at(slot, fuel, Flow::BadPc);
            };
            if FUEL {
                fuel -= 1;
            }
            step_ld64(ctx, first, second);
        }
        ControlFlow::Break(flow) => return calls.stop.at(slot, fuel, flow),
    }

    // SAFETY: the next slot follows a slot below `len`, or the second slot of LD_IMM64, which `second_half` found
    // below `len`, or the target of a jump or local call that `transfer::bound` left in `0..=len` (see `Slot`)
    let slot = slot.offset(1);
    match unsafe { fetch::<M, H, FUEL>(table, slot, fuel) } {
        Some((next, insn, fuel)) => become next(ctx, insn, code, slot, fuel, calls, table),
        None => calls.stop.at(slot, 0, Flow::OutOfFuel),
    }
}

/// The rest of the handler of a helper `call`, or with `KFUNC` a kfunc `call`: runs it on the host and continues with
/// the next instruction.
// Out of line, so that the handler, which also runs local calls, calls no function and needs no stack frame.
#[inline(never)]
extern "rust-preserve-none" fn host_call<M: Memory, H: Host<M>, const FUEL: bool, const KFUNC: bool>(
    ctx: &mut Context<M>,
    insn: Instruction,
    code: &[Instruction],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
) {
    let id = insn.imm() as u32;
    let (r0, flow) = match KFUNC {
        true => (calls.host.kfunc(ctx, id), Flow::CallKfunc(id)),
        false => (calls.host.helper(ctx, id), Flow::CallHelper(id)),
    };
    let Some(r0) = r0 else {
        return calls.stop.at(slot, fuel, flow);
    };
    calls.stack.revalidate(&ctx.data);
    ctx.regs[0] = r0;

    let slot = slot.offset(1);
    // SAFETY: the slots from `len` on hold the guard, so this handler ran below `len` (see `Slot`)
    match unsafe { fetch::<M, H, FUEL>(table, slot, fuel) } {
        Some((next, insn, fuel)) => become next(ctx, insn, code, slot, fuel, calls, table),
        None => calls.stop.at(slot, 0, Flow::OutOfFuel),
    }
}

/// The instruction in `slot`, its handler and the fuel left once it is charged, or `None` if no fuel is left.
///
/// # Safety
///
/// `slot` must point into the slots of a [`Code`] that is still borrowed; [`Slot`] states which slots those are.
#[inline(always)]
unsafe fn fetch<M: Memory, H: Host<M>, const FUEL: bool>(
    table: &Table<M, H>,
    slot: Slot,
    fuel: u64,
) -> Option<(Handler<M, H>, Instruction, u64)> {
    let left = charge::<FUEL>(fuel)?;
    // SAFETY: the caller's
    let insn = unsafe { slot.get() };
    Some((table.of(insn), insn, left))
}

/// The fuel left once an instruction is charged, or `None` if none is left. It takes at most `i64::MAX` units, the
/// most [`run`] accepts.
#[inline(always)]
fn charge<const FUEL: bool>(fuel: u64) -> Option<u64> {
    // a decrement and a sign test, where `fuel == 0` would take a test, a branch and a decrement
    let left = fuel.wrapping_sub(u64::from(FUEL));
    (!FUEL || left as i64 >= 0).then_some(left)
}

/// [`fetch`] at a pc no proof covers, with the slot at `pc`, or why it can't run.
#[inline(always)]
fn fetch_checked<M: Memory, H: Host<M>, const FUEL: bool>(
    table: &Table<M, H>,
    code: &[Instruction],
    pc: u64,
    fuel: u64,
) -> Result<Checked<M, H>, Flow<M::Err>> {
    let Some(left) = charge::<FUEL>(fuel) else {
        return Err(Flow::OutOfFuel);
    };
    if pc >= code.len() as u64 {
        return Err(Flow::BadPc);
    }
    let insn = code[pc as usize];
    Ok((table.of(insn), insn, Slot::at(code, pc), left))
}

/// The handler, instruction and slot at the pc [`fetch_checked`] checked, and the fuel left once it is charged.
type Checked<M, H> = (Handler<M, H>, Instruction, Slot, u64);

impl<M: Memory, H> Table<M, H> {
    /// The handler of `insn`.
    #[inline(always)]
    fn of(&self, insn: Instruction) -> Handler<M, H> {
        self.0[usize::from(insn.0 as u8)]
    }
}

#[inline(always)]
pub(crate) fn step_ld64<M: Memory>(ctx: &mut Context<M>, insn: Instruction, second: Instruction) {
    debug_assert!(matches!(
        (insn.opcode().class(), insn.opcode().mem_mode(), insn.opcode().mem_size(), insn.src_reg()),
        (Class::LdImm, MemMode::Imm, MemSize::DWord, 0)
    ));

    // the first slot carries the low 32 bits, the second the high 32 bits
    let imm_lo = insn.imm() as u32 as u64;
    let imm_hi = second.imm() as u32 as u64;
    ctx.regs[usize::from(insn.dst_reg())] = imm_lo | (imm_hi << 32);
}

/// Whether [`run`] meters fuel, chosen by the `fuel` feature.
const METERED: bool = cfg!(feature = "fuel");

/// Execute from `*pc` until an instruction the caller must handle.
///
/// ALU, memory and jump instructions, local calls and their returns, and helper and kfunc calls that `calls.host` runs
/// stay inside the handler chain, so each one costs a single dispatch. `calls` holds the frames of the local calls in
/// progress and keeps them from one `run` to the next. Execution returns helper and kfunc calls that the host declined,
/// indirect calls and jumps, [`Flow::Exit`] from the entry frame and faults with `*pc` at the instruction that produced
/// them, and [`Flow::OutOfFuel`] or [`Flow::BadPc`] with `*pc` at the instruction that could not run. With the `fuel`
/// feature, each executed instruction consumes one unit of `fuel`, and LD_IMM64 one per slot: with one unit left, it
/// stops with [`Flow::OutOfFuel`] and that unit. `*fuel` must be at most `i64::MAX`; a larger budget may stop at once
/// with [`Flow::OutOfFuel`]. Without the feature, `run` takes no `fuel` and never runs out.
#[inline]
pub fn run<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: &Code,
    pc: &mut u64,
    #[cfg(feature = "fuel")] fuel: &mut u64,
    calls: &mut CallStack<H, M::Err>,
) -> Flow<M::Err> {
    #[cfg(not(feature = "fuel"))]
    let fuel = &mut 0;

    let slots = code.slots();
    let table = &Handlers::<M, H, METERED>::TABLE;
    calls.stack.revalidate(&ctx.data);
    let (first, insn, slot, left) = match fetch_checked::<M, H, METERED>(table, slots, *pc, *fuel) {
        Ok(next) => next,
        Err(flow) => return flow,
    };
    first(ctx, insn, slots, slot, left, calls, table);
    let stop = &mut calls.stop;
    (*pc, *fuel) = (stop.pc(code.slots()), stop.fuel);
    // Test the tag alone first: the handler stored the flow one field at a time, and a single load of the whole flow
    // can't take its bytes from several stores, so it waits for them to reach the cache.
    match stop.flow {
        Flow::Exit => Flow::Exit,
        _ => std::mem::replace(&mut stop.flow, Flow::Next),
    }
}
