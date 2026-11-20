#![feature(explicit_tail_calls, rust_preserve_none_cc)]
#![allow(incomplete_features)]

use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::ControlFlow;

use op::{Fields, Op, Shape};
use opcode::{Class, OpCode, CALL, LD_IMM64};
use transfer::Slot;

/// `for $pat in $iter { $body }` in a const context, where `for` isn't allowed. `$iter` is a
/// [`Range`](std::ops::Range), whose values `$pat` takes in turn, or an array or slice, whose elements `$pat` takes by
/// value, or by reference behind a leading `&`. `$body` is a block or a single expression. `continue` and `break` work
/// as in `for`.
macro_rules! const_for {
    // `$iter` is the tokens before `=>`, a range if a `..` stands among them
    (@split $pat:tt [$($start:tt)*] .. $end:expr => $body:expr) => {{
        let std::ops::Range { start, end } = ($($start)*)..$end;
        let mut next = start;
        while next < end {
            let $pat = next;
            next += 1;
            $body;
        }
    }};
    (@split $pat:tt [& $($items:tt)*] => $body:expr) => {
        const_for!(@each $pat [&] ($($items)*) $body)
    };
    (@split $pat:tt [$($items:tt)*] => $body:expr) => {
        const_for!(@each $pat [] ($($items)*) $body)
    };
    (@split $pat:tt [$($done:tt)*] $token:tt $($rest:tt)*) => {
        const_for!(@split $pat [$($done)* $token] $($rest)*)
    };
    (@each $pat:tt [$($borrow:tt)?] ($items:expr) $body:expr) => {{
        let items: &[_] = &$items;
        let mut next = 0;
        while next < items.len() {
            let $pat = $($borrow)? items[next];
            next += 1;
            $body;
        }
    }};
    ($pat:pat in $($rest:tt)*) => {
        const_for!(@split $pat [] $($rest)*)
    };
}

/// A table with the value of `$value` for each opcode byte `$byte`.
macro_rules! byte_table {
    (|$byte:ident| $value:expr) => {{
        let mut table = [{
            let $byte = 0u8;
            $value
        }; 256];
        const_for!(i in 1..256 => {
            let $byte = i as u8;
            table[i] = $value;
        });
        table
    }};
}

/// Continues at `$slot`, in the block of the slot the handler runs: tail-calls the handler of its instruction. The
/// handler that expands it ends here. `$slot` must lie in `0..=len`. A true `$split` makes the tail call one of two, as
/// [`split`] describes.
macro_rules! become_at {
    ($ctx:expr, $code:expr, $slot:expr, $fuel:expr, $calls:expr, $table:expr, $split:expr) => {{
        let slot = $slot;
        // SAFETY: the caller's (see `Slot`)
        let op = unsafe { slot.get() };
        match $split && $crate::split::odd(op) {
            true => become $table.odd(op)($ctx, $code, slot, $fuel, $calls, $table, op),
            false => become $table.of(op)($ctx, $code, slot, $fuel, $calls, $table, op),
        }
    }};
}

/// Continues at the slot after `$slot`, in the same block, as [`become_at!`] does. `$slot` must lie below `len`, as the
/// slot of every handler but the guard's does, and must not end its block ([`fuel`]).
macro_rules! become_next {
    ($ctx:expr, $code:expr, $slot:expr, $fuel:expr, $calls:expr, $table:expr) => {
        become_next!($ctx, $code, $slot, $fuel, $calls, $table, false)
    };
    ($ctx:expr, $code:expr, $slot:expr, $fuel:expr, $calls:expr, $table:expr, $split:expr) => {
        become_at!($ctx, $code, $slot.offset(1), $fuel, $calls, $table, $split)
    };
}

/// Enters the block of `$slot` there: charges the fuel of the slots from it to the end of its block and continues
/// there as [`become_at!`] does, or in [`fuel::single_step`] if the fuel can't pay for them. Either way, the handler
/// that expands it ends here; the handler's generic parameters must be `M`, `H` and `FUEL`. `$slot` must lie in
/// `0..=len`: the slot after one below `len`, or a target that [`transfer::bound`] proves.
macro_rules! become_enter {
    ($ctx:expr, $code:expr, $slot:expr, $fuel:expr, $calls:expr, $table:expr) => {
        become_enter!($ctx, $code, $slot, $fuel, $calls, $table, false)
    };
    ($ctx:expr, $code:expr, $slot:expr, $fuel:expr, $calls:expr, $table:expr, $split:expr) => {{
        let slot = $slot;
        let left = $crate::fuel::enter::<FUEL>($code, slot, $fuel);
        if FUEL && (left as i64) < 0 {
            core::hint::cold_path();
            let op = $crate::op::Op::UNREAD;
            become $crate::fuel::single_step::<M, H, FUEL>($ctx, $code, slot, left, $calls, $table, op)
        }
        become_at!($ctx, $code, slot, left, $calls, $table, $split)
    }};
}

/// Continues at `$pc`, which no proof covers: enters its block there as [`become_enter!`] does, or stops with the flow
/// [`fetch_checked`] reports. Either way, the handler that expands it ends here; its generic parameters are named as
/// for [`become_enter!`].
macro_rules! become_at_pc {
    ($ctx:expr, $code:expr, $pc:expr, $fuel:expr, $calls:expr, $table:expr) => {{
        let pc = $pc;
        match $crate::fetch_checked::<M, H, FUEL>($table, $code, pc, $fuel) {
            Ok((next, op, slot, fuel)) => become next($ctx, $code, slot, fuel, $calls, $table, op),
            Err(flow) => return $calls.stop.at_pc(pc, $fuel, flow),
        }
    }};
}

mod call;
mod debug;
mod fuel;
mod fuse;
mod instruction;
mod mem;
mod memory;
mod op;
mod ops;
mod split;
mod stack;
mod transfer;

pub mod opcode;

pub use call::{CallStack, Callee, Host, MAX_CALL_DEPTH};
pub use fuse::Code;
pub use instruction::{
    decode_instructions, instructions_from_bytes, Instruction, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL,
};
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

    /// `callx`: call through the address in `dst_reg`, which [`Host::callx`] declined or resolved to a pc outside the
    /// code.
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
    // R11 - R15: unused; a 4-bit register index into 16 entries needs no bounds check
    pub regs: [u64; 16],
    pub data: M,
}

impl<M: Memory> Context<M> {
    pub const fn new(data: M) -> Self {
        Self { regs: [0; 16], data }
    }
}

#[inline(always)]
fn step<M: Memory, R: ops::Regs, I: Fields>(regs: &mut R, mem: &mut M, insn: I) -> ControlFlow<Flow<M::Err>> {
    use mem::{SOURCE_IMM, SOURCE_REG};
    use ops::{BITS_32, BITS_64};

    match insn.opcode().class() {
        Class::Alu32 => ControlFlow::Break(ops::math::<_, _, BITS_32>(regs, insn)),
        Class::Alu64 => ControlFlow::Break(ops::math::<_, _, BITS_64>(regs, insn)),

        Class::Jmp32 => ControlFlow::Break(ops::jump::<_, _, BITS_32>(regs, insn)),
        Class::Jmp64 => ControlFlow::Break(ops::jump::<_, _, BITS_64>(regs, insn)),

        Class::LdImm => mem::ld64(insn),
        Class::LdReg => ControlFlow::Break(mem::load(regs, mem, insn)),

        Class::StImm => ControlFlow::Break(mem::store::<_, _, SOURCE_IMM>(regs, mem, insn)),
        Class::StReg => ControlFlow::Break(mem::store::<_, _, SOURCE_REG>(regs, mem, insn)),
    }
}

/// Runs the instruction `op` in `slot` of `code` and continues with the next one, until it stops in `calls.stop`. A
/// metering handler receives `fuel` already charged for the slots from its own to the end of its block, as [`fuel`]
/// describes; the others pass it on as is. `table` is the [`Table`] the handler belongs to, which dispatch indexes from
/// a register.
///
/// The handler of opcode byte `OP` runs only slots in the layout of `OP` ([`op::LAYOUTS`]), and reads their fields
/// with [`Slot::view`]: from `op` where one instruction extracts them, else from the slot.
///
/// `preserve_none` passes all arguments in registers (the Windows x64 C convention has four) and saves no registers, so
/// a tail call between handlers is a jump. It passes them in R12, R13, R14, R15, RDI, RSI, RDX, RCX ... in order; `op`
/// comes eighth, so that it lands in RCX: a single `movzx` reads its second byte from CH, and a shift by its `imm`
/// takes the count from CL.
type Handler<M, H> = extern "rust-preserve-none" fn(
    &mut Context<M>,
    &[Op],
    Slot,
    u64,
    &mut CallStack<H, <M as Memory>::Err>,
    &Table<M, H>,
    Op,
);

/// The handler of every opcode byte, and the copy of them that [`split`] dispatches through.
struct Table<M: Memory, H>([Handler<M, H>; 256], [Handler<M, H>; 256]);

/// The [`Table`] of the handlers with and without `FUEL`. Each handler runs [`step`] with its opcode as a constant, so
/// the class, operation, source, mode and size matches fold away; the bytes of superinstructions and r10 accesses get
/// theirs from [`fuse::install`], and the plain loads and stores theirs from [`stack::install`]. With `FUEL`, the
/// handlers meter fuel; without it, they never read it.
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
        stack::install::<M, H, FUEL>(&mut table);
        Table(table, table)
    };

    /// The table [`fuel::single_step`] runs a block's slots with: each dispatch returns to it.
    const STEPS: Table<M, H> = Table([fuel::single_step::<M, H, FUEL>; 256], [fuel::single_step::<M, H, FUEL>; 256]);
}

/// The [`Handler`] of opcode `OP`. Each handler fetches the next instruction itself and ends in indirect jumps of its
/// own (two for the opcodes that [`split`] names), so the branch predictor tracks the successors of every opcode
/// separately.
#[inline(never)]
extern "rust-preserve-none" fn handler<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: &[Op],
    mut slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    // SAFETY: a handler's slot lies below `len`, and has the layout of its opcode (see `Handler`)
    let insn = unsafe { slot.view(op, const { Shape::of(OP) }) };
    // Only jump-class opcodes jump, call or exit, and they end their block (see `fuel`). Without the guards, a handler
    // whose `step` returns from an outlined call (atomics) would test for those flows too.
    let jumps = matches!(OpCode(OP).class(), Class::Jmp32 | Class::Jmp64);
    match step(&mut ctx.regs, &mut ctx.data, insn) {
        ControlFlow::Break(Flow::Next) => {}
        ControlFlow::Break(Flow::Jump(offset)) if jumps => slot = slot.offset(offset),
        ControlFlow::Break(Flow::Call(offset)) if jumps => {
            // the call ends its block, so the fuel is charged up to it
            if !calls.push(&mut ctx.regs, slot.pc(code)) {
                return calls.stop.at(slot, fuel, Flow::StackOverflow);
            }
            slot = slot.offset(offset);
        }
        ControlFlow::Break(Flow::Exit) if jumps => match calls.pop(&mut ctx.regs) {
            // `CallStack::push` takes any pc, so this one has no proof
            Some(call_pc) => become_at_pc!(ctx, code, call_pc.wrapping_add(1), fuel, calls, table),
            None => return calls.stop.at(slot, fuel, Flow::Exit),
        },
        ControlFlow::Break(Flow::CallHelper(_)) if jumps => {
            become host_call::<M, H, FUEL, false>(ctx, code, slot, fuel, calls, table, op)
        }
        ControlFlow::Break(Flow::CallKfunc(_)) if jumps => {
            become host_call::<M, H, FUEL, true>(ctx, code, slot, fuel, calls, table, op)
        }
        ControlFlow::Break(Flow::CallIndirect(_)) if jumps => {
            become indirect_call::<M, H, FUEL>(ctx, code, slot, fuel, calls, table, op)
        }
        ControlFlow::Continue(()) => {
            // SAFETY: this handler runs a slot below `len` (see `Slot`), so the next one lies in `0..=len`
            let second = unsafe { slot.offset(1).get() };
            let Some(upper) = transfer::second_half(second) else {
                // the code ends inside LD_IMM64, which doesn't run and gets its unit back, as at the guard
                let left = fuel::unspent::<FUEL>(code, slot, fuel) + u64::from(FUEL);
                return calls.stop.at(slot, left, Flow::BadPc);
            };
            slot = slot.offset(1);
            step_ld64(&mut ctx.regs, insn, upper);
        }
        ControlFlow::Break(flow) => return calls.stop.at(slot, fuel::unspent::<FUEL>(code, slot, fuel), flow),
    }

    // `slot` is the slot of `insn` or of the second half of LD_IMM64, which `second_half` found below `len`, or it
    // precedes the target of a jump or local call
    if jumps {
        become_enter!(ctx, code, slot.offset(1), fuel, calls, table, split::splits(OP))
    }
    become_next!(ctx, code, slot, fuel, calls, table, split::splits(OP))
}

/// The rest of the handler of a helper `call`, or with `KFUNC` a kfunc `call`: runs it on the host and continues with
/// the next instruction.
// Out of line, so that the handler, which also runs local calls, calls no function and needs no stack frame.
#[inline(never)]
extern "rust-preserve-none" fn host_call<M: Memory, H: Host<M>, const FUEL: bool, const KFUNC: bool>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    // SAFETY: as in the handler of `call`, which continues here
    let id = unsafe { slot.view(op, const { Shape::of(CALL) }) }.imm() as u32;
    let (r0, flow) = match KFUNC {
        true => (calls.host.kfunc(ctx, id), Flow::CallKfunc(id)),
        false => (calls.host.helper(ctx, id), Flow::CallHelper(id)),
    };
    let Some(r0) = r0 else {
        return calls.stop.at(slot, fuel, flow);
    };
    calls.windows.revalidate(&ctx.data);
    ctx.regs[0] = r0;

    become_enter!(ctx, code, slot.offset(1), fuel, calls, table)
}

/// The rest of the handler of `callx`: enters the guest function that [`Host::callx`] names, as a local call does, or
/// continues with the next instruction after the host function it ran.
#[inline(never)]
extern "rust-preserve-none" fn indirect_call<M: Memory, H: Host<M>, const FUEL: bool>(
    ctx: &mut Context<M>,
    code: &[Op],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
    op: Op,
) {
    const CALLX: u8 = OpCode::jmp64_from_parts(opcode::JmpOpc::Call, opcode::Source::Reg).0;
    // SAFETY: as in the handler of `callx`, which continues here
    let target = ops::Regs::get(&ctx.regs, unsafe { slot.view(op, const { Shape::of(CALLX) }) }.dst_reg());
    let callee = calls.host.callx(ctx, target);
    calls.windows.revalidate(&ctx.data);
    match callee {
        Some(Callee::Local(pc)) => {
            // the ops from `len` on all hold the guard, and no op below it does
            let in_code = pc < op::ops(code) as u64 && code[pc as usize].byte() != transfer::GUARD;
            if !in_code {
                return calls.stop.at(slot, fuel, Flow::CallIndirect(target));
            }
            if !calls.push(&mut ctx.regs, slot.pc(code)) {
                return calls.stop.at(slot, fuel, Flow::StackOverflow);
            }
            become_at_pc!(ctx, code, pc, fuel, calls, table)
        }
        Some(Callee::Host(r0)) => {
            ctx.regs[0] = r0;
            become_enter!(ctx, code, slot.offset(1), fuel, calls, table)
        }
        None => calls.stop.at(slot, fuel, Flow::CallIndirect(target)),
    }
}

/// The handler, op and slot at `pc`, which no proof covers, and the fuel the handler receives as it enters the block
/// there ([`fuel::enter`]), or why it can't run.
#[inline(always)]
fn fetch_checked<M: Memory, H: Host<M>, const FUEL: bool>(
    table: &Table<M, H>,
    code: &[Op],
    pc: u64,
    fuel: u64,
) -> Result<Checked<M, H>, Flow<M::Err>> {
    if pc >= op::ops(code) as u64 {
        // an instruction there would be charged first
        return Err(match FUEL && fuel == 0 {
            true => Flow::OutOfFuel,
            false => Flow::BadPc,
        });
    }
    let op = code[pc as usize];
    let slot = Slot::at(code, pc);
    let left = fuel::enter::<FUEL>(code, slot, fuel);
    let mut next = table.of(op);
    if FUEL {
        // a `cmov`, as a branch would take a jump on the common side
        next = core::hint::select_unpredictable((left as i64) < 0, fuel::single_step::<M, H, FUEL>, next);
    }
    Ok((next, op, slot, left))
}

/// The handler, op and slot at the pc [`fetch_checked`] checked, and the fuel the handler receives.
type Checked<M, H> = (Handler<M, H>, Op, Slot, u64);

impl<M: Memory, H> Table<M, H> {
    /// The handler of `op`.
    #[inline(always)]
    fn of(&self, op: Op) -> Handler<M, H> {
        self.0[usize::from(op.byte())]
    }
}

/// Runs the LD_IMM64 `insn`, whose second slot holds the upper half `upper` of its immediate.
#[inline(always)]
fn step_ld64(regs: &mut impl ops::Regs, insn: impl Fields, upper: i32) {
    debug_assert!(insn.opcode().0 == LD_IMM64 && insn.src_reg() == op::Reg::R0);

    let imm_lo = insn.imm() as u32 as u64;
    let imm_hi = upper as u32 as u64;
    regs.set(insn.dst_reg(), imm_lo | (imm_hi << 32));
}

/// Whether [`run`] meters fuel, chosen by the `fuel` feature.
const METERED: bool = cfg!(feature = "fuel");

/// Execute from `*pc` until an instruction the caller must handle.
///
/// ALU, memory and jump instructions, local calls and their returns, and helper, kfunc and `callx` calls that
/// `calls.host` runs or resolves stay inside the handler chain, so each one costs a single dispatch. `calls` holds the
/// frames of the local calls in progress and keeps them from one `run` to the next. Execution returns helper, kfunc and
/// `callx` calls that the host declined, indirect jumps, [`Flow::Exit`] from the entry frame and faults with `*pc` at
/// the instruction that produced them, and [`Flow::OutOfFuel`] or [`Flow::BadPc`] with `*pc` at the instruction that
/// could not run. With the `fuel` feature, each executed instruction consumes one unit of `fuel`, and LD_IMM64 one per
/// slot: with one unit left, it stops with [`Flow::OutOfFuel`] and that unit. The interpreter charges the units of a
/// whole basic block as it enters the block, but stops and leaves `*fuel` exactly where charging each instruction would.
/// `*fuel` must be at most `i64::MAX`. Without the feature, `run` takes no `fuel` and never runs out.
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
    calls.windows.revalidate(&ctx.data);
    let (first, op, slot, left) = match fetch_checked::<M, H, METERED>(table, slots, *pc, *fuel) {
        Ok(next) => next,
        Err(flow) => return flow,
    };
    first(ctx, slots, slot, left, calls, table, op);
    let stop = &mut calls.stop;
    (*pc, *fuel) = (stop.pc(code.slots()), stop.fuel);
    // Test the tag alone first: the handler stored the flow one field at a time, and a single load of the whole flow
    // can't take its bytes from several stores, so it waits for them to reach the cache.
    match stop.flow {
        Flow::Exit => Flow::Exit,
        _ => std::mem::replace(&mut stop.flow, Flow::Next),
    }
}
