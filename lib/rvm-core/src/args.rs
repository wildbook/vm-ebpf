//! Stack arguments: how a call passes its arguments 6 to 12, as clang 23 compiles it.
//!
//! The caller stores argument `5 + k` with an 8-byte `stx` or `st` to `r11 - 8k`, and the callee loads it with an
//! 8-byte `ldx` from `r11 + 8k`, for `k` from 1 to [`MAX_STACK_ARGS`]. No instruction writes r11, and the two views
//! are no memory: the interpreter keeps one [`Row`] of slots per call depth, and a store writes slot `k` of the row
//! that a load of the callee reads. A local call, a `callx` and an `exit` change the depth and nothing else, so they
//! cost what they cost without stack arguments.
//!
//! [`Code::new`](crate::Code::new) gives the three forms the bytes [`LOAD`], [`STORE`] and [`STORE_IMM`], and fails
//! those with another offset. Every other instruction that names r11 keeps it as the register it is to them.
//!
//! A slot keeps the last value stored to it: nothing clears a row when a call returns, and a callee that loads an
//! argument its caller didn't store reads what an earlier call at that depth stored there, or 0.
//!
//! A host function gets the row of its caller where the embedder marked the `call` with
//! [`Code::pass_stack_args`](crate::Code::pass_stack_args) ([`CALL`]), a native function where its
//! [`NativeSig`](crate::NativeSig) has more than five arguments, and the native target of a `callx` in every program
//! that stores a stack argument ([`CALLX`]).

use crate::code::Slots;
use crate::dispatch::{Handler, Spare, Table};
use crate::fuel::Fuel;
use crate::handler::indirect_call;
use crate::slot::{Fields, Shape, Slot};
use crate::step::Regs;
use crate::transfer::Ip;
use crate::{Context, Host, Interpreter, Memory, Reason};

/// Most arguments a call passes on the stack: arguments 6 to 12.
pub const MAX_STACK_ARGS: usize = 7;

/// The arguments a call passes on the stack: argument `5 + k` at index `k - 1`.
pub type StackArgs = [u64; MAX_STACK_ARGS];

/// The stack arguments of the calls one frame makes: argument `5 + k` in slot `k`. No instruction names slot 0, the
/// 8 bytes at r11 itself, which makes the index of a slot the offset of its instruction in units of 8 bytes.
pub type Row = [u64; MAX_STACK_ARGS + 1];

/// The [`StackArgs`] in `row`.
#[inline(always)]
pub fn slots(row: &Row) -> &StackArgs {
    row.last_chunk().expect("a row has a slot more than the arguments")
}

/// [`slots`], to fill them.
#[inline(always)]
pub fn slots_mut(row: &mut Row) -> &mut StackArgs {
    row.last_chunk_mut().expect("a row has a slot more than the arguments")
}

/// `rX = *(u64 *)(r11 + 8k)`: the callee loads argument `5 + k`.
pub const LOAD: u8 = 0xb9;
/// `*(u64 *)(r11 - 8k) = rX`: the caller stores argument `5 + k`.
pub const STORE: u8 = 0xbb;
/// `*(u64 *)(r11 - 8k) = imm`.
pub const STORE_IMM: u8 = 0xba;
/// A kfunc `call` that passes the stack arguments to the host ([`Host::call_kfunc_stack`]).
pub const CALL: u8 = 0xed;
/// A `callx` in a program that stores stack arguments: a native target gets them.
pub const CALLX: u8 = 0xfd;

/// Whether `offset`, of a load, or negated, of a store, names one of the slots 1 to [`MAX_STACK_ARGS`].
pub const fn is_slot(offset: i16) -> bool {
    offset % 8 == 0 && 8 <= offset && offset <= 8 * MAX_STACK_ARGS as i16
}

/// The slot of a [`Row`] at `offset`, which [`is_slot`].
// masked, so that the index needs no bounds check
#[inline(always)]
fn slot_at(offset: i16) -> usize {
    usize::from(offset as u16 >> 3) & MAX_STACK_ARGS
}

const _: () = assert!((MAX_STACK_ARGS + 1).is_power_of_two());

pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
    table[LOAD as usize] = load::<M, H>;
    table[STORE as usize] = store::<M, H, false>;
    table[STORE_IMM as usize] = store::<M, H, true>;
    table[CALL as usize] = host_call::<M, H, F>;
    table[CALLX as usize] = indirect_call::<M, H, F, true>;
}

/// The handler of [`LOAD`].
#[inline(never)]
extern "rust-preserve-none" fn load<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and a stack-argument load has the layout of the load it stands for
    let insn = unsafe { ip.view(slot, const { Shape::of(LOAD) }) };
    let value = interp.incoming()[slot_at(insn.offset())];
    ctx.regs.set(insn.dst_reg(), value);

    become_next!(ctx, code, ip, interp, table)
}

/// The handler of [`STORE`], or with `IMM` of [`STORE_IMM`].
#[inline(never)]
extern "rust-preserve-none" fn store<M: Memory, H: Host<M>, const IMM: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: as in `load`
    let insn = unsafe { ip.view(slot, const { Shape::of(if IMM { STORE_IMM } else { STORE }) }) };
    let value = match IMM {
        true => i64::from(insn.imm()) as u64,
        false => ctx.regs.get(insn.src_reg()),
    };
    interp.outgoing()[slot_at(insn.offset().wrapping_neg())] = value;

    become_next!(ctx, code, ip, interp, table)
}

/// The handler of [`CALL`]: runs the kfunc on the host with the stack arguments of the frame, and continues with
/// the next instruction.
#[inline(never)]
extern "rust-preserve-none" fn host_call<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and `Code::pass_stack_args` leaves the slot in the layout of `call`
    let id = unsafe { ip.view(slot, const { Shape::of(CALL) }) }.imm() as u32;
    let (stack, host) = interp.stack_args_and_host();
    let Some(r0) = host.call_kfunc_stack(ctx, id, stack) else {
        return interp.stop.at(ip, Reason::CallKfunc(id));
    };
    interp.windows.revalidate(ctx.memory);
    ctx.regs[0] = r0;

    become_enter!(ctx, code, ip.offset(1), interp, table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::INVALID;
    use crate::opcode::{call, AluOpc, JmpOpc, MemMode, MemSize, OpCode, Source};
    use crate::{Callee, Code, Instruction, NativeCall};

    struct NoMem;

    // SAFETY: the default `window` reports no windows
    unsafe impl Memory for NoMem {
        type Error = ();

        fn load_u8(&self, _: u64) -> Result<u8, ()> {
            Err(())
        }

        fn store_u8(&mut self, _: u64, _: u8) -> Result<(), ()> {
            Err(())
        }

        fn native_ptr(&self, _: u64, _: u64, _: bool) -> Result<u64, ()> {
            Err(())
        }
    }

    struct NoHost;

    impl Host<NoMem> for NoHost {
        fn call_helper(&mut self, _: &mut Context<NoMem>, _: u32) -> Option<u64> {
            None
        }

        fn call_kfunc(&mut self, _: &mut Context<NoMem>, _: u32) -> Option<u64> {
            None
        }

        fn call_indirect(&mut self, _: &mut Context<NoMem>, _: u64, _: NativeCall<'_, ()>) -> Option<Callee> {
            None
        }
    }

    const R11: u8 = 11;
    const EXIT: Instruction = Instruction::new(OpCode::jmp64(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0);

    fn ldx(size: MemSize, dst: u8, src: u8, offset: i16) -> Instruction {
        Instruction::new(OpCode::ldx(size, MemMode::Mem), dst, src, offset, 0)
    }

    fn stx(size: MemSize, dst: u8, offset: i16, src: u8) -> Instruction {
        Instruction::new(OpCode::stx(size, MemMode::Mem), dst, src, offset, 0)
    }

    fn st(size: MemSize, dst: u8, offset: i16, imm: i32) -> Instruction {
        Instruction::new(OpCode::st(size, MemMode::Mem), dst, 0, offset, imm)
    }

    fn alu(opc: AluOpc, dst: u8, src: u8) -> Instruction {
        Instruction::new(OpCode::alu64(opc, Source::Reg), dst, src, 0, 0)
    }

    fn alu_imm(opc: AluOpc, dst: u8, imm: i32) -> Instruction {
        Instruction::new(OpCode::alu64(opc, Source::Imm), dst, 0, 0, imm)
    }

    /// A local call of the function `slots` slots after the next instruction.
    fn call(slots: i32) -> Instruction {
        Instruction::new(OpCode::jmp64(JmpOpc::Call, Source::Imm), 0, call::LOCAL, 0, slots)
    }

    /// Clang reads every stack argument before a function's first call, so no object shows whether a frame still
    /// reads its own arguments after a call that passed others. Here each function loads its argument again after
    /// the function it called stored and loaded one in the same slot.
    #[test]
    fn a_row_per_depth() {
        let dw = MemSize::DWord;
        #[rustfmt::skip]
        let code = Code::new([
            // main: r0 = arg + 10 * middle(7)
            ldx(dw, 6, R11, 8),
            st(dw, R11, -8, 7),
            call(5),
            alu_imm(AluOpc::Mul, 0, 10),
            ldx(dw, 6, R11, 8),
            alu(AluOpc::Add, 0, 6),
            EXIT,
            // middle(x): r0 = x + 10 * leaf(x + 1), with x read again after the call
            EXIT,
            ldx(dw, 7, R11, 8),
            alu_imm(AluOpc::Add, 7, 1),
            stx(dw, R11, -8, 7),
            call(4),
            alu_imm(AluOpc::Mul, 0, 10),
            ldx(dw, 7, R11, 8),
            alu(AluOpc::Add, 0, 7),
            EXIT,
            // leaf(x): r0 = x
            ldx(dw, 0, R11, 8),
            EXIT,
        ]);
        let mut memory = NoMem;
        let mut interp = Interpreter::new(0, NoHost);
        interp.entry_args()[0] = 3;

        for _ in 0..2 {
            let mut ctx = Context::new(&mut memory);
            let stop = interp.run(&mut ctx, &code, 0);
            assert_eq!((stop.reason, stop.pc), (Reason::Exit, 6));
            // leaf 8, middle 7 + 80, main 3 + 870
            assert_eq!(ctx.regs[0], 873);
        }
    }

    /// The three forms take only the offsets of arguments 6 to 12, and every other instruction keeps r11 as a
    /// register.
    #[test]
    fn only_slots_through_r11() {
        let dw = MemSize::DWord;
        let byte = |insn: Instruction| Code::new([insn, EXIT]).slots().get(0).unwrap().byte();

        for k in 1..=MAX_STACK_ARGS as i16 {
            assert_eq!(byte(ldx(dw, 1, R11, 8 * k)), LOAD);
            assert_eq!(byte(stx(dw, R11, -8 * k, 1)), STORE);
            assert_eq!(byte(st(dw, R11, -8 * k, 1)), STORE_IMM);
        }
        for offset in [0, 4, 9, 64, -8, i16::MIN, i16::MAX] {
            assert_eq!(byte(ldx(dw, 1, R11, offset)), INVALID, "load at {offset}");
            let offset = offset.wrapping_neg();
            assert_eq!(byte(stx(dw, R11, offset, 1)), INVALID, "store at {offset}");
            assert_eq!(byte(st(dw, R11, offset, 1)), INVALID, "store at {offset}");
        }
        // a load into r10, and the fields that the verifier reserves
        assert_eq!(byte(ldx(dw, 10, R11, 8)), INVALID);
        assert_eq!(byte(Instruction::new(OpCode::ldx(dw, MemMode::Mem), 1, R11, 8, 1)), INVALID);
        assert_eq!(byte(Instruction::new(OpCode::st(dw, MemMode::Mem), R11, 1, -8, 1)), INVALID);

        // r11 as the value of a store, as the base of other sizes, and in ALU instructions
        for insn in [
            stx(dw, 1, -8, R11),
            ldx(MemSize::Word, 1, R11, 8),
            stx(MemSize::Word, R11, -8, 1),
        ] {
            assert_eq!(byte(insn), insn.byte());
        }
        let code = Code::new([alu_imm(AluOpc::Mov, R11, 5), alu(AluOpc::Mov, 0, R11), EXIT]);
        let mut memory = NoMem;
        let mut ctx = Context::new(&mut memory);
        let stop = Interpreter::new(0, NoHost).run(&mut ctx, &code, 0);
        assert_eq!((stop.reason, ctx.regs[0]), (Reason::Exit, 5));
    }
}
