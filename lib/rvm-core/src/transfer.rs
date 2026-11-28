//! Control transfers that need no bounds check.
//!
//! [`Code::new`](crate::Code::new) ends the code with a [`GUARD`] slot, and [`bound`] proves that every pc a handler
//! continues at without a check lies in `0..=len`, the guard included. Handlers carry the pc as an [`Ip`], a pointer
//! to the slot, and read such a slot without a check; the guard stops with [`Reason::BadPc`] where the code ends, as a
//! checked fetch would. The interpreter checks the pc a run starts at, the `exit` handler the pc it returns to, the
//! `callx` handler the pc [`Host::call_indirect`] names, and the caller of the run the targets of `gotox`.

use crate::code::{Slots, ThreadedSlot};
use crate::dispatch::{Handler, Spare};
use crate::fuel::{Fuel, RestsPtr};
use crate::fuse::Super;
use crate::opcode::{call, Class, JmpOpc, OpCode, Source};
use crate::slot::{Shape, Slot, View};
use crate::step::{self, Step, BITS_32, BITS_64};
use crate::{Context, Host, Instruction, Interpreter, Memory, Reason};

/// The slot after the code, and every slot after it: there is no instruction here.
pub const GUARD: u8 = 0xe0;

/// A jump or local call whose target lies outside the code, which runs from a slot after the guard. Its `imm` is the
/// index of the slot after the guard that holds the instruction with the opcode byte [`GUARD`], and its `dst_reg` and
/// `src_reg` hold the low and high half of the opcode byte.
pub const FAR: u8 = 0xe8;

/// Proves where handlers continue: afterwards, the slots from the original `code.len()` on all hold [`GUARD`], and
/// the handler of each slot below it continues without a check only at a pc in `0..=len`:
/// - a jump or local call at `pc` continues at `pc + 1` or at its target; one whose target lies outside gets [`FAR`],
///   which checks it;
/// - a superinstruction continues after its sequence or at the target of its branch; one that [`fits`] rejects runs
///   its first instruction alone instead;
/// - LD_IMM64 continues after its second slot only if that slot isn't the guard; every other handler continues at
///   `pc + 1`.
///
/// No slot below `len` holds `GUARD`, and only this function gives one `FAR`: [`Code::new`](crate::Code::new) frees
/// both bytes as it does every byte with a handler of its own.
pub fn bound(code: &mut Vec<Instruction>) {
    let len = code.len();

    let mut far = Vec::new();
    for pc in 0..len {
        let slot = code[pc];
        if let Some(sup) = Super::with_byte(slot.byte()) {
            // the branch lies after `pc`, so this loop hasn't changed it yet
            if !fits(sup, code, pc) {
                code[pc] = sup.first_of(slot);
            }
        } else if moves(code, pc) {
            far.push(slot.with_byte(GUARD));
            // below 2^32, as `Code::new` takes fewer than 2^31 slots and moves at most one per slot
            let at = (len + far.len()) as u32;
            let byte = slot.byte();
            code[pc] = Instruction::new(OpCode(FAR), byte, byte >> 4, 0, at as i32);
        }
    }

    code.reserve_exact(1 + far.len());
    code.push(Instruction(u64::from(GUARD)));
    code.extend(far);
}

/// Whether the superinstruction `sup` at `pc` continues only at pcs in `0..=code.len()`: its sequence lies in `code`,
/// and so does the target of its branch if it has one. It also reads every slot of its sequence as loaded, so it fuses
/// only where `bound` moves none of them behind the guard.
pub fn fits(sup: &Super, code: &[Instruction], pc: usize) -> bool {
    let len = code.len();
    let last = pc + sup.len() - 1;
    last < len
        && (!sup.branches() || lands(len, last, code[last].offset().into()))
        && (1..sup.len()).all(|k| !moves(code, pc + k))
}

/// Whether `bound` moves the instruction in slot `pc` behind the guard: it has a fixed target outside
/// `0..=code.len()`.
// inline, as `bound` asks it for every slot
#[inline(always)]
fn moves(code: &[Instruction], pc: usize) -> bool {
    displacement(code[pc]).is_some_and(|displacement| !lands(code.len(), pc, displacement))
}

/// Whether the target `pc + 1 + displacement` lies in `0..=len`.
fn lands(len: usize, pc: usize, displacement: i64) -> bool {
    let target = pc as i64 + 1 + displacement;
    (0..=len as i64).contains(&target)
}

/// The displacement of the fixed target the handler of `insn` may continue at, `pc + 1 + displacement`, as
/// [`step::jump`] computes it, or `None` if it continues only at `pc + 1` or a target it computes at run time.
fn displacement(insn: Instruction) -> Option<i64> {
    let target = TARGETS[usize::from(insn.byte())];
    if target & FIXED == 0 || (target & LOCAL_CALL != 0 && insn.src_reg() != call::LOCAL) {
        return None;
    }
    Some(if target & IN_IMM != 0 {
        insn.imm().into()
    } else {
        insn.offset().into()
    })
}

/// Whether and where an instruction holds the displacement of a fixed target, as the bits of a [`TARGETS`] entry:
/// it has one;
const FIXED: u8 = 1;
/// in `imm`, else in `offset`;
const IN_IMM: u8 = 2;
/// and only if it is a local call.
const LOCAL_CALL: u8 = 4;

/// For each opcode byte, the bits above. A table of bits and not of an enum, which `displacement` would match with
/// branches that cost [`bound`] a quarter of its speed.
const TARGETS: [u8; 256] = {
    const OFFSET: u8 = FIXED;
    const IMM: u8 = FIXED | IN_IMM;
    const CALL: u8 = IMM | LOCAL_CALL;

    byte_table!(|byte| {
        let opc = OpCode(byte);
        let jmp64 = matches!(opc.class(), Class::Jmp64);
        let imm = matches!(opc.source(), Source::Imm);
        match opc.jmp_opc() {
            _ if !opc.is_jump() => 0,
            JmpOpc::Ja if imm && jmp64 => OFFSET,
            JmpOpc::Ja if imm => IMM,
            JmpOpc::Call if imm && jmp64 => CALL,
            // `gotox`, helper and kfunc calls, `callx`, `exit`, `may_goto` and the encodings that fail
            JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit | JmpOpc::Jcond | JmpOpc::UndefF => 0,
            // conditional jumps
            _ => OFFSET,
        }
    })
};

/// A pointer to the [`ThreadedSlot`] of the instruction a handler runs, which handlers carry in place of its pc.
///
/// Every `Ip` a handler receives points into the compiled stream of the [`Code`](crate::Code) that the run executes:
/// the interpreter and the checked fetches make one only for a pc they found there, and a handler moves one without a
/// check only from a slot below `len`, to the next slot or to a target that [`bound`] proves lies in `0..=len`. The
/// slots from `len` on all hold [`GUARD`], whose handler continues nowhere. So a handler reads its own slot, and the
/// slot it continues at, without a check.
#[derive(Clone, Copy)]
pub struct Ip(pub *const ThreadedSlot);

impl Ip {
    /// The ip of `pc` in `code`, where `pc` is known to be a valid slot boundary in `code`.
    #[inline(always)]
    pub fn at(code: Slots, pc: u64) -> Self {
        code.ip_at_unchecked(pc)
    }

    /// The ip `n` slots on, which may lie outside the code.
    #[inline(always)]
    pub fn offset(self, n: i64) -> Self {
        Self(self.0.wrapping_offset(n as isize))
    }

    /// The ip `bytes` bytes on (a multiple of `size_of::<ThreadedSlot>()`), which may lie outside the code.
    #[inline(always)]
    pub fn byte_offset(self, bytes: isize) -> Self {
        debug_assert!(bytes % (size_of::<ThreadedSlot>() as isize) == 0);
        Self(self.0.cast::<u8>().wrapping_offset(bytes).cast::<ThreadedSlot>())
    }

    /// The pc of the slot in `code`, which it lies in.
    #[inline(always)]
    pub fn pc(self, code: Slots) -> u64 {
        code.pc_at(self.addr())
    }

    #[inline(always)]
    pub fn addr(self) -> usize {
        self.0.addr()
    }

    /// The handler and payload slot at this ip.
    ///
    /// # Safety
    ///
    /// It must lie in the compiled stream of a [`Code`](crate::Code) built for `<M, H>` that is still borrowed.
    #[inline(always)]
    pub unsafe fn fetch<M: Memory, H: Host<M>>(self) -> (Handler<M, H>, Slot) {
        // SAFETY: the caller's
        let entry = unsafe { *self.0 };
        // SAFETY: `compile_threaded` populated `entry.handler` from `DispatchTable<M, H>`.
        let handler: Handler<M, H> = unsafe { std::mem::transmute(entry.handler) };
        (handler, entry.slot)
    }

    /// The [`Slot`] at this ip.
    ///
    /// # Safety
    ///
    /// It must lie in the slots of a [`Code`](crate::Code) that is still borrowed.
    #[inline(always)]
    pub unsafe fn get(self) -> Slot {
        // SAFETY: the caller's
        unsafe { (*self.0).slot }
    }

    /// The fields of the threaded slot it points to, as the handler of an opcode byte of shape `shape` reads them,
    /// taking `held`, that slot in a register.
    ///
    /// # Safety
    ///
    /// As for [`Ip::get`] while the view is in use; `held` must be the threaded slot it points to, and it must have
    /// the threaded layout of `shape` (see [`View::threaded`]).
    #[inline(always)]
    pub unsafe fn view<'a>(self, held: Slot, shape: Shape) -> View<'a, true> {
        // SAFETY: the caller's
        unsafe { View::threaded(&(*self.0).slot, Some(held), shape) }
    }

    /// The `n` threaded slots from this one on, borrowed from `code`.
    ///
    /// # Safety
    ///
    /// They must lie in `code`.
    #[inline(always)]
    pub unsafe fn slots<'a>(self, _code: Slots<'a>, n: usize) -> &'a [ThreadedSlot] {
        // SAFETY: the caller's
        unsafe { std::slice::from_raw_parts(self.0, n) }
    }
}

/// The upper half of the immediate of the LD_IMM64 whose second slot holds `second`, or `None` if the code ends before
/// it.
#[inline(always)]
pub fn second_half(second: Slot) -> Option<i32> {
    match second.byte() {
        GUARD => None,
        // `Code::new` leaves LD_IMM64 only where its second slot holds the byte `MISSING`, whose layout keeps `imm`
        _ => Some(second.imm()),
    }
}

/// Give [`GUARD`] and [`FAR`] their handlers.
pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
    table[GUARD as usize] = guard::<M, H>;
    table[FAR as usize] = far::<M, H, F>;
}

/// The handler of [`GUARD`]: the code has no instruction at `ip`.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn guard<M: Memory, H: Host<M>>(
    _ctx: &mut Context<M>,
    _code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    _rests: RestsPtr,
    _: Spare,
    _slot: Slot,
) {
    interp.stop.at(ip, Reason::BadPc)
}

/// The handler of [`FAR`]: runs the instruction that `bound` moved behind the guard, and checks where it continues.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn far<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    rests: RestsPtr,
    _: Spare,
    far: Slot,
) {
    let Some(pc) = run_moved(ctx, code, ip, interp, far) else {
        return;
    };
    become_at_pc!(ctx, code, pc, interp, rests)
}

/// Runs the jump or local call that the [`FAR`] slot `far` at `ip` stands for, and returns the pc it continues at.
/// `None` if it stopped the run.
// out of line, so that the handlers of `FAR` for every `Fuel` share it
#[inline(never)]
fn run_moved<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    far: Slot,
) -> Option<u64> {
    // the opcode byte of the moved instruction, from the halves in `dst_reg` and `src_reg`
    let far = far.instruction();
    let byte = far.dst_reg() | far.src_reg() << 4;
    let moved = code
        .raw_slot(u64::from(far.imm() as u32))
        .expect("a moved instruction behind the guard");
    let moved = moved.instruction().with_byte(byte);

    let step: Step<M::Error> = match moved.opcode().class() {
        Class::Jmp32 => step::jump::<_, _, BITS_32>(&ctx.regs, moved),
        Class::Jmp64 => step::jump::<_, _, BITS_64>(&ctx.regs, moved),
        _ => unreachable!("`bound` moves only jumps and local calls"),
    };
    let pc = ip.pc(code);
    let target = match step {
        Step::Next => pc,
        Step::Jump(offset) => pc.wrapping_add_signed(offset),
        Step::Call(offset) => {
            if !interp.push(&mut ctx.regs, ip.offset(1)) {
                interp.stop.at(ip, Reason::StackOverflow);
                return None;
            }
            pc.wrapping_add_signed(offset)
        }
        // `bound` moves no instruction that `Code::new` fails, no `exit` and no calls but local ones
        _ => unreachable!("`bound` moves only jumps and local calls"),
    };
    Some(target.wrapping_add(1))
}

/// Every kind of fixed target at the edges `bound` decides, with ample fuel and with the fuel running out on the way.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::{AluOpc, LD_IMM64};
    use crate::{Callee, Code, NativeCall};

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

    /// Run `code` from `pc` with r2 = 5, and with the `fuel` feature with `fuel`, and check the reason, pc and r0 it
    /// stops with, and with the feature the fuel left.
    #[track_caller]
    fn expect(code: &[Instruction], pc: u64, fuel: u64, (reason, stop_pc, left, r0): (Reason<()>, u64, u64, u64)) {
        let code = Code::new(code);
        let mut memory = NoMem;
        let mut ctx = Context::new(&mut memory);
        ctx.regs[2] = 5;
        let mut interp = Interpreter::new(0, NoHost);
        #[cfg(feature = "fuel")]
        interp.set_limit(Some(fuel));
        let stop = interp.run(&mut ctx, &code, pc);
        assert_eq!((stop.reason, stop.pc, ctx.regs[0]), (reason, stop_pc, r0));
        if crate::METERED {
            assert_eq!(interp.fuel(), Some(left));
        }
        let _ = fuel;
    }

    const EXIT: Instruction = Instruction::new(OpCode::jmp64(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0);
    const JA32: OpCode = OpCode::jmp32(JmpOpc::Ja, Source::Imm);

    #[test]
    fn targets_at_the_edges() {
        let jmp = |opc, d: i64| Instruction::new(OpCode::jmp64(opc, Source::Imm), 0, 0, d as i16, 0);
        let ja32 = |d: i64| Instruction::new(JA32, 0, 0, 0, d as i32);
        let call = |d: i64| Instruction::new(OpCode::jmp64(JmpOpc::Call, Source::Imm), 0, call::LOCAL, 0, d as i32);
        // r1 + 1 < r2
        let add = Instruction::new(OpCode::alu64(AluOpc::Add, Source::Imm), 1, 0, 0, 1);
        let jlt = |d: i64| Instruction::new(OpCode::jmp64(JmpOpc::Jlt, Source::Reg), 1, 2, d as i16, 0);

        let len = 4;
        for target in [0, len - 1, len, len + 1, -1, -1000] {
            let lands = (0..len).contains(&target);
            // each starts at slot 1 and transfers from slot 1, or slot 2 in the superinstruction `add; jlt`
            for (code, ran, returns) in [
                ([EXIT, jmp(JmpOpc::Jeq, target - 2), EXIT, EXIT], 1, false),
                ([EXIT, jmp(JmpOpc::Ja, target - 2), EXIT, EXIT], 1, false),
                ([EXIT, ja32(target - 2), EXIT, EXIT], 1, false),
                ([EXIT, call(target - 2), EXIT, EXIT], 1, true),
                ([EXIT, add, jlt(target - 3), EXIT], 2, false),
            ] {
                if code[1] == add {
                    // a branch to the guard slot keeps the superinstruction
                    let fused = Code::new(code).raw_slot(1).unwrap().byte() != add.byte();
                    assert_eq!(fused, (0..=len).contains(&target), "{code:?}");
                }
                let stop = match (lands, returns) {
                    (true, false) => (Reason::Exit, target as u64, 10 - ran - 1, 0),
                    // the callee's `exit` returns to the `exit` after the call
                    (true, true) => (Reason::Exit, 2, 10 - ran - 2, 0),
                    (false, _) => (Reason::BadPc, target as u64, 10 - ran, 0),
                };
                expect(&code, 1, 10, stop);
                if crate::METERED {
                    expect(&code, 1, ran, (Reason::OutOfFuel, target as u64, 0, 0));
                }
            }
        }
    }

    /// One interpreter over several runs: each `run` starts with the limit whatever the last one left, also at a pc
    /// outside the code, and `resume` continues with the fuel left.
    #[cfg(feature = "fuel")]
    #[test]
    fn fuel_across_runs() {
        let add = Instruction::new(OpCode::alu64(AluOpc::Add, Source::Imm), 0, 0, 0, 1);
        let code = Code::new([add, add, add, EXIT]);
        let mut memory = NoMem;
        let mut interp = Interpreter::new(0, NoHost);
        interp.set_limit(Some(2));

        let mut run = |pc: u64| {
            let mut ctx = Context::new(&mut memory);
            let stop = interp.run(&mut ctx, &code, pc);
            (stop.reason, stop.pc, interp.fuel(), ctx.regs[0])
        };
        assert_eq!(run(0), (Reason::OutOfFuel, 2, Some(0), 2));
        assert_eq!(run(9), (Reason::BadPc, 9, Some(2), 0));
        assert_eq!(run(2), (Reason::Exit, 3, Some(0), 1));
        assert_eq!(run(1), (Reason::OutOfFuel, 3, Some(0), 2));

        let mut resume = |fuel: u64, pc: u64| {
            let mut ctx = Context::new(&mut memory);
            interp.set_fuel(fuel);
            let stop = interp.resume(&mut ctx, &code, pc);
            (stop.reason, stop.pc, interp.fuel())
        };
        assert_eq!(resume(1, 3), (Reason::Exit, 3, Some(0)));
        assert_eq!(resume(0, 9), (Reason::OutOfFuel, 9, Some(0)));
        assert_eq!(resume(3, 1), (Reason::Exit, 3, Some(0)));
        assert_eq!(resume(2, 1), (Reason::OutOfFuel, 3, Some(0)));
    }

    #[test]
    fn ld_imm64_at_the_end() {
        let lddw = Instruction::new(OpCode(LD_IMM64), 0, 0, 0, 7);
        expect(&[EXIT, lddw], 1, 10, (Reason::BadPc, 1, 10, 0));
        if crate::METERED {
            expect(&[EXIT, lddw], 1, 1, (Reason::OutOfFuel, 1, 1, 0));
        }

        // a second slot that holds more than the upper half fails the LD_IMM64 as the verifier rejects it, and runs as
        // an instruction of its own; LD_IMM64's byte there doesn't fuse `lddw; add64`
        let hi = 1 << 20;
        let far = Instruction::new(JA32, 0, 0, 0, hi);
        expect(&[lddw, far, EXIT], 0, 10, (Reason::InvalidInstruction, 0, 9, 0));
        expect(&[lddw, far, EXIT], 1, 10, (Reason::BadPc, 2 + hi as u64, 9, 0));
        let add = Instruction::new(OpCode::alu64(AluOpc::Add, Source::Reg), 0, 2, 0, 0);
        let upper = Instruction::new(OpCode(LD_IMM64), 0, 0, 0, 0);
        expect(&[lddw, upper, add, EXIT], 0, 10, (Reason::InvalidInstruction, 0, 9, 0));

        // `lddw r0; add64 r0, r2` fused, with the fuel running out in each slot and after it
        let value = (hi as u64) << 32 | 7;
        let upper = Instruction::new(OpCode(0), 0, 0, 0, hi);
        let code = [lddw, upper, add, EXIT];
        assert_ne!(Code::new(code).raw_slot(0).unwrap().byte(), LD_IMM64);
        expect(&code, 0, 10, (Reason::Exit, 3, 6, value + 5));
        if crate::METERED {
            expect(&code, 0, 0, (Reason::OutOfFuel, 0, 0, 0));
            expect(&code, 0, 1, (Reason::OutOfFuel, 0, 1, 0));
            expect(&code, 0, 2, (Reason::OutOfFuel, 2, 0, value));
            expect(&code, 0, 3, (Reason::OutOfFuel, 3, 0, value + 5));
        }
    }
}
