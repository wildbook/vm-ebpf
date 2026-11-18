//! Control transfers that need no bounds check.
//!
//! [`Code::new`](crate::Code::new) ends the code with a [`GUARD`] slot, and [`bound`] proves that every pc a handler
//! continues at without a check lies in `0..=len`, the guard included. So [`fetch`](crate::fetch) reads such a pc
//! without checking it, and the guard stops with [`Flow::BadPc`] where the code ends, as a checked fetch would.
//! [`run`](crate::run) checks the pc it starts at, the `exit` handler the pc it returns to, and the runtime the
//! targets of `callx` and `gotox`.

use crate::fuse::Super;
use crate::opcode::{Class, JmpOpc, OpCode, Source};
use crate::ops::{self, BITS_32, BITS_64};
use crate::{fetch_checked, CallStack, Context, Flow, Handler, Host, Instruction, Memory, Table, BPF_PSEUDO_CALL};

/// The slot after the code, and every slot after it: there is no instruction here.
pub const GUARD: u8 = 0xe0;

/// A jump or local call whose target lies outside the code. Its `imm` is the index of a slot after the guard that
/// holds the instruction with the opcode byte [`GUARD`], and its `dst_reg` and `src_reg` hold the low and high half of
/// the opcode byte.
pub const FAR: u8 = 0xe8;

/// Proves where handlers continue: afterwards, the slots from the original `code.len()` on all hold [`GUARD`], and
/// the handler of each slot below it continues without a check only at a pc in `0..=len`:
/// - a jump or local call at `pc` continues at `pc + 1` or at its target; one whose target lies outside gets [`FAR`],
///   which checks it;
/// - a superinstruction continues after its sequence or at the target of its branch; one whose sequence runs past the
///   code or whose branch target lies outside runs its first instruction alone instead;
/// - LD_IMM64 continues after its second slot only if that slot isn't the guard; every other handler continues at
///   `pc + 1`.
///
/// No slot below `len` holds `GUARD`, and only this function gives one `FAR`: [`Code::new`](crate::Code::new) frees
/// both bytes as it does every byte with a handler of its own.
pub fn bound(code: &mut Vec<Instruction>) {
    let len = code.len();
    let lands = |pc: usize, displacement: i64| {
        let target = pc as i64 + 1 + displacement;
        (0..=len as i64).contains(&target)
    };

    let mut far = Vec::new();
    for pc in 0..len {
        let slot = code[pc];
        if let Some(sup) = Super::with_byte(slot.0 as u8) {
            // the branch lies after `pc`, so this loop hasn't changed it yet
            let last = pc + sup.len() - 1;
            let fits = last < len && (!sup.branches() || lands(last, i64::from(code[last].offset())));
            if !fits {
                code[pc] = sup.first_of(slot);
            }
        } else if let Some(displacement) = displacement(slot) {
            if !lands(pc, displacement) {
                far.push(Instruction(slot.0 & !0xFF | u64::from(GUARD)));
                let at = u32::try_from(len + far.len()).expect("fewer than 2^31 slots");
                let byte = slot.0 as u8;
                code[pc] = Instruction::from_parts(OpCode(FAR), byte, byte >> 4, 0, at as i32);
            }
        }
    }

    code.reserve_exact(1 + far.len());
    code.push(Instruction(u64::from(GUARD)));
    code.extend(far);
}

/// The displacement of the fixed target the handler of `insn` may continue at, `pc + 1 + displacement`, as
/// [`ops::jump`] computes it, or `None` if it continues only at `pc + 1` or a target it computes at run time.
fn displacement(insn: Instruction) -> Option<i64> {
    let target = TARGETS[insn.0 as u8 as usize];
    if !target.fixed || (target.local_call && insn.src_reg() != BPF_PSEUDO_CALL) {
        return None;
    }
    Some(if target.in_imm {
        insn.imm().into()
    } else {
        insn.offset().into()
    })
}

/// Whether and where an instruction with a given opcode byte holds the displacement of a fixed target.
#[derive(Clone, Copy)]
struct Target {
    fixed: bool,
    /// In `imm`, else in `offset`.
    in_imm: bool,
    /// A call, which has a fixed target only if it is a local one.
    local_call: bool,
}

/// The [`Target`] of each opcode byte.
const TARGETS: [Target; 256] = {
    const NONE: Target = Target {
        fixed: false,
        in_imm: false,
        local_call: false,
    };
    const OFFSET: Target = Target { fixed: true, ..NONE };
    const IMM: Target = Target { in_imm: true, ..OFFSET };
    const CALL: Target = Target {
        local_call: true,
        ..IMM
    };

    let mut table = [NONE; 256];
    let mut byte = 0;
    while byte < 256 {
        let opc = OpCode(byte as u8);
        let jmp64 = matches!(opc.class(), Class::Jmp64);
        let imm = matches!(opc.alu_src(), Source::Imm);
        table[byte] = match opc.jmp_opc() {
            _ if !matches!(opc.class(), Class::Jmp64 | Class::Jmp32) => NONE,
            JmpOpc::Ja if imm && jmp64 => OFFSET,
            JmpOpc::Ja if imm => IMM,
            JmpOpc::Call if imm && jmp64 => CALL,
            // `gotox`, helper and kfunc calls, `callx`, `exit`, `may_goto` and the encodings that fail
            JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit | JmpOpc::Jcond | JmpOpc::UndefF => NONE,
            // conditional jumps
            _ => OFFSET,
        };
        byte += 1;
    }
    table
};

/// The second slot of the LD_IMM64 whose second slot holds `second`, or `None` if the code ends before it.
#[inline(always)]
pub fn second_half(code: &[Instruction], second: Instruction) -> Option<Instruction> {
    match second.0 as u8 {
        GUARD => None,
        // a jump that `bound` moved: the instruction after the guard holds its `imm`
        FAR => {
            core::hint::cold_path();
            Some(code[second.imm() as u32 as usize])
        }
        _ => Some(second),
    }
}

/// Give [`GUARD`] and [`FAR`] their handlers.
pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
    table[GUARD as usize] = guard::<M, H, FUEL>;
    table[FAR as usize] = far::<M, H, FUEL>;
}

/// The handler of [`GUARD`]: the code has no instruction at `pc`.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn guard<M: Memory, H: Host<M>, const FUEL: bool>(
    _ctx: &mut Context<M>,
    _code: &[Instruction],
    _insn: Instruction,
    pc: u64,
    fuel: u64,
    calls: &mut CallStack<H>,
    _table: &Table<M, H>,
) -> Flow<M> {
    // the fetch charged the unit of an instruction that doesn't run
    calls.stop.at(pc, fuel + u64::from(FUEL), Flow::BadPc)
}

/// The handler of [`FAR`]: runs the jump or local call that `bound` moved behind the guard, and checks where it
/// continues.
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn far<M: Memory, H: Host<M>, const FUEL: bool>(
    ctx: &mut Context<M>,
    code: &[Instruction],
    insn: Instruction,
    mut pc: u64,
    fuel: u64,
    calls: &mut CallStack<H>,
    table: &Table<M, H>,
) -> Flow<M> {
    let byte = insn.dst_reg() | insn.src_reg() << 4;
    let jump = Instruction(code[insn.imm() as u32 as usize].0 & !0xFF | u64::from(byte));
    let flow = match jump.opcode().class() {
        Class::Jmp32 => ops::jump::<_, BITS_32>(ctx, jump),
        _ => ops::jump::<_, BITS_64>(ctx, jump),
    };
    match flow {
        Flow::Next => {}
        Flow::Jump(offset) => pc = pc.wrapping_add_signed(offset),
        Flow::Call(offset) => {
            if !calls.push(&mut ctx.regs, pc) {
                return calls.stop.at(pc, fuel, Flow::StackOverflow);
            }
            pc = pc.wrapping_add_signed(offset);
        }
        // `bound` moves only jumps and local calls with a fixed target
        flow => return calls.stop.at(pc, fuel, flow),
    }

    let pc = pc.wrapping_add(1);
    match fetch_checked::<M, H, FUEL>(table, code, pc, fuel) {
        Ok((next, insn, fuel)) => become next(ctx, code, insn, pc, fuel, calls, table),
        Err(flow) => calls.stop.at(pc, fuel, flow),
    }
}

/// Every kind of fixed target at the edges `bound` decides, with ample fuel and with the fuel running out on the way.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::AluOpc;
    use crate::{run, Code};

    #[derive(Debug)]
    struct NoMem;

    // SAFETY: the default `window` reports no windows
    unsafe impl Memory for NoMem {
        type Err = ();

        fn load_u8(&self, _: u64) -> Result<u8, ()> {
            Err(())
        }

        fn store_u8(&mut self, _: u64, _: u8) -> Result<(), ()> {
            Err(())
        }
    }

    struct NoHost;

    impl Host<NoMem> for NoHost {
        fn helper(&mut self, _: &mut Context<NoMem>, _: u32) -> Option<u64> {
            None
        }

        fn kfunc(&mut self, _: &mut Context<NoMem>, _: u32) -> Option<u64> {
            None
        }
    }

    /// Run `code` from `pc` with `fuel` and r2 = 5, and check the flow, pc and r0 it stops with, and with the `fuel`
    /// feature the fuel left.
    #[track_caller]
    fn expect(code: &[Instruction], pc: u64, fuel: u64, stop: (&str, u64, u64, u64)) {
        let code = Code::new(code);
        let mut ctx = Context::new(NoMem);
        ctx.regs[2] = 5;
        let mut calls = CallStack::new(0, NoHost);
        let mut pc = pc;
        #[cfg(feature = "fuel")]
        let mut fuel = fuel;
        #[cfg(feature = "fuel")]
        let flow = run(&mut ctx, &code, &mut pc, &mut fuel, &mut calls);
        #[cfg(not(feature = "fuel"))]
        let flow = run(&mut ctx, &code, &mut pc, &mut calls);
        let flow = format!("{flow:?}");
        let (flow, left, r0) = (flow.split('(').next().unwrap(), fuel, ctx.regs[0]);
        assert_eq!((flow, pc, r0), (stop.0, stop.1, stop.3));
        if cfg!(feature = "fuel") {
            assert_eq!(left, stop.2);
        }
    }

    const EXIT: Instruction = Instruction::from_parts(OpCode::jmp64_from_parts(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0);
    const JA32: OpCode = OpCode::jmp32_from_parts(JmpOpc::Ja, Source::Imm);

    #[test]
    fn targets_at_the_edges() {
        let jmp = |opc, d: i64| Instruction::from_parts(OpCode::jmp64_from_parts(opc, Source::Imm), 0, 0, d as i16, 0);
        let ja32 = |d: i64| Instruction::from_parts(JA32, 0, 0, 0, d as i32);
        let call = |d: i64| {
            let opc = OpCode::jmp64_from_parts(JmpOpc::Call, Source::Imm);
            Instruction::from_parts(opc, 0, BPF_PSEUDO_CALL, 0, d as i32)
        };
        // r1 + 1 < r2
        let add = Instruction::from_parts(AluOpc::add_64(Source::Imm), 1, 0, 0, 1);
        let jlt = |d: i64| {
            let opc = OpCode::jmp64_from_parts(JmpOpc::Jlt, Source::Reg);
            Instruction::from_parts(opc, 1, 2, d as i16, 0)
        };

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
                    let fused = Code::new(code).slots()[1].0 as u8 != add.0 as u8;
                    assert_eq!(fused, (0..=len).contains(&target), "{code:?}");
                }
                let stop = match (lands, returns) {
                    (true, false) => ("Exit", target as u64, 10 - ran - 1, 0),
                    // the callee's `exit` returns to the `exit` after the call
                    (true, true) => ("Exit", 2, 10 - ran - 2, 0),
                    (false, _) => ("BadPc", target as u64, 10 - ran, 0),
                };
                expect(&code, 1, 10, stop);
                if cfg!(feature = "fuel") {
                    expect(&code, 1, ran, ("OutOfFuel", target as u64, 0, 0));
                }
            }
        }
    }

    #[test]
    fn ld_imm64_at_the_end() {
        let lddw = Instruction::from_parts(OpCode(0x18), 0, 0, 0, 7);
        expect(&[EXIT, lddw], 1, 10, ("BadPc", 2, 9, 0));
        if cfg!(feature = "fuel") {
            expect(&[EXIT, lddw], 1, 1, ("OutOfFuel", 1, 1, 0));
        }

        // a second slot that `bound` moves behind the guard still holds the upper half
        let hi = 1 << 20;
        let far = Instruction::from_parts(JA32, 0, 0, 0, hi);
        expect(&[lddw, far, EXIT], 0, 10, ("Exit", 2, 7, (hi as u64) << 32 | 7));
        expect(&[lddw, far, EXIT], 1, 10, ("BadPc", 2 + hi as u64, 9, 0));
    }
}
