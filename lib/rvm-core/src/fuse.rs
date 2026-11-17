//! Superinstructions: common instruction sequences that [`run`](crate::run)
//! executes with one dispatch.
//!
//! [`Code::new`] gives the first slot of each sequence it recognises the opcode
//! byte of a superinstruction, one of the LD-class bytes that rvm doesn't run (see
//! [`MISSING`]). The other slots keep their instructions, so a jump into the
//! middle of a sequence runs them one by one. A superinstruction behaves exactly
//! like its sequence:
//! - it charges one unit of fuel per instruction, and runs only the first
//!   instruction when the fuel would run out inside the sequence;
//! - an instruction that faults stops execution at its own pc, with the effects
//!   of the instructions before it.

use std::ops::ControlFlow;

use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source};
use crate::{handler_of, step, CallStack, Context, Flow, Handler, Handlers, Host, Instruction, Memory};

/// Bytecode prepared for [`run`](crate::run).
#[derive(Debug)]
pub struct Code(Box<[Instruction]>);

impl Code {
    /// Prepare `insns` for [`run`](crate::run): fuse the sequences that have a
    /// superinstruction.
    pub fn new(insns: impl Into<Box<[Instruction]>>) -> Self {
        let mut insns = insns.into();
        fuse(&mut insns);
        Self(insns)
    }

    /// The number of instruction slots.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn slots(&self) -> &[Instruction] {
        &self.0
    }
}

/// Rewrite each sequence that has a superinstruction to it.
fn fuse(code: &mut [Instruction]) {
    for insn in code.iter_mut() {
        if is_reserved(insn.0 as u8) {
            insn.0 = insn.0 & !0xFF | u64::from(MISSING);
        }
    }

    // A superinstruction changes only its first slot, and there only the opcode
    // byte unless the slot holds a register `mov`. So the code from slot `i` on is
    // still as loaded, and a tail, which is never such a `mov`, keeps its fields.
    for i in 0..code.len() {
        // the slot after LD_IMM64 holds the upper half of its immediate
        if i > 0 && code[i - 1].0 as u8 == LD_IMM64 {
            continue;
        }
        let window = &code[i..];
        if let Some(slot) = SUPERS.iter().find_map(|&(byte, sup)| sup.encode(byte, window)) {
            code[i] = slot;
        }
    }
}

const LD_IMM64: u8 = OpCode(Class::LdImm as u8 | MemMode::Imm as u8 | MemSize::DWord as u8).0;

const MOV64: u8 = AluOpc::mov_64(Source::Reg).0;
const MOV32: u8 = AluOpc::mov_32(Source::Reg).0;
const ADD64_REG: u8 = AluOpc::add_64(Source::Reg).0;
const ADD64_IMM: u8 = AluOpc::add_64(Source::Imm).0;

const fn ldx(size: MemSize) -> u8 {
    OpCode::ldreg_from_parts(size, MemMode::Mem).0
}

const fn st(size: MemSize) -> u8 {
    OpCode::stimm_from_parts(size, MemMode::Mem).0
}

const fn jmp(opc: JmpOpc, src: Source) -> u8 {
    OpCode::jmp64_from_parts(opc, src).0
}

/// Every opcode byte of the LD class but LD_IMM64, the legacy packet loads among
/// them, runs as the same unsupported instruction ([`Flow::Missing`]).
/// [`Code::new`] rewrites them all to this one, which frees the others for
/// superinstructions.
const MISSING: u8 = Class::LdImm as u8;

const fn is_reserved(byte: u8) -> bool {
    byte & 0b111 == Class::LdImm as u8 && byte != LD_IMM64 && byte != MISSING
}

/// The opcodes of the sequence a superinstruction runs.
#[derive(Clone, Copy)]
struct Super {
    /// The first instruction. With `alu`, a register `mov` whose slot also holds
    /// the source operand of `alu` in its `imm` field.
    first: u8,
    /// An ALU instruction on the destination of the `mov`, or 0.
    alu: u8,
    /// The next instruction, which the superinstruction reads from its own slot,
    /// or 0.
    tail: u8,
}

macro_rules! superinstructions {
    ($($byte:literal: $first:expr, $alu:expr, $tail:expr;)*) => {
        /// Superinstructions by opcode byte; [`Code::new`] tries them in this order.
        const SUPERS: &[(u8, Super)] = &[$(Super { first: $first, alu: $alu, tail: $tail }.checked($byte)),*];

        const _: () = {
            let mut i = 0;
            while i < SUPERS.len() {
                let mut j = i + 1;
                while j < SUPERS.len() {
                    assert!(SUPERS[i].0 != SUPERS[j].0, "two superinstructions share a byte");
                    j += 1;
                }
                i += 1;
            }
        };

        /// Give each superinstruction byte its handler.
        pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = fused::<M, H, FUEL, $byte>;)*
        }
    };
}

// Longer sequences first, so that they win over their prefixes.
superinstructions! {
    // r_a = r_b; r_a += r_c; then a load, store or branch
    0x08: MOV64, ADD64_REG, ldx(MemSize::Byte);
    0x10: MOV64, ADD64_REG, ldx(MemSize::Word);
    0x20: MOV64, ADD64_REG, st(MemSize::Byte);
    0x28: MOV64, ADD64_REG, jmp(JmpOpc::Jlt, Source::Imm);
    // three-address ALU: r_a = r_b; r_a op= src
    0x30: MOV64, ADD64_REG, 0;
    0x38: MOV64, ADD64_IMM, 0;
    0x40: MOV64, AluOpc::mul_64(Source::Reg).0, 0;
    0x48: MOV64, AluOpc::xor_64(Source::Reg).0, 0;
    0x50: MOV64, AluOpc::lsh_64(Source::Imm).0, 0;
    0x58: MOV64, AluOpc::rsh_64(Source::Imm).0, 0;
    0x60: MOV32, AluOpc::and_32(Source::Imm).0, 0;
    0x68: MOV32, AluOpc::and_32(Source::Reg).0, 0;
    0x70: MOV32, AluOpc::or_32(Source::Reg).0, 0;
    0x78: MOV32, AluOpc::lsh_32(Source::Imm).0, 0;
    0x80: MOV32, AluOpc::rsh_32(Source::Imm).0, 0;
    // loop counters: r_a += imm, then a branch
    0x88: ADD64_IMM, 0, jmp(JmpOpc::Jlt, Source::Reg);
    0x90: ADD64_IMM, 0, jmp(JmpOpc::Jne, Source::Imm);
    0x98: ADD64_IMM, 0, jmp(JmpOpc::Jgt, Source::Imm);
}

impl Super {
    /// The superinstruction with opcode byte `byte`.
    const fn of(byte: u8) -> Self {
        let mut i = 0;
        while i < SUPERS.len() {
            if SUPERS[i].0 == byte {
                return SUPERS[i].1;
            }
            i += 1;
        }
        panic!("not a superinstruction");
    }

    /// Pairs the superinstruction with its opcode `byte`, and fails to compile one
    /// that [`fused`] can't run: only the last instruction may branch, none may
    /// call or exit, and none may be LD_IMM64.
    const fn checked(self, byte: u8) -> (u8, Self) {
        assert!(is_reserved(byte));
        assert!(self.len() > 1);
        let first = OpCode(self.first).class();
        assert!(!matches!(first, Class::LdImm | Class::Jmp32 | Class::Jmp64));
        if self.alu != 0 {
            assert!(self.first == MOV64 || self.first == MOV32);
            assert!(OpCode(self.alu).class() as u8 == first as u8);
        }
        if self.tail != 0 {
            let tail = OpCode(self.tail);
            assert!(!matches!(tail.class(), Class::LdImm));
            if matches!(tail.class(), Class::Jmp32 | Class::Jmp64) {
                assert!(!matches!(tail.jmp_opc(), JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit));
            }
            // The slot of a tail must keep its fields, and a three-address
            // superinstruction changes the `imm` of a register `mov`.
            assert!(self.tail != MOV64 && self.tail != MOV32);
        }
        (byte, self)
    }

    /// The number of instructions in the sequence.
    const fn len(self) -> usize {
        1 + (self.alu != 0) as usize + (self.tail != 0) as usize
    }

    /// The first instruction of the sequence whose first slot holds `slot`.
    #[inline(always)]
    fn first_of(self, slot: Instruction) -> Instruction {
        match self.alu {
            0 => Instruction(slot.0 & !0xFF | u64::from(self.first)),
            _ => Instruction::from_parts(OpCode(self.first), slot.dst_reg(), slot.src_reg(), 0, 0),
        }
    }

    /// The instructions of the sequence, from its first slot `slot` and the code
    /// `window` that starts there; entries past [`Super::len`] are filler.
    #[inline(always)]
    fn decode(self, slot: Instruction, window: &[Instruction]) -> [Instruction; 3] {
        let mut insns = [self.first_of(slot); 3];
        let mut k = 1;
        if self.alu != 0 {
            let (dst, operand) = (slot.dst_reg(), slot.imm());
            let alu = OpCode(self.alu);
            insns[1] = match alu.alu_src() {
                Source::Imm => Instruction::from_parts(alu, dst, 0, 0, operand),
                Source::Reg => Instruction::from_parts(alu, dst, operand as u8 & 0xF, 0, 0),
            };
            k = 2;
        }
        if self.tail != 0 {
            insns[k] = Instruction(window[k].0 & !0xFF | u64::from(self.tail));
        }
        insns
    }

    /// The first slot of this superinstruction, with opcode byte `byte`, for the
    /// sequence at the start of `window`, if it has one.
    fn encode(self, byte: u8, window: &[Instruction]) -> Option<Instruction> {
        let sequence = window.get(..self.len())?;
        let first = sequence[0];
        let slot = match self.alu {
            0 => Instruction(first.0 & !0xFF | u64::from(byte)),
            _ => {
                let alu = sequence[1];
                let operand = match alu.opcode().alu_src() {
                    Source::Imm => alu.imm(),
                    Source::Reg => i32::from(alu.src_reg()),
                };
                Instruction::from_parts(OpCode(byte), first.dst_reg(), first.src_reg(), 0, operand)
            }
        };
        (self.decode(slot, window)[..self.len()] == *sequence).then_some(slot)
    }

    /// Whether instruction `k` of the sequence may branch.
    const fn branches_at(self, k: usize) -> bool {
        k == self.len() - 1 && matches!(OpCode(self.tail).class(), Class::Jmp32 | Class::Jmp64)
    }
}

/// The handler of superinstruction `S`. It runs the sequence as the handlers of
/// its instructions would, one after another.
#[inline(never)]
extern "rust-preserve-none" fn fused<M: Memory, H: Host<M>, const FUEL: bool, const S: u8>(
    ctx: &mut Context<M>,
    code: &[Instruction],
    insn: Instruction,
    pc: u64,
    fuel: u64,
    calls: &mut CallStack<H>,
) -> Flow<M> {
    let sup = const { Super::of(S) };
    let len = const { Super::of(S).len() };

    // the sequence and the slot after it
    let window = code.get(pc as usize..pc as usize + len + 1);
    let Some(window) = window.filter(|_| !FUEL || fuel >= len as u64 - 1) else {
        // the fuel runs out inside the sequence, or the code ends with it
        let alone = const { Handlers::<M, H, FUEL>::TABLE[Super::of(S).first as usize] };
        become alone(ctx, code, sup.first_of(insn), pc, fuel, calls)
    };

    // one block per instruction, so that each `step` sees a constant opcode
    let [i0, i1, i2] = sup.decode(insn, window);
    let mut target = None;
    macro_rules! exec {
        ($k:literal, $insn:expr) => {
            if $k < len {
                let at = pc + $k;
                match step(ctx, $insn) {
                    ControlFlow::Break(Flow::Next) => {}
                    ControlFlow::Break(Flow::Jump(offset)) if const { Super::of(S).branches_at($k) } => {
                        target = Some(at.wrapping_add_signed(offset).wrapping_add(1));
                    }
                    ControlFlow::Break(flow) => return calls.stop.at(at, fuel - $k * u64::from(FUEL), flow),
                    // `Super::checked` keeps LD_IMM64 out
                    ControlFlow::Continue(_) => unreachable!(),
                }
            }
        };
    }
    exec!(0, i0);
    exec!(1, i1);
    exec!(2, i2);

    let fuel = fuel - (len as u64 - 1) * u64::from(FUEL);
    let pc = target.unwrap_or(pc + len as u64);
    if FUEL && fuel == 0 {
        return calls.stop.at(pc, fuel, Flow::OutOfFuel);
    }
    // a negative jump target wraps to a huge pc and fails the fetch
    let insn = match target {
        None => window[len],
        Some(target) => match code.get(target as usize) {
            Some(&insn) => insn,
            None => return calls.stop.at(pc, fuel, Flow::BadPc),
        },
    };
    become handler_of::<M, H, FUEL>(insn)(ctx, code, insn, pc, fuel - u64::from(FUEL), calls)
}
