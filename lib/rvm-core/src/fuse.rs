//! Superinstructions: common instruction sequences that [`run`](crate::run) executes with one dispatch.
//!
//! [`Code::new`] gives the first slot of each sequence it recognises the opcode byte of a superinstruction, one of the
//! LD-class bytes that rvm doesn't run (see [`MISSING`]). The other slots keep their instructions, so a jump into the
//! middle of a sequence runs them one by one. A superinstruction behaves exactly like its sequence:
//! - it charges one unit of fuel per instruction, and runs only the first instruction when the fuel would run out
//!   inside the sequence;
//! - an instruction that faults stops execution at its own pc, with the effects of the instructions before it.
//!
//! The same bytes mark the loads and stores through r10 that [`stack::access`] runs.

use std::ops::ControlFlow;

use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source};
use crate::{handler_of, stack, step, CallStack, Context, Flow, Handler, Handlers, Host, Instruction, Memory};

/// Bytecode prepared for [`run`](crate::run).
#[derive(Debug)]
pub struct Code(Box<[Instruction]>);

impl Code {
    /// Prepare `insns` for [`run`](crate::run): fuse the sequences that have a superinstruction.
    ///
    /// r10 is read-only, so an instruction that would write it fails with [`Flow::FailCpu`]: an ALU, ALU64 or LDX
    /// instruction, LD_IMM64 or a load-acquire with `dst_reg` 10, and an atomic that fetches into `src_reg` 10.
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

/// Give r10 writes and the bytes rvm doesn't run their failing bytes, and the sequences with a superinstruction and r10
/// accesses theirs.
fn fuse(code: &mut [Instruction]) {
    // Only the opcode byte changes, so the second slot of LD_IMM64 keeps its `imm`.
    for insn in code.iter_mut() {
        if is_reserved(insn.0 as u8) {
            insn.0 = insn.0 & !0xFF | u64::from(MISSING);
        } else if writes_r10(*insn) {
            insn.0 = insn.0 & !0xFF | u64::from(INVALID);
        }
    }

    // A superinstruction or r10 access changes only its first slot, and there only the opcode byte, unless the slot
    // holds a register `mov` with `imm` 0: then it also puts its operand in `imm`, which a register `mov` ignores. So
    // the code from slot `i` on is still as loaded, and a tail, which reads only its slot's fields, later reads an
    // instruction that runs the same.
    for i in 0..code.len() {
        // the slot after LD_IMM64 holds the upper half of its immediate
        if i > 0 && code[i - 1].0 as u8 == LD_IMM64 {
            continue;
        }
        let window = &code[i..];
        if let Some(slot) = SUPERS.iter().find_map(|&(byte, sup)| sup.encode(byte, window)) {
            code[i] = slot;
        } else if let Some(byte) = stack_byte(code[i]) {
            code[i].0 = code[i].0 & !0xFF | u64::from(byte);
        }
    }
}

/// Whether `insn` writes r10.
fn writes_r10(insn: Instruction) -> bool {
    const FETCH: i32 = 0x01;
    const CMPXCHG: i32 = 0xf0 | FETCH;
    const LOAD_ACQ: i32 = 0x100;

    let opc = insn.opcode();
    match opc.class() {
        Class::Alu32 | Class::Alu64 | Class::LdReg => insn.dst_reg() == 10,
        Class::LdImm => opc.0 == LD_IMM64 && insn.dst_reg() == 10,
        Class::StReg if matches!(opc.mem_mode(), MemMode::Atomic) => match insn.imm() {
            LOAD_ACQ => insn.dst_reg() == 10,
            // CMPXCHG fetches into r0
            imm => insn.src_reg() == 10 && imm & FETCH != 0 && imm != CMPXCHG,
        },
        Class::StReg | Class::StImm | Class::Jmp32 | Class::Jmp64 => false,
    }
}

/// The opcode byte of the r10 access `insn`, if it is a load or store with one.
fn stack_byte(insn: Instruction) -> Option<u8> {
    let opc = insn.opcode();
    let base = match opc.class() {
        Class::LdReg => insn.src_reg(),
        _ => insn.dst_reg(),
    };
    let (byte, _) = STACK.iter().find(|&&(_, usual)| usual == opc.0)?;
    (base == 10).then_some(*byte)
}

const LD_IMM64: u8 = OpCode(Class::LdImm as u8 | MemMode::Imm as u8 | MemSize::DWord as u8).0;

const MOV64: u8 = AluOpc::mov_64(Source::Reg).0;
const MOV32: u8 = AluOpc::mov_32(Source::Reg).0;
const ADD64_REG: u8 = AluOpc::add_64(Source::Reg).0;
const ADD64_IMM: u8 = AluOpc::add_64(Source::Imm).0;

const fn ldx(size: MemSize) -> u8 {
    OpCode::ldreg_from_parts(size, MemMode::Mem).0
}

const fn stx(size: MemSize) -> u8 {
    OpCode::streg_from_parts(size, MemMode::Mem).0
}

const fn st(size: MemSize) -> u8 {
    OpCode::stimm_from_parts(size, MemMode::Mem).0
}

const fn jmp(opc: JmpOpc, src: Source) -> u8 {
    OpCode::jmp64_from_parts(opc, src).0
}

/// Every opcode byte of the LD class but LD_IMM64, the legacy packet loads among them, runs as the same unsupported
/// instruction ([`Flow::Missing`]). [`Code::new`] rewrites them all to this one, which frees the others for
/// superinstructions and r10 accesses.
const MISSING: u8 = Class::LdImm as u8;

/// An undefined ALU64 operation, which always fails with [`Flow::FailCpu`]; the byte of every instruction that would
/// write r10.
const INVALID: u8 = AluOpc::UndefE as u8 | Class::Alu64 as u8;

const fn is_reserved(byte: u8) -> bool {
    byte & 0b111 == Class::LdImm as u8 && byte != LD_IMM64 && byte != MISSING
}

/// The opcodes of the sequence a superinstruction runs.
#[derive(Clone, Copy)]
struct Super {
    /// The first instruction. With `alu`, a register `mov` whose slot also holds the source operand of `alu` in its
    /// `imm` field.
    first: u8,
    /// An ALU instruction on the destination of the `mov`, or 0.
    alu: u8,
    /// The next instructions, each of which the superinstruction reads from its own slot; 0 after the last.
    tail: [u8; 3],
}

/// The most instructions a superinstruction runs.
const MAX_LEN: usize = 5;

macro_rules! superinstructions {
    ($($byte:literal: $first:expr, $alu:expr $(, $tail:expr)*;)*) => {
        /// Superinstructions by opcode byte; [`Code::new`] tries them in this order.
        const SUPERS: &[(u8, Super)] = &[$(Super::new($first, $alu, &[$($tail),*]).checked($byte)),*];

        /// Give each superinstruction byte its handler.
        const fn install_supers<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = fused::<M, H, FUEL, $byte>;)*
        }
    };
}

// Longer sequences first, so that they win over their prefixes.
superinstructions! {
    // rotate: t = x; t >>= k; x <<= 32 - k; then x |= t, or y = x; y |= t
    0xd0: MOV32, AluOpc::rsh_32(Source::Imm).0, AluOpc::lsh_32(Source::Imm).0, MOV32, AluOpc::or_32(Source::Reg).0;
    0xd8: MOV32, AluOpc::rsh_32(Source::Imm).0, AluOpc::lsh_32(Source::Imm).0, AluOpc::or_32(Source::Reg).0;
    // r_a = r_b; r_a += r_c; then a load, store or branch
    0x08: MOV64, ADD64_REG, ldx(MemSize::Byte);
    0x10: MOV64, ADD64_REG, ldx(MemSize::Word);
    0x20: MOV64, ADD64_REG, st(MemSize::Byte);
    0x28: MOV64, ADD64_REG, jmp(JmpOpc::Jlt, Source::Imm);
    // three-address ALU: r_a = r_b; r_a op= src
    0x30: MOV64, ADD64_REG;
    0x38: MOV64, ADD64_IMM;
    0x40: MOV64, AluOpc::mul_64(Source::Reg).0;
    0x48: MOV64, AluOpc::xor_64(Source::Reg).0;
    0x50: MOV64, AluOpc::lsh_64(Source::Imm).0;
    0x58: MOV64, AluOpc::rsh_64(Source::Imm).0;
    0x60: MOV32, AluOpc::and_32(Source::Imm).0;
    0x68: MOV32, AluOpc::and_32(Source::Reg).0;
    0x70: MOV32, AluOpc::or_32(Source::Reg).0;
    0x78: MOV32, AluOpc::lsh_32(Source::Imm).0;
    0x80: MOV32, AluOpc::rsh_32(Source::Imm).0;
    // loop counters: r_a += imm, then a branch
    0x88: ADD64_IMM, 0, jmp(JmpOpc::Jlt, Source::Reg);
    0x90: ADD64_IMM, 0, jmp(JmpOpc::Jne, Source::Imm);
    0x98: ADD64_IMM, 0, jmp(JmpOpc::Jgt, Source::Imm);
}

macro_rules! stack_accesses {
    ($($byte:literal: $usual:expr;)*) => {
        /// Loads and stores through r10 by opcode byte, with the opcode they stand for.
        const STACK: &[(u8, u8)] = &[$(($byte, $usual)),*];

        /// Give each r10 access byte its handler.
        const fn install_stack<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = stack::access::<M, H, FUEL, { $usual }>;)*
        }
    };
}

stack_accesses! {
    0xa0: ldx(MemSize::Word);
    0xa8: ldx(MemSize::DWord);
    0xb0: stx(MemSize::Word);
    0xb8: stx(MemSize::DWord);
    0xc0: st(MemSize::Word);
    0xc8: st(MemSize::DWord);
}

// Every byte above is a reserved one and has one use.
const _: () = {
    let mut bytes = [false; 256];
    let mut i = 0;
    while i < SUPERS.len() + STACK.len() {
        let byte = match i < SUPERS.len() {
            true => SUPERS[i].0,
            false => STACK[i - SUPERS.len()].0,
        };
        assert!(is_reserved(byte));
        assert!(!bytes[byte as usize], "two uses of one opcode byte");
        bytes[byte as usize] = true;
        i += 1;
    }
};

/// Give each superinstruction and r10 access byte its handler.
pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
    install_supers::<M, H, FUEL>(table);
    install_stack::<M, H, FUEL>(table);
}

impl Super {
    const fn new(first: u8, alu: u8, tail: &[u8]) -> Self {
        let mut sup = Self {
            first,
            alu,
            tail: [0; 3],
        };
        let mut k = 0;
        while k < tail.len() {
            assert!(tail[k] != 0);
            sup.tail[k] = tail[k];
            k += 1;
        }
        sup
    }

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

    /// Pairs the superinstruction with its opcode `byte`, and fails to compile one that [`fused`] can't run: only the
    /// last instruction may branch, none may call or exit, and none may be LD_IMM64.
    const fn checked(self, byte: u8) -> (u8, Self) {
        assert!(self.len() > 1);
        let mut k = 0;
        while k < self.len() {
            let opc = OpCode(self.opcode(k));
            assert!(!matches!(opc.class(), Class::LdImm));
            if matches!(opc.class(), Class::Jmp32 | Class::Jmp64) {
                assert!(k == self.len() - 1 && k > 0);
                assert!(!matches!(opc.jmp_opc(), JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit));
            }
            k += 1;
        }
        if self.alu != 0 {
            assert!(self.first == MOV64 || self.first == MOV32);
            assert!(OpCode(self.alu).class() as u8 == OpCode(self.first).class() as u8);
        }
        (byte, self)
    }

    /// The number of instructions in the sequence.
    const fn len(self) -> usize {
        let mut tail = 0;
        while tail < self.tail.len() && self.tail[tail] != 0 {
            tail += 1;
        }
        1 + (self.alu != 0) as usize + tail
    }

    /// The opcode of instruction `k` of the sequence.
    const fn opcode(self, k: usize) -> u8 {
        match (k, self.alu != 0) {
            (0, _) => self.first,
            (1, true) => self.alu,
            (_, alu) => self.tail[k - 1 - alu as usize],
        }
    }

    /// The first instruction of the sequence whose first slot holds `slot`.
    #[inline(always)]
    fn first_of(self, slot: Instruction) -> Instruction {
        match self.alu {
            0 => Instruction(slot.0 & !0xFF | u64::from(self.first)),
            _ => Instruction::from_parts(OpCode(self.first), slot.dst_reg(), slot.src_reg(), 0, 0),
        }
    }

    /// The instructions of the sequence, from its first slot `slot` and the code `window` that starts there; entries
    /// past [`Super::len`] are filler.
    #[inline(always)]
    fn decode(self, slot: Instruction, window: &[Instruction]) -> [Instruction; MAX_LEN] {
        let mut insns = [self.first_of(slot); MAX_LEN];
        if self.alu != 0 {
            let (dst, operand) = (slot.dst_reg(), slot.imm());
            let alu = OpCode(self.alu);
            insns[1] = match alu.alu_src() {
                Source::Imm => Instruction::from_parts(alu, dst, 0, 0, operand),
                Source::Reg => Instruction::from_parts(alu, dst, operand as u8, 0, 0),
            };
        }
        let start = 1 + (self.alu != 0) as usize;
        for k in start..self.len() {
            insns[k] = Instruction(window[k].0 & !0xFF | u64::from(self.opcode(k)));
        }
        insns
    }

    /// The first slot of this superinstruction, with opcode byte `byte`, for the sequence at the start of `window`, if
    /// it has one.
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
        k == self.len() - 1 && matches!(OpCode(self.opcode(k)).class(), Class::Jmp32 | Class::Jmp64)
    }
}

/// The handler of superinstruction `S`. It runs the sequence as the handlers of its instructions would, one after
/// another.
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
    let at = pc as usize;
    let window = code.get(at..=at + len);
    let Some(window) = window.filter(|_| !FUEL || fuel >= len as u64 - 1) else {
        // the fuel runs out inside the sequence, or the code ends with it
        let alone = const { Handlers::<M, H, FUEL>::TABLE[Super::of(S).first as usize] };
        become alone(ctx, code, sup.first_of(insn), pc, fuel, calls)
    };

    // one block per instruction, so that each `step` sees a constant opcode
    let [i0, i1, i2, i3, i4] = sup.decode(insn, window);
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
    exec!(3, i3);
    exec!(4, i4);

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
