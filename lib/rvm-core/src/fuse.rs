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
use crate::transfer::{self, FAR, GUARD};
use crate::{handler_of, stack, step, CallStack, Context, Flow, Handler, Handlers, Host, Instruction, Memory};

/// Bytecode prepared for [`run`](crate::run).
#[derive(Debug)]
pub struct Code {
    /// The code, then the slots [`transfer::bound`] appends.
    slots: Box<[Instruction]>,
    len: usize,
}

impl Code {
    /// Prepare `insns` for [`run`](crate::run): fuse the sequences that have a superinstruction.
    ///
    /// r10 is read-only, so an instruction that would write it fails with [`Flow::FailCpu`]: an ALU, ALU64 or LDX
    /// instruction, LD_IMM64 or a load-acquire with `dst_reg` 10, and an atomic that fetches into `src_reg` 10.
    ///
    /// The code keeps the allocation of `insns` if it has room for one more slot.
    ///
    /// # Panics
    ///
    /// Panics if `insns` has 2^31 slots or more.
    pub fn new(insns: impl Into<Vec<Instruction>>) -> Self {
        let mut slots = insns.into();
        let len = slots.len();
        fuse(&mut slots);
        transfer::bound(&mut slots);
        Self {
            slots: slots.into_boxed_slice(),
            len,
        }
    }

    /// The number of instruction slots.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes the load or store in slot `pc` accesses, or `None` if the slot holds none, for reporting a
    /// [`Flow::FailMem`] at `pc`.
    #[cold]
    pub fn access_size(&self, pc: u64) -> Option<usize> {
        let byte = self.slots.get(usize::try_from(pc).ok()?)?.0 as u8;
        // the first slot of a superinstruction or r10 access holds a reserved byte in place of its opcode
        let byte = match (STACK.iter().find(|s| s.0 == byte), SUPERS.iter().find(|s| s.0 == byte)) {
            (Some(&(_, usual)), _) => usual,
            (None, Some(&(_, sup))) => sup.ops[0],
            (None, None) => byte,
        };
        let opc = OpCode(byte);
        if !matches!(opc.class(), Class::LdReg | Class::StReg | Class::StImm) {
            return None;
        }
        Some(match opc.mem_size() {
            MemSize::Byte => 1,
            MemSize::Half => 2,
            MemSize::Word => 4,
            MemSize::DWord => 8,
        })
    }

    /// The code and the slots after it, which all hold [`GUARD`].
    pub(crate) fn slots(&self) -> &[Instruction] {
        &self.slots
    }
}

/// Give r10 writes and the bytes rvm doesn't run their failing bytes, and the sequences with a superinstruction and r10
/// accesses theirs.
fn fuse(code: &mut [Instruction]) {
    // Only the opcode byte changes, so the second slot of LD_IMM64 keeps its `imm`.
    for insn in code.iter_mut() {
        let writes = WRITES[insn.0 as u8 as usize];
        // `&` and `|` don't branch, so only the rare rewrite and atomics do
        let r10 = (writes.dst & (insn.dst_reg() == 10)) | (writes.atomic && atomic_writes_r10(*insn));
        if writes.reserved | r10 {
            let byte = if writes.reserved { MISSING } else { INVALID };
            insn.0 = insn.0 & !0xFF | u64::from(byte);
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
        let found = candidates(window)
            .iter()
            .find_map(|&(byte, sup)| sup.encode(byte, window));
        debug_assert_eq!(found, SUPERS.iter().find_map(|&(byte, sup)| sup.encode(byte, window)));
        if let Some(slot) = found {
            code[i] = slot;
        } else if let Some(byte) = stack_byte(code[i]) {
            code[i].0 = code[i].0 & !0xFF | u64::from(byte);
        }
    }
}

/// What an instruction with a given opcode byte may write that the first pass of [`fuse`] rewrites.
#[derive(Clone, Copy)]
struct Writes {
    /// The byte [`is_reserved`].
    reserved: bool,
    /// `dst_reg`.
    dst: bool,
    /// The byte is an atomic's: [`atomic_writes_r10`] decides.
    atomic: bool,
}

/// The [`Writes`] of each opcode byte.
const WRITES: [Writes; 256] = {
    let mut table = [Writes {
        reserved: false,
        dst: false,
        atomic: false,
    }; 256];
    let mut byte = 0;
    while byte < 256 {
        let opc = OpCode(byte as u8);
        let writes = &mut table[byte];
        match opc.class() {
            _ if is_reserved(opc.0) => writes.reserved = true,
            Class::Alu32 | Class::Alu64 | Class::LdReg => writes.dst = true,
            Class::LdImm => writes.dst = opc.0 == LD_IMM64,
            Class::StReg => writes.atomic = matches!(opc.mem_mode(), MemMode::Atomic),
            Class::StImm | Class::Jmp32 | Class::Jmp64 => {}
        }
        byte += 1;
    }
    table
};

/// Whether the atomic `insn` writes r10.
fn atomic_writes_r10(insn: Instruction) -> bool {
    const FETCH: i32 = 0x01;
    const CMPXCHG: i32 = 0xf0 | FETCH;
    const LOAD_ACQ: i32 = 0x100;

    match insn.imm() {
        LOAD_ACQ => insn.dst_reg() == 10,
        // CMPXCHG fetches into r0
        imm => insn.src_reg() == 10 && imm & FETCH != 0 && imm != CMPXCHG,
    }
}

/// The opcode byte of the r10 access `insn`, if it is a load or store with one.
fn stack_byte(insn: Instruction) -> Option<u8> {
    let byte = STACK_BYTES[insn.0 as u8 as usize]?;
    let base = match insn.opcode().class() {
        Class::LdReg => insn.src_reg(),
        _ => insn.dst_reg(),
    };
    (base == 10).then_some(byte)
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
pub struct Super {
    /// The opcode of each instruction, then zeros.
    ops: [u8; MAX_LEN],
    len: u8,
    /// Whether the second instruction is an ALU instruction on the destination of the first, a register `mov`, whose
    /// slot also holds the source operand of the ALU instruction in its `imm` field. Each other instruction the
    /// superinstruction reads from its own slot.
    alu: bool,
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

// Every byte above and those of `transfer` is a reserved one and has one use.
const _: () = {
    let mut bytes = [false; 256];
    let mut i = 0;
    while i < SUPERS.len() + STACK.len() + 2 {
        let byte = match i {
            _ if i < SUPERS.len() => SUPERS[i].0,
            _ if i < SUPERS.len() + STACK.len() => STACK[i - SUPERS.len()].0,
            _ if i == SUPERS.len() + STACK.len() => GUARD,
            _ => FAR,
        };
        assert!(is_reserved(byte));
        assert!(!bytes[byte as usize], "two uses of one opcode byte");
        bytes[byte as usize] = true;
        i += 1;
    }
};

/// For each opcode byte, the byte of the r10 access with that opcode, if there is one.
const STACK_BYTES: [Option<u8>; 256] = {
    let mut table = [None; 256];
    let mut i = 0;
    while i < STACK.len() {
        table[STACK[i].1 as usize] = Some(STACK[i].0);
        i += 1;
    }
    table
};

/// [`SUPERS`] grouped by their first two opcodes, each group in [`SUPERS`] order, so that the first match is the same.
const BY_PAIR: [(u8, Super); SUPERS.len()] = {
    const fn pair(sup: Super) -> u16 {
        (sup.ops[0] as u16) << 8 | sup.ops[1] as u16
    }

    // a stable insertion sort
    let mut sorted = [SUPERS[0]; SUPERS.len()];
    let mut i = 0;
    while i < SUPERS.len() {
        let mut j = i;
        while j > 0 && pair(sorted[j - 1].1) > pair(SUPERS[i].1) {
            sorted[j] = sorted[j - 1];
            j -= 1;
        }
        sorted[j] = SUPERS[i];
        i += 1;
    }
    sorted
};

/// The number of opcodes that start a superinstruction.
const FIRSTS: usize = {
    let mut n = 1;
    let mut i = 1;
    while i < BY_PAIR.len() {
        n += (BY_PAIR[i].1.ops[0] != BY_PAIR[i - 1].1.ops[0]) as usize;
        i += 1;
    }
    n
};

/// For each opcode byte, the row of [`GROUPS`] for the superinstructions that start with it: 0 if none does.
const ROWS: [u8; 256] = {
    let mut rows = [0; 256];
    let mut row = 0;
    let mut i = 0;
    while i < BY_PAIR.len() {
        let first = BY_PAIR[i].1.ops[0] as usize;
        if rows[first] == 0 {
            row += 1;
            rows[first] = row;
        }
        i += 1;
    }
    rows
};

/// For each row of [`ROWS`] and second opcode byte, the range of [`BY_PAIR`] whose superinstructions start with
/// those two opcodes. Row 0 is empty.
const GROUPS: [[(u8, u8); 256]; 1 + FIRSTS] = {
    let mut groups = [[(0, 0); 256]; 1 + FIRSTS];
    let mut i = 0;
    while i < BY_PAIR.len() {
        let sup = BY_PAIR[i].1;
        let group = &mut groups[ROWS[sup.ops[0] as usize] as usize][sup.ops[1] as usize];
        if group.1 == 0 {
            group.0 = i as u8;
        }
        group.1 += 1;
        i += 1;
    }
    groups
};

/// The superinstructions that start with the first two opcodes of `window`, in the order [`Code::new`] tries them.
fn candidates(window: &[Instruction]) -> &'static [(u8, Super)] {
    let [first, second, ..] = window else {
        return &[];
    };
    let row = ROWS[first.0 as u8 as usize];
    // most slots start none
    if row == 0 {
        return &[];
    }
    let (start, len) = GROUPS[row as usize][second.0 as u8 as usize];
    &BY_PAIR[start as usize..][..len as usize]
}

/// Give each superinstruction and r10 access byte its handler.
pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
    install_supers::<M, H, FUEL>(table);
    install_stack::<M, H, FUEL>(table);
}

impl Super {
    const fn new(first: u8, alu: u8, tail: &[u8]) -> Self {
        let mut sup = Self {
            ops: [0; MAX_LEN],
            len: 1,
            alu: alu != 0,
        };
        sup.ops[0] = first;
        if sup.alu {
            sup.ops[1] = alu;
            sup.len += 1;
        }
        let mut k = 0;
        while k < tail.len() {
            assert!(tail[k] != 0);
            sup.ops[sup.len as usize] = tail[k];
            sup.len += 1;
            k += 1;
        }
        sup
    }

    /// The superinstruction with opcode byte `byte`, if there is one.
    pub fn with_byte(byte: u8) -> Option<Self> {
        const BY_BYTE: [Option<Super>; 256] = {
            let mut table = [None; 256];
            let mut i = 0;
            while i < SUPERS.len() {
                table[SUPERS[i].0 as usize] = Some(SUPERS[i].1);
                i += 1;
            }
            table
        };
        BY_BYTE[byte as usize]
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
            let opc = OpCode(self.ops[k]);
            assert!(!matches!(opc.class(), Class::LdImm));
            if matches!(opc.class(), Class::Jmp32 | Class::Jmp64) {
                assert!(k == self.len() - 1 && k > 0);
                assert!(!matches!(opc.jmp_opc(), JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit));
            }
            k += 1;
        }
        if self.alu {
            assert!(self.ops[0] == MOV64 || self.ops[0] == MOV32);
            assert!(OpCode(self.ops[1]).class() as u8 == OpCode(self.ops[0]).class() as u8);
        }
        (byte, self)
    }

    /// The number of instructions in the sequence.
    #[inline(always)]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// The first instruction of the sequence whose first slot holds `slot`.
    #[inline(always)]
    pub fn first_of(self, slot: Instruction) -> Instruction {
        match self.alu {
            false => Instruction(slot.0 & !0xFF | u64::from(self.ops[0])),
            true => Instruction::from_parts(OpCode(self.ops[0]), slot.dst_reg(), slot.src_reg(), 0, 0),
        }
    }

    /// The instructions of the sequence, from its first slot `slot` and the code `window` that starts there; entries
    /// past [`Super::len`] are filler.
    #[inline(always)]
    fn decode(self, slot: Instruction, window: &[Instruction]) -> [Instruction; MAX_LEN] {
        let mut insns = [self.first_of(slot); MAX_LEN];
        if self.alu {
            let (dst, operand) = (slot.dst_reg(), slot.imm());
            let alu = OpCode(self.ops[1]);
            insns[1] = match alu.alu_src() {
                Source::Imm => Instruction::from_parts(alu, dst, 0, 0, operand),
                Source::Reg => Instruction::from_parts(alu, dst, operand as u8, 0, 0),
            };
        }
        let start = 1 + self.alu as usize;
        for k in start..self.len() {
            insns[k] = Instruction(window[k].0 & !0xFF | u64::from(self.ops[k]));
        }
        insns
    }

    /// The first slot of this superinstruction, with opcode byte `byte`, for the sequence at the start of `window`, if
    /// it has one.
    #[inline(always)]
    fn encode(self, byte: u8, window: &[Instruction]) -> Option<Instruction> {
        let sequence = window.get(..self.len())?;
        // `candidates` matched the first two opcodes, and the candidates that share those mostly differ in the last
        if sequence[self.len() - 1].0 as u8 != self.ops[self.len() - 1] {
            return None;
        }
        let first = sequence[0];
        let slot = match self.alu {
            false => Instruction(first.0 & !0xFF | u64::from(byte)),
            true => {
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
    #[inline(always)]
    const fn branches_at(self, k: usize) -> bool {
        k == self.len() - 1 && matches!(OpCode(self.ops[k]).class(), Class::Jmp32 | Class::Jmp64)
    }

    /// Whether the last instruction of the sequence may branch.
    #[inline(always)]
    pub const fn branches(self) -> bool {
        self.branches_at(self.len() - 1)
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

    // the fuel runs out inside the sequence
    if FUEL && fuel < len as u64 - 1 {
        let alone = const { Handlers::<M, H, FUEL>::TABLE[Super::of(S).ops[0] as usize] };
        become alone(ctx, code, sup.first_of(insn), pc, fuel, calls)
    }
    // SAFETY: `transfer::bound` leaves a superinstruction only where its sequence lies in the code, and the guard slot
    // follows the code
    let window = unsafe { code.get_unchecked(pc as usize..=pc as usize + len) };

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
    let insn = match target {
        None => window[len],
        // SAFETY: `transfer::bound` leaves a superinstruction only where its branch target lies in `0..=len`
        Some(target) => unsafe { *code.get_unchecked(target as usize) },
    };
    become handler_of::<M, H, FUEL>(insn)(ctx, code, insn, pc, fuel - u64::from(FUEL), calls)
}
