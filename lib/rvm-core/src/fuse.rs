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

use crate::opcode::atomic::{CMPXCHG, FETCH, LOAD_ACQ};
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, LD_IMM64};
use crate::ops::Regs;
use crate::transfer::{self, Slot, FAR, GUARD};
use crate::{charge, stack, step, CallStack, Context, Flow, Handler, Handlers, Host, Instruction, Memory, Table};

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
        let byte = self.slots.get(usize::try_from(pc).ok()?)?.byte();
        // the first slot of a superinstruction or r10 access holds a reserved byte in place of its opcode
        let byte = match (STACK.iter().find(|s| s.0 == byte), Super::with_byte(byte)) {
            (Some(&(_, usual)), _) => usual,
            (None, Some(sup)) => sup.op(0),
            (None, None) => byte,
        };
        let opc = OpCode(byte);
        if !matches!(opc.class(), Class::LdReg | Class::StReg | Class::StImm) {
            return None;
        }
        Some(opc.mem_size().bytes())
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
        let writes = WRITES[usize::from(insn.byte())];
        // `&` and `|` don't branch, so only the rare rewrite and atomics do
        let r10 = (writes.dst & (insn.dst_reg() == 10)) | (writes.atomic && atomic_writes_r10(*insn));
        if writes.reserved | r10 {
            let byte = if writes.reserved { MISSING } else { INVALID };
            *insn = insn.with_opcode(byte);
        }
    }

    // A superinstruction or r10 access changes only the opcode byte of its first slot. So the code from slot `i` on is
    // still as loaded but for opcode bytes, and a handler, which reads the other fields of its sequence's slots, later
    // reads the fields `encode` checked.
    for i in 0..code.len() {
        // the slot after LD_IMM64 holds the upper half of its immediate
        if i > 0 && code[i - 1].byte() == LD_IMM64 {
            continue;
        }
        let window = &code[i..];
        let found = candidates(window).iter().find_map(|&(_, _, encode)| encode(window));
        debug_assert_eq!(found, SUPERS.iter().find_map(|&(_, _, encode)| encode(window)));
        if let Some(slot) = found {
            code[i] = slot;
        } else if let Some(byte) = stack_byte(code[i]) {
            code[i] = code[i].with_opcode(byte);
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
    const NONE: Writes = Writes {
        reserved: false,
        dst: false,
        atomic: false,
    };

    byte_table!(|byte| {
        let opc = OpCode(byte);
        match opc.class() {
            _ if is_reserved(byte) => Writes { reserved: true, ..NONE },
            Class::Alu32 | Class::Alu64 | Class::LdReg => Writes { dst: true, ..NONE },
            Class::LdImm => Writes {
                dst: byte == LD_IMM64,
                ..NONE
            },
            Class::StReg => Writes {
                atomic: matches!(opc.mem_mode(), MemMode::Atomic),
                ..NONE
            },
            Class::StImm | Class::Jmp32 | Class::Jmp64 => NONE,
        }
    })
};

/// Whether the atomic `insn` writes r10.
fn atomic_writes_r10(insn: Instruction) -> bool {
    match insn.imm() {
        LOAD_ACQ => insn.dst_reg() == 10,
        // CMPXCHG fetches into r0
        imm => insn.src_reg() == 10 && imm & FETCH != 0 && imm != CMPXCHG,
    }
}

/// The opcode byte of the r10 access `insn`, if it is a load or store with one.
fn stack_byte(insn: Instruction) -> Option<u8> {
    let byte = STACK_BYTES[usize::from(insn.byte())]?;
    let base = match insn.opcode().class() {
        Class::LdReg => insn.src_reg(),
        _ => insn.dst_reg(),
    };
    (base == 10).then_some(byte)
}

const fn ldx(size: MemSize) -> u8 {
    OpCode::ldreg_from_parts(size, MemMode::Mem).0
}

const fn stx(size: MemSize) -> u8 {
    OpCode::streg_from_parts(size, MemMode::Mem).0
}

const fn st(size: MemSize) -> u8 {
    OpCode::stimm_from_parts(size, MemMode::Mem).0
}

/// Every opcode byte of the LD class but LD_IMM64, the legacy packet loads among them, runs as the same unsupported
/// instruction ([`Flow::Missing`]). [`Code::new`] rewrites them all to this one, which frees the others for
/// superinstructions and r10 accesses.
const MISSING: u8 = Class::LdImm as u8;

/// An undefined ALU64 operation, which always fails with [`Flow::FailCpu`]; the byte of every instruction that would
/// write r10.
const INVALID: u8 = OpCode::alu64_from_parts(AluOpc::UndefE, Source::Imm).0;

const fn is_reserved(byte: u8) -> bool {
    byte & 0b111 == Class::LdImm as u8 && byte != LD_IMM64 && byte != MISSING
}

/// A superinstruction: the sequence it runs, over registers that the table names by role, and what [`fused`] and
/// [`Code::new`] derive from it.
#[derive(Clone, Copy)]
pub struct Super {
    steps: [Step; MAX_LEN],
    len: u8,

    roles: u8,
    /// For each role, the position of the operand that names it first and the shift of that operand's register field,
    /// where the code gives the role its register.
    homes: [(u8, u8); MAX_ROLES],
    /// The roles the sequence reads before it writes them, one bit each.
    loads: u8,
    /// The roles the sequence writes, one bit each.
    writes: u8,
    /// The position the written roles go back to their registers before: the one after the last instruction that
    /// writes a role.
    save_at: u8,
    /// For each position, the roles written before it that aren't back in their registers yet.
    unsaved: [u8; MAX_LEN],
    /// The position and register field shift of the register operand `_`, if the sequence has one.
    free: Option<(u8, u8)>,
}

/// The most instructions a superinstruction runs.
const MAX_LEN: usize = 5;

/// The most roles a superinstruction has.
const MAX_ROLES: usize = 3;

macro_rules! superinstructions {
    ($($byte:literal: $($op:ident $($operand:tt),*);+;)*) => {
        /// Superinstructions by opcode byte, with their [`Encode`]; [`Code::new`] tries them in this order.
        const SUPERS: &[(u8, Super, Encode)] =
            &[$(($byte, Super::new(&[$((stringify!($op), &[$(operand!($operand)),*])),+]), encode_as::<$byte>)),*];

        /// Give each superinstruction byte its handler.
        const fn install_supers<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = fused::<M, H, FUEL, $byte>;)*
        }
    };
}

/// An [`Operand`] as [`superinstructions!`] writes it.
macro_rules! operand {
    (_) => {
        Operand::Any
    };
    ([$base:ident + _]) => {
        Operand::Mem(stringify!($base), true)
    };
    ([$base:ident]) => {
        Operand::Mem(stringify!($base), false)
    };
    ($role:ident) => {
        Operand::Role(stringify!($role))
    };
}

// Each line gives the opcode byte of a superinstruction and its sequence in eBPF assembler syntax, with roles in place of
// registers. A sequence fuses where each role stands for one register throughout and different roles for different
// registers. `_` stands for whatever its slot holds: an immediate, an offset, a jump target, or a register that no role
// names, which only the last instruction may have. Every field a line doesn't mention is zero. Longer sequences come
// first, so that they win over their prefixes.
superinstructions! {
    // rotate: t = x >> k | x << (32 - k), into x or y
    0xd0: mov32 t, x; rsh32 t, _; lsh32 x, _; mov32 y, x; or32 y, t;
    0xd8: mov32 t, x; rsh32 t, _; lsh32 x, _; or32 x, t;
    // a = b + c, then a load, store or branch through a
    0x08: mov64 a, b; add64 a, c; ldxb _, [a + _];
    0x10: mov64 a, b; add64 a, c; ldxw _, [a + _];
    0x20: mov64 a, b; add64 a, c; stb [a + _], _;
    0x28: mov64 a, b; add64 a, c; jlt a, _, _;
    // three-address ALU: a = b op c
    0x30: mov64 a, b; add64 a, c;
    0x38: mov64 a, b; add64 a, _;
    0x40: mov64 a, b; mul64 a, c;
    0x48: mov64 a, b; xor64 a, c;
    0x50: mov64 a, b; lsh64 a, _;
    0x58: mov64 a, b; rsh64 a, _;
    0x60: mov32 a, b; and32 a, _;
    0x68: mov32 a, b; and32 a, c;
    0x70: mov32 a, b; or32 a, c;
    0x78: mov32 a, b; lsh32 a, _;
    0x80: mov32 a, b; rsh32 a, _;
    // loop counters: a += imm, then a branch on a
    0x88: add64 a, _; jlt a, c, _;
    0x90: add64 a, _; jne a, _, _;
    0x98: add64 a, _; jgt a, _, _;
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
    const fn claim(used: &mut [bool; 256], byte: u8) {
        assert!(is_reserved(byte));
        assert!(!used[byte as usize], "two uses of one opcode byte");
        used[byte as usize] = true;
    }

    let mut used = [false; 256];
    const_for!(i in 0..SUPERS.len() => {
        claim(&mut used, SUPERS[i].0);
    });
    const_for!(i in 0..STACK.len() => {
        claim(&mut used, STACK[i].0);
    });
    claim(&mut used, GUARD);
    claim(&mut used, FAR);
};

/// For each opcode byte, the index in [`SUPERS`] of its superinstruction: `u8::MAX` if it has none.
const BY_BYTE: [u8; 256] = {
    let mut table = [u8::MAX; 256];
    const_for!(i in 0..SUPERS.len() => {
        table[SUPERS[i].0 as usize] = i as u8;
    });
    table
};

/// For each opcode byte, the byte of the r10 access with that opcode, if there is one.
const STACK_BYTES: [Option<u8>; 256] = {
    let mut table = [None; 256];
    const_for!(i in 0..STACK.len() => {
        table[STACK[i].1 as usize] = Some(STACK[i].0);
    });
    table
};

/// [`SUPERS`] grouped by their first two opcodes, each group in [`SUPERS`] order, so that the first match is the same.
const BY_PAIR: [(u8, Super, Encode); SUPERS.len()] = {
    const fn pair(sup: Super) -> u16 {
        (sup.op(0) as u16) << 8 | sup.op(1) as u16
    }

    // a stable insertion sort
    let mut sorted = [SUPERS[0]; SUPERS.len()];
    const_for!(i in 0..SUPERS.len() => {
        let mut j = i;
        while j > 0 && pair(sorted[j - 1].1) > pair(SUPERS[i].1) {
            sorted[j] = sorted[j - 1];
            j -= 1;
        }
        sorted[j] = SUPERS[i];
    });
    sorted
};

/// The number of opcodes that start a superinstruction.
const FIRSTS: usize = {
    let mut n = 1;
    const_for!(i in 1..BY_PAIR.len() => {
        n += (BY_PAIR[i].1.op(0) != BY_PAIR[i - 1].1.op(0)) as usize;
    });
    n
};

/// For each opcode byte, the row of [`GROUPS`] for the superinstructions that start with it: 0 if none does.
const ROWS: [u8; 256] = {
    let mut rows = [0; 256];
    let mut row = 0;
    const_for!(i in 0..BY_PAIR.len() => {
        let first = BY_PAIR[i].1.op(0) as usize;
        if rows[first] == 0 {
            row += 1;
            rows[first] = row;
        }
    });
    rows
};

/// For each row of [`ROWS`] and second opcode byte, the range of [`BY_PAIR`] whose superinstructions start with
/// those two opcodes. Row 0 is empty.
const GROUPS: [[(u8, u8); 256]; 1 + FIRSTS] = {
    let mut groups = [[(0, 0); 256]; 1 + FIRSTS];
    const_for!(i in 0..BY_PAIR.len() => {
        let sup = BY_PAIR[i].1;
        let group = &mut groups[ROWS[sup.op(0) as usize] as usize][sup.op(1) as usize];
        if group.1 == 0 {
            group.0 = i as u8;
        }
        group.1 += 1;
    });
    groups
};

/// The superinstructions that start with the first two opcodes of `window`, in the order [`Code::new`] tries them.
fn candidates(window: &[Instruction]) -> &'static [(u8, Super, Encode)] {
    let [first, second, ..] = window else {
        return &[];
    };
    let row = ROWS[usize::from(first.byte())];
    // most slots start none
    if row == 0 {
        return &[];
    }
    let (start, len) = GROUPS[row as usize][usize::from(second.byte())];
    &BY_PAIR[start as usize..][..len as usize]
}

/// Give each superinstruction and r10 access byte its handler.
pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
    install_supers::<M, H, FUEL>(table);
    install_stack::<M, H, FUEL>(table);
}

impl Super {
    /// The superinstruction that runs `insns`, each a mnemonic and its operands, and fails to compile one that
    /// [`fused`] can't run.
    const fn new(insns: &[(&'static str, &[Operand])]) -> Self {
        let len = insns.len();
        assert!(1 < len && len <= MAX_LEN);

        let mut names = Names {
            names: [""; MAX_ROLES],
            len: 0,
        };
        let mut steps = [Step::NONE; MAX_LEN];
        const_for!(k in 0..len => {
            steps[k] = Step::parse(insns[k].0, insns[k].1, &mut names);
            // only the last instruction may branch, and it continues at `pc + 1` or a fixed target
            if matches!(OpCode(steps[k].op).class(), Class::Jmp32 | Class::Jmp64) {
                assert!(k == len - 1, "a branch before the end of a sequence");
            }
        });

        let mut sup = Self {
            steps,
            len: len as u8,
            roles: names.len,
            homes: [(0, 0); MAX_ROLES],
            loads: 0,
            writes: 0,
            save_at: 0,
            unsaved: [0; MAX_LEN],
            free: None,
        };
        const_for!(role in 0..names.len => {
            sup.homes[role as usize] = sup.home(role);
        });

        const_for!(k in 0..len => {
            const_for!(role in 0..names.len => {
                if steps[k].reads(Field::Role(role)) && sup.writes & 1 << role == 0 {
                    sup.loads |= 1 << role;
                }
            });
            sup.unsaved[k] = sup.writes;
            if let Field::Role(role) = steps[k].written() {
                sup.writes |= 1 << role;
                sup.save_at = k as u8 + 1;
            }
        });
        // the written roles are back in their registers from `save_at` on
        const_for!(k in sup.save_at as usize..len => {
            sup.unsaved[k] = 0;
        });

        const_for!(k in 0..len => {
            let free = match (steps[k].dst, steps[k].src) {
                (Field::Any, _) => Some((k as u8, DST)),
                (_, Field::Any) => Some((k as u8, SRC)),
                _ => None,
            };
            if free.is_some() {
                assert!(sup.free.is_none(), "two register operands `_`");
                sup.free = free;
            }
        });
        // `Roles` gives the register `_` its value in the registers, so it may share a register with a role only where
        // the roles are back there for good
        if let Some((k, _)) = sup.free {
            assert!(k as usize == len - 1 && k >= sup.save_at, "a register `_` before the end of a sequence");
        }
        sup
    }

    /// The position of the operand that names `role` first, and the shift of its register field.
    const fn home(self, role: u8) -> (u8, u8) {
        const_for!(k in 0..self.len() => {
            let step = self.steps[k];
            if step.dst.is(role) {
                return (k as u8, DST);
            }
            if step.src.is(role) {
                return (k as u8, SRC);
            }
        });
        unreachable!()
    }

    /// The superinstruction with opcode byte `byte`, if there is one.
    pub fn with_byte(byte: u8) -> Option<&'static Self> {
        let index = BY_BYTE[usize::from(byte)];
        SUPERS.get(usize::from(index)).map(|(_, sup, _)| sup)
    }

    /// The superinstruction with opcode byte `byte`.
    const fn of(byte: u8) -> Self {
        let index = BY_BYTE[byte as usize] as usize;
        assert!(index < SUPERS.len(), "not a superinstruction");
        SUPERS[index].1
    }

    /// The number of instructions in the sequence.
    #[inline(always)]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// The opcode of instruction `k` of the sequence.
    #[inline(always)]
    const fn op(self, k: usize) -> u8 {
        self.steps[k].op
    }

    /// The first instruction of the sequence whose first slot holds `slot`.
    #[inline(always)]
    pub fn first_of(self, slot: Instruction) -> Instruction {
        slot.with_opcode(self.op(0))
    }

    /// The register of each role, from `slot(k)`, the slot of instruction `k` of the sequence.
    #[inline(always)]
    fn registers(self, slot: impl Fn(usize) -> Instruction) -> [u8; MAX_ROLES] {
        let mut registers = [0; MAX_ROLES];
        for role in 0..self.roles as usize {
            let (k, shift) = self.homes[role];
            registers[role] = field(slot(k as usize), shift);
        }
        registers
    }

    /// Instruction `k` of the sequence, from its slot `slot`: the register of each role from `roles`, and the register
    /// operand `_` from `free`, else from `slot`.
    #[inline(always)]
    fn decode(self, k: usize, slot: Instruction, roles: [u8; MAX_ROLES], free: Option<u8>) -> Instruction {
        let step = self.steps[k];
        let dst = step.dst.register(roles, free, slot.dst_reg());
        let src = step.src.register(roles, free, slot.src_reg());
        let off = if let Field::Any = step.off { slot.offset() } else { 0 };
        let imm = if let Field::Any = step.imm { slot.imm() } else { 0 };
        Instruction::from_parts(OpCode(step.op), dst, src, off, imm)
    }

    /// The first slot of this superinstruction, with opcode byte `byte`, for the sequence at the start of `window`, if
    /// it has one.
    #[inline(always)]
    fn encode(self, byte: u8, window: &[Instruction]) -> Option<Instruction> {
        let sequence = window.get(..self.len())?;
        // `candidates` matched the first two opcodes, and the candidates that share those mostly differ in the last
        if sequence[self.len() - 1].byte() != self.op(self.len() - 1) {
            return None;
        }
        let registers = self.registers(|k| sequence[k]);
        // `fused` keeps each role in a variable of its own
        for role in 1..self.roles as usize {
            if registers[..role].contains(&registers[role]) {
                return None;
            }
        }
        for (k, &insn) in sequence.iter().enumerate() {
            if self.decode(k, insn, registers, None) != insn {
                return None;
            }
        }
        Some(sequence[0].with_opcode(byte))
    }

    /// Whether instruction `k` of the sequence may branch.
    #[inline(always)]
    const fn branches_at(self, k: usize) -> bool {
        k == self.len() - 1 && matches!(OpCode(self.op(k)).class(), Class::Jmp32 | Class::Jmp64)
    }

    /// Whether the last instruction of the sequence may branch.
    #[inline(always)]
    pub const fn branches(self) -> bool {
        self.branches_at(self.len() - 1)
    }
}

/// [`Super::encode`] of one superinstruction.
type Encode = fn(&[Instruction]) -> Option<Instruction>;

/// [`Super::encode`] of the superinstruction with opcode byte `S`, compiled with its sequence constant.
fn encode_as<const S: u8>(window: &[Instruction]) -> Option<Instruction> {
    const { Super::of(S) }.encode(S, window)
}

/// The shifts of the `dst_reg` and `src_reg` fields in an instruction.
const DST: u8 = 8;
const SRC: u8 = 12;

/// The register field at `shift` of `insn`.
#[inline(always)]
const fn field(insn: Instruction, shift: u8) -> u8 {
    (insn.0 >> shift) as u8 & 0xF
}

/// An instruction of a superinstruction's sequence.
#[derive(Clone, Copy)]
struct Step {
    op: u8,
    dst: Field,
    src: Field,
    off: Field,
    imm: Field,
}

/// Where the value of an instruction field comes from.
#[derive(Clone, Copy)]
enum Field {
    Zero,
    /// The register of a role.
    Role(u8),
    /// The slot: `_`.
    Any,
}

impl Field {
    const fn is(self, role: u8) -> bool {
        matches!(self, Field::Role(r) if r == role)
    }

    /// The register of a register field: from `roles` for a role, else `free`, else the slot's `own`.
    #[inline(always)]
    fn register(self, roles: [u8; MAX_ROLES], free: Option<u8>, own: u8) -> u8 {
        match self {
            Field::Zero => 0,
            Field::Role(role) => roles[role as usize],
            Field::Any => free.unwrap_or(own),
        }
    }
}

/// An operand as the table writes it.
#[derive(Clone, Copy)]
enum Operand {
    /// A role, by name.
    Role(&'static str),
    /// `_`.
    Any,
    /// `[base + _]` or `[base]`: the role of the base, and whether the offset is `_`.
    Mem(&'static str, bool),
}

/// The roles a sequence names, in the order it names them first.
struct Names {
    names: [&'static str; MAX_ROLES],
    len: u8,
}

impl Names {
    /// The field of the role `name`.
    const fn role(&mut self, name: &'static str) -> Field {
        const_for!(role in 0..self.len => {
            if eq(self.names[role as usize].as_bytes(), name.as_bytes()) {
                return Field::Role(role);
            }
        });
        assert!((self.len as usize) < MAX_ROLES, "too many roles");
        let role = self.len;
        self.names[role as usize] = name;
        self.len += 1;
        Field::Role(role)
    }

    /// The field of the register operand `operand`.
    const fn register(&mut self, operand: Operand) -> Field {
        match operand {
            Operand::Role(name) => self.role(name),
            Operand::Any => Field::Any,
            Operand::Mem(..) => panic!("a memory operand in place of a register"),
        }
    }
}

impl Step {
    const NONE: Self = Self {
        op: 0,
        dst: Field::Zero,
        src: Field::Zero,
        off: Field::Zero,
        imm: Field::Zero,
    };

    /// The instruction `mnemonic operands`, whose roles `names` numbers.
    const fn parse(mnemonic: &str, operands: &[Operand], names: &mut Names) -> Self {
        const ALU: [(&str, AluOpc); 12] = [
            ("add", AluOpc::Add),
            ("sub", AluOpc::Sub),
            ("mul", AluOpc::Mul),
            ("div", AluOpc::Div),
            ("or", AluOpc::Or),
            ("and", AluOpc::And),
            ("lsh", AluOpc::Lsh),
            ("rsh", AluOpc::Rsh),
            ("mod", AluOpc::Mod),
            ("xor", AluOpc::Xor),
            ("mov", AluOpc::Mov),
            ("arsh", AluOpc::Arsh),
        ];
        const JMP: [(&str, JmpOpc); 11] = [
            ("jeq", JmpOpc::Jeq),
            ("jgt", JmpOpc::Jgt),
            ("jge", JmpOpc::Jge),
            ("jset", JmpOpc::Jset),
            ("jne", JmpOpc::Jne),
            ("jsgt", JmpOpc::Jsgt),
            ("jsge", JmpOpc::Jsge),
            ("jlt", JmpOpc::Jlt),
            ("jle", JmpOpc::Jle),
            ("jslt", JmpOpc::Jslt),
            ("jsle", JmpOpc::Jsle),
        ];
        const SIZES: [(&str, MemSize); 4] = [
            ("b", MemSize::Byte),
            ("h", MemSize::Half),
            ("w", MemSize::Word),
            ("dw", MemSize::DWord),
        ];
        let mut step = Self::NONE;
        let name = mnemonic.as_bytes();

        // loads and stores: `ldx dst, [base]`, `st [base], imm`, `stx [base], src`
        let (load, rest) = match (strip(name, b"ldx"), strip(name, b"stx"), strip(name, b"st")) {
            (Some(size), ..) => (true, Some(size)),
            (None, Some(size), _) | (None, None, Some(size)) => (false, Some(size)),
            _ => (false, None),
        };
        if let Some(size) = rest {
            let Some(size) = find(&SIZES, size) else {
                panic!("unknown access size")
            };
            let (register, memory) = match (load, operands) {
                (true, &[register, memory]) => (register, memory),
                (false, &[memory, register]) => (register, memory),
                _ => panic!("a load or store takes a register or immediate and a memory operand"),
            };
            let Operand::Mem(base, offset) = memory else {
                panic!("a load or store without a memory operand")
            };
            let opc = match (load, register) {
                (true, _) => OpCode::ldreg_from_parts(size, MemMode::Mem),
                (false, Operand::Any) => OpCode::stimm_from_parts(size, MemMode::Mem),
                (false, _) => OpCode::streg_from_parts(size, MemMode::Mem),
            };
            step.op = opc.0;
            if offset {
                step.off = Field::Any;
            }
            match opc.class() {
                Class::LdReg => {
                    step.dst = names.register(register);
                    step.src = names.role(base);
                }
                Class::StImm => {
                    step.dst = names.role(base);
                    step.imm = Field::Any;
                }
                _ => {
                    step.dst = names.role(base);
                    step.src = names.register(register);
                }
            }
            return step;
        }

        // ALU instructions and conditional jumps: `op dst, src` and `jcc dst, src, target`, where `src` is `_` for an
        // immediate. ALU mnemonics end in 32 or 64, and jumps in 32 for JMP32.
        let (name, width) = match name {
            [name @ .., b'3', b'2'] => (name, Some(32)),
            [name @ .., b'6', b'4'] => (name, Some(64)),
            name => (name, None),
        };
        let (dst, src, target) = match *operands {
            [dst, src] => (dst, src, None),
            [dst, src, target] => (dst, src, Some(target)),
            _ => panic!("an ALU instruction or jump takes two operands and a target"),
        };
        step.dst = names.register(dst);
        let source = match src {
            Operand::Any => {
                step.imm = Field::Any;
                Source::Imm
            }
            _ => {
                step.src = names.register(src);
                Source::Reg
            }
        };
        step.op = match (find(&ALU, name), find(&JMP, name), width, target) {
            (Some(alu), None, Some(32), None) => OpCode::alu32_from_parts(alu, source).0,
            (Some(alu), None, Some(64), None) => OpCode::alu64_from_parts(alu, source).0,
            (None, Some(jmp), Some(32), Some(Operand::Any)) => OpCode::jmp32_from_parts(jmp, source).0,
            (None, Some(jmp), None | Some(64), Some(Operand::Any)) => OpCode::jmp64_from_parts(jmp, source).0,
            _ => panic!("unknown mnemonic, or a target that isn't `_`"),
        };
        if target.is_some() {
            step.off = Field::Any;
        }
        step
    }

    /// Whether the instruction reads the register of `role`.
    const fn reads(self, role: Field) -> bool {
        let Field::Role(role) = role else {
            return false;
        };
        let opc = OpCode(self.op);
        let dst = match opc.class() {
            Class::Alu32 | Class::Alu64 => !matches!(opc.alu_opc(), AluOpc::Mov),
            Class::LdReg => false,
            _ => true,
        };
        // `src` names a register only where the instruction reads one
        (dst && self.dst.is(role)) || self.src.is(role)
    }

    /// The register field the instruction writes.
    const fn written(self) -> Field {
        match OpCode(self.op).class() {
            Class::Alu32 | Class::Alu64 | Class::LdReg => self.dst,
            _ => Field::Zero,
        }
    }
}

const fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    const_for!(i in 0..a.len() => {
        if a[i] != b[i] {
            return false;
        }
    });
    true
}

/// `name` without `prefix`, if it starts with it.
const fn strip<'a>(name: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if name.len() < prefix.len() {
        return None;
    }
    let (head, rest) = name.split_at(prefix.len());
    match eq(head, prefix) {
        true => Some(rest),
        false => None,
    }
}

/// The value of `name` in `table`.
const fn find<T: Copy>(table: &[(&str, T)], name: &[u8]) -> Option<T> {
    const_for!(i in 0..table.len() => {
        if eq(table[i].0.as_bytes(), name) {
            return Some(table[i].1);
        }
    });
    None
}

/// The handler of superinstruction `S`. It runs the sequence as the handlers of its instructions would, one after
/// another, but keeps each role in a variable of its own: it loads the roles the sequence reads before it writes them,
/// and stores the written ones back once, after the last instruction that writes one or before an instruction that
/// stops.
#[inline(never)]
extern "rust-preserve-none" fn fused<M: Memory, H: Host<M>, const FUEL: bool, const S: u8>(
    ctx: &mut Context<M>,
    insn: Instruction,
    code: &[Instruction],
    slot: Slot,
    fuel: u64,
    calls: &mut CallStack<H, M::Err>,
    table: &Table<M, H>,
) {
    let sup = const { Super::of(S) };
    let len = const { Super::of(S).len() };

    // the fuel runs out inside the sequence
    if FUEL && fuel < len as u64 - 1 {
        let alone = const { Handlers::<M, H, FUEL>::TABLE.0[Super::of(S).op(0) as usize] };
        become alone(ctx, sup.first_of(insn), code, slot, fuel, calls, table)
    }
    // SAFETY: `transfer::bound` leaves a superinstruction only where its sequence lies in the code, and the guard slot
    // follows the code (see `Slot`)
    let window = unsafe { slot.window(code, len + 1) };
    // the first slot is `insn`, which is already in a register
    let slot_of = |k: usize| if k == 0 { insn } else { window[k] };

    let registers = sup.registers(slot_of);
    let free = match sup.free {
        Some((k, shift)) => field(slot_of(k as usize), shift),
        None => 0,
    };
    let mut roles = Roles {
        values: [0; MAX_ROLES],
        regs: &mut ctx.regs,
        free,
    };
    roles.load(registers, sup.loads);

    // Continue at `$next` with the instruction `$insn` there, once the sequence is charged. A branch dispatches on each
    // side, so that it stays a branch: a `cmov` of the next slot's address would make the next fetch wait for the
    // registers the branch compares.
    macro_rules! dispatch {
        ($next:expr, $insn:expr) => {{
            let next = $next;
            let Some(left) = charge::<FUEL>(fuel - (len as u64 - 1) * u64::from(FUEL)) else {
                return calls.stop.at(next, 0, Flow::OutOfFuel);
            };
            let insn = $insn;
            become table.of(insn)(ctx, insn, code, next, left, calls, table)
        }};
    }

    // one block per instruction, so that each `step` sees a constant opcode and constant register indexes
    macro_rules! exec {
        ($k:literal) => {
            if $k < len {
                if $k == sup.save_at as usize {
                    roles.save(registers, sup.writes);
                }
                let at = slot.offset($k);
                let decoded = sup.decode($k, slot_of($k), ROLE_INDEXES, Some(FREE));
                match step(&mut roles, &mut ctx.data, decoded) {
                    ControlFlow::Break(Flow::Next) => {}
                    // only the last instruction branches, after `save_at`
                    ControlFlow::Break(Flow::Jump(offset)) if const { Super::of(S).branches_at($k) } => {
                        let target = slot.offset($k + 1 + offset);
                        // SAFETY: `transfer::bound` leaves a superinstruction only where its branch target lies in
                        // `0..=len` (see `Slot`)
                        dispatch!(target, unsafe { target.get() })
                    }
                    ControlFlow::Break(flow) => {
                        roles.save(registers, sup.unsaved[$k]);
                        return calls.stop.at(at, fuel - $k * u64::from(FUEL), flow);
                    }
                    // `Step::parse` makes no LD_IMM64
                    ControlFlow::Continue(_) => unreachable!(),
                }
            }
        };
    }
    // one `exec!` per instruction a sequence may have
    const _: () = assert!(MAX_LEN == 5);
    exec!(0);
    exec!(1);
    exec!(2);
    exec!(3);
    exec!(4);
    if sup.save_at as usize == len {
        roles.save(registers, sup.writes);
    }
    dispatch!(slot.offset(len as i64), window[len])
}

/// The registers of a superinstruction's sequence as [`fused`] runs it: its instructions name role `r` as register
/// `r`, kept in `values`, and the register operand `_` as [`FREE`], which is register `free` in `regs`.
struct Roles<'a> {
    values: [u64; MAX_ROLES],
    regs: &'a mut [u64; 16],
    free: u8,
}

/// The register indexes [`fused`] gives the roles.
const ROLE_INDEXES: [u8; MAX_ROLES] = [0, 1, 2];

/// The register index [`fused`] gives the register operand `_`.
const FREE: u8 = 15;

impl Roles<'_> {
    /// Load the roles in the bit set `roles` from their registers `registers`.
    #[inline(always)]
    fn load(&mut self, registers: [u8; MAX_ROLES], roles: u8) {
        for role in 0..MAX_ROLES {
            if roles & 1 << role != 0 {
                self.values[role] = self.regs[usize::from(registers[role])];
            }
        }
    }

    /// Store the roles in the bit set `roles` to their registers `registers`.
    #[inline(always)]
    fn save(&mut self, registers: [u8; MAX_ROLES], roles: u8) {
        for role in 0..MAX_ROLES {
            if roles & 1 << role != 0 {
                self.regs[usize::from(registers[role])] = self.values[role];
            }
        }
    }
}

// The instructions name no fixed register: `Step::parse` makes no atomics, of which `CMPXCHG` names r0.
impl Regs for Roles<'_> {
    #[inline(always)]
    fn get(&self, reg: u8) -> u64 {
        match reg {
            FREE => self.regs[usize::from(self.free)],
            role => self.values[usize::from(role)],
        }
    }

    #[inline(always)]
    fn set(&mut self, reg: u8, value: u64) {
        match reg {
            FREE => self.regs[usize::from(self.free)] = value,
            role => self.values[usize::from(role)] = value,
        }
    }
}
