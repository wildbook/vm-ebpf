//! Superinstructions: common instruction sequences that [`run`](crate::run) executes with one dispatch.
//!
//! [`Code::new`] gives the first slot of each sequence it recognises the opcode byte of a superinstruction, one of the
//! bytes that no slot holds once it ran (see [`canonical`]). The other slots keep what they hold, so a jump into the
//! middle of a sequence runs its instructions one by one. A superinstruction behaves exactly like its sequence:
//! - it lies in one of the blocks that fuel is charged for ([`fuel`](crate::fuel)), and where the fuel runs out inside
//!   its block, its instructions run one at a time;
//! - an instruction that faults stops execution at its own pc, with the effects of the instructions before it;
//! - a load or store that misses its data window ([`stack::data_step`]) continues the sequence unfused from itself.
//!
//! The same bytes mark the loads and stores through r10 that [`stack::access`] runs.

mod handler;
mod supers;

pub use supers::Super;
use supers::{Encode, SUPERS};

use crate::op::{self, Op};
use crate::opcode::atomic::{CMPXCHG, FETCH, LOAD_ACQ};
use crate::opcode::{AluEnd, AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, CALL, LD_IMM64};
use crate::transfer::{self, FAR, GUARD};
use crate::{stack, Handler, Host, Instruction, Memory, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL};

/// Bytecode prepared for [`run`](crate::run).
#[cfg_attr(not(feature = "fuel"), derive(Debug))]
pub struct Code {
    /// The code, then the slots [`transfer::bound`] appends, in the [slot format](crate::op), and with the `fuel`
    /// feature the `rest` of each ([`fuel`](crate::fuel)).
    slots: Box<[Op]>,
    len: usize,
}

impl Code {
    /// Prepare `insns` for [`run`](crate::run): fuse the sequences that have a superinstruction.
    ///
    /// r10 is read-only, so an instruction that would write it fails with [`Flow::FailCpu`](crate::Flow::FailCpu): an
    /// ALU, ALU64 or LDX instruction, LD_IMM64 or a load-acquire with `dst_reg` 10, and an atomic that fetches into
    /// `src_reg` 10.
    ///
    /// An instruction that sets a field the kernel verifier reserves also fails with `FailCpu`, as the verifier
    /// rejects it (`check_insn_fields` and the LD_IMM64 check in `check_and_resolve_insns`, kernel/bpf/verifier.c):
    /// - `src_reg` of ALU operations and conditional jumps with an immediate, END, ST, `ja`, `gotox`, `callx` and
    ///   `exit`, and `dst_reg` of `ja`, `exit` and `call` with an immediate;
    /// - `offset` of ALU operations but DIV, MOD and `mov` from a register, of `gotox`, `callx`, JMP32 `ja`,
    ///   LD_IMM64, and `call` but a kfunc's;
    /// - `imm` of ALU operations but END and of conditional jumps from a register, of LDX, STX, NEG, JMP `ja`,
    ///   `gotox`, `callx` and `exit`;
    /// - NEG from a register, `call` with a `src_reg` other than 0, 1 and 2, and LD_IMM64 whose second slot holds
    ///   anything but the upper half of the immediate.
    ///
    /// The verifier accepts `exit` with `src_reg` 1, which unwinds; rvm fails it, as it does `may_goto` with that
    /// `src_reg`.
    ///
    /// The code keeps the allocation of `insns` if it has room for one more slot, or with the `fuel` feature for two
    /// slots per instruction and two more.
    ///
    /// # Panics
    ///
    /// Panics if `insns` has 2^31 slots or more.
    pub fn new(insns: impl Into<Vec<Instruction>>) -> Self {
        let mut insns = insns.into();
        let len = insns.len();
        i32::try_from(len).expect("fewer than 2^31 slots");
        #[cfg(feature = "fuel")]
        // room for the guard and the `rest` of each slot, so that neither `bound` nor `fuel::slots` reallocates
        // unless `bound` moves instructions behind the guard
        insns.reserve_exact(len + 2);
        fuse(&mut insns);
        transfer::bound(&mut insns);
        #[cfg(not(feature = "fuel"))]
        // in place, as `Op` and `Instruction` have the same size and alignment
        let slots: Vec<Op> = insns.into_iter().map(Op::new).collect();
        #[cfg(feature = "fuel")]
        let slots = crate::fuel::slots(insns);
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
    /// [`Flow::FailMem`](crate::Flow::FailMem) at `pc`.
    #[cold]
    pub fn access_size(&self, pc: u64) -> Option<usize> {
        let op = *self.slots[..op::ops(&self.slots)].get(usize::try_from(pc).ok()?)?;
        let opc = OpCode(usual(op.byte()));
        if !matches!(opc.class(), Class::LdReg | Class::StReg | Class::StImm) {
            return None;
        }
        Some(opc.mem_size().bytes())
    }

    /// The code and the slots after it, which all hold [`GUARD`], then with the `fuel` feature the `rest` of each.
    pub(crate) fn slots(&self) -> &[Op] {
        &self.slots
    }
}

/// Shows each op with the `rest` of its block.
#[cfg(feature = "fuel")]
impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt;

        let ops = (0..op::ops(&self.slots) as u64).map(|pc| {
            let slot = transfer::Slot::at(&self.slots, pc);
            // SAFETY: the slot lies in the ops of a code built with the `fuel` feature
            let (op, rest) = unsafe { (slot.get(), slot.rest(&self.slots)) };
            fmt::from_fn(move |f| write!(f, "{op:?} rest {rest}"))
        });
        let slots = fmt::from_fn(|f| f.debug_list().entries(ops.clone()).finish());
        f.debug_struct("Code")
            .field("slots", &slots)
            .field("len", &self.len)
            .finish()
    }
}

/// The opcode that the instruction in a slot with opcode byte `byte` runs as: for the first slot of a superinstruction
/// or r10 access, which holds a free byte in its place, the first instruction of the sequence or the load or store, and
/// for a `mov` from a register with an offset, the `mov`.
pub const fn usual(byte: u8) -> u8 {
    const_for!((stack, op) in STACK => {
        if stack == byte {
            return op;
        }
    });
    match (byte, Super::with_byte(byte)) {
        (MOVSX32, _) => MOV32_REG,
        (MOVSX64, _) => MOV64_REG,
        (_, Some(sup)) => sup.op(0),
        (_, None) => byte,
    }
}

/// [`usual`] of each opcode byte.
pub const USUAL: [u8; 256] = byte_table!(|byte| usual(byte));

/// Whether [`Code::new`] leaves the opcode byte `byte` only where `offset` is 0: that of `mov` and `mov32`, which with
/// an offset run as MOVSX or fail, and those whose `offset` the verifier reserves.
#[inline(always)]
pub const fn offset_is_zero(byte: u8) -> bool {
    let rewrite = REWRITES[byte as usize];
    (rewrite.nonzero | rewrite.reserved) & OFFSET_BITS == OFFSET_BITS
}

/// Give the bytes that run as another theirs, r10 writes and instructions with a reserved field their failing byte,
/// `mov` from a register with an offset its MOVSX byte and pseudo LD_IMM64 its missing one, and the sequences with a
/// superinstruction and r10 accesses theirs.
fn fuse(code: &mut [Instruction]) {
    // Only the opcode byte changes, so the second slot of LD_IMM64 keeps its `imm`. The loop rewrites only slot `i`,
    // so it reads slot `i + 1` as loaded.
    for i in 0..code.len() {
        let insn = code[i];
        let rewrite = REWRITES[usize::from(insn.byte())];
        // most instructions pass both tests
        if insn.0 & rewrite.screen != 0 || (rewrite.dst && insn.dst_reg() == 10) {
            code[i] = rewrite.apply(insn, code.get(i + 1));
        }
    }

    // A superinstruction or r10 access changes only the opcode byte of its first slot. So the code from slot `i` on is
    // still as loaded but for opcode bytes, and a handler, which reads the other fields of its sequence's slots, later
    // reads the fields `encode` checked, and the slots of its sequence that `transfer::fits` keeps as they are. A
    // sequence whose branch leaves the code gives way to the next candidate, as `transfer::bound` would run it unfused.
    // The second slot of each LD_IMM64 left holds the byte [`MISSING`], which starts no sequence.
    for i in 0..code.len() {
        let window = &code[i..];
        // most candidates differ from the code in their last opcode, which this tests without a call
        let fused = |(_, sup, encode): &(u8, Super, Encode)| {
            let last = sup.len() - 1;
            let ends = window.get(last).is_some_and(|insn| insn.byte() == sup.op(last));
            ends.then(|| encode(window))
                .flatten()
                .filter(|_| transfer::fits(sup, code, i))
        };
        let found = candidates(window).iter().find_map(fused);
        debug_assert_eq!(found, SUPERS.iter().find_map(fused));
        if let Some(slot) = found {
            code[i] = slot;
        } else if let Some(byte) = stack_byte(code[i]) {
            code[i] = code[i].with_opcode(byte);
        }
    }
}

/// Why the first pass of [`fuse`] may rewrite an instruction with a given opcode byte.
#[derive(Clone, Copy)]
struct Rewrite {
    /// The [`canonical`] byte.
    canonical: Option<u8>,
    /// The instruction writes `dst_reg`.
    dst: bool,
    /// The byte is an atomic's: [`atomic_writes_r10`] decides whether it writes r10.
    atomic: bool,
    /// The bits of the fields that give the instruction `nonzero_byte` where they aren't 0: `src_reg` of LD_IMM64, a
    /// pseudo load, which runs as [`MISSING`] does, and `offset` of `mov` from a register, which runs as MOVSX or
    /// fails.
    nonzero: u64,
    nonzero_byte: u8,
    /// The bits of the fields the verifier reserves (see [`Code::new`]), which give the instruction [`INVALID`] where
    /// they aren't 0.
    reserved: u64,
    /// The bits of an instruction that send it to [`Rewrite::apply`] where they aren't 0: `nonzero` and `reserved`,
    /// and the opcode byte if the byte has a `canonical` one, is an atomic's, `call` or LD_IMM64. No such byte is 0.
    screen: u64,
}

impl Rewrite {
    /// `insn`, whose opcode byte has this rewrite and which `next` follows, with the opcode byte the first pass of
    /// [`fuse`] gives it.
    #[cold]
    #[inline(never)]
    fn apply(self, insn: Instruction, next: Option<&Instruction>) -> Instruction {
        let r10 = (self.dst && insn.dst_reg() == 10) || (self.atomic && atomic_writes_r10(insn));
        let reserved = (insn.0 & self.reserved != 0)
            || (insn.byte() == CALL && call_reserved(insn))
            || (insn.byte() == LD_IMM64 && next.is_some_and(|second| second.0 as u32 != 0));
        let byte = match (self.canonical, r10 || reserved) {
            (Some(byte), _) => byte,
            (None, true) => INVALID,
            (None, false) if insn.0 & self.nonzero != 0 => self.nonzero_byte,
            // an atomic, `call` or LD_IMM64 that needs no rewrite
            (None, false) => return insn,
        };
        insn.with_opcode(byte)
    }
}

/// The bits of each field of an [`Instruction`] but the opcode byte.
const DST_BITS: u64 = 0xF00;
const SRC_BITS: u64 = 0xF000;
const OFFSET_BITS: u64 = 0xFFFF_0000;
const IMM_BITS: u64 = 0xFFFF_FFFF_0000_0000;

const REWRITES: [Rewrite; 256] = {
    const NONE: Rewrite = Rewrite {
        canonical: None,
        dst: false,
        atomic: false,
        nonzero: 0,
        nonzero_byte: 0,
        reserved: 0,
        screen: 0,
    };

    byte_table!(|byte| {
        let opc = OpCode(byte);
        let reserved = reserved(opc);
        let rewrite = match opc.class() {
            _ if canonical(byte).is_some() => Rewrite {
                canonical: canonical(byte),
                ..NONE
            },
            Class::Alu32 | Class::Alu64 => {
                let (nonzero, nonzero_byte) = match byte {
                    MOV32_REG => (OFFSET_BITS, MOVSX32),
                    MOV64_REG => (OFFSET_BITS, MOVSX64),
                    _ => (0, 0),
                };
                Rewrite {
                    dst: true,
                    nonzero,
                    nonzero_byte,
                    reserved,
                    ..NONE
                }
            }
            Class::LdReg => Rewrite {
                dst: true,
                reserved,
                ..NONE
            },
            Class::LdImm if byte == LD_IMM64 => Rewrite {
                dst: true,
                nonzero: SRC_BITS,
                nonzero_byte: MISSING,
                reserved,
                ..NONE
            },
            Class::StReg => Rewrite {
                atomic: matches!(opc.mem_mode(), MemMode::Atomic),
                reserved,
                ..NONE
            },
            Class::LdImm | Class::StImm | Class::Jmp32 | Class::Jmp64 => Rewrite { reserved, ..NONE },
        };
        let always = rewrite.canonical.is_some() || rewrite.atomic || byte == CALL || byte == LD_IMM64;
        assert!(!always || byte != 0, "a rewritten byte 0, which `screen` can't catch");
        Rewrite {
            screen: rewrite.nonzero | rewrite.reserved | if always { 0xFF } else { 0 },
            ..rewrite
        }
    })
};

/// The bits of the fields that the verifier reserves in every instruction with opcode `opc` that runs, as
/// `check_insn_fields` checks them; [`call_reserved`] and [`fuse`] check those that depend on other fields.
const fn reserved(opc: OpCode) -> u64 {
    let reg = matches!(opc.alu_src(), Source::Reg);
    // the field that doesn't name the source
    let unused = if reg { IMM_BITS } else { SRC_BITS };
    let jmp64 = matches!(opc.class(), Class::Jmp64);
    match opc.class() {
        Class::Alu32 | Class::Alu64 => match opc.alu_opc() {
            // `INVALID`, which keeps every field
            AluOpc::UndefE | AluOpc::UndefF => 0,
            AluOpc::Neg => SRC_BITS | OFFSET_BITS | IMM_BITS,
            AluOpc::End => SRC_BITS | OFFSET_BITS,
            // the offset of DIV and MOD makes them signed, and that of `mov` from a register MOVSX
            AluOpc::Div | AluOpc::Mod => unused,
            AluOpc::Mov if reg => IMM_BITS,
            _ => unused | OFFSET_BITS,
        },
        Class::Jmp32 | Class::Jmp64 => match opc.jmp_opc() {
            // `gotox` and `callx`
            JmpOpc::Ja | JmpOpc::Call if reg => SRC_BITS | OFFSET_BITS | IMM_BITS,
            JmpOpc::Ja if jmp64 => SRC_BITS | DST_BITS | IMM_BITS,
            JmpOpc::Ja => SRC_BITS | DST_BITS | OFFSET_BITS,
            JmpOpc::Exit => SRC_BITS | DST_BITS | IMM_BITS,
            JmpOpc::Call => DST_BITS,
            // `ops::jump` checks the fields of `may_goto`
            JmpOpc::Jcond => 0,
            _ => unused,
        },
        Class::LdReg => IMM_BITS,
        Class::StImm => SRC_BITS,
        Class::StReg if matches!(opc.mem_mode(), MemMode::Mem) => IMM_BITS,
        Class::LdImm if opc.0 == LD_IMM64 => OFFSET_BITS,
        Class::StReg | Class::LdImm => 0,
    }
}

/// Whether the `call` with an immediate `insn` sets a field that the verifier reserves where it depends on the kind of
/// call in `src_reg`: a kind other than a helper, local or kfunc call, or an `offset` in a call that isn't a kfunc's.
fn call_reserved(insn: Instruction) -> bool {
    match insn.src_reg() {
        0 | BPF_PSEUDO_CALL => insn.offset() != 0,
        BPF_PSEUDO_KFUNC_CALL => false,
        _ => true,
    }
}

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

/// The byte of every LD-class instruction but LD_IMM64, the legacy packet loads among them, which all run as the same
/// unsupported instruction ([`Flow::Missing`](crate::Flow::Missing)).
const MISSING: u8 = Class::LdImm as u8;

/// An undefined ALU64 operation: the byte of every instruction that always fails with
/// [`Flow::FailCpu`](crate::Flow::FailCpu), and of every instruction that would write r10.
const INVALID: u8 = OpCode::alu64_from_parts(AluOpc::UndefE, Source::Imm).0;

const MOV32_REG: u8 = OpCode::alu32_from_parts(AluOpc::Mov, Source::Reg).0;
const MOV64_REG: u8 = OpCode::alu64_from_parts(AluOpc::Mov, Source::Reg).0;

/// The bytes of `mov32` and `mov` from a register with an offset: MOVSX, or a reserved offset, which fails.
const MOVSX32: u8 = 0xf0;
const MOVSX64: u8 = 0xf8;

/// The byte [`Code::new`] gives an instruction with opcode byte `byte` in its place, if it gives it another: one that
/// runs the same whatever the other fields hold. No slot holds `byte` afterwards, which frees it for a handler of its
/// own.
const fn canonical(byte: u8) -> Option<u8> {
    match byte {
        MISSING | LD_IMM64 | INVALID => None,
        _ if byte & 0b111 == Class::LdImm as u8 => Some(MISSING),
        _ if always_fails(OpCode(byte)) => Some(INVALID),
        _ => None,
    }
}

/// Whether every instruction with opcode `opc` fails with [`Flow::FailCpu`](crate::Flow::FailCpu), whatever its other
/// fields hold, as [`ops`](crate::ops) and [`mem`](crate::mem) run it or as the verifier rejects it (NEG from a
/// register).
const fn always_fails(opc: OpCode) -> bool {
    let jmp32 = matches!(opc.class(), Class::Jmp32);
    let imm = matches!(opc.alu_src(), Source::Imm);
    match opc.class() {
        Class::Alu32 | Class::Alu64 => match opc.alu_opc() {
            AluOpc::UndefE | AluOpc::UndefF => true,
            AluOpc::Neg => !imm,
            AluOpc::End => matches!((opc.class(), opc.alu_end()), (Class::Alu64, AluEnd::ToBE)),
            _ => false,
        },
        Class::Jmp32 | Class::Jmp64 => match opc.jmp_opc() {
            JmpOpc::Call => jmp32,
            JmpOpc::Ja => jmp32 && !imm,
            JmpOpc::Exit | JmpOpc::Jcond => jmp32 || !imm,
            JmpOpc::UndefF => true,
            _ => false,
        },
        Class::LdReg => match opc.mem_mode() {
            MemMode::Mem => false,
            MemMode::MemSX => matches!(opc.mem_size(), MemSize::DWord),
            _ => true,
        },
        Class::StImm => !matches!(opc.mem_mode(), MemMode::Mem),
        Class::StReg => !matches!(opc.mem_mode(), MemMode::Mem | MemMode::Atomic),
        Class::LdImm => false,
    }
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

const fn ldx(size: MemSize) -> u8 {
    OpCode::ldreg_from_parts(size, MemMode::Mem).0
}

const fn stx(size: MemSize) -> u8 {
    OpCode::streg_from_parts(size, MemMode::Mem).0
}

const fn st(size: MemSize) -> u8 {
    OpCode::stimm_from_parts(size, MemMode::Mem).0
}

// Every superinstruction, r10 access, MOVSX and `transfer` byte is a free one and has one use.
const _: () = {
    const fn claim(used: &mut [bool; 256], byte: u8) {
        assert!(canonical(byte).is_some(), "a byte that slots hold");
        assert!(!used[byte as usize], "two uses of one opcode byte");
        used[byte as usize] = true;
    }

    let mut used = [false; 256];
    const_for!((byte, ..) in SUPERS => claim(&mut used, byte));
    const_for!((byte, _) in STACK => claim(&mut used, byte));
    claim(&mut used, GUARD);
    claim(&mut used, FAR);
    claim(&mut used, MOVSX32);
    claim(&mut used, MOVSX64);
};

/// For each opcode byte, the byte of the r10 access with that opcode, if there is one.
const STACK_BYTES: [Option<u8>; 256] = {
    let mut table = [None; 256];
    const_for!((byte, usual) in STACK => table[usual as usize] = Some(byte));
    table
};

/// [`SUPERS`] grouped by their first two opcodes, each group in [`SUPERS`] order, so that the first match is the same.
const BY_PAIR: [(u8, Super, Encode); SUPERS.len()] = {
    const fn pair(sup: Super) -> u16 {
        (sup.op(0) as u16) << 8 | sup.second() as u16
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
    const_for!(i in 1..BY_PAIR.len() => n += (BY_PAIR[i].1.op(0) != BY_PAIR[i - 1].1.op(0)) as usize);
    n
};

/// For each opcode byte, the row of [`GROUPS`] for the superinstructions that start with it: 0 if none does.
const ROWS: [u8; 256] = {
    let mut rows = [0; 256];
    let mut row = 0;
    const_for!((_, sup, _) in BY_PAIR => {
        let first = sup.op(0) as usize;
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
        let group = &mut groups[ROWS[sup.op(0) as usize] as usize][sup.second() as usize];
        if group.1 == 0 {
            group.0 = i as u8;
        }
        group.1 += 1;
    });
    groups
};

/// The superinstructions that start with the first two opcodes of `window`, in the order [`Code::new`] tries them.
fn candidates(window: &[Instruction]) -> &'static [(u8, Super, Encode)] {
    let Some(first) = window.first() else {
        return &[];
    };
    let row = ROWS[usize::from(first.byte())];
    // most slots start none
    if row == 0 {
        return &[];
    }
    // the second instruction follows the upper half of an LD_IMM64
    let Some(second) = window.get(1 + usize::from(first.byte() == LD_IMM64)) else {
        return &[];
    };
    let (start, len) = GROUPS[row as usize][usize::from(second.byte())];
    &BY_PAIR[start as usize..][..len as usize]
}

/// Give each superinstruction and r10 access byte its handler.
pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
    supers::install::<M, H, FUEL>(table);
    install_stack::<M, H, FUEL>(table);
}

/// Each kind of field the verifier reserves, set where it is reserved and where an instruction uses it.
#[cfg(test)]
#[test]
fn reserved_fields() {
    let insn = Instruction::from_parts;
    let (alu, jmp) = (OpCode::alu64_from_parts, OpCode::jmp64_from_parts);
    let exit = insn(jmp(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0);
    let fails = |slots: &[Instruction]| Code::new(slots).slots()[0].byte() == INVALID;
    for (slot, reserved) in [
        (insn(alu(AluOpc::Add, Source::Imm), 1, 2, 0, 1), true),
        (insn(alu(AluOpc::Add, Source::Reg), 1, 2, 0, 1), true),
        (insn(alu(AluOpc::Add, Source::Reg), 1, 2, 1, 0), true),
        (insn(alu(AluOpc::Div, Source::Reg), 1, 2, 1, 0), false),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 8, 0), false),
        (insn(alu(AluOpc::Mov, Source::Reg), 1, 2, 8, 1), true),
        (insn(alu(AluOpc::Neg, Source::Reg), 1, 0, 0, 0), true),
        (insn(alu(AluOpc::Neg, Source::Imm), 1, 0, 0, 1), true),
        (insn(jmp(JmpOpc::Exit, Source::Imm), 0, 1, 0, 0), true),
        (insn(jmp(JmpOpc::Ja, Source::Imm), 1, 0, 0, 0), true),
        (insn(jmp(JmpOpc::Jeq, Source::Imm), 1, 2, 0, 0), true),
        (insn(jmp(JmpOpc::Call, Source::Imm), 0, 0, 1, 1), true),
        (insn(jmp(JmpOpc::Call, Source::Imm), 0, BPF_PSEUDO_KFUNC_CALL, 1, 1), false),
        (insn(jmp(JmpOpc::Call, Source::Imm), 0, 3, 0, 1), true),
        (insn(OpCode::ldreg_from_parts(MemSize::Word, MemMode::Mem), 1, 2, 0, 1), true),
        (insn(OpCode::stimm_from_parts(MemSize::Word, MemMode::Mem), 1, 2, 0, 1), true),
        (insn(OpCode(LD_IMM64), 1, 0, 1, 7), true),
    ] {
        assert_eq!(fails(&[slot, exit]), reserved, "{slot:?}");
    }

    // the second slot of LD_IMM64 holds the upper half of the immediate and nothing else
    let lddw = insn(OpCode(LD_IMM64), 1, 0, 0, 7);
    assert!(!fails(&[lddw, insn(OpCode(0), 0, 0, 0, 5)]));
    assert!(fails(&[lddw, insn(OpCode(0), 1, 0, 0, 5)]));
    assert!(fails(&[lddw, insn(OpCode(LD_IMM64), 0, 0, 0, 5)]));
}
