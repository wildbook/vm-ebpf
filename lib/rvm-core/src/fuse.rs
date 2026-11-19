//! Superinstructions: common instruction sequences that [`run`](crate::run) executes with one dispatch.
//!
//! [`Code::new`] gives the first slot of each sequence it recognises the opcode byte of a superinstruction, one of the
//! bytes that no slot holds once it ran (see [`canonical`]). The other slots keep their instructions, so a jump into the
//! middle of a sequence runs them one by one. A superinstruction behaves exactly like its sequence:
//! - it charges one unit of fuel per instruction, and runs only the first instruction when the fuel would run out
//!   inside the sequence;
//! - an instruction that faults stops execution at its own pc, with the effects of the instructions before it.
//!
//! The same bytes mark the loads and stores through r10 that [`stack::access`] runs.

mod handler;
mod supers;

pub use supers::Super;
use supers::{Encode, SUPERS};

use crate::opcode::atomic::{CMPXCHG, FETCH, LOAD_ACQ};
use crate::opcode::{AluEnd, AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, LD_IMM64};
use crate::transfer::{self, FAR, GUARD};
use crate::{stack, Handler, Host, Instruction, Memory};

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
    /// r10 is read-only, so an instruction that would write it fails with [`Flow::FailCpu`](crate::Flow::FailCpu): an
    /// ALU, ALU64 or LDX instruction, LD_IMM64 or a load-acquire with `dst_reg` 10, and an atomic that fetches into
    /// `src_reg` 10.
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
    /// [`Flow::FailMem`](crate::Flow::FailMem) at `pc`.
    #[cold]
    pub fn access_size(&self, pc: u64) -> Option<usize> {
        let byte = self.slots.get(usize::try_from(pc).ok()?)?.byte();
        // the first slot of a superinstruction or r10 access holds a free byte in place of its opcode
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

/// Give the bytes that run as another theirs and r10 writes their failing byte, and the sequences with a
/// superinstruction and r10 accesses theirs.
fn fuse(code: &mut [Instruction]) {
    // Only the opcode byte changes, so the second slot of LD_IMM64 keeps its `imm`.
    for insn in code.iter_mut() {
        let writes = WRITES[usize::from(insn.byte())];
        // `&` and `|` don't branch, so only the rare rewrite and atomics do
        let r10 = (writes.dst & (insn.dst_reg() == 10)) | (writes.atomic && atomic_writes_r10(*insn));
        if writes.canonical.is_some() | r10 {
            *insn = insn.with_opcode(writes.canonical.unwrap_or(INVALID));
        }
    }

    // A superinstruction or r10 access changes only the opcode byte of its first slot. So the code from slot `i` on is
    // still as loaded but for opcode bytes, and a handler, which reads the other fields of its sequence's slots, later
    // reads the fields `encode` checked. A sequence whose branch leaves the code gives way to the next candidate, as
    // `transfer::bound` would run it unfused.
    for i in 0..code.len() {
        // the slot after LD_IMM64 holds the upper half of its immediate
        if i > 0 && code[i - 1].byte() == LD_IMM64 {
            continue;
        }
        let window = &code[i..];
        let fused = |(_, sup, encode): &(u8, Super, Encode)| encode(window).filter(|_| transfer::fits(sup, code, i));
        let found = candidates(window).iter().find_map(fused);
        debug_assert_eq!(found, SUPERS.iter().find_map(fused));
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
    /// The [`canonical`] byte.
    canonical: Option<u8>,
    /// `dst_reg`.
    dst: bool,
    /// The byte is an atomic's: [`atomic_writes_r10`] decides.
    atomic: bool,
}

const WRITES: [Writes; 256] = {
    const NONE: Writes = Writes {
        canonical: None,
        dst: false,
        atomic: false,
    };

    byte_table!(|byte| {
        let opc = OpCode(byte);
        match opc.class() {
            _ if canonical(byte).is_some() => Writes {
                canonical: canonical(byte),
                ..NONE
            },
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

/// The byte of every LD-class instruction but LD_IMM64, the legacy packet loads among them, which all run as the same
/// unsupported instruction ([`Flow::Missing`](crate::Flow::Missing)).
const MISSING: u8 = Class::LdImm as u8;

/// An undefined ALU64 operation: the byte of every instruction that always fails with
/// [`Flow::FailCpu`](crate::Flow::FailCpu), and of every instruction that would write r10.
const INVALID: u8 = OpCode::alu64_from_parts(AluOpc::UndefE, Source::Imm).0;

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
/// fields hold, as [`ops`](crate::ops) and [`mem`](crate::mem) run it.
const fn always_fails(opc: OpCode) -> bool {
    let jmp32 = matches!(opc.class(), Class::Jmp32);
    let imm = matches!(opc.alu_src(), Source::Imm);
    match opc.class() {
        Class::Alu32 | Class::Alu64 => match opc.alu_opc() {
            AluOpc::UndefE | AluOpc::UndefF => true,
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

// Every superinstruction, r10 access and `transfer` byte is a free one and has one use.
const _: () = {
    const fn claim(used: &mut [bool; 256], byte: u8) {
        assert!(canonical(byte).is_some(), "a byte that slots hold");
        assert!(!used[byte as usize], "two uses of one opcode byte");
        used[byte as usize] = true;
    }

    let mut used = [false; 256];
    const_for!((byte, ..) in SUPERS => {
        claim(&mut used, byte);
    });
    const_for!((byte, _) in STACK => {
        claim(&mut used, byte);
    });
    claim(&mut used, GUARD);
    claim(&mut used, FAR);
};

/// For each opcode byte, the byte of the r10 access with that opcode, if there is one.
const STACK_BYTES: [Option<u8>; 256] = {
    let mut table = [None; 256];
    const_for!((byte, usual) in STACK => {
        table[usual as usize] = Some(byte);
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
    supers::install::<M, H, FUEL>(table);
    install_stack::<M, H, FUEL>(table);
}
