//! The superinstruction table, and the [`Super`] that the compiler derives from each of its lines.

use super::handler::fused;
use crate::op::{Fields, Reg};
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, LD_IMM64};
use crate::{Handler, Host, Instruction, Memory};

macro_rules! superinstructions {
    ($($byte:literal: $($op:ident $($operand:tt),*);+;)*) => {
        /// Superinstructions by opcode byte, with their [`Encode`]; [`Code::new`](crate::Code::new) tries them in this
        /// order.
        pub const SUPERS: &[(u8, Super, Encode)] =
            &[$(($byte, Super::new(&[$((stringify!($op), &[$(operand!($operand)),*])),+]), encode_as::<$byte>)),*];

        /// Give each superinstruction byte its handler.
        pub const fn install<M: Memory, H: Host<M>, const FUEL: bool>(table: &mut [Handler<M, H>; 256]) {
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
// names, which only the last instruction may have. Every field a line doesn't mention is zero. `lddw` is LD_IMM64 with
// `src_reg` 0, whose second slot may hold anything besides the upper half of its immediate. Longer sequences come first,
// so that they win over their prefixes.
superinstructions! {
    // rotate: t = x >> k | x << (32 - k), into x or y
    0xd0: mov32 t, x; rsh32 t, _; lsh32 x, _; mov32 y, x; or32 y, t;
    0xd8: mov32 t, x; rsh32 t, _; lsh32 x, _; or32 x, t;
    // a = b + c, then a load, store or branch through a, or a byte load through a and a branch on the byte
    0x9e: mov64 a, b; add64 a, c; ldxb a, [a + _]; jeq32 a, _, _;
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
    // two moves
    0xf5: mov64 a, b; mov64 _, _;
    // loop counters: a += imm, then a branch on a or another add
    0x88: add64 a, _; jlt a, c, _;
    0x90: add64 a, _; jne a, _, _;
    0x98: add64 a, _; jgt a, _, _;
    0x86: add64 a, _; add64 _, _;
    // the address of an element of a global array
    0xf7: lddw a, _; add64 a, b;
}

/// For each opcode byte, the index in [`SUPERS`] of its superinstruction: `u8::MAX` if it has none.
const BY_BYTE: [u8; 256] = {
    let mut table = [u8::MAX; 256];
    const_for!(i in 0..SUPERS.len() => table[SUPERS[i].0 as usize] = i as u8);
    table
};

/// A superinstruction: the sequence it runs, over registers that the table names by role, and what [`fused`] and
/// [`Code::new`](crate::Code::new) derive from it. Its sequence fills one slot per instruction and two per LD_IMM64,
/// and everything it records about an instruction it records at the instruction's first slot.
#[derive(Clone, Copy)]
pub struct Super {
    /// One per slot; the second slot of an LD_IMM64 has [`Step::NONE`].
    steps: [Step; MAX_LEN],
    len: u8,
    roles: u8,
    /// For each role, the slot of the operand that names it first and whether that operand is `src_reg`, where the
    /// code gives the role its register.
    homes: [(u8, bool); MAX_ROLES],

    /// The roles the sequence reads before it writes them, one bit each.
    pub loads: u8,
    /// The roles the sequence writes, one bit each.
    pub writes: u8,
    /// The slot the written roles go back to their registers before: the one after the last instruction that writes
    /// a role.
    pub save_at: u8,
    /// For each slot, the roles written before it that aren't back in their registers yet.
    pub unsaved: [u8; MAX_LEN],
    /// The slot of the instruction whose `dst_reg` is the register operand `_`, if the sequence has one. In a source
    /// operand, `_` is an immediate.
    pub free_at: Option<u8>,
}

/// The most slots a superinstruction's sequence fills.
pub const MAX_LEN: usize = 5;

/// The most roles a superinstruction has.
pub const MAX_ROLES: usize = 4;

impl Super {
    /// The superinstruction that runs `insns`, each a mnemonic and its operands, and fails to compile one that
    /// [`fused`] can't run.
    const fn new(insns: &[(&'static str, &[Operand])]) -> Self {
        assert!(insns.len() > 1, "a sequence of one instruction");

        let mut sup = Self {
            steps: [Step::NONE; MAX_LEN],
            len: 0,
            roles: 0,
            homes: [(0, false); MAX_ROLES],
            loads: 0,
            writes: 0,
            save_at: 0,
            unsaved: [0; MAX_LEN],
            free_at: None,
        };
        let mut names = Names {
            names: [""; MAX_ROLES],
            len: 0,
        };
        const_for!((mnemonic, operands) in insns => {
            let step = Step::parse(mnemonic, operands, &mut names);
            assert!(sup.len() + step.slots() <= MAX_LEN, "a sequence of more than `MAX_LEN` slots");
            sup.steps[sup.len()] = step;
            sup.len += step.slots() as u8;
        });
        let len = sup.len();
        // `encode` matches the opcode of the last slot first
        assert!(!sup.is_data(len - 1), "an LD_IMM64 at the end of a sequence");

        const_for!(k in 0..len => {
            // only the last instruction may branch, and it continues at `pc + 1` or a fixed target
            assert!(k == len - 1 || !sup.branches_at(k), "a branch before the end of a sequence");
            if let Field::Any = sup.steps[k].dst {
                assert!(k == len - 1, "a register `_` before the end of a sequence");
                sup.free_at = Some(k as u8);
            }
        });

        sup.roles = names.len;
        const_for!(role in 0..sup.roles => sup.homes[role as usize] = sup.home(role));

        const_for!(k in 0..len => {
            let step = sup.steps[k];
            const_for!(role in 0..sup.roles => {
                if step.reads(role) && sup.writes & 1 << role == 0 {
                    sup.loads |= 1 << role;
                }
            });
            sup.unsaved[k] = sup.writes;
            if let Field::Role(role) = step.written() {
                sup.writes |= 1 << role;
                sup.save_at = (k + step.slots()) as u8;
            }
        });
        // the written roles are back in their registers from `save_at` on
        const_for!(k in sup.save_at as usize..len => sup.unsaved[k] = 0);

        // `Roles` gives the register `_` its value in the registers, so it may share a register with a role only where
        // the roles are back there for good
        if let Some(k) = sup.free_at {
            assert!(k >= sup.save_at, "a register `_` before the roles are back in their registers");
        }
        sup
    }

    /// The slot of the operand that names `role` first, and whether that operand is `src_reg`.
    const fn home(self, role: u8) -> (u8, bool) {
        const_for!(k in 0..self.len() => {
            let step = self.steps[k];
            if step.dst.is(role) {
                return (k as u8, false);
            }
            if step.src.is(role) {
                return (k as u8, true);
            }
        });
        unreachable!()
    }

    /// The superinstruction with opcode byte `byte`, if there is one.
    pub const fn with_byte(byte: u8) -> Option<&'static Self> {
        match BY_BYTE[byte as usize] as usize {
            index if index < SUPERS.len() => Some(&SUPERS[index].1),
            _ => None,
        }
    }

    /// The superinstruction with opcode byte `byte`.
    pub const fn of(byte: u8) -> Self {
        *Self::with_byte(byte).expect("not a superinstruction")
    }

    /// The number of slots the sequence fills.
    #[inline(always)]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// The opcode of the instruction whose first slot is slot `k` of the sequence.
    #[inline(always)]
    pub const fn op(self, k: usize) -> u8 {
        self.steps[k].op
    }

    /// Whether slot `k` of the sequence holds the upper half of an LD_IMM64's immediate, not an instruction.
    #[inline(always)]
    pub const fn is_data(self, k: usize) -> bool {
        k > 0 && self.op(k - 1) == LD_IMM64
    }

    /// The opcode of the second instruction of the sequence.
    pub const fn second(self) -> u8 {
        self.op(1 + self.is_data(1) as usize)
    }

    /// The first instruction of the sequence whose first slot holds `slot`.
    #[inline(always)]
    pub fn first_of(self, slot: Instruction) -> Instruction {
        slot.with_opcode(self.op(0))
    }

    /// The register of each role, from `slot(k)`, slot `k` of the sequence.
    #[inline(always)]
    pub fn registers<F: Fields>(self, slot: impl Fn(usize) -> F) -> [Reg; MAX_ROLES] {
        let mut registers = [Reg::R0; MAX_ROLES];
        for role in 0..self.roles as usize {
            let (k, src) = self.homes[role];
            let slot = slot(k as usize);
            registers[role] = if src { slot.src_reg() } else { slot.dst_reg() };
        }
        registers
    }

    /// The instruction whose first slot is slot `k` of the sequence, from that slot `slot`: the register of each role
    /// from `roles`, and the register operand `_` from `free`, else from `slot`.
    #[inline(always)]
    pub fn decode(self, k: usize, slot: impl Fields, roles: [Reg; MAX_ROLES], free: Option<Reg>) -> Instruction {
        let step = self.steps[k];
        let dst = step.dst.register(roles, free, slot.dst_reg());
        let src = step.src.register(roles, free, slot.src_reg());
        let off = if let Field::Any = step.off { slot.offset() } else { 0 };
        let imm = if let Field::Any = step.imm { slot.imm() } else { 0 };
        Instruction::from_parts(OpCode(step.op), dst.get(), src.get(), off, imm)
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
            // `fused` reads only the `imm` of the second slot of LD_IMM64, which it may hold with any other fields
            if !self.is_data(k) && self.decode(k, insn, registers, None) != insn {
                return None;
            }
        }
        Some(sequence[0].with_opcode(byte))
    }

    /// Whether the instruction at slot `k` of the sequence may branch.
    #[inline(always)]
    pub const fn branches_at(self, k: usize) -> bool {
        matches!(OpCode(self.op(k)).class(), Class::Jmp32 | Class::Jmp64)
    }

    /// Whether the last instruction of the sequence may branch.
    #[inline(always)]
    pub const fn branches(self) -> bool {
        self.branches_at(self.len() - 1)
    }
}

/// [`Super::encode`] of one superinstruction.
pub type Encode = fn(&[Instruction]) -> Option<Instruction>;

/// [`Super::encode`] of the superinstruction with opcode byte `S`, compiled with its sequence constant.
fn encode_as<const S: u8>(window: &[Instruction]) -> Option<Instruction> {
    const { Super::of(S) }.encode(S, window)
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
    fn register(self, roles: [Reg; MAX_ROLES], free: Option<Reg>, own: Reg) -> Reg {
        match self {
            Field::Zero => Reg::R0,
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
    /// The field of the role `name`. Role names, like mnemonics, ignore case.
    const fn role(&mut self, name: &'static str) -> Field {
        const_for!(role in 0..self.len => {
            if self.names[role as usize].eq_ignore_ascii_case(name) {
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

    /// The number of slots the instruction fills.
    const fn slots(self) -> usize {
        1 + (self.op == LD_IMM64) as usize
    }

    /// The instruction `mnemonic operands`, whose roles `names` numbers.
    const fn parse(mnemonic: &str, operands: &[Operand], names: &mut Names) -> Self {
        let mut step = Self::NONE;

        // `lddw dst, _`: LD_IMM64 with `src_reg` 0, the only form that loads its immediate
        if let b"lddw" = mnemonic.as_bytes() {
            let &[dst, Operand::Any] = operands else {
                panic!("`lddw` takes a register and an immediate")
            };
            step.op = LD_IMM64;
            step.dst = names.register(dst);
            step.imm = Field::Any;
            return step;
        }

        // loads and stores: `ldx dst, [base]`, `st [base], imm`, `stx [base], src`
        let access = match mnemonic.as_bytes() {
            [b'l', b'd', b'x', size @ ..] => Some((true, size)),
            [b's', b't', b'x', size @ ..] | [b's', b't', size @ ..] => Some((false, size)),
            _ => None,
        };
        if let Some((load, size)) = access {
            let Some(size) = MemSize::from_name(size) else {
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
        let (name, width) = match mnemonic.as_bytes() {
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
        step.op = match (AluOpc::from_name(name), JmpOpc::from_name(name), width, target) {
            (_, Some(JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit | JmpOpc::Jcond), ..) => panic!("not a conditional jump"),
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
    const fn reads(self, role: u8) -> bool {
        let opc = OpCode(self.op);
        let dst = match opc.class() {
            Class::Alu32 | Class::Alu64 => !matches!(opc.alu_opc(), AluOpc::Mov),
            Class::LdReg | Class::LdImm => false,
            _ => true,
        };
        // `src` names a register only where the instruction reads one
        (dst && self.dst.is(role)) || self.src.is(role)
    }

    /// The register field the instruction writes.
    const fn written(self) -> Field {
        match OpCode(self.op).class() {
            Class::Alu32 | Class::Alu64 | Class::LdReg | Class::LdImm => self.dst,
            _ => Field::Zero,
        }
    }
}
