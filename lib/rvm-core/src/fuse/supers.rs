//! The superinstruction table, and the [`Super`] that the compiler derives from each of its lines.

use super::handler::fused;
use crate::context::FP;
use crate::dispatch::Handler;
use crate::fuel::{Fuel, Unmetered};
use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, MemSize, OpCode, Source, LD_IMM64};
use crate::slot::{Fields, Reg};
use crate::{Host, Instruction, Memory};

macro_rules! superinstructions {
    ($($byte:literal: $($op:ident $($operand:tt),*);+;)*) => {
        /// Superinstructions by opcode byte; [`Code::new`](crate::Code::new) tries them in this order.
        pub const SUPERS: &[(u8, Super)] =
            &[$(($byte, Super::new(&[$((stringify!($op), &[$(operand!($operand)),*])),+]))),*];

        /// Give each superinstruction byte its handler.
        pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
            $(table[$byte] = handler_of::<M, H, F, $byte>();)*
        }
    };
}

/// The handler of superinstruction `S` in the table of the runs that meter with `F`. A sequence that doesn't end its
/// block has the same handler in every table.
const fn handler_of<M: Memory, H: Host<M>, F: Fuel, const S: u8>() -> Handler<M, H> {
    match Super::of(S).branches() {
        true => fused::<M, H, F, S>,
        false => fused::<M, H, Unmetered, S>,
    }
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

// Each line gives the opcode byte of a superinstruction and its sequence in eBPF assembler syntax, with roles in place
// of registers. A sequence fuses where each role stands for one register throughout and different roles for different
// registers. `_` stands for whatever its slot holds: an immediate, an offset, a jump target, or a register that no role
// names, which only the last instruction may have. `fp` is r10 as the base of a 4 or 8 byte load or store. Every field
// a line doesn't mention is zero. `lddw` is LD_IMM64 with `src_reg` 0, whose second slot `Code::new` leaves only where
// it holds the upper half of the immediate and nothing else. Longer sequences come first, so that they win over their
// prefixes.
superinstructions! {
    // 32-bit rotates: t = x >> k | x << (32 - k) in either shift order, into x
    0xd8: mov32 t, x; rsh32 t, _; lsh32 x, _; or32 x, t;
    0x30: mov32 t, x; lsh32 t, _; rsh32 x, _; or32 x, t;
    // a = b + c, then a load or store through a, or a byte load through a and a branch on the byte
    0x9e: mov64 a, b; add64 a, c; ldxb a, [a + _]; jeq32 a, _, _;
    0x08: mov64 a, b; add64 a, c; ldxb _, [a + _];
    0x20: mov64 a, b; add64 a, c; stb [a + _], _;
    // two moves
    0xf5: mov64 a, b; mov64 _, _;
    // loop counters and mask tests: a += imm or a &= imm, then a branch on a or another ALU op
    0x88: add64 a, _; jlt a, c, _;
    0x01: add64 a, _; jlt a, _, _;
    0x90: add64 a, _; jne a, _, _;
    0x98: add64 a, _; jgt a, _, _;
    0x09: add32 a, _; jeq32 a, _, _;
    0x11: add32 a, _; jne32 a, _, _;
    0x21: and32 a, _; jeq32 a, _, _;
    0x29: and32 a, _; jne32 a, _, _;
    0x31: add32 a, _; and32 a, _;
    0x86: add64 a, _; add64 _, _;
    // indexed byte load without a preceding move
    0x39: add64 a, b; ldxb _, [a + _];
    // the address of an element of a global array
    0xf7: lddw a, _; add64 a, b;
    // spill traffic: a reload and an operation, or a load and a spill, over any registers
    0x19: ldxdw a, [fp + _]; mul64 b, c;
    0x1a: ldxw a, [fp + _]; add32 b, c;
    0x41: ldxw a, [fp + _]; add32 a, _;
    0x1b: ldxw a, [b + _]; stxw [fp + _], c;
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
    /// One per slot; the second slot of an LD_IMM64 has [`Part::NONE`].
    parts: [Part; MAX_LEN],
    len: u8,
    roles: u8,
    /// For each role, the slot of the operand that names it first and whether that operand is `src_reg`, where the
    /// code gives the role its register.
    homes: [(u8, bool); MAX_ROLES],
    /// For each slot, the bits that [`Super::encode`] compares with the opcode of its part: the opcode byte, and
    /// `offset` and `imm` unless they are `_`. None in the second slot of an LD_IMM64.
    masks: [u64; MAX_LEN],
    /// For each role, a 1 in the low bit of each register field that names it, in the register bytes that
    /// [`Super::encode`] packs: byte 1 of slot `k` at byte `k`.
    spreads: [u64; MAX_ROLES],
    /// The bits of the register fields that aren't `_`, in the register bytes.
    register_bits: u64,
    /// r10 in each register field that names `fp`, in the register bytes.
    fixed: u64,
    /// The roles that name the base of a load or store and that no instruction writes, one bit each. None of them
    /// stands for r10, so that every access through r10 that a superinstruction runs is an `fp` one, which tries the
    /// window around r10 first. A role that an instruction writes isn't r10 anyway: `Code::new` fails writes to r10.
    bases: u8,
    /// The roles `encode` compares: all of them, or none for a direct sequence, whose roles tie no register to another.
    compared: u8,

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
    /// Whether the sequence names each role once. A role named once ties its register to no other, and a variable
    /// would hold its value for one use, so such a sequence fuses whatever registers its slots name, the same register
    /// for several roles among them, and runs on the registers themselves: it loads and saves no role.
    pub direct: bool,
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
            parts: [Part::NONE; MAX_LEN],
            len: 0,
            roles: 0,
            homes: [(0, false); MAX_ROLES],
            masks: [0; MAX_LEN],
            spreads: [0; MAX_ROLES],
            register_bits: 0,
            fixed: 0,
            bases: 0,
            compared: 0,
            loads: 0,
            writes: 0,
            save_at: 0,
            unsaved: [0; MAX_LEN],
            free_at: None,
            direct: true,
        };
        let mut names = Names {
            names: [""; MAX_ROLES],
            len: 0,
        };
        const_for!((mnemonic, operands) in insns => {
            let part = Part::parse(mnemonic, operands, &mut names);
            assert!(sup.len() + part.slots() <= MAX_LEN, "a sequence of more than `MAX_LEN` slots");
            sup.parts[sup.len()] = part;
            sup.len += part.slots() as u8;
        });
        let len = sup.len();
        // `fuse` tests the opcode of the last slot first
        assert!(!sup.is_data(len - 1), "an LD_IMM64 at the end of a sequence");

        const_for!(k in 0..len => {
            // only the last instruction may branch, and it continues at `pc + 1` or a fixed target
            assert!(k == len - 1 || !sup.branches_at(k), "a branch before the end of a sequence");
            if let Field::Any = sup.parts[k].dst {
                assert!(k == len - 1, "a register `_` before the end of a sequence");
                sup.free_at = Some(k as u8);
            }
        });

        sup.roles = names.len;
        const_for!(role in 0..sup.roles => sup.homes[role as usize] = sup.home(role));
        // what `encode` compares
        const_for!(k in 0..len => {
            // `rewrite` failed the LD_IMM64 whose second slot holds more than the upper half of `imm`
            if sup.is_data(k) {
                continue;
            }
            let part = sup.parts[k];
            sup.masks[k] = Instruction::OPCODE;
            const_for!((field, bits) in [(part.off, Instruction::OFFSET), (part.imm, Instruction::IMM)] => {
                if !matches!(field, Field::Any) {
                    sup.masks[k] |= bits;
                }
            });
            const_for!((field, shift) in [(part.dst, 8 * k), (part.src, 8 * k + 4)] => {
                if !matches!(field, Field::Any) {
                    sup.register_bits |= 0xF << shift;
                }
                match field {
                    Field::Role(role) => sup.spreads[role as usize] |= 1 << shift,
                    Field::Fp => sup.fixed |= (FP as u64) << shift,
                    Field::Zero | Field::Any => {}
                }
            });
            if let Field::Role(role) = part.base() {
                sup.bases |= 1 << role;
            }
        });
        const_for!(k in 0..len => {
            if let Field::Role(role) = sup.parts[k].written() {
                sup.bases &= !(1 << role);
            }
        });

        const_for!(role in 0..sup.roles => sup.direct &= sup.spreads[role as usize].count_ones() == 1);
        if sup.direct {
            const_for!(role in 0..sup.roles => sup.register_bits &= !(0xF * sup.spreads[role as usize]));
        } else {
            sup.compared = sup.roles;
        }
        // the roles `fused` keeps in variables
        if !sup.direct {
            const_for!(k in 0..len => {
                let part = sup.parts[k];
                const_for!(role in 0..sup.roles => {
                    if part.reads(role) && sup.writes & 1 << role == 0 {
                        sup.loads |= 1 << role;
                    }
                });
                sup.unsaved[k] = sup.writes;
                if let Field::Role(role) = part.written() {
                    sup.writes |= 1 << role;
                    sup.save_at = (k + part.slots()) as u8;
                }
            });
        }
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
            let part = self.parts[k];
            if part.dst.is(role) {
                return (k as u8, false);
            }
            if part.src.is(role) {
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
    // by reference, so that a `k` known only at run time indexes `parts` in place, not a copy on the stack
    #[inline(always)]
    pub const fn opcode(&self, k: usize) -> u8 {
        self.parts[k].op
    }

    /// Whether slot `k` of the sequence holds the upper half of an LD_IMM64's immediate, not an instruction.
    #[inline(always)]
    pub const fn is_data(self, k: usize) -> bool {
        k > 0 && self.opcode(k - 1) == LD_IMM64
    }

    /// The opcode of the second instruction of the sequence.
    pub const fn second(self) -> u8 {
        self.opcode(1 + self.is_data(1) as usize)
    }

    /// Whether the load or store at slot `k` of the sequence addresses through `fp` (r10).
    pub const fn is_fp_access(self, k: usize) -> bool {
        matches!(self.parts[k].base(), Field::Fp)
    }

    /// The first instruction of the sequence whose first slot holds `slot`.
    #[inline(always)]
    pub fn first_of(self, slot: Instruction) -> Instruction {
        slot.with_byte(self.opcode(0))
    }

    /// The register of each role, from `slot(k)`, slot `k` of the sequence.
    // Unrolled over `MAX_ROLES` so `homes[role]` and `slot(k)` fold at `opt-level = "s"` too, instead of copying
    // `Super` to the stack and emitting a jump table.
    #[inline(always)]
    pub fn registers<F: Fields>(self, slot: impl Fn(usize) -> F) -> [Reg; MAX_ROLES] {
        let mut registers = [Reg::R0; MAX_ROLES];
        macro_rules! fetch {
            ($($role:literal),*) => {$(
                if $role < self.roles as usize {
                    let (k, src) = self.homes[$role];
                    let slot = slot(k as usize);
                    registers[$role] = if src { slot.src_reg() } else { slot.dst_reg() };
                }
            )*};
        }
        const _: () = assert!(MAX_ROLES == 4);
        fetch!(0, 1, 2, 3);
        registers
    }

    /// The instruction whose first slot is slot `k` of the sequence, from that slot `slot`: the register of each role
    /// from `roles`, and the register operand `_` from `free`, else from `slot`.
    #[inline(always)]
    pub fn decode(self, k: usize, slot: impl Fields, roles: [Reg; MAX_ROLES], free: Option<Reg>) -> Instruction {
        let part = self.parts[k];
        let dst = part.dst.register(roles, free, slot.dst_reg());
        let src = part.src.register(roles, free, slot.src_reg());
        let off = if let Field::Any = part.off { slot.offset() } else { 0 };
        let imm = if let Field::Any = part.imm { slot.imm() } else { 0 };
        Instruction::new(OpCode(part.op), dst.get(), src.get(), off, imm)
    }

    /// The first slot of this superinstruction, with opcode byte `byte`, for the sequence at the start of `window`, if
    /// it has one.
    pub fn encode(&self, byte: u8, window: &[Instruction]) -> Option<Instruction> {
        let sequence = window.get(..self.len())?;
        let mut differs = 0;
        // byte 1 of slot `k`, which holds its register fields, at byte `k`
        let mut registers = 0;
        for (k, ((insn, part), mask)) in sequence.iter().zip(&self.parts).zip(&self.masks).enumerate() {
            differs |= (insn.0 ^ u64::from(part.op)) & mask;
            registers |= (insn.0 >> 8 & 0xFF) << (8 * k);
        }

        // the register of each role, from its home, in every register field that names the role
        let mut expected = self.fixed;
        let mut used = 0u16;
        for (&(k, src), spread) in self.homes.iter().zip(&self.spreads).take(usize::from(self.compared)) {
            let register = registers >> (8 * k + 4 * u8::from(src)) & 0xF;
            // `fused` keeps each role in a variable of its own
            if used & 1 << register != 0 {
                return None;
            }
            used |= 1 << register;
            expected |= register * spread;
        }
        if self.bases != 0 && self.base_on_stack(registers) {
            return None;
        }

        differs |= (registers ^ expected) & self.register_bits;
        (differs == 0).then(|| sequence[0].with_byte(byte))
    }

    /// Whether a role in `bases` stands for r10 in the register bytes `registers` that `encode` packs.
    fn base_on_stack(&self, registers: u64) -> bool {
        (0..usize::from(self.roles)).any(|role| {
            let (k, src) = self.homes[role];
            self.bases >> role & 1 != 0 && registers >> (8 * k + 4 * u8::from(src)) & 0xF == FP as u64
        })
    }

    /// Whether the instruction at slot `k` of the sequence may branch.
    #[inline(always)]
    pub const fn branches_at(self, k: usize) -> bool {
        OpCode(self.opcode(k)).is_jump()
    }

    /// Whether the last instruction of the sequence may branch.
    #[inline(always)]
    pub const fn branches(self) -> bool {
        self.branches_at(self.len() - 1)
    }
}

/// An instruction of a superinstruction's sequence.
#[derive(Clone, Copy)]
struct Part {
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
    /// r10: `fp`, which only names the base of a load or store.
    Fp,
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
            Field::Fp => Reg::low(FP as u8),
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
    /// `[base + _]` or `[base]`: the role of the base, or `fp`, and whether the offset is `_`.
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
        assert!(!name.eq_ignore_ascii_case("fp"), "`fp` other than as the base of a load or store");
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

    /// The field of the base of a memory operand: r10 for `fp`, else a role.
    const fn base(&mut self, name: &'static str) -> Field {
        match name.eq_ignore_ascii_case("fp") {
            true => Field::Fp,
            false => self.role(name),
        }
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

impl Part {
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
        let mut part = Self::NONE;

        // `lddw dst, _`: LD_IMM64 with `src_reg` 0, the only form that loads its immediate
        if let b"lddw" = mnemonic.as_bytes() {
            let &[dst, Operand::Any] = operands else {
                panic!("`lddw` takes a register and an immediate")
            };
            part.op = LD_IMM64;
            part.dst = names.register(dst);
            part.imm = Field::Any;
            return part;
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
                (true, _) => OpCode::ldx(size, MemMode::Mem),
                (false, Operand::Any) => OpCode::st(size, MemMode::Mem),
                (false, _) => OpCode::stx(size, MemMode::Mem),
            };
            part.op = opc.0;
            if offset {
                part.off = Field::Any;
            }
            match opc.class() {
                Class::Ldx => {
                    part.dst = names.register(register);
                    part.src = names.base(base);
                }
                Class::St => {
                    part.dst = names.base(base);
                    part.imm = Field::Any;
                }
                _ => {
                    part.dst = names.base(base);
                    part.src = names.register(register);
                }
            }
            return part;
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
        part.dst = names.register(dst);
        let source = match src {
            Operand::Any => {
                part.imm = Field::Any;
                Source::Imm
            }
            _ => {
                part.src = names.register(src);
                Source::Reg
            }
        };
        part.op = match (AluOpc::from_name(name), JmpOpc::from_name(name), width, target) {
            (_, Some(JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit | JmpOpc::Jcond), ..) => panic!("not a conditional jump"),
            (Some(alu), None, Some(32), None) => OpCode::alu32(alu, source).0,
            (Some(alu), None, Some(64), None) => OpCode::alu64(alu, source).0,
            (None, Some(jmp), Some(32), Some(Operand::Any)) => OpCode::jmp32(jmp, source).0,
            (None, Some(jmp), None | Some(64), Some(Operand::Any)) => OpCode::jmp64(jmp, source).0,
            _ => panic!("unknown mnemonic, or a target that isn't `_`"),
        };
        if target.is_some() {
            part.off = Field::Any;
        }
        part
    }

    /// Whether the instruction reads the register of `role`.
    const fn reads(self, role: u8) -> bool {
        let opc = OpCode(self.op);
        let dst = match opc.class() {
            Class::Alu32 | Class::Alu64 => !matches!(opc.alu_opc(), AluOpc::Mov),
            Class::Ldx | Class::Ld => false,
            _ => true,
        };
        // `src` names a register only where the instruction reads one
        (dst && self.dst.is(role)) || self.src.is(role)
    }

    /// The register field the instruction writes.
    const fn written(self) -> Field {
        match OpCode(self.op).class() {
            Class::Alu32 | Class::Alu64 | Class::Ldx | Class::Ld => self.dst,
            _ => Field::Zero,
        }
    }

    /// The field of the base register, for a load or store.
    const fn base(self) -> Field {
        match OpCode(self.op).class() {
            Class::Ldx => self.src,
            Class::St | Class::Stx => self.dst,
            _ => Field::Zero,
        }
    }
}
