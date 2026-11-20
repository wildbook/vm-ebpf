//! The opcode byte and its fields, as RFC 9669 lays them out, and the values of the other fields that select what an
//! opcode does: the kind of a `call` ([`call`]) and the operation of an atomic ([`atomic`]).

use std::fmt::{self, Debug, Formatter};

/// An opcode byte. Its low 3 bits are the [`Class`], which decides how the other bits read: an operation and its
/// [`Source`] for the ALU and jump classes, a [`MemSize`] and [`MemMode`] for the load and store classes.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OpCode(pub u8);

impl OpCode {
    pub const fn alu32(opc: AluOpc, src: Source) -> Self {
        OpCode(Class::Alu32 as u8 | opc as u8 | src as u8)
    }

    pub const fn alu64(opc: AluOpc, src: Source) -> Self {
        OpCode(Class::Alu64 as u8 | opc as u8 | src as u8)
    }

    /// The byte swap of the ALU32 class.
    pub const fn end32(end: AluEnd) -> Self {
        OpCode(Class::Alu32 as u8 | AluOpc::End as u8 | end as u8)
    }

    /// The byte swap of the ALU64 class.
    pub const fn end64(end: AluEnd) -> Self {
        OpCode(Class::Alu64 as u8 | AluOpc::End as u8 | end as u8)
    }

    pub const fn jmp32(opc: JmpOpc, src: Source) -> Self {
        OpCode(Class::Jmp32 as u8 | opc as u8 | src as u8)
    }

    pub const fn jmp64(opc: JmpOpc, src: Source) -> Self {
        OpCode(Class::Jmp64 as u8 | opc as u8 | src as u8)
    }

    /// A load into a register.
    pub const fn ldx(size: MemSize, mode: MemMode) -> Self {
        OpCode(Class::Ldx as u8 | size as u8 | mode as u8)
    }

    /// A store of an immediate.
    pub const fn st(size: MemSize, mode: MemMode) -> Self {
        OpCode(Class::St as u8 | size as u8 | mode as u8)
    }

    /// A store from a register.
    pub const fn stx(size: MemSize, mode: MemMode) -> Self {
        OpCode(Class::Stx as u8 | size as u8 | mode as u8)
    }
}

#[rustfmt::skip]
#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    #[inline(always)] pub const fn class(self) -> Class { Class::from_u8(self.0 & 0b00000_111) }

    #[inline(always)] pub const fn alu_opc(self) -> AluOpc { AluOpc::from_u8(self.0 & 0b1111_0_000) }
    #[inline(always)] pub const fn alu_end(self) -> AluEnd { AluEnd::from_u8(self.0 & 0b0000_1_000) }

    #[inline(always)] pub const fn jmp_opc(self) -> JmpOpc { JmpOpc::from_u8(self.0 & 0b1111_0_000) }

    /// The source operand of an ALU or jump instruction.
    #[inline(always)] pub const fn source(self) -> Source { Source::from_u8(self.0 & 0b0000_1_000) }

    #[inline(always)] pub const fn mem_size(self) -> MemSize { MemSize::from_u8(self.0 & 0b000_11_000) }
    #[inline(always)] pub const fn mem_mode(self) -> MemMode { MemMode::from_u8(self.0 & 0b111_00_000) }
}

impl OpCode {
    /// Whether the opcode is of a jump class, which holds the jumps, the calls and `exit`.
    #[inline(always)]
    pub const fn is_jump(self) -> bool {
        matches!(self.class(), Class::Jmp32 | Class::Jmp64)
    }

    /// Whether the opcode is of a class that loads from or stores to memory: LDX, ST or STX.
    #[inline(always)]
    pub const fn is_access(self) -> bool {
        matches!(self.class(), Class::Ldx | Class::St | Class::Stx)
    }
}

/// The opcode byte of LD_IMM64, whose two slots load a 64-bit immediate.
pub const LD_IMM64: u8 = OpCode(Class::Ld as u8 | MemMode::Imm as u8 | MemSize::DWord as u8).0;

/// The opcode byte of `call`: a helper, local or kfunc call, as `src_reg` selects ([`call`]).
pub const CALL: u8 = OpCode::jmp64(JmpOpc::Call, Source::Imm).0;

/// The opcode byte of `callx`: a call through the address in `dst_reg`.
pub const CALLX: u8 = OpCode::jmp64(JmpOpc::Call, Source::Reg).0;

/// The `src_reg` of a [`CALL`], which selects what it calls.
pub mod call {
    /// The helper with the ID in `imm`.
    pub const HELPER: u8 = 0;
    /// The function of the program at the offset in `imm` (`BPF_PSEUDO_CALL`).
    pub const LOCAL: u8 = 1;
    /// The external function with the ID in `imm` (`BPF_PSEUDO_KFUNC_CALL`).
    pub const KFUNC: u8 = 2;
}

/// The `imm` of an `STX | ATOMIC` instruction, which selects its operation.
pub mod atomic {
    pub const ADD: i32 = 0x00;
    pub const OR: i32 = 0x40;
    pub const AND: i32 = 0x50;
    pub const XOR: i32 = 0xa0;
    pub const XCHG: i32 = 0xe0 | FETCH;
    /// Compares with r0 and writes the old value there.
    pub const CMPXCHG: i32 = 0xf0 | FETCH;
    /// Set in a read-modify-write operation that writes the old value to `src_reg`.
    pub const FETCH: i32 = 0x01;
    /// Load-acquire, which reads through `src_reg` into `dst_reg`; any size.
    pub const LOAD_ACQ: i32 = 0x100;
    /// Store-release; any size.
    pub const STORE_REL: i32 = 0x110;
}

/// Declares a `#[repr(u8)]` enum covering every value of `mask`, a `from_u8` decoder for it and a `from_name` lookup
/// by mnemonic. `mask` documents which bits belong to the enum; `from_u8` asserts the input carries no other bits. A
/// variant's mnemonic is its name in any case; `Variant("name")` gives it another one, and `Variant(_)` none.
macro_rules! bits_enum {
    ($vis:vis enum $name:ident : $mask:literal { $($variant:ident $(($mnemonic:tt))? = $val:expr),+ $(,)? }) => {
        #[repr(u8)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        $vis enum $name {
            $($variant = $val),+
        }

        impl $name {
            #[inline(always)]
            pub const fn from_u8(x: u8) -> Self {
                debug_assert!((x & !$mask) == 0);
                match x {
                    $(x if x == $name::$variant as u8 => $name::$variant,)+
                    _ => unreachable!(),
                }
            }

            /// The variant with the mnemonic `name`, ignoring case.
            pub const fn from_name(name: &[u8]) -> Option<Self> {
                $(bits_enum!(@match name, $variant $($mnemonic)?);)+
                None
            }
        }
    };
    (@match $name:ident, $variant:ident) => {
        bits_enum!(@match $name, $variant stringify!($variant))
    };
    (@match $name:ident, $variant:ident _) => {};
    (@match $name:ident, $variant:ident $mnemonic:expr) => {
        if $name.eq_ignore_ascii_case($mnemonic.as_bytes()) {
            return Some(Self::$variant);
        }
    };
}

bits_enum! {
    pub enum Class : 0b0000_0111 {
        Ld = 0x00,    // 0b....'.'000
        Ldx = 0x01,   // 0b....'.'001
        St = 0x02,    // 0b....'.'010
        Stx = 0x03,   // 0b....'.'011
        Alu32 = 0x04, // 0b....'.'100
        Jmp64 = 0x05, // 0b....'.'101
        Jmp32 = 0x06, // 0b....'.'110
        Alu64 = 0x07, // 0b....'.'111
    }
}

bits_enum! {
    pub enum Source : 0b0000_1000 {
        Imm = 0x00, // 0b....'0'...
        Reg = 0x08, // 0b....'1'...
    }
}

bits_enum! {
    pub enum AluOpc : 0b1111_0000 {
        Add = 0x00,       // 0b0000'.'...
        Sub = 0x10,       // 0b0001'.'...
        Mul = 0x20,       // 0b0010'.'...
        Div = 0x30,       // 0b0011'.'...
        Or = 0x40,        // 0b0100'.'...
        And = 0x50,       // 0b0101'.'...
        Lsh = 0x60,       // 0b0110'.'...
        Rsh = 0x70,       // 0b0111'.'...
        Neg = 0x80,       // 0b1000'.'...
        Mod = 0x90,       // 0b1001'.'...
        Xor = 0xA0,       // 0b1010'.'...
        Mov = 0xB0,       // 0b1011'.'...
        Arsh = 0xC0,      // 0b1100'.'...
        End = 0xD0,       // 0b1101'.'...
        UndefE(_) = 0xE0, // 0b1110'.'...
        UndefF(_) = 0xF0, // 0b1111'.'...
    }
}

bits_enum! {
    pub enum AluEnd : 0b0000_1000 {
        ToLE = 0x00, // 0b....'0'...
        ToBE = 0x08, // 0b....'1'...
    }
}

bits_enum! {
    pub enum JmpOpc : 0b1111_0000 {
        Ja = 0x00,        // 0b0000'.'...
        Jeq = 0x10,       // 0b0001'.'...
        Jgt = 0x20,       // 0b0010'.'...
        Jge = 0x30,       // 0b0011'.'...
        Jset = 0x40,      // 0b0100'.'...
        Jne = 0x50,       // 0b0101'.'...
        Jsgt = 0x60,      // 0b0110'.'...
        Jsge = 0x70,      // 0b0111'.'...
        Call = 0x80,      // 0b1000'.'...
        Exit = 0x90,      // 0b1001'.'...
        Jlt = 0xA0,       // 0b1010'.'...
        Jle = 0xB0,       // 0b1011'.'...
        Jslt = 0xC0,      // 0b1100'.'...
        Jsle = 0xD0,      // 0b1101'.'...
        Jcond = 0xE0,     // 0b1110'.'...
        UndefF(_) = 0xF0, // 0b1111'.'...
    }
}

bits_enum! {
    pub enum MemSize : 0b0001_1000 {
        Word("w") = 0x00,   // 0b...'00'...
        Half("h") = 0x08,   // 0b...'01'...
        Byte("b") = 0x10,   // 0b...'10'...
        DWord("dw") = 0x18, // 0b...'11'...
    }
}

impl MemSize {
    /// The number of bytes an access of this size reads or writes.
    pub const fn bytes(self) -> usize {
        match self {
            MemSize::Byte => 1,
            MemSize::Half => 2,
            MemSize::Word => 4,
            MemSize::DWord => 8,
        }
    }
}

bits_enum! {
    pub enum MemMode : 0b1110_0000 {
        Imm = 0x00,       // 0b000'..'...
        Abs = 0x20,       // 0b001'..'...
        Ind = 0x40,       // 0b010'..'...
        Mem = 0x60,       // 0b011'..'...
        MemSX = 0x80,     // 0b100'..'...
        UndefA(_) = 0xA0, // 0b101'..'...
        Atomic = 0xC0,    // 0b110'..'...
        UndefE(_) = 0xE0, // 0b111'..'...
    }
}

#[rustfmt::skip]
impl Debug for OpCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dstr = f.debug_struct("OpCode");
        dstr.field("class", &self.class());

        match self.class() {
            | Class::Ld
            | Class::Ldx
            | Class::St
            | Class::Stx => {
                dstr.field("size", &self.mem_size())
                    .field("mode", &self.mem_mode());
            },

            | Class::Jmp64
            | Class::Jmp32 => {
                dstr.field("opc", &self.jmp_opc())
                    .field("src", &self.source());
            },

            | Class::Alu32
            | Class::Alu64 => {
                dstr.field("opc", &self.alu_opc());
                match self.alu_opc() == AluOpc::End {
                    true => dstr.field("end", &self.alu_end()),
                    false => dstr.field("src", &self.source()),
                };
            },
        };

        dstr.finish()
    }
}
