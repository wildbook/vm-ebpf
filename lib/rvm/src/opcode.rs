use crate::consts::{alu, class, jmp, mem, BPF_K, BPF_X};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OpCode(pub u8);

#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    pub const fn class(self) -> Class {
        Class::from_u8(self.0 & 0b00000_111)
    }
}

impl OpCode {
    pub const fn stimm_from_parts(size: MemSize, mode: MemMode) -> Self {
        OpCode(Class::StImm as u8 | size as u8 | mode as u8)
    }

    pub const fn streg_from_parts(size: MemSize, mode: MemMode) -> Self {
        OpCode(Class::StReg as u8 | size as u8 | mode as u8)
    }

    pub const fn ldreg_from_parts(size: MemSize, mode: MemMode) -> Self {
        OpCode(Class::LdReg as u8 | size as u8 | mode as u8)
    }

    pub const fn jmp32_from_parts(opc: JmpOpc, src: Source) -> Self {
        OpCode(Class::Jmp32 as u8 | opc as u8 | src as u8)
    }

    pub const fn jmp64_from_parts(opc: JmpOpc, src: Source) -> Self {
        OpCode(Class::Jmp64 as u8 | opc as u8 | src as u8)
    }
}

#[rustfmt::skip]
#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    pub const fn alu_opc(self) -> AluOpc { AluOpc::from_u8(self.0 & 0b1111_0_000) }
    pub const fn alu_src(self) -> Source { Source::from_u8(self.0 & 0b0000_1_000) }
    pub const fn alu_end(self) -> AluEnd { AluEnd::from_u8(self.0 & 0b0000_1_000) }
}

#[rustfmt::skip]
#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    pub const fn jmp_opc(self) -> JmpOpc { JmpOpc::from_u8(self.0 & 0b1111_0_000) }
    pub const fn jmp_src(self) -> Source { Source::from_u8(self.0 & 0b0000_1_000) }
}

#[rustfmt::skip]
#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    pub const fn mem_size(self) -> MemSize { MemSize::from_u8(self.0 & 0b000_11_000) }
    pub const fn mem_mode(self) -> MemMode { MemMode::from_u8(self.0 & 0b111_00_000) }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Class {
    LdImm = class::BPF_LD,     // 0b....'.'000
    LdReg = class::BPF_LDX,    // 0b....'.'001
    StImm = class::BPF_ST,     // 0b....'.'010
    StReg = class::BPF_STX,    // 0b....'.'011
    Alu32 = class::BPF_ALU_32, // 0b....'.'100
    Jmp64 = class::BPF_JMP_64, // 0b....'.'101
    Jmp32 = class::BPF_JMP_32, // 0b....'.'110
    Alu64 = class::BPF_ALU_64, // 0b....'.'111
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Imm = BPF_K, // 0b....'0'...
    Reg = BPF_X, // 0b....'1'...
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AluOpc {
    Add = alu::BPF_ADD,   // 0b0000'.'...
    Sub = alu::BPF_SUB,   // 0b0001'.'...
    Mul = alu::BPF_MUL,   // 0b0010'.'...
    Div = alu::BPF_DIV,   // 0b0011'.'...
    Or = alu::BPF_OR,     // 0b0100'.'...
    And = alu::BPF_AND,   // 0b0101'.'...
    Lsh = alu::BPF_LSH,   // 0b0110'.'...
    Rsh = alu::BPF_RSH,   // 0b0111'.'...
    Neg = alu::BPF_NEG,   // 0b1000'.'...
    Mod = alu::BPF_MOD,   // 0b1001'.'...
    Xor = alu::BPF_XOR,   // 0b1010'.'...
    Mov = alu::BPF_MOV,   // 0b1011'.'...
    Arsh = alu::BPF_ARSH, // 0b1100'.'...
    End = alu::BPF_END,   // 0b1101'.'...
    UndefE = 0xE0,        // 0b1110'.'...
    UndefF = 0xF0,        // 0b1111'.'...
}

#[rustfmt::skip]
impl AluOpc {
    pub const fn add_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Add  as u8 | src as u8) }
    pub const fn sub_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Sub  as u8 | src as u8) }
    pub const fn mul_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Mul  as u8 | src as u8) }
    pub const fn div_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Div  as u8 | src as u8) }
    pub const fn or_32(src: Source)    -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Or   as u8 | src as u8) }
    pub const fn and_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::And  as u8 | src as u8) }
    pub const fn lsh_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Lsh  as u8 | src as u8) }
    pub const fn rsh_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Rsh  as u8 | src as u8) }
    pub const fn neg_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Neg  as u8 | src as u8) }
    pub const fn r#mod_32(src: Source) -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Mod  as u8 | src as u8) }
    pub const fn xor_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Xor  as u8 | src as u8) }
    pub const fn mov_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Mov  as u8 | src as u8) }
    pub const fn arsh_32(src: Source)  -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Arsh as u8 | src as u8) }
    pub const fn end_32(end: AluEnd)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::End  as u8 | end as u8) }
    
    pub const fn add_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Add  as u8 | src as u8) }
    pub const fn sub_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Sub  as u8 | src as u8) }
    pub const fn mul_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Mul  as u8 | src as u8) }
    pub const fn div_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Div  as u8 | src as u8) }
    pub const fn or_64(src: Source)    -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Or   as u8 | src as u8) }
    pub const fn and_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::And  as u8 | src as u8) }
    pub const fn lsh_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Lsh  as u8 | src as u8) }
    pub const fn rsh_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Rsh  as u8 | src as u8) }
    pub const fn neg_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Neg  as u8 | src as u8) }
    pub const fn r#mod_64(src: Source) -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Mod  as u8 | src as u8) }
    pub const fn xor_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Xor  as u8 | src as u8) }
    pub const fn mov_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Mov  as u8 | src as u8) }
    pub const fn arsh_64(src: Source)  -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Arsh as u8 | src as u8) }
    pub const fn end_64(end: AluEnd)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::End  as u8 | end as u8) }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AluEnd {
    ToLE = alu::BPF_TO_LE, // 0b....'0'...
    ToBE = alu::BPF_TO_BE, // 0b....'1'...
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JmpOpc {
    Ja = jmp::BPF_JA,     // 0b0000'.'...
    Jeq = jmp::BPF_JEQ,   // 0b0001'.'...
    Jgt = jmp::BPF_JGT,   // 0b0010'.'...
    Jge = jmp::BPF_JGE,   // 0b0011'.'...
    Jset = jmp::BPF_JSET, // 0b0100'.'...
    Jne = jmp::BPF_JNE,   // 0b0101'.'...
    Jsgt = jmp::BPF_JSGT, // 0b0110'.'...
    Jsge = jmp::BPF_JSGE, // 0b0111'.'...
    Call = jmp::BPF_CALL, // 0b1000'.'...
    Exit = jmp::BPF_EXIT, // 0b1001'.'...
    Jlt = jmp::BPF_JLT,   // 0b1010'.'...
    Jle = jmp::BPF_JLE,   // 0b1011'.'...
    Jslt = jmp::BPF_JSLT, // 0b1100'.'...
    Jsle = jmp::BPF_JSLE, // 0b1101'.'...
    UndefE = 0xE0,        // 0b1110'.'...
    UndefF = 0xF0,        // 0b1111'.'...
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemSize {
    Word = mem::size::BPF_W,   // 0b...'00'...
    Half = mem::size::BPF_H,   // 0b...'01'...
    Byte = mem::size::BPF_B,   // 0b...'10'...
    DWord = mem::size::BPF_DW, // 0b...'11'...
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemMode {
    Imm = mem::mode::BPF_IMM,       // 0b000'..'...
    Abs = mem::mode::BPF_ABS,       // 0b001'..'...
    Ind = mem::mode::BPF_IND,       // 0b010'..'...
    Mem = mem::mode::BPF_MEM,       // 0b011'..'...
    MemSX = mem::mode::BPF_MEM_SX,  // 0b100'..'...
    UndefA = 0xA0,                  // 0b101'..'...
    Atomic = mem::mode::BPF_ATOMIC, // 0b110'..'...
    UndefE = 0xE0,                  // 0b111'..'...
}

impl Class {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b00000_111) == 0);
        match x {
            x if x == Class::LdImm as u8 => Class::LdImm,
            x if x == Class::LdReg as u8 => Class::LdReg,
            x if x == Class::StImm as u8 => Class::StImm,
            x if x == Class::StReg as u8 => Class::StReg,
            x if x == Class::Alu32 as u8 => Class::Alu32,
            x if x == Class::Jmp64 as u8 => Class::Jmp64,
            x if x == Class::Jmp32 as u8 => Class::Jmp32,
            x if x == Class::Alu64 as u8 => Class::Alu64,
            _ => unreachable!(),
        }
    }
}

impl Source {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b0000_1_000) == 0);
        match x {
            x if x == Source::Imm as u8 => Source::Imm,
            x if x == Source::Reg as u8 => Source::Reg,
            _ => unreachable!(),
        }
    }
}

impl AluOpc {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b1111_0_000) == 0);
        match x {
            x if x == AluOpc::Add as u8 => AluOpc::Add,
            x if x == AluOpc::Sub as u8 => AluOpc::Sub,
            x if x == AluOpc::Mul as u8 => AluOpc::Mul,
            x if x == AluOpc::Div as u8 => AluOpc::Div,
            x if x == AluOpc::Or as u8 => AluOpc::Or,
            x if x == AluOpc::And as u8 => AluOpc::And,
            x if x == AluOpc::Lsh as u8 => AluOpc::Lsh,
            x if x == AluOpc::Rsh as u8 => AluOpc::Rsh,
            x if x == AluOpc::Neg as u8 => AluOpc::Neg,
            x if x == AluOpc::Mod as u8 => AluOpc::Mod,
            x if x == AluOpc::Xor as u8 => AluOpc::Xor,
            x if x == AluOpc::Mov as u8 => AluOpc::Mov,
            x if x == AluOpc::Arsh as u8 => AluOpc::Arsh,
            x if x == AluOpc::End as u8 => AluOpc::End,

            x if x == AluOpc::UndefE as u8 => AluOpc::UndefE,
            x if x == AluOpc::UndefF as u8 => AluOpc::UndefF,
            _ => unreachable!(),
        }
    }
}

impl AluEnd {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b0000_1_000) == 0);
        match x {
            x if x == AluEnd::ToLE as u8 => AluEnd::ToLE,
            x if x == AluEnd::ToBE as u8 => AluEnd::ToBE,
            _ => unreachable!(),
        }
    }
}

impl JmpOpc {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b1111_0_000) == 0);
        match x {
            x if x == JmpOpc::Ja as u8 => JmpOpc::Ja,
            x if x == JmpOpc::Jeq as u8 => JmpOpc::Jeq,
            x if x == JmpOpc::Jgt as u8 => JmpOpc::Jgt,
            x if x == JmpOpc::Jge as u8 => JmpOpc::Jge,
            x if x == JmpOpc::Jset as u8 => JmpOpc::Jset,
            x if x == JmpOpc::Jne as u8 => JmpOpc::Jne,
            x if x == JmpOpc::Jsgt as u8 => JmpOpc::Jsgt,
            x if x == JmpOpc::Jsge as u8 => JmpOpc::Jsge,
            x if x == JmpOpc::Call as u8 => JmpOpc::Call,
            x if x == JmpOpc::Exit as u8 => JmpOpc::Exit,
            x if x == JmpOpc::Jlt as u8 => JmpOpc::Jlt,
            x if x == JmpOpc::Jle as u8 => JmpOpc::Jle,
            x if x == JmpOpc::Jslt as u8 => JmpOpc::Jslt,
            x if x == JmpOpc::Jsle as u8 => JmpOpc::Jsle,

            x if x == JmpOpc::UndefE as u8 => JmpOpc::UndefE,
            x if x == JmpOpc::UndefF as u8 => JmpOpc::UndefF,
            _ => unreachable!(),
        }
    }
}

impl MemSize {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b000_11_000) == 0);
        match x {
            x if x == MemSize::Word as u8 => MemSize::Word,
            x if x == MemSize::Half as u8 => MemSize::Half,
            x if x == MemSize::Byte as u8 => MemSize::Byte,
            x if x == MemSize::DWord as u8 => MemSize::DWord,
            _ => unreachable!(),
        }
    }
}

impl MemMode {
    pub const fn from_u8(x: u8) -> Self {
        debug_assert!((x & !0b111_00_000) == 0);
        match x {
            x if x == MemMode::Imm as u8 => MemMode::Imm,
            x if x == MemMode::Abs as u8 => MemMode::Abs,
            x if x == MemMode::Ind as u8 => MemMode::Ind,
            x if x == MemMode::Mem as u8 => MemMode::Mem,
            x if x == MemMode::MemSX as u8 => MemMode::MemSX,
            x if x == MemMode::Atomic as u8 => MemMode::Atomic,

            x if x == MemMode::UndefA as u8 => MemMode::UndefA,
            x if x == MemMode::UndefE as u8 => MemMode::UndefE,
            _ => unreachable!(),
        }
    }
}
