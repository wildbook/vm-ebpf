#[derive(Copy, Clone, PartialEq, Eq)]
pub struct OpCode(pub u8);

#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    #[inline(always)]
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
    #[inline(always)]
    pub const fn alu_opc(self) -> AluOpc { AluOpc::from_u8(self.0 & 0b1111_0_000) }
    #[inline(always)]
    pub const fn alu_src(self) -> Source { Source::from_u8(self.0 & 0b0000_1_000) }
    #[inline(always)]
    pub const fn alu_end(self) -> AluEnd { AluEnd::from_u8(self.0 & 0b0000_1_000) }
}

#[rustfmt::skip]
#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    #[inline(always)]
    pub const fn jmp_opc(self) -> JmpOpc { JmpOpc::from_u8(self.0 & 0b1111_0_000) }
}

#[rustfmt::skip]
#[allow(clippy::unusual_byte_groupings)]
impl OpCode {
    #[inline(always)]
    pub const fn mem_size(self) -> MemSize { MemSize::from_u8(self.0 & 0b000_11_000) }
    #[inline(always)]
    pub const fn mem_mode(self) -> MemMode { MemMode::from_u8(self.0 & 0b111_00_000) }
}

/// Declares a `#[repr(u8)]` enum covering every value of `mask` and a `from_u8` decoder for it. `mask` documents which
/// bits belong to the enum; `from_u8` asserts the input carries no other bits.
macro_rules! bits_enum {
    ($vis:vis enum $name:ident : $mask:literal { $($variant:ident = $val:expr),+ $(,)? }) => {
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
        }
    };
}

bits_enum! {
    pub enum Class : 0b0000_0111 {
        LdImm = 0x00, // 0b....'.'000
        LdReg = 0x01, // 0b....'.'001
        StImm = 0x02, // 0b....'.'010
        StReg = 0x03, // 0b....'.'011
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
        Add = 0x00,    // 0b0000'.'...
        Sub = 0x10,    // 0b0001'.'...
        Mul = 0x20,    // 0b0010'.'...
        Div = 0x30,    // 0b0011'.'...
        Or = 0x40,     // 0b0100'.'...
        And = 0x50,    // 0b0101'.'...
        Lsh = 0x60,    // 0b0110'.'...
        Rsh = 0x70,    // 0b0111'.'...
        Neg = 0x80,    // 0b1000'.'...
        Mod = 0x90,    // 0b1001'.'...
        Xor = 0xA0,    // 0b1010'.'...
        Mov = 0xB0,    // 0b1011'.'...
        Arsh = 0xC0,   // 0b1100'.'...
        End = 0xD0,    // 0b1101'.'...
        UndefE = 0xE0, // 0b1110'.'...
        UndefF = 0xF0, // 0b1111'.'...
    }
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
    pub const fn mod_32(src: Source)   -> OpCode { OpCode(Class::Alu32 as u8 | AluOpc::Mod  as u8 | src as u8) }
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
    pub const fn mod_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Mod  as u8 | src as u8) }
    pub const fn xor_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Xor  as u8 | src as u8) }
    pub const fn mov_64(src: Source)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Mov  as u8 | src as u8) }
    pub const fn arsh_64(src: Source)  -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::Arsh as u8 | src as u8) }
    pub const fn end_64(end: AluEnd)   -> OpCode { OpCode(Class::Alu64 as u8 | AluOpc::End  as u8 | end as u8) }
}

bits_enum! {
    pub enum AluEnd : 0b0000_1000 {
        ToLE = 0x00, // 0b....'0'...
        ToBE = 0x08, // 0b....'1'...
    }
}

bits_enum! {
    pub enum JmpOpc : 0b1111_0000 {
        Ja = 0x00,     // 0b0000'.'...
        Jeq = 0x10,    // 0b0001'.'...
        Jgt = 0x20,    // 0b0010'.'...
        Jge = 0x30,    // 0b0011'.'...
        Jset = 0x40,   // 0b0100'.'...
        Jne = 0x50,    // 0b0101'.'...
        Jsgt = 0x60,   // 0b0110'.'...
        Jsge = 0x70,   // 0b0111'.'...
        Call = 0x80,   // 0b1000'.'...
        Exit = 0x90,   // 0b1001'.'...
        Jlt = 0xA0,    // 0b1010'.'...
        Jle = 0xB0,    // 0b1011'.'...
        Jslt = 0xC0,   // 0b1100'.'...
        Jsle = 0xD0,   // 0b1101'.'...
        Jcond = 0xE0,  // 0b1110'.'...
        UndefF = 0xF0, // 0b1111'.'...
    }
}

bits_enum! {
    pub enum MemSize : 0b0001_1000 {
        Word = 0x00,  // 0b...'00'...
        Half = 0x08,  // 0b...'01'...
        Byte = 0x10,  // 0b...'10'...
        DWord = 0x18, // 0b...'11'...
    }
}

bits_enum! {
    pub enum MemMode : 0b1110_0000 {
        Imm = 0x00,    // 0b000'..'...
        Abs = 0x20,    // 0b001'..'...
        Ind = 0x40,    // 0b010'..'...
        Mem = 0x60,    // 0b011'..'...
        MemSX = 0x80,  // 0b100'..'...
        UndefA = 0xA0, // 0b101'..'...
        Atomic = 0xC0, // 0b110'..'...
        UndefE = 0xE0, // 0b111'..'...
    }
}
