//! The eBPF instruction as bytecode encodes it.

use std::fmt::{self, Debug, Formatter};

use crate::opcode::OpCode;

/// An eBPF instruction as bytecode encodes it: 8 little-endian bytes that hold the opcode byte, `dst_reg` and
/// `src_reg` (4 bits each), `offset` and `imm`. LD_IMM64 fills two of them.
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Instruction(pub u64);

impl Instruction {
    /// The bits of each field.
    pub(crate) const OPCODE: u64 = 0xFF;
    pub(crate) const DST_REG: u64 = 0xF00;
    pub(crate) const SRC_REG: u64 = 0xF000;
    pub(crate) const OFFSET: u64 = 0xFFFF_0000;
    pub(crate) const IMM: u64 = 0xFFFF_FFFF_0000_0000;

    /// Assemble an instruction; only the low 4 bits of `dst_reg` and `src_reg` are kept.
    pub const fn new(opcode: OpCode, dst_reg: u8, src_reg: u8, offset: i16, imm: i32) -> Self {
        const _: () = assert!(Instruction::new(OpCode(0xFF), 0x00, 0x00, 00, 00).0 == Instruction::OPCODE);
        const _: () = assert!(Instruction::new(OpCode(0x00), 0xFF, 0x00, 00, 00).0 == Instruction::DST_REG);
        const _: () = assert!(Instruction::new(OpCode(0x00), 0x00, 0xFF, 00, 00).0 == Instruction::SRC_REG);
        const _: () = assert!(Instruction::new(OpCode(0x00), 0x00, 0x00, -1, 00).0 == Instruction::OFFSET);
        const _: () = assert!(Instruction::new(OpCode(0x00), 0x00, 0x00, 00, -1).0 == Instruction::IMM);

        let imm = (imm as u32 as u64) << 32;
        let offset = (offset as u16 as u64) << 16;
        let src_reg = ((src_reg & 0xF) as u64) << 12;
        let dst_reg = ((dst_reg & 0xF) as u64) << 8;

        Self(imm | offset | src_reg | dst_reg | opcode.0 as u64)
    }

    /// Decode little-endian bytecode; a trailing partial instruction is ignored.
    // inline, so the loop gets the optimisation level of the caller
    #[inline]
    pub fn decode(bytes: &[u8]) -> Vec<Self> {
        let words = bytes.as_chunks::<8>().0;
        // room for the guard slot that `Code::new` appends
        let mut insns = Vec::with_capacity(words.len() + 1);
        insns.extend(words.iter().map(|w| Self(u64::from_le_bytes(*w))));
        insns
    }

    pub const fn opcode(self) -> OpCode {
        OpCode(self.byte())
    }

    /// The opcode byte.
    pub const fn byte(self) -> u8 {
        self.0 as u8
    }

    pub const fn dst_reg(self) -> u8 {
        ((self.0 & Self::DST_REG) >> 8) as u8
    }

    pub const fn src_reg(self) -> u8 {
        ((self.0 & Self::SRC_REG) >> 12) as u8
    }

    pub const fn offset(self) -> i16 {
        ((self.0 & Self::OFFSET) >> 16) as i16
    }

    pub const fn imm(self) -> i32 {
        ((self.0 & Self::IMM) >> 32) as i32
    }

    /// This instruction with the opcode byte `byte`.
    pub(crate) const fn with_byte(self, byte: u8) -> Self {
        Self(self.0 & !Self::OPCODE | byte as u64)
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instruction")
            .field("opcode", &self.opcode())
            .field("dst_reg", &self.dst_reg())
            .field("src_reg", &self.src_reg())
            .field("offset", &self.offset())
            .field("imm", &self.imm())
            .finish()
    }
}
