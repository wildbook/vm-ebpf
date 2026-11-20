use crate::opcode::OpCode;

/// An eBPF instruction as bytecode encodes it: 8 little-endian bytes that hold the opcode byte, `dst_reg` and
/// `src_reg` (4 bits each), `offset` and `imm`. LD_IMM64 fills two of them.
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Instruction(pub u64);

impl Instruction {
    /// Assemble an instruction; only the low 4 bits of `dst` and `src` are kept.
    pub const fn from_parts(opc: OpCode, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        const _: () = assert!(Instruction::from_parts(OpCode(0xFF), 0x00, 0x00, 00, 00).0 == 0x00000000000000FF);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x0F, 0x00, 00, 00).0 == 0x0000000000000F00);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x00, 0x0F, 00, 00).0 == 0x000000000000F000);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x00, 0x00, -1, 00).0 == 0x00000000FFFF0000);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x00, 0x00, 00, -1).0 == 0xFFFFFFFF00000000);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0xFF, 0xFF, 00, 00).0 == 0x000000000000FF00);

        let imm = (imm as u32 as u64) << 32;
        let off = (off as u16 as u64) << 16;
        let src = ((src & 0xF) as u64) << 12;
        let dst = ((dst & 0xF) as u64) << 8;
        let opc = opc.0 as u64;

        Self(imm | off | src | dst | opc)
    }

    pub const fn imm(self) -> i32 {
        ((self.0 & 0xFFFFFFFF00000000) >> 32) as i32
    }

    pub const fn offset(self) -> i16 {
        ((self.0 & 0x00000000FFFF0000) >> 16) as i16
    }

    pub const fn src_reg(self) -> u8 {
        ((self.0 & 0x000000000000F000) >> 12) as u8
    }

    pub const fn dst_reg(self) -> u8 {
        ((self.0 & 0x0000000000000F00) >> 8) as u8
    }

    pub const fn opcode(self) -> OpCode {
        OpCode((self.0 & 0x00000000000000FF) as u8)
    }

    /// The opcode byte.
    pub const fn byte(self) -> u8 {
        self.0 as u8
    }

    /// This instruction with the opcode byte `byte`.
    pub const fn with_opcode(self, byte: u8) -> Self {
        Self(self.0 & !0xFF | byte as u64)
    }
}

/// Decode little-endian bytecode for [`Code::new`](crate::Code::new); a trailing partial word is ignored.
// inline, so the loop gets the optimisation level of the caller
#[inline]
pub fn decode_instructions(bytes: &[u8]) -> Vec<Instruction> {
    let words = bytes.as_chunks::<8>().0;
    // room for the guard slot that `Code::new` appends
    let mut insns = Vec::with_capacity(words.len() + 1);
    insns.extend(words.iter().map(|w| Instruction(u64::from_le_bytes(*w))));
    insns
}

/// `src_reg` of a `call` instruction targeting a program-local function.
pub const BPF_PSEUDO_CALL: u8 = 1;
/// `src_reg` of a `call` instruction targeting the host's extern table.
pub const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
