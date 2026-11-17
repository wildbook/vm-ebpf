//! Decoded eBPF instruction representation.

use std::fmt;

use crate::mnemonic::Mnemonic;
use crate::operand::Operand;

/// A decoded eBPF instruction with full metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// The instruction mnemonic.
    pub mnemonic: Mnemonic,
    /// Destination operand (usually a register).
    pub dst: Operand,
    /// Source operand (register, immediate, or memory).
    pub src: Operand,
    /// Byte offset within the bytecode.
    pub offset: u64,
    /// Size in bytes (8 for normal instructions, 16 for LDDW).
    pub size: u8,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Raw instruction bytes (first 8 bytes).
    pub raw: u64,
    /// Second 8 bytes for wide instructions (LDDW).
    pub raw2: Option<u64>,
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = &self.mnemonic;
        write!(f, "{mnemonic}")?;

        match (&self.dst, &self.src) {
            (Operand::None, Operand::None) => {}
            (dst, Operand::None) => write!(f, " {dst}")?,
            (Operand::None, src) => write!(f, " {src}")?,
            (dst, src) => write!(f, " {dst}, {src}")?,
        }

        Ok(())
    }
}

/// Raw eBPF instruction (8 bytes, little-endian).
///
/// Layout:
/// - Bits 0-7: opcode
/// - Bits 8-11: dst register
/// - Bits 12-15: src register
/// - Bits 16-31: offset (signed)
/// - Bits 32-63: immediate (signed)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct RawInstruction(pub u64);

impl RawInstruction {
    /// Wrap a raw instruction word.
    #[inline]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Create from parts.
    #[inline]
    pub const fn from_parts(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
        let imm = (imm as u32 as u64) << 32;
        let off = (offset as u16 as u64) << 16;
        let src = ((src & 0xF) as u64) << 12;
        let dst = ((dst & 0xF) as u64) << 8;
        let opc = opcode as u64;
        Self(imm | off | src | dst | opc)
    }

    /// Get the opcode byte.
    #[inline]
    pub const fn opcode(self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    /// Get the destination register (4 bits).
    #[inline]
    pub const fn dst(self) -> u8 {
        ((self.0 >> 8) & 0xF) as u8
    }

    /// Get the source register (4 bits).
    #[inline]
    pub const fn src(self) -> u8 {
        ((self.0 >> 12) & 0xF) as u8
    }

    /// Get the offset (signed 16-bit).
    #[inline]
    pub const fn offset(self) -> i16 {
        ((self.0 >> 16) & 0xFFFF) as i16
    }

    /// Get the immediate value (signed 32-bit).
    #[inline]
    pub const fn imm(self) -> i32 {
        ((self.0 >> 32) & 0xFFFFFFFF) as i32
    }

    /// Get the raw u64 value.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Convert to little-endian bytes.
    #[inline]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Create from little-endian bytes.
    #[inline]
    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }
}

/// eBPF instruction class constants (bits 0-2 of opcode).
#[allow(missing_docs)]
pub mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU32: u8 = 0x04;
    pub const JMP64: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

/// ALU operation codes (bits 4-7 of opcode).
#[allow(missing_docs)]
pub mod alu {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xA0;
    pub const MOV: u8 = 0xB0;
    pub const ARSH: u8 = 0xC0;
    pub const END: u8 = 0xD0;
}

/// Jump operation codes (bits 4-7 of opcode).
#[allow(missing_docs)]
pub mod jmp {
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xA0;
    pub const JLE: u8 = 0xB0;
    pub const JSLT: u8 = 0xC0;
    pub const JSLE: u8 = 0xD0;
    pub const JCOND: u8 = 0xE0;
}

/// Memory size codes (bits 3-4 of opcode).
#[allow(missing_docs)]
pub mod size {
    pub const W: u8 = 0x00; // 32-bit word
    pub const H: u8 = 0x08; // 16-bit half
    pub const B: u8 = 0x10; // 8-bit byte
    pub const DW: u8 = 0x18; // 64-bit double word
}

/// Memory addressing mode codes (bits 5-7 of opcode).
#[allow(missing_docs)]
pub mod mode {
    pub const IMM: u8 = 0x00;
    pub const ABS: u8 = 0x20;
    pub const IND: u8 = 0x40;
    pub const MEM: u8 = 0x60;
    pub const MEMSX: u8 = 0x80;
    pub const ATOMIC: u8 = 0xC0;
}

/// Atomic operation codes (encoded in the imm field for ATOMIC mode).
#[allow(missing_docs)]
pub mod atomic {
    pub const ADD: i32 = 0x00;
    pub const OR: i32 = 0x40;
    pub const AND: i32 = 0x50;
    pub const XOR: i32 = 0xa0;
    pub const XCHG: i32 = 0xe1;
    pub const CMPXCHG: i32 = 0xf1;
    /// Fetch variant flag: the prior value is written back to `src`.
    pub const FETCH: i32 = 0x01;
}

/// Source is immediate value (K).
pub const SRC_IMM: u8 = 0x00;
/// Source is register (X).
pub const SRC_REG: u8 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_instruction_parts() {
        let raw = RawInstruction::from_parts(0xBF, 1, 2, -16, 42);
        assert_eq!(raw.opcode(), 0xBF);
        assert_eq!(raw.dst(), 1);
        assert_eq!(raw.src(), 2);
        assert_eq!(raw.offset(), -16);
        assert_eq!(raw.imm(), 42);
    }
}
