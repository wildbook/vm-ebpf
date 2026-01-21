//! eBPF instruction operand types.

use std::fmt;

use crate::register::Register;

/// Operand type for decoded instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// Register operand.
    Reg(Register),
    /// Immediate value (32-bit, sign-extended).
    Imm(i32),
    /// 64-bit immediate value (for LDDW).
    Imm64(i64),
    /// Memory operand: `[base_reg + offset]`.
    #[allow(missing_docs)]
    Mem { base: Register, offset: i16 },
    /// Offset for jumps (relative to next instruction).
    Off(i16),
    /// No operand.
    None,
}

impl Operand {
    /// Check if this is a register operand.
    #[inline]
    pub const fn is_reg(&self) -> bool {
        matches!(self, Operand::Reg(_))
    }

    /// Check if this is an immediate operand.
    #[inline]
    pub const fn is_imm(&self) -> bool {
        matches!(self, Operand::Imm(_) | Operand::Imm64(_))
    }

    /// Check if this is a memory operand.
    #[inline]
    pub const fn is_mem(&self) -> bool {
        matches!(self, Operand::Mem { .. })
    }

    /// Check if this is a none/empty operand.
    #[inline]
    pub const fn is_none(&self) -> bool {
        matches!(self, Operand::None)
    }

    /// Get the register if this is a register operand.
    #[inline]
    pub const fn as_reg(&self) -> Option<Register> {
        match self {
            Operand::Reg(r) => Some(*r),
            _ => None,
        }
    }

    /// Get the immediate value if this is an immediate operand.
    #[inline]
    pub const fn as_imm(&self) -> Option<i64> {
        match self {
            Operand::Imm(v) => Some(*v as i64),
            Operand::Imm64(v) => Some(*v),
            _ => None,
        }
    }

    /// Get memory base and offset if this is a memory operand.
    #[inline]
    pub const fn as_mem(&self) -> Option<(Register, i16)> {
        match self {
            Operand::Mem { base, offset } => Some((*base, *offset)),
            _ => None,
        }
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Reg(r) => write!(f, "{r}"),
            Operand::Imm(v) => {
                if *v < 0 {
                    let abs = (-*v) as u32;
                    write!(f, "-{abs:#x}")
                } else {
                    let val = *v as u32;
                    write!(f, "{val:#x}")
                }
            }
            Operand::Imm64(v) => {
                if *v < 0 {
                    let abs = (-*v) as u64;
                    write!(f, "-{abs:#x}")
                } else {
                    let val = *v as u64;
                    write!(f, "{val:#x}")
                }
            }
            Operand::Mem { base, offset } => {
                if *offset >= 0 {
                    let off = *offset as u16;
                    write!(f, "[{base}+{off:#x}]")
                } else {
                    let off = (-*offset) as u16;
                    write!(f, "[{base}-{off:#x}]")
                }
            }
            Operand::Off(off) => {
                if *off >= 0 {
                    write!(f, "+{off}")
                } else {
                    write!(f, "{off}")
                }
            }
            Operand::None => Ok(()),
        }
    }
}

/// Memory size for load/store operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemSize {
    /// Byte (8-bit)
    Byte,
    /// Half-word (16-bit)
    Half,
    /// Word (32-bit)
    Word,
    /// Double-word (64-bit)
    DWord,
}

impl MemSize {
    /// Get the size in bytes.
    #[inline]
    pub const fn bytes(self) -> u8 {
        match self {
            MemSize::Byte => 1,
            MemSize::Half => 2,
            MemSize::Word => 4,
            MemSize::DWord => 8,
        }
    }

    /// Get the size in bits.
    #[inline]
    pub const fn bits(self) -> u8 {
        self.bytes() * 8
    }
}

impl fmt::Display for MemSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemSize::Byte => f.write_str("b"),
            MemSize::Half => f.write_str("h"),
            MemSize::Word => f.write_str("w"),
            MemSize::DWord => f.write_str("dw"),
        }
    }
}
