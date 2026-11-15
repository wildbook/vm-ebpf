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
    Off(i32),
    /// No operand.
    None,
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Reg(r) => write!(f, "{r}"),
            Operand::Imm(v) => {
                if *v < 0 {
                    write!(f, "-{:#x}", v.unsigned_abs())
                } else {
                    write!(f, "{:#x}", *v as u32)
                }
            }
            Operand::Imm64(v) => {
                if *v < 0 {
                    write!(f, "-{:#x}", v.unsigned_abs())
                } else {
                    write!(f, "{:#x}", *v as u64)
                }
            }
            Operand::Mem { base, offset } => {
                let sign = if *offset < 0 { '-' } else { '+' };
                write!(f, "[{base}{sign}{:#x}]", offset.unsigned_abs())
            }
            Operand::Off(off) => write!(f, "{off:+}"),
            Operand::None => Ok(()),
        }
    }
}
