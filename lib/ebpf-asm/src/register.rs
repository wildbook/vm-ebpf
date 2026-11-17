//! eBPF register definitions.
//!
//! eBPF has 11 registers (R0-R10):
//! - R0: Return value from function calls and exit value
//! - R1-R5: Function call arguments
//! - R6-R9: Callee-saved registers
//! - R10: Read-only frame pointer (stack base)

use std::fmt;

/// eBPF register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Register {
    R0 = 0,
    R1 = 1,
    R2 = 2,
    R3 = 3,
    R4 = 4,
    R5 = 5,
    R6 = 6,
    R7 = 7,
    R8 = 8,
    R9 = 9,
    /// Frame pointer (read-only stack base).
    R10 = 10,
}

impl Register {
    /// Create a register from a 4-bit value (0-10). Returns `None` if the value is out of range.
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Register> {
        match value {
            0 => Some(Register::R0),
            1 => Some(Register::R1),
            2 => Some(Register::R2),
            3 => Some(Register::R3),
            4 => Some(Register::R4),
            5 => Some(Register::R5),
            6 => Some(Register::R6),
            7 => Some(Register::R7),
            8 => Some(Register::R8),
            9 => Some(Register::R9),
            10 => Some(Register::R10),
            _ => None,
        }
    }

    /// Get the register number (0-10).
    #[inline]
    pub const fn number(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.number())
    }
}

#[allow(missing_docs)]
pub const R0: Register = Register::R0;
#[allow(missing_docs)]
pub const R1: Register = Register::R1;
#[allow(missing_docs)]
pub const R2: Register = Register::R2;
#[allow(missing_docs)]
pub const R3: Register = Register::R3;
#[allow(missing_docs)]
pub const R4: Register = Register::R4;
#[allow(missing_docs)]
pub const R5: Register = Register::R5;
#[allow(missing_docs)]
pub const R6: Register = Register::R6;
#[allow(missing_docs)]
pub const R7: Register = Register::R7;
#[allow(missing_docs)]
pub const R8: Register = Register::R8;
#[allow(missing_docs)]
pub const R9: Register = Register::R9;
#[allow(missing_docs)]
pub const R10: Register = Register::R10;
/// Alias for the frame pointer register.
pub const FP: Register = Register::R10;
