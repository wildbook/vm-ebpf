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
    /// All registers in order.
    pub const ALL: [Register; 11] = [
        Register::R0,
        Register::R1,
        Register::R2,
        Register::R3,
        Register::R4,
        Register::R5,
        Register::R6,
        Register::R7,
        Register::R8,
        Register::R9,
        Register::R10,
    ];

    /// Create a register from a 4-bit value (0-10).
    /// Returns `None` if the value is out of range.
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

    /// Check if this is the frame pointer register.
    #[inline]
    pub const fn is_frame_pointer(self) -> bool {
        matches!(self, Register::R10)
    }

    /// Check if this is a callee-saved register (R6-R9).
    #[inline]
    pub const fn is_callee_saved(self) -> bool {
        matches!(self, Register::R6 | Register::R7 | Register::R8 | Register::R9)
    }

    /// Check if this is an argument register (R1-R5).
    #[inline]
    pub const fn is_argument(self) -> bool {
        matches!(self, Register::R1 | Register::R2 | Register::R3 | Register::R4 | Register::R5)
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.number())
    }
}

impl TryFrom<u8> for Register {
    type Error = InvalidRegister;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Register::from_u8(value).ok_or(InvalidRegister(value))
    }
}

/// Error returned when trying to create a register from an invalid value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidRegister(pub u8);

impl fmt::Display for InvalidRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid register: {}", self.0)
    }
}

impl std::error::Error for InvalidRegister {}

// Convenient register constants
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_from_u8() {
        for i in 0..=10 {
            assert!(Register::from_u8(i).is_some());
        }
        assert!(Register::from_u8(11).is_none());
        assert!(Register::from_u8(15).is_none());
    }

    #[test]
    fn test_register_display() {
        assert_eq!(format!("{R0}"), "r0");
        assert_eq!(format!("{R10}"), "r10");
    }

    #[test]
    fn test_register_properties() {
        assert!(R10.is_frame_pointer());
        assert!(!R0.is_frame_pointer());

        assert!(R6.is_callee_saved());
        assert!(R9.is_callee_saved());
        assert!(!R0.is_callee_saved());
        assert!(!R10.is_callee_saved());

        assert!(R1.is_argument());
        assert!(R5.is_argument());
        assert!(!R0.is_argument());
        assert!(!R6.is_argument());
    }
}
