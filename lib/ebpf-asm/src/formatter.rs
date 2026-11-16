//! eBPF instruction formatting.
//!
//! Provides customizable text formatting for decoded instructions.

use std::fmt::Write;

use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;
use crate::operand::Operand;

/// eBPF instruction formatter.
///
/// Produces output like:
/// - `mov64 r0, 0x2a`
/// - `add64 r0, r1`
/// - `ldxdw r0, [r1+0x10]`
/// - `jeq r0, 0x0, +5`
///
/// With `show_bytes` enabled:
/// - `b7 00 00 00 2a 00 00 00  mov64 r0, 0x2a`
pub struct DefaultFormatter {
    show_bytes: bool,
}

impl DefaultFormatter {
    /// Create a new default formatter.
    pub fn new() -> Self {
        Self { show_bytes: false }
    }

    /// Enable raw bytes display before the instruction.
    pub fn with_bytes(mut self) -> Self {
        self.show_bytes = true;
        self
    }

    /// Format an instruction to a string.
    pub fn format_to_string(&self, insn: &Instruction) -> String {
        let mut out = String::new();

        if self.show_bytes {
            for b in insn.raw.to_le_bytes() {
                write!(out, "{b:02x} ").unwrap();
            }
            out.push(' ');
        }

        write!(out, "{}", insn.mnemonic.name()).unwrap();

        match insn.mnemonic {
            Mnemonic::Exit => {}
            Mnemonic::Ja
            | Mnemonic::Ja32
            | Mnemonic::Call
            | Mnemonic::CallLocal
            | Mnemonic::CallKfunc
            | Mnemonic::Callx
            | Mnemonic::Gotox => {
                write!(out, " {}", insn.dst).unwrap();
            }
            _ if insn.mnemonic.is_conditional_jump() => {
                // Conditional jumps carry their offset in the raw instruction, not in
                // the decoded src/dst operands.
                let offset = ((insn.raw >> 16) & 0xFFFF) as i16;
                write!(out, " {}, {}, {}", insn.dst, insn.src, Operand::Off(offset.into())).unwrap();
            }
            _ if insn.mnemonic.is_endian() || matches!(insn.mnemonic, Mnemonic::Neg64 | Mnemonic::Neg32) => {
                write!(out, " {}", insn.dst).unwrap();
            }
            _ => {
                if !matches!(insn.dst, Operand::None) {
                    write!(out, " {}", insn.dst).unwrap();
                    if !matches!(insn.src, Operand::None) {
                        write!(out, ", {}", insn.src).unwrap();
                    }
                }
            }
        }

        out
    }
}

impl Default for DefaultFormatter {
    fn default() -> Self {
        Self::new()
    }
}
