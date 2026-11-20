//! Text for decoded instructions.

use std::fmt::Write;

use crate::instruction::{Instruction, RawInstruction};
use crate::mnemonic::Mnemonic;
use crate::operand::Operand;

/// Renders decoded instructions as text:
///
/// - `mov64 r0, 0x2a`
/// - `add64 r0, r1`
/// - `ldxdw r0, [r1+0x10]`
/// - `jeq r0, 0x0, +5`
///
/// [`with_bytes`](Self::with_bytes) puts the raw bytes in front: `b7 00 00 00 2a 00 00 00  mov64 r0, 0x2a`.
/// `Instruction` implements `Display` with the text of `Formatter::new()`.
#[derive(Default)]
pub struct Formatter {
    show_bytes: bool,
}

impl Formatter {
    /// A formatter that shows no raw bytes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show the raw bytes before the instruction, both slots for `lddw` and other wide instructions.
    pub fn with_bytes(mut self) -> Self {
        self.show_bytes = true;
        self
    }

    /// The text of `insn`.
    pub fn format(&self, insn: &Instruction) -> String {
        let mut out = String::new();

        if self.show_bytes {
            for slot in [Some(insn.raw), insn.raw2].into_iter().flatten() {
                for b in slot.to_le_bytes() {
                    write!(out, "{b:02x} ").unwrap();
                }
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
            | Mnemonic::Gotox
            | Mnemonic::MayGoto => {
                write!(out, " {}", insn.dst).unwrap();
            }
            Mnemonic::LdPseudo => {
                let kind = RawInstruction(insn.raw).src();
                write!(out, " {}, {kind:#x}, {}", insn.dst, insn.src).unwrap();
            }
            Mnemonic::AddrSpaceCast => {
                let imm = RawInstruction(insn.raw).imm() as u32;
                let (dst_as, src_as) = (imm >> 16, imm & 0xFFFF);
                write!(out, " {}, {}, {dst_as:#x}, {src_as:#x}", insn.dst, insn.src).unwrap();
            }
            _ if insn.mnemonic.is_conditional_jump() => {
                // Conditional jumps carry their offset in the raw instruction, not in the decoded src/dst operands.
                let offset = RawInstruction(insn.raw).offset();
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
