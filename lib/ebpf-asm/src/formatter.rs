//! eBPF instruction formatting.
//!
//! Provides customizable text formatting for decoded instructions.

use crate::instruction::Instruction;
use crate::mnemonic::Mnemonic;
use crate::operand::Operand;

/// Trait for formatting eBPF instructions.
pub trait Formatter {
    /// Format an instruction to the given output.
    fn format(&self, insn: &Instruction, output: &mut dyn FormatterOutput);

    /// Format an instruction to a string.
    fn format_to_string(&self, insn: &Instruction) -> String {
        let mut output = StringOutput::new();
        self.format(insn, &mut output);
        output.into_string()
    }
}

/// Trait for receiving formatted output.
pub trait FormatterOutput {
    /// Write a mnemonic.
    fn write_mnemonic(&mut self, mnemonic: &str);

    /// Write a register.
    fn write_register(&mut self, reg: &str);

    /// Write an immediate value.
    fn write_immediate(&mut self, value: &str);

    /// Write a memory reference.
    fn write_memory(&mut self, text: &str);

    /// Write an offset (for jumps).
    fn write_offset(&mut self, text: &str);

    /// Write punctuation (comma, brackets, etc).
    fn write_punctuation(&mut self, text: &str);

    /// Write whitespace.
    fn write_whitespace(&mut self, text: &str);
}

/// Simple string output that collects formatted text.
pub struct StringOutput {
    buffer: String,
}

impl StringOutput {
    /// Create a new string output.
    pub fn new() -> Self {
        Self { buffer: String::new() }
    }

    /// Create with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: String::with_capacity(capacity),
        }
    }

    /// Get the accumulated string.
    pub fn as_str(&self) -> &str {
        &self.buffer
    }

    /// Convert to string.
    pub fn into_string(self) -> String {
        self.buffer
    }
}

impl Default for StringOutput {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatterOutput for StringOutput {
    fn write_mnemonic(&mut self, mnemonic: &str) {
        self.buffer.push_str(mnemonic);
    }

    fn write_register(&mut self, reg: &str) {
        self.buffer.push_str(reg);
    }

    fn write_immediate(&mut self, value: &str) {
        self.buffer.push_str(value);
    }

    fn write_memory(&mut self, text: &str) {
        self.buffer.push_str(text);
    }

    fn write_offset(&mut self, text: &str) {
        self.buffer.push_str(text);
    }

    fn write_punctuation(&mut self, text: &str) {
        self.buffer.push_str(text);
    }

    fn write_whitespace(&mut self, text: &str) {
        self.buffer.push_str(text);
    }
}

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
    /// Use uppercase for hex values.
    pub uppercase_hex: bool,
    /// Show instruction offset prefix.
    pub show_offset: bool,
    /// Minimum mnemonic width for alignment.
    pub mnemonic_width: usize,
    /// Show raw instruction bytes before disassembly.
    pub show_bytes: bool,
}

impl DefaultFormatter {
    /// Create a new default formatter.
    pub fn new() -> Self {
        Self {
            uppercase_hex: false,
            show_offset: false,
            mnemonic_width: 0,
            show_bytes: false,
        }
    }

    /// Enable offset prefix display.
    pub fn with_offset(mut self) -> Self {
        self.show_offset = true;
        self
    }

    /// Set minimum mnemonic width for alignment.
    pub fn with_mnemonic_width(mut self, width: usize) -> Self {
        self.mnemonic_width = width;
        self
    }

    /// Enable raw bytes display before the instruction.
    pub fn with_bytes(mut self) -> Self {
        self.show_bytes = true;
        self
    }

    fn format_operand(&self, operand: &Operand, output: &mut dyn FormatterOutput) {
        match operand {
            Operand::Reg(r) => {
                output.write_register(&format!("{r}"));
            }
            Operand::Imm(v) => {
                let s = if *v < 0 {
                    format!("-{:#x}", (-*v) as u32)
                } else {
                    format!("{:#x}", *v as u32)
                };
                output.write_immediate(&s);
            }
            Operand::Imm64(v) => {
                let s = if *v < 0 {
                    format!("-{:#x}", (-*v) as u64)
                } else {
                    format!("{:#x}", *v as u64)
                };
                output.write_immediate(&s);
            }
            Operand::Mem { base, offset } => {
                output.write_punctuation("[");
                output.write_register(&format!("{base}"));
                if *offset >= 0 {
                    output.write_punctuation("+");
                    output.write_immediate(&format!("{:#x}", *offset as u16));
                } else {
                    output.write_punctuation("-");
                    output.write_immediate(&format!("{:#x}", (-*offset) as u16));
                }
                output.write_punctuation("]");
            }
            Operand::Off(off) => {
                let s = if *off >= 0 { format!("+{off}") } else { format!("{off}") };
                output.write_offset(&s);
            }
            Operand::None => {}
        }
    }
}

impl Default for DefaultFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl Formatter for DefaultFormatter {
    fn format(&self, insn: &Instruction, output: &mut dyn FormatterOutput) {
        // Show raw bytes if enabled
        if self.show_bytes {
            let bytes = insn.raw.to_le_bytes();
            for b in &bytes {
                output.write_punctuation(&format!("{:02x} ", b));
            }
            output.write_whitespace(" ");
        }

        // Offset prefix
        if self.show_offset {
            output.write_offset(&format!("{:04x}: ", insn.offset()));
        }

        // Mnemonic
        let mnemonic = insn.mnemonic.name();
        output.write_mnemonic(mnemonic);

        // Padding for alignment
        if self.mnemonic_width > 0 && mnemonic.len() < self.mnemonic_width {
            let padding = " ".repeat(self.mnemonic_width - mnemonic.len());
            output.write_whitespace(&padding);
        }

        // Special cases for different instruction types
        match insn.mnemonic {
            Mnemonic::Exit => {
                // No operands
            }
            Mnemonic::Ja | Mnemonic::Ja32 => {
                // Just offset
                output.write_whitespace(" ");
                self.format_operand(&insn.dst, output);
            }
            Mnemonic::Call | Mnemonic::CallLocal => {
                // Function ID
                output.write_whitespace(" ");
                self.format_operand(&insn.dst, output);
            }
            _ if insn.mnemonic.is_conditional_jump() => {
                // Conditional jumps: if dst CMP src goto +offset
                output.write_whitespace(" ");
                self.format_operand(&insn.dst, output);
                output.write_punctuation(",");
                output.write_whitespace(" ");
                self.format_operand(&insn.src, output);
                // Add offset from raw instruction
                let offset = ((insn.raw >> 16) & 0xFFFF) as i16;
                output.write_punctuation(",");
                output.write_whitespace(" ");
                let off_str = if offset >= 0 {
                    format!("+{offset}")
                } else {
                    format!("{offset}")
                };
                output.write_offset(&off_str);
            }
            _ if insn.mnemonic.is_endian() => {
                // Endian: just dst
                output.write_whitespace(" ");
                self.format_operand(&insn.dst, output);
            }
            Mnemonic::Neg64 | Mnemonic::Neg32 => {
                // Negation: just dst
                output.write_whitespace(" ");
                self.format_operand(&insn.dst, output);
            }
            _ => {
                // Standard two-operand format
                if !matches!(insn.dst, Operand::None) {
                    output.write_whitespace(" ");
                    self.format_operand(&insn.dst, output);

                    if !matches!(insn.src, Operand::None) {
                        output.write_punctuation(",");
                        output.write_whitespace(" ");
                        self.format_operand(&insn.src, output);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::decode_one;

    #[test]
    fn test_format_exit() {
        let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        let fmt = DefaultFormatter::new();
        assert_eq!(fmt.format_to_string(&insn), "exit");
    }

    #[test]
    fn test_format_mov64_imm() {
        let bytes = [0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        let fmt = DefaultFormatter::new();
        assert_eq!(fmt.format_to_string(&insn), "mov64 r0, 0x2a");
    }

    #[test]
    fn test_format_add64_reg() {
        let bytes = [0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        let fmt = DefaultFormatter::new();
        assert_eq!(fmt.format_to_string(&insn), "add64 r0, r1");
    }

    #[test]
    fn test_format_ldxdw() {
        let bytes = [0x79, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        let fmt = DefaultFormatter::new();
        assert_eq!(fmt.format_to_string(&insn), "ldxdw r0, [r1+0x10]");
    }

    #[test]
    fn test_format_with_offset() {
        let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        let fmt = DefaultFormatter::new().with_offset();
        assert_eq!(fmt.format_to_string(&insn), "0000: exit");
    }
}
