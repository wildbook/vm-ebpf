//! An eBPF assembler and disassembler.
//!
//! [`Assembler`] builds bytecode through one method per instruction and resolves jumps to labels:
//!
//! ```
//! use ebpf_asm::{Assembler, R0};
//!
//! let mut asm = Assembler::new();
//! let loop_start = asm.create_label();
//!
//! asm.mov64_imm(R0, 10);
//! asm.set_label(&loop_start).unwrap();
//! asm.sub64_imm(R0, 1);
//! asm.jne_imm(R0, 0, &loop_start);
//! asm.exit();
//!
//! let bytecode = asm.assemble().unwrap();
//! assert_eq!(bytecode.len(), 4 * 8);
//! ```
//!
//! [`Decoder`] iterates over the instructions in bytecode. An [`Instruction`] prints as text, and [`Formatter`] can
//! put the raw bytes in front:
//!
//! ```
//! use ebpf_asm::Decoder;
//!
//! // mov64 r0, 42; exit
//! let bytes = [
//!     0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
//!     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let text: Vec<String> = Decoder::new(&bytes).map(|insn| insn.to_string()).collect();
//! assert_eq!(text, ["mov64 r0, 0x2a", "exit"]);
//! ```

#![warn(missing_docs)]
#![deny(unsafe_code)]

mod assembler;
mod decoder;
mod formatter;
mod instruction;
mod mnemonic;
mod operand;
mod register;

pub use assembler::{AsmError, Assembler, Label};
pub use decoder::Decoder;
pub use formatter::Formatter;
pub use instruction::Instruction;
pub use mnemonic::Mnemonic;
pub use operand::Operand;
pub use register::{Register, FP, R0, R1, R10, R2, R3, R4, R5, R6, R7, R8, R9};

#[cfg(test)]
mod tests {
    use super::*;

    /// The v4 forms that share an opcode with an older instruction and differ only in `off`, the class or the source
    /// bit, plus extreme offsets.
    #[test]
    fn v4_forms_disassemble_distinctly() {
        let mut asm = Assembler::new();
        let far = asm.create_label();
        asm.movsx832(R0, R1)
            .movsx1632(R0, R1)
            .movsx864(R0, R1)
            .movsx1664(R0, R1)
            .movsx3264(R0, R1);
        asm.bswap16(R0).bswap32(R0).bswap64(R0).le16(R0).be64(R0);
        asm.ja32(&far);
        asm.gotox(R1).callx(R2);
        asm.ldxdw(R0, R1, i16::MIN).jeq_imm(R0, i32::MIN, &far);
        asm.set_label(&far).unwrap();
        asm.exit();

        let text: Vec<String> = Decoder::new(&asm.assemble().unwrap())
            .map(|insn| insn.to_string())
            .collect();
        assert_eq!(
            text,
            [
                "movsx832 r0, r1",
                "movsx1632 r0, r1",
                "movsx864 r0, r1",
                "movsx1664 r0, r1",
                "movsx3264 r0, r1",
                "bswap16 r0",
                "bswap32 r0",
                "bswap64 r0",
                "le16 r0",
                "be64 r0",
                "ja32 +4",
                "gotox r1",
                "callx r2",
                "ldxdw r0, [r1-0x8000]",
                "jeq r0, -0x80000000, +0",
                "exit",
            ]
        );

        // `ja32` carries its offset in the 32-bit imm, beyond the reach of `off`
        let insn = Decoder::new(&[0x06, 0, 0, 0, 0x00, 0x00, 0x01, 0x00]).next().unwrap();
        assert_eq!(insn.to_string(), "ja32 +65536");
    }
}
