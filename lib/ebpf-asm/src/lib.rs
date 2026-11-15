//! eBPF Assembler and Disassembler Library
//!
//! This crate provides tools for working with eBPF bytecode:
//!
//! - **Decoder**: Disassemble eBPF bytecode into structured instructions
//! - **Assembler**: Build eBPF bytecode with label support
//! - **Formatter**: Customize instruction text output
//!
//! # Disassembly Example
//!
//! ```
//! use ebpf_asm::{Decoder, DefaultFormatter, Formatter};
//!
//! // eBPF bytecode: mov64 r0, 42; exit
//! let bytes = [
//!     0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
//!     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let formatter = DefaultFormatter::new();
//! for insn in Decoder::new(&bytes) {
//!     println!("{:04x}: {}", insn.offset(), formatter.format_to_string(&insn));
//! }
//! ```
//!
//! # Assembly Example
//!
//! ```
//! use ebpf_asm::{Assembler, R0, R1};
//!
//! let mut asm = Assembler::new();
//!
//! // Create a countdown loop
//! let mut loop_start = asm.create_label();
//!
//! asm.mov64_imm(R0, 10);       // r0 = 10
//! asm.set_label(&mut loop_start).unwrap();
//! asm.sub64_imm(R0, 1);         // r0--
//! asm.jne_imm(R0, 0, &loop_start); // if r0 != 0 goto loop_start
//! asm.exit();
//!
//! let bytecode = asm.assemble().unwrap();
//! assert_eq!(bytecode.len(), 32); // 4 instructions * 8 bytes
//! ```
//!
//! # Round-Trip Example
//!
//! ```
//! use ebpf_asm::{Assembler, Decoder, R0};
//!
//! // Assemble
//! let mut asm = Assembler::new();
//! asm.mov64_imm(R0, 42);
//! asm.exit();
//! let code = asm.assemble().unwrap();
//!
//! // Disassemble
//! let insns: Vec<_> = Decoder::new(&code).collect();
//! assert_eq!(insns.len(), 2);
//! assert_eq!(insns[0].mnemonic().name(), "mov64");
//! assert_eq!(insns[1].mnemonic().name(), "exit");
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

// Re-export main types
pub use assembler::{AsmError, AssembledProgram, Assembler, CoreRelo, CoreReloKind, Label};
pub use decoder::{decode_all, decode_one, Decoder};
pub use formatter::{DefaultFormatter, Formatter, FormatterOutput, StringOutput};
pub use instruction::{Instruction, RawInstruction};
pub use mnemonic::Mnemonic;
pub use operand::{MemSize, Operand};
pub use register::{InvalidRegister, Register, FP, R0, R1, R10, R2, R3, R4, R5, R6, R7, R8, R9};

/// Instruction encoding constants.
pub mod encoding {
    pub use crate::instruction::{alu, class, jmp, mode, size, SRC_IMM, SRC_REG};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip_simple() {
        // Assemble
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 42);
        asm.add64_imm(R0, 8);
        asm.exit();
        let code = asm.assemble().unwrap();

        // Disassemble
        let insns = decode_all(&code);
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].mnemonic, Mnemonic::Mov64);
        assert_eq!(insns[1].mnemonic, Mnemonic::Add64);
        assert_eq!(insns[2].mnemonic, Mnemonic::Exit);
    }

    #[test]
    fn test_round_trip_with_labels() {
        // Assemble with labels
        let mut asm = Assembler::new();
        let mut loop_label = asm.create_label();
        let mut end_label = asm.create_label();

        asm.mov64_imm(R0, 5); // insn 0
        asm.set_label(&mut loop_label).unwrap(); // label points to insn 1
        asm.sub64_imm(R0, 1); // insn 1
        asm.jeq_imm(R0, 0, &end_label); // insn 2
        asm.ja(&loop_label); // insn 3
        asm.set_label(&mut end_label).unwrap(); // label points to insn 4
        asm.exit(); // insn 4

        let code = asm.assemble().unwrap();

        // Disassemble and check offsets
        let insns = decode_all(&code);
        assert_eq!(insns.len(), 5);

        // JEQ is at insn 2, should jump forward to insn 4 (exit)
        // offset = 4 - (2 + 1) = 1
        assert_eq!(insns[2].mnemonic, Mnemonic::Jeq);
        let jeq_offset = ((insns[2].raw >> 16) & 0xFFFF) as i16;
        assert_eq!(jeq_offset, 1); // Skip JA, land on EXIT

        // JA is at insn 3, should jump backward to insn 1 (sub64)
        // offset = 1 - (3 + 1) = -3
        assert_eq!(insns[3].mnemonic, Mnemonic::Ja);
        let ja_offset = ((insns[3].raw >> 16) & 0xFFFF) as i16;
        assert_eq!(ja_offset, -3); // Back to sub64
    }

    #[test]
    fn test_round_trip_lddw() {
        let mut asm = Assembler::new();
        asm.lddw(R0, 0xDEADBEEFCAFEBABEu64 as i64);
        asm.exit();

        let code = asm.assemble().unwrap();
        assert_eq!(code.len(), 24); // 16 + 8 bytes

        // The 64-bit immediate splits across the low 32 bits of each LDDW slot.
        let lo = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);
        let hi = u32::from_le_bytes([code[12], code[13], code[14], code[15]]);
        assert_eq!(lo, 0xCAFEBABE);
        assert_eq!(hi, 0xDEADBEEF);

        let insns = decode_all(&code);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, Mnemonic::Lddw);
        assert_eq!(insns[0].size, 16);

        if let Operand::Imm64(v) = insns[0].src {
            assert_eq!(v as u64, 0xDEADBEEFCAFEBABE);
        } else {
            panic!("Expected Imm64 operand");
        }
    }

    #[test]
    fn test_round_trip_memory() {
        let mut asm = Assembler::new();
        asm.ldxdw(R0, R10, -8);
        asm.stxdw(R10, -16, R0);
        asm.ldxw(R1, R0, 0);
        asm.stxb(R0, 4, R1);
        asm.exit();

        let code = asm.assemble().unwrap();

        let insns = decode_all(&code);
        assert_eq!(insns.len(), 5);
        assert_eq!(insns[0].mnemonic, Mnemonic::Ldxdw);
        assert_eq!(insns[1].mnemonic, Mnemonic::Stxdw);
        assert_eq!(insns[2].mnemonic, Mnemonic::Ldxw);
        assert_eq!(insns[3].mnemonic, Mnemonic::Stxb);
    }

    #[test]
    fn test_all_alu64_operations() {
        let mut asm = Assembler::new();
        asm.add64(R0, R1);
        asm.sub64(R0, R1);
        asm.mul64(R0, R1);
        asm.div64(R0, R1);
        asm.or64(R0, R1);
        asm.and64(R0, R1);
        asm.lsh64(R0, R1);
        asm.rsh64(R0, R1);
        asm.neg64(R0);
        asm.mod64(R0, R1);
        asm.xor64(R0, R1);
        asm.mov64(R0, R1);
        asm.arsh64(R0, R1);
        asm.exit();

        let code = asm.assemble().unwrap();
        let insns = decode_all(&code);

        assert_eq!(insns[0].mnemonic, Mnemonic::Add64);
        assert_eq!(insns[1].mnemonic, Mnemonic::Sub64);
        assert_eq!(insns[2].mnemonic, Mnemonic::Mul64);
        assert_eq!(insns[3].mnemonic, Mnemonic::Div64);
        assert_eq!(insns[4].mnemonic, Mnemonic::Or64);
        assert_eq!(insns[5].mnemonic, Mnemonic::And64);
        assert_eq!(insns[6].mnemonic, Mnemonic::Lsh64);
        assert_eq!(insns[7].mnemonic, Mnemonic::Rsh64);
        assert_eq!(insns[8].mnemonic, Mnemonic::Neg64);
        assert_eq!(insns[9].mnemonic, Mnemonic::Mod64);
        assert_eq!(insns[10].mnemonic, Mnemonic::Xor64);
        assert_eq!(insns[11].mnemonic, Mnemonic::Mov64);
        assert_eq!(insns[12].mnemonic, Mnemonic::Arsh64);
    }

    #[test]
    fn test_all_jump_conditions() {
        let mut asm = Assembler::new();
        let mut l1 = asm.create_label();
        let mut l2 = asm.create_label();
        let mut l3 = asm.create_label();
        let mut l4 = asm.create_label();
        let mut l5 = asm.create_label();
        let mut l6 = asm.create_label();

        asm.set_label(&mut l1).unwrap();
        asm.jeq_imm(R0, 0, &l2);
        asm.set_label(&mut l2).unwrap();
        asm.jne_imm(R0, 0, &l3);
        asm.set_label(&mut l3).unwrap();
        asm.jgt_imm(R0, 0, &l4);
        asm.set_label(&mut l4).unwrap();
        asm.jge_imm(R0, 0, &l5);
        asm.set_label(&mut l5).unwrap();
        asm.jlt_imm(R0, 0, &l6);
        asm.set_label(&mut l6).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        let insns = decode_all(&code);

        assert_eq!(insns[0].mnemonic, Mnemonic::Jeq);
        assert_eq!(insns[1].mnemonic, Mnemonic::Jne);
        assert_eq!(insns[2].mnemonic, Mnemonic::Jgt);
        assert_eq!(insns[3].mnemonic, Mnemonic::Jge);
        assert_eq!(insns[4].mnemonic, Mnemonic::Jlt);
    }

    #[test]
    fn test_endianness() {
        let mut asm = Assembler::new();
        asm.le16(R0);
        asm.le32(R0);
        asm.le64(R0);
        asm.be16(R0);
        asm.be32(R0);
        asm.be64(R0);
        asm.exit();

        let code = asm.assemble().unwrap();
        let insns = decode_all(&code);

        assert_eq!(insns[0].mnemonic, Mnemonic::Le16);
        assert_eq!(insns[1].mnemonic, Mnemonic::Le32);
        assert_eq!(insns[2].mnemonic, Mnemonic::Le64);
        assert_eq!(insns[3].mnemonic, Mnemonic::Be16);
        assert_eq!(insns[4].mnemonic, Mnemonic::Be32);
        assert_eq!(insns[5].mnemonic, Mnemonic::Be64);
    }
}
