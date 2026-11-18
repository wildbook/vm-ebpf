//! eBPF Assembler and Disassembler Library
//!
//! This crate provides tools for working with eBPF bytecode:
//!
//! - **Decoder**: Disassemble eBPF bytecode into structured instructions
//! - **Assembler**: Build eBPF bytecode with label support
//! - **DefaultFormatter**: Render decoded instructions as text
//!
//! # Disassembly Example
//!
//! ```
//! use ebpf_asm::{Decoder, DefaultFormatter};
//!
//! // eBPF bytecode: mov64 r0, 42; exit
//! let bytes = [
//!     0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
//!     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//! ];
//!
//! let formatter = DefaultFormatter::new();
//! for insn in Decoder::new(&bytes) {
//!     println!("{:04x}: {}", insn.offset, formatter.format_to_string(&insn));
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
//! let loop_start = asm.create_label();
//!
//! asm.mov64_imm(R0, 10);       // r0 = 10
//! asm.set_label(&loop_start).unwrap();
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
//! assert_eq!(insns[0].mnemonic.name(), "mov64");
//! assert_eq!(insns[1].mnemonic.name(), "exit");
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

pub use assembler::{AsmError, AssembledProgram, Assembler, Label};
pub use decoder::{decode_all, Decoder};
pub use formatter::DefaultFormatter;
pub use instruction::Instruction;
pub use mnemonic::Mnemonic;
pub use operand::Operand;
pub use register::{Register, FP, R0, R1, R10, R2, R3, R4, R5, R6, R7, R8, R9};

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs every assembler instruction through `assemble` and `decode_all` and checks that every emitted opcode
    /// decodes.
    #[test]
    fn round_trip_every_instruction() {
        let mut asm = Assembler::new();
        let l1 = asm.create_label();
        let l2 = asm.create_label();

        asm.add64(R0, R1).add64_imm(R0, 1);
        asm.sub64(R0, R1).sub64_imm(R0, 1);
        asm.mul64(R0, R1).mul64_imm(R0, 1);
        asm.div64(R0, R1).div64_imm(R0, 1);
        asm.sdiv64(R0, R1).sdiv64_imm(R0, 1);
        asm.or64(R0, R1).or64_imm(R0, 1);
        asm.and64(R0, R1).and64_imm(R0, 1);
        asm.lsh64(R0, R1).lsh64_imm(R0, 1);
        asm.rsh64(R0, R1).rsh64_imm(R0, 1);
        asm.neg64(R0);
        asm.mod64(R0, R1).mod64_imm(R0, 1);
        asm.smod64(R0, R1).smod64_imm(R0, 1);
        asm.xor64(R0, R1).xor64_imm(R0, 1);
        asm.mov64(R0, R1).mov64_imm(R0, 1);
        asm.arsh64(R0, R1).arsh64_imm(R0, 1);

        asm.add32(R0, R1).add32_imm(R0, 1);
        asm.sub32(R0, R1).sub32_imm(R0, 1);
        asm.mul32(R0, R1).mul32_imm(R0, 1);
        asm.div32(R0, R1).div32_imm(R0, 1);
        asm.sdiv32(R0, R1).sdiv32_imm(R0, 1);
        asm.or32(R0, R1).or32_imm(R0, 1);
        asm.and32(R0, R1).and32_imm(R0, 1);
        asm.lsh32(R0, R1).lsh32_imm(R0, 1);
        asm.rsh32(R0, R1).rsh32_imm(R0, 1);
        asm.neg32(R0);
        asm.mod32(R0, R1).mod32_imm(R0, 1);
        asm.smod32(R0, R1).smod32_imm(R0, 1);
        asm.xor32(R0, R1).xor32_imm(R0, 1);
        asm.mov32(R0, R1).mov32_imm(R0, 1);
        asm.arsh32(R0, R1).arsh32_imm(R0, 1);

        asm.le16(R0).le32(R0).le64(R0);
        asm.be16(R0).be32(R0).be64(R0);

        asm.ja(&l1);
        asm.set_label(&l1).unwrap();
        asm.ja_off(0);
        asm.jeq(R0, R1, &l2).jeq_imm(R0, 1, &l2);
        asm.jne(R0, R1, &l2).jne_imm(R0, 1, &l2);
        asm.jgt(R0, R1, &l2).jgt_imm(R0, 1, &l2);
        asm.jge(R0, R1, &l2).jge_imm(R0, 1, &l2);
        asm.jlt(R0, R1, &l2).jlt_imm(R0, 1, &l2);
        asm.jle(R0, R1, &l2).jle_imm(R0, 1, &l2);
        asm.jset(R0, R1, &l2).jset_imm(R0, 1, &l2);
        asm.jsgt(R0, R1, &l2).jsgt_imm(R0, 1, &l2);
        asm.jsge(R0, R1, &l2).jsge_imm(R0, 1, &l2);
        asm.jslt(R0, R1, &l2).jslt_imm(R0, 1, &l2);
        asm.jsle(R0, R1, &l2).jsle_imm(R0, 1, &l2);

        asm.jeq32(R0, R1, &l2).jeq32_imm(R0, 1, &l2);
        asm.jne32(R0, R1, &l2).jne32_imm(R0, 1, &l2);
        asm.jgt32(R0, R1, &l2).jgt32_imm(R0, 1, &l2);
        asm.jge32(R0, R1, &l2).jge32_imm(R0, 1, &l2);
        asm.jlt32(R0, R1, &l2).jlt32_imm(R0, 1, &l2);
        asm.jle32(R0, R1, &l2).jle32_imm(R0, 1, &l2);
        asm.jset32(R0, R1, &l2).jset32_imm(R0, 1, &l2);
        asm.jsgt32(R0, R1, &l2).jsgt32_imm(R0, 1, &l2);
        asm.jsge32(R0, R1, &l2).jsge32_imm(R0, 1, &l2);
        asm.jslt32(R0, R1, &l2).jslt32_imm(R0, 1, &l2);
        asm.jsle32(R0, R1, &l2).jsle32_imm(R0, 1, &l2);

        asm.ldxdw(R0, R1, 0);
        asm.ldxw(R0, R1, 0);
        asm.ldxh(R0, R1, 0);
        asm.ldxb(R0, R1, 0);
        asm.ldxsw(R0, R1, 0);
        asm.ldxsh(R0, R1, 0);
        asm.ldxsb(R0, R1, 0);
        asm.lddw(R0, 0x1234);

        asm.stxdw(R1, 0, R0);
        asm.stxw(R1, 0, R0);
        asm.stxh(R1, 0, R0);
        asm.stxb(R1, 0, R0);
        asm.stdw(R1, 0, 1);
        asm.stw(R1, 0, 1);
        asm.sth(R1, 0, 1);
        asm.stb(R1, 0, 1);
        asm.load_acquire64(R0, R1, 0).load_acquire32(R0, R1, 0);
        asm.load_acquire16(R0, R1, 0).load_acquire8(R0, R1, 0);
        asm.store_release64(R1, 0, R0).store_release32(R1, 0, R0);
        asm.store_release16(R1, 0, R0).store_release8(R1, 0, R0);

        asm.call(1);
        asm.callx(R1);
        asm.gotox(R1).may_goto(&l2);
        let func = asm.create_label();
        asm.call_local(&func);
        asm.set_label(&func).unwrap();
        asm.set_label(&l2).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        let insns = decode_all(&code);
        let consumed: usize = insns.iter().map(|i| i.size as usize).sum();
        assert_eq!(consumed, code.len(), "decoder must consume every emitted byte");
        assert!(insns.iter().all(|i| i.mnemonic != Mnemonic::Unknown), "every emitted opcode must decode");
    }

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

        let fmt = DefaultFormatter::new();
        let text: Vec<String> = decode_all(&asm.assemble().unwrap())
            .iter()
            .map(|i| fmt.format_to_string(i))
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
        let insn = &decode_all(&[0x06, 0, 0, 0, 0x00, 0x00, 0x01, 0x00])[0];
        assert_eq!(fmt.format_to_string(insn), "ja32 +65536");
    }
}
