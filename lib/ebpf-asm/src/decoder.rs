//! eBPF bytecode decoder.
//!
//! Decodes raw eBPF bytecode into structured `Instruction` representations.

use crate::instruction::{alu, atomic, class, jmp, mode, size, Instruction, RawInstruction, SRC_IMM, SRC_REG};
use crate::mnemonic::Mnemonic;
use crate::operand::Operand;
use crate::register::Register;

/// eBPF bytecode decoder.
///
/// Iterates over bytecode and yields decoded instructions.
///
/// # Example
///
/// ```
/// use ebpf_asm::Decoder;
///
/// let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // exit
/// let decoder = Decoder::new(&bytes);
/// for insn in decoder {
///     println!("{}", insn);
/// }
/// ```
pub struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    /// Create a new decoder for the given bytecode.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Get the current byte offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get the remaining bytes.
    pub fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }

    /// Check if there are more instructions to decode.
    pub fn can_decode(&self) -> bool {
        self.offset + 8 <= self.bytes.len()
    }

    /// Decode the next instruction.
    pub fn decode(&mut self) -> Option<Instruction> {
        if !self.can_decode() {
            return None;
        }

        let start_offset = self.offset;

        // Read first 8 bytes
        let raw_bytes: [u8; 8] = self.bytes[self.offset..][..8].try_into().unwrap();
        let raw = RawInstruction::from_le_bytes(raw_bytes);
        self.offset += 8;

        let opcode = raw.opcode();
        let inst_class = opcode & 0x07;
        let dst_reg = Register::from_u8(raw.dst()).unwrap_or(Register::R0);
        let src_reg = Register::from_u8(raw.src()).unwrap_or(Register::R0);
        let offset = raw.offset();
        let imm = raw.imm();

        let (mnemonic, dst, src, size, raw2) = match inst_class {
            class::ALU64 => decode_alu(opcode, dst_reg, src_reg, offset, imm, true),
            class::ALU32 => decode_alu(opcode, dst_reg, src_reg, offset, imm, false),
            class::JMP64 => decode_jmp(opcode, dst_reg, src_reg, offset, imm, true),
            class::JMP32 => decode_jmp(opcode, dst_reg, src_reg, offset, imm, false),
            class::LDX => decode_ldx(opcode, dst_reg, src_reg, offset),
            class::STX => decode_stx(opcode, dst_reg, src_reg, offset, imm),
            class::ST => decode_st(opcode, dst_reg, offset, imm),
            class::LD => {
                // LD class includes LDDW (64-bit immediate load)
                let mem_mode = opcode & 0xE0;
                let mem_size = opcode & 0x18;

                if mem_mode == mode::IMM && mem_size == size::DW {
                    // LDDW - read second instruction
                    if self.offset + 8 > self.bytes.len() {
                        (Mnemonic::Unknown, Operand::None, Operand::None, 8, None)
                    } else {
                        let raw2_bytes: [u8; 8] = self.bytes[self.offset..][..8].try_into().unwrap();
                        let raw2 = RawInstruction::from_le_bytes(raw2_bytes);
                        self.offset += 8;

                        let imm_lo = imm as u32 as u64;
                        let imm_hi = raw2.imm() as u32 as u64;
                        let imm64 = (imm_hi << 32) | imm_lo;

                        (Mnemonic::Lddw, Operand::Reg(dst_reg), Operand::Imm64(imm64 as i64), 16, Some(raw2.value()))
                    }
                } else {
                    // Other LD modes (ABS, IND) - legacy packet access
                    (Mnemonic::Unknown, Operand::None, Operand::None, 8, None)
                }
            }
            _ => (Mnemonic::Unknown, Operand::None, Operand::None, 8, None),
        };

        Some(Instruction {
            mnemonic,
            dst,
            src,
            offset: start_offset as u64,
            size,
            opcode,
            raw: raw.value(),
            raw2,
        })
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        self.decode()
    }
}

/// Decode an ALU instruction.
fn decode_alu(
    opcode: u8,
    dst: Register,
    src_reg: Register,
    offset: i16,
    imm: i32,
    is_64: bool,
) -> (Mnemonic, Operand, Operand, u8, Option<u64>) {
    let alu_op = opcode & 0xF0;
    let src_type = opcode & 0x08;

    // Handle endianness conversions (special case)
    if alu_op == alu::END {
        let mnemonic = if src_type == SRC_IMM {
            // LE
            match imm {
                16 => Mnemonic::Le16,
                32 => Mnemonic::Le32,
                64 => Mnemonic::Le64,
                _ => Mnemonic::Unknown,
            }
        } else {
            // BE
            match imm {
                16 => Mnemonic::Be16,
                32 => Mnemonic::Be32,
                64 => Mnemonic::Be64,
                _ => Mnemonic::Unknown,
            }
        };
        return (mnemonic, Operand::Reg(dst), Operand::None, 8, None);
    }

    let mnemonic = match (alu_op, is_64, offset) {
        (alu::ADD, true, _) => Mnemonic::Add64,
        (alu::ADD, false, _) => Mnemonic::Add32,
        (alu::SUB, true, _) => Mnemonic::Sub64,
        (alu::SUB, false, _) => Mnemonic::Sub32,
        (alu::MUL, true, _) => Mnemonic::Mul64,
        (alu::MUL, false, _) => Mnemonic::Mul32,
        (alu::DIV, true, 0) => Mnemonic::Div64,
        (alu::DIV, false, 0) => Mnemonic::Div32,
        (alu::DIV, true, 1) => Mnemonic::SDiv64,
        (alu::DIV, false, 1) => Mnemonic::SDiv32,
        (alu::OR, true, _) => Mnemonic::Or64,
        (alu::OR, false, _) => Mnemonic::Or32,
        (alu::AND, true, _) => Mnemonic::And64,
        (alu::AND, false, _) => Mnemonic::And32,
        (alu::LSH, true, _) => Mnemonic::Lsh64,
        (alu::LSH, false, _) => Mnemonic::Lsh32,
        (alu::RSH, true, _) => Mnemonic::Rsh64,
        (alu::RSH, false, _) => Mnemonic::Rsh32,
        (alu::NEG, true, _) => Mnemonic::Neg64,
        (alu::NEG, false, _) => Mnemonic::Neg32,
        (alu::MOD, true, 0) => Mnemonic::Mod64,
        (alu::MOD, false, 0) => Mnemonic::Mod32,
        (alu::MOD, true, 1) => Mnemonic::SMod64,
        (alu::MOD, false, 1) => Mnemonic::SMod32,
        (alu::XOR, true, _) => Mnemonic::Xor64,
        (alu::XOR, false, _) => Mnemonic::Xor32,
        (alu::MOV, true, _) => Mnemonic::Mov64,
        (alu::MOV, false, _) => Mnemonic::Mov32,
        (alu::ARSH, true, _) => Mnemonic::Arsh64,
        (alu::ARSH, false, _) => Mnemonic::Arsh32,
        _ => Mnemonic::Unknown,
    };

    let src = if src_type == SRC_REG {
        Operand::Reg(src_reg)
    } else {
        Operand::Imm(imm)
    };

    // NEG only has dst
    if alu_op == alu::NEG {
        (mnemonic, Operand::Reg(dst), Operand::None, 8, None)
    } else {
        (mnemonic, Operand::Reg(dst), src, 8, None)
    }
}

/// Decode a JMP instruction.
fn decode_jmp(
    opcode: u8,
    dst: Register,
    src_reg: Register,
    offset: i16,
    imm: i32,
    is_64: bool,
) -> (Mnemonic, Operand, Operand, u8, Option<u64>) {
    let jmp_op = opcode & 0xF0;
    let src_type = opcode & 0x08;

    // Special instructions: CALL, EXIT, JA
    match jmp_op {
        jmp::EXIT => {
            return (Mnemonic::Exit, Operand::None, Operand::None, 8, None);
        }
        jmp::CALL => {
            let mnemonic = if src_reg.number() == 1 {
                Mnemonic::CallLocal
            } else {
                Mnemonic::Call
            };
            return (mnemonic, Operand::Imm(imm), Operand::None, 8, None);
        }
        jmp::JA => {
            let mnemonic = if is_64 { Mnemonic::Ja } else { Mnemonic::Ja32 };
            // JA uses offset for 64-bit class, imm for 32-bit class
            let target = if is_64 {
                Operand::Off(offset)
            } else {
                Operand::Off(imm as i16)
            };
            return (mnemonic, target, Operand::None, 8, None);
        }
        _ => {}
    }

    let mnemonic = match (jmp_op, is_64) {
        (jmp::JEQ, true) => Mnemonic::Jeq,
        (jmp::JEQ, false) => Mnemonic::Jeq32,
        (jmp::JGT, true) => Mnemonic::Jgt,
        (jmp::JGT, false) => Mnemonic::Jgt32,
        (jmp::JGE, true) => Mnemonic::Jge,
        (jmp::JGE, false) => Mnemonic::Jge32,
        (jmp::JLT, true) => Mnemonic::Jlt,
        (jmp::JLT, false) => Mnemonic::Jlt32,
        (jmp::JLE, true) => Mnemonic::Jle,
        (jmp::JLE, false) => Mnemonic::Jle32,
        (jmp::JSET, true) => Mnemonic::Jset,
        (jmp::JSET, false) => Mnemonic::Jset32,
        (jmp::JNE, true) => Mnemonic::Jne,
        (jmp::JNE, false) => Mnemonic::Jne32,
        (jmp::JSGT, true) => Mnemonic::Jsgt,
        (jmp::JSGT, false) => Mnemonic::Jsgt32,
        (jmp::JSGE, true) => Mnemonic::Jsge,
        (jmp::JSGE, false) => Mnemonic::Jsge32,
        (jmp::JSLT, true) => Mnemonic::Jslt,
        (jmp::JSLT, false) => Mnemonic::Jslt32,
        (jmp::JSLE, true) => Mnemonic::Jsle,
        (jmp::JSLE, false) => Mnemonic::Jsle32,
        _ => Mnemonic::Unknown,
    };

    let src = if src_type == SRC_REG {
        Operand::Reg(src_reg)
    } else {
        Operand::Imm(imm)
    };

    // Conditional jumps: dst, src, offset
    // We encode offset in a special way for the display
    (mnemonic, Operand::Reg(dst), src, 8, None)
}

/// Decode a LDX (load from memory) instruction.
fn decode_ldx(opcode: u8, dst: Register, src: Register, offset: i16) -> (Mnemonic, Operand, Operand, u8, Option<u64>) {
    let mem_size = opcode & 0x18;
    let mem_mode = opcode & 0xE0;

    let mnemonic = match (mem_mode, mem_size) {
        (mode::MEM, size::DW) => Mnemonic::Ldxdw,
        (mode::MEM, size::W) => Mnemonic::Ldxw,
        (mode::MEM, size::H) => Mnemonic::Ldxh,
        (mode::MEM, size::B) => Mnemonic::Ldxb,
        (mode::MEMSX, size::DW) => Mnemonic::Ldxsdw,
        (mode::MEMSX, size::W) => Mnemonic::Ldxsw,
        (mode::MEMSX, size::H) => Mnemonic::Ldxsh,
        (mode::MEMSX, size::B) => Mnemonic::Ldxsb,
        _ => Mnemonic::Unknown,
    };

    (mnemonic, Operand::Reg(dst), Operand::Mem { base: src, offset }, 8, None)
}

/// Decode a STX (store to memory from register) instruction.
fn decode_stx(
    opcode: u8,
    dst: Register,
    src: Register,
    offset: i16,
    imm: i32,
) -> (Mnemonic, Operand, Operand, u8, Option<u64>) {
    let mem_size = opcode & 0x18;
    let mem_mode = opcode & 0xE0;

    // Check for atomic operations
    if mem_mode == mode::ATOMIC {
        return decode_atomic(mem_size, dst, src, offset, imm);
    }

    let mnemonic = match mem_size {
        size::DW => Mnemonic::Stxdw,
        size::W => Mnemonic::Stxw,
        size::H => Mnemonic::Stxh,
        size::B => Mnemonic::Stxb,
        _ => Mnemonic::Unknown,
    };

    (mnemonic, Operand::Mem { base: dst, offset }, Operand::Reg(src), 8, None)
}

/// Decode an atomic operation.
fn decode_atomic(
    mem_size: u8,
    dst: Register,
    src: Register,
    offset: i16,
    imm: i32,
) -> (Mnemonic, Operand, Operand, u8, Option<u64>) {
    let is_64 = mem_size == size::DW;
    let is_fetch = (imm & atomic::FETCH) != 0 && imm != atomic::XCHG && imm != atomic::CMPXCHG;

    // Mask out the fetch bit for comparison (except for XCHG/CMPXCHG which include it)
    let op = if imm == atomic::XCHG || imm == atomic::CMPXCHG {
        imm
    } else {
        imm & !atomic::FETCH
    };

    let mnemonic = match (op, is_64, is_fetch) {
        (atomic::ADD, true, false) => Mnemonic::AtomicAdd64,
        (atomic::ADD, false, false) => Mnemonic::AtomicAdd32,
        (atomic::ADD, true, true) => Mnemonic::AtomicFetchAdd64,
        (atomic::ADD, false, true) => Mnemonic::AtomicFetchAdd32,
        (atomic::OR, true, false) => Mnemonic::AtomicOr64,
        (atomic::OR, false, false) => Mnemonic::AtomicOr32,
        (atomic::OR, true, true) => Mnemonic::AtomicFetchOr64,
        (atomic::OR, false, true) => Mnemonic::AtomicFetchOr32,
        (atomic::AND, true, false) => Mnemonic::AtomicAnd64,
        (atomic::AND, false, false) => Mnemonic::AtomicAnd32,
        (atomic::AND, true, true) => Mnemonic::AtomicFetchAnd64,
        (atomic::AND, false, true) => Mnemonic::AtomicFetchAnd32,
        (atomic::XOR, true, false) => Mnemonic::AtomicXor64,
        (atomic::XOR, false, false) => Mnemonic::AtomicXor32,
        (atomic::XOR, true, true) => Mnemonic::AtomicFetchXor64,
        (atomic::XOR, false, true) => Mnemonic::AtomicFetchXor32,
        (atomic::XCHG, true, _) => Mnemonic::AtomicXchg64,
        (atomic::XCHG, false, _) => Mnemonic::AtomicXchg32,
        (atomic::CMPXCHG, true, _) => Mnemonic::AtomicCmpxchg64,
        (atomic::CMPXCHG, false, _) => Mnemonic::AtomicCmpxchg32,
        _ => Mnemonic::Unknown,
    };

    (mnemonic, Operand::Mem { base: dst, offset }, Operand::Reg(src), 8, None)
}

/// Decode a ST (store immediate to memory) instruction.
fn decode_st(opcode: u8, dst: Register, offset: i16, imm: i32) -> (Mnemonic, Operand, Operand, u8, Option<u64>) {
    let mem_size = opcode & 0x18;

    let mnemonic = match mem_size {
        size::DW => Mnemonic::Stdw,
        size::W => Mnemonic::Stw,
        size::H => Mnemonic::Sth,
        size::B => Mnemonic::Stb,
        _ => Mnemonic::Unknown,
    };

    (mnemonic, Operand::Mem { base: dst, offset }, Operand::Imm(imm), 8, None)
}

/// Decode a single instruction from bytes.
pub fn decode_one(bytes: &[u8]) -> Option<Instruction> {
    Decoder::new(bytes).decode()
}

/// Decode all instructions from bytes.
pub fn decode_all(bytes: &[u8]) -> Vec<Instruction> {
    Decoder::new(bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_exit() {
        let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Exit);
    }

    #[test]
    fn test_decode_mov64_imm() {
        // mov64 r0, 42
        let bytes = [0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Mov64);
        assert_eq!(insn.dst, Operand::Reg(Register::R0));
        assert_eq!(insn.src, Operand::Imm(42));
    }

    #[test]
    fn test_decode_add64_reg() {
        // add64 r0, r1
        let bytes = [0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Add64);
        assert_eq!(insn.dst, Operand::Reg(Register::R0));
        assert_eq!(insn.src, Operand::Reg(Register::R1));
    }

    #[test]
    fn test_decode_lddw() {
        // lddw r0, 0x123456789abcdef0
        let bytes = [
            0x18, 0x00, 0x00, 0x00, 0xf0, 0xde, 0xbc, 0x9a, // first insn: imm = low 32 bits
            0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, // second insn: imm = high 32 bits
        ];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Lddw);
        assert_eq!(insn.size, 16);
        assert_eq!(insn.src, Operand::Imm64(0x123456789abcdef0u64 as i64));
    }

    #[test]
    fn test_decode_ldxdw() {
        // ldxdw r0, [r1+16]
        let bytes = [0x79, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Ldxdw);
        assert_eq!(insn.dst, Operand::Reg(Register::R0));
        assert_eq!(
            insn.src,
            Operand::Mem {
                base: Register::R1,
                offset: 16
            }
        );
    }

    #[test]
    fn test_decode_jeq() {
        // jeq r0, 0, +5
        let bytes = [0x15, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Jeq);
    }

    #[test]
    fn test_decode_multiple() {
        let bytes = [
            0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r0, 42
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];
        let insns = decode_all(&bytes);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, Mnemonic::Mov64);
        assert_eq!(insns[1].mnemonic, Mnemonic::Exit);
    }

    #[test]
    fn test_decode_atomic_add64() {
        // lock *(u64 *)(r1 + 0) += r2
        // opcode = STX class (0x03) | DW size (0x18) | ATOMIC mode (0xC0) = 0xDB
        // imm = 0x00 (ADD)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicAdd64);
        assert_eq!(
            insn.dst,
            Operand::Mem {
                base: Register::R1,
                offset: 0
            }
        );
        assert_eq!(insn.src, Operand::Reg(Register::R2));
    }

    #[test]
    fn test_decode_atomic_add32() {
        // lock *(u32 *)(r1 + 0) += r2
        // opcode = STX class (0x03) | W size (0x00) | ATOMIC mode (0xC0) = 0xC3
        // imm = 0x00 (ADD)
        let bytes = [0xc3, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicAdd32);
    }

    #[test]
    fn test_decode_atomic_fetch_add64() {
        // r2 = atomic_fetch_add((u64 *)(r1 + 0), r2)
        // opcode = 0xDB, imm = 0x01 (ADD | FETCH)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicFetchAdd64);
    }

    #[test]
    fn test_decode_atomic_or64() {
        // lock *(u64 *)(r1 + 0) |= r2
        // opcode = 0xDB, imm = 0x40 (OR)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicOr64);
    }

    #[test]
    fn test_decode_atomic_and64() {
        // lock *(u64 *)(r1 + 0) &= r2
        // opcode = 0xDB, imm = 0x50 (AND)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicAnd64);
    }

    #[test]
    fn test_decode_atomic_xor64() {
        // lock *(u64 *)(r1 + 0) ^= r2
        // opcode = 0xDB, imm = 0xa0 (XOR)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicXor64);
    }

    #[test]
    fn test_decode_atomic_xchg64() {
        // r2 = xchg((u64 *)(r1 + 0), r2)
        // opcode = 0xDB, imm = 0xe1 (XCHG)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicXchg64);
    }

    #[test]
    fn test_decode_atomic_cmpxchg64() {
        // r0 = cmpxchg((u64 *)(r1 + 0), r0, r2)
        // opcode = 0xDB, imm = 0xf1 (CMPXCHG)
        let bytes = [0xdb, 0x21, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes).unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::AtomicCmpxchg64);
    }
}
