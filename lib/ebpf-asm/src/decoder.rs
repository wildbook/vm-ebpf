//! eBPF bytecode decoder.
//!
//! Acceptance follows llvm-objdump: a field the instruction defines must hold a valid value, a field it does not define
//! is ignored, and anything else decodes as `Mnemonic::Unknown` with no operands. Register numbers above 10 are
//! invalid, so llvm's internal `r11` decodes as `Unknown` too.

use crate::instruction::{alu, atomic, class, jmp, mode, size, Instruction, RawInstruction, SRC_REG};
use crate::mnemonic::Mnemonic;
use crate::operand::Operand;
use crate::register::Register;

/// Mnemonic and operands of a valid instruction; `None` for an invalid encoding.
type Decoded = Option<(Mnemonic, Operand, Operand)>;

/// Iterator over the instructions in eBPF bytecode.
///
/// # Example
///
/// ```
/// use ebpf_asm::Decoder;
///
/// let bytes = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // exit
/// let decoder = Decoder::new(&bytes);
/// for insn in decoder {
///     println!("{insn}");
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
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Instruction;

    fn next(&mut self) -> Option<Self::Item> {
        let start_offset = self.offset;
        let raw = self.slot(start_offset)?;
        self.offset += 8;

        let mut size = 8;
        let mut raw2 = None;
        let decoded = if raw.opcode() == LDDW {
            // the second slot only contributes its imm; an invalid first slot leaves it to decode on its own
            match (decode_lddw_head(raw), self.slot(self.offset)) {
                (Some(dst), Some(next)) => {
                    self.offset += 8;
                    size = 16;
                    raw2 = Some(next.value());
                    Some(decode_lddw(raw, dst, next))
                }
                _ => None,
            }
        } else {
            decode(raw)
        };
        let (mnemonic, dst, src) = decoded.unwrap_or((Mnemonic::Unknown, Operand::None, Operand::None));

        Some(Instruction {
            mnemonic,
            dst,
            src,
            offset: start_offset as u64,
            size,
            opcode: raw.opcode(),
            raw: raw.value(),
            raw2,
        })
    }
}

impl Decoder<'_> {
    fn slot(&self, at: usize) -> Option<RawInstruction> {
        let bytes = self.bytes.get(at..)?.get(..8)?;
        Some(RawInstruction::from_le_bytes(bytes.try_into().unwrap()))
    }
}

const LDDW: u8 = class::LD | mode::IMM | size::DW;

fn reg(number: u8) -> Option<Register> {
    Register::from_u8(number)
}

/// `[base + off]` with the base register taken from the `dst` or `src` field.
fn mem(base: u8, raw: RawInstruction) -> Option<Operand> {
    Some(Operand::Mem {
        base: reg(base)?,
        offset: raw.offset(),
    })
}

/// Decode a single-slot instruction.
fn decode(raw: RawInstruction) -> Decoded {
    match raw.class() {
        class::ALU64 => decode_alu(raw, true),
        class::ALU32 => decode_alu(raw, false),
        class::JMP64 => decode_jmp(raw, true),
        class::JMP32 => decode_jmp(raw, false),
        class::LDX => decode_ldx(raw),
        class::STX => decode_stx(raw),
        class::ST => decode_st(raw),
        _ => decode_ld(raw),
    }
}

/// Validate the first slot of a 64-bit immediate load and return its destination.
fn decode_lddw_head(raw: RawInstruction) -> Option<Register> {
    if raw.offset() != 0 {
        return None;
    }
    reg(raw.dst())
}

/// Decode a 64-bit immediate load; a nonzero `src_reg` selects a pseudo kind (map fd, map value, BTF id, ...) whose
/// meaning the loader resolves.
fn decode_lddw(raw: RawInstruction, dst: Register, next: RawInstruction) -> (Mnemonic, Operand, Operand) {
    let imm64 = (u64::from(next.imm() as u32) << 32) | u64::from(raw.imm() as u32);
    let mnemonic = match raw.src() {
        0 => Mnemonic::Lddw,
        _ => Mnemonic::LdPseudo,
    };
    (mnemonic, Operand::Reg(dst), Operand::Imm64(imm64 as i64))
}

/// Decode the legacy packet loads; LD_IMM64 is handled by the iterator.
fn decode_ld(raw: RawInstruction) -> Decoded {
    let (abs, ind) = match raw.size() {
        size::W => (Mnemonic::Ldabsw, Mnemonic::Ldindw),
        size::H => (Mnemonic::Ldabsh, Mnemonic::Ldindh),
        size::B => (Mnemonic::Ldabsb, Mnemonic::Ldindb),
        _ => return None,
    };
    match raw.mode() {
        mode::ABS => Some((abs, Operand::Imm(raw.imm()), Operand::None)),
        mode::IND => Some((ind, Operand::Reg(reg(raw.src())?), Operand::Imm(raw.imm()))),
        _ => None,
    }
}

fn decode_alu(raw: RawInstruction, is_64: bool) -> Decoded {
    let op = raw.op();
    let is_reg = raw.opcode() & SRC_REG != 0;
    let dst = Operand::Reg(reg(raw.dst())?);
    let imm = raw.imm();

    if op == alu::NEG {
        let mnemonic = if is_64 { Mnemonic::Neg64 } else { Mnemonic::Neg32 };
        return (!is_reg).then_some((mnemonic, dst, Operand::None));
    }
    if op == alu::END {
        // ALU64 is the unconditional swap; ALU32 converts to the endianness in the source bit
        let mnemonic = match (is_64, is_reg, imm) {
            (true, false, 16) => Mnemonic::Bswap16,
            (true, false, 32) => Mnemonic::Bswap32,
            (true, false, 64) => Mnemonic::Bswap64,
            (false, false, 16) => Mnemonic::Le16,
            (false, false, 32) => Mnemonic::Le32,
            (false, false, 64) => Mnemonic::Le64,
            (false, true, 16) => Mnemonic::Be16,
            (false, true, 32) => Mnemonic::Be32,
            (false, true, 64) => Mnemonic::Be64,
            _ => return None,
        };
        return Some((mnemonic, dst, Operand::None));
    }

    let pick = |m64, m32| if is_64 { m64 } else { m32 };
    let mnemonic = match (op, raw.offset()) {
        (alu::ADD, 0) => pick(Mnemonic::Add64, Mnemonic::Add32),
        (alu::SUB, 0) => pick(Mnemonic::Sub64, Mnemonic::Sub32),
        (alu::MUL, 0) => pick(Mnemonic::Mul64, Mnemonic::Mul32),
        (alu::DIV, 0) => pick(Mnemonic::Div64, Mnemonic::Div32),
        (alu::DIV, 1) => pick(Mnemonic::SDiv64, Mnemonic::SDiv32),
        (alu::OR, 0) => pick(Mnemonic::Or64, Mnemonic::Or32),
        (alu::AND, 0) => pick(Mnemonic::And64, Mnemonic::And32),
        (alu::LSH, 0) => pick(Mnemonic::Lsh64, Mnemonic::Lsh32),
        (alu::RSH, 0) => pick(Mnemonic::Rsh64, Mnemonic::Rsh32),
        (alu::MOD, 0) => pick(Mnemonic::Mod64, Mnemonic::Mod32),
        (alu::MOD, 1) => pick(Mnemonic::SMod64, Mnemonic::SMod32),
        (alu::XOR, 0) => pick(Mnemonic::Xor64, Mnemonic::Xor32),
        (alu::MOV, 0) => pick(Mnemonic::Mov64, Mnemonic::Mov32),
        (alu::ARSH, 0) => pick(Mnemonic::Arsh64, Mnemonic::Arsh32),
        // register-only moves: `off` is the source width of a sign-extending move, or 1 for an address space cast whose
        // two address spaces are packed into `imm`
        (alu::MOV, 8) if is_reg => pick(Mnemonic::Movsx864, Mnemonic::Movsx832),
        (alu::MOV, 16) if is_reg => pick(Mnemonic::Movsx1664, Mnemonic::Movsx1632),
        (alu::MOV, 32) if is_reg && is_64 => Mnemonic::Movsx3264,
        (alu::MOV, 1) if is_reg && is_64 => Mnemonic::AddrSpaceCast,
        _ => return None,
    };

    let src = if is_reg {
        Operand::Reg(reg(raw.src())?)
    } else {
        Operand::Imm(imm)
    };
    Some((mnemonic, dst, src))
}

fn decode_jmp(raw: RawInstruction, is_64: bool) -> Decoded {
    let op = raw.op();
    let is_reg = raw.opcode() & SRC_REG != 0;
    let off = Operand::Off(raw.offset().into());

    match (op, is_64, is_reg) {
        // JMP64 `ja` jumps by `off`, JMP32 `ja32` (`gotol`) by the 32-bit `imm`
        (jmp::JA, true, false) => Some((Mnemonic::Ja, off, Operand::None)),
        (jmp::JA, false, false) => Some((Mnemonic::Ja32, Operand::Off(raw.imm()), Operand::None)),
        (jmp::JA, true, true) => Some((Mnemonic::Gotox, Operand::Reg(reg(raw.dst())?), Operand::None)),
        (jmp::CALL, true, false) => {
            let mnemonic = match raw.src() {
                1 => Mnemonic::CallLocal,
                2 => Mnemonic::CallKfunc,
                _ => Mnemonic::Call,
            };
            Some((mnemonic, Operand::Imm(raw.imm()), Operand::None))
        }
        (jmp::CALL, true, true) => Some((Mnemonic::Callx, Operand::Reg(reg(raw.dst())?), Operand::None)),
        (jmp::EXIT, true, false) if raw.imm() == 0 => Some((Mnemonic::Exit, Operand::None, Operand::None)),
        (jmp::JCOND, true, false) => Some((Mnemonic::MayGoto, off, Operand::None)),
        (jmp::JA | jmp::CALL | jmp::EXIT | jmp::JCOND, _, _) => None,
        _ => decode_cond_jmp(raw, is_64),
    }
}

fn decode_cond_jmp(raw: RawInstruction, is_64: bool) -> Decoded {
    let pick = |m64, m32| if is_64 { m64 } else { m32 };
    let mnemonic = match raw.op() {
        jmp::JEQ => pick(Mnemonic::Jeq, Mnemonic::Jeq32),
        jmp::JGT => pick(Mnemonic::Jgt, Mnemonic::Jgt32),
        jmp::JGE => pick(Mnemonic::Jge, Mnemonic::Jge32),
        jmp::JLT => pick(Mnemonic::Jlt, Mnemonic::Jlt32),
        jmp::JLE => pick(Mnemonic::Jle, Mnemonic::Jle32),
        jmp::JSET => pick(Mnemonic::Jset, Mnemonic::Jset32),
        jmp::JNE => pick(Mnemonic::Jne, Mnemonic::Jne32),
        jmp::JSGT => pick(Mnemonic::Jsgt, Mnemonic::Jsgt32),
        jmp::JSGE => pick(Mnemonic::Jsge, Mnemonic::Jsge32),
        jmp::JSLT => pick(Mnemonic::Jslt, Mnemonic::Jslt32),
        jmp::JSLE => pick(Mnemonic::Jsle, Mnemonic::Jsle32),
        _ => return None,
    };

    // the formatter reads the branch offset from the raw instruction
    let src = if raw.opcode() & SRC_REG != 0 {
        Operand::Reg(reg(raw.src())?)
    } else {
        Operand::Imm(raw.imm())
    };
    Some((mnemonic, Operand::Reg(reg(raw.dst())?), src))
}

fn decode_ldx(raw: RawInstruction) -> Decoded {
    let mnemonic = match (raw.mode(), raw.size()) {
        (mode::MEM, size::DW) => Mnemonic::Ldxdw,
        (mode::MEM, size::W) => Mnemonic::Ldxw,
        (mode::MEM, size::H) => Mnemonic::Ldxh,
        (mode::MEM, size::B) => Mnemonic::Ldxb,
        (mode::MEMSX, size::W) => Mnemonic::Ldxsw,
        (mode::MEMSX, size::H) => Mnemonic::Ldxsh,
        (mode::MEMSX, size::B) => Mnemonic::Ldxsb,
        _ => return None,
    };
    Some((mnemonic, Operand::Reg(reg(raw.dst())?), mem(raw.src(), raw)?))
}

fn decode_stx(raw: RawInstruction) -> Decoded {
    let mem_size = raw.size();
    let mnemonic = match raw.mode() {
        mode::ATOMIC => decode_atomic(mem_size, raw.imm())?,
        mode::MEM => match mem_size {
            size::DW => Mnemonic::Stxdw,
            size::W => Mnemonic::Stxw,
            size::H => Mnemonic::Stxh,
            _ => Mnemonic::Stxb,
        },
        _ => return None,
    };
    let load = matches!(
        mnemonic,
        Mnemonic::LoadAcquire64 | Mnemonic::LoadAcquire32 | Mnemonic::LoadAcquire16 | Mnemonic::LoadAcquire8
    );
    match load {
        true => Some((mnemonic, Operand::Reg(reg(raw.dst())?), mem(raw.src(), raw)?)),
        false => Some((mnemonic, mem(raw.dst(), raw)?, Operand::Reg(reg(raw.src())?))),
    }
}

/// Pick the atomic operation from `imm` as llvm does. For W and DW, bits 0-3 equal to 1 select a fetching operation
/// from bits 4-7. Otherwise bits 4-8 equal to 0x10 select load-acquire and 0x11 store-release, of any size, and failing
/// that bits 4-7 select a W or DW operation without fetch. The remaining bits are ignored.
fn decode_atomic(mem_size: u8, imm: i32) -> Option<Mnemonic> {
    use Mnemonic::*;

    let wide = matches!(mem_size, size::DW | size::W);
    let pick = |m64, m32| match mem_size {
        size::DW => Some(m64),
        size::W => Some(m32),
        _ => None,
    };
    let any_size = |m64, m32, m16, m8| match mem_size {
        size::DW => m64,
        size::W => m32,
        size::H => m16,
        _ => m8,
    };

    let op = imm & 0xF0;
    if imm & 0x0F == atomic::FETCH && wide {
        match op {
            atomic::ADD => return pick(AtomicFetchAdd64, AtomicFetchAdd32),
            atomic::OR => return pick(AtomicFetchOr64, AtomicFetchOr32),
            atomic::AND => return pick(AtomicFetchAnd64, AtomicFetchAnd32),
            atomic::XOR => return pick(AtomicFetchXor64, AtomicFetchXor32),
            _ if op == atomic::XCHG & 0xF0 => return pick(AtomicXchg64, AtomicXchg32),
            _ if op == atomic::CMPXCHG & 0xF0 => return pick(AtomicCmpxchg64, AtomicCmpxchg32),
            _ => {}
        }
    }
    match imm & 0x1F0 {
        atomic::LOAD_ACQ => return Some(any_size(LoadAcquire64, LoadAcquire32, LoadAcquire16, LoadAcquire8)),
        atomic::STORE_REL => return Some(any_size(StoreRelease64, StoreRelease32, StoreRelease16, StoreRelease8)),
        _ => {}
    }
    match op {
        atomic::ADD => pick(AtomicAdd64, AtomicAdd32),
        atomic::OR => pick(AtomicOr64, AtomicOr32),
        atomic::AND => pick(AtomicAnd64, AtomicAnd32),
        atomic::XOR => pick(AtomicXor64, AtomicXor32),
        _ => None,
    }
}

fn decode_st(raw: RawInstruction) -> Decoded {
    if raw.mode() != mode::MEM {
        return None;
    }
    let mnemonic = match raw.size() {
        size::DW => Mnemonic::Stdw,
        size::W => Mnemonic::Stw,
        size::H => Mnemonic::Sth,
        _ => Mnemonic::Stb,
    };
    Some((mnemonic, mem(raw.dst(), raw)?, Operand::Imm(raw.imm())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodings where field validation matters, with llvm-objdump 22's text for the same bytes. llvm ignores fields an
    /// instruction does not define and rejects defined fields with invalid values; register 11, which llvm prints as
    /// `r11`, is out of the ISA's range.
    #[test]
    fn field_validation_matches_llvm() {
        #[rustfmt::skip]
        let table = [
            // bytes, llvm-objdump, ebpf-asm
            ("bf2b000000000000", "r11 = r2", "unknown"),
            ("bfc1000000000000", "<unknown>", "unknown"),
            ("612c000000000000", "<unknown>", "unknown"),
            // ST/STX modes other than MEM, sizes other than W/DW for read-modify-write atomics
            ("0221030004000000", "<unknown>", "unknown"),
            ("e221030004000000", "<unknown>", "unknown"),
            ("6221030004000000", "*(u32 *)(r1 + 0x3) = 0x4", "stw [r1+0x3], 0x4"),
            ("0321030004000000", "<unknown>", "unknown"),
            ("cb21000000000000", "<unknown>", "unknown"),
            ("d321000000000000", "<unknown>", "unknown"),
            // atomic imm: bits 4-7 select the operation, bits 0-3 equal to 1 fetch
            ("c321030004000000", "lock *(u32 *)(r1 + 0x3) += w2", "lock add32 [r1+0x3], r2"),
            ("db21000041000000", "r2 = atomic_fetch_or((u64 *)(r1 + 0x0), r2)", "lock for64 [r1+0x0], r2"),
            ("db210000e0000000", "<unknown>", "unknown"),
            ("db21030010000000", "<unknown>", "unknown"),
            // load-acquire (bits 4-8 0x10) reads through src into dst, store-release (0x11) stores src; any size
            ("db10000000010000", "r0 = load_acquire((u64 *)(r1 + 0x0))", "load_acquire64 r0, [r1+0x0]"),
            ("db21000010010000", "store_release((u64 *)(r1 + 0x0), r2)", "store_release64 [r1+0x0], r2"),
            ("d310000000010000", "w0 = load_acquire((u8 *)(r1 + 0x0))", "load_acquire8 r0, [r1+0x0]"),
            ("cb21f8ff10010000", "store_release((u16 *)(r1 - 0x8), w2)", "store_release16 [r1-0x8], r2"),
            ("db21030010030080", "store_release((u64 *)(r1 + 0x3), r2)", "store_release64 [r1+0x3], r2"),
            ("db1b000000010000", "r11 = load_acquire((u64 *)(r1 + 0x0))", "unknown"),
            // a W or DW fetch wins over load-acquire; B and H have none
            ("c321030001010000", "w2 = atomic_fetch_add((u32 *)(r1 + 0x3), w2)", "lock fadd32 [r1+0x3], r2"),
            ("cb21030001010000", "w1 = load_acquire((u16 *)(r2 + 0x3))", "load_acquire16 r1, [r2+0x3]"),
            // JMP32 has no call, exit or gotox; exit takes no X bit and needs imm 0
            ("8621030004000000", "<unknown>", "unknown"),
            ("8e21000000000000", "<unknown>", "unknown"),
            ("9621000000000000", "<unknown>", "unknown"),
            ("0e21030004000000", "<unknown>", "unknown"),
            ("9d21030004000000", "<unknown>", "unknown"),
            ("9521000002000000", "<unknown>", "unknown"),
            ("9521030000000000", "exit", "exit"),
            // `off` selects movsx, sdiv/smod or addr_space_cast and is reserved elsewhere
            ("b421080010000000", "<unknown>", "unknown"),
            ("bc21200000000000", "<unknown>", "unknown"),
            ("bf21080000000000", "r1 = (s8)r2", "movsx864 r1, r2"),
            ("3f21010000000000", "r1 s/= r2", "sdiv64 r1, r2"),
            ("0421030004000000", "<unknown>", "unknown"),
            ("bf01010007000000", "r1 = addr_space_cast(r0, 0x0, 0x7)", "addr_space_cast r1, r0, 0x0, 0x7"),
            // undefined fields are ignored: imm of a register ALU op, src of neg
            ("0c21000002000000", "w1 += w2", "add32 r1, r2"),
            ("8421030004000000", "w1 = -w1", "neg32 r1"),
            ("8c21000000000000", "<unknown>", "unknown"),
            ("df21000010000000", "<unknown>", "unknown"),
            // LD_IMM64 pseudo kinds, reserved `off`
            ("18110000030000000000000000000000", "ld_pseudo\tr1, 0x1, 0x3", "ld_pseudo r1, 0x1, 0x3"),
            ("18010100030000000000000000000000", "<unknown>", "unknown"),
            // legacy packet loads and may_goto
            ("2000000004000000", "r0 = *(u32 *)skb[0x4]", "ldabsw 0x4"),
            ("5021030004000000", "r0 = *(u8 *)skb[r2]", "ldindb r2, 0x4"),
            ("3800000004000000", "<unknown>", "unknown"),
            ("e521030004000000", "may_goto +0x3", "may_goto +3"),
            ("ed21030000000000", "<unknown>", "unknown"),
        ];

        for (hex, llvm, want) in table {
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..][..2], 16).unwrap())
                .collect();
            let insn = Decoder::new(&bytes).next().unwrap();
            assert_eq!(insn.to_string(), want, "{hex} (llvm: {llvm})");
        }
    }

    #[test]
    fn decode_lddw_pair() {
        // lddw r0, 0x123456789abcdef0
        let bytes = [
            0x18, 0x00, 0x00, 0x00, 0xf0, 0xde, 0xbc, 0x9a, // first insn: imm = low 32 bits
            0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, // second insn: imm = high 32 bits
        ];
        let insn = Decoder::new(&bytes).next().unwrap();
        assert_eq!(insn.mnemonic, Mnemonic::Lddw);
        assert_eq!(insn.size, 16);
        assert_eq!(insn.src, Operand::Imm64(0x123456789abcdef0u64 as i64));
    }
}
