//! eBPF assembler with labels.
//!
//! ```
//! use ebpf_asm::{Assembler, R0};
//!
//! let mut asm = Assembler::new();
//! let loop_start = asm.label();
//!
//! asm.mov64_imm(R0, 10);
//! asm.bind(loop_start);
//! asm.sub64_imm(R0, 1);
//! asm.jne_imm(R0, 0, loop_start);
//! asm.exit();
//!
//! let code = asm.assemble().unwrap();
//! ```

use std::fmt;

use crate::instruction::{alu, atomic, class, jmp, mode, size, RawInstruction, SRC_IMM, SRC_REG};
#[cfg(test)]
use crate::mnemonic::Mnemonic;
use crate::register::Register;
#[cfg(test)]
use crate::register::{R0, R1};

/// Why [`Assembler::assemble`] failed. The fields are instruction indices, where `lddw` counts as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    /// Instruction `insn` jumps to a label that [`Assembler::bind`] never bound.
    #[allow(missing_docs)]
    UnboundLabel { insn: usize },
    /// The jump from instruction `from` to instruction `to` doesn't fit the offset field of the instruction.
    #[allow(missing_docs)]
    OffsetOutOfRange { from: usize, to: usize },
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsmError::UnboundLabel { insn } => write!(f, "instruction {insn} jumps to a label that is not bound"),
            AsmError::OffsetOutOfRange { from, to } => {
                write!(f, "jump offset out of range: {from} -> {to}")
            }
        }
    }
}

impl std::error::Error for AsmError {}

/// A branch target of one [`Assembler`], created with [`Assembler::label`] and bound with [`Assembler::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label {
    id: usize,
}

/// A label reference that needs to be resolved.
#[derive(Debug, Clone)]
struct LabelRef {
    label_id: usize,
    /// Index of the referencing instruction entry.
    insn_index: usize,
    ref_type: LabelRefType,
}

#[derive(Debug, Clone, Copy)]
enum LabelRefType {
    /// Conditional jump or JA in the JMP64 class: offset in bits 16-31.
    Jump,
    /// BPF-to-BPF call or JA in the JMP32 class: offset in bits 32-63 (imm field).
    Imm32,
}

#[derive(Debug, Clone)]
struct AsmInsn {
    raw: RawInstruction,
    /// Second slot of LDDW.
    raw2: Option<RawInstruction>,
}

// Each `*_family!` row names the mnemonic its methods decode to. The macro also emits `$cases`, a test-only table of
// every method it defines, which `tests::every_method_decodes_to_its_mnemonic` runs through the decoder.

/// An assembler method called with fixed operands, and the mnemonic its output must decode to.
#[cfg(test)]
type Case = (&'static str, fn(&mut Assembler) -> &mut Assembler, Mnemonic);

/// Emits a jump through `emit` that targets the instruction after it.
#[cfg(test)]
fn jump_to_next(asm: &mut Assembler, emit: fn(&mut Assembler, Label) -> &mut Assembler) -> &mut Assembler {
    let next = asm.label();
    emit(asm, next).bind(next)
}

/// Emits a register/immediate pair of ALU instruction methods for one opcode. `$off` is the ALU `offset` nibble eBPF
/// uses to pick the signed variant of DIV/MOD.
macro_rules! alu_family {
    ($cases:ident, $class:ident; $( $name:ident, $name_imm:ident = $op:ident, $off:expr => $mnem:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, src`")]
            pub fn $name(&mut self, dst: Register, src: Register) -> &mut Self {
                let opcode = class::$class | alu::$op | SRC_REG;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), $off, 0));
                self
            }

            #[doc = concat!("`", stringify!($name_imm), " dst, imm`")]
            pub fn $name_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
                let opcode = class::$class | alu::$op | SRC_IMM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, $off, imm));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R0, R1), Mnemonic::$mnem),
            (stringify!($name_imm), |a| a.$name_imm(R0, 1), Mnemonic::$mnem),
        )+];
    };
}

/// Emits one sign-extending move method per (source width, class) row. `$off` is the ALU `offset` nibble that selects
/// the source width to sign-extend from.
macro_rules! movsx_family {
    ($cases:ident; $( $name:ident = $class:ident, $off:expr => $mnem:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, src`")]
            pub fn $name(&mut self, dst: Register, src: Register) -> &mut Self {
                let opcode = class::$class | alu::MOV | SRC_REG;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), $off, 0));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R0, R1), Mnemonic::$mnem),
        )+];
    };
}

/// Emits a register/immediate pair of conditional jump methods for one opcode.
macro_rules! jmp_family {
    ($cases:ident, $class:ident; $( $name:ident, $name_imm:ident = $op:ident => $mnem:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, src, label`")]
            pub fn $name(&mut self, dst: Register, src: Register, label: Label) -> &mut Self {
                let opcode = class::$class | jmp::$op | SRC_REG;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
                self.add_label_ref(label, LabelRefType::Jump);
                self
            }

            #[doc = concat!("`", stringify!($name_imm), " dst, imm, label`")]
            pub fn $name_imm(&mut self, dst: Register, imm: i32, label: Label) -> &mut Self {
                let opcode = class::$class | jmp::$op | SRC_IMM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
                self.add_label_ref(label, LabelRefType::Jump);
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| jump_to_next(a, |a, l| a.$name(R0, R1, l)), Mnemonic::$mnem),
            (stringify!($name_imm), |a| jump_to_next(a, |a, l| a.$name_imm(R0, 1, l)), Mnemonic::$mnem),
        )+];
    };
}

/// Emits one load-from-memory method per (mnemonic, size, mode) row.
macro_rules! ldx_family {
    ($cases:ident; $( $name:ident = $size:ident, $mode:ident => $mnem:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, [src+off]`")]
            pub fn $name(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
                let opcode = class::LDX | size::$size | mode::$mode;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R0, R1, 0), Mnemonic::$mnem),
        )+];
    };
}

/// Emits one store-to-memory-from-register method per size.
macro_rules! stx_family {
    ($cases:ident; $( $name:ident = $size:ident => $mnem:ident );+ $(;)?) => {
        $(
            #[doc = concat!("`", stringify!($name), " [dst+off], src`")]
            pub fn $name(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::MEM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R1, 0, R0), Mnemonic::$mnem),
        )+];
    };
}

/// Emits one store-immediate-to-memory method per size.
macro_rules! st_family {
    ($cases:ident; $( $name:ident = $size:ident => $mnem:ident );+ $(;)?) => {
        $(
            #[doc = concat!("`", stringify!($name), " [dst+off], imm`")]
            pub fn $name(&mut self, dst: Register, offset: i16, imm: i32) -> &mut Self {
                let opcode = class::ST | size::$size | mode::MEM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R1, 0, 1), Mnemonic::$mnem),
        )+];
    };
}

/// Emits a non-fetch/fetch pair of atomic read-modify-write methods per op, for one memory size. `xchg` and `cmpxchg`
/// always report the prior value, so they are defined separately instead of through this macro.
macro_rules! atomic_family {
    ($cases:ident, $size:ident; $( $name:ident, $name_fetch:ident = $op:ident => $mnem:ident, $mnem_fetch:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " [dst+off], src`")]
            pub fn $name(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::ATOMIC;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::$op));
                self
            }

            #[doc = concat!("`", stringify!($name_fetch), " [dst+off], src`")]
            pub fn $name_fetch(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::ATOMIC;
                let imm = atomic::$op | atomic::FETCH;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, imm));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R1, 0, R0), Mnemonic::$mnem),
            (stringify!($name_fetch), |a| a.$name_fetch(R1, 0, R0), Mnemonic::$mnem_fetch),
        )+];
    };
}

/// Emits a load-acquire and a store-release method per memory size, with the operand order of `ldx*` and `stx*`.
macro_rules! acquire_release_family {
    ($cases:ident; $( $load:ident, $store:ident = $size:ident => $mnem_load:ident, $mnem_store:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($load), " dst, [src+off]`")]
            pub fn $load(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
                let opcode = class::STX | size::$size | mode::ATOMIC;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::LOAD_ACQ));
                self
            }

            #[doc = concat!("`", stringify!($store), " [dst+off], src`")]
            pub fn $store(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::ATOMIC;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::STORE_REL));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($load), |a| a.$load(R0, R1, 0), Mnemonic::$mnem_load),
            (stringify!($store), |a| a.$store(R1, 0, R0), Mnemonic::$mnem_store),
        )+];
    };
}

/// Emits one byte-swap method per bit width, for a fixed class and source type (`le*`/`be*` are ALU32 and truncate;
/// `bswap*` is ALU64 and always swaps the full width regardless of host endianness).
macro_rules! endian_family {
    ($cases:ident, $class:ident, $src:ident; $( $name:ident = $bits:expr => $mnem:ident ),+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst`")]
            pub fn $name(&mut self, dst: Register) -> &mut Self {
                let opcode = class::$class | alu::END | $src;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, $bits));
                self
            }
        )+

        #[cfg(test)]
        const $cases: &[Case] = &[$(
            (stringify!($name), |a| a.$name(R0), Mnemonic::$mnem),
        )+];
    };
}

/// Builds eBPF bytecode one instruction per method call. The instruction methods return the assembler, so calls chain.
#[derive(Default)]
pub struct Assembler {
    instructions: Vec<AsmInsn>,
    /// The instruction index each label is bound to, by label ID.
    labels: Vec<Option<usize>>,
    label_refs: Vec<LabelRef>,
}

impl Assembler {
    /// An assembler with no instructions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Slot index (8-byte units) of each instruction entry, plus the total at the end.
    fn slot_prefix(&self) -> Vec<usize> {
        let mut slots = Vec::with_capacity(self.instructions.len() + 1);
        let mut slot = 0;
        slots.push(slot);
        for insn in &self.instructions {
            slot += if insn.raw2.is_some() { 2 } else { 1 };
            slots.push(slot);
        }
        slots
    }

    /// A new label, not bound yet.
    pub fn label(&mut self) -> Label {
        self.labels.push(None);
        Label {
            id: self.labels.len() - 1,
        }
    }

    /// Bind `label` to the next instruction added.
    ///
    /// # Panics
    ///
    /// Panics if `label` is already bound or comes from another assembler.
    pub fn bind(&mut self, label: Label) -> &mut Self {
        let position = self.instructions.len();
        let bound = self.labels[label.id].replace(position);
        assert!(bound.is_none(), "label bound twice");
        self
    }

    /// Add a single-slot instruction.
    fn emit(&mut self, raw: RawInstruction) {
        self.instructions.push(AsmInsn { raw, raw2: None });
    }

    /// Add a wide (16-byte) instruction.
    fn emit_wide(&mut self, raw: RawInstruction, raw2: RawInstruction) {
        self.instructions.push(AsmInsn { raw, raw2: Some(raw2) });
    }

    /// Reference `label` from the last emitted instruction.
    fn add_label_ref(&mut self, label: Label, ref_type: LabelRefType) {
        self.label_refs.push(LabelRef {
            label_id: label.id,
            insn_index: self.instructions.len() - 1,
            ref_type,
        });
    }

    /// Resolve all label references and return the bytecode.
    pub fn assemble(&self) -> Result<Vec<u8>, AsmError> {
        let mut code = Vec::with_capacity(self.instructions.len() * 8);
        for insn in &self.instructions {
            code.extend_from_slice(&insn.raw.to_le_bytes());
            if let Some(raw2) = insn.raw2 {
                code.extend_from_slice(&raw2.to_le_bytes());
            }
        }

        // Labels and refs hold entry indices; jumps count 8-byte slots (LDDW takes two).
        let slot_of = self.slot_prefix();
        for label_ref in &self.label_refs {
            let from = label_ref.insn_index;
            let to = self.labels[label_ref.label_id].ok_or(AsmError::UnboundLabel { insn: from })?;
            // eBPF jumps are relative to the next slot
            let offset = slot_of[to] as i64 - (slot_of[from] as i64 + 1);
            let out_of_range = AsmError::OffsetOutOfRange { from, to };

            let insn = &mut code[slot_of[from] * 8..][..8];
            match label_ref.ref_type {
                LabelRefType::Jump => {
                    let offset = i16::try_from(offset).map_err(|_| out_of_range)?;
                    insn[2..4].copy_from_slice(&offset.to_le_bytes());
                }
                LabelRefType::Imm32 => {
                    let offset = i32::try_from(offset).map_err(|_| out_of_range)?;
                    insn[4..8].copy_from_slice(&offset.to_le_bytes());
                }
            }
        }

        Ok(code)
    }

    /// `neg64 dst`: 64-bit negation.
    pub fn neg64(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    /// `neg32 dst`: 32-bit negation.
    pub fn neg32(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    alu_family!(ALU64_CASES, ALU64;
        add64, add64_imm = ADD, 0 => Add64;
        sub64, sub64_imm = SUB, 0 => Sub64;
        mul64, mul64_imm = MUL, 0 => Mul64;
        div64, div64_imm = DIV, 0 => Div64;
        sdiv64, sdiv64_imm = DIV, 1 => SDiv64;
        or64, or64_imm = OR, 0 => Or64;
        and64, and64_imm = AND, 0 => And64;
        lsh64, lsh64_imm = LSH, 0 => Lsh64;
        rsh64, rsh64_imm = RSH, 0 => Rsh64;
        mod64, mod64_imm = MOD, 0 => Mod64;
        smod64, smod64_imm = MOD, 1 => SMod64;
        xor64, xor64_imm = XOR, 0 => Xor64;
        mov64, mov64_imm = MOV, 0 => Mov64;
        arsh64, arsh64_imm = ARSH, 0 => Arsh64;
    );

    alu_family!(ALU32_CASES, ALU32;
        add32, add32_imm = ADD, 0 => Add32;
        sub32, sub32_imm = SUB, 0 => Sub32;
        mul32, mul32_imm = MUL, 0 => Mul32;
        div32, div32_imm = DIV, 0 => Div32;
        sdiv32, sdiv32_imm = DIV, 1 => SDiv32;
        or32, or32_imm = OR, 0 => Or32;
        and32, and32_imm = AND, 0 => And32;
        lsh32, lsh32_imm = LSH, 0 => Lsh32;
        rsh32, rsh32_imm = RSH, 0 => Rsh32;
        mod32, mod32_imm = MOD, 0 => Mod32;
        smod32, smod32_imm = MOD, 1 => SMod32;
        xor32, xor32_imm = XOR, 0 => Xor32;
        mov32, mov32_imm = MOV, 0 => Mov32;
        arsh32, arsh32_imm = ARSH, 0 => Arsh32;
    );

    movsx_family!(MOVSX_CASES;
        movsx832 = ALU32, 8 => Movsx832;
        movsx1632 = ALU32, 16 => Movsx1632;
        movsx864 = ALU64, 8 => Movsx864;
        movsx1664 = ALU64, 16 => Movsx1664;
        movsx3264 = ALU64, 32 => Movsx3264;
    );

    endian_family!(LE_CASES, ALU32, SRC_IMM; le16 = 16 => Le16, le32 = 32 => Le32, le64 = 64 => Le64);
    endian_family!(BE_CASES, ALU32, SRC_REG; be16 = 16 => Be16, be32 = 32 => Be32, be64 = 64 => Be64);
    endian_family!(BSWAP_CASES, ALU64, SRC_IMM; bswap16 = 16 => Bswap16, bswap32 = 32 => Bswap32, bswap64 = 64 => Bswap64);

    ldx_family!(LDX_CASES;
        ldxdw = DW, MEM => Ldxdw;
        ldxw = W, MEM => Ldxw;
        ldxh = H, MEM => Ldxh;
        ldxb = B, MEM => Ldxb;
        ldxsw = W, MEMSX => Ldxsw;
        ldxsh = H, MEMSX => Ldxsh;
        ldxsb = B, MEMSX => Ldxsb;
    );

    /// `lddw dst, imm64`: load a 64-bit immediate.
    pub fn lddw(&mut self, dst: Register, imm: i64) -> &mut Self {
        let opcode = class::LD | size::DW | mode::IMM;
        let imm_lo = imm as u32 as i32;
        let imm_hi = (imm as u64 >> 32) as u32 as i32;
        let raw1 = RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm_lo);
        let raw2 = RawInstruction::from_parts(0, 0, 0, 0, imm_hi);
        self.emit_wide(raw1, raw2);
        self
    }

    stx_family!(STX_CASES; stxdw = DW => Stxdw; stxw = W => Stxw; stxh = H => Stxh; stxb = B => Stxb);
    st_family!(ST_CASES; stdw = DW => Stdw; stw = W => Stw; sth = H => Sth; stb = B => Stb);

    atomic_family!(ATOMIC64_CASES, DW;
        atomic_add64, atomic_fetch_add64 = ADD => AtomicAdd64, AtomicFetchAdd64;
        atomic_or64, atomic_fetch_or64 = OR => AtomicOr64, AtomicFetchOr64;
        atomic_and64, atomic_fetch_and64 = AND => AtomicAnd64, AtomicFetchAnd64;
        atomic_xor64, atomic_fetch_xor64 = XOR => AtomicXor64, AtomicFetchXor64;
    );
    atomic_family!(ATOMIC32_CASES, W;
        atomic_add32, atomic_fetch_add32 = ADD => AtomicAdd32, AtomicFetchAdd32;
        atomic_or32, atomic_fetch_or32 = OR => AtomicOr32, AtomicFetchOr32;
        atomic_and32, atomic_fetch_and32 = AND => AtomicAnd32, AtomicFetchAnd32;
        atomic_xor32, atomic_fetch_xor32 = XOR => AtomicXor32, AtomicFetchXor32;
    );

    /// `lock xchg64 [dst+off], src`: 64-bit atomic exchange; always reports the prior value.
    pub fn atomic_xchg64(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::DW | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::XCHG));
        self
    }

    /// `lock xchg32 [dst+off], src`: 32-bit atomic exchange; always reports the prior value.
    pub fn atomic_xchg32(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::W | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::XCHG));
        self
    }

    /// `lock cmpxchg64 [dst+off], src`: 64-bit atomic compare-and-exchange against `r0`; always reports the prior value
    /// in `r0`.
    pub fn atomic_cmpxchg64(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::DW | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::CMPXCHG));
        self
    }

    /// `lock cmpxchg32 [dst+off], src`: 32-bit atomic compare-and-exchange against `r0`; always reports the prior value
    /// in `r0`.
    pub fn atomic_cmpxchg32(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::W | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::CMPXCHG));
        self
    }

    acquire_release_family!(ACQUIRE_RELEASE_CASES;
        load_acquire64, store_release64 = DW => LoadAcquire64, StoreRelease64;
        load_acquire32, store_release32 = W => LoadAcquire32, StoreRelease32;
        load_acquire16, store_release16 = H => LoadAcquire16, StoreRelease16;
        load_acquire8, store_release8 = B => LoadAcquire8, StoreRelease8;
    );

    /// `ja label`: unconditional jump to a label.
    pub fn ja(&mut self, label: Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::Jump);
        self
    }

    /// `ja offset`: unconditional jump to a relative offset.
    pub fn ja_off(&mut self, offset: i16) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, offset, 0));
        self
    }

    /// `ja32 label`: unconditional jump in the JMP32 class, whose offset sits in the 32-bit `imm` field instead of the
    /// 16-bit `offset` (RFC 9669 Section 4.3).
    pub fn ja32(&mut self, label: Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::Imm32);
        self
    }

    /// `gotox dst`: jump to the code address in `dst`.
    pub fn gotox(&mut self, dst: Register) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    /// `may_goto label`: jump to a label once the runtime's loop budget runs out (`JMP | JCOND`, `src_reg` 0).
    pub fn may_goto(&mut self, label: Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JCOND;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::Jump);
        self
    }

    jmp_family!(JMP64_CASES, JMP64;
        jeq, jeq_imm = JEQ => Jeq;
        jne, jne_imm = JNE => Jne;
        jgt, jgt_imm = JGT => Jgt;
        jge, jge_imm = JGE => Jge;
        jlt, jlt_imm = JLT => Jlt;
        jle, jle_imm = JLE => Jle;
        jset, jset_imm = JSET => Jset;
        jsgt, jsgt_imm = JSGT => Jsgt;
        jsge, jsge_imm = JSGE => Jsge;
        jslt, jslt_imm = JSLT => Jslt;
        jsle, jsle_imm = JSLE => Jsle;
    );

    jmp_family!(JMP32_CASES, JMP32;
        jeq32, jeq32_imm = JEQ => Jeq32;
        jne32, jne32_imm = JNE => Jne32;
        jgt32, jgt32_imm = JGT => Jgt32;
        jge32, jge32_imm = JGE => Jge32;
        jlt32, jlt32_imm = JLT => Jlt32;
        jle32, jle32_imm = JLE => Jle32;
        jset32, jset32_imm = JSET => Jset32;
        jsgt32, jsgt32_imm = JSGT => Jsgt32;
        jsge32, jsge32_imm = JSGE => Jsge32;
        jslt32, jslt32_imm = JSLT => Jslt32;
        jsle32, jsle32_imm = JSLE => Jsle32;
    );

    /// `call imm`: call a helper function by ID.
    pub fn call(&mut self, func_id: i32) -> &mut Self {
        let opcode = class::JMP64 | jmp::CALL;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, func_id));
        self
    }

    /// `call label`: BPF-to-BPF call (`src_reg = 1`).
    pub fn call_local(&mut self, label: Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::CALL;
        self.emit(RawInstruction::from_parts(opcode, 0, 1, 0, 0));
        self.add_label_ref(label, LabelRefType::Imm32);
        self
    }

    /// `callx dst`: call the function whose address is in `dst`.
    pub fn callx(&mut self, dst: Register) -> &mut Self {
        let opcode = class::JMP64 | jmp::CALL | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    /// `exit`: return from the program.
    pub fn exit(&mut self) -> &mut Self {
        let opcode = class::JMP64 | jmp::EXIT;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::Decoder;

    /// The methods not defined through a `*_family!`.
    const OTHER_CASES: &[Case] = &[
        ("neg64", |a| a.neg64(R0), Mnemonic::Neg64),
        ("neg32", |a| a.neg32(R0), Mnemonic::Neg32),
        ("lddw", |a| a.lddw(R0, 0x1234), Mnemonic::Lddw),
        ("atomic_xchg64", |a| a.atomic_xchg64(R1, 0, R0), Mnemonic::AtomicXchg64),
        ("atomic_xchg32", |a| a.atomic_xchg32(R1, 0, R0), Mnemonic::AtomicXchg32),
        ("atomic_cmpxchg64", |a| a.atomic_cmpxchg64(R1, 0, R0), Mnemonic::AtomicCmpxchg64),
        ("atomic_cmpxchg32", |a| a.atomic_cmpxchg32(R1, 0, R0), Mnemonic::AtomicCmpxchg32),
        ("ja", |a| jump_to_next(a, |a, l| a.ja(l)), Mnemonic::Ja),
        ("ja_off", |a| a.ja_off(0), Mnemonic::Ja),
        ("ja32", |a| jump_to_next(a, |a, l| a.ja32(l)), Mnemonic::Ja32),
        ("gotox", |a| a.gotox(R1), Mnemonic::Gotox),
        ("may_goto", |a| jump_to_next(a, |a, l| a.may_goto(l)), Mnemonic::MayGoto),
        ("call", |a| a.call(1), Mnemonic::Call),
        ("call_local", |a| jump_to_next(a, |a, l| a.call_local(l)), Mnemonic::CallLocal),
        ("callx", |a| a.callx(R1), Mnemonic::Callx),
        ("exit", |a| a.exit(), Mnemonic::Exit),
    ];

    /// Each method emits exactly one instruction, which decodes to the mnemonic its table names.
    #[test]
    fn every_method_decodes_to_its_mnemonic() {
        let tables = [
            Assembler::ALU64_CASES,
            Assembler::ALU32_CASES,
            Assembler::MOVSX_CASES,
            Assembler::LE_CASES,
            Assembler::BE_CASES,
            Assembler::BSWAP_CASES,
            Assembler::LDX_CASES,
            Assembler::STX_CASES,
            Assembler::ST_CASES,
            Assembler::ATOMIC64_CASES,
            Assembler::ATOMIC32_CASES,
            Assembler::ACQUIRE_RELEASE_CASES,
            Assembler::JMP64_CASES,
            Assembler::JMP32_CASES,
            OTHER_CASES,
        ];

        for &(name, emit, mnemonic) in tables.iter().copied().flatten() {
            let mut asm = Assembler::new();
            emit(&mut asm);
            let code = asm.assemble().unwrap();
            let insns: Vec<_> = Decoder::new(&code).collect();
            assert_eq!(insns.len(), 1, "{name}");
            assert_eq!(insns[0].mnemonic, mnemonic, "{name}");
            assert_eq!(insns[0].size as usize, code.len(), "{name}");
        }
    }

    #[test]
    fn jump_offsets_count_lddw_slots() {
        let mut asm = Assembler::new();
        let fwd = asm.label();
        let back = asm.label();

        asm.bind(back);
        asm.ja(fwd); // slot 0
        asm.lddw(R0, 0x1_0000_0002); // slots 1-2
        asm.ja(back); // slot 3
        asm.bind(fwd);
        asm.exit(); // slot 4

        let code = asm.assemble().unwrap();
        let (words, _) = code.as_chunks::<8>();
        let insns: Vec<u64> = words.iter().map(|w| u64::from_le_bytes(*w)).collect();
        let off = |i: usize| (insns[i] >> 16) as i16;
        assert_eq!(off(0), 3); // 0 + 1 + 3 = 4 (exit)
        assert_eq!(off(3), -4); // 3 + 1 - 4 = 0
    }
}
