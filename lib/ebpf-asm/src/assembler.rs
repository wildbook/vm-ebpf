//! eBPF assembler with label support and CO-RE relocation tracking.
//!
//! Provides a builder-style API for creating eBPF bytecode with automatic
//! label resolution for branches and CO-RE (Compile Once - Run Everywhere)
//! relocation tracking.
//!
//! # Basic Example
//!
//! ```
//! use ebpf_asm::{Assembler, R0, R1};
//!
//! let mut asm = Assembler::new();
//!
//! // Create a label for a loop
//! let mut loop_start = asm.create_label();
//!
//! // mov64 r0, 10
//! asm.mov64_imm(R0, 10);
//!
//! // loop_start:
//! asm.set_label(&mut loop_start).unwrap();
//!
//! // sub64 r0, 1
//! asm.sub64_imm(R0, 1);
//!
//! // jne r0, 0, loop_start
//! asm.jne_imm(R0, 0, &loop_start);
//!
//! // exit
//! asm.exit();
//!
//! let code = asm.assemble().unwrap();
//! ```
//!
//! # CO-RE Example
//!
//! ```
//! use btf::CoreReloKind;
//! use ebpf_asm::{Assembler, R1, R3};
//!
//! let mut asm = Assembler::new();
//!
//! // Load a field offset that will be patched by CO-RE at load time
//! asm.mov64_imm(R3, 8);  // placeholder offset
//! asm.mark_core_relo(CoreReloKind::FieldByteOffset, 1, 17);  // type_id=1, access_str_off=17
//!
//! asm.add64(R1, R3);
//! asm.exit();
//!
//! let result = asm.assemble_with_core().unwrap();
//! assert_eq!(result.relocations.len(), 1);
//! assert_eq!(result.relocations[0].insn_off, 0);  // first instruction
//! ```

use std::collections::HashMap;
use std::fmt;

use btf::{CoreRelo, CoreReloKind};

use crate::instruction::{alu, atomic, class, jmp, mode, size, RawInstruction, SRC_IMM, SRC_REG};
use crate::register::Register;

/// Assembler error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    /// Label was not defined (set_label never called).
    UndefinedLabel(String),
    /// Label was already defined.
    DuplicateLabel(String),
    /// Jump offset is out of range for i16.
    #[allow(missing_docs)]
    OffsetOutOfRange { from: usize, to: usize },
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsmError::UndefinedLabel(name) => write!(f, "undefined label: {name}"),
            AsmError::DuplicateLabel(name) => write!(f, "duplicate label: {name}"),
            AsmError::OffsetOutOfRange { from, to } => {
                write!(f, "jump offset out of range: {from} -> {to}")
            }
        }
    }
}

impl std::error::Error for AsmError {}

/// Pending CO-RE relocation (attached to an instruction index, not yet resolved to bytes).
#[derive(Debug, Clone)]
struct PendingCoreRelo {
    /// Instruction index this relocation applies to.
    insn_index: usize,
    /// BTF type ID.
    type_id: u32,
    /// Access string offset in BTF strings.
    access_str_off: u32,
    /// Relocation kind.
    kind: CoreReloKind,
}

/// Result of assembling with CO-RE relocation tracking.
#[derive(Debug, Clone)]
pub struct AssembledProgram {
    /// The assembled bytecode.
    pub bytecode: Vec<u8>,
    /// CO-RE relocations with resolved byte offsets.
    pub relocations: Vec<CoreRelo>,
}

impl AssembledProgram {
    /// Get the bytecode as u64 instruction words.
    pub fn instructions(&self) -> Vec<u64> {
        let (words, _) = self.bytecode.as_chunks::<8>();
        words.iter().map(|w| u64::from_le_bytes(*w)).collect()
    }
}

/// A label identifier for branch targets.
///
/// Labels are created with `Assembler::create_label()` and bound to
/// a position with `Assembler::set_label()`.
#[derive(Debug, Clone)]
pub struct Label {
    id: usize,
    name: Option<String>,
    position: Option<usize>,
}

impl Label {
    fn new(id: usize) -> Self {
        Self {
            id,
            name: None,
            position: None,
        }
    }
}

/// A reference to a label that needs to be resolved.
#[derive(Debug, Clone)]
struct LabelRef {
    /// Label ID being referenced.
    label_id: usize,
    /// Instruction index where the reference occurs.
    insn_index: usize,
    /// Type of reference (determines how offset is encoded).
    ref_type: LabelRefType,
}

#[derive(Debug, Clone, Copy)]
enum LabelRefType {
    /// Jump (conditional or JA in the JMP64 class) - offset in bits 16-31.
    Jump,
    /// BPF-to-BPF call or JA in the JMP32 class - offset in bits 32-63 (imm field).
    Imm32,
}

/// Internal instruction representation during assembly.
#[derive(Debug, Clone)]
struct AsmInsn {
    raw: RawInstruction,
    /// Second instruction for LDDW.
    raw2: Option<RawInstruction>,
}

/// Emits a register/immediate pair of ALU instruction methods for one opcode. `$off`
/// is the ALU `offset` nibble eBPF uses to pick the signed variant of DIV/MOD.
macro_rules! alu_family {
    ($class:ident; $( $name:ident, $name_imm:ident = $op:ident, $off:expr; )+) => {
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
    };
}

/// Emits one sign-extending move method per (source width, class) row. `$off`
/// is the ALU `offset` nibble that selects the source width to sign-extend from.
macro_rules! movsx_family {
    ($( $name:ident = $class:ident, $off:expr );+ $(;)?) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, src`")]
            pub fn $name(&mut self, dst: Register, src: Register) -> &mut Self {
                let opcode = class::$class | alu::MOV | SRC_REG;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), $off, 0));
                self
            }
        )+
    };
}

/// Emits a register/immediate pair of conditional jump methods for one opcode.
macro_rules! jmp_family {
    ($class:ident; $( $name:ident, $name_imm:ident = $op:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, src, label`")]
            pub fn $name(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
                let opcode = class::$class | jmp::$op | SRC_REG;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
                self.add_label_ref(label, LabelRefType::Jump);
                self
            }

            #[doc = concat!("`", stringify!($name_imm), " dst, imm, label`")]
            pub fn $name_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
                let opcode = class::$class | jmp::$op | SRC_IMM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
                self.add_label_ref(label, LabelRefType::Jump);
                self
            }
        )+
    };
}

/// Emits one load-from-memory method per (mnemonic, size, mode) row.
macro_rules! ldx_family {
    ($( $name:ident = $size:ident, $mode:ident; )+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst, [src+off]`")]
            pub fn $name(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
                let opcode = class::LDX | size::$size | mode::$mode;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
                self
            }
        )+
    };
}

/// Emits one store-to-memory-from-register method per size.
macro_rules! stx_family {
    ($( $name:ident = $size:ident );+) => {
        $(
            #[doc = concat!("`", stringify!($name), " [dst+off], src`")]
            pub fn $name(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::MEM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
                self
            }
        )+
    };
}

/// Emits one store-immediate-to-memory method per size.
macro_rules! st_family {
    ($( $name:ident = $size:ident );+) => {
        $(
            #[doc = concat!("`", stringify!($name), " [dst+off], imm`")]
            pub fn $name(&mut self, dst: Register, offset: i16, imm: i32) -> &mut Self {
                let opcode = class::ST | size::$size | mode::MEM;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
                self
            }
        )+
    };
}

/// Emits a non-fetch/fetch pair of atomic read-modify-write methods per op, for
/// one memory size. `xchg` and `cmpxchg` always report the prior value, so they
/// are defined separately instead of through this macro.
macro_rules! atomic_family {
    ($size:ident; $( $name:ident, $name_fetch:ident = $op:ident );+ $(;)?) => {
        $(
            #[doc = concat!("`lock ", stringify!($op), " [dst+off], src`")]
            pub fn $name(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::ATOMIC;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::$op));
                self
            }

            #[doc = concat!("`lock fetch ", stringify!($op), " [dst+off], src`")]
            pub fn $name_fetch(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
                let opcode = class::STX | size::$size | mode::ATOMIC;
                let imm = atomic::$op | atomic::FETCH;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, imm));
                self
            }
        )+
    };
}

/// Emits one byte-swap method per bit width, for a fixed class and source type
/// (`le*`/`be*` are ALU32 and truncate; `swap*` is ALU64 and always swaps the
/// full width regardless of host endianness).
macro_rules! endian_family {
    ($class:ident, $src:ident; $( $name:ident = $bits:expr ),+) => {
        $(
            #[doc = concat!("`", stringify!($name), " dst`")]
            pub fn $name(&mut self, dst: Register) -> &mut Self {
                let opcode = class::$class | alu::END | $src;
                self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, $bits));
                self
            }
        )+
    };
}

/// eBPF bytecode assembler.
///
/// Provides a fluent API for building eBPF programs with automatic
/// label resolution and CO-RE relocation tracking.
pub struct Assembler {
    /// Assembled instructions.
    instructions: Vec<AsmInsn>,
    /// Label counter for generating unique IDs.
    label_counter: usize,
    /// Label positions (label_id -> instruction index).
    label_positions: HashMap<usize, usize>,
    /// Pending label references to resolve.
    label_refs: Vec<LabelRef>,
    /// Pending CO-RE relocations (instruction index based).
    core_relos: Vec<PendingCoreRelo>,
}

impl Assembler {
    /// Create a new assembler.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            label_counter: 0,
            label_positions: HashMap::new(),
            label_refs: Vec::new(),
            core_relos: Vec::new(),
        }
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

    /// Create a new unbound label.
    pub fn create_label(&mut self) -> Label {
        let id = self.label_counter;
        self.label_counter += 1;
        Label::new(id)
    }

    /// Bind a label to the current position.
    ///
    /// The label will point to the next instruction added.
    pub fn set_label(&mut self, label: &mut Label) -> Result<&mut Self, AsmError> {
        if label.position.is_some() {
            let name = label.name.clone().unwrap_or_else(|| format!("L{}", label.id));
            return Err(AsmError::DuplicateLabel(name));
        }

        let position = self.instructions.len();
        label.position = Some(position);
        self.label_positions.insert(label.id, position);
        Ok(self)
    }

    /// Add a raw instruction.
    fn emit(&mut self, raw: RawInstruction) {
        self.instructions.push(AsmInsn { raw, raw2: None });
    }

    /// Add a wide (16-byte) instruction.
    fn emit_wide(&mut self, raw: RawInstruction, raw2: RawInstruction) {
        self.instructions.push(AsmInsn { raw, raw2: Some(raw2) });
    }

    /// Add a label reference for later resolution.
    fn add_label_ref(&mut self, label: &Label, ref_type: LabelRefType) {
        self.label_refs.push(LabelRef {
            label_id: label.id,
            insn_index: self.instructions.len() - 1,
            ref_type,
        });
    }

    /// Assemble the program into bytecode.
    ///
    /// Resolves all label references and returns the final bytecode.
    pub fn assemble(&mut self) -> Result<Vec<u8>, AsmError> {
        // Labels and refs hold entry indices; jumps count 8-byte slots (LDDW takes two).
        let slot_of = self.slot_prefix();

        // Resolve all label references
        for i in 0..self.label_refs.len() {
            let label_ref = &self.label_refs[i];
            let target_pos = self
                .label_positions
                .get(&label_ref.label_id)
                .copied()
                .ok_or_else(|| AsmError::UndefinedLabel(format!("L{}", label_ref.label_id)))?;

            // eBPF jumps are relative to the NEXT slot
            let offset = (slot_of[target_pos] as i64) - (slot_of[label_ref.insn_index] as i64 + 1);
            let insn_index = label_ref.insn_index;
            let ref_type = label_ref.ref_type;

            let insn = &mut self.instructions[insn_index];

            match ref_type {
                LabelRefType::Jump => {
                    // Offset in bits 16-31 (i16)
                    if offset < i16::MIN as i64 || offset > i16::MAX as i64 {
                        return Err(AsmError::OffsetOutOfRange {
                            from: insn_index,
                            to: target_pos,
                        });
                    }
                    // Update offset field
                    let raw = insn.raw.value();
                    let mask = 0xFFFFFFFF0000FFFF_u64;
                    let new_offset = ((offset as i16 as u16 as u64) << 16) & 0x00000000FFFF0000;
                    insn.raw = RawInstruction::new((raw & mask) | new_offset);
                }
                LabelRefType::Imm32 => {
                    // Offset in bits 32-63 (i32)
                    if offset < i32::MIN as i64 || offset > i32::MAX as i64 {
                        return Err(AsmError::OffsetOutOfRange {
                            from: insn_index,
                            to: target_pos,
                        });
                    }
                    // Update imm field
                    let raw = insn.raw.value();
                    let mask = 0x00000000FFFFFFFF_u64;
                    let new_imm = ((offset as i32 as u32 as u64) << 32) & 0xFFFFFFFF00000000;
                    insn.raw = RawInstruction::new((raw & mask) | new_imm);
                }
            }
        }

        // Emit bytecode
        let mut code = Vec::with_capacity(self.instructions.len() * 8);
        for insn in &self.instructions {
            code.extend_from_slice(&insn.raw.to_le_bytes());
            if let Some(raw2) = insn.raw2 {
                code.extend_from_slice(&raw2.to_le_bytes());
            }
        }

        Ok(code)
    }

    // ==================== CO-RE Relocation Methods ====================

    /// Mark the last emitted instruction with a CO-RE relocation.
    ///
    /// This attaches relocation metadata to the most recently emitted instruction.
    /// At assembly time, the instruction index is converted to a byte offset.
    ///
    /// # Panics
    ///
    /// Panics if no instructions have been emitted yet.
    ///
    /// # Example
    ///
    /// ```
    /// use btf::CoreReloKind;
    /// use ebpf_asm::{Assembler, R3};
    ///
    /// let mut asm = Assembler::new();
    ///
    /// // Emit a MOV with a placeholder offset, then mark it for CO-RE
    /// asm.mov64_imm(R3, 8);
    /// asm.mark_core_relo(CoreReloKind::FieldByteOffset, 1, 17);
    ///
    /// let result = asm.assemble_with_core().unwrap();
    /// assert_eq!(result.relocations.len(), 1);
    /// ```
    pub fn mark_core_relo(&mut self, kind: CoreReloKind, type_id: u32, access_str_off: u32) -> &mut Self {
        assert!(!self.instructions.is_empty(), "mark_core_relo called with no instructions");
        let insn_index = self.instructions.len() - 1;
        self.core_relos.push(PendingCoreRelo {
            insn_index,
            type_id,
            access_str_off,
            kind,
        });
        self
    }

    /// Assemble the program with CO-RE relocation information.
    ///
    /// Returns both the bytecode and the resolved CO-RE relocations.
    /// Each relocation's `insn_off` is set to the byte offset of its instruction.
    pub fn assemble_with_core(&mut self) -> Result<AssembledProgram, AsmError> {
        let byte_offsets: Vec<u32> = self.slot_prefix().iter().map(|&s| (s * 8) as u32).collect();

        // Assemble the bytecode
        let bytecode = self.assemble()?;

        // Resolve CO-RE relocations
        let relocations = self
            .core_relos
            .iter()
            .map(|pending| CoreRelo {
                insn_off: byte_offsets[pending.insn_index],
                type_id: pending.type_id,
                access_str_off: pending.access_str_off,
                kind: pending.kind,
            })
            .collect();

        Ok(AssembledProgram { bytecode, relocations })
    }

    // ==================== ALU Instructions ====================

    /// `neg64 dst` - 64-bit negation.
    pub fn neg64(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    /// `neg32 dst` - 32-bit negation.
    pub fn neg32(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    alu_family!(ALU64;
        add64, add64_imm = ADD, 0;
        sub64, sub64_imm = SUB, 0;
        mul64, mul64_imm = MUL, 0;
        div64, div64_imm = DIV, 0;
        sdiv64, sdiv64_imm = DIV, 1;
        or64, or64_imm = OR, 0;
        and64, and64_imm = AND, 0;
        lsh64, lsh64_imm = LSH, 0;
        rsh64, rsh64_imm = RSH, 0;
        mod64, mod64_imm = MOD, 0;
        smod64, smod64_imm = MOD, 1;
        xor64, xor64_imm = XOR, 0;
        mov64, mov64_imm = MOV, 0;
        arsh64, arsh64_imm = ARSH, 0;
    );

    alu_family!(ALU32;
        add32, add32_imm = ADD, 0;
        sub32, sub32_imm = SUB, 0;
        mul32, mul32_imm = MUL, 0;
        div32, div32_imm = DIV, 0;
        sdiv32, sdiv32_imm = DIV, 1;
        or32, or32_imm = OR, 0;
        and32, and32_imm = AND, 0;
        lsh32, lsh32_imm = LSH, 0;
        rsh32, rsh32_imm = RSH, 0;
        mod32, mod32_imm = MOD, 0;
        smod32, smod32_imm = MOD, 1;
        xor32, xor32_imm = XOR, 0;
        mov32, mov32_imm = MOV, 0;
        arsh32, arsh32_imm = ARSH, 0;
    );

    movsx_family!(
        movsx832 = ALU32, 8;
        movsx1632 = ALU32, 16;
        movsx864 = ALU64, 8;
        movsx1664 = ALU64, 16;
        movsx3264 = ALU64, 32;
    );

    // ==================== Endianness Instructions ====================

    endian_family!(ALU32, SRC_IMM; le16 = 16, le32 = 32, le64 = 64);
    endian_family!(ALU32, SRC_REG; be16 = 16, be32 = 32, be64 = 64);
    endian_family!(ALU64, SRC_IMM; swap16 = 16, swap32 = 32, swap64 = 64);

    // ==================== Memory Load Instructions ====================

    ldx_family!(
        ldxdw = DW, MEM;
        ldxw = W, MEM;
        ldxh = H, MEM;
        ldxb = B, MEM;
        ldxsw = W, MEMSX;
        ldxsh = H, MEMSX;
        ldxsb = B, MEMSX;
    );

    /// `lddw dst, imm64` - Load 64-bit immediate.
    pub fn lddw(&mut self, dst: Register, imm: i64) -> &mut Self {
        let opcode = class::LD | size::DW | mode::IMM;
        let imm_lo = imm as u32 as i32;
        let imm_hi = (imm as u64 >> 32) as u32 as i32;
        let raw1 = RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm_lo);
        let raw2 = RawInstruction::from_parts(0, 0, 0, 0, imm_hi);
        self.emit_wide(raw1, raw2);
        self
    }

    // ==================== Memory Store Instructions ====================

    stx_family!(stxdw = DW; stxw = W; stxh = H; stxb = B);
    st_family!(stdw = DW; stw = W; sth = H; stb = B);

    // ==================== Atomic Instructions ====================

    atomic_family!(DW;
        atomic_add64, atomic_fetch_add64 = ADD;
        atomic_or64, atomic_fetch_or64 = OR;
        atomic_and64, atomic_fetch_and64 = AND;
        atomic_xor64, atomic_fetch_xor64 = XOR;
    );
    atomic_family!(W;
        atomic_add32, atomic_fetch_add32 = ADD;
        atomic_or32, atomic_fetch_or32 = OR;
        atomic_and32, atomic_fetch_and32 = AND;
        atomic_xor32, atomic_fetch_xor32 = XOR;
    );

    /// `lock xchg [dst+off], src` - 64-bit atomic exchange; always reports the prior value.
    pub fn atomic_xchg64(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::DW | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::XCHG));
        self
    }

    /// `lock xchg32 [dst+off], src` - 32-bit atomic exchange; always reports the prior value.
    pub fn atomic_xchg32(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::W | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::XCHG));
        self
    }

    /// `lock cmpxchg [dst+off], src` - 64-bit atomic compare-and-exchange against `r0`;
    /// always reports the prior value in `r0`.
    pub fn atomic_cmpxchg64(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::DW | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::CMPXCHG));
        self
    }

    /// `lock cmpxchg32 [dst+off], src` - 32-bit atomic compare-and-exchange against `r0`;
    /// always reports the prior value in `r0`.
    pub fn atomic_cmpxchg32(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::W | mode::ATOMIC;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, atomic::CMPXCHG));
        self
    }

    // ==================== Jump Instructions with Labels ====================

    /// `ja label` - Unconditional jump to label.
    pub fn ja(&mut self, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::Jump);
        self
    }

    /// `ja offset` - Unconditional jump to relative offset.
    pub fn ja_off(&mut self, offset: i16) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, offset, 0));
        self
    }

    /// `ja32 label` - Unconditional jump to label, JMP32 class (RFC 9669 Section 4.3:
    /// the relative offset sits in the 32-bit `imm` field instead of the 16-bit `offset`).
    pub fn ja32(&mut self, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::Imm32);
        self
    }

    jmp_family!(JMP64;
        jeq, jeq_imm = JEQ;
        jne, jne_imm = JNE;
        jgt, jgt_imm = JGT;
        jge, jge_imm = JGE;
        jlt, jlt_imm = JLT;
        jle, jle_imm = JLE;
        jset, jset_imm = JSET;
        jsgt, jsgt_imm = JSGT;
        jsge, jsge_imm = JSGE;
        jslt, jslt_imm = JSLT;
        jsle, jsle_imm = JSLE;
    );

    jmp_family!(JMP32;
        jeq32, jeq32_imm = JEQ;
        jne32, jne32_imm = JNE;
        jgt32, jgt32_imm = JGT;
        jge32, jge32_imm = JGE;
        jlt32, jlt32_imm = JLT;
        jle32, jle32_imm = JLE;
        jset32, jset32_imm = JSET;
        jsgt32, jsgt32_imm = JSGT;
        jsge32, jsge32_imm = JSGE;
        jslt32, jslt32_imm = JSLT;
        jsle32, jsle32_imm = JSLE;
    );

    // ==================== Call / Exit ====================

    /// `call imm` - Call helper function by ID.
    pub fn call(&mut self, func_id: i32) -> &mut Self {
        let opcode = class::JMP64 | jmp::CALL;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, func_id));
        self
    }

    /// `call label` - Call local function (BPF-to-BPF call).
    pub fn call_local(&mut self, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::CALL;
        // src_reg = 1 indicates BPF-to-BPF call
        self.emit(RawInstruction::from_parts(opcode, 0, 1, 0, 0));
        self.add_label_ref(label, LabelRefType::Imm32);
        self
    }

    /// `exit` - Exit program.
    pub fn exit(&mut self) -> &mut Self {
        let opcode = class::JMP64 | jmp::EXIT;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self
    }
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::register::*;

    #[test]
    fn test_simple_program() {
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 42);
        asm.exit();

        let code = asm.assemble().unwrap();
        assert_eq!(code.len(), 16); // 2 instructions * 8 bytes

        // mov64 r0, 42 = 0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00
        assert_eq!(code[0], 0xb7);
        assert_eq!(code[4], 42);

        // exit = 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        assert_eq!(code[8], 0x95);
    }

    #[test]
    fn test_forward_label() {
        let mut asm = Assembler::new();
        let mut end = asm.create_label();

        asm.mov64_imm(R0, 1);
        asm.ja(&end);
        asm.mov64_imm(R0, 2);
        asm.set_label(&mut end).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        // Check jump offset: from insn 1 to insn 3, offset = 3 - (1 + 1) = 1
        let offset = i16::from_le_bytes([code[10], code[11]]);
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_backward_label() {
        let mut asm = Assembler::new();
        let mut loop_start = asm.create_label();

        asm.mov64_imm(R0, 10); // insn 0
        asm.set_label(&mut loop_start).unwrap(); // label points to insn 1
        asm.sub64_imm(R0, 1); // insn 1
        asm.jne_imm(R0, 0, &loop_start); // insn 2
        asm.exit(); // insn 3

        let code = asm.assemble().unwrap();
        // jne_imm is at bytes 16-23 (insn 2)
        // offset field is at bytes 18-19 (bits 16-31)
        // Jump from insn 2 to insn 1: offset = 1 - (2 + 1) = -2
        let offset = i16::from_le_bytes([code[18], code[19]]);
        assert_eq!(offset, -2);
    }

    #[test]
    fn test_undefined_label() {
        let mut asm = Assembler::new();
        let end = asm.create_label();

        asm.ja(&end);
        asm.exit();

        let result = asm.assemble();
        assert!(matches!(result, Err(AsmError::UndefinedLabel(_))));
    }

    #[test]
    fn test_duplicate_label() {
        let mut asm = Assembler::new();
        let mut label = asm.create_label();

        asm.set_label(&mut label).unwrap();
        let result = asm.set_label(&mut label);
        assert!(matches!(result, Err(AsmError::DuplicateLabel(_))));
    }

    #[test]
    fn test_memory_operations() {
        let mut asm = Assembler::new();
        asm.ldxdw(R0, R1, 16);
        asm.stxdw(R1, -8, R0);
        asm.exit();

        let code = asm.assemble().unwrap();
        assert_eq!(code.len(), 24);

        // ldxdw r0, [r1+16]
        assert_eq!(code[0], 0x79);
        let offset = i16::from_le_bytes([code[2], code[3]]);
        assert_eq!(offset, 16);

        // stxdw [r1-8], r0
        assert_eq!(code[8], 0x7b);
        let offset = i16::from_le_bytes([code[10], code[11]]);
        assert_eq!(offset, -8);
    }

    #[test]
    fn test_call_helper() {
        let mut asm = Assembler::new();
        asm.call(1); // bpf_map_lookup_elem
        asm.exit();

        let code = asm.assemble().unwrap();
        assert_eq!(code[0], 0x85); // call opcode
        let func_id = i32::from_le_bytes([code[4], code[5], code[6], code[7]]);
        assert_eq!(func_id, 1);
    }

    #[test]
    fn test_local_call() {
        let mut asm = Assembler::new();
        let mut func = asm.create_label();

        asm.call_local(&func);
        asm.exit();
        asm.set_label(&mut func).unwrap();
        asm.mov64_imm(R0, 0);
        asm.exit();

        let code = asm.assemble().unwrap();
        // src_reg should be 1 for local call
        assert_eq!((code[1] >> 4) & 0xF, 1);
    }

    #[test]
    fn test_mark_core_relo() {
        let mut asm = Assembler::new();

        // Emit instruction and mark with CO-RE relocation
        asm.mov64_imm(R3, 8);
        asm.mark_core_relo(CoreReloKind::FieldByteOffset, 1, 17);

        asm.add64(R1, R3);

        // Second relocation, at a later instruction
        asm.mov64_imm(R4, 1);
        asm.mark_core_relo(CoreReloKind::FieldExists, 1, 25); // debug_flags exists check

        asm.exit();

        let result = asm.assemble_with_core().unwrap();

        assert_eq!(result.relocations.len(), 2);
        assert_eq!(result.relocations[0].insn_off, 0); // first instruction
        assert_eq!(result.relocations[0].type_id, 1);
        assert_eq!(result.relocations[0].access_str_off, 17);
        assert_eq!(result.relocations[0].kind, CoreReloKind::FieldByteOffset);

        // Second relo at instruction 2 (after add64)
        assert_eq!(result.relocations[1].insn_off, 16);
        assert_eq!(result.relocations[1].kind, CoreReloKind::FieldExists);
    }

    #[test]
    fn test_core_relo_with_wide_instruction() {
        let mut asm = Assembler::new();

        // LDDW is a wide instruction (16 bytes)
        asm.lddw(R0, 0x1234567890ABCDEF_i64);

        // Instruction after LDDW should be at byte offset 16, not 8
        asm.mov64_imm(R1, 42);
        asm.mark_core_relo(CoreReloKind::TypeSize, 2, 0);

        asm.exit();

        let result = asm.assemble_with_core().unwrap();

        assert_eq!(result.relocations.len(), 1);
        // LDDW takes 16 bytes, so mov64 is at offset 16
        assert_eq!(result.relocations[0].insn_off, 16);
    }

    #[test]
    fn test_jmp32_opcodes() {
        let mut asm = Assembler::new();
        let mut labels: Vec<_> = (0..11).map(|_| asm.create_label()).collect();

        asm.mov32_imm(R0, 100);
        asm.jeq32_imm(R0, 100, &labels[0]);
        asm.set_label(&mut labels[0]).unwrap();
        asm.jne32_imm(R0, 50, &labels[1]);
        asm.set_label(&mut labels[1]).unwrap();
        asm.jgt32_imm(R0, 10, &labels[2]);
        asm.set_label(&mut labels[2]).unwrap();
        asm.jge32_imm(R0, 10, &labels[3]);
        asm.set_label(&mut labels[3]).unwrap();
        asm.jlt32_imm(R0, 10, &labels[4]);
        asm.set_label(&mut labels[4]).unwrap();
        asm.jle32_imm(R0, 10, &labels[5]);
        asm.set_label(&mut labels[5]).unwrap();
        asm.jsgt32_imm(R0, -10, &labels[6]);
        asm.set_label(&mut labels[6]).unwrap();
        asm.jsge32_imm(R0, -10, &labels[7]);
        asm.set_label(&mut labels[7]).unwrap();
        asm.jslt32_imm(R0, -10, &labels[8]);
        asm.set_label(&mut labels[8]).unwrap();
        asm.jsle32_imm(R0, -10, &labels[9]);
        asm.set_label(&mut labels[9]).unwrap();
        asm.jset32_imm(R0, 0x80, &labels[10]);
        asm.set_label(&mut labels[10]).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();

        // JMP32 = 0x06, each condition in the high nibble, SRC_IMM = 0x00.
        assert_eq!(code[8], 0x16); // jeq32
        assert_eq!(code[16], 0x56); // jne32
        assert_eq!(code[24], 0x26); // jgt32
        assert_eq!(code[32], 0x36); // jge32
        assert_eq!(code[40], 0xa6); // jlt32
        assert_eq!(code[48], 0xb6); // jle32
        assert_eq!(code[56], 0x66); // jsgt32
        assert_eq!(code[64], 0x76); // jsge32
        assert_eq!(code[72], 0xc6); // jslt32
        assert_eq!(code[80], 0xd6); // jsle32
        assert_eq!(code[88], 0x46); // jset32
    }

    #[test]
    fn test_jmp32_with_register() {
        let mut asm = Assembler::new();
        let mut target = asm.create_label();

        asm.jeq32(R0, R1, &target);
        asm.set_label(&mut target).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        // JMP32 = 0x06, JEQ = 0x10, SRC_REG = 0x08 -> 0x1e
        assert_eq!(code[0], 0x1e);
        // src register should be R1 (1) in upper nibble of byte 1
        assert_eq!((code[1] >> 4) & 0xF, 1);
    }

    #[test]
    fn test_jump_offsets_count_lddw_slots() {
        let mut asm = Assembler::new();
        let mut fwd = asm.create_label();
        let mut back = asm.create_label();

        asm.set_label(&mut back).unwrap();
        asm.ja(&fwd); // slot 0
        asm.lddw(R0, 0x1_0000_0002); // slots 1-2
        asm.ja(&back); // slot 3
        asm.set_label(&mut fwd).unwrap();
        asm.exit(); // slot 4

        let code = asm.assemble().unwrap();
        let (words, _) = code.as_chunks::<8>();
        let insns: Vec<u64> = words.iter().map(|w| u64::from_le_bytes(*w)).collect();
        let off = |i: usize| (insns[i] >> 16) as i16;
        assert_eq!(off(0), 3); // 0 + 1 + 3 = 4 (exit)
        assert_eq!(off(3), -4); // 3 + 1 - 4 = 0
    }
}
