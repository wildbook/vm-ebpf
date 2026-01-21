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
//! use ebpf_asm::{Assembler, CoreReloKind, R1, R3};
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

use crate::instruction::{alu, class, jmp, mode, size, RawInstruction, SRC_IMM, SRC_REG};
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
    /// Immediate value out of range.
    ImmediateOutOfRange(i64),
    /// Invalid label reference.
    InvalidLabel,
}

impl fmt::Display for AsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsmError::UndefinedLabel(name) => write!(f, "undefined label: {name}"),
            AsmError::DuplicateLabel(name) => write!(f, "duplicate label: {name}"),
            AsmError::OffsetOutOfRange { from, to } => {
                write!(f, "jump offset out of range: {from} -> {to}")
            }
            AsmError::ImmediateOutOfRange(v) => write!(f, "immediate out of range: {v}"),
            AsmError::InvalidLabel => write!(f, "invalid label reference"),
        }
    }
}

impl std::error::Error for AsmError {}

// ============================================================================
// CO-RE (Compile Once - Run Everywhere) Relocation Support
// ============================================================================

/// CO-RE relocation kind.
///
/// These match the BPF CO-RE relocation kinds used in BTF.ext sections.
/// The assembler tracks these and produces them at assembly time with
/// resolved byte offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CoreReloKind {
    /// Field byte offset within a struct.
    FieldByteOffset = 0,
    /// Field byte size.
    FieldByteSize = 1,
    /// Field existence check (0 or 1).
    FieldExists = 2,
    /// Field signedness (0 or 1).
    FieldSigned = 3,
    /// Field left shift for bitfield reading.
    FieldLShiftU64 = 4,
    /// Field right shift for bitfield reading.
    FieldRShiftU64 = 5,
    /// Local BTF type ID.
    TypeIdLocal = 6,
    /// Target BTF type ID.
    TypeIdTarget = 7,
    /// Type existence check (0 or 1).
    TypeExists = 8,
    /// Type size in bytes.
    TypeSize = 9,
    /// Enum value existence check.
    EnumvalExists = 10,
    /// Enum value.
    EnumvalValue = 11,
    /// Type matches check.
    TypeMatches = 12,
}

impl CoreReloKind {
    /// Convert to raw u32 value.
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// A CO-RE relocation entry produced by the assembler.
///
/// This contains all the information needed to apply a CO-RE relocation
/// at load time. The `insn_off` is a byte offset (not instruction index).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRelo {
    /// Instruction byte offset from the start of the program.
    pub insn_off: u32,
    /// BTF type ID in the program's BTF.
    pub type_id: u32,
    /// Offset into BTF string table for the access string (field name).
    pub access_str_off: u32,
    /// The kind of relocation.
    pub kind: CoreReloKind,
}

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
        self.bytecode
            .chunks_exact(8)
            .map(|chunk| {
                let arr: [u8; 8] = chunk.try_into().unwrap();
                u64::from_le_bytes(arr)
            })
            .collect()
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

    fn named(id: usize, name: String) -> Self {
        Self {
            id,
            name: Some(name),
            position: None,
        }
    }

    /// Check if this label has been bound to a position.
    pub fn is_bound(&self) -> bool {
        self.position.is_some()
    }

    /// Get the label's name, if any.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
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
    /// Conditional jump - offset in bits 16-31.
    ConditionalJump,
    /// Unconditional jump (JA) - offset in bits 16-31.
    UnconditionalJump,
    /// BPF-to-BPF call - offset in bits 32-63 (imm field).
    LocalCall,
}

/// Internal instruction representation during assembly.
#[derive(Debug, Clone)]
struct AsmInsn {
    raw: RawInstruction,
    /// Second instruction for LDDW.
    raw2: Option<RawInstruction>,
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

    /// Create with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            instructions: Vec::with_capacity(capacity),
            label_counter: 0,
            label_positions: HashMap::new(),
            label_refs: Vec::new(),
            core_relos: Vec::new(),
        }
    }

    /// Get the current instruction count.
    ///
    /// This is useful for CO-RE relocations where you need to track
    /// instruction indices for patching.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Check if the assembler is empty.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Get the current instruction index (where the next instruction will be placed).
    ///
    /// This is an alias for `len()` but is more descriptive when used for
    /// tracking instruction positions for CO-RE relocations.
    ///
    /// # Example
    ///
    /// ```
    /// use ebpf_asm::{Assembler, R0, R3};
    ///
    /// let mut asm = Assembler::new();
    ///
    /// // Track the index before emitting
    /// let mov_idx = asm.current_index();
    /// asm.mov64_imm(R3, 8);  // This instruction is at mov_idx
    ///
    /// // Now you can use mov_idx for CO-RE relocation
    /// assert_eq!(mov_idx, 0);
    /// ```
    #[inline]
    pub fn current_index(&self) -> usize {
        self.instructions.len()
    }

    /// Get the byte offset for a given instruction index.
    ///
    /// CO-RE relocations use byte offsets, not instruction indices.
    /// This helper converts an instruction index to its byte offset
    /// (instruction_index * 8).
    ///
    /// # Example
    ///
    /// ```
    /// use ebpf_asm::Assembler;
    ///
    /// let asm = Assembler::new();
    /// assert_eq!(asm.byte_offset(0), 0);
    /// assert_eq!(asm.byte_offset(1), 8);
    /// assert_eq!(asm.byte_offset(5), 40);
    /// ```
    #[inline]
    pub fn byte_offset(&self, insn_index: usize) -> u32 {
        (insn_index * 8) as u32
    }

    /// Get the byte offset for the current instruction position.
    ///
    /// This is equivalent to `byte_offset(current_index())`.
    #[inline]
    pub fn current_byte_offset(&self) -> u32 {
        self.byte_offset(self.instructions.len())
    }

    /// Create a new unbound label.
    pub fn create_label(&mut self) -> Label {
        let id = self.label_counter;
        self.label_counter += 1;
        Label::new(id)
    }

    /// Create a new named unbound label.
    pub fn create_named_label(&mut self, name: impl Into<String>) -> Label {
        let id = self.label_counter;
        self.label_counter += 1;
        Label::named(id, name.into())
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
        // Resolve all label references
        for i in 0..self.label_refs.len() {
            let label_ref = &self.label_refs[i];
            let target_pos = self
                .label_positions
                .get(&label_ref.label_id)
                .copied()
                .ok_or_else(|| AsmError::UndefinedLabel(format!("L{}", label_ref.label_id)))?;

            // Calculate offset (target - (source + 1))
            // eBPF jumps are relative to the NEXT instruction
            let offset = (target_pos as i64) - (label_ref.insn_index as i64 + 1);
            let insn_index = label_ref.insn_index;
            let ref_type = label_ref.ref_type;

            let insn = &mut self.instructions[insn_index];

            match ref_type {
                LabelRefType::ConditionalJump | LabelRefType::UnconditionalJump => {
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
                LabelRefType::LocalCall => {
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

    /// Assemble to a vector of u64 instruction words.
    ///
    /// This is useful for integration with VMs that work with u64 instructions
    /// rather than byte arrays.
    ///
    /// # Example
    ///
    /// ```
    /// use ebpf_asm::{Assembler, R0};
    ///
    /// let mut asm = Assembler::new();
    /// asm.mov64_imm(R0, 42);
    /// asm.exit();
    ///
    /// let instructions = asm.assemble_to_u64().unwrap();
    /// assert_eq!(instructions.len(), 2);
    /// ```
    pub fn assemble_to_u64(&mut self) -> Result<Vec<u64>, AsmError> {
        let bytes = self.assemble()?;
        let mut instructions = Vec::with_capacity(bytes.len() / 8);
        for chunk in bytes.chunks_exact(8) {
            let arr: [u8; 8] = chunk.try_into().unwrap();
            instructions.push(u64::from_le_bytes(arr));
        }
        Ok(instructions)
    }

    /// Reset the assembler for reuse.
    pub fn reset(&mut self) {
        self.instructions.clear();
        self.label_positions.clear();
        self.label_refs.clear();
        self.core_relos.clear();
        // Don't reset label_counter to avoid ID collisions
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
    /// use ebpf_asm::{Assembler, CoreReloKind, R3};
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

    /// Mark a specific instruction index with a CO-RE relocation.
    ///
    /// This is useful when you need to mark an instruction that isn't the last one.
    ///
    /// # Panics
    ///
    /// Panics if `insn_index` is out of bounds.
    pub fn mark_core_relo_at(
        &mut self,
        insn_index: usize,
        kind: CoreReloKind,
        type_id: u32,
        access_str_off: u32,
    ) -> &mut Self {
        assert!(
            insn_index < self.instructions.len(),
            "mark_core_relo_at: index {} out of bounds (len={})",
            insn_index,
            self.instructions.len()
        );
        self.core_relos.push(PendingCoreRelo {
            insn_index,
            type_id,
            access_str_off,
            kind,
        });
        self
    }

    /// Convenience: Mark the last instruction as a field byte offset relocation.
    pub fn mark_field_offset(&mut self, type_id: u32, access_str_off: u32) -> &mut Self {
        self.mark_core_relo(CoreReloKind::FieldByteOffset, type_id, access_str_off)
    }

    /// Convenience: Mark the last instruction as a field exists relocation.
    pub fn mark_field_exists(&mut self, type_id: u32, access_str_off: u32) -> &mut Self {
        self.mark_core_relo(CoreReloKind::FieldExists, type_id, access_str_off)
    }

    /// Convenience: Mark the last instruction as a type size relocation.
    pub fn mark_type_size(&mut self, type_id: u32) -> &mut Self {
        self.mark_core_relo(CoreReloKind::TypeSize, type_id, 0)
    }

    /// Convenience: Mark the last instruction as an enum value relocation.
    pub fn mark_enum_value(&mut self, type_id: u32, variant_str_off: u32) -> &mut Self {
        self.mark_core_relo(CoreReloKind::EnumvalValue, type_id, variant_str_off)
    }

    /// Assemble the program with CO-RE relocation information.
    ///
    /// Returns both the bytecode and the resolved CO-RE relocations.
    /// Each relocation's `insn_off` is set to the byte offset of its instruction.
    pub fn assemble_with_core(&mut self) -> Result<AssembledProgram, AsmError> {
        // First, compute instruction byte offsets
        // Wide instructions (LDDW) take 16 bytes, others take 8
        let mut byte_offsets = Vec::with_capacity(self.instructions.len());
        let mut current_offset = 0u32;

        for insn in &self.instructions {
            byte_offsets.push(current_offset);
            current_offset += 8;
            if insn.raw2.is_some() {
                current_offset += 8;
            }
        }

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

    // ==================== ALU64 Instructions ====================

    /// `add64 dst, src` - 64-bit addition with register source.
    pub fn add64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::ADD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `add64 dst, imm` - 64-bit addition with immediate.
    pub fn add64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::ADD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `sub64 dst, src` - 64-bit subtraction with register source.
    pub fn sub64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::SUB | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `sub64 dst, imm` - 64-bit subtraction with immediate.
    pub fn sub64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::SUB | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `mul64 dst, src` - 64-bit multiplication with register source.
    pub fn mul64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::MUL | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `mul64 dst, imm` - 64-bit multiplication with immediate.
    pub fn mul64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::MUL | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `div64 dst, src` - 64-bit unsigned division with register source.
    pub fn div64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::DIV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `div64 dst, imm` - 64-bit unsigned division with immediate.
    pub fn div64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::DIV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `sdiv64 dst, src` - 64-bit signed division with register source.
    pub fn sdiv64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::DIV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 1, 0));
        self
    }

    /// `sdiv64 dst, imm` - 64-bit signed division with immediate.
    pub fn sdiv64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::DIV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 1, imm));
        self
    }

    /// `or64 dst, src` - 64-bit bitwise OR with register source.
    pub fn or64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::OR | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `or64 dst, imm` - 64-bit bitwise OR with immediate.
    pub fn or64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::OR | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `and64 dst, src` - 64-bit bitwise AND with register source.
    pub fn and64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::AND | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `and64 dst, imm` - 64-bit bitwise AND with immediate.
    pub fn and64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::AND | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `lsh64 dst, src` - 64-bit left shift with register source.
    pub fn lsh64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::LSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `lsh64 dst, imm` - 64-bit left shift with immediate.
    pub fn lsh64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::LSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `rsh64 dst, src` - 64-bit logical right shift with register source.
    pub fn rsh64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::RSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `rsh64 dst, imm` - 64-bit logical right shift with immediate.
    pub fn rsh64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::RSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `neg64 dst` - 64-bit negation.
    pub fn neg64(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    /// `mod64 dst, src` - 64-bit unsigned modulo with register source.
    pub fn mod64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::MOD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `mod64 dst, imm` - 64-bit unsigned modulo with immediate.
    pub fn mod64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::MOD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `smod64 dst, src` - 64-bit signed modulo with register source.
    pub fn smod64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::MOD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 1, 0));
        self
    }

    /// `smod64 dst, imm` - 64-bit signed modulo with immediate.
    pub fn smod64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::MOD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 1, imm));
        self
    }

    /// `xor64 dst, src` - 64-bit bitwise XOR with register source.
    pub fn xor64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::XOR | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `xor64 dst, imm` - 64-bit bitwise XOR with immediate.
    pub fn xor64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::XOR | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `mov64 dst, src` - 64-bit move from register.
    pub fn mov64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::MOV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `mov64 dst, imm` - 64-bit move immediate.
    pub fn mov64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::MOV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `arsh64 dst, src` - 64-bit arithmetic right shift with register source.
    pub fn arsh64(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU64 | alu::ARSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `arsh64 dst, imm` - 64-bit arithmetic right shift with immediate.
    pub fn arsh64_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU64 | alu::ARSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    // ==================== ALU32 Instructions ====================

    /// `add32 dst, src` - 32-bit addition with register source.
    pub fn add32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::ADD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `add32 dst, imm` - 32-bit addition with immediate.
    pub fn add32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::ADD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `sub32 dst, src` - 32-bit subtraction with register source.
    pub fn sub32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::SUB | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `sub32 dst, imm` - 32-bit subtraction with immediate.
    pub fn sub32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::SUB | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `mul32 dst, src` - 32-bit multiplication with register source.
    pub fn mul32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::MUL | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `mul32 dst, imm` - 32-bit multiplication with immediate.
    pub fn mul32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::MUL | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `div32 dst, src` - 32-bit unsigned division with register source.
    pub fn div32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::DIV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `div32 dst, imm` - 32-bit unsigned division with immediate.
    pub fn div32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::DIV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `sdiv32 dst, src` - 32-bit signed division with register source.
    pub fn sdiv32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::DIV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 1, 0));
        self
    }

    /// `sdiv32 dst, imm` - 32-bit signed division with immediate.
    pub fn sdiv32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::DIV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 1, imm));
        self
    }

    /// `or32 dst, src` - 32-bit bitwise OR with register source.
    pub fn or32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::OR | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `or32 dst, imm` - 32-bit bitwise OR with immediate.
    pub fn or32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::OR | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `and32 dst, src` - 32-bit bitwise AND with register source.
    pub fn and32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::AND | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `and32 dst, imm` - 32-bit bitwise AND with immediate.
    pub fn and32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::AND | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `lsh32 dst, src` - 32-bit left shift with register source.
    pub fn lsh32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::LSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `lsh32 dst, imm` - 32-bit left shift with immediate.
    pub fn lsh32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::LSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `rsh32 dst, src` - 32-bit logical right shift with register source.
    pub fn rsh32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::RSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `rsh32 dst, imm` - 32-bit logical right shift with immediate.
    pub fn rsh32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::RSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `neg32 dst` - 32-bit negation.
    pub fn neg32(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        self
    }

    /// `mod32 dst, src` - 32-bit unsigned modulo with register source.
    pub fn mod32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::MOD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `mod32 dst, imm` - 32-bit unsigned modulo with immediate.
    pub fn mod32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::MOD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `smod32 dst, src` - 32-bit signed modulo with register source.
    pub fn smod32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::MOD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 1, 0));
        self
    }

    /// `smod32 dst, imm` - 32-bit signed modulo with immediate.
    pub fn smod32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::MOD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 1, imm));
        self
    }

    /// `xor32 dst, src` - 32-bit bitwise XOR with register source.
    pub fn xor32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::XOR | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `xor32 dst, imm` - 32-bit bitwise XOR with immediate.
    pub fn xor32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::XOR | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `mov32 dst, src` - 32-bit move from register.
    pub fn mov32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::MOV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `mov32 dst, imm` - 32-bit move immediate.
    pub fn mov32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::MOV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    /// `arsh32 dst, src` - 32-bit arithmetic right shift with register source.
    pub fn arsh32(&mut self, dst: Register, src: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::ARSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self
    }

    /// `arsh32 dst, imm` - 32-bit arithmetic right shift with immediate.
    pub fn arsh32_imm(&mut self, dst: Register, imm: i32) -> &mut Self {
        let opcode = class::ALU32 | alu::ARSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self
    }

    // ==================== Endianness Instructions ====================

    /// `le16 dst` - Convert to little-endian 16-bit.
    pub fn le16(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::END | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 16));
        self
    }

    /// `le32 dst` - Convert to little-endian 32-bit.
    pub fn le32(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::END | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 32));
        self
    }

    /// `le64 dst` - Convert to little-endian 64-bit.
    pub fn le64(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::END | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 64));
        self
    }

    /// `be16 dst` - Convert to big-endian 16-bit.
    pub fn be16(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::END | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 16));
        self
    }

    /// `be32 dst` - Convert to big-endian 32-bit.
    pub fn be32(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::END | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 32));
        self
    }

    /// `be64 dst` - Convert to big-endian 64-bit.
    pub fn be64(&mut self, dst: Register) -> &mut Self {
        let opcode = class::ALU32 | alu::END | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 64));
        self
    }

    // ==================== Memory Load Instructions ====================

    /// `ldxdw dst, [src+off]` - Load 64-bit from memory.
    pub fn ldxdw(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `ldxw dst, [src+off]` - Load 32-bit from memory.
    pub fn ldxw(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `ldxh dst, [src+off]` - Load 16-bit from memory.
    pub fn ldxh(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `ldxb dst, [src+off]` - Load 8-bit from memory.
    pub fn ldxb(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `ldxsw dst, [src+off]` - Load 32-bit with sign extension.
    pub fn ldxsw(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::W | mode::MEMSX;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `ldxsh dst, [src+off]` - Load 16-bit with sign extension.
    pub fn ldxsh(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::H | mode::MEMSX;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `ldxsb dst, [src+off]` - Load 8-bit with sign extension.
    pub fn ldxsb(&mut self, dst: Register, src: Register, offset: i16) -> &mut Self {
        let opcode = class::LDX | size::B | mode::MEMSX;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

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

    /// `stxdw [dst+off], src` - Store 64-bit to memory from register.
    pub fn stxdw(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `stxw [dst+off], src` - Store 32-bit to memory from register.
    pub fn stxw(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `stxh [dst+off], src` - Store 16-bit to memory from register.
    pub fn stxh(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `stxb [dst+off], src` - Store 8-bit to memory from register.
    pub fn stxb(&mut self, dst: Register, offset: i16, src: Register) -> &mut Self {
        let opcode = class::STX | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        self
    }

    /// `stdw [dst+off], imm` - Store 64-bit immediate to memory.
    pub fn stdw(&mut self, dst: Register, offset: i16, imm: i32) -> &mut Self {
        let opcode = class::ST | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        self
    }

    /// `stw [dst+off], imm` - Store 32-bit immediate to memory.
    pub fn stw(&mut self, dst: Register, offset: i16, imm: i32) -> &mut Self {
        let opcode = class::ST | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        self
    }

    /// `sth [dst+off], imm` - Store 16-bit immediate to memory.
    pub fn sth(&mut self, dst: Register, offset: i16, imm: i32) -> &mut Self {
        let opcode = class::ST | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        self
    }

    /// `stb [dst+off], imm` - Store 8-bit immediate to memory.
    pub fn stb(&mut self, dst: Register, offset: i16, imm: i32) -> &mut Self {
        let opcode = class::ST | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        self
    }

    // ==================== Jump Instructions with Labels ====================

    /// `ja label` - Unconditional jump to label.
    pub fn ja(&mut self, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::UnconditionalJump);
        self
    }

    /// `ja offset` - Unconditional jump to relative offset.
    pub fn ja_off(&mut self, offset: i16) -> &mut Self {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, offset, 0));
        self
    }

    /// `jeq dst, src, label` - Jump if equal (register).
    pub fn jeq(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JEQ | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jeq dst, imm, label` - Jump if equal (immediate).
    pub fn jeq_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JEQ | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jne dst, src, label` - Jump if not equal (register).
    pub fn jne(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JNE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jne dst, imm, label` - Jump if not equal (immediate).
    pub fn jne_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JNE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jgt dst, src, label` - Jump if greater than (unsigned, register).
    pub fn jgt(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JGT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jgt dst, imm, label` - Jump if greater than (unsigned, immediate).
    pub fn jgt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JGT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jge dst, src, label` - Jump if greater or equal (unsigned, register).
    pub fn jge(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JGE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jge dst, imm, label` - Jump if greater or equal (unsigned, immediate).
    pub fn jge_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JGE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jlt dst, src, label` - Jump if less than (unsigned, register).
    pub fn jlt(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JLT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jlt dst, imm, label` - Jump if less than (unsigned, immediate).
    pub fn jlt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JLT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jle dst, src, label` - Jump if less or equal (unsigned, register).
    pub fn jle(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JLE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jle dst, imm, label` - Jump if less or equal (unsigned, immediate).
    pub fn jle_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JLE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jset dst, src, label` - Jump if bits set.
    pub fn jset(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSET | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jset dst, imm, label` - Jump if bits set (immediate).
    pub fn jset_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSET | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsgt dst, src, label` - Jump if signed greater than.
    pub fn jsgt(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSGT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsgt dst, imm, label` - Jump if signed greater than (immediate).
    pub fn jsgt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSGT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsge dst, src, label` - Jump if signed greater or equal.
    pub fn jsge(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSGE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsge dst, imm, label` - Jump if signed greater or equal (immediate).
    pub fn jsge_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSGE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jslt dst, src, label` - Jump if signed less than.
    pub fn jslt(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSLT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jslt dst, imm, label` - Jump if signed less than (immediate).
    pub fn jslt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSLT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsle dst, src, label` - Jump if signed less or equal.
    pub fn jsle(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSLE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsle dst, imm, label` - Jump if signed less or equal (immediate).
    pub fn jsle_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP64 | jmp::JSLE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    // ==================== JMP32 Instructions ====================

    /// `jeq32 dst, src, label` - Jump if equal (32-bit comparison, register).
    pub fn jeq32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JEQ | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jeq32 dst, imm, label` - Jump if equal (32-bit comparison, immediate).
    pub fn jeq32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JEQ | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jne32 dst, src, label` - Jump if not equal (32-bit comparison, register).
    pub fn jne32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JNE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jne32 dst, imm, label` - Jump if not equal (32-bit comparison, immediate).
    pub fn jne32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JNE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jgt32 dst, src, label` - Jump if greater than (32-bit unsigned, register).
    pub fn jgt32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JGT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jgt32 dst, imm, label` - Jump if greater than (32-bit unsigned, immediate).
    pub fn jgt32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JGT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jge32 dst, src, label` - Jump if greater or equal (32-bit unsigned, register).
    pub fn jge32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JGE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jge32 dst, imm, label` - Jump if greater or equal (32-bit unsigned, immediate).
    pub fn jge32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JGE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jlt32 dst, src, label` - Jump if less than (32-bit unsigned, register).
    pub fn jlt32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JLT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jlt32 dst, imm, label` - Jump if less than (32-bit unsigned, immediate).
    pub fn jlt32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JLT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jle32 dst, src, label` - Jump if less or equal (32-bit unsigned, register).
    pub fn jle32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JLE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jle32 dst, imm, label` - Jump if less or equal (32-bit unsigned, immediate).
    pub fn jle32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JLE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jset32 dst, src, label` - Jump if bits set (32-bit, register).
    pub fn jset32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSET | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jset32 dst, imm, label` - Jump if bits set (32-bit, immediate).
    pub fn jset32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSET | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsgt32 dst, src, label` - Jump if signed greater than (32-bit, register).
    pub fn jsgt32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSGT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsgt32 dst, imm, label` - Jump if signed greater than (32-bit, immediate).
    pub fn jsgt32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSGT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsge32 dst, src, label` - Jump if signed greater or equal (32-bit, register).
    pub fn jsge32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSGE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsge32 dst, imm, label` - Jump if signed greater or equal (32-bit, immediate).
    pub fn jsge32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSGE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jslt32 dst, src, label` - Jump if signed less than (32-bit, register).
    pub fn jslt32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSLT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jslt32 dst, imm, label` - Jump if signed less than (32-bit, immediate).
    pub fn jslt32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSLT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsle32 dst, src, label` - Jump if signed less or equal (32-bit, register).
    pub fn jsle32(&mut self, dst: Register, src: Register, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSLE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

    /// `jsle32 dst, imm, label` - Jump if signed less or equal (32-bit, immediate).
    pub fn jsle32_imm(&mut self, dst: Register, imm: i32, label: &Label) -> &mut Self {
        let opcode = class::JMP32 | jmp::JSLE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        self
    }

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
        self.add_label_ref(label, LabelRefType::LocalCall);
        self
    }

    /// `exit` - Exit program.
    pub fn exit(&mut self) -> &mut Self {
        let opcode = class::JMP64 | jmp::EXIT;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self
    }

    // ==================== Raw Instruction ====================

    /// Emit a raw instruction.
    pub fn raw(&mut self, opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> &mut Self {
        self.emit(RawInstruction::from_parts(opcode, dst, src, offset, imm));
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
    fn test_lddw() {
        let mut asm = Assembler::new();
        asm.lddw(R0, 0x123456789ABCDEF0u64 as i64);
        asm.exit();

        let code = asm.assemble().unwrap();
        assert_eq!(code.len(), 24); // 16 + 8 bytes

        // Check opcode
        assert_eq!(code[0], 0x18);

        // Check low 32 bits
        let lo = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);
        assert_eq!(lo, 0x9ABCDEF0);

        // Check high 32 bits
        let hi = u32::from_le_bytes([code[12], code[13], code[14], code[15]]);
        assert_eq!(hi, 0x12345678);
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
    fn test_current_index() {
        let mut asm = Assembler::new();

        assert_eq!(asm.current_index(), 0);
        asm.mov64_imm(R0, 42);
        assert_eq!(asm.current_index(), 1);
        asm.add64_imm(R0, 10);
        assert_eq!(asm.current_index(), 2);
        asm.exit();
        assert_eq!(asm.current_index(), 3);
    }

    #[test]
    fn test_byte_offset() {
        let asm = Assembler::new();
        assert_eq!(asm.byte_offset(0), 0);
        assert_eq!(asm.byte_offset(1), 8);
        assert_eq!(asm.byte_offset(5), 40);
        assert_eq!(asm.byte_offset(100), 800);
    }

    #[test]
    fn test_current_byte_offset() {
        let mut asm = Assembler::new();

        assert_eq!(asm.current_byte_offset(), 0);
        asm.mov64_imm(R0, 42);
        assert_eq!(asm.current_byte_offset(), 8);
        asm.add64_imm(R0, 10);
        assert_eq!(asm.current_byte_offset(), 16);
    }

    #[test]
    fn test_mark_core_relo() {
        let mut asm = Assembler::new();

        // Emit instruction and mark with CO-RE relocation
        asm.mov64_imm(R3, 8);
        asm.mark_core_relo(CoreReloKind::FieldByteOffset, 1, 17);

        asm.add64(R1, R3);
        asm.exit();

        let result = asm.assemble_with_core().unwrap();

        assert_eq!(result.relocations.len(), 1);
        let relo = &result.relocations[0];
        assert_eq!(relo.insn_off, 0); // first instruction
        assert_eq!(relo.type_id, 1);
        assert_eq!(relo.access_str_off, 17);
        assert_eq!(relo.kind, CoreReloKind::FieldByteOffset);
    }

    #[test]
    fn test_mark_multiple_relos() {
        let mut asm = Assembler::new();

        // First relocation
        asm.mov64_imm(R3, 8);
        asm.mark_field_offset(1, 17); // pid offset

        asm.add64(R1, R3);

        // Second relocation
        asm.mov64_imm(R4, 1);
        asm.mark_field_exists(1, 25); // debug_flags exists check

        asm.exit();

        let result = asm.assemble_with_core().unwrap();

        assert_eq!(result.relocations.len(), 2);

        // First relo at instruction 0
        assert_eq!(result.relocations[0].insn_off, 0);
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
        asm.mark_type_size(2);

        asm.exit();

        let result = asm.assemble_with_core().unwrap();

        assert_eq!(result.relocations.len(), 1);
        // LDDW takes 16 bytes, so mov64 is at offset 16
        assert_eq!(result.relocations[0].insn_off, 16);
    }

    #[test]
    fn test_assembled_program_instructions() {
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 42);
        asm.exit();

        let result = asm.assemble_with_core().unwrap();
        let insns = result.instructions();

        assert_eq!(insns.len(), 2);
        // mov64 r0, 42
        assert_eq!(insns[0] & 0xFF, 0xb7);
        // exit
        assert_eq!(insns[1] & 0xFF, 0x95);
    }

    #[test]
    fn test_mark_core_relo_at() {
        let mut asm = Assembler::new();

        asm.mov64_imm(R0, 0); // idx 0
        asm.mov64_imm(R1, 8); // idx 1
        asm.mov64_imm(R2, 16); // idx 2
        asm.exit();

        // Mark instruction 1 (not the last one)
        asm.mark_core_relo_at(1, CoreReloKind::FieldByteOffset, 1, 17);

        let result = asm.assemble_with_core().unwrap();

        assert_eq!(result.relocations.len(), 1);
        assert_eq!(result.relocations[0].insn_off, 8); // instruction 1
    }

    #[test]
    fn test_jmp32_jeq() {
        let mut asm = Assembler::new();
        let mut target = asm.create_label();

        asm.mov32_imm(R0, 100);
        asm.jeq32_imm(R0, 100, &target);
        asm.mov32_imm(R0, 0);
        asm.set_label(&mut target).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        // jeq32 is at instruction 1, opcode should be 0x06 (JMP32 class) | 0x10 (JEQ)
        // JMP32 = 0x06, JEQ = 0x10, SRC_IMM = 0x00 -> 0x16
        assert_eq!(code[8], 0x16);
    }

    #[test]
    fn test_jmp32_jne() {
        let mut asm = Assembler::new();
        let mut target = asm.create_label();

        asm.mov32_imm(R0, 100);
        asm.jne32_imm(R0, 50, &target);
        asm.mov32_imm(R0, 0);
        asm.set_label(&mut target).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        // JMP32 = 0x06, JNE = 0x50, SRC_IMM = 0x00 -> 0x56
        assert_eq!(code[8], 0x56);
    }

    #[test]
    fn test_jmp32_unsigned_comparisons() {
        let mut asm = Assembler::new();
        let mut l1 = asm.create_label();
        let mut l2 = asm.create_label();
        let mut l3 = asm.create_label();
        let mut l4 = asm.create_label();

        asm.jgt32_imm(R0, 10, &l1);
        asm.set_label(&mut l1).unwrap();
        asm.jge32_imm(R0, 10, &l2);
        asm.set_label(&mut l2).unwrap();
        asm.jlt32_imm(R0, 10, &l3);
        asm.set_label(&mut l3).unwrap();
        asm.jle32_imm(R0, 10, &l4);
        asm.set_label(&mut l4).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();

        // JMP32 = 0x06
        // JGT = 0x20, JGE = 0x30, JLT = 0xa0, JLE = 0xb0
        assert_eq!(code[0], 0x26); // jgt32
        assert_eq!(code[8], 0x36); // jge32
        assert_eq!(code[16], 0xa6); // jlt32
        assert_eq!(code[24], 0xb6); // jle32
    }

    #[test]
    fn test_jmp32_signed_comparisons() {
        let mut asm = Assembler::new();
        let mut l1 = asm.create_label();
        let mut l2 = asm.create_label();
        let mut l3 = asm.create_label();
        let mut l4 = asm.create_label();

        asm.jsgt32_imm(R0, -10, &l1);
        asm.set_label(&mut l1).unwrap();
        asm.jsge32_imm(R0, -10, &l2);
        asm.set_label(&mut l2).unwrap();
        asm.jslt32_imm(R0, -10, &l3);
        asm.set_label(&mut l3).unwrap();
        asm.jsle32_imm(R0, -10, &l4);
        asm.set_label(&mut l4).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();

        // JMP32 = 0x06
        // JSGT = 0x60, JSGE = 0x70, JSLT = 0xc0, JSLE = 0xd0
        assert_eq!(code[0], 0x66); // jsgt32
        assert_eq!(code[8], 0x76); // jsge32
        assert_eq!(code[16], 0xc6); // jslt32
        assert_eq!(code[24], 0xd6); // jsle32
    }

    #[test]
    fn test_jmp32_jset() {
        let mut asm = Assembler::new();
        let mut target = asm.create_label();

        asm.jset32_imm(R0, 0x80, &target);
        asm.set_label(&mut target).unwrap();
        asm.exit();

        let code = asm.assemble().unwrap();
        // JMP32 = 0x06, JSET = 0x40 -> 0x46
        assert_eq!(code[0], 0x46);
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
}
