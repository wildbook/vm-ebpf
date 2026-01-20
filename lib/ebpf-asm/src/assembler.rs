//! eBPF assembler with label support.
//!
//! Provides a builder-style API for creating eBPF bytecode with automatic
//! label resolution for branches.
//!
//! # Example
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
//! asm.mov64_imm(R0, 10).unwrap();
//!
//! // loop_start:
//! asm.set_label(&mut loop_start).unwrap();
//!
//! // sub64 r0, 1
//! asm.sub64_imm(R0, 1).unwrap();
//!
//! // jne r0, 0, loop_start
//! asm.jne_imm(R0, 0, &loop_start).unwrap();
//!
//! // exit
//! asm.exit().unwrap();
//!
//! let code = asm.assemble().unwrap();
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
            AsmError::UndefinedLabel(name) => write!(f, "undefined label: {}", name),
            AsmError::DuplicateLabel(name) => write!(f, "duplicate label: {}", name),
            AsmError::OffsetOutOfRange { from, to } => {
                write!(f, "jump offset out of range: {} -> {}", from, to)
            }
            AsmError::ImmediateOutOfRange(v) => write!(f, "immediate out of range: {}", v),
            AsmError::InvalidLabel => write!(f, "invalid label reference"),
        }
    }
}

impl std::error::Error for AsmError {}

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
/// label resolution.
pub struct Assembler {
    /// Assembled instructions.
    instructions: Vec<AsmInsn>,
    /// Label counter for generating unique IDs.
    label_counter: usize,
    /// Label positions (label_id -> instruction index).
    label_positions: HashMap<usize, usize>,
    /// Pending label references to resolve.
    label_refs: Vec<LabelRef>,
}

impl Assembler {
    /// Create a new assembler.
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            label_counter: 0,
            label_positions: HashMap::new(),
            label_refs: Vec::new(),
        }
    }

    /// Create with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            instructions: Vec::with_capacity(capacity),
            label_counter: 0,
            label_positions: HashMap::new(),
            label_refs: Vec::new(),
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
    /// asm.mov64_imm(R3, 8).unwrap();  // This instruction is at mov_idx
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
    /// asm.mov64_imm(R0, 42).unwrap();
    /// asm.exit().unwrap();
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
        // Don't reset label_counter to avoid ID collisions
    }

    // ==================== ALU64 Instructions ====================

    /// `add64 dst, src` - 64-bit addition with register source.
    pub fn add64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::ADD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `add64 dst, imm` - 64-bit addition with immediate.
    pub fn add64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::ADD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `sub64 dst, src` - 64-bit subtraction with register source.
    pub fn sub64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::SUB | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `sub64 dst, imm` - 64-bit subtraction with immediate.
    pub fn sub64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::SUB | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `mul64 dst, src` - 64-bit multiplication with register source.
    pub fn mul64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::MUL | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `mul64 dst, imm` - 64-bit multiplication with immediate.
    pub fn mul64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::MUL | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `div64 dst, src` - 64-bit unsigned division with register source.
    pub fn div64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::DIV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `div64 dst, imm` - 64-bit unsigned division with immediate.
    pub fn div64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::DIV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `sdiv64 dst, src` - 64-bit signed division with register source.
    pub fn sdiv64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::DIV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 1, 0));
        Ok(self)
    }

    /// `sdiv64 dst, imm` - 64-bit signed division with immediate.
    pub fn sdiv64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::DIV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 1, imm));
        Ok(self)
    }

    /// `or64 dst, src` - 64-bit bitwise OR with register source.
    pub fn or64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::OR | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `or64 dst, imm` - 64-bit bitwise OR with immediate.
    pub fn or64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::OR | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `and64 dst, src` - 64-bit bitwise AND with register source.
    pub fn and64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::AND | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `and64 dst, imm` - 64-bit bitwise AND with immediate.
    pub fn and64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::AND | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `lsh64 dst, src` - 64-bit left shift with register source.
    pub fn lsh64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::LSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `lsh64 dst, imm` - 64-bit left shift with immediate.
    pub fn lsh64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::LSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `rsh64 dst, src` - 64-bit logical right shift with register source.
    pub fn rsh64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::RSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `rsh64 dst, imm` - 64-bit logical right shift with immediate.
    pub fn rsh64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::RSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `neg64 dst` - 64-bit negation.
    pub fn neg64(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::NEG | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 0));
        Ok(self)
    }

    /// `mod64 dst, src` - 64-bit unsigned modulo with register source.
    pub fn mod64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::MOD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `mod64 dst, imm` - 64-bit unsigned modulo with immediate.
    pub fn mod64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::MOD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `xor64 dst, src` - 64-bit bitwise XOR with register source.
    pub fn xor64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::XOR | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `xor64 dst, imm` - 64-bit bitwise XOR with immediate.
    pub fn xor64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::XOR | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `mov64 dst, src` - 64-bit move from register.
    pub fn mov64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::MOV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `mov64 dst, imm` - 64-bit move immediate.
    pub fn mov64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::MOV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `arsh64 dst, src` - 64-bit arithmetic right shift with register source.
    pub fn arsh64(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::ARSH | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `arsh64 dst, imm` - 64-bit arithmetic right shift with immediate.
    pub fn arsh64_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU64 | alu::ARSH | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    // ==================== ALU32 Instructions ====================

    /// `add32 dst, src` - 32-bit addition with register source.
    pub fn add32(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::ADD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `add32 dst, imm` - 32-bit addition with immediate.
    pub fn add32_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::ADD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `sub32 dst, src` - 32-bit subtraction with register source.
    pub fn sub32(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::SUB | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `sub32 dst, imm` - 32-bit subtraction with immediate.
    pub fn sub32_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::SUB | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    /// `mov32 dst, src` - 32-bit move from register.
    pub fn mov32(&mut self, dst: Register, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::MOV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        Ok(self)
    }

    /// `mov32 dst, imm` - 32-bit move immediate.
    pub fn mov32_imm(&mut self, dst: Register, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::MOV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        Ok(self)
    }

    // ==================== Endianness Instructions ====================

    /// `le16 dst` - Convert to little-endian 16-bit.
    pub fn le16(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::END | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 16));
        Ok(self)
    }

    /// `le32 dst` - Convert to little-endian 32-bit.
    pub fn le32(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::END | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 32));
        Ok(self)
    }

    /// `le64 dst` - Convert to little-endian 64-bit.
    pub fn le64(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::END | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 64));
        Ok(self)
    }

    /// `be16 dst` - Convert to big-endian 16-bit.
    pub fn be16(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::END | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 16));
        Ok(self)
    }

    /// `be32 dst` - Convert to big-endian 32-bit.
    pub fn be32(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::END | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 32));
        Ok(self)
    }

    /// `be64 dst` - Convert to big-endian 64-bit.
    pub fn be64(&mut self, dst: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::ALU32 | alu::END | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, 64));
        Ok(self)
    }

    // ==================== Memory Load Instructions ====================

    /// `ldxdw dst, [src+off]` - Load 64-bit from memory.
    pub fn ldxdw(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `ldxw dst, [src+off]` - Load 32-bit from memory.
    pub fn ldxw(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `ldxh dst, [src+off]` - Load 16-bit from memory.
    pub fn ldxh(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `ldxb dst, [src+off]` - Load 8-bit from memory.
    pub fn ldxb(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `ldxsw dst, [src+off]` - Load 32-bit with sign extension.
    pub fn ldxsw(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::W | mode::MEMSX;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `ldxsh dst, [src+off]` - Load 16-bit with sign extension.
    pub fn ldxsh(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::H | mode::MEMSX;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `ldxsb dst, [src+off]` - Load 8-bit with sign extension.
    pub fn ldxsb(&mut self, dst: Register, src: Register, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::LDX | size::B | mode::MEMSX;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `lddw dst, imm64` - Load 64-bit immediate.
    pub fn lddw(&mut self, dst: Register, imm: i64) -> Result<&mut Self, AsmError> {
        let opcode = class::LD | size::DW | mode::IMM;
        let imm_lo = imm as u32 as i32;
        let imm_hi = (imm as u64 >> 32) as u32 as i32;
        let raw1 = RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm_lo);
        let raw2 = RawInstruction::from_parts(0, 0, 0, 0, imm_hi);
        self.emit_wide(raw1, raw2);
        Ok(self)
    }

    // ==================== Memory Store Instructions ====================

    /// `stxdw [dst+off], src` - Store 64-bit to memory from register.
    pub fn stxdw(&mut self, dst: Register, offset: i16, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::STX | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `stxw [dst+off], src` - Store 32-bit to memory from register.
    pub fn stxw(&mut self, dst: Register, offset: i16, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::STX | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `stxh [dst+off], src` - Store 16-bit to memory from register.
    pub fn stxh(&mut self, dst: Register, offset: i16, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::STX | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `stxb [dst+off], src` - Store 8-bit to memory from register.
    pub fn stxb(&mut self, dst: Register, offset: i16, src: Register) -> Result<&mut Self, AsmError> {
        let opcode = class::STX | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        Ok(self)
    }

    /// `stdw [dst+off], imm` - Store 64-bit immediate to memory.
    pub fn stdw(&mut self, dst: Register, offset: i16, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ST | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        Ok(self)
    }

    /// `stw [dst+off], imm` - Store 32-bit immediate to memory.
    pub fn stw(&mut self, dst: Register, offset: i16, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ST | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        Ok(self)
    }

    /// `sth [dst+off], imm` - Store 16-bit immediate to memory.
    pub fn sth(&mut self, dst: Register, offset: i16, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ST | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        Ok(self)
    }

    /// `stb [dst+off], imm` - Store 8-bit immediate to memory.
    pub fn stb(&mut self, dst: Register, offset: i16, imm: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::ST | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, offset, imm));
        Ok(self)
    }

    // ==================== Jump Instructions with Labels ====================

    /// `ja label` - Unconditional jump to label.
    pub fn ja(&mut self, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        self.add_label_ref(label, LabelRefType::UnconditionalJump);
        Ok(self)
    }

    /// `ja offset` - Unconditional jump to relative offset.
    pub fn ja_off(&mut self, offset: i16) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JA;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, offset, 0));
        Ok(self)
    }

    /// `jeq dst, src, label` - Jump if equal (register).
    pub fn jeq(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JEQ | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jeq dst, imm, label` - Jump if equal (immediate).
    pub fn jeq_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JEQ | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jne dst, src, label` - Jump if not equal (register).
    pub fn jne(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JNE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jne dst, imm, label` - Jump if not equal (immediate).
    pub fn jne_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JNE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jgt dst, src, label` - Jump if greater than (unsigned, register).
    pub fn jgt(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JGT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jgt dst, imm, label` - Jump if greater than (unsigned, immediate).
    pub fn jgt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JGT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jge dst, src, label` - Jump if greater or equal (unsigned, register).
    pub fn jge(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JGE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jge dst, imm, label` - Jump if greater or equal (unsigned, immediate).
    pub fn jge_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JGE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jlt dst, src, label` - Jump if less than (unsigned, register).
    pub fn jlt(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JLT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jlt dst, imm, label` - Jump if less than (unsigned, immediate).
    pub fn jlt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JLT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jle dst, src, label` - Jump if less or equal (unsigned, register).
    pub fn jle(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JLE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jle dst, imm, label` - Jump if less or equal (unsigned, immediate).
    pub fn jle_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JLE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jset dst, src, label` - Jump if bits set.
    pub fn jset(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSET | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jset dst, imm, label` - Jump if bits set (immediate).
    pub fn jset_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSET | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jsgt dst, src, label` - Jump if signed greater than.
    pub fn jsgt(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSGT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jsgt dst, imm, label` - Jump if signed greater than (immediate).
    pub fn jsgt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSGT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jsge dst, src, label` - Jump if signed greater or equal.
    pub fn jsge(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSGE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jsge dst, imm, label` - Jump if signed greater or equal (immediate).
    pub fn jsge_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSGE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jslt dst, src, label` - Jump if signed less than.
    pub fn jslt(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSLT | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jslt dst, imm, label` - Jump if signed less than (immediate).
    pub fn jslt_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSLT | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jsle dst, src, label` - Jump if signed less or equal.
    pub fn jsle(&mut self, dst: Register, src: Register, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSLE | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    /// `jsle dst, imm, label` - Jump if signed less or equal (immediate).
    pub fn jsle_imm(&mut self, dst: Register, imm: i32, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::JSLE | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        self.add_label_ref(label, LabelRefType::ConditionalJump);
        Ok(self)
    }

    // ==================== Call / Exit ====================

    /// `call imm` - Call helper function by ID.
    pub fn call(&mut self, func_id: i32) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::CALL;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, func_id));
        Ok(self)
    }

    /// `call label` - Call local function (BPF-to-BPF call).
    pub fn call_local(&mut self, label: &Label) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::CALL;
        // src_reg = 1 indicates BPF-to-BPF call
        self.emit(RawInstruction::from_parts(opcode, 0, 1, 0, 0));
        self.add_label_ref(label, LabelRefType::LocalCall);
        Ok(self)
    }

    /// `exit` - Exit program.
    pub fn exit(&mut self) -> Result<&mut Self, AsmError> {
        let opcode = class::JMP64 | jmp::EXIT;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, 0));
        Ok(self)
    }

    // ==================== Raw Instruction ====================

    /// Emit a raw instruction.
    pub fn raw(&mut self, opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> &mut Self {
        self.emit(RawInstruction::from_parts(opcode, dst, src, offset, imm));
        self
    }

    /// Emit a raw instruction and return its index.
    ///
    /// This is useful for CO-RE relocations where you need to track
    /// which instruction to patch.
    pub fn raw_idx(&mut self, opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> usize {
        let idx = self.instructions.len();
        self.emit(RawInstruction::from_parts(opcode, dst, src, offset, imm));
        idx
    }

    // ==================== Index-returning variants for CO-RE ====================

    /// `mov64 dst, imm` - 64-bit move immediate, returns instruction index.
    ///
    /// This variant is useful for CO-RE relocations where the immediate
    /// value needs to be patched at load time.
    ///
    /// # Example
    ///
    /// ```
    /// use ebpf_asm::{Assembler, R3};
    ///
    /// let mut asm = Assembler::new();
    /// let idx = asm.mov64_imm_idx(R3, 8);  // Placeholder offset
    /// // Use idx and asm.byte_offset(idx) for CO-RE relocation
    /// ```
    pub fn mov64_imm_idx(&mut self, dst: Register, imm: i32) -> usize {
        let idx = self.instructions.len();
        let opcode = class::ALU64 | alu::MOV | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        idx
    }

    /// `ldxw dst, [src+off]` - Load 32-bit from memory, returns instruction index.
    pub fn ldxw_idx(&mut self, dst: Register, src: Register, offset: i16) -> usize {
        let idx = self.instructions.len();
        let opcode = class::LDX | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        idx
    }

    /// `ldxdw dst, [src+off]` - Load 64-bit from memory, returns instruction index.
    pub fn ldxdw_idx(&mut self, dst: Register, src: Register, offset: i16) -> usize {
        let idx = self.instructions.len();
        let opcode = class::LDX | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        idx
    }

    /// `ldxh dst, [src+off]` - Load 16-bit from memory, returns instruction index.
    pub fn ldxh_idx(&mut self, dst: Register, src: Register, offset: i16) -> usize {
        let idx = self.instructions.len();
        let opcode = class::LDX | size::H | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        idx
    }

    /// `ldxb dst, [src+off]` - Load 8-bit from memory, returns instruction index.
    pub fn ldxb_idx(&mut self, dst: Register, src: Register, offset: i16) -> usize {
        let idx = self.instructions.len();
        let opcode = class::LDX | size::B | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        idx
    }

    /// `stxw [dst+off], src` - Store 32-bit to memory, returns instruction index.
    pub fn stxw_idx(&mut self, dst: Register, offset: i16, src: Register) -> usize {
        let idx = self.instructions.len();
        let opcode = class::STX | size::W | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        idx
    }

    /// `stxdw [dst+off], src` - Store 64-bit to memory, returns instruction index.
    pub fn stxdw_idx(&mut self, dst: Register, offset: i16, src: Register) -> usize {
        let idx = self.instructions.len();
        let opcode = class::STX | size::DW | mode::MEM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), offset, 0));
        idx
    }

    /// `add64 dst, imm` - 64-bit addition with immediate, returns instruction index.
    pub fn add64_imm_idx(&mut self, dst: Register, imm: i32) -> usize {
        let idx = self.instructions.len();
        let opcode = class::ALU64 | alu::ADD | SRC_IMM;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), 0, 0, imm));
        idx
    }

    /// `add64 dst, src` - 64-bit addition with register, returns instruction index.
    pub fn add64_idx(&mut self, dst: Register, src: Register) -> usize {
        let idx = self.instructions.len();
        let opcode = class::ALU64 | alu::ADD | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        idx
    }

    /// `mov64 dst, src` - 64-bit move from register, returns instruction index.
    pub fn mov64_idx(&mut self, dst: Register, src: Register) -> usize {
        let idx = self.instructions.len();
        let opcode = class::ALU64 | alu::MOV | SRC_REG;
        self.emit(RawInstruction::from_parts(opcode, dst.number(), src.number(), 0, 0));
        idx
    }

    /// `call imm` - Call helper function by ID, returns instruction index.
    pub fn call_idx(&mut self, func_id: i32) -> usize {
        let idx = self.instructions.len();
        let opcode = class::JMP64 | jmp::CALL;
        self.emit(RawInstruction::from_parts(opcode, 0, 0, 0, func_id));
        idx
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
        asm.mov64_imm(R0, 42).unwrap();
        asm.exit().unwrap();

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

        asm.mov64_imm(R0, 1).unwrap();
        asm.ja(&end).unwrap();
        asm.mov64_imm(R0, 2).unwrap();
        asm.set_label(&mut end).unwrap();
        asm.exit().unwrap();

        let code = asm.assemble().unwrap();
        // Check jump offset: from insn 1 to insn 3, offset = 3 - (1 + 1) = 1
        let offset = i16::from_le_bytes([code[10], code[11]]);
        assert_eq!(offset, 1);
    }

    #[test]
    fn test_backward_label() {
        let mut asm = Assembler::new();
        let mut loop_start = asm.create_label();

        asm.mov64_imm(R0, 10).unwrap(); // insn 0
        asm.set_label(&mut loop_start).unwrap(); // label points to insn 1
        asm.sub64_imm(R0, 1).unwrap(); // insn 1
        asm.jne_imm(R0, 0, &loop_start).unwrap(); // insn 2
        asm.exit().unwrap(); // insn 3

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
        asm.lddw(R0, 0x123456789ABCDEF0u64 as i64).unwrap();
        asm.exit().unwrap();

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

        asm.ja(&end).unwrap();
        asm.exit().unwrap();

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
        asm.ldxdw(R0, R1, 16).unwrap();
        asm.stxdw(R1, -8, R0).unwrap();
        asm.exit().unwrap();

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
        asm.call(1).unwrap(); // bpf_map_lookup_elem
        asm.exit().unwrap();

        let code = asm.assemble().unwrap();
        assert_eq!(code[0], 0x85); // call opcode
        let func_id = i32::from_le_bytes([code[4], code[5], code[6], code[7]]);
        assert_eq!(func_id, 1);
    }

    #[test]
    fn test_local_call() {
        let mut asm = Assembler::new();
        let mut func = asm.create_label();

        asm.call_local(&func).unwrap();
        asm.exit().unwrap();
        asm.set_label(&mut func).unwrap();
        asm.mov64_imm(R0, 0).unwrap();
        asm.exit().unwrap();

        let code = asm.assemble().unwrap();
        // src_reg should be 1 for local call
        assert_eq!((code[1] >> 4) & 0xF, 1);
    }

    #[test]
    fn test_current_index() {
        let mut asm = Assembler::new();

        assert_eq!(asm.current_index(), 0);
        asm.mov64_imm(R0, 42).unwrap();
        assert_eq!(asm.current_index(), 1);
        asm.add64_imm(R0, 10).unwrap();
        assert_eq!(asm.current_index(), 2);
        asm.exit().unwrap();
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
    fn test_mov64_imm_idx() {
        let mut asm = Assembler::new();

        let idx0 = asm.mov64_imm_idx(R0, 10);
        let idx1 = asm.mov64_imm_idx(R1, 20);
        let idx2 = asm.mov64_imm_idx(R2, 30);

        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);

        // Verify byte offsets for CO-RE
        assert_eq!(asm.byte_offset(idx0), 0);
        assert_eq!(asm.byte_offset(idx1), 8);
        assert_eq!(asm.byte_offset(idx2), 16);
    }

    #[test]
    fn test_ldxw_idx_for_core() {
        let mut asm = Assembler::new();

        // Typical CO-RE pattern: load with offset that gets patched
        let load_idx = asm.ldxw_idx(R2, R1, 8); // r2 = *(u32*)(r1 + 8)

        assert_eq!(load_idx, 0);
        assert_eq!(asm.byte_offset(load_idx), 0);

        let code = asm.assemble().unwrap();
        // Check opcode for LDX_W
        assert_eq!(code[0], 0x61);
        // Check offset field
        let offset = i16::from_le_bytes([code[2], code[3]]);
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_raw_idx() {
        let mut asm = Assembler::new();

        asm.mov64_imm(R0, 0).unwrap();
        let raw_idx = asm.raw_idx(0x61, 2, 1, 8, 0); // LDX_W r2, [r1+8]
        asm.exit().unwrap();

        assert_eq!(raw_idx, 1);
        assert_eq!(asm.byte_offset(raw_idx), 8);
    }

    #[test]
    fn test_current_byte_offset() {
        let mut asm = Assembler::new();

        assert_eq!(asm.current_byte_offset(), 0);
        asm.mov64_imm(R0, 42).unwrap();
        assert_eq!(asm.current_byte_offset(), 8);
        asm.add64_imm(R0, 10).unwrap();
        assert_eq!(asm.current_byte_offset(), 16);
    }
}
