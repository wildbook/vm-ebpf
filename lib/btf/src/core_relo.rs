//! CO-RE (Compile Once - Run Everywhere) relocation support.
//!
//! This module handles parsing of `.BTF.ext` sections and applying
//! CO-RE relocations to eBPF instructions based on the host's type registry.

use crate::parse::{Btf, BtfError};
use crate::registry::TypeRegistry;
use crate::strings::BtfStrings;
use crate::types::BtfTypeInfo;

/// CO-RE relocation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CoreReloKind {
    /// Field byte offset.
    FieldByteOffset = 0,
    /// Field byte size.
    FieldByteSize = 1,
    /// Field existence (0 or 1).
    FieldExists = 2,
    /// Field signedness (0 or 1).
    FieldSigned = 3,
    /// Field left shift for reading/writing.
    FieldLShiftU64 = 4,
    /// Field right shift for reading/writing.
    FieldRShiftU64 = 5,
    /// Type ID (local BTF).
    TypeIdLocal = 6,
    /// Type ID (target BTF).
    TypeIdTarget = 7,
    /// Type existence (0 or 1).
    TypeExists = 8,
    /// Type size.
    TypeSize = 9,
    /// Enum value existence.
    EnumvalExists = 10,
    /// Enum value.
    EnumvalValue = 11,
    /// Type matches (0 or 1).
    TypeMatches = 12,
}

impl CoreReloKind {
    /// Parse from raw value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::FieldByteOffset),
            1 => Some(Self::FieldByteSize),
            2 => Some(Self::FieldExists),
            3 => Some(Self::FieldSigned),
            4 => Some(Self::FieldLShiftU64),
            5 => Some(Self::FieldRShiftU64),
            6 => Some(Self::TypeIdLocal),
            7 => Some(Self::TypeIdTarget),
            8 => Some(Self::TypeExists),
            9 => Some(Self::TypeSize),
            10 => Some(Self::EnumvalExists),
            11 => Some(Self::EnumvalValue),
            12 => Some(Self::TypeMatches),
            _ => None,
        }
    }

    /// Check if this is a field-based relocation.
    pub fn is_field_relo(self) -> bool {
        matches!(
            self,
            Self::FieldByteOffset
                | Self::FieldByteSize
                | Self::FieldExists
                | Self::FieldSigned
                | Self::FieldLShiftU64
                | Self::FieldRShiftU64
        )
    }

    /// Check if this is a type-based relocation.
    pub fn is_type_relo(self) -> bool {
        matches!(self, Self::TypeIdLocal | Self::TypeIdTarget | Self::TypeExists | Self::TypeSize | Self::TypeMatches)
    }

    /// Check if this is an enum-based relocation.
    pub fn is_enum_relo(self) -> bool {
        matches!(self, Self::EnumvalExists | Self::EnumvalValue)
    }
}

/// A single CO-RE relocation entry.
#[derive(Debug, Clone)]
pub struct CoreRelo {
    /// Instruction offset (in bytes from section start).
    pub insn_off: u32,
    /// BTF type ID in the local (program) BTF.
    pub type_id: u32,
    /// Access string offset in BTF strings.
    pub access_str_off: u32,
    /// Relocation kind.
    pub kind: CoreReloKind,
}

impl CoreRelo {
    pub const SIZE: usize = 16;

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let insn_off = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let type_id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let access_str_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let kind_raw = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let kind = CoreReloKind::from_u32(kind_raw)?;

        Some(Self {
            insn_off,
            type_id,
            access_str_off,
            kind,
        })
    }
}

/// BTF.ext header.
#[derive(Debug, Clone, Copy)]
pub struct BtfExtHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub func_info_off: u32,
    pub func_info_len: u32,
    pub line_info_off: u32,
    pub line_info_len: u32,
    pub core_relo_off: u32,
    pub core_relo_len: u32,
}

impl BtfExtHeader {
    pub const MIN_SIZE: usize = 24;
    pub const SIZE_WITH_CORE: usize = 32;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        let version = data[2];
        let flags = data[3];
        let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let func_info_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let func_info_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let line_info_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let line_info_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        // CO-RE relocations are optional (added later)
        let (core_relo_off, core_relo_len) =
            if hdr_len as usize >= Self::SIZE_WITH_CORE && data.len() >= Self::SIZE_WITH_CORE {
                let off = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
                let len = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
                (off, len)
            } else {
                (0, 0)
            };

        Some(Self {
            magic,
            version,
            flags,
            hdr_len,
            func_info_off,
            func_info_len,
            line_info_off,
            line_info_len,
            core_relo_off,
            core_relo_len,
        })
    }
}

/// CO-RE relocations for a specific section.
#[derive(Debug, Clone)]
pub struct SectionCoreRelos<'a> {
    /// Section name.
    pub section_name: &'a str,
    /// Relocations for this section.
    pub relos: Vec<CoreRelo>,
}

/// Parsed BTF.ext data.
#[derive(Debug, Clone)]
pub struct BtfExt<'a> {
    /// Header.
    pub header: BtfExtHeader,
    /// CO-RE relocations grouped by section.
    pub core_relos: Vec<SectionCoreRelos<'a>>,
}

impl<'a> BtfExt<'a> {
    /// Parse BTF.ext from raw bytes.
    ///
    /// Requires the BTF strings table for resolving section names.
    pub fn parse(data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Self, BtfError> {
        let header = BtfExtHeader::parse(data).ok_or(BtfError::TooShort)?;

        if header.magic != crate::raw::BTF_MAGIC {
            return Err(BtfError::BadMagic(header.magic));
        }

        let core_relos = if header.core_relo_len > 0 {
            Self::parse_core_relos(data, &header, strings)?
        } else {
            Vec::new()
        };

        Ok(Self { header, core_relos })
    }

    fn parse_core_relos(
        data: &'a [u8],
        header: &BtfExtHeader,
        strings: &BtfStrings<'a>,
    ) -> Result<Vec<SectionCoreRelos<'a>>, BtfError> {
        let start = header.hdr_len as usize + header.core_relo_off as usize;
        let end = start + header.core_relo_len as usize;

        if end > data.len() || start >= data.len() {
            return Err(BtfError::SectionOverflow);
        }

        let relo_data = &data[start..end];
        if relo_data.len() < 4 {
            return Ok(Vec::new());
        }

        // First 4 bytes: record size
        let rec_size = u32::from_le_bytes([relo_data[0], relo_data[1], relo_data[2], relo_data[3]]) as usize;
        if rec_size < CoreRelo::SIZE {
            return Err(BtfError::InvalidType(0));
        }

        let mut offset = 4;
        let mut sections = Vec::new();

        while offset + 8 <= relo_data.len() {
            // Section header: sec_name_off (4) + num_info (4)
            let sec_name_off = u32::from_le_bytes([
                relo_data[offset],
                relo_data[offset + 1],
                relo_data[offset + 2],
                relo_data[offset + 3],
            ]);
            let num_info = u32::from_le_bytes([
                relo_data[offset + 4],
                relo_data[offset + 5],
                relo_data[offset + 6],
                relo_data[offset + 7],
            ]);
            offset += 8;

            let section_name = strings.get_or_empty(sec_name_off);
            let mut relos = Vec::with_capacity(num_info as usize);

            for _ in 0..num_info {
                if offset + rec_size > relo_data.len() {
                    return Err(BtfError::SectionOverflow);
                }
                if let Some(relo) = CoreRelo::parse(&relo_data[offset..]) {
                    relos.push(relo);
                }
                offset += rec_size;
            }

            sections.push(SectionCoreRelos { section_name, relos });
        }

        Ok(sections)
    }

    /// Get CO-RE relocations for a specific section.
    pub fn relos_for_section(&self, section_name: &str) -> Option<&[CoreRelo]> {
        self.core_relos
            .iter()
            .find(|s| s.section_name == section_name)
            .map(|s| s.relos.as_slice())
    }
}

/// Error during CO-RE relocation application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreReloError {
    /// Type not found in registry.
    TypeNotFound(String),
    /// Field not found in type.
    FieldNotFound { type_name: String, field_name: String },
    /// Enum variant not found.
    EnumVariantNotFound { enum_name: String, variant_name: String },
    /// Invalid access string.
    InvalidAccessString(String),
    /// Instruction offset out of bounds.
    InstructionOutOfBounds(u32),
    /// Invalid BTF type ID.
    InvalidTypeId(u32),
    /// Unsupported relocation kind.
    UnsupportedRelo(CoreReloKind),
}

impl core::fmt::Display for CoreReloError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TypeNotFound(name) => write!(f, "type not found: {}", name),
            Self::FieldNotFound { type_name, field_name } => {
                write!(f, "field '{}' not found in type '{}'", field_name, type_name)
            }
            Self::EnumVariantNotFound {
                enum_name,
                variant_name,
            } => {
                write!(f, "enum variant '{}' not found in '{}'", variant_name, enum_name)
            }
            Self::InvalidAccessString(s) => write!(f, "invalid access string: {}", s),
            Self::InstructionOutOfBounds(off) => write!(f, "instruction offset out of bounds: {}", off),
            Self::InvalidTypeId(id) => write!(f, "invalid BTF type ID: {}", id),
            Self::UnsupportedRelo(kind) => write!(f, "unsupported relocation kind: {:?}", kind),
        }
    }
}

impl std::error::Error for CoreReloError {}

/// Result of applying a CO-RE relocation.
#[derive(Debug, Clone, Copy)]
pub struct ReloResult {
    /// The computed value to patch into the instruction.
    pub value: u64,
    /// Whether the relocation succeeded (for existence checks).
    #[allow(dead_code)]
    pub success: bool,
}

/// Apply CO-RE relocations to eBPF instructions.
///
/// # Arguments
///
/// * `instructions` - Mutable slice of 8-byte eBPF instructions
/// * `btf` - The program's BTF (for type information)
/// * `registry` - The host's type registry
/// * `relos` - CO-RE relocations to apply
///
/// # Returns
///
/// Number of relocations successfully applied.
pub fn apply_core_relocations(
    instructions: &mut [u64],
    btf: &Btf<'_>,
    registry: &TypeRegistry,
    relos: &[CoreRelo],
) -> Result<usize, CoreReloError> {
    let mut applied = 0;

    for relo in relos {
        match apply_single_relocation(instructions, btf, registry, relo) {
            Ok(_) => applied += 1,
            Err(e) => {
                // For existence checks, a "not found" is not an error
                if matches!(
                    relo.kind,
                    CoreReloKind::FieldExists | CoreReloKind::TypeExists | CoreReloKind::EnumvalExists
                ) {
                    // Patch with 0 (does not exist)
                    patch_instruction(instructions, relo.insn_off, 0)?;
                    applied += 1;
                } else {
                    return Err(e);
                }
            }
        }
    }

    Ok(applied)
}

fn apply_single_relocation(
    instructions: &mut [u64],
    btf: &Btf<'_>,
    registry: &TypeRegistry,
    relo: &CoreRelo,
) -> Result<ReloResult, CoreReloError> {
    // Get the type from BTF
    let btf_type = btf
        .type_by_id(relo.type_id)
        .ok_or(CoreReloError::InvalidTypeId(relo.type_id))?;

    // Get the access string
    let access_str = btf
        .strings()
        .get(relo.access_str_off)
        .ok_or_else(|| CoreReloError::InvalidAccessString(format!("offset {}", relo.access_str_off)))?;

    let result = compute_relocation_value(btf_type, btf, registry, access_str, relo.kind)?;

    patch_instruction(instructions, relo.insn_off, result.value)?;

    Ok(result)
}

fn compute_relocation_value(
    btf_type: &BtfTypeInfo<'_>,
    _btf: &Btf<'_>,
    registry: &TypeRegistry,
    access_str: &str,
    kind: CoreReloKind,
) -> Result<ReloResult, CoreReloError> {
    let type_name = btf_type.name().unwrap_or("");

    match kind {
        CoreReloKind::FieldByteOffset => {
            let field_name = parse_field_access(access_str)?;
            let offset = registry
                .field_offset(type_name, field_name)
                .ok_or_else(|| CoreReloError::FieldNotFound {
                    type_name: type_name.to_string(),
                    field_name: field_name.to_string(),
                })?;
            Ok(ReloResult {
                value: offset as u64,
                success: true,
            })
        }

        CoreReloKind::FieldByteSize => {
            let field_name = parse_field_access(access_str)?;
            let size = registry
                .field_size(type_name, field_name)
                .ok_or_else(|| CoreReloError::FieldNotFound {
                    type_name: type_name.to_string(),
                    field_name: field_name.to_string(),
                })?;
            Ok(ReloResult {
                value: size as u64,
                success: true,
            })
        }

        CoreReloKind::FieldExists => {
            let field_name = parse_field_access(access_str)?;
            let exists = registry.field_exists(type_name, field_name);
            Ok(ReloResult {
                value: exists as u64,
                success: exists,
            })
        }

        CoreReloKind::TypeExists => {
            let exists = registry.has_struct(type_name) || registry.has_enum(type_name);
            Ok(ReloResult {
                value: exists as u64,
                success: exists,
            })
        }

        CoreReloKind::TypeSize => {
            let size = registry
                .struct_size(type_name)
                .ok_or_else(|| CoreReloError::TypeNotFound(type_name.to_string()))?;
            Ok(ReloResult {
                value: size as u64,
                success: true,
            })
        }

        CoreReloKind::EnumvalExists => {
            // For enums, access_str is the variant name
            let variant_name = access_str;
            let exists = registry.enum_variant_exists(type_name, variant_name);
            Ok(ReloResult {
                value: exists as u64,
                success: exists,
            })
        }

        CoreReloKind::EnumvalValue => {
            let variant_name = access_str;
            let value =
                registry
                    .enum_value(type_name, variant_name)
                    .ok_or_else(|| CoreReloError::EnumVariantNotFound {
                        enum_name: type_name.to_string(),
                        variant_name: variant_name.to_string(),
                    })?;
            Ok(ReloResult {
                value: value as u64,
                success: true,
            })
        }

        // For now, we don't fully support these
        CoreReloKind::FieldSigned
        | CoreReloKind::FieldLShiftU64
        | CoreReloKind::FieldRShiftU64
        | CoreReloKind::TypeIdLocal
        | CoreReloKind::TypeIdTarget
        | CoreReloKind::TypeMatches => Err(CoreReloError::UnsupportedRelo(kind)),
    }
}

/// Parse a field access string like "0:1:2" or just a field name.
///
/// For simple cases, we just return the first component.
fn parse_field_access(access_str: &str) -> Result<&str, CoreReloError> {
    // Access strings can be:
    // - Simple field name: "my_field"
    // - Numeric indices: "0:1:2" (for nested access)
    //
    // For now, we handle simple field names.
    // Numeric indices would require walking the BTF type hierarchy.

    if access_str.is_empty() {
        return Err(CoreReloError::InvalidAccessString(access_str.to_string()));
    }

    // If it's all digits and colons, it's an index path
    // For now, we don't fully support index paths
    if access_str.chars().all(|c| c.is_ascii_digit() || c == ':') {
        // Index-based access - would need BTF type walking
        // For now, return an error indicating we need field name
        return Err(CoreReloError::InvalidAccessString(format!(
            "index-based access '{}' not yet supported",
            access_str
        )));
    }

    Ok(access_str)
}

/// Patch an instruction's immediate value.
fn patch_instruction(instructions: &mut [u64], insn_off: u32, value: u64) -> Result<(), CoreReloError> {
    // insn_off is in bytes, instructions are 8 bytes each
    let insn_idx = (insn_off / 8) as usize;

    if insn_idx >= instructions.len() {
        return Err(CoreReloError::InstructionOutOfBounds(insn_off));
    }

    // The immediate is in the upper 32 bits of the instruction
    let instr = &mut instructions[insn_idx];

    // Clear old imm and set new one
    // Instruction format: imm (32) | offset (16) | src (4) | dst (4) | opcode (8)
    *instr = (*instr & 0x00000000FFFFFFFF) | ((value as u32 as u64) << 32);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_relo_kind() {
        assert_eq!(CoreReloKind::from_u32(0), Some(CoreReloKind::FieldByteOffset));
        assert_eq!(CoreReloKind::from_u32(2), Some(CoreReloKind::FieldExists));
        assert_eq!(CoreReloKind::from_u32(9), Some(CoreReloKind::TypeSize));
        assert_eq!(CoreReloKind::from_u32(100), None);
    }

    #[test]
    fn test_patch_instruction() {
        let mut instructions = vec![0x0000000000000000u64; 4];

        // Patch instruction at offset 0 with value 42
        patch_instruction(&mut instructions, 0, 42).unwrap();
        assert_eq!(instructions[0] >> 32, 42);

        // Patch instruction at offset 16 (index 2) with value 100
        patch_instruction(&mut instructions, 16, 100).unwrap();
        assert_eq!(instructions[2] >> 32, 100);
    }
}
