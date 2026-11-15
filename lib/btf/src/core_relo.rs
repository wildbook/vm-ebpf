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
            Self::TypeNotFound(name) => write!(f, "type not found: {name}"),
            Self::FieldNotFound { type_name, field_name } => {
                write!(f, "field '{field_name}' not found in type '{type_name}'")
            }
            Self::EnumVariantNotFound {
                enum_name,
                variant_name,
            } => {
                write!(f, "enum variant '{variant_name}' not found in '{enum_name}'")
            }
            Self::InvalidAccessString(s) => write!(f, "invalid access string: {s}"),
            Self::InstructionOutOfBounds(off) => write!(f, "instruction offset out of bounds: {off}"),
            Self::InvalidTypeId(id) => write!(f, "invalid BTF type ID: {id}"),
            Self::UnsupportedRelo(kind) => write!(f, "unsupported relocation kind: {kind:?}"),
        }
    }
}

impl std::error::Error for CoreReloError {}

/// Helper ID that unresolved relocations call, as in libbpf: running such an
/// instruction must fail, while a program that never reaches it still works.
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// A relocation whose target the host doesn't have; its instruction was poisoned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// Byte offset of the poisoned instruction in its section.
    pub insn_off: u32,
    /// Why the relocation couldn't be resolved.
    pub error: CoreReloError,
}

/// Apply CO-RE relocations to eBPF instructions, against the host's types in `registry`.
///
/// A relocation whose type, field or enum value the host lacks rewrites its instruction
/// into a call to [`CORE_POISON_HELPER`], so code guarded by an existence check still
/// loads; those are returned. Malformed relocations and unsupported kinds are errors.
pub fn apply_core_relocations(
    instructions: &mut [u64],
    btf: &Btf<'_>,
    registry: &TypeRegistry,
    relos: &[CoreRelo],
) -> Result<Vec<Unresolved>, CoreReloError> {
    const BPF_CALL: u64 = 0x85;

    let mut unresolved = Vec::new();
    for relo in relos {
        match apply_single_relocation(instructions, btf, registry, relo) {
            Ok(()) => {}
            Err(
                error @ (CoreReloError::TypeNotFound(_)
                | CoreReloError::FieldNotFound { .. }
                | CoreReloError::EnumVariantNotFound { .. }),
            ) => {
                let insn = instructions
                    .get_mut((relo.insn_off / 8) as usize)
                    .ok_or(CoreReloError::InstructionOutOfBounds(relo.insn_off))?;
                *insn = BPF_CALL | (u64::from(CORE_POISON_HELPER) << 32);
                unresolved.push(Unresolved {
                    insn_off: relo.insn_off,
                    error,
                });
            }
            Err(e) => return Err(e),
        }
    }
    Ok(unresolved)
}

fn apply_single_relocation(
    instructions: &mut [u64],
    btf: &Btf<'_>,
    registry: &TypeRegistry,
    relo: &CoreRelo,
) -> Result<(), CoreReloError> {
    // Get the type from BTF
    let btf_type = btf
        .type_by_id(relo.type_id)
        .ok_or(CoreReloError::InvalidTypeId(relo.type_id))?;

    // Get the access string
    let access_str = btf.strings().get(relo.access_str_off).ok_or_else(|| {
        let off = relo.access_str_off;
        CoreReloError::InvalidAccessString(format!("offset {off}"))
    })?;

    let value = compute_relocation_value(btf_type, btf, registry, access_str, relo.kind)?;
    patch_instruction(instructions, relo.insn_off, value)
}

fn compute_relocation_value(
    btf_type: &BtfTypeInfo<'_>,
    btf: &Btf<'_>,
    registry: &TypeRegistry,
    access_str: &str,
    kind: CoreReloKind,
) -> Result<u64, CoreReloError> {
    // libbpf strips typedefs/modifiers from the root (`typedef struct {..} ev_t`).
    let root = skip_modifiers(btf, btf_type)?;
    let type_name = root.name().unwrap_or("");

    let field_not_found = |missing: (String, String)| CoreReloError::FieldNotFound {
        type_name: missing.0,
        field_name: missing.1,
    };

    match kind {
        CoreReloKind::FieldByteOffset => {
            let field = resolve_field(root, btf, registry, access_str)?.map_err(field_not_found)?;
            Ok(field.offset)
        }

        CoreReloKind::FieldByteSize => {
            let field = resolve_field(root, btf, registry, access_str)?.map_err(field_not_found)?;
            Ok(field.size)
        }

        CoreReloKind::FieldExists => {
            let exists = resolve_field(root, btf, registry, access_str)?.is_ok();
            Ok(exists as u64)
        }

        CoreReloKind::TypeExists => {
            let exists = registry.has_struct(type_name) || registry.has_enum(type_name);
            Ok(exists as u64)
        }

        CoreReloKind::TypeSize => {
            let size = registry
                .struct_size(type_name)
                .ok_or_else(|| CoreReloError::TypeNotFound(type_name.to_string()))?;
            Ok(size as u64)
        }

        CoreReloKind::EnumvalExists => {
            let variant_name = resolve_enum_variant(root, access_str)?;
            let exists = registry.enum_variant_exists(type_name, variant_name);
            Ok(exists as u64)
        }

        CoreReloKind::EnumvalValue => {
            let variant_name = resolve_enum_variant(root, access_str)?;
            let value =
                registry
                    .enum_value(type_name, variant_name)
                    .ok_or_else(|| CoreReloError::EnumVariantNotFound {
                        enum_name: type_name.to_string(),
                        variant_name: variant_name.to_string(),
                    })?;
            Ok(value as u64)
        }

        // the bitfield kinds need bit offsets and signedness the registry doesn't record
        CoreReloKind::FieldSigned
        | CoreReloKind::FieldLShiftU64
        | CoreReloKind::FieldRShiftU64
        | CoreReloKind::TypeIdLocal
        | CoreReloKind::TypeIdTarget
        | CoreReloKind::TypeMatches => Err(CoreReloError::UnsupportedRelo(kind)),
    }
}

/// A field resolved against the host layout.
struct HostField {
    /// Byte offset from the root pointer.
    offset: u64,
    /// Byte size of the accessed field/element.
    size: u64,
}

/// `(type name, field name)` of the first hop the host registry doesn't know.
type MissingField = (String, String);

/// Resolve a field access string against the host layout.
///
/// Access strings are either a plain field name (`"pid"`) or clang's index path
/// (`"0:1:2"`): the first index is an array index into the root (`&p[3].f`), and each
/// following index is a member index (struct/union) or element index (array).
/// Host offsets are summed level by level, looking each struct up by its local name.
///
/// The outer `Result` is a malformed relocation; the inner one a field the host lacks.
fn resolve_field(
    root: &BtfTypeInfo<'_>,
    btf: &Btf<'_>,
    registry: &TypeRegistry,
    access_str: &str,
) -> Result<Result<HostField, MissingField>, CoreReloError> {
    let invalid = || CoreReloError::InvalidAccessString(access_str.to_string());

    if access_str.is_empty() {
        return Err(invalid());
    }

    // Plain field name on the root struct.
    if !access_str.bytes().all(|c| c.is_ascii_digit() || c == b':') {
        let owner = root.name().unwrap_or("");
        return Ok(match (registry.field_offset(owner, access_str), registry.field_size(owner, access_str)) {
            (Some(offset), Some(size)) => Ok(HostField {
                offset: offset as u64,
                size: size as u64,
            }),
            _ => Err((owner.to_string(), access_str.to_string())),
        });
    }

    let mut indices = access_str.split(':').map(|s| s.parse::<u64>().map_err(|_| invalid()));
    let first = indices.next().ok_or_else(invalid)??;

    let mut offset = 0;
    if first != 0 {
        match host_size(root, btf, registry)? {
            Some(size) => offset += first * size,
            None => return Ok(Err((root.name().unwrap_or("").to_string(), String::new()))),
        }
    }

    let mut cur = root;
    let mut size = None;
    for idx in indices {
        let idx = idx?;
        match cur {
            BtfTypeInfo::Struct { name, members, .. } | BtfTypeInfo::Union { name, members, .. } => {
                let member = members.get(idx as usize).ok_or_else(invalid)?;
                let (Some(field_off), Some(field_size)) =
                    (registry.field_offset(name, member.name), registry.field_size(name, member.name))
                else {
                    return Ok(Err((name.to_string(), member.name.to_string())));
                };
                offset += field_off as u64;
                size = Some(field_size as u64);
                cur = resolve_id(btf, member.type_id)?;
            }
            BtfTypeInfo::Array { elem_type, .. } => {
                let elem = resolve_id(btf, *elem_type)?;
                let Some(elem_size) = host_size(elem, btf, registry)? else {
                    return Ok(Err((elem.name().unwrap_or("").to_string(), String::new())));
                };
                offset += idx * elem_size;
                size = Some(elem_size);
                cur = elem;
            }
            _ => return Err(invalid()),
        }
    }

    let size = size.ok_or_else(invalid)?;
    Ok(Ok(HostField { offset, size }))
}

/// Host byte size of a type: registered structs use the registry, everything else
/// (ints, enums, pointers, arrays of those) keeps its local BTF size.
fn host_size(ty: &BtfTypeInfo<'_>, btf: &Btf<'_>, registry: &TypeRegistry) -> Result<Option<u64>, CoreReloError> {
    Ok(match ty {
        BtfTypeInfo::Struct { name, .. } | BtfTypeInfo::Union { name, .. } => registry.struct_size(name).map(u64::from),
        BtfTypeInfo::Ptr { .. } => Some(8),
        BtfTypeInfo::Array { elem_type, nelems, .. } => {
            host_size(resolve_id(btf, *elem_type)?, btf, registry)?.map(|s| s * u64::from(*nelems))
        }
        _ => ty.size().map(u64::from),
    })
}

/// Look up a type ID and strip typedefs/modifiers.
fn resolve_id<'a, 'b>(btf: &'b Btf<'a>, id: u32) -> Result<&'b BtfTypeInfo<'a>, CoreReloError> {
    let ty = btf.type_by_id(id).ok_or(CoreReloError::InvalidTypeId(id))?;
    skip_modifiers(btf, ty)
}

/// Name of the enum variant a relocation refers to. clang emits the variant's index
/// in the local enum; a plain name is accepted as well.
fn resolve_enum_variant<'a>(root: &BtfTypeInfo<'a>, access_str: &'a str) -> Result<&'a str, CoreReloError> {
    let Ok(idx) = access_str.parse::<usize>() else {
        return Ok(access_str);
    };
    let name = match root {
        BtfTypeInfo::Enum { variants, .. } => variants.get(idx).map(|v| v.name),
        BtfTypeInfo::Enum64 { variants, .. } => variants.get(idx).map(|v| v.name),
        _ => None,
    };
    name.ok_or_else(|| CoreReloError::InvalidAccessString(access_str.to_string()))
}

/// Skip typedef/const/volatile/restrict/type-tag to the underlying type.
fn skip_modifiers<'a, 'b>(btf: &'b Btf<'a>, mut ty: &'b BtfTypeInfo<'a>) -> Result<&'b BtfTypeInfo<'a>, CoreReloError> {
    loop {
        let next = match ty {
            BtfTypeInfo::Typedef { type_id, .. }
            | BtfTypeInfo::Const { type_id }
            | BtfTypeInfo::Volatile { type_id }
            | BtfTypeInfo::Restrict { type_id }
            | BtfTypeInfo::TypeTag { type_id, .. } => *type_id,
            _ => return Ok(ty),
        };
        ty = btf.type_by_id(next).ok_or(CoreReloError::InvalidTypeId(next))?;
    }
}

/// Patch the relocated value into an instruction.
///
/// Memory instructions (LDX/ST/STX in any mode, incl. MEMSX and atomics) get the value
/// in `off`; LD_IMM64 gets all 64 bits across both slots; everything else gets `imm`.
fn patch_instruction(instructions: &mut [u64], insn_off: u32, value: u64) -> Result<(), CoreReloError> {
    const BPF_LD_IMM64: u8 = 0x18;
    const IMM_MASK: u64 = 0xFFFF_FFFF_0000_0000;

    let insn_idx = (insn_off / 8) as usize;
    let instr = instructions
        .get_mut(insn_idx)
        .ok_or(CoreReloError::InstructionOutOfBounds(insn_off))?;

    let opcode = *instr as u8;
    match opcode & 0x07 {
        // BPF_LDX, BPF_ST, BPF_STX
        0x01..=0x03 => {
            let off = value as i16 as u16;
            *instr = (*instr & !0xFFFF_0000) | ((off as u64) << 16);
        }
        _ if opcode == BPF_LD_IMM64 => {
            *instr = (*instr & !IMM_MASK) | (value << 32);
            let hi = instructions
                .get_mut(insn_idx + 1)
                .ok_or(CoreReloError::InstructionOutOfBounds(insn_off + 8))?;
            *hi = (*hi & !IMM_MASK) | (value & IMM_MASK);
        }
        _ => *instr = (*instr & !IMM_MASK) | ((value as u32 as u64) << 32),
    }

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
}
