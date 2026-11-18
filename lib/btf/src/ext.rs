//! `.BTF.ext` parsing: the CO-RE relocation records clang emits next to a program's BTF.

use crate::parse::{check_header, section, word, BtfError};
use crate::strings::BtfStrings;

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
    /// The kind with discriminant `val`, or `None` if BTF defines no such kind.
    pub fn from_u32(val: u32) -> Option<Self> {
        KINDS.get(usize::try_from(val).ok()?).copied()
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

/// Every kind, indexed by its discriminant.
const KINDS: [CoreReloKind; 13] = {
    use CoreReloKind::*;
    [
        FieldByteOffset,
        FieldByteSize,
        FieldExists,
        FieldSigned,
        FieldLShiftU64,
        FieldRShiftU64,
        TypeIdLocal,
        TypeIdTarget,
        TypeExists,
        TypeSize,
        EnumvalExists,
        EnumvalValue,
        TypeMatches,
    ]
};

const _: () = {
    let mut i = 0;
    while i < KINDS.len() {
        assert!(KINDS[i] as usize == i);
        i += 1;
    }
};

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

    /// Parse from bytes. Fails on a relocation kind this crate doesn't know, since skipping it would leave the
    /// instruction with its compile-time value.
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        if data.len() < Self::SIZE {
            return Err(BtfError::TooShort);
        }
        let raw_kind = word(data, 3);
        let kind = CoreReloKind::from_u32(raw_kind).ok_or(BtfError::UnknownReloKind(raw_kind))?;

        Ok(Self {
            insn_off: word(data, 0),
            type_id: word(data, 1),
            access_str_off: word(data, 2),
            kind,
        })
    }
}

/// Minimum size of a `.BTF.ext` header: magic, version, flags, hdr_len, and the (unused) func_info/line_info
/// offset/length fields.
const BTF_EXT_HDR_MIN_SIZE: usize = 24;
/// Header size once the (optional, added later) CO-RE relocation fields are present.
const BTF_EXT_HDR_SIZE_WITH_CORE: usize = 32;

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
    /// CO-RE relocations grouped by section.
    pub core_relos: Vec<SectionCoreRelos<'a>>,
}

impl<'a> BtfExt<'a> {
    /// Parse BTF.ext from raw bytes.
    ///
    /// Requires the BTF strings table for resolving section names.
    pub fn parse(data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Self, BtfError> {
        let hdr_len = check_header(data, BTF_EXT_HDR_MIN_SIZE)?;

        // older headers end before the CO-RE relocation fields
        if hdr_len < BTF_EXT_HDR_SIZE_WITH_CORE || data.len() < BTF_EXT_HDR_SIZE_WITH_CORE {
            return Ok(Self { core_relos: Vec::new() });
        }
        let relo_data = section(data, hdr_len, word(data, 6), word(data, 7))?;
        let core_relos = Self::parse_core_relos(relo_data, strings)?;

        Ok(Self { core_relos })
    }

    fn parse_core_relos(relo_data: &[u8], strings: &BtfStrings<'a>) -> Result<Vec<SectionCoreRelos<'a>>, BtfError> {
        if relo_data.len() < 4 {
            return Ok(Vec::new());
        }

        let rec_size = word(relo_data, 0);
        if (rec_size as usize) < CoreRelo::SIZE {
            return Err(BtfError::BadRecordSize(rec_size));
        }
        let rec_size = rec_size as usize;

        let mut offset = 4;
        let mut sections = Vec::new();

        while offset + 8 <= relo_data.len() {
            // section header: sec_name_off, num_info
            let sec_name_off = word(&relo_data[offset..], 0);
            let num_info = word(&relo_data[offset..], 1);
            offset += 8;

            let section_name = strings.get_or_empty(sec_name_off);
            let records = (num_info as usize)
                .checked_mul(rec_size)
                .filter(|&len| len <= relo_data.len() - offset)
                .ok_or(BtfError::SectionOverflow)?;
            let relos = relo_data[offset..][..records]
                .chunks_exact(rec_size)
                .map(CoreRelo::parse)
                .collect::<Result<_, _>>()?;
            offset += records;

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
