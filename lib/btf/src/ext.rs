//! `.BTF.ext` parsing: the CO-RE relocation records clang emits next to a program's BTF.

use crate::parse::{check_header, section, word, BtfError};
use crate::strings::BtfStrings;

/// Minimum size of a `.BTF.ext` header: magic, version, flags, hdr_len, and the func_info and line_info offsets and
/// lengths, which this crate doesn't read.
const BTF_EXT_HDR_MIN_SIZE: usize = 24;
/// Size of a header that also has the offset and length of the CO-RE relocations. Older headers end before them.
const BTF_EXT_HDR_SIZE_WITH_CORE: usize = 32;

/// The CO-RE relocations of a `.BTF.ext` section.
#[derive(Debug, Clone)]
pub struct BtfExt<'a> {
    sections: Vec<SectionCoreRelos<'a>>,
}

/// The CO-RE relocations of one code section.
#[derive(Debug, Clone)]
struct SectionCoreRelos<'a> {
    section_name: &'a str,
    relos: Vec<CoreRelo>,
}

impl<'a> BtfExt<'a> {
    /// Parses a `.BTF.ext` section. `strings` is the string table of the `.BTF` section next to it, which holds the
    /// section names.
    pub fn parse(data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Self, BtfError> {
        let hdr_len = check_header(data, BTF_EXT_HDR_MIN_SIZE)?;

        if hdr_len < BTF_EXT_HDR_SIZE_WITH_CORE || data.len() < BTF_EXT_HDR_SIZE_WITH_CORE {
            return Ok(Self { sections: Vec::new() });
        }
        let relo_data = section(data, hdr_len, word(data, 6), word(data, 7))?;
        let sections = Self::parse_core_relos(relo_data, strings)?;

        Ok(Self { sections })
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

    /// The relocations of the code section `section_name`, or `None` if it has none.
    pub fn relos_for_section(&self, section_name: &str) -> Option<&[CoreRelo]> {
        self.sections
            .iter()
            .find(|s| s.section_name == section_name)
            .map(|s| s.relos.as_slice())
    }
}

/// One CO-RE relocation.
#[derive(Debug, Clone)]
pub struct CoreRelo {
    /// Byte offset of the instruction in its section.
    pub insn_off: u32,
    /// The root type of the access, an ID in the program's BTF.
    pub type_id: u32,
    /// Offset of the access string, such as `0:1:2`, in the string table of the program's BTF.
    pub access_str_off: u32,
    pub kind: CoreReloKind,
}

impl CoreRelo {
    /// Size of the fields this crate reads from a record.
    const SIZE: usize = 16;

    /// Parses a record of at least [`SIZE`](Self::SIZE) bytes. Fails on a relocation kind this crate doesn't know,
    /// since skipping it would leave the instruction with its compile-time value.
    fn parse(data: &[u8]) -> Result<Self, BtfError> {
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

/// What a CO-RE relocation patches into its instruction (`enum bpf_core_relo_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum CoreReloKind {
    FieldByteOffset = 0,
    FieldByteSize = 1,
    /// Whether the field exists, 0 or 1.
    FieldExists = 2,
    /// Whether the field is signed, 0 or 1.
    FieldSigned = 3,
    /// The left shift that moves a bitfield, loaded into a `u64`, to the top bits.
    FieldLShiftU64 = 4,
    /// The right shift that then moves it down to bit 0.
    FieldRShiftU64 = 5,
    /// The type's ID in the program's BTF.
    TypeIdLocal = 6,
    /// The type's ID in the target BTF.
    TypeIdTarget = 7,
    /// Whether the type exists, 0 or 1.
    TypeExists = 8,
    TypeSize = 9,
    /// Whether the enumerator exists, 0 or 1.
    EnumvalExists = 10,
    EnumvalValue = 11,
    /// Whether the target has a type that matches the local one member by member, 0 or 1.
    TypeMatches = 12,
}

impl CoreReloKind {
    /// The kind with discriminant `val`, or `None` if BTF defines no such kind.
    pub fn from_u32(val: u32) -> Option<Self> {
        KINDS.get(usize::try_from(val).ok()?).copied()
    }

    /// Whether the relocation is about a struct or union field.
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

    /// Whether the relocation is about a type as a whole.
    pub fn is_type_relo(self) -> bool {
        matches!(self, Self::TypeIdLocal | Self::TypeIdTarget | Self::TypeExists | Self::TypeSize | Self::TypeMatches)
    }

    /// Whether the relocation is about an enumerator.
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
