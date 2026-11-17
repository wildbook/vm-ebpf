//! BTF parsing from raw bytes.

use crate::raw::{BtfKind, BTF_MAGIC, BTF_VERSION};
use crate::strings::BtfStrings;
use crate::types::*;

/// Error type for BTF parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfError {
    /// Data too short for header.
    TooShort,
    /// Invalid magic number.
    BadMagic(u16),
    /// Unsupported version.
    BadVersion(u8),
    /// Section extends beyond data.
    SectionOverflow,
    /// Invalid type data.
    InvalidType(u32),
    /// Unknown type kind.
    UnknownKind(u8),
    /// Unknown CO-RE relocation kind in `.BTF.ext`.
    UnknownReloKind(u32),
}

impl core::fmt::Display for BtfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "BTF data too short"),
            Self::BadMagic(m) => write!(f, "invalid BTF magic: {m:#06x}"),
            Self::BadVersion(v) => write!(f, "unsupported BTF version: {v}"),
            Self::SectionOverflow => write!(f, "BTF section extends beyond data"),
            Self::InvalidType(id) => write!(f, "invalid BTF type at id {id}"),
            Self::UnknownKind(k) => write!(f, "unknown BTF kind: {k}"),
            Self::UnknownReloKind(k) => write!(f, "unknown CO-RE relocation kind: {k}"),
        }
    }
}

impl std::error::Error for BtfError {}

/// Read a little-endian `u32` at word index `i` (byte offset `i * 4`).
///
/// # Panics
///
/// Panics if the word does not fit in `b`; callers only use it on slices already bounds-checked against the record size
/// they are reading.
pub fn word(b: &[u8], i: usize) -> u32 {
    let o = i * 4;
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Parsed BTF data.
#[derive(Debug, Clone)]
pub struct Btf<'a> {
    /// String table.
    strings: BtfStrings<'a>,
    /// Parsed types (index 0 is void, types start at index 1).
    types: Vec<BtfTypeInfo<'a>>,
}

impl<'a> Btf<'a> {
    /// Parse BTF from raw section bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, BtfError> {
        if data.len() < 24 {
            return Err(BtfError::TooShort);
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        let version = data[2];
        if magic != BTF_MAGIC {
            return Err(BtfError::BadMagic(magic));
        }
        if version != BTF_VERSION {
            return Err(BtfError::BadVersion(version));
        }
        let hdr_len = word(data, 1) as usize;
        let type_off = word(data, 2) as usize;
        let type_len = word(data, 3) as usize;
        let str_off = word(data, 4) as usize;
        let str_len = word(data, 5) as usize;

        let section = |off: usize, len: usize| data.get(hdr_len + off..)?.get(..len);
        let type_data = section(type_off, type_len).ok_or(BtfError::SectionOverflow)?;
        let str_data = section(str_off, str_len).ok_or(BtfError::SectionOverflow)?;
        let strings = BtfStrings::new(str_data);

        let types = Self::parse_types(type_data, &strings)?;

        Ok(Self { strings, types })
    }

    fn parse_types(type_data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Vec<BtfTypeInfo<'a>>, BtfError> {
        // Type ID 0 is void
        let mut types = vec![BtfTypeInfo::Void];
        let mut offset = 0;
        let mut type_id = 1u32;

        while offset < type_data.len() {
            let remaining = &type_data[offset..];
            if remaining.len() < 12 {
                return Err(BtfError::InvalidType(type_id));
            }
            let name_off = word(remaining, 0);
            let info = word(remaining, 1);
            let size_or_type = word(remaining, 2);

            let kind = BtfKind::from_info(info).ok_or(BtfError::UnknownKind(((info >> 24) & 0x1F) as u8))?;
            let vlen = (info & 0xFFFF) as u16;
            let kind_flag = (info >> 31) != 0;
            let extra_size = kind.extra_size(vlen);
            if 12 + extra_size > remaining.len() {
                return Err(BtfError::InvalidType(type_id));
            }
            let extra = &remaining[12..][..extra_size];

            let name = strings.get_or_empty(name_off);

            let type_info = match kind {
                // type 0 is the implicit void; libbpf rejects `BTF_KIND_UNKN` inside the type section too
                BtfKind::Void => return Err(BtfError::InvalidType(type_id)),

                BtfKind::Int => {
                    let int_info = word(extra, 0);
                    BtfTypeInfo::Int {
                        name,
                        size: size_or_type,
                        encoding: ((int_info & 0x0F000000) >> 24) as u8,
                        offset: ((int_info & 0x00FF0000) >> 16) as u8,
                        bits: (int_info & 0x000000FF) as u8,
                    }
                }

                BtfKind::Ptr => BtfTypeInfo::Ptr {
                    pointee_type: size_or_type,
                },

                BtfKind::Array => BtfTypeInfo::Array {
                    elem_type: word(extra, 0),
                    index_type: word(extra, 1),
                    nelems: word(extra, 2),
                },

                BtfKind::Struct => BtfTypeInfo::Struct {
                    name,
                    size: size_or_type,
                    members: Self::parse_members(extra, vlen, kind_flag, strings),
                },

                BtfKind::Union => BtfTypeInfo::Union {
                    name,
                    size: size_or_type,
                    members: Self::parse_members(extra, vlen, kind_flag, strings),
                },

                BtfKind::Enum => BtfTypeInfo::Enum {
                    name,
                    size: size_or_type,
                    is_signed: kind_flag,
                    is_64: false,
                    variants: extra
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| EnumValue {
                            name: strings.get_or_empty(word(c, 0)),
                            value: i64::from(word(c, 1) as i32),
                        })
                        .collect(),
                },

                BtfKind::Fwd => BtfTypeInfo::Fwd {
                    name,
                    is_union: kind_flag,
                },

                BtfKind::Typedef => BtfTypeInfo::Typedef {
                    name,
                    type_id: size_or_type,
                },

                BtfKind::Volatile => BtfTypeInfo::Volatile { type_id: size_or_type },

                BtfKind::Const => BtfTypeInfo::Const { type_id: size_or_type },

                BtfKind::Restrict => BtfTypeInfo::Restrict { type_id: size_or_type },

                BtfKind::Func => BtfTypeInfo::Func {
                    name,
                    proto_type: size_or_type,
                    linkage: vlen,
                },

                BtfKind::FuncProto => BtfTypeInfo::FuncProto {
                    return_type: size_or_type,
                    params: extra
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| Param {
                            name: strings.get_or_empty(word(c, 0)),
                            type_id: word(c, 1),
                        })
                        .collect(),
                },

                BtfKind::Var => BtfTypeInfo::Var {
                    name,
                    type_id: size_or_type,
                    linkage: word(extra, 0),
                },

                BtfKind::DataSec => BtfTypeInfo::DataSec {
                    name,
                    size: size_or_type,
                    vars: extra
                        .as_chunks::<12>()
                        .0
                        .iter()
                        .map(|c| VarSecInfo {
                            type_id: word(c, 0),
                            offset: word(c, 1),
                            size: word(c, 2),
                        })
                        .collect(),
                },

                BtfKind::Float => BtfTypeInfo::Float {
                    name,
                    size: size_or_type,
                },

                BtfKind::DeclTag => BtfTypeInfo::DeclTag {
                    name,
                    type_id: size_or_type,
                    component_idx: word(extra, 0) as i32,
                },

                BtfKind::TypeTag => BtfTypeInfo::TypeTag {
                    name,
                    type_id: size_or_type,
                },

                BtfKind::Enum64 => BtfTypeInfo::Enum {
                    name,
                    size: size_or_type,
                    is_signed: kind_flag,
                    is_64: true,
                    variants: extra
                        .as_chunks::<12>()
                        .0
                        .iter()
                        .map(|c| EnumValue {
                            name: strings.get_or_empty(word(c, 0)),
                            value: ((word(c, 2) as u64) << 32 | word(c, 1) as u64) as i64,
                        })
                        .collect(),
                },
            };

            types.push(type_info);
            offset += 12 + extra_size;
            type_id += 1;
        }

        Ok(types)
    }

    fn parse_members(data: &'a [u8], count: u16, kind_flag: bool, strings: &BtfStrings<'a>) -> Vec<Member<'a>> {
        data.as_chunks::<12>()
            .0
            .iter()
            .take(count as usize)
            .map(|c| {
                let raw_offset = word(c, 2);
                Member {
                    name: strings.get_or_empty(word(c, 0)),
                    type_id: word(c, 1),
                    bit_offset: if kind_flag { raw_offset & 0xFFFFFF } else { raw_offset },
                    bitfield_size: if kind_flag { raw_offset >> 24 } else { 0 },
                }
            })
            .collect()
    }

    /// Get the string table.
    pub fn strings(&self) -> &BtfStrings<'a> {
        &self.strings
    }

    /// Get a type by ID.
    ///
    /// Type ID 0 is void. IDs start at 1.
    pub fn type_by_id(&self, id: u32) -> Option<&BtfTypeInfo<'a>> {
        self.types.get(id as usize)
    }

    /// Iterate over all types.
    pub fn types(&self) -> impl Iterator<Item = (u32, &BtfTypeInfo<'a>)> {
        self.types.iter().enumerate().map(|(i, t)| (i as u32, t))
    }

    /// Resolve a type through modifiers (const, volatile, restrict, typedef).
    ///
    /// Returns the underlying "real" type ID and info, or `None` for a missing type or a chain of over 32 modifiers,
    /// which a cycle makes endless.
    pub fn resolve_type(&self, mut type_id: u32) -> Option<(u32, &BtfTypeInfo<'a>)> {
        for _ in 0..=MAX_RESOLVE_DEPTH {
            let ty = self.type_by_id(type_id)?;
            match ty {
                BtfTypeInfo::Typedef { type_id: inner, .. }
                | BtfTypeInfo::Volatile { type_id: inner }
                | BtfTypeInfo::Const { type_id: inner }
                | BtfTypeInfo::Restrict { type_id: inner }
                | BtfTypeInfo::TypeTag { type_id: inner, .. } => {
                    type_id = *inner;
                }
                _ => return Some((type_id, ty)),
            }
        }
        None
    }

    /// Byte size of a type, resolving through typedefs/modifiers/vars and, like libbpf's `btf__resolve_size`,
    /// multiplying an array's element size by its length.
    ///
    /// `None` for a missing type, a size that overflows `u64`, or a chain of over 32 modifiers and arrays.
    pub fn resolve_size(&self, mut id: u32) -> Option<u64> {
        let mut count = 1u64;
        for _ in 0..=MAX_RESOLVE_DEPTH {
            let ty = self.type_by_id(id)?;
            let size = match ty {
                BtfTypeInfo::Typedef { type_id, .. }
                | BtfTypeInfo::Volatile { type_id }
                | BtfTypeInfo::Const { type_id }
                | BtfTypeInfo::Restrict { type_id }
                | BtfTypeInfo::TypeTag { type_id, .. }
                | BtfTypeInfo::Var { type_id, .. } => {
                    id = *type_id;
                    continue;
                }
                BtfTypeInfo::Array { elem_type, nelems, .. } => {
                    count = count.checked_mul(u64::from(*nelems))?;
                    id = *elem_type;
                    continue;
                }
                BtfTypeInfo::Ptr { .. } => 8,
                _ => u64::from(ty.size()?),
            };
            return size.checked_mul(count);
        }
        None
    }
}

/// Longest chain of modifiers, typedefs and arrays that resolution follows, as in libbpf.
pub const MAX_RESOLVE_DEPTH: usize = 32;
