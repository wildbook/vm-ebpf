//! `.BTF` parsing.

use crate::raw::{
    BtfKind, TypeHeader, BTF_ENUM64_SIZE, BTF_ENUM_SIZE, BTF_HEADER_LEN, BTF_MAGIC, BTF_MEMBER_SIZE, BTF_PARAM_SIZE,
    BTF_VAR_SECINFO_SIZE, BTF_VERSION, TYPE_HEADER_LEN,
};
use crate::strings::BtfStrings;
use crate::types::{BtfType, EnumValue, Member, Param, VarSecInfo};

/// Why `.BTF` or `.BTF.ext` data failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfError {
    /// The data is shorter than its header.
    TooShort,
    BadMagic(u16),
    BadVersion(u8),
    /// A section named by the header extends past the data.
    SectionOverflow,
    /// The record of the type with this ID is malformed.
    InvalidType(u32),
    UnknownKind(u8),
    /// Unknown CO-RE relocation kind in `.BTF.ext`.
    UnknownReloKind(u32),
    /// `.BTF.ext` CO-RE relocation records are smaller than the fields this crate reads.
    BadRecordSize(u32),
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
            Self::BadRecordSize(n) => write!(f, "CO-RE relocation record size {n} is too small"),
        }
    }
}

impl std::error::Error for BtfError {}

/// Read a little-endian `u32` at word index `i` (byte offset `i * 4`). Panics if the word does not fit in `b`; callers
/// use it on slices that they checked against the size of the record they read.
pub fn word(b: &[u8], i: usize) -> u32 {
    let o = i * 4;
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Check the magic and version that `.BTF` and `.BTF.ext` headers share, and return the header length that section
/// offsets count from. `min_len` is the shortest header the caller reads, at least 8 bytes.
pub fn check_header(data: &[u8], min_len: usize) -> Result<usize, BtfError> {
    if data.len() < min_len {
        return Err(BtfError::TooShort);
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC {
        return Err(BtfError::BadMagic(magic));
    }
    let version = data[2];
    if version != BTF_VERSION {
        return Err(BtfError::BadVersion(version));
    }
    Ok(word(data, 1) as usize)
}

/// The `len` bytes at `off` past a header of `hdr_len` bytes.
pub fn section(data: &[u8], hdr_len: usize, off: u32, len: u32) -> Result<&[u8], BtfError> {
    let start = data.get(hdr_len + off as usize..);
    start
        .and_then(|s| s.get(..len as usize))
        .ok_or(BtfError::SectionOverflow)
}

/// A parsed `.BTF` section: its types and its string table.
#[derive(Debug, Clone)]
pub struct Btf<'a> {
    strings: BtfStrings<'a>,
    /// Indexed by type ID; index 0 is void.
    types: Vec<BtfType<'a>>,
}

impl<'a> Btf<'a> {
    /// Parses the bytes of a `.BTF` section.
    pub fn parse(data: &'a [u8]) -> Result<Self, BtfError> {
        let hdr_len = check_header(data, BTF_HEADER_LEN)?;
        let type_data = section(data, hdr_len, word(data, 2), word(data, 3))?;
        let str_data = section(data, hdr_len, word(data, 4), word(data, 5))?;
        let strings = BtfStrings::new(str_data);

        let types = Self::parse_types(type_data, &strings)?;

        Ok(Self { strings, types })
    }

    fn parse_types(type_data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Vec<BtfType<'a>>, BtfError> {
        let mut types = vec![BtfType::Void];
        let mut offset = 0;
        let mut type_id = 1u32;

        while offset < type_data.len() {
            let remaining = &type_data[offset..];
            if remaining.len() < TYPE_HEADER_LEN {
                return Err(BtfError::InvalidType(type_id));
            }
            let header = TypeHeader::decode(remaining)?;
            let record_len = TYPE_HEADER_LEN + header.kind.extra_size(header.vlen);
            let extra = remaining
                .get(TYPE_HEADER_LEN..record_len)
                .ok_or(BtfError::InvalidType(type_id))?;
            types.push(parse_type(&header, extra, strings).ok_or(BtfError::InvalidType(type_id))?);
            offset += record_len;
            type_id += 1;
        }

        Ok(types)
    }

    pub fn strings(&self) -> &BtfStrings<'a> {
        &self.strings
    }

    /// The type with this ID. ID 0 is void, and the types of the section have IDs from 1 in section order.
    pub fn type_by_id(&self, id: u32) -> Option<&BtfType<'a>> {
        self.types.get(id as usize)
    }

    /// Every type with its ID, starting with void at ID 0.
    pub fn types(&self) -> impl Iterator<Item = (u32, &BtfType<'a>)> {
        self.types.iter().enumerate().map(|(i, t)| (i as u32, t))
    }

    /// The struct named `name`: its size and each member's name and offset, in bytes and declaration order. `None` if
    /// no struct has that name or one of its members is a bitfield.
    pub fn struct_layout(&self, name: &str) -> Option<(usize, Vec<(&'a str, usize)>)> {
        let (size, members) = self.types.iter().find_map(|ty| match ty {
            BtfType::Struct { name: n, size, members } if *n == name => Some((*size as usize, members)),
            _ => None,
        })?;
        let byte_offset = |m: &Member<'a>| (m.bitfield_size == 0 && m.bit_offset % 8 == 0).then_some(m.bit_offset / 8);
        let offsets = members.iter().map(|m| Some((m.name, byte_offset(m)? as usize)));
        Some((size, offsets.collect::<Option<_>>()?))
    }

    /// Resolve a type through modifiers (const, volatile, restrict, typedef).
    ///
    /// Returns the underlying "real" type ID and info, or `None` for a missing type or a chain of over 32 modifiers,
    /// which a cycle makes endless.
    pub fn resolve_type(&self, mut type_id: u32) -> Option<(u32, &BtfType<'a>)> {
        for _ in 0..=MAX_RESOLVE_DEPTH {
            let ty = self.type_by_id(type_id)?;
            match ty {
                BtfType::Typedef { type_id: inner, .. }
                | BtfType::Volatile { type_id: inner }
                | BtfType::Const { type_id: inner }
                | BtfType::Restrict { type_id: inner }
                | BtfType::TypeTag { type_id: inner, .. } => {
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
                BtfType::Typedef { type_id, .. }
                | BtfType::Volatile { type_id }
                | BtfType::Const { type_id }
                | BtfType::Restrict { type_id }
                | BtfType::TypeTag { type_id, .. }
                | BtfType::Var { type_id, .. } => {
                    id = *type_id;
                    continue;
                }
                BtfType::Array { elem_type, nelems, .. } => {
                    count = count.checked_mul(u64::from(*nelems))?;
                    id = *elem_type;
                    continue;
                }
                BtfType::Ptr { .. } => 8,
                _ => u64::from(ty.size()?),
            };
            return size.checked_mul(count);
        }
        None
    }
}

/// Build one type from its header and the `extra` bytes that follow it. `None` for `BTF_KIND_UNKN`, which only the
/// implicit type 0 may be; libbpf rejects it inside the type section too.
fn parse_type<'a>(header: &TypeHeader, extra: &'a [u8], strings: &BtfStrings<'a>) -> Option<BtfType<'a>> {
    let name = strings.get_or_empty(header.name_off);
    let size_or_type = header.size_or_type;
    let kind_flag = header.kind_flag;
    let members = || {
        records(extra, |c: &[u8; BTF_MEMBER_SIZE]| {
            let raw_offset = word(c, 2);
            Member {
                name: strings.get_or_empty(word(c, 0)),
                type_id: word(c, 1),
                bit_offset: if kind_flag { raw_offset & 0xFFFFFF } else { raw_offset },
                bitfield_size: if kind_flag { raw_offset >> 24 } else { 0 },
            }
        })
    };

    Some(match header.kind {
        BtfKind::Void => return None,
        BtfKind::Int => {
            let int_info = word(extra, 0);
            BtfType::Int {
                name,
                size: size_or_type,
                encoding: ((int_info & 0x0F000000) >> 24) as u8,
                offset: ((int_info & 0x00FF0000) >> 16) as u8,
                bits: (int_info & 0x000000FF) as u8,
            }
        }
        BtfKind::Ptr => BtfType::Ptr {
            pointee_type: size_or_type,
        },
        BtfKind::Array => BtfType::Array {
            elem_type: word(extra, 0),
            index_type: word(extra, 1),
            nelems: word(extra, 2),
        },
        BtfKind::Struct => BtfType::Struct {
            name,
            size: size_or_type,
            members: members(),
        },
        BtfKind::Union => BtfType::Union {
            name,
            size: size_or_type,
            members: members(),
        },
        BtfKind::Enum => BtfType::Enum {
            name,
            size: size_or_type,
            is_signed: kind_flag,
            is_64: false,
            variants: records(extra, |c: &[u8; BTF_ENUM_SIZE]| EnumValue {
                name: strings.get_or_empty(word(c, 0)),
                value: i64::from(word(c, 1) as i32),
            }),
        },
        BtfKind::Fwd => BtfType::Fwd {
            name,
            is_union: kind_flag,
        },
        BtfKind::Typedef => BtfType::Typedef {
            name,
            type_id: size_or_type,
        },
        BtfKind::Volatile => BtfType::Volatile { type_id: size_or_type },
        BtfKind::Const => BtfType::Const { type_id: size_or_type },
        BtfKind::Restrict => BtfType::Restrict { type_id: size_or_type },
        BtfKind::Func => BtfType::Func {
            name,
            proto_type: size_or_type,
            linkage: header.vlen,
        },
        BtfKind::FuncProto => BtfType::FuncProto {
            return_type: size_or_type,
            params: records(extra, |c: &[u8; BTF_PARAM_SIZE]| Param {
                name: strings.get_or_empty(word(c, 0)),
                type_id: word(c, 1),
            }),
        },
        BtfKind::Var => BtfType::Var {
            name,
            type_id: size_or_type,
            linkage: word(extra, 0),
        },
        BtfKind::DataSec => BtfType::DataSec {
            name,
            size: size_or_type,
            vars: records(extra, |c: &[u8; BTF_VAR_SECINFO_SIZE]| VarSecInfo {
                type_id: word(c, 0),
                offset: word(c, 1),
                size: word(c, 2),
            }),
        },
        BtfKind::Float => BtfType::Float {
            name,
            size: size_or_type,
        },
        BtfKind::DeclTag => BtfType::DeclTag {
            name,
            type_id: size_or_type,
            component_idx: word(extra, 0) as i32,
        },
        BtfKind::TypeTag => BtfType::TypeTag {
            name,
            type_id: size_or_type,
        },
        BtfKind::Enum64 => BtfType::Enum {
            name,
            size: size_or_type,
            is_signed: kind_flag,
            is_64: true,
            variants: records(extra, |c: &[u8; BTF_ENUM64_SIZE]| EnumValue {
                name: strings.get_or_empty(word(c, 0)),
                value: ((word(c, 2) as u64) << 32 | word(c, 1) as u64) as i64,
            }),
        },
    })
}

/// Map each whole `N`-byte record in `extra` through `f`.
fn records<const N: usize, T>(extra: &[u8], f: impl FnMut(&[u8; N]) -> T) -> Vec<T> {
    extra.as_chunks::<N>().0.iter().map(f).collect()
}

/// Longest chain of modifiers, typedefs and arrays that resolution follows, as in libbpf.
pub const MAX_RESOLVE_DEPTH: usize = 32;
