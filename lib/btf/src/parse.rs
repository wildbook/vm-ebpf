//! BTF parsing from raw bytes.

use crate::raw::*;
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
    /// Invalid string offset.
    InvalidString(u32),
}

impl core::fmt::Display for BtfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "BTF data too short"),
            Self::BadMagic(m) => write!(f, "invalid BTF magic: {:#06x}", m),
            Self::BadVersion(v) => write!(f, "unsupported BTF version: {}", v),
            Self::SectionOverflow => write!(f, "BTF section extends beyond data"),
            Self::InvalidType(id) => write!(f, "invalid BTF type at id {}", id),
            Self::UnknownKind(k) => write!(f, "unknown BTF kind: {}", k),
            Self::InvalidString(off) => write!(f, "invalid string offset: {}", off),
        }
    }
}

impl std::error::Error for BtfError {}

/// Parsed BTF data.
#[derive(Debug, Clone)]
pub struct Btf<'a> {
    /// The raw data.
    #[allow(dead_code)]
    data: &'a [u8],
    /// The header.
    header: BtfHeader,
    /// String table.
    strings: BtfStrings<'a>,
    /// Parsed types (index 0 is void, types start at index 1).
    types: Vec<BtfTypeInfo<'a>>,
}

impl<'a> Btf<'a> {
    /// Parse BTF from raw section bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, BtfError> {
        let header = BtfHeader::parse(data).ok_or(BtfError::TooShort)?;

        // Validate header
        if header.magic != BTF_MAGIC {
            return Err(BtfError::BadMagic(header.magic));
        }
        if header.version != BTF_VERSION {
            return Err(BtfError::BadVersion(header.version));
        }

        let hdr_len = header.hdr_len as usize;

        // Validate section bounds
        let type_start = hdr_len + header.type_off as usize;
        let type_end = type_start + header.type_len as usize;
        let str_start = hdr_len + header.str_off as usize;
        let str_end = str_start + header.str_len as usize;

        if type_end > data.len() || str_end > data.len() {
            return Err(BtfError::SectionOverflow);
        }

        let type_data = &data[type_start..type_end];
        let str_data = &data[str_start..str_end];
        let strings = BtfStrings::new(str_data);

        // Parse types
        let types = Self::parse_types(type_data, &strings)?;

        Ok(Self {
            data,
            header,
            strings,
            types,
        })
    }

    fn parse_types(type_data: &'a [u8], strings: &BtfStrings<'a>) -> Result<Vec<BtfTypeInfo<'a>>, BtfError> {
        // Type ID 0 is void
        let mut types = vec![BtfTypeInfo::Void];
        let mut offset = 0;
        let mut type_id = 1u32;

        while offset < type_data.len() {
            let remaining = &type_data[offset..];
            let btf_type = BtfType::parse(remaining).ok_or(BtfError::InvalidType(type_id))?;

            let kind = btf_type
                .kind()
                .ok_or(BtfError::UnknownKind(((btf_type.info >> 24) & 0x1F) as u8))?;
            let vlen = btf_type.vlen();
            let kind_flag = btf_type.kind_flag();
            let extra_size = kind.extra_size(vlen);

            let extra_start = offset + BtfType::SIZE;
            let extra_end = extra_start + extra_size;
            if extra_end > type_data.len() {
                return Err(BtfError::InvalidType(type_id));
            }
            let extra = &type_data[extra_start..extra_end];

            let name = strings.get_or_empty(btf_type.name_off);

            let type_info = match kind {
                BtfKind::Void => BtfTypeInfo::Void,

                BtfKind::Int => {
                    if extra.len() < 4 {
                        return Err(BtfError::InvalidType(type_id));
                    }
                    let int_info = u32::from_le_bytes([extra[0], extra[1], extra[2], extra[3]]);
                    BtfTypeInfo::Int {
                        name,
                        size: btf_type.size_or_type,
                        encoding: btf_int_encoding(int_info),
                        offset: btf_int_offset(int_info),
                        bits: btf_int_bits(int_info),
                    }
                }

                BtfKind::Ptr => BtfTypeInfo::Ptr {
                    pointee_type: btf_type.size_or_type,
                },

                BtfKind::Array => {
                    let arr = BtfArray::parse(extra).ok_or(BtfError::InvalidType(type_id))?;
                    BtfTypeInfo::Array {
                        elem_type: arr.elem_type,
                        index_type: arr.index_type,
                        nelems: arr.nelems,
                    }
                }

                BtfKind::Struct => {
                    let members = Self::parse_members(extra, vlen, kind_flag, strings)?;
                    BtfTypeInfo::Struct {
                        name,
                        size: btf_type.size_or_type,
                        members,
                    }
                }

                BtfKind::Union => {
                    let members = Self::parse_members(extra, vlen, kind_flag, strings)?;
                    BtfTypeInfo::Union {
                        name,
                        size: btf_type.size_or_type,
                        members,
                    }
                }

                BtfKind::Enum => {
                    let variants = Self::parse_enum_values(extra, vlen, strings)?;
                    BtfTypeInfo::Enum {
                        name,
                        size: btf_type.size_or_type,
                        is_signed: kind_flag,
                        variants,
                    }
                }

                BtfKind::Fwd => BtfTypeInfo::Fwd {
                    name,
                    is_union: kind_flag,
                },

                BtfKind::Typedef => BtfTypeInfo::Typedef {
                    name,
                    type_id: btf_type.size_or_type,
                },

                BtfKind::Volatile => BtfTypeInfo::Volatile {
                    type_id: btf_type.size_or_type,
                },

                BtfKind::Const => BtfTypeInfo::Const {
                    type_id: btf_type.size_or_type,
                },

                BtfKind::Restrict => BtfTypeInfo::Restrict {
                    type_id: btf_type.size_or_type,
                },

                BtfKind::Func => BtfTypeInfo::Func {
                    name,
                    proto_type: btf_type.size_or_type,
                    linkage: vlen,
                },

                BtfKind::FuncProto => {
                    let params = Self::parse_params(extra, vlen, strings)?;
                    BtfTypeInfo::FuncProto {
                        return_type: btf_type.size_or_type,
                        params,
                    }
                }

                BtfKind::Var => {
                    let var = BtfVar::parse(extra).ok_or(BtfError::InvalidType(type_id))?;
                    BtfTypeInfo::Var {
                        name,
                        type_id: btf_type.size_or_type,
                        linkage: var.linkage,
                    }
                }

                BtfKind::DataSec => {
                    let vars = Self::parse_var_secinfos(extra, vlen)?;
                    BtfTypeInfo::DataSec {
                        name,
                        size: btf_type.size_or_type,
                        vars,
                    }
                }

                BtfKind::Float => BtfTypeInfo::Float {
                    name,
                    size: btf_type.size_or_type,
                },

                BtfKind::DeclTag => {
                    if extra.len() < 4 {
                        return Err(BtfError::InvalidType(type_id));
                    }
                    let component_idx = i32::from_le_bytes([extra[0], extra[1], extra[2], extra[3]]);
                    BtfTypeInfo::DeclTag {
                        name,
                        type_id: btf_type.size_or_type,
                        component_idx,
                    }
                }

                BtfKind::TypeTag => BtfTypeInfo::TypeTag {
                    name,
                    type_id: btf_type.size_or_type,
                },

                BtfKind::Enum64 => {
                    let variants = Self::parse_enum64_values(extra, vlen, strings)?;
                    BtfTypeInfo::Enum64 {
                        name,
                        size: btf_type.size_or_type,
                        is_signed: kind_flag,
                        variants,
                    }
                }
            };

            types.push(type_info);
            offset = extra_end;
            type_id += 1;
        }

        Ok(types)
    }

    fn parse_members(
        data: &'a [u8],
        count: u16,
        kind_flag: bool,
        strings: &BtfStrings<'a>,
    ) -> Result<Vec<Member<'a>>, BtfError> {
        let mut members = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let start = i * BtfMember::SIZE;
            let member_data = &data[start..];
            let raw = BtfMember::parse(member_data).ok_or(BtfError::InvalidType(0))?;
            members.push(Member {
                name: strings.get_or_empty(raw.name_off),
                type_id: raw.type_id,
                bit_offset: raw.bit_offset(kind_flag),
                bitfield_size: raw.bitfield_size(kind_flag),
            });
        }
        Ok(members)
    }

    fn parse_enum_values(data: &'a [u8], count: u16, strings: &BtfStrings<'a>) -> Result<Vec<EnumValue<'a>>, BtfError> {
        let mut values = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let start = i * BtfEnum::SIZE;
            let enum_data = &data[start..];
            let raw = BtfEnum::parse(enum_data).ok_or(BtfError::InvalidType(0))?;
            values.push(EnumValue {
                name: strings.get_or_empty(raw.name_off),
                value: raw.val,
            });
        }
        Ok(values)
    }

    fn parse_enum64_values(
        data: &'a [u8],
        count: u16,
        strings: &BtfStrings<'a>,
    ) -> Result<Vec<Enum64Value<'a>>, BtfError> {
        let mut values = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let start = i * BtfEnum64::SIZE;
            let enum_data = &data[start..];
            let raw = BtfEnum64::parse(enum_data).ok_or(BtfError::InvalidType(0))?;
            values.push(Enum64Value {
                name: strings.get_or_empty(raw.name_off),
                value: raw.value(),
            });
        }
        Ok(values)
    }

    fn parse_params(data: &'a [u8], count: u16, strings: &BtfStrings<'a>) -> Result<Vec<Param<'a>>, BtfError> {
        let mut params = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let start = i * BtfParam::SIZE;
            let param_data = &data[start..];
            let raw = BtfParam::parse(param_data).ok_or(BtfError::InvalidType(0))?;
            params.push(Param {
                name: strings.get_or_empty(raw.name_off),
                type_id: raw.type_id,
            });
        }
        Ok(params)
    }

    fn parse_var_secinfos(data: &[u8], count: u16) -> Result<Vec<VarSecInfo>, BtfError> {
        let mut vars = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let start = i * BtfVarSecinfo::SIZE;
            let var_data = &data[start..];
            let raw = BtfVarSecinfo::parse(var_data).ok_or(BtfError::InvalidType(0))?;
            vars.push(VarSecInfo {
                type_id: raw.type_id,
                offset: raw.offset,
                size: raw.size,
            });
        }
        Ok(vars)
    }

    /// Get the header.
    pub fn header(&self) -> &BtfHeader {
        &self.header
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

    /// Get the number of types (including void at index 0).
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Iterate over all types.
    pub fn types(&self) -> impl Iterator<Item = (u32, &BtfTypeInfo<'a>)> {
        self.types.iter().enumerate().map(|(i, t)| (i as u32, t))
    }

    /// Find a type by name and kind.
    pub fn find_type(&self, name: &str, kind: BtfKind) -> Option<(u32, &BtfTypeInfo<'a>)> {
        self.types().find(|(_, t)| t.kind() == kind && t.name() == Some(name))
    }

    /// Find a struct by name.
    pub fn find_struct(&self, name: &str) -> Option<(u32, &BtfTypeInfo<'a>)> {
        self.find_type(name, BtfKind::Struct)
    }

    /// Find a union by name.
    pub fn find_union(&self, name: &str) -> Option<(u32, &BtfTypeInfo<'a>)> {
        self.find_type(name, BtfKind::Union)
    }

    /// Find an enum by name.
    pub fn find_enum(&self, name: &str) -> Option<(u32, &BtfTypeInfo<'a>)> {
        self.find_type(name, BtfKind::Enum)
            .or_else(|| self.find_type(name, BtfKind::Enum64))
    }

    /// Resolve a type through modifiers (const, volatile, restrict, typedef).
    ///
    /// Returns the underlying "real" type ID and info.
    pub fn resolve_type(&self, mut type_id: u32) -> Option<(u32, &BtfTypeInfo<'a>)> {
        loop {
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
    }

    /// Get a struct member by name.
    pub fn struct_member(&self, type_id: u32, member_name: &str) -> Option<&Member<'a>> {
        let (_, ty) = self.resolve_type(type_id)?;
        match ty {
            BtfTypeInfo::Struct { members, .. } | BtfTypeInfo::Union { members, .. } => {
                members.iter().find(|m| m.name == member_name)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse() {
        // Minimal valid BTF header
        let mut data = vec![0u8; 24];
        data[0..2].copy_from_slice(&BTF_MAGIC.to_le_bytes());
        data[2] = BTF_VERSION;
        data[3] = 0; // flags
        data[4..8].copy_from_slice(&24u32.to_le_bytes()); // hdr_len
                                                          // type_off, type_len, str_off, str_len all 0

        let header = BtfHeader::parse(&data).unwrap();
        assert_eq!(header.magic, BTF_MAGIC);
        assert_eq!(header.version, BTF_VERSION);
    }
}
