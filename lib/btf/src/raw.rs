//! BTF type kind values and their on-disk sizes, matching the kernel definitions.

use crate::parse::{word, BtfError};

/// BTF magic number (little-endian).
pub const BTF_MAGIC: u16 = 0xEB9F;

/// BTF version we support.
pub const BTF_VERSION: u8 = 1;

/// Integer-encoding flag: the value is signed.
pub const BTF_INT_SIGNED: u8 = 1 << 0;

/// Size in bytes of the `btf_type` header that starts every type record.
pub const TYPE_HEADER_LEN: usize = 12;

/// BTF type kind values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtfKind {
    /// Type ID 0 only
    Void = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    /// Enum with up to 32-bit values
    Enum = 6,
    /// Forward declaration
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    /// Function prototype
    FuncProto = 13,
    Var = 14,
    /// Data section
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    /// Enum with 64-bit values
    Enum64 = 19,
}

impl BtfKind {
    /// The kind with discriminant `kind`, or `None` if BTF defines no such kind.
    pub fn from_u8(kind: u8) -> Option<Self> {
        KINDS.get(usize::from(kind)).copied()
    }

    /// Size in bytes of additional data following the type header for this kind.
    pub fn extra_size(self, vlen: u16) -> usize {
        match self {
            Self::Void => 0,
            Self::Int => 4,
            Self::Ptr => 0,
            Self::Array => 12,                                // btf_array
            Self::Struct | Self::Union => vlen as usize * 12, // btf_member
            Self::Enum => vlen as usize * 8,                  // btf_enum
            Self::Fwd => 0,
            Self::Typedef => 0,
            Self::Volatile => 0,
            Self::Const => 0,
            Self::Restrict => 0,
            Self::Func => 0,
            Self::FuncProto => vlen as usize * 8, // btf_param
            Self::Var => 4,                       // btf_var
            Self::DataSec => vlen as usize * 12,  // btf_var_secinfo
            Self::Float => 0,
            Self::DeclTag => 4, // btf_decl_tag
            Self::TypeTag => 0,
            Self::Enum64 => vlen as usize * 12, // btf_enum64
        }
    }
}

/// Every kind, indexed by its discriminant.
const KINDS: [BtfKind; 20] = {
    use BtfKind::*;
    [
        Void, Int, Ptr, Array, Struct, Union, Enum, Fwd, Typedef, Volatile, Const, Restrict, Func, FuncProto, Var,
        DataSec, Float, DeclTag, TypeTag, Enum64,
    ]
};

const _: () = {
    let mut i = 0;
    while i < KINDS.len() {
        assert!(KINDS[i] as usize == i);
        i += 1;
    }
};

/// The `btf_type` header, with its `info` word split into fields.
#[derive(Debug, Clone, Copy)]
pub struct TypeHeader {
    pub name_off: u32,
    pub kind: BtfKind,
    pub vlen: u16,
    pub kind_flag: bool,
    pub size_or_type: u32,
}

impl TypeHeader {
    /// Decode the header at the start of `b`, which holds at least [`TYPE_HEADER_LEN`] bytes.
    pub fn decode(b: &[u8]) -> Result<Self, BtfError> {
        let info = word(b, 1);
        let raw_kind = ((info >> 24) & 0x1F) as u8;
        Ok(Self {
            name_off: word(b, 0),
            kind: BtfKind::from_u8(raw_kind).ok_or(BtfError::UnknownKind(raw_kind))?,
            vlen: (info & 0xFFFF) as u16,
            kind_flag: (info >> 31) != 0,
            size_or_type: word(b, 2),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let info = (u32::from(self.kind_flag) << 31) | ((self.kind as u32) << 24) | u32::from(self.vlen);
        out.extend_from_slice(&self.name_off.to_le_bytes());
        out.extend_from_slice(&info.to_le_bytes());
        out.extend_from_slice(&self.size_or_type.to_le_bytes());
    }
}
