//! BTF type kind values and their on-disk sizes, matching the kernel definitions.

use crate::parse::{word, BtfError};

/// BTF magic number (little-endian).
pub const BTF_MAGIC: u16 = 0xEB9F;

/// The BTF version this crate reads and writes.
pub const BTF_VERSION: u8 = 1;

/// Size in bytes of the `btf_header` that starts a `.BTF` section.
pub const BTF_HEADER_LEN: usize = 24;

/// Flag in the encoding of an `Int`: the value is signed.
pub const BTF_INT_SIGNED: u8 = 1 << 0;

/// Size in bytes of the `btf_type` header that starts every type record.
pub const TYPE_HEADER_LEN: usize = 12;

// Sizes in bytes of the records that follow a type header, named after the kernel structs they hold. `BTF_INT_SIZE`
// is the `u32` that packs an integer's encoding, bit offset and bit count.
pub const BTF_INT_SIZE: usize = 4;
pub const BTF_ARRAY_SIZE: usize = 12;
pub const BTF_MEMBER_SIZE: usize = 12;
pub const BTF_ENUM_SIZE: usize = 8;
pub const BTF_PARAM_SIZE: usize = 8;
pub const BTF_VAR_SIZE: usize = 4;
pub const BTF_VAR_SECINFO_SIZE: usize = 12;
pub const BTF_DECL_TAG_SIZE: usize = 4;
pub const BTF_ENUM64_SIZE: usize = 12;

/// `Func` linkage (`enum btf_func_linkage`): visible only inside its object.
pub const BTF_FUNC_STATIC: u16 = 0;
/// `Func` linkage: defined here and visible to other objects.
pub const BTF_FUNC_GLOBAL: u16 = 1;
/// `Func` linkage: declared here and defined elsewhere.
pub const BTF_FUNC_EXTERN: u16 = 2;

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
        let vlen = usize::from(vlen);
        match self {
            Self::Void => 0,
            Self::Int => BTF_INT_SIZE,
            Self::Ptr => 0,
            Self::Array => BTF_ARRAY_SIZE,
            Self::Struct | Self::Union => vlen * BTF_MEMBER_SIZE,
            Self::Enum => vlen * BTF_ENUM_SIZE,
            Self::Fwd => 0,
            Self::Typedef => 0,
            Self::Volatile => 0,
            Self::Const => 0,
            Self::Restrict => 0,
            Self::Func => 0,
            Self::FuncProto => vlen * BTF_PARAM_SIZE,
            Self::Var => BTF_VAR_SIZE,
            Self::DataSec => vlen * BTF_VAR_SECINFO_SIZE,
            Self::Float => 0,
            Self::DeclTag => BTF_DECL_TAG_SIZE,
            Self::TypeTag => 0,
            Self::Enum64 => vlen * BTF_ENUM64_SIZE,
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
