//! BTF type kind values and their on-disk sizes, matching the kernel definitions.

/// BTF magic number (little-endian).
pub const BTF_MAGIC: u16 = 0xEB9F;

/// BTF version we support.
pub const BTF_VERSION: u8 = 1;

/// Integer-encoding flag: the value is signed.
pub const BTF_INT_SIGNED: u8 = 1 << 0;

/// BTF type kind values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtfKind {
    /// Void type (type_id 0)
    Void = 0,
    /// Integer
    Int = 1,
    /// Pointer
    Ptr = 2,
    /// Array
    Array = 3,
    /// Struct
    Struct = 4,
    /// Union
    Union = 5,
    /// Enum (up to 32-bit values)
    Enum = 6,
    /// Forward declaration
    Fwd = 7,
    /// Typedef
    Typedef = 8,
    /// Volatile qualifier
    Volatile = 9,
    /// Const qualifier
    Const = 10,
    /// Restrict qualifier
    Restrict = 11,
    /// Function
    Func = 12,
    /// Function prototype
    FuncProto = 13,
    /// Variable
    Var = 14,
    /// Data section
    DataSec = 15,
    /// Floating point
    Float = 16,
    /// Declaration tag
    DeclTag = 17,
    /// Type tag
    TypeTag = 18,
    /// Enum (64-bit values)
    Enum64 = 19,
}

impl BtfKind {
    /// Parse a BTF kind from the info field.
    pub fn from_info(info: u32) -> Option<Self> {
        let kind = ((info >> 24) & 0x1F) as u8;
        match kind {
            0 => Some(Self::Void),
            1 => Some(Self::Int),
            2 => Some(Self::Ptr),
            3 => Some(Self::Array),
            4 => Some(Self::Struct),
            5 => Some(Self::Union),
            6 => Some(Self::Enum),
            7 => Some(Self::Fwd),
            8 => Some(Self::Typedef),
            9 => Some(Self::Volatile),
            10 => Some(Self::Const),
            11 => Some(Self::Restrict),
            12 => Some(Self::Func),
            13 => Some(Self::FuncProto),
            14 => Some(Self::Var),
            15 => Some(Self::DataSec),
            16 => Some(Self::Float),
            17 => Some(Self::DeclTag),
            18 => Some(Self::TypeTag),
            19 => Some(Self::Enum64),
            _ => None,
        }
    }

    /// Size in bytes of additional data following the 12-byte type header for this kind.
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
