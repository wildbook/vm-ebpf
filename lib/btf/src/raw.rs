//! Raw BTF structures matching the kernel definitions.
//!
//! These structures are parsed directly from the BTF section bytes.

/// BTF magic number (little-endian).
pub const BTF_MAGIC: u16 = 0xEB9F;

/// BTF version we support.
pub const BTF_VERSION: u8 = 1;

/// BTF header at the start of the .BTF section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfHeader {
    /// Magic number (0xeB9F)
    pub magic: u16,
    /// Version (1)
    pub version: u8,
    /// Flags (0)
    pub flags: u8,
    /// Size of this header
    pub hdr_len: u32,
    /// Offset of type section (relative to end of header)
    pub type_off: u32,
    /// Length of type section
    pub type_len: u32,
    /// Offset of string section (relative to end of header)
    pub str_off: u32,
    /// Length of string section
    pub str_len: u32,
}

impl BtfHeader {
    /// Minimum header size (the required fields).
    pub const MIN_SIZE: usize = 24;

    /// Parse a BTF header from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        let version = data[2];
        let flags = data[3];
        let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let type_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let type_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let str_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let str_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);

        Some(Self {
            magic,
            version,
            flags,
            hdr_len,
            type_off,
            type_len,
            str_off,
            str_len,
        })
    }
}

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

    /// Size in bytes of additional data following btf_type for this kind.
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

/// Raw BTF type entry (12 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfType {
    /// Offset into string table for the name.
    pub name_off: u32,
    /// Info bits: vlen (0-15), kind (24-28), kind_flag (31).
    pub info: u32,
    /// Size or type depending on kind.
    pub size_or_type: u32,
}

impl BtfType {
    /// Size of a BtfType in bytes.
    pub const SIZE: usize = 12;

    /// Parse from bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            name_off: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            info: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_or_type: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }

    /// Get the kind from info.
    pub fn kind(&self) -> Option<BtfKind> {
        BtfKind::from_info(self.info)
    }

    /// Get vlen (number of elements) from info.
    pub fn vlen(&self) -> u16 {
        (self.info & 0xFFFF) as u16
    }

    /// Get kind_flag from info.
    pub fn kind_flag(&self) -> bool {
        (self.info >> 31) != 0
    }
}

/// BTF struct/union member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfMember {
    /// Offset into string table for member name.
    pub name_off: u32,
    /// Type ID of the member.
    pub type_id: u32,
    /// Bit offset (or bitfield info if kind_flag is set).
    pub offset: u32,
}

impl BtfMember {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            name_off: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            type_id: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            offset: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }

    /// Get the bit offset (when kind_flag is false, this is the full offset).
    pub fn bit_offset(&self, kind_flag: bool) -> u32 {
        if kind_flag {
            self.offset & 0xFFFFFF
        } else {
            self.offset
        }
    }

    /// Get the bitfield size (only valid when kind_flag is true).
    pub fn bitfield_size(&self, kind_flag: bool) -> u32 {
        if kind_flag {
            self.offset >> 24
        } else {
            0
        }
    }
}

/// BTF array info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfArray {
    /// Element type ID.
    pub elem_type: u32,
    /// Index type ID.
    pub index_type: u32,
    /// Number of elements.
    pub nelems: u32,
}

impl BtfArray {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            elem_type: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            index_type: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            nelems: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

/// BTF enum value (32-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfEnum {
    /// Offset into string table for name.
    pub name_off: u32,
    /// Value.
    pub val: i32,
}

impl BtfEnum {
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            name_off: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            val: i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// BTF enum64 value (64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfEnum64 {
    /// Offset into string table for name.
    pub name_off: u32,
    /// Low 32 bits of value.
    pub val_lo32: u32,
    /// High 32 bits of value.
    pub val_hi32: u32,
}

impl BtfEnum64 {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            name_off: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            val_lo32: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            val_hi32: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }

    /// Get the full 64-bit value.
    pub fn value(&self) -> i64 {
        ((self.val_hi32 as u64) << 32 | self.val_lo32 as u64) as i64
    }
}

/// BTF function parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfParam {
    /// Offset into string table for parameter name.
    pub name_off: u32,
    /// Type ID.
    pub type_id: u32,
}

impl BtfParam {
    pub const SIZE: usize = 8;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            name_off: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            type_id: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// BTF variable linkage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BtfVarLinkage {
    Static = 0,
    GlobalAlloc = 1,
    GlobalExtern = 2,
}

/// BTF variable info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfVar {
    pub linkage: u32,
}

impl BtfVar {
    pub const SIZE: usize = 4;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            linkage: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        })
    }
}

/// BTF datasec variable info.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BtfVarSecinfo {
    /// Type ID of the variable.
    pub type_id: u32,
    /// Offset within the section.
    pub offset: u32,
    /// Size of the variable.
    pub size: u32,
}

impl BtfVarSecinfo {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            type_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            offset: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

/// Integer encoding flags.
pub mod int_encoding {
    pub const BTF_INT_SIGNED: u8 = 1 << 0;
    pub const BTF_INT_CHAR: u8 = 1 << 1;
    pub const BTF_INT_BOOL: u8 = 1 << 2;
}

/// Extract integer encoding from the extra u32.
pub fn btf_int_encoding(val: u32) -> u8 {
    ((val & 0x0F000000) >> 24) as u8
}

/// Extract integer offset from the extra u32.
pub fn btf_int_offset(val: u32) -> u8 {
    ((val & 0x00FF0000) >> 16) as u8
}

/// Extract integer bits from the extra u32.
pub fn btf_int_bits(val: u32) -> u8 {
    (val & 0x000000FF) as u8
}
