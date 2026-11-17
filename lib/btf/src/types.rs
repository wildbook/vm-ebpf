//! High-level BTF type representations.

use crate::raw::BtfKind;

/// A parsed BTF type with all its information.
#[derive(Debug, Clone)]
pub enum BtfTypeInfo<'a> {
    /// Void type (implicit, type_id 0).
    Void,

    /// Integer type.
    Int {
        name: &'a str,
        size: u32,
        encoding: u8,
        offset: u8,
        bits: u8,
    },

    /// Pointer type.
    Ptr { pointee_type: u32 },

    /// Array type.
    Array {
        elem_type: u32,
        index_type: u32,
        nelems: u32,
    },

    /// Struct type.
    Struct {
        name: &'a str,
        size: u32,
        members: Vec<Member<'a>>,
    },

    /// Union type.
    Union {
        name: &'a str,
        size: u32,
        members: Vec<Member<'a>>,
    },

    /// Enum type. `is_64` tells apart the kernel's 32-bit `BTF_KIND_ENUM` and 64-bit `BTF_KIND_ENUM64` encodings;
    /// `kind()` reports them separately, but every other consumer treats the two the same.
    Enum {
        name: &'a str,
        size: u32,
        is_signed: bool,
        is_64: bool,
        variants: Vec<EnumValue<'a>>,
    },

    /// Forward declaration.
    Fwd { name: &'a str, is_union: bool },

    /// Typedef.
    Typedef { name: &'a str, type_id: u32 },

    /// Volatile qualifier.
    Volatile { type_id: u32 },

    /// Const qualifier.
    Const { type_id: u32 },

    /// Restrict qualifier.
    Restrict { type_id: u32 },

    /// Function.
    Func {
        name: &'a str,
        proto_type: u32,
        linkage: u16,
    },

    /// Function prototype.
    FuncProto { return_type: u32, params: Vec<Param<'a>> },

    /// Variable.
    Var { name: &'a str, type_id: u32, linkage: u32 },

    /// Data section.
    DataSec {
        name: &'a str,
        size: u32,
        vars: Vec<VarSecInfo>,
    },

    /// Floating point type.
    Float { name: &'a str, size: u32 },

    /// Declaration tag.
    DeclTag {
        name: &'a str,
        type_id: u32,
        component_idx: i32,
    },

    /// Type tag.
    TypeTag { name: &'a str, type_id: u32 },
}

impl<'a> BtfTypeInfo<'a> {
    /// Get the kind of this type.
    pub fn kind(&self) -> BtfKind {
        match self {
            Self::Void => BtfKind::Void,
            Self::Int { .. } => BtfKind::Int,
            Self::Ptr { .. } => BtfKind::Ptr,
            Self::Array { .. } => BtfKind::Array,
            Self::Struct { .. } => BtfKind::Struct,
            Self::Union { .. } => BtfKind::Union,
            Self::Enum { is_64: false, .. } => BtfKind::Enum,
            Self::Enum { is_64: true, .. } => BtfKind::Enum64,
            Self::Fwd { .. } => BtfKind::Fwd,
            Self::Typedef { .. } => BtfKind::Typedef,
            Self::Volatile { .. } => BtfKind::Volatile,
            Self::Const { .. } => BtfKind::Const,
            Self::Restrict { .. } => BtfKind::Restrict,
            Self::Func { .. } => BtfKind::Func,
            Self::FuncProto { .. } => BtfKind::FuncProto,
            Self::Var { .. } => BtfKind::Var,
            Self::DataSec { .. } => BtfKind::DataSec,
            Self::Float { .. } => BtfKind::Float,
            Self::DeclTag { .. } => BtfKind::DeclTag,
            Self::TypeTag { .. } => BtfKind::TypeTag,
        }
    }

    /// Get the name of this type, if it has one.
    pub fn name(&self) -> Option<&'a str> {
        match self {
            Self::Void => None,
            Self::Int { name, .. } => Some(*name),
            Self::Ptr { .. } => None,
            Self::Array { .. } => None,
            Self::Struct { name, .. } => Some(*name),
            Self::Union { name, .. } => Some(*name),
            Self::Enum { name, .. } => Some(*name),
            Self::Fwd { name, .. } => Some(*name),
            Self::Typedef { name, .. } => Some(*name),
            Self::Volatile { .. } => None,
            Self::Const { .. } => None,
            Self::Restrict { .. } => None,
            Self::Func { name, .. } => Some(*name),
            Self::FuncProto { .. } => None,
            Self::Var { name, .. } => Some(*name),
            Self::DataSec { name, .. } => Some(*name),
            Self::Float { name, .. } => Some(*name),
            Self::DeclTag { name, .. } => Some(*name),
            Self::TypeTag { name, .. } => Some(*name),
        }
    }

    /// Get the size of this type in bytes, if applicable.
    pub fn size(&self) -> Option<u32> {
        match self {
            Self::Int { size, .. } => Some(*size),
            Self::Struct { size, .. } => Some(*size),
            Self::Union { size, .. } => Some(*size),
            Self::Enum { size, .. } => Some(*size),
            Self::DataSec { size, .. } => Some(*size),
            Self::Float { size, .. } => Some(*size),
            _ => None,
        }
    }
}

/// A struct/union member.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    /// Member name.
    pub name: &'a str,
    /// Type ID of the member.
    pub type_id: u32,
    /// Bit offset from the start of the struct.
    pub bit_offset: u32,
    /// Bitfield size (0 if not a bitfield).
    pub bitfield_size: u32,
}

/// An enum value. 32-bit `BTF_KIND_ENUM` values are sign-extended to `i64` at parse time, the same widening libbpf
/// applies when comparing a 32-bit enum against a 64-bit one.
#[derive(Debug, Clone)]
pub struct EnumValue<'a> {
    /// Variant name.
    pub name: &'a str,
    /// Value.
    pub value: i64,
}

/// A function parameter.
#[derive(Debug, Clone)]
pub struct Param<'a> {
    /// Parameter name.
    pub name: &'a str,
    /// Type ID.
    pub type_id: u32,
}

/// Variable info within a data section.
#[derive(Debug, Clone, Copy)]
pub struct VarSecInfo {
    /// Type ID of the variable.
    pub type_id: u32,
    /// Offset within the section.
    pub offset: u32,
    /// Size of the variable.
    pub size: u32,
}
