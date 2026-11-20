//! Parsed BTF types.

use crate::raw::BtfKind;

/// A parsed BTF type. Fields named `type_id` and `*_type` hold the ID of another type in the same BTF.
#[derive(Debug, Clone)]
pub enum BtfType<'a> {
    /// Type ID 0, which no record encodes.
    Void,

    Int {
        name: &'a str,
        size: u32,
        /// Flags such as [`BTF_INT_SIGNED`](crate::BTF_INT_SIGNED).
        encoding: u8,
        offset: u8,
        bits: u8,
    },

    Ptr {
        pointee_type: u32,
    },

    Array {
        elem_type: u32,
        index_type: u32,
        nelems: u32,
    },

    Struct {
        name: &'a str,
        size: u32,
        members: Vec<Member<'a>>,
    },

    Union {
        name: &'a str,
        size: u32,
        members: Vec<Member<'a>>,
    },

    /// `is_64` tells apart the kernel's 32-bit `BTF_KIND_ENUM` and 64-bit `BTF_KIND_ENUM64` encodings; `kind()` reports
    /// them separately, but every other consumer treats the two the same.
    Enum {
        name: &'a str,
        size: u32,
        is_signed: bool,
        is_64: bool,
        variants: Vec<EnumValue<'a>>,
    },

    /// Forward declaration of a struct or union.
    Fwd {
        name: &'a str,
        is_union: bool,
    },

    Typedef {
        name: &'a str,
        type_id: u32,
    },

    Volatile {
        type_id: u32,
    },

    Const {
        type_id: u32,
    },

    Restrict {
        type_id: u32,
    },

    Func {
        name: &'a str,
        proto_type: u32,
        /// One of [`BTF_FUNC_STATIC`](crate::BTF_FUNC_STATIC), [`BTF_FUNC_GLOBAL`](crate::BTF_FUNC_GLOBAL) and
        /// [`BTF_FUNC_EXTERN`](crate::BTF_FUNC_EXTERN).
        linkage: u16,
    },

    FuncProto {
        return_type: u32,
        params: Vec<Param<'a>>,
    },

    Var {
        name: &'a str,
        type_id: u32,
        linkage: u32,
    },

    /// A data section and the variables in it.
    DataSec {
        name: &'a str,
        size: u32,
        vars: Vec<VarSecInfo>,
    },

    Float {
        name: &'a str,
        size: u32,
    },

    /// A tag on the type `type_id`, or on its member or parameter `component_idx` when that is not -1.
    DeclTag {
        name: &'a str,
        type_id: u32,
        component_idx: i32,
    },

    TypeTag {
        name: &'a str,
        type_id: u32,
    },
}

impl<'a> BtfType<'a> {
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

    /// The name, for the kinds that have one; `""` for an anonymous type of such a kind.
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

    /// The size in bytes, for the kinds that record one. [`Btf::resolve_size`](crate::Btf::resolve_size) also covers
    /// pointers, arrays, typedefs and qualifiers.
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

/// A struct or union member.
#[derive(Debug, Clone)]
pub struct Member<'a> {
    pub name: &'a str,
    pub type_id: u32,
    /// Offset from the start of the struct, in bits.
    pub bit_offset: u32,
    /// Width in bits, or 0 if the member is not a bitfield.
    pub bitfield_size: u32,
}

/// An enumerator. 32-bit `BTF_KIND_ENUM` values are sign-extended to `i64` at parse time, the same widening libbpf
/// applies when comparing a 32-bit enum against a 64-bit one.
#[derive(Debug, Clone)]
pub struct EnumValue<'a> {
    pub name: &'a str,
    pub value: i64,
}

/// A function parameter.
#[derive(Debug, Clone)]
pub struct Param<'a> {
    pub name: &'a str,
    pub type_id: u32,
}

/// A variable in a data section.
#[derive(Debug, Clone, Copy)]
pub struct VarSecInfo {
    pub type_id: u32,
    /// Offset in the section, in bytes.
    pub offset: u32,
    pub size: u32,
}
