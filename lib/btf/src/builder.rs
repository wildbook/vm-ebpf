//! Builder for host-defined BTF.
//!
//! The host describes its own types as a compiler describes a program's: as standard BTF. [`BtfBuilder`] collects the
//! types and [`BtfBuilder::encode`] produces bytes that [`Btf::parse`] reads back, so CO-RE relocations resolve against
//! the host's types as they would against a second translation unit.

use hashbrown::HashMap;

use crate::parse::{Btf, BtfError};
use crate::raw::{BtfKind, TypeHeader, BTF_HEADER_LEN, BTF_INT_SIGNED, BTF_MAGIC, BTF_VERSION};
use crate::types::{BtfType, Member};

/// Builds standard BTF describing the host's types.
///
/// Type IDs are assigned in creation order starting at 1 (0 is always `void`), the same scheme `Btf::parse` uses, so
/// IDs returned by this builder and IDs read back from `encode()`'s output agree.
pub struct BtfBuilder {
    strings: Vec<u8>,
    string_offsets: HashMap<String, u32>,
    types: Vec<TypeEntry>,
}

impl Default for BtfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BtfBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self {
            // Offset 0 is the empty string, used for every anonymous type's name.
            strings: vec![0],
            string_offsets: HashMap::new(),
            types: Vec::new(),
        }
    }

    /// Add an integer type (`unsigned long`, `int`, `_Bool`, ...).
    pub fn add_int(&mut self, name: &str, size: u32, signed: bool) -> u32 {
        let name = self.string(name);
        let encoding = if signed { BTF_INT_SIGNED } else { 0 };
        let bits = (size * 8) as u8;
        self.push(TypeEntry::Int {
            name,
            size,
            encoding,
            offset: 0,
            bits,
        })
    }

    /// Add a pointer to `target`.
    pub fn add_ptr(&mut self, target: u32) -> u32 {
        self.push(TypeEntry::Ptr { pointee: target })
    }

    /// Add an array of `nelems` elements of `elem`.
    pub fn add_array(&mut self, elem: u32, nelems: u32) -> u32 {
        self.push(TypeEntry::Array { elem, index: 0, nelems })
    }

    /// Add a struct with no members yet; add them with [`member`](Self::member) or
    /// [`bitfield_member`](Self::bitfield_member).
    pub fn add_struct(&mut self, name: &str, size: u32) -> u32 {
        let name = self.string(name);
        self.push(TypeEntry::Struct {
            name,
            size,
            members: Vec::new(),
        })
    }

    /// Add a union with no members yet.
    pub fn add_union(&mut self, name: &str, size: u32) -> u32 {
        let name = self.string(name);
        self.push(TypeEntry::Union {
            name,
            size,
            members: Vec::new(),
        })
    }

    /// Add a byte-aligned member to the struct or union `owner`.
    ///
    /// # Panics
    ///
    /// Panics if `owner` is not a struct or union previously returned by this builder.
    pub fn member(&mut self, owner: u32, name: &str, byte_offset: u32, type_id: u32) {
        let name = self.string(name);
        self.members_of(owner).push(MemberEntry {
            name,
            type_id,
            bit_offset: byte_offset * 8,
            bitfield_size: 0,
        });
    }

    /// Add a bitfield member to the struct or union `owner`.
    ///
    /// # Panics
    ///
    /// Panics if `owner` is not a struct or union previously returned by this builder.
    pub fn bitfield_member(&mut self, owner: u32, name: &str, bit_offset: u32, bit_size: u32, type_id: u32) {
        let name = self.string(name);
        self.members_of(owner).push(MemberEntry {
            name,
            type_id,
            bit_offset,
            bitfield_size: bit_size,
        });
    }

    fn members_of(&mut self, owner: u32) -> &mut Vec<MemberEntry> {
        match owner.checked_sub(1).and_then(|i| self.types.get_mut(i as usize)) {
            Some(TypeEntry::Struct { members, .. } | TypeEntry::Union { members, .. }) => members,
            _ => panic!("BTF type {owner} is not a struct or union"),
        }
    }

    /// Add an enum with no enumerators yet; add them with [`enumerator`](Self::enumerator). Encoded as `ENUM64` if a
    /// value needs it.
    pub fn add_enum(&mut self, name: &str, size: u32, signed: bool) -> u32 {
        let name = self.string(name);
        self.push(TypeEntry::Enum {
            name,
            size,
            is_signed: signed,
            variants: Vec::new(),
        })
    }

    /// Add an enumerator to the enum `owner`.
    ///
    /// # Panics
    ///
    /// Panics if `owner` is not an enum previously returned by this builder.
    pub fn enumerator(&mut self, owner: u32, name: &str, value: i64) {
        let name = self.string(name);
        match owner.checked_sub(1).and_then(|i| self.types.get_mut(i as usize)) {
            Some(TypeEntry::Enum { variants, .. }) => variants.push((name, value)),
            _ => panic!("BTF type {owner} is not an enum"),
        }
    }

    /// Add a typedef naming `target`.
    pub fn add_typedef(&mut self, name: &str, target: u32) -> u32 {
        let name = self.string(name);
        self.push(TypeEntry::Typedef { name, target })
    }

    /// Add a floating-point type.
    pub fn add_float(&mut self, name: &str, size: u32) -> u32 {
        let name = self.string(name);
        self.push(TypeEntry::Float { name, size })
    }

    /// Add a forward declaration of a struct (`is_union = false`) or union.
    pub fn add_fwd(&mut self, name: &str, is_union: bool) -> u32 {
        let name = self.string(name);
        self.push(TypeEntry::Fwd { name, is_union })
    }

    /// Append a BTF blob compiled from C (clang `-g`, or pahole output), remapping its type IDs and string offsets so
    /// it coexists with types already in this builder. This is how a host ships its layout as a compiled header instead
    /// of describing it field by field.
    pub fn append_btf(&mut self, bytes: &[u8]) -> Result<(), BtfError> {
        let foreign = Btf::parse(bytes)?;
        let id_base = self.types.len() as u32;
        // type_by_id(0) is the implicit `void`, shared across every BTF blob; skip it.
        for (_, ty) in foreign.types().skip(1) {
            let entry = self.convert(ty, id_base);
            self.types.push(entry);
        }
        Ok(())
    }

    fn convert(&mut self, ty: &BtfType<'_>, id_base: u32) -> TypeEntry {
        let remap = |id| remap_id(id, id_base);
        match ty {
            BtfType::Void => unreachable!("void is type 0, not a stored entry"),
            &BtfType::Int {
                name,
                size,
                encoding,
                offset,
                bits,
            } => TypeEntry::Int {
                name: self.string(name),
                size,
                encoding,
                offset,
                bits,
            },
            &BtfType::Ptr { pointee_type } => TypeEntry::Ptr {
                pointee: remap(pointee_type),
            },
            &BtfType::Array {
                elem_type,
                index_type,
                nelems,
            } => TypeEntry::Array {
                elem: remap(elem_type),
                index: remap(index_type),
                nelems,
            },
            BtfType::Struct { name, size, members } => TypeEntry::Struct {
                name: self.string(name),
                size: *size,
                members: self.convert_members(members, id_base),
            },
            BtfType::Union { name, size, members } => TypeEntry::Union {
                name: self.string(name),
                size: *size,
                members: self.convert_members(members, id_base),
            },
            BtfType::Enum {
                name,
                size,
                is_signed,
                variants,
                ..
            } => TypeEntry::Enum {
                name: self.string(name),
                size: *size,
                is_signed: *is_signed,
                variants: variants.iter().map(|v| (self.string(v.name), v.value)).collect(),
            },
            &BtfType::Fwd { name, is_union } => TypeEntry::Fwd {
                name: self.string(name),
                is_union,
            },
            &BtfType::Typedef { name, type_id } => TypeEntry::Typedef {
                name: self.string(name),
                target: remap(type_id),
            },
            &BtfType::Volatile { type_id } => TypeEntry::Volatile { target: remap(type_id) },
            &BtfType::Const { type_id } => TypeEntry::Const { target: remap(type_id) },
            &BtfType::Restrict { type_id } => TypeEntry::Restrict { target: remap(type_id) },
            &BtfType::Func {
                name,
                proto_type,
                linkage,
            } => TypeEntry::Func {
                name: self.string(name),
                proto: remap(proto_type),
                linkage,
            },
            BtfType::FuncProto { return_type, params } => TypeEntry::FuncProto {
                ret: remap(*return_type),
                params: params.iter().map(|p| (self.string(p.name), remap(p.type_id))).collect(),
            },
            &BtfType::Var { name, type_id, linkage } => TypeEntry::Var {
                name: self.string(name),
                target: remap(type_id),
                linkage,
            },
            BtfType::DataSec { name, size, vars } => TypeEntry::DataSec {
                name: self.string(name),
                size: *size,
                vars: vars.iter().map(|v| (remap(v.type_id), v.offset, v.size)).collect(),
            },
            &BtfType::Float { name, size } => TypeEntry::Float {
                name: self.string(name),
                size,
            },
            &BtfType::DeclTag {
                name,
                type_id,
                component_idx,
            } => TypeEntry::DeclTag {
                name: self.string(name),
                target: remap(type_id),
                component_idx,
            },
            &BtfType::TypeTag { name, type_id } => TypeEntry::TypeTag {
                name: self.string(name),
                target: remap(type_id),
            },
        }
    }

    fn convert_members(&mut self, members: &[Member<'_>], id_base: u32) -> Vec<MemberEntry> {
        members
            .iter()
            .map(|m| MemberEntry {
                name: self.string(m.name),
                type_id: remap_id(m.type_id, id_base),
                bit_offset: m.bit_offset,
                bitfield_size: m.bitfield_size,
            })
            .collect()
    }

    fn push(&mut self, entry: TypeEntry) -> u32 {
        self.types.push(entry);
        self.types.len() as u32
    }

    /// Intern `name` in the string table, returning its offset. Reuses an existing offset for a name already interned,
    /// same as kernel BTF producers do.
    pub fn string(&mut self, name: &str) -> u32 {
        if name.is_empty() {
            return 0;
        }
        if let Some(&off) = self.string_offsets.get(name) {
            return off;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.string_offsets.insert(name.to_string(), off);
        off
    }

    /// Encode the collected types as a standard BTF blob, parseable by [`Btf::parse`].
    pub fn encode(&self) -> Vec<u8> {
        let mut type_data = Vec::new();
        for entry in &self.types {
            entry.encode(&mut type_data);
        }

        let hdr_len = BTF_HEADER_LEN as u32;
        let type_len = type_data.len() as u32;
        let str_len = self.strings.len() as u32;
        let mut out = Vec::with_capacity((hdr_len + type_len + str_len) as usize);
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
        out.push(0); // flags
        out.extend_from_slice(&hdr_len.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&type_len.to_le_bytes());
        out.extend_from_slice(&type_len.to_le_bytes()); // str_off, right after the types
        out.extend_from_slice(&str_len.to_le_bytes());
        out.extend_from_slice(&type_data);
        out.extend_from_slice(&self.strings);
        out
    }
}

/// The ID that type `id` of an appended BTF gets after `id_base` earlier types. Void stays 0.
fn remap_id(id: u32, id_base: u32) -> u32 {
    if id == 0 {
        0
    } else {
        id + id_base
    }
}

/// One struct/union member, pending encoding.
struct MemberEntry {
    name: u32,
    type_id: u32,
    bit_offset: u32,
    bitfield_size: u32,
}

/// One BTF type, pending encoding. Mirrors [`BtfType`] but owns its data, so `member`/`enumerator` can keep
/// extending a struct or enum after it is created.
enum TypeEntry {
    Int {
        name: u32,
        size: u32,
        encoding: u8,
        offset: u8,
        bits: u8,
    },
    Ptr {
        pointee: u32,
    },
    Array {
        elem: u32,
        index: u32,
        nelems: u32,
    },
    Struct {
        name: u32,
        size: u32,
        members: Vec<MemberEntry>,
    },
    Union {
        name: u32,
        size: u32,
        members: Vec<MemberEntry>,
    },
    Enum {
        name: u32,
        size: u32,
        is_signed: bool,
        variants: Vec<(u32, i64)>,
    },
    Fwd {
        name: u32,
        is_union: bool,
    },
    Typedef {
        name: u32,
        target: u32,
    },
    Volatile {
        target: u32,
    },
    Const {
        target: u32,
    },
    Restrict {
        target: u32,
    },
    Func {
        name: u32,
        proto: u32,
        linkage: u16,
    },
    FuncProto {
        ret: u32,
        params: Vec<(u32, u32)>,
    },
    Var {
        name: u32,
        target: u32,
        linkage: u32,
    },
    DataSec {
        name: u32,
        size: u32,
        vars: Vec<(u32, u32, u32)>,
    },
    Float {
        name: u32,
        size: u32,
    },
    DeclTag {
        name: u32,
        target: u32,
        component_idx: i32,
    },
    TypeTag {
        name: u32,
        target: u32,
    },
}

/// Write a BTF type header: name offset, kind/vlen/kind_flag info, and size-or-type.
fn header(out: &mut Vec<u8>, name_off: u32, kind: BtfKind, vlen: u16, kind_flag: bool, size_or_type: u32) {
    TypeHeader {
        name_off,
        kind,
        vlen,
        kind_flag,
        size_or_type,
    }
    .encode(out);
}

impl TypeEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int {
                name,
                size,
                encoding,
                offset,
                bits,
            } => {
                header(out, *name, BtfKind::Int, 0, false, *size);
                let int_info = (u32::from(*encoding) << 24) | (u32::from(*offset) << 16) | u32::from(*bits);
                out.extend_from_slice(&int_info.to_le_bytes());
            }
            Self::Ptr { pointee } => header(out, 0, BtfKind::Ptr, 0, false, *pointee),
            Self::Array { elem, index, nelems } => {
                header(out, 0, BtfKind::Array, 0, false, 0);
                out.extend_from_slice(&elem.to_le_bytes());
                out.extend_from_slice(&index.to_le_bytes());
                out.extend_from_slice(&nelems.to_le_bytes());
            }
            Self::Struct { name, size, members } => Self::encode_members(out, *name, BtfKind::Struct, *size, members),
            Self::Union { name, size, members } => Self::encode_members(out, *name, BtfKind::Union, *size, members),
            Self::Enum {
                name,
                size,
                is_signed,
                variants,
            } => Self::encode_enum(out, *name, *size, *is_signed, variants),
            Self::Fwd { name, is_union } => header(out, *name, BtfKind::Fwd, 0, *is_union, 0),
            Self::Typedef { name, target } => header(out, *name, BtfKind::Typedef, 0, false, *target),
            Self::Volatile { target } => header(out, 0, BtfKind::Volatile, 0, false, *target),
            Self::Const { target } => header(out, 0, BtfKind::Const, 0, false, *target),
            Self::Restrict { target } => header(out, 0, BtfKind::Restrict, 0, false, *target),
            Self::Func { name, proto, linkage } => header(out, *name, BtfKind::Func, *linkage, false, *proto),
            Self::FuncProto { ret, params } => {
                header(out, 0, BtfKind::FuncProto, params.len() as u16, false, *ret);
                for (pname, ptype) in params {
                    out.extend_from_slice(&pname.to_le_bytes());
                    out.extend_from_slice(&ptype.to_le_bytes());
                }
            }
            Self::Var { name, target, linkage } => {
                header(out, *name, BtfKind::Var, 0, false, *target);
                out.extend_from_slice(&linkage.to_le_bytes());
            }
            Self::DataSec { name, size, vars } => {
                header(out, *name, BtfKind::DataSec, vars.len() as u16, false, *size);
                for (type_id, offset, var_size) in vars {
                    out.extend_from_slice(&type_id.to_le_bytes());
                    out.extend_from_slice(&offset.to_le_bytes());
                    out.extend_from_slice(&var_size.to_le_bytes());
                }
            }
            Self::Float { name, size } => header(out, *name, BtfKind::Float, 0, false, *size),
            Self::DeclTag {
                name,
                target,
                component_idx,
            } => {
                header(out, *name, BtfKind::DeclTag, 0, false, *target);
                out.extend_from_slice(&component_idx.to_le_bytes());
            }
            Self::TypeTag { name, target } => header(out, *name, BtfKind::TypeTag, 0, false, *target),
        }
    }

    fn encode_members(out: &mut Vec<u8>, name: u32, kind: BtfKind, size: u32, members: &[MemberEntry]) {
        let kind_flag = members.iter().any(|m| m.bitfield_size != 0);
        header(out, name, kind, members.len() as u16, kind_flag, size);
        for m in members {
            out.extend_from_slice(&m.name.to_le_bytes());
            out.extend_from_slice(&m.type_id.to_le_bytes());
            let offset = if kind_flag {
                (m.bitfield_size << 24) | (m.bit_offset & 0x00FF_FFFF)
            } else {
                m.bit_offset
            };
            out.extend_from_slice(&offset.to_le_bytes());
        }
    }

    /// Enums encode as 8-byte `BTF_KIND_ENUM` entries unless a value needs the full 64 bits, in which case the kernel's
    /// `BTF_KIND_ENUM64` format is used instead.
    fn encode_enum(out: &mut Vec<u8>, name: u32, size: u32, is_signed: bool, variants: &[(u32, i64)]) {
        let fits_32 = if is_signed {
            variants.iter().all(|&(_, v)| i32::try_from(v).is_ok())
        } else {
            variants.iter().all(|&(_, v)| u32::try_from(v).is_ok())
        };
        if fits_32 {
            header(out, name, BtfKind::Enum, variants.len() as u16, is_signed, size);
            for &(vname, value) in variants {
                out.extend_from_slice(&vname.to_le_bytes());
                out.extend_from_slice(&(value as u32).to_le_bytes());
            }
        } else {
            header(out, name, BtfKind::Enum64, variants.len() as u16, is_signed, size);
            for &(vname, value) in variants {
                let bits = value as u64;
                out.extend_from_slice(&vname.to_le_bytes());
                out.extend_from_slice(&(bits as u32).to_le_bytes());
                out.extend_from_slice(&((bits >> 32) as u32).to_le_bytes());
            }
        }
    }
}
