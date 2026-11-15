//! BPF maps.
//!
//! Programs declare maps libbpf style in the `.maps` section; the linker reads the
//! definitions from BTF. All map values live in guest memory region [`MAPS_REGION`],
//! so the pointer `map_lookup_elem` returns is an ordinary guest address the program
//! can load from, store to and use with atomics.
//!
//! - Array maps: value `i` is at `base + i * stride`. Lookups are pure arithmetic.
//! - Hash maps: values sit in fixed slots of the same layout; a host-side index maps
//!   keys to slots. Deleting a key frees its slot for reuse, so a pointer the program
//!   kept across a delete then aliases whichever value takes the slot next, as with
//!   kernel hash maps.
//!
//! Each map starts on a cache line, and values are padded to 8 bytes so 64 bit
//! atomics on them are aligned.
//!
//! The guest refers to a map by its handle: the `lddw` the program uses to load a map
//! gets the map's index in this program.

use std::collections::HashMap;

use btf::{Btf, BtfTypeInfo};

use crate::error::{LinkError, Result, VmError};
use crate::helper::{HelperContext, HelperRegistry};
use crate::memory::{region_base, Perms, VmMemory};
use crate::module::Module;
use crate::section::SectionKind;

/// Guest region holding all map values.
pub const MAPS_REGION: usize = 4;

/// Standard helper IDs bound to the built-in map implementation.
pub const BPF_FUNC_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_FUNC_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_FUNC_MAP_DELETE_ELEM: u32 = 3;

/// `map_update_elem` flags.
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

const ENOENT: i64 = 2;
const E2BIG: i64 = 7;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;

const CACHE_LINE: u64 = 64;

/// Kind of map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    Array,
    Hash,
}

/// A map declaration read from a module's BTF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapDef {
    pub name: String,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// Why a map update or delete failed. Guest helpers return these as negative errno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// Key not present (`ENOENT`).
    NotFound,
    /// `BPF_NOEXIST` and the key is present (`EEXIST`).
    Exists,
    /// No free slot, or an array index out of range (`E2BIG`).
    Full,
    /// Bad key or value size, unknown flags, or delete on an array map (`EINVAL`).
    Invalid,
}

impl MapError {
    fn errno(self) -> i64 {
        match self {
            Self::NotFound => ENOENT,
            Self::Exists => EEXIST,
            Self::Full => E2BIG,
            Self::Invalid => EINVAL,
        }
    }
}

/// The maps of a linked program.
#[derive(Debug, Default, Clone)]
pub struct Maps {
    maps: Vec<Map>,
    by_name: HashMap<String, u32>,
}

#[derive(Debug, Clone)]
struct Map {
    def: MapDef,
    // guest address of value 0
    base: u64,
    // value size rounded up to 8
    stride: u64,
    // hash maps only
    index: Option<HashIndex>,
}

#[derive(Debug, Clone, Default)]
struct HashIndex {
    slots: HashMap<Box<[u8]>, u32>,
    free: Vec<u32>,
}

impl Maps {
    /// Lay out `defs` and return the maps and the size of the region they need.
    pub fn new(defs: Vec<MapDef>) -> (Self, usize) {
        let mut maps = Self::default();
        let mut len = 0;
        for def in defs {
            let stride = u64::from(def.value_size).next_multiple_of(8);
            let base = region_base(MAPS_REGION) + len;
            len = (len + stride * u64::from(def.max_entries)).next_multiple_of(CACHE_LINE);
            let index = (def.kind == MapKind::Hash).then(|| HashIndex {
                slots: HashMap::with_capacity(def.max_entries as usize),
                free: (0..def.max_entries).rev().collect(),
            });
            maps.by_name.insert(def.name.clone(), maps.maps.len() as u32);
            maps.maps.push(Map {
                def,
                base,
                stride,
                index,
            });
        }
        (maps, len as usize)
    }

    /// Handle of the map called `name`.
    pub fn handle(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Definition of the map with `handle`.
    pub fn def(&self, handle: u32) -> Option<&MapDef> {
        self.maps.get(handle as usize).map(|m| &m.def)
    }

    /// Number of maps.
    pub fn len(&self) -> usize {
        self.maps.len()
    }

    /// Whether the program declares no maps.
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
    }

    /// Guest address of the value for `key`, if present.
    pub fn lookup(&self, handle: u32, key: &[u8]) -> Option<u64> {
        let map = self.maps.get(handle as usize)?;
        map.slot(key).map(|slot| map.addr(slot))
    }

    /// Insert or replace the value for `key`; `flags` is `BPF_ANY`, `BPF_NOEXIST` or `BPF_EXIST`.
    pub fn update(
        &mut self,
        mem: &mut VmMemory,
        handle: u32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> std::result::Result<(), MapError> {
        let map = self.maps.get_mut(handle as usize).ok_or(MapError::Invalid)?;
        if value.len() != map.def.value_size as usize || flags > BPF_EXIST {
            return Err(MapError::Invalid);
        }

        let slot = match &mut map.index {
            None => {
                if flags == BPF_NOEXIST {
                    return Err(MapError::Exists); // every array index always exists
                }
                map.array_slot(key)?
            }
            Some(index) => {
                if key.len() != map.def.key_size as usize {
                    return Err(MapError::Invalid);
                }
                match (index.slots.get(key), flags) {
                    (Some(_), BPF_NOEXIST) => return Err(MapError::Exists),
                    (Some(&slot), _) => slot,
                    (None, BPF_EXIST) => return Err(MapError::NotFound),
                    (None, _) => {
                        let slot = index.free.pop().ok_or(MapError::Full)?;
                        index.slots.insert(key.into(), slot);
                        slot
                    }
                }
            }
        };

        let addr = map.addr(slot);
        mem.write_bytes(addr, value).expect("map slots are mapped");
        Ok(())
    }

    /// Remove `key`. Array maps don't support deletion.
    pub fn delete(&mut self, mem: &mut VmMemory, handle: u32, key: &[u8]) -> std::result::Result<(), MapError> {
        let map = self.maps.get_mut(handle as usize).ok_or(MapError::Invalid)?;
        let index = map.index.as_mut().ok_or(MapError::Invalid)?;
        let slot = index.slots.remove(key).ok_or(MapError::NotFound)?;
        index.free.push(slot);

        let (addr, len) = (map.addr(slot), map.def.value_size as usize);
        mem.bytes_mut(addr, len).expect("map slots are mapped").fill(0);
        Ok(())
    }
}

impl Map {
    fn addr(&self, slot: u32) -> u64 {
        self.base + u64::from(slot) * self.stride
    }

    fn slot(&self, key: &[u8]) -> Option<u32> {
        match &self.index {
            None => self.array_slot(key).ok(),
            Some(index) => index.slots.get(key).copied(),
        }
    }

    fn array_slot(&self, key: &[u8]) -> std::result::Result<u32, MapError> {
        let idx = u32::from_le_bytes(key.try_into().map_err(|_| MapError::Invalid)?);
        if idx >= self.def.max_entries {
            return Err(MapError::Full);
        }
        Ok(idx)
    }
}

/// Map definitions declared in `module`'s `.maps` section.
pub fn map_defs(module: &Module) -> Result<Vec<MapDef>> {
    let has_maps = module.sections.iter().any(|s| s.kind == SectionKind::Maps);
    let (true, Some(data)) = (has_maps, module.btf_data.as_deref()) else {
        return Ok(Vec::new());
    };
    let btf = Btf::parse(data).map_err(|e| invalid(format!("BTF: {e:?}")))?;

    let mut defs = Vec::new();
    for (_, ty) in btf.types() {
        let BtfTypeInfo::DataSec {
            name: ".maps", vars, ..
        } = ty
        else {
            continue;
        };
        for var in vars {
            let Some(BtfTypeInfo::Var { name, type_id, .. }) = btf.type_by_id(var.type_id) else {
                continue;
            };
            defs.push(parse_def(&btf, name, *type_id)?);
        }
    }
    Ok(defs)
}

/// Parse one libbpf map definition: `__uint(field, n)` is `int (*field)[n]`, and
/// `__type(field, T)` is `T *field`.
fn parse_def(btf: &Btf<'_>, name: &str, type_id: u32) -> Result<MapDef> {
    let bad = |what: &str| invalid(format!("map {name}: {what}"));

    let Some(BtfTypeInfo::Struct { members, .. }) = resolve(btf, type_id) else {
        return Err(bad("definition is not a struct"));
    };

    let (mut kind, mut max_entries, mut key_size, mut value_size) = (None, None, None, None);
    for member in members {
        let Some(BtfTypeInfo::Ptr { pointee_type }) = resolve(btf, member.type_id) else {
            return Err(bad("field is not a pointer"));
        };
        let pointee = resolve(btf, *pointee_type);
        let uint = || match pointee {
            Some(BtfTypeInfo::Array { nelems, .. }) => Ok(*nelems),
            _ => Err(bad("expected __uint")),
        };
        match member.name {
            "type" => kind = Some(uint()?),
            "max_entries" => max_entries = Some(uint()?),
            "key_size" => key_size = Some(uint()?),
            "value_size" => value_size = Some(uint()?),
            "key" => key_size = Some(size_of_type(btf, *pointee_type).ok_or_else(|| bad("unsized key"))?),
            "value" => value_size = Some(size_of_type(btf, *pointee_type).ok_or_else(|| bad("unsized value"))?),
            _ => {}
        }
    }

    let kind = match kind.ok_or_else(|| bad("missing type"))? {
        BPF_MAP_TYPE_HASH => MapKind::Hash,
        BPF_MAP_TYPE_ARRAY => MapKind::Array,
        other => return Err(bad(&format!("unsupported map type {other}"))),
    };
    let key_size = key_size.ok_or_else(|| bad("missing key"))?;
    let value_size = value_size.ok_or_else(|| bad("missing value"))?;
    let max_entries = max_entries.ok_or_else(|| bad("missing max_entries"))?;
    if kind == MapKind::Array && key_size != 4 {
        return Err(bad("array map keys must be 4 bytes"));
    }
    if value_size == 0 || max_entries == 0 {
        return Err(bad("zero value size or max_entries"));
    }

    Ok(MapDef {
        name: name.to_string(),
        kind,
        key_size,
        value_size,
        max_entries,
    })
}

fn resolve<'a, 'b>(btf: &'b Btf<'a>, id: u32) -> Option<&'b BtfTypeInfo<'a>> {
    btf.resolve_type(id).map(|(_, ty)| ty)
}

fn size_of_type(btf: &Btf<'_>, id: u32) -> Option<u32> {
    match resolve(btf, id)? {
        BtfTypeInfo::Ptr { .. } => Some(8),
        BtfTypeInfo::Array { elem_type, nelems, .. } => Some(size_of_type(btf, *elem_type)? * nelems),
        ty => ty.size(),
    }
}

fn invalid(msg: String) -> VmError {
    LinkError::InvalidReference(msg).into()
}

/// Bind helpers 1 to 3 to the built-in map implementation unless the host registered
/// its own under those IDs.
pub fn register_helpers(helpers: &mut HelperRegistry) {
    type Builtin = fn(&mut HelperContext) -> i64;
    let builtins: [(u32, Builtin); 3] = [
        (BPF_FUNC_MAP_LOOKUP_ELEM, lookup_elem),
        (BPF_FUNC_MAP_UPDATE_ELEM, update_elem),
        (BPF_FUNC_MAP_DELETE_ELEM, delete_elem),
    ];
    for (id, f) in builtins {
        if !helpers.has(id) {
            helpers.register_with_ctx(id, f);
        }
    }
}

/// Copy `len` guest bytes at `addr`, or `None` if they aren't mapped.
fn guest_bytes(mem: &VmMemory, addr: u64, len: u32) -> Option<Vec<u8>> {
    mem.bytes(addr, len as usize).ok().map(<[u8]>::to_vec)
}

fn lookup_elem(ctx: &mut HelperContext) -> i64 {
    let (Some(mem), Some(maps)) = (ctx.memory.as_deref(), ctx.maps.as_deref()) else {
        return 0;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return 0;
    };
    let Ok(key) = mem.bytes(ctx.args.r2, def.key_size as usize) else {
        return 0;
    };
    maps.lookup(handle, key).unwrap_or(0) as i64
}

fn update_elem(ctx: &mut HelperContext) -> i64 {
    let (Some(mem), Some(maps)) = (ctx.memory.as_deref_mut(), ctx.maps.as_deref_mut()) else {
        return -EINVAL;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return -EINVAL;
    };
    let (Some(key), Some(value)) =
        (guest_bytes(mem, ctx.args.r2, def.key_size), guest_bytes(mem, ctx.args.r3, def.value_size))
    else {
        return -EINVAL;
    };
    match maps.update(mem, handle, &key, &value, ctx.args.r4) {
        Ok(()) => 0,
        Err(e) => -e.errno(),
    }
}

fn delete_elem(ctx: &mut HelperContext) -> i64 {
    let (Some(mem), Some(maps)) = (ctx.memory.as_deref_mut(), ctx.maps.as_deref_mut()) else {
        return -EINVAL;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return -EINVAL;
    };
    let Some(key) = guest_bytes(mem, ctx.args.r2, def.key_size) else {
        return -EINVAL;
    };
    match maps.delete(mem, handle, &key) {
        Ok(()) => 0,
        Err(e) => -e.errno(),
    }
}

/// Host access to one map of a [`crate::Program`].
pub struct MapRef<'a> {
    maps: &'a mut Maps,
    memory: &'a mut VmMemory,
    handle: u32,
}

impl<'a> MapRef<'a> {
    pub fn new(maps: &'a mut Maps, memory: &'a mut VmMemory, handle: u32) -> Self {
        Self { maps, memory, handle }
    }

    /// The map's definition.
    pub fn def(&self) -> &MapDef {
        self.maps.def(self.handle).expect("handle comes from this map set")
    }

    /// The value for `key`, read in place from guest memory.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let addr = self.maps.lookup(self.handle, key)?;
        self.memory.bytes(addr, self.def().value_size as usize).ok()
    }

    /// Insert or replace the value for `key`; see [`Maps::update`] for `flags`.
    pub fn update(&mut self, key: &[u8], value: &[u8], flags: u64) -> std::result::Result<(), MapError> {
        self.maps.update(self.memory, self.handle, key, value, flags)
    }

    /// Remove `key`.
    pub fn delete(&mut self, key: &[u8]) -> std::result::Result<(), MapError> {
        self.maps.delete(self.memory, self.handle, key)
    }
}

/// Map the region holding all map values into `memory`.
pub fn map_region(memory: &mut VmMemory, len: usize) {
    if len != 0 {
        memory.map(MAPS_REGION, len, Perms::RW);
    }
}
