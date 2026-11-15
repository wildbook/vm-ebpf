//! BPF maps.
//!
//! Programs declare maps libbpf style in the `.maps` section; the linker reads the
//! definitions from BTF. All map values live in guest memory region
//! [`crate::layout::MAPS_REGION`], so the pointer `map_lookup_elem` returns is an
//! ordinary guest address the program can load from, store to and use with atomics.
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

use std::sync::Arc;

use hashbrown::HashMap;

use crate::error::{LinkError, Result, VmError};
use crate::layout::MAPS_REGION;
use crate::memory::{region_base, VmMemory};

mod btf;
mod hash;
mod helpers;
mod shared;

pub use btf::map_defs;
use hash::HashIndex;
pub use helpers::{register_helpers, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM, BPF_FUNC_MAP_UPDATE_ELEM};
use shared::{read, write};
pub use shared::{SharedMap, SharedMaps};

/// `map_update_elem` flags.
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;

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
            Self::NotFound => helpers::ENOENT,
            Self::Exists => helpers::EEXIST,
            Self::Full => helpers::E2BIG,
            Self::Invalid => helpers::EINVAL,
        }
    }
}

/// The maps of a linked program.
#[derive(Debug, Default, Clone)]
pub struct Maps {
    maps: Vec<Map>,
    by_name: HashMap<String, u32>,
}

/// Host access to one map of a [`crate::Program`].
pub struct MapRef<'a> {
    maps: &'a mut Maps,
    memory: &'a mut VmMemory,
    handle: u32,
}

#[derive(Debug, Clone)]
struct Map {
    def: MapDef,
    // guest address of value 0
    base: u64,
    // distance between values
    stride: u64,
    index: Index,
}

#[derive(Debug, Clone)]
enum Index {
    Array,
    Hash(HashIndex),
    // also keeps the shared storage mapped into this program alive
    Shared(Arc<SharedMap>),
}

impl Maps {
    /// Lay out `defs`, binding those declared shared to the VM-wide instance, and
    /// return the maps and the size of the private region they need.
    pub fn new(defs: Vec<MapDef>, shared: &SharedMaps) -> Result<(Self, usize)> {
        let mut maps = Self::default();
        let mut len = 0;
        for def in defs {
            let (base, stride, index) = match shared.bind(&def)? {
                Some(map) => (region_base(map.region), map.stride, Index::Shared(map)),
                None => {
                    let stride = u64::from(def.value_size).next_multiple_of(8);
                    let base = region_base(MAPS_REGION) + len;
                    len = (len + stride * u64::from(def.max_entries)).next_multiple_of(CACHE_LINE);
                    let index = match def.kind {
                        MapKind::Array => Index::Array,
                        MapKind::Hash => Index::Hash(HashIndex::new(def.key_size, def.max_entries)),
                    };
                    (base, stride, index)
                }
            };
            maps.by_name.insert(def.name.clone(), maps.maps.len() as u32);
            maps.maps.push(Map {
                def,
                base,
                stride,
                index,
            });
        }
        Ok((maps, len as usize))
    }

    /// Shared maps this program binds, for mapping their storage into its memory.
    pub fn shared(&self) -> impl Iterator<Item = &SharedMap> {
        self.maps.iter().filter_map(|m| match &m.index {
            Index::Shared(shared) => Some(&**shared),
            _ => None,
        })
    }

    /// Handle of the map called `name`.
    pub fn handle(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Definition of the map with `handle`.
    #[inline]
    pub fn def(&self, handle: u32) -> Option<&MapDef> {
        self.maps.get(handle as usize).map(|m| &m.def)
    }

    /// Guest address of the value for `key`, if present.
    #[inline]
    pub fn lookup(&self, handle: u32, key: &[u8]) -> Option<u64> {
        let map = self.maps.get(handle as usize)?;
        map.slot(key).map(|slot| map.addr(slot))
    }

    /// Find or create the slot for `key` and return its guest address; the caller
    /// writes the value. `flags` is `BPF_ANY`, `BPF_NOEXIST` or `BPF_EXIST`.
    pub fn upsert(&mut self, handle: u32, key: &[u8], flags: u64) -> std::result::Result<u64, MapError> {
        let map = self.maps.get_mut(handle as usize).ok_or(MapError::Invalid)?;
        if flags > BPF_EXIST {
            return Err(MapError::Invalid);
        }
        let slot = map.upsert(key, flags)?;
        Ok(map.addr(slot))
    }

    /// Remove `key` and return the guest address of its freed value. Array maps
    /// don't support deletion.
    pub fn remove(&mut self, handle: u32, key: &[u8]) -> std::result::Result<u64, MapError> {
        let map = self.maps.get_mut(handle as usize).ok_or(MapError::Invalid)?;
        let slot = map.with_hash(|index| index.remove(key)).ok_or(MapError::Invalid)??;
        Ok(map.addr(slot))
    }
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

    /// Insert or replace the value for `key`; see [`Maps::upsert`] for `flags`.
    pub fn update(&mut self, key: &[u8], value: &[u8], flags: u64) -> std::result::Result<(), MapError> {
        if self
            .maps
            .def(self.handle)
            .is_none_or(|def| value.len() != def.value_size as usize)
        {
            return Err(MapError::Invalid);
        }
        let addr = self.maps.upsert(self.handle, key, flags)?;
        self.memory.write_bytes(addr, value).expect("map slots are mapped");
        Ok(())
    }

    /// Remove `key` and zero its value.
    pub fn delete(&mut self, key: &[u8]) -> std::result::Result<(), MapError> {
        let addr = self.maps.remove(self.handle, key)?;
        let len = self.def().value_size as usize;
        self.memory.bytes_mut(addr, len).expect("map slots are mapped").fill(0);
        Ok(())
    }
}

impl Map {
    #[inline]
    fn addr(&self, slot: u32) -> u64 {
        self.base + u64::from(slot) * self.stride
    }

    /// Run `f` on the hash index, private or shared; `None` for array maps.
    fn with_hash<R>(&mut self, f: impl FnOnce(&mut HashIndex) -> R) -> Option<R> {
        match &mut self.index {
            Index::Array => None,
            Index::Hash(index) => Some(f(index)),
            Index::Shared(shared) => shared.index.as_ref().map(|index| f(&mut write(index))),
        }
    }

    #[inline]
    fn slot(&self, key: &[u8]) -> Option<u32> {
        match &self.index {
            Index::Array => self.array_slot(key).ok(),
            Index::Hash(index) => index.get(key),
            Index::Shared(shared) => match &shared.index {
                None => self.array_slot(key).ok(),
                Some(index) => read(index).get(key),
            },
        }
    }

    fn upsert(&mut self, key: &[u8], flags: u64) -> std::result::Result<u32, MapError> {
        if self.def.kind == MapKind::Array {
            if flags == BPF_NOEXIST {
                return Err(MapError::Exists); // every array index always exists
            }
            return self.array_slot(key);
        }
        if key.len() != self.def.key_size as usize {
            return Err(MapError::Invalid);
        }
        self.with_hash(|index| index.upsert(key, flags))
            .expect("hash map has an index")
    }

    #[inline]
    fn array_slot(&self, key: &[u8]) -> std::result::Result<u32, MapError> {
        let idx = u32::from_le_bytes(key.try_into().map_err(|_| MapError::Invalid)?);
        if idx >= self.def.max_entries {
            return Err(MapError::Full);
        }
        Ok(idx)
    }
}

fn invalid(msg: String) -> VmError {
    LinkError::InvalidReference(msg).into()
}
