//! BPF maps.
//!
//! Programs declare maps libbpf style in the `.maps` section; the linker reads the definitions from BTF. All map values
//! live in guest memory region [`crate::layout::MAPS_REGION`], so the pointer `map_lookup_elem` returns is an ordinary
//! guest address the program can load from, store to and use with atomics.
//!
//! - Array maps: value `i` is at `base + i * stride`. Lookups are pure arithmetic.
//! - Hash maps: values sit in fixed slots of the same layout; a host-side index maps keys to slots. Deleting a key
//!   frees its slot for reuse, so a pointer the program kept across a delete then aliases whichever value takes the
//!   slot next, as with kernel hash maps.
//!
//! Each map starts on a cache line, and values are padded to 8 bytes so 64 bit atomics on them are aligned.
//!
//! The guest refers to a map by its handle: the `lddw` the program uses to load a map gets the map's index in this
//! program.

use std::ops::Range;
use std::sync::{Arc, RwLockReadGuard};

use hashbrown::{hash_table, HashMap};

use crate::error::{Result, VmError};
use crate::layout::MAPS_REGION;
use crate::memory::{region_base, Pod, VmMemory, MAX_REGION_LEN};

#[cfg(feature = "link")]
mod btf;
mod hash;
mod helpers;
mod shared;

#[cfg(feature = "link")]
pub use btf::map_defs;
use hash::HashIndex;
pub use helpers::{register_helpers, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM, BPF_FUNC_MAP_UPDATE_ELEM};
use shared::{read, write};
pub use shared::{SharedMap, SharedMaps};

/// `map_update_elem` flag: insert the key or replace its value.
pub const BPF_ANY: u64 = 0;
/// `map_update_elem` flag: insert the key only if it is absent.
pub const BPF_NOEXIST: u64 = 1;
/// `map_update_elem` flag: replace the value only if the key is present.
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

/// Why a map access failed. Guest helpers return these as negative errno.
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

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "key not found",
            Self::Exists => "key already present",
            Self::Full => "map full, or array index out of range",
            Self::Invalid => "wrong key or value size, unknown flags, or delete on an array map",
        })
    }
}

impl std::error::Error for MapError {}

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
    /// Lay out `defs`, binding those declared shared to the VM-wide instance, and return the maps and the size of the
    /// private region they need. Definitions that can't be laid out fail with `bad_map`.
    pub fn new(defs: Vec<MapDef>, shared: &SharedMaps, bad_map: fn(String) -> VmError) -> Result<(Self, usize)> {
        let mut maps = Self::default();
        let mut len = 0;
        for def in defs {
            check_def(&def).map_err(bad_map)?;
            if maps.by_name.insert(def.name.clone(), maps.maps.len() as u32).is_some() {
                return Err(bad_map(format!("map {}: declared twice", def.name)));
            }
            let (base, stride, index) = match shared.bind(&def, bad_map)? {
                Some(map) => (region_base(map.region), map.stride, Index::Shared(map)),
                None => {
                    let stride = u64::from(def.value_size).next_multiple_of(8);
                    let base = region_base(MAPS_REGION) + len;
                    len = (len + stride * u64::from(def.max_entries)).next_multiple_of(CACHE_LINE);
                    if len > MAX_REGION_LEN as u64 {
                        return Err(bad_map(format!("map {}: maps exceed {MAX_REGION_LEN} bytes", def.name)));
                    }
                    let index = match def.kind {
                        MapKind::Array => Index::Array,
                        MapKind::Hash => Index::Hash(HashIndex::new(def.key_size, def.max_entries)),
                    };
                    (base, stride, index)
                }
            };
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

    /// Find or create the slot for `key` and return its guest address; the caller writes the value. `flags` is
    /// `BPF_ANY`, `BPF_NOEXIST` or `BPF_EXIST`.
    pub fn upsert(&mut self, handle: u32, key: &[u8], flags: u64) -> std::result::Result<u64, MapError> {
        let map = self.maps.get_mut(handle as usize).ok_or(MapError::Invalid)?;
        if flags > BPF_EXIST {
            return Err(MapError::Invalid);
        }
        let slot = map.upsert(key, flags)?;
        Ok(map.addr(slot))
    }

    /// Remove `key` and return the guest address of its freed value. Array maps don't support deletion.
    pub fn remove(&mut self, handle: u32, key: &[u8]) -> std::result::Result<u64, MapError> {
        let map = self.maps.get_mut(handle as usize).ok_or(MapError::Invalid)?;
        let slot = map.with_hash(|index| index.remove(key)).ok_or(MapError::Invalid)??;
        Ok(map.addr(slot))
    }
}

impl<'a> MapRef<'a> {
    /// `handle` must be a map in `maps`, whose slots `memory` maps.
    pub(crate) fn new(maps: &'a mut Maps, memory: &'a mut VmMemory, handle: u32) -> Self {
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

    /// The value for `key`, copied out as a `V`. Fails with [`MapError::NotFound`] if the key is absent, and with
    /// [`MapError::Invalid`] if `K` or `V` differs in size from the map's keys or values.
    pub fn get_as<K: Pod, V: Pod>(&self, key: K) -> std::result::Result<V, MapError> {
        check_sizes::<K, V>(self.def())?;
        let value = self.get(key.as_bytes()).ok_or(MapError::NotFound)?;
        Ok(V::from_bytes(value).expect("value size checked"))
    }

    /// [`MapRef::update`] with the bytes of `key` and `value`.
    pub fn update_as<K: Pod, V: Pod>(&mut self, key: K, value: V, flags: u64) -> std::result::Result<(), MapError> {
        self.update(key.as_bytes(), value.as_bytes(), flags)
    }

    /// The map's entries, for [`Entries::iter`] or [`Entries::iter_as`].
    pub fn entries(&self) -> Entries<'_> {
        let map = &self.maps.maps[self.handle as usize];
        let index = match &map.index {
            Index::Array => EntriesIndex::Array,
            Index::Hash(index) => EntriesIndex::Hash(index),
            Index::Shared(shared) => match &shared.index {
                None => EntriesIndex::Array,
                Some(index) => EntriesIndex::Shared(read(index)),
            },
        };
        Entries {
            map,
            memory: self.memory,
            index,
        }
    }
}

/// The entries of one map, from [`MapRef::entries`].
///
/// For a shared hash map, this holds the map's key index locked for reading until it is dropped. Guests that insert or
/// delete keys meanwhile wait, and one that runs on this thread deadlocks.
pub struct Entries<'a> {
    map: &'a Map,
    memory: &'a VmMemory,
    index: EntriesIndex<'a>,
}

enum EntriesIndex<'a> {
    Array,
    Hash(&'a HashIndex),
    Shared(RwLockReadGuard<'a, HashIndex>),
}

impl Entries<'_> {
    /// Every element of an array map with its index, in index order, or the keys present in a hash map with their
    /// values, in no particular order.
    pub fn iter(&self) -> MapIter<'_> {
        let slots = match &self.index {
            EntriesIndex::Array => Slots::Array(0..self.map.def.max_entries),
            EntriesIndex::Hash(index) => Slots::Hash(index, index.slots()),
            EntriesIndex::Shared(index) => Slots::Hash(index, index.slots()),
        };
        MapIter {
            map: self.map,
            memory: self.memory,
            slots,
        }
    }

    /// [`Entries::iter`] with keys and values copied out as `K` and `V`; an array index is a 4 byte key. Fails with
    /// [`MapError::Invalid`] if `K` or `V` differs in size from the map's keys or values.
    pub fn iter_as<K: Pod, V: Pod>(&self) -> std::result::Result<impl Iterator<Item = (K, V)> + '_, MapError> {
        check_sizes::<K, V>(&self.map.def)?;
        Ok(self.iter().map(|(key, value)| {
            let key = match key {
                MapKey::Index(index) => K::from_bytes(&index.to_le_bytes()),
                MapKey::Bytes(bytes) => K::from_bytes(bytes),
            };
            let value = V::from_bytes(value);
            (key.expect("key size checked"), value.expect("value size checked"))
        }))
    }
}

impl<'a> IntoIterator for &'a Entries<'_> {
    type Item = (MapKey<'a>, &'a [u8]);
    type IntoIter = MapIter<'a>;

    fn into_iter(self) -> MapIter<'a> {
        self.iter()
    }
}

/// A key from [`MapIter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKey<'a> {
    /// An array map's index.
    Index(u32),
    /// A hash map's key.
    Bytes(&'a [u8]),
}

/// The keys and values of a map, read in place from guest memory; see [`Entries::iter`].
pub struct MapIter<'a> {
    map: &'a Map,
    memory: &'a VmMemory,
    slots: Slots<'a>,
}

enum Slots<'a> {
    Array(Range<u32>),
    Hash(&'a HashIndex, hash_table::Iter<'a, u32>),
}

impl<'a> Iterator for MapIter<'a> {
    type Item = (MapKey<'a>, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, slot) = match &mut self.slots {
            Slots::Array(indices) => {
                let index = indices.next()?;
                (MapKey::Index(index), index)
            }
            Slots::Hash(index, slots) => {
                let index: &'a HashIndex = index;
                let slot = *slots.next()?;
                (MapKey::Bytes(index.key(slot)), slot)
            }
        };
        let (addr, len) = (self.map.addr(slot), self.map.def.value_size as usize);
        let value = self.memory.bytes(addr, len).expect("map slots are mapped");
        Some((key, value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.slots {
            Slots::Array(indices) => indices.size_hint(),
            Slots::Hash(_, slots) => slots.size_hint(),
        }
    }
}

impl ExactSizeIterator for MapIter<'_> {}

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

/// Reject a map no program can use, or whose values or keys don't fit in a region with values padded to a cache line,
/// as shared maps may be.
pub fn check_def(def: &MapDef) -> std::result::Result<(), String> {
    let bad = |what: &str| Err(format!("map {}: {what}", def.name));
    if def.value_size == 0 || def.max_entries == 0 {
        return bad("zero value size or max_entries");
    }
    if def.kind == MapKind::Array && def.key_size != 4 {
        return bad("array map keys must be 4 bytes");
    }
    let entries = u64::from(def.max_entries);
    let values = u64::from(def.value_size).next_multiple_of(CACHE_LINE) * entries;
    if values.max(u64::from(def.key_size) * entries) > MAX_REGION_LEN as u64 {
        return bad("too large");
    }
    Ok(())
}

fn check_sizes<K: Pod, V: Pod>(def: &MapDef) -> std::result::Result<(), MapError> {
    if size_of::<K>() != def.key_size as usize || size_of::<V>() != def.value_size as usize {
        return Err(MapError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Perms;

    #[test]
    fn typed_access_and_iteration() {
        let def = |name: &str, kind, key_size, value_size| MapDef {
            name: name.into(),
            kind,
            key_size,
            value_size,
            max_entries: 3,
        };
        let defs = vec![def("hash", MapKind::Hash, 8, 8), def("array", MapKind::Array, 4, 16)];
        let (mut maps, len) = Maps::new(defs, &SharedMaps::default(), VmError::InvalidImage).unwrap();
        let mut memory = VmMemory::new();
        memory.map(MAPS_REGION, len, Perms::RW);

        let mut hash = MapRef::new(&mut maps, &mut memory, 0);
        assert_eq!(hash.entries().iter().len(), 0);
        assert_eq!(hash.get_as::<u64, u64>(1), Err(MapError::NotFound));
        assert_eq!(hash.get_as::<u64, u32>(1), Err(MapError::Invalid));
        assert_eq!(hash.get_as::<u32, u64>(1), Err(MapError::Invalid));
        assert_eq!(hash.update_as(1u64, 10u32, BPF_ANY), Err(MapError::Invalid));
        assert!(hash.entries().iter_as::<u64, u32>().is_err());

        // a deleted key leaves the iteration, and its slot goes to the next insert
        for key in 1..=3u64 {
            hash.update_as(key, key * 10, BPF_ANY).unwrap();
        }
        hash.delete(&2u64.to_le_bytes()).unwrap();
        let mut entries: Vec<(u64, u64)> = hash.entries().iter_as().unwrap().collect();
        entries.sort();
        assert_eq!(entries, [(1, 10), (3, 30)]);
        hash.update_as(4u64, 40u64, BPF_NOEXIST).unwrap();
        let mut entries: Vec<(u64, u64)> = hash.entries().iter_as().unwrap().collect();
        entries.sort();
        assert_eq!(entries, [(1, 10), (3, 30), (4, 40)]);
        assert_eq!(hash.get_as::<u64, u64>(2), Err(MapError::NotFound));

        // every array index exists, zeroed until written
        let mut array = MapRef::new(&mut maps, &mut memory, 1);
        array.update_as(1u32, [7u64, 8], BPF_ANY).unwrap();
        let values: Vec<(u32, [u64; 2])> = array.entries().iter_as().unwrap().collect();
        assert_eq!(values, [(0, [0, 0]), (1, [7, 8]), (2, [0, 0])]);
        assert_eq!(array.entries().iter().nth(1).unwrap().0, MapKey::Index(1));
        assert_eq!(array.get_as::<u32, [u64; 2]>(3), Err(MapError::NotFound));
    }
}
