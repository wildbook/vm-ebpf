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

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use hashbrown::hash_table::Entry;
use hashbrown::HashTable;

use btf::{Btf, BtfTypeInfo};

use crate::error::{LinkError, Result, VmError};
use crate::helper::{HelperContext, HelperRegistry};
use crate::memory::{region_base, Perms, VmMemory, MAX_REGIONS};
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

/// Fixed-capacity hash index: keys live in one preallocated block at their value's
/// slot, and the table holds slot numbers, so inserts never allocate.
#[derive(Debug, Clone)]
struct HashIndex {
    table: HashTable<u32>,
    keys: Box<[u8]>,
    key_size: usize,
    free: Vec<u32>,
    hasher: foldhash::fast::RandomState,
}

impl HashIndex {
    fn new(key_size: u32, max_entries: u32) -> Self {
        let key_size = key_size as usize;
        Self {
            table: HashTable::with_capacity(max_entries as usize),
            keys: vec![0; key_size * max_entries as usize].into(),
            key_size,
            free: (0..max_entries).rev().collect(),
            hasher: Default::default(),
        }
    }

    fn key_at(keys: &[u8], key_size: usize, slot: u32) -> &[u8] {
        &keys[slot as usize * key_size..][..key_size]
    }

    #[inline]
    fn get(&self, key: &[u8]) -> Option<u32> {
        let hash = self.hasher.hash_one(key);
        self.table
            .find(hash, |&slot| Self::key_at(&self.keys, self.key_size, slot) == key)
            .copied()
    }

    fn upsert(&mut self, key: &[u8], flags: u64) -> std::result::Result<u32, MapError> {
        let Self {
            table,
            keys,
            key_size,
            free,
            hasher,
        } = self;
        let hash = hasher.hash_one(key);
        match table.entry(
            hash,
            |&slot| Self::key_at(keys, *key_size, slot) == key,
            |&slot| hasher.hash_one(Self::key_at(keys, *key_size, slot)),
        ) {
            Entry::Occupied(_) if flags == BPF_NOEXIST => Err(MapError::Exists),
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(_) if flags == BPF_EXIST => Err(MapError::NotFound),
            Entry::Vacant(entry) => {
                let slot = free.pop().ok_or(MapError::Full)?;
                keys[slot as usize * *key_size..][..*key_size].copy_from_slice(key);
                entry.insert(slot);
                Ok(slot)
            }
        }
    }

    fn remove(&mut self, key: &[u8]) -> std::result::Result<u32, MapError> {
        let hash = self.hasher.hash_one(key);
        let (keys, key_size) = (&self.keys, self.key_size);
        let entry = self
            .table
            .find_entry(hash, |&slot| Self::key_at(keys, key_size, slot) == key)
            .map_err(|_| MapError::NotFound)?;
        let (slot, _) = entry.remove();
        self.free.push(slot);
        Ok(slot)
    }
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

    /// Number of maps.
    pub fn len(&self) -> usize {
        self.maps.len()
    }

    /// Whether the program declares no maps.
    pub fn is_empty(&self) -> bool {
        self.maps.is_empty()
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

    /// Insert or replace the value for `key`; see [`Maps::upsert`] for `flags`.
    pub fn update(
        &mut self,
        mem: &mut VmMemory,
        handle: u32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> std::result::Result<(), MapError> {
        if self.def(handle).is_none_or(|def| value.len() != def.value_size as usize) {
            return Err(MapError::Invalid);
        }
        let addr = self.upsert(handle, key, flags)?;
        mem.write_bytes(addr, value).expect("map slots are mapped");
        Ok(())
    }

    /// Remove `key` and zero its value.
    pub fn delete(&mut self, mem: &mut VmMemory, handle: u32, key: &[u8]) -> std::result::Result<(), MapError> {
        let addr = self.remove(handle, key)?;
        let len = self.maps[handle as usize].def.value_size as usize;
        mem.bytes_mut(addr, len).expect("map slots are mapped").fill(0);
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

fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// First guest region used for shared maps; each shared map has its own region at
/// the same address in every program.
pub const SHARED_MAPS_FIRST_REGION: usize = MAX_REGIONS / 2;

/// Maps that every program linked by one VM shares by name.
#[derive(Debug, Default)]
pub struct SharedMaps {
    state: Mutex<SharedState>,
}

#[derive(Debug, Default)]
struct SharedState {
    // name -> pad values to a cache line
    declared: HashMap<String, bool>,
    bound: HashMap<String, Arc<SharedMap>>,
    next_region: usize,
}

/// One shared map: its storage and, for hash maps, the key index.
#[derive(Debug)]
pub struct SharedMap {
    def: MapDef,
    region: usize,
    stride: u64,
    storage: Storage,
    index: Option<RwLock<HashIndex>>,
}

impl SharedMap {
    /// Guest region the values live in.
    pub fn region(&self) -> usize {
        self.region
    }

    /// Host pointer and length of the values.
    pub fn storage(&self) -> (NonNull<u8>, usize) {
        (self.storage.ptr, self.storage.len)
    }
}

impl SharedMaps {
    /// Make maps called `name` shared by every program linked afterwards.
    pub fn declare(&self, name: &str, pad_values: bool) {
        lock(&self.state).declared.insert(name.to_string(), pad_values);
    }

    /// The shared instance for `def`, created by the first program that declares it.
    /// `None` if maps with this name aren't shared.
    fn bind(&self, def: &MapDef) -> Result<Option<Arc<SharedMap>>> {
        let mut state = lock(&self.state);
        if let Some(map) = state.bound.get(&def.name) {
            if map.def != *def {
                return Err(LinkError::MapMismatch(def.name.clone()).into());
            }
            return Ok(Some(map.clone()));
        }
        let Some(&pad_values) = state.declared.get(&def.name) else {
            return Ok(None);
        };

        let region = SHARED_MAPS_FIRST_REGION + state.next_region;
        if region >= MAX_REGIONS {
            return Err(invalid(format!("too many shared maps for {}", def.name)));
        }
        let stride = u64::from(def.value_size).next_multiple_of(if pad_values { CACHE_LINE } else { 8 });
        let map = Arc::new(SharedMap {
            def: def.clone(),
            region,
            stride,
            storage: Storage::new((stride * u64::from(def.max_entries)) as usize),
            index: (def.kind == MapKind::Hash).then(|| RwLock::new(HashIndex::new(def.key_size, def.max_entries))),
        });
        state.next_region += 1;
        state.bound.insert(def.name.clone(), map.clone());
        Ok(Some(map))
    }
}

/// Zeroed, cache-line aligned host memory.
#[derive(Debug)]
struct Storage {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: plain heap memory owned by this value; concurrent guest access is governed
// by the contract of `Vm::share_map`.
unsafe impl Send for Storage {}
unsafe impl Sync for Storage {}

impl Storage {
    fn new(len: usize) -> Self {
        let layout = Self::layout(len);
        // SAFETY: non-zero size (`max_entries` and `value_size` are non-zero).
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr, len }
    }

    fn layout(len: usize) -> Layout {
        Layout::from_size_align(len, CACHE_LINE as usize).expect("map storage layout")
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout.
        unsafe { dealloc(self.ptr.as_ptr(), Self::layout(self.len)) };
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
    // one closure type per helper, so each slot calls its body directly
    if !helpers.has(BPF_FUNC_MAP_LOOKUP_ELEM) {
        helpers.register_with_ctx(BPF_FUNC_MAP_LOOKUP_ELEM, |ctx: &mut HelperContext| lookup_elem(ctx));
    }
    if !helpers.has(BPF_FUNC_MAP_UPDATE_ELEM) {
        helpers.register_with_ctx(BPF_FUNC_MAP_UPDATE_ELEM, |ctx: &mut HelperContext| update_elem(ctx));
    }
    if !helpers.has(BPF_FUNC_MAP_DELETE_ELEM) {
        helpers.register_with_ctx(BPF_FUNC_MAP_DELETE_ELEM, |ctx: &mut HelperContext| delete_elem(ctx));
    }
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
    let (key_size, value_size) = (def.key_size as usize, def.value_size as usize);

    // check the value before inserting the key, so a bad pointer changes nothing
    if mem.bytes(ctx.args.r3, value_size).is_err() {
        return -EINVAL;
    }
    let Ok(key) = mem.bytes(ctx.args.r2, key_size) else {
        return -EINVAL;
    };
    let addr = match maps.upsert(handle, key, ctx.args.r4) {
        Ok(addr) => addr,
        Err(e) => return -e.errno(),
    };
    mem.copy(ctx.args.r3, addr, value_size).expect("value checked above");
    0
}

fn delete_elem(ctx: &mut HelperContext) -> i64 {
    let (Some(mem), Some(maps)) = (ctx.memory.as_deref_mut(), ctx.maps.as_deref_mut()) else {
        return -EINVAL;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return -EINVAL;
    };
    let value_size = def.value_size as usize;
    let Ok(key) = mem.bytes(ctx.args.r2, def.key_size as usize) else {
        return -EINVAL;
    };
    match maps.remove(handle, key) {
        Ok(addr) => {
            mem.bytes_mut(addr, value_size).expect("map slots are mapped").fill(0);
            0
        }
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
