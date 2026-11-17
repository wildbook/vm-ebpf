//! Fixed-capacity hash index used by hash maps.

use std::hash::BuildHasher;

use hashbrown::hash_table::{self, Entry};
use hashbrown::HashTable;

use super::{MapError, BPF_EXIST, BPF_NOEXIST};

// The default seed comes from address-space layout, which Windows randomizes per
// executable per boot: two builds of the same source then probe differently, which
// changes guest timing and PGO profiles. Benchmarks fix it; a fixed seed lets guest
// code choose colliding keys, so production builds keep the random one.
#[cfg(feature = "fixed-hash-seed")]
type Seed = foldhash::fast::FixedState;
#[cfg(not(feature = "fixed-hash-seed"))]
type Seed = foldhash::fast::RandomState;

/// Fixed-capacity hash index: keys live in one preallocated block at their value's
/// slot, and the table holds slot numbers, so inserts never allocate.
#[derive(Debug, Clone)]
pub struct HashIndex {
    table: HashTable<u32>,
    keys: Box<[u8]>,
    key_size: usize,
    free: Vec<u32>,
    hasher: Seed,
}

impl HashIndex {
    pub fn new(key_size: u32, max_entries: u32) -> Self {
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

    /// Occupied slots, in table order.
    pub fn slots(&self) -> hash_table::Iter<'_, u32> {
        self.table.iter()
    }

    /// The key stored at `slot`.
    pub fn key(&self, slot: u32) -> &[u8] {
        Self::key_at(&self.keys, self.key_size, slot)
    }

    #[inline]
    pub fn get(&self, key: &[u8]) -> Option<u32> {
        let hash = self.hasher.hash_one(key);
        self.table
            .find(hash, |&slot| Self::key_at(&self.keys, self.key_size, slot) == key)
            .copied()
    }

    pub fn upsert(&mut self, key: &[u8], flags: u64) -> std::result::Result<u32, MapError> {
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

    pub fn remove(&mut self, key: &[u8]) -> std::result::Result<u32, MapError> {
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
