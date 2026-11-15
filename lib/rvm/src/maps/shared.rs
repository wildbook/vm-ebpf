//! Maps shared by name between every program a VM links.

use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use hashbrown::HashMap;

use super::hash::HashIndex;
use super::{invalid, MapDef, MapKind, CACHE_LINE};
use crate::error::{LinkError, Result};
use crate::memory::{SharedBuffer, MAX_REGIONS};

pub fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

pub fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

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
    pub region: usize,
    pub stride: u64,
    storage: Arc<SharedBuffer>,
    pub index: Option<RwLock<HashIndex>>,
}

impl SharedMap {
    /// Guest region the values live in.
    pub fn region(&self) -> usize {
        self.region
    }

    /// The values' backing memory.
    pub fn storage(&self) -> &Arc<SharedBuffer> {
        &self.storage
    }
}

impl SharedMaps {
    /// Make maps called `name` shared by every program linked afterwards.
    pub fn declare(&self, name: &str, pad_values: bool) {
        lock(&self.state).declared.insert(name.to_string(), pad_values);
    }

    /// The shared instance for `def`, created by the first program that declares it.
    /// `None` if maps with this name aren't shared.
    pub fn bind(&self, def: &MapDef) -> Result<Option<Arc<SharedMap>>> {
        use crate::layout::SHARED_MAPS_FIRST_REGION;

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
            storage: Arc::new(SharedBuffer::new((stride * u64::from(def.max_entries)) as usize)),
            index: (def.kind == MapKind::Hash).then(|| RwLock::new(HashIndex::new(def.key_size, def.max_entries))),
        });
        state.next_region += 1;
        state.bound.insert(def.name.clone(), map.clone());
        Ok(Some(map))
    }
}
