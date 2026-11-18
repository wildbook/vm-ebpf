//! Maps shared by name between every program a VM links.

use std::sync::{Arc, Mutex, RwLock};

use super::hash::HashIndex;
use super::{MapDef, MapKind, CACHE_LINE};
use crate::error::{LinkError, Result};
use crate::memory::{SharedBuffer, MAX_REGIONS};
use crate::sync::lock;

/// Maps that every program linked by one VM shares by name.
#[derive(Debug, Default)]
pub struct SharedMaps {
    state: Mutex<SharedState>,
}

#[derive(Debug, Default)]
struct SharedState {
    // name, pad values to a cache line
    declared: Vec<(String, bool)>,
    bound: Vec<Arc<SharedMap>>,
    next_region: usize,
}

/// One shared map: its storage and, for hash maps, the key index.
#[derive(Debug)]
pub struct SharedMap {
    def: MapDef,
    pub region: usize,
    pub stride: u64,
    pub storage: Arc<SharedBuffer>,
    pub index: Option<RwLock<HashIndex>>,
}

impl SharedMaps {
    /// Make maps called `name` shared by every program linked afterwards.
    pub fn declare(&self, name: &str, pad_values: bool) {
        let mut state = lock(&self.state);
        match state.declared.iter_mut().find(|e| e.0 == name) {
            Some(e) => e.1 = pad_values,
            None => state.declared.push((name.to_string(), pad_values)),
        }
    }

    /// The shared instance for `def`, created by the first program that declares it. `None` if maps with this name
    /// aren't shared.
    pub fn bind(&self, def: &MapDef) -> Result<Option<Arc<SharedMap>>> {
        use crate::layout::SHARED_MAPS_FIRST_REGION;

        let mut state = lock(&self.state);
        if let Some(map) = state.bound.iter().find(|m| m.def.name == def.name) {
            if map.def != *def {
                return Err(LinkError::MapMismatch(def.name.clone()).into());
            }
            return Ok(Some(map.clone()));
        }
        let Some(&(_, pad_values)) = state.declared.iter().find(|e| e.0 == def.name) else {
            return Ok(None);
        };

        let region = SHARED_MAPS_FIRST_REGION + state.next_region;
        if region >= MAX_REGIONS {
            return Err(LinkError::InvalidMap(format!("too many shared maps for {}", def.name)).into());
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
        state.bound.push(map.clone());
        Ok(Some(map))
    }
}
