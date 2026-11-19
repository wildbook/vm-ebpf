//! Maps shared by name between every program a VM links.

use std::sync::{Arc, Mutex, RwLock};

use super::hash::HashIndex;
use super::{MapDef, MapKind, CACHE_LINE, VALUE_ALIGN};
use crate::error::{LinkError, Result};
use crate::memory::{MemoryBudget, SharedBuffer, MAX_REGIONS};
use crate::sync::lock;

/// Maps that every program linked by one VM shares by name.
#[derive(Debug, Default)]
pub struct SharedMaps {
    state: Mutex<SharedState>,
}

#[derive(Debug, Default)]
struct SharedState {
    declared: Vec<Declared>,
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
        match state.declared.iter_mut().find(|d| d.name == name) {
            Some(d) => d.pad_values = pad_values,
            None => state.declared.push(Declared {
                name: name.to_string(),
                pad_values,
            }),
        }
    }

    /// The shared instance for `def`, created by the first program that declares it, which pays for it from `budget`.
    /// `None` if maps with this name aren't shared.
    pub fn bind(&self, def: &MapDef, budget: &mut MemoryBudget) -> Result<Option<Arc<SharedMap>>> {
        use crate::layout::SHARED_MAPS_FIRST_REGION;

        let mut state = lock(&self.state);
        if let Some(map) = state.bound.iter().find(|m| m.def.name == def.name) {
            if map.def != *def {
                return Err(LinkError::MapMismatch(def.name.clone()).into());
            }
            return Ok(Some(map.clone()));
        }
        let Some(&Declared { pad_values, .. }) = state.declared.iter().find(|d| d.name == def.name) else {
            return Ok(None);
        };

        let region = SHARED_MAPS_FIRST_REGION + state.next_region;
        if region >= MAX_REGIONS {
            return Err(LinkError::InvalidMap(format!("too many shared maps for {}", def.name)).into());
        }
        let stride = u64::from(def.value_size).next_multiple_of(if pad_values { CACHE_LINE } else { VALUE_ALIGN });
        let values = stride * u64::from(def.max_entries);
        budget.take(values)?;
        let storage = Arc::new(SharedBuffer::new(values as usize)?);
        let index = match def.kind {
            MapKind::Array => None,
            MapKind::Hash => Some(RwLock::new(HashIndex::new(def.key_size, def.max_entries, budget)?)),
        };
        let map = Arc::new(SharedMap {
            def: def.clone(),
            region,
            stride,
            storage,
            index,
        });
        state.next_region += 1;
        state.bound.push(map.clone());
        Ok(Some(map))
    }
}

/// A map name that [`SharedMaps::declare`] made shared.
#[derive(Debug)]
struct Declared {
    name: String,
    // pad values to a cache line
    pad_values: bool,
}
