//! Map declarations, as images carry them. Without the `maps` feature, an image that declares maps doesn't load.

#[cfg(any(feature = "maps", feature = "link"))]
use crate::error::{LinkError, Result};
#[cfg(any(feature = "maps", feature = "link"))]
use crate::memory::MAX_REGION_LEN;

#[cfg(feature = "link")]
mod btf;

#[cfg(feature = "link")]
pub use btf::map_defs;

#[cfg(any(feature = "maps", feature = "link"))]
pub const CACHE_LINE: u64 = 64;

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

/// Reject a map no program can use, or whose values or keys don't fit in a region with values padded to a cache line,
/// as shared maps may be.
#[cfg(any(feature = "maps", feature = "link"))]
pub fn check_def(def: &MapDef) -> Result<()> {
    let bad = |what: &str| Err(LinkError::InvalidMap(format!("map {}: {what}", def.name)).into());
    if def.value_size == 0 || def.max_entries == 0 {
        return bad("zero value size or max_entries");
    }
    if def.kind == MapKind::Array && def.key_size != 4 {
        return bad("array map keys must be 4 bytes");
    }
    if def.kind == MapKind::Hash && def.key_size == 0 {
        return bad("hash map key size must not be zero");
    }
    let entries = u64::from(def.max_entries);
    let values = u64::from(def.value_size).next_multiple_of(CACHE_LINE) * entries;
    if values.max(u64::from(def.key_size) * entries) > MAX_REGION_LEN as u64 {
        return bad("too large");
    }
    Ok(())
}
