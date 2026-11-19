//! Standard map helpers (`map_lookup_elem`, `map_update_elem`, `map_delete_elem`).
//!
//! Keys and values come from guest pointers, read with the guest's own permissions, so a helper reads no memory the
//! program couldn't load from itself.

use super::Maps;
use crate::helper::{HelperContext, HelperRegistry};
use crate::memory::Perms;
use crate::std_helpers::{BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM, BPF_FUNC_MAP_UPDATE_ELEM, EINVAL};

pub const ENOENT: i64 = 2;
pub const E2BIG: i64 = 7;
pub const EEXIST: i64 = 17;

/// Bind the map helpers to the built-in map implementation.
pub fn register_helpers(helpers: &mut HelperRegistry) {
    // each fn item has its own type, so each slot calls its body directly
    helpers.register_helper_raw(BPF_FUNC_MAP_LOOKUP_ELEM, lookup_elem);
    helpers.register_helper_raw(BPF_FUNC_MAP_UPDATE_ELEM, update_elem);
    helpers.register_helper_raw(BPF_FUNC_MAP_DELETE_ELEM, delete_elem);
}

fn lookup_elem(ctx: &mut HelperContext) -> i64 {
    let Some(map) = MapArg::new(&mut ctx.host.maps, ctx.args.r1) else {
        return 0;
    };
    let Ok(key) = ctx.memory.slice(ctx.args.r2, map.key_size, Perms::R) else {
        return 0;
    };
    map.maps.lookup(map.handle, key).unwrap_or(0) as i64
}

fn update_elem(ctx: &mut HelperContext) -> i64 {
    let Some(map) = MapArg::new(&mut ctx.host.maps, ctx.args.r1) else {
        return -EINVAL;
    };

    // check the value before inserting the key, so a bad pointer changes nothing
    if ctx.memory.slice(ctx.args.r3, map.value_size, Perms::R).is_err() {
        return -EINVAL;
    }
    let Ok(key) = ctx.memory.slice(ctx.args.r2, map.key_size, Perms::R) else {
        return -EINVAL;
    };
    let slot = match map.maps.upsert(map.handle, key, ctx.args.r4) {
        Ok(slot) => slot,
        Err(e) => return -e.errno(),
    };
    ctx.memory
        .copy(ctx.args.r3, slot.addr, map.value_size)
        .expect("value checked above");
    0
}

fn delete_elem(ctx: &mut HelperContext) -> i64 {
    let Some(map) = MapArg::new(&mut ctx.host.maps, ctx.args.r1) else {
        return -EINVAL;
    };
    let Ok(key) = ctx.memory.slice(ctx.args.r2, map.key_size, Perms::R) else {
        return -EINVAL;
    };
    match map.maps.remove(map.handle, key) {
        Ok(slot) => {
            ctx.memory
                .zero(slot.addr, map.value_size)
                .expect("map slots are mapped");
            0
        }
        Err(e) => -e.errno(),
    }
}

/// The map a helper call names by its handle in r1.
struct MapArg<'a> {
    maps: &'a mut Maps,
    handle: u32,
    key_size: usize,
    value_size: usize,
}

impl<'a> MapArg<'a> {
    /// The map with handle `r1` among the calling program's `maps`, if it has one.
    #[inline]
    fn new(maps: &'a mut Maps, r1: u64) -> Option<Self> {
        let handle = r1 as u32;
        let def = maps.def(handle)?;
        let (key_size, value_size) = (def.key_size as usize, def.value_size as usize);
        Some(Self {
            maps,
            handle,
            key_size,
            value_size,
        })
    }
}
