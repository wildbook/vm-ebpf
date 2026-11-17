//! Standard map helpers (`map_lookup_elem`, `map_update_elem`, `map_delete_elem`).

use crate::helper::{HelperContext, HelperRegistry};

/// Standard helper IDs bound to the built-in map implementation.
pub const BPF_FUNC_MAP_LOOKUP_ELEM: u32 = 1;
pub const BPF_FUNC_MAP_UPDATE_ELEM: u32 = 2;
pub const BPF_FUNC_MAP_DELETE_ELEM: u32 = 3;

pub const ENOENT: i64 = 2;
pub const E2BIG: i64 = 7;
pub const EEXIST: i64 = 17;
pub const EINVAL: i64 = 22;

/// Bind helpers 1 to 3 to the built-in map implementation unless the host registered its own under those IDs.
pub fn register_helpers(helpers: &mut HelperRegistry) {
    // one closure type per helper, so each slot calls its body directly
    if helpers.slot_of_id(BPF_FUNC_MAP_LOOKUP_ELEM).is_none() {
        helpers.register_with_ctx(BPF_FUNC_MAP_LOOKUP_ELEM, |ctx: &mut HelperContext| lookup_elem(ctx));
    }
    if helpers.slot_of_id(BPF_FUNC_MAP_UPDATE_ELEM).is_none() {
        helpers.register_with_ctx(BPF_FUNC_MAP_UPDATE_ELEM, |ctx: &mut HelperContext| update_elem(ctx));
    }
    if helpers.slot_of_id(BPF_FUNC_MAP_DELETE_ELEM).is_none() {
        helpers.register_with_ctx(BPF_FUNC_MAP_DELETE_ELEM, |ctx: &mut HelperContext| delete_elem(ctx));
    }
}

fn lookup_elem(ctx: &mut HelperContext) -> i64 {
    let Some(maps) = ctx.maps.as_deref() else {
        return 0;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return 0;
    };
    let Ok(key) = ctx.memory.bytes(ctx.args.r2, def.key_size as usize) else {
        return 0;
    };
    maps.lookup(handle, key).unwrap_or(0) as i64
}

fn update_elem(ctx: &mut HelperContext) -> i64 {
    let Some(maps) = ctx.maps.as_deref_mut() else {
        return -EINVAL;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return -EINVAL;
    };
    let (key_size, value_size) = (def.key_size as usize, def.value_size as usize);

    // check the value before inserting the key, so a bad pointer changes nothing
    if ctx.memory.bytes(ctx.args.r3, value_size).is_err() {
        return -EINVAL;
    }
    let Ok(key) = ctx.memory.bytes(ctx.args.r2, key_size) else {
        return -EINVAL;
    };
    let addr = match maps.upsert(handle, key, ctx.args.r4) {
        Ok(addr) => addr,
        Err(e) => return -e.errno(),
    };
    ctx.memory
        .copy(ctx.args.r3, addr, value_size)
        .expect("value checked above");
    0
}

fn delete_elem(ctx: &mut HelperContext) -> i64 {
    let Some(maps) = ctx.maps.as_deref_mut() else {
        return -EINVAL;
    };
    let handle = ctx.args.r1 as u32;
    let Some(def) = maps.def(handle) else {
        return -EINVAL;
    };
    let value_size = def.value_size as usize;
    let Ok(key) = ctx.memory.bytes(ctx.args.r2, def.key_size as usize) else {
        return -EINVAL;
    };
    match maps.remove(handle, key) {
        Ok(addr) => {
            ctx.memory
                .bytes_mut(addr, value_size)
                .expect("map slots are mapped")
                .fill(0);
            0
        }
        Err(e) => -e.errno(),
    }
}
