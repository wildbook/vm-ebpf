//! Standard map helpers (`map_lookup_elem`, `map_update_elem`, `map_delete_elem`).
//!
//! Keys and values come from guest pointers, read with the guest's own permissions, so a helper reads no memory the
//! program couldn't load from itself.

use crate::helper::{HelperContext, HelperRegistry};
use crate::memory::{Perms, VmMemory};

/// Helper ID of `void *map_lookup_elem(void *map, const void *key)`.
pub const BPF_FUNC_MAP_LOOKUP_ELEM: u32 = 1;
/// Helper ID of `long map_update_elem(void *map, const void *key, const void *value, u64 flags)`.
pub const BPF_FUNC_MAP_UPDATE_ELEM: u32 = 2;
/// Helper ID of `long map_delete_elem(void *map, const void *key)`.
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
    let Some(key) = readable(ctx.memory, ctx.args.r2, def.key_size as usize) else {
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
    if readable(ctx.memory, ctx.args.r3, value_size).is_none() {
        return -EINVAL;
    }
    let Some(key) = readable(ctx.memory, ctx.args.r2, key_size) else {
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
    let Some(key) = readable(ctx.memory, ctx.args.r2, def.key_size as usize) else {
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

/// `len` bytes at guest address `addr`, if the guest may read them.
fn readable(memory: &VmMemory, addr: u64, len: usize) -> Option<&[u8]> {
    let ptr = memory.host_ptr(addr, len, Perms::R).ok()?;
    // SAFETY: `host_ptr` checked that the range lies inside a live region, which the borrow of `memory` keeps mapped.
    Some(unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) })
}
