//! Standard map helpers (`map_lookup_elem`, `map_update_elem`, `map_delete_elem`).
//!
//! Keys and values come from guest pointers, read with the guest's own permissions, so a helper reads no memory the
//! program couldn't load from itself.

use super::Maps;
use crate::helper::{HelperContext, HelperRegistry, HostFn};
use crate::memory::{Perms, VmMemory};
use crate::std_helpers::{BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM, BPF_FUNC_MAP_UPDATE_ELEM, EINVAL};

pub const ENOENT: i64 = 2;
pub const E2BIG: i64 = 7;
pub const EEXIST: i64 = 17;

/// Maximum key size copied onto the stack before touching a map index; larger keys copy into a `Vec`.
const INLINE_KEY_LEN: usize = 64;

/// A map key copied out of guest memory through a raw pointer so no `&[u8]` is ever formed over shared or raw memory.
enum KeyBuf {
    Inline([u8; INLINE_KEY_LEN], usize),
    Heap(Vec<u8>),
}

impl KeyBuf {
    #[inline]
    fn copy_from(memory: &VmMemory, addr: u64, len: usize) -> Option<Self> {
        let src = memory.host_ptr(addr, len, Perms::R).ok()?;
        if len <= INLINE_KEY_LEN {
            let mut buf = [0u8; INLINE_KEY_LEN];
            // SAFETY: `host_ptr` checked that `src..src+len` is readable; `buf` is freshly stack-allocated.
            unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr(), len) };
            Some(Self::Inline(buf, len))
        } else {
            let mut buf = vec![0u8; len];
            // SAFETY: `host_ptr` checked that `src..src+len` is readable; `buf` is freshly heap-allocated.
            unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr(), len) };
            Some(Self::Heap(buf))
        }
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline(buf, len) => &buf[..*len],
            Self::Heap(buf) => buf,
        }
    }
}

/// Bind the map helpers to the built-in map implementation.
pub fn register_helpers(helpers: &mut HelperRegistry) {
    // each closure has its own type, so each slot calls its body directly
    helpers.put_id(BPF_FUNC_MAP_LOOKUP_ELEM, HostFn::raw(|ctx| Ok(lookup_elem(ctx) as u64)));
    helpers.put_id(BPF_FUNC_MAP_UPDATE_ELEM, HostFn::raw(|ctx| Ok(update_elem(ctx) as u64)));
    helpers.put_id(BPF_FUNC_MAP_DELETE_ELEM, HostFn::raw(|ctx| Ok(delete_elem(ctx) as u64)));
}

fn lookup_elem(ctx: &mut HelperContext) -> i64 {
    let Some(map) = MapArg::new(&mut ctx.host.maps, ctx.args.r1) else {
        return 0;
    };
    let Some(key) = KeyBuf::copy_from(ctx.memory, ctx.args.r2, map.key_size) else {
        return 0;
    };
    map.maps.lookup(map.handle, key.as_slice()).unwrap_or(0) as i64
}

fn update_elem(ctx: &mut HelperContext) -> i64 {
    let Some(map) = MapArg::new(&mut ctx.host.maps, ctx.args.r1) else {
        return -EINVAL;
    };

    // check the value before inserting the key, so a bad pointer changes nothing
    if ctx.memory.host_ptr(ctx.args.r3, map.value_size, Perms::R).is_err() {
        return -EINVAL;
    }
    let Some(key) = KeyBuf::copy_from(ctx.memory, ctx.args.r2, map.key_size) else {
        return -EINVAL;
    };
    let slot = match map.maps.upsert(map.handle, key.as_slice(), ctx.args.r4) {
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
    let Some(key) = KeyBuf::copy_from(ctx.memory, ctx.args.r2, map.key_size) else {
        return -EINVAL;
    };
    match map.maps.remove(map.handle, key.as_slice()) {
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
        let handle = u32::try_from(r1).ok()?;
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
