//! Standard BPF helper IDs, and the standard helpers that touch host state. None of those is registered by default; a
//! host enables each with the matching `Vm::enable_*` call, and a program calling a disabled one fails to link. The
//! map helpers are in `maps`.

use std::cell::Cell;
use std::hash::BuildHasher;
use std::sync::LazyLock;
use std::time::Instant;

use crate::helper::{HelperContext, HelperRegistry, HostFn};
use crate::memory::GuestMemory;

/// Declares the standard helpers: an ID constant for each, [`helper_name`] and, for tests, `STD_HELPERS`.
macro_rules! std_helpers {
    ($($(#[$doc:meta])* $id_const:ident = $id:literal, $name:literal;)*) => {
        $($(#[$doc])* pub const $id_const: u32 = $id;)*

        /// Name of a standard helper ID, for error messages.
        pub fn helper_name(id: u32) -> Option<&'static str> {
            match id {
                $($id_const => Some($name),)*
                _ => None,
            }
        }

        /// Every standard helper's ID and name.
        #[cfg(test)]
        pub const STD_HELPERS: &[(u32, &str)] = &[$(($id, $name)),*];
    };
}

// bpf/rvm_bpf.h declares these for C as `bpf_<name>`
std_helpers! {
    /// `void *map_lookup_elem(void *map, const void *key)`
    BPF_FUNC_MAP_LOOKUP_ELEM = 1, "map_lookup_elem";
    /// `long map_update_elem(void *map, const void *key, const void *value, u64 flags)`
    BPF_FUNC_MAP_UPDATE_ELEM = 2, "map_update_elem";
    /// `long map_delete_elem(void *map, const void *key)`
    BPF_FUNC_MAP_DELETE_ELEM = 3, "map_delete_elem";
    /// `u64 bpf_ktime_get_ns(void)`
    BPF_FUNC_KTIME_GET_NS = 5, "ktime_get_ns";
    /// `long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)`
    BPF_FUNC_TRACE_PRINTK = 6, "trace_printk";
    /// `u32 bpf_get_prandom_u32(void)`
    BPF_FUNC_GET_PRANDOM_U32 = 7, "get_prandom_u32";
}

/// `EINVAL`, which helpers return negated when an argument is invalid.
pub const EINVAL: i64 = 22;

/// Register `ktime_get_ns`: monotonic nanoseconds since the first time any VM in this process registered it.
pub fn register_time(helpers: &mut HelperRegistry) {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    let start = *START;
    let now = move |_: ()| start.elapsed().as_nanos() as u64;
    helpers.put_id(BPF_FUNC_KTIME_GET_NS, HostFn::typed(now));
}

/// Register `get_prandom_u32`: a per-thread xorshift generator with a random seed. Not cryptographically secure, like
/// the kernel's.
pub fn register_random(helpers: &mut HelperRegistry) {
    thread_local! {
        // foldhash seeds from address-space layout, so this needs no OS randomness
        static STATE: Cell<u64> = Cell::new(foldhash::fast::RandomState::default().hash_one(0u64) | 1);
    }
    let next = |_: ()| {
        STATE.with(|state| {
            let mut x = state.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            state.set(x);
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
        })
    };
    helpers.put_id(BPF_FUNC_GET_PRANDOM_U32, HostFn::typed(next));
}

/// Register `trace_printk`, passing each formatted line to `sink`.
///
/// Supports the kernel's conversions: `%d %i %u %x %X %p %c %s %%` with `l`/`ll` length modifiers, and up to three
/// arguments. Returns the formatted length, or -EINVAL if the format string isn't readable. The format string and `%s`
/// arguments are read with the guest's permissions.
pub fn register_print(helpers: &mut HelperRegistry, sink: impl Fn(&str) + Send + Sync + 'static) {
    let print = move |ctx: &mut HelperContext| {
        let mem = GuestMemory::new(ctx.memory);
        let Ok(fmt) = mem.read_vec(ctx.args.r1, ctx.args.r2 as usize) else {
            return Ok(-EINVAL as u64);
        };
        let line = format(&mem, &fmt, [ctx.args.r3, ctx.args.r4, ctx.args.r5]);
        sink(line.trim_end_matches('\n'));
        Ok(line.len() as u64)
    };
    helpers.put_id(BPF_FUNC_TRACE_PRINTK, HostFn::raw(print));
}

fn format(mem: &GuestMemory, fmt: &[u8], args: [u64; 3]) -> String {
    let fmt = fmt.split(|&b| b == 0).next().unwrap_or_default();
    let mut args = args.into_iter();
    let mut out = String::new();
    let mut i = 0;

    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' {
            out.push(c as char);
            continue;
        }

        let mut longs = 0;
        while fmt.get(i) == Some(&b'l') {
            longs += 1;
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            out.push('%');
            break;
        };
        i += 1;
        if conv == b'%' {
            out.push('%');
            continue;
        }

        let arg = args.next().unwrap_or(0);
        match (conv, longs) {
            (b'd' | b'i', 0) => out += &(arg as i32).to_string(),
            (b'd' | b'i', _) => out += &(arg as i64).to_string(),
            (b'u', 0) => out += &(arg as u32).to_string(),
            (b'u', _) => out += &arg.to_string(),
            (b'x', 0) => out += &format!("{:x}", arg as u32),
            (b'x', _) => out += &format!("{arg:x}"),
            (b'X', 0) => out += &format!("{:X}", arg as u32),
            (b'X', _) => out += &format!("{arg:X}"),
            (b'p', _) => out += &format!("{arg:#x}"),
            (b'c', _) => out.push(arg as u8 as char),
            (b's', _) => out += &guest_str(mem, arg),
            _ => {
                out.push('%');
                out.push(conv as char);
            }
        }
    }
    out
}

/// A NUL-terminated guest string, at most 256 bytes; unreadable bytes end it.
fn guest_str(mem: &GuestMemory, addr: u64) -> String {
    let bytes: Vec<u8> = (0..256)
        .map_while(|i| mem.read::<u8>(addr.wrapping_add(i)).ok())
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
