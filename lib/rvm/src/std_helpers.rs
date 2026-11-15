//! Standard BPF helpers that touch host state. None is registered by default; a
//! host enables each with the matching `Vm::enable_*` call, and a program calling a
//! disabled one fails to link.

use std::cell::Cell;
use std::hash::BuildHasher;
use std::sync::LazyLock;
use std::time::Instant;

use crate::helper::{HelperContext, HelperRegistry};
use crate::memory::VmMemory;

/// `u64 bpf_ktime_get_ns(void)`
pub const BPF_FUNC_KTIME_GET_NS: u32 = 5;
/// `long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)`
pub const BPF_FUNC_TRACE_PRINTK: u32 = 6;
/// `u32 bpf_get_prandom_u32(void)`
pub const BPF_FUNC_GET_PRANDOM_U32: u32 = 7;

/// Name of a standard helper ID, for error messages.
pub fn helper_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "map_lookup_elem",
        2 => "map_update_elem",
        3 => "map_delete_elem",
        BPF_FUNC_KTIME_GET_NS => "ktime_get_ns",
        BPF_FUNC_TRACE_PRINTK => "trace_printk",
        BPF_FUNC_GET_PRANDOM_U32 => "get_prandom_u32",
        _ => return None,
    })
}

/// Register `ktime_get_ns`: monotonic nanoseconds since the first call in this process.
pub fn register_time(helpers: &mut HelperRegistry) {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    let start = *START;
    helpers.register(BPF_FUNC_KTIME_GET_NS, move |_: ()| start.elapsed().as_nanos() as u64);
}

/// Register `get_prandom_u32`: a per-thread xorshift generator with a random seed.
/// Not cryptographically secure, like the kernel's.
pub fn register_random(helpers: &mut HelperRegistry) {
    thread_local! {
        // foldhash seeds from address-space layout, so this needs no OS randomness
        static STATE: Cell<u64> = Cell::new(foldhash::fast::RandomState::default().hash_one(0u64) | 1);
    }
    helpers.register(BPF_FUNC_GET_PRANDOM_U32, |_: ()| {
        STATE.with(|state| {
            let mut x = state.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            state.set(x);
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
        })
    });
}

/// Register `trace_printk`, passing each formatted line to `sink`.
///
/// Supports the kernel's conversions: `%d %i %u %x %X %p %c %s %%` with `l`/`ll`
/// length modifiers, and up to three arguments. Returns the formatted length, or
/// -EINVAL if the format string isn't readable.
pub fn register_print(helpers: &mut HelperRegistry, sink: impl Fn(&str) + Send + Sync + 'static) {
    helpers.register_with_ctx(BPF_FUNC_TRACE_PRINTK, move |ctx: &mut HelperContext| -> i64 {
        const EINVAL: i64 = 22;
        let Some(mem) = ctx.memory.as_deref() else {
            return -EINVAL;
        };
        let Ok(fmt) = mem.bytes(ctx.args.r1, ctx.args.r2 as usize) else {
            return -EINVAL;
        };
        let line = format(mem, fmt, [ctx.args.r3, ctx.args.r4, ctx.args.r5]);
        sink(line.trim_end_matches('\n'));
        line.len() as i64
    });
}

fn format(mem: &VmMemory, fmt: &[u8], args: [u64; 3]) -> String {
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
fn guest_str(mem: &VmMemory, addr: u64) -> String {
    let bytes: Vec<u8> = (0..256)
        .map_while(|i| mem.read::<u8>(addr + i).ok())
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
