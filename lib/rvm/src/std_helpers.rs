//! Standard BPF helper IDs, and the standard helpers that touch host state. None of those is registered by default; a
//! host enables each with the matching `Vm::enable_*` call, and a program calling a disabled one fails to link. The
//! map helpers are in `maps`.

use std::cell::Cell;
use std::hash::BuildHasher;
use std::sync::LazyLock;
use std::time::Instant;

use crate::helper::{HelperContext, HelperRegistry, HostFn, Stop};
use crate::memory::{GuestMemory, Perms};

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

/// Register checked `memset`, `memcpy`, `memmove` and `memcmp` builtins so clang-compiled code does not need
/// `-fno-builtin`. Each checks guest permissions and returns the original guest destination pointer.
pub fn register_mem_builtins(helpers: &mut HelperRegistry) {
    helpers.put_name("memset".into(), HostFn::raw(builtin_memset));
    helpers.put_name("memcpy".into(), HostFn::raw(builtin_memcpy));
    helpers.put_name("memmove".into(), HostFn::raw(builtin_memcpy));
    helpers.put_name("memcmp".into(), HostFn::raw(builtin_memcmp));
}

fn builtin_memset(ctx: &mut HelperContext) -> Result<u64, Stop> {
    let (dst, byte, len) = (ctx.args.r1, ctx.args.r2 as u8, ctx.args.r3);
    if len == 0 {
        return Ok(dst);
    }
    let Ok(len) = usize::try_from(len) else {
        return Err(Stop::MemoryFault(dst));
    };
    let ptr = ctx
        .memory
        .host_ptr(dst, len, Perms::W)
        .map_err(|e| Stop::MemoryFault(e.addr))?;
    // SAFETY: `host_ptr` checked `dst..dst+len` is writable guest memory.
    unsafe { ptr.as_ptr().write_bytes(byte, len) };
    Ok(dst)
}

/// Handles both `memcpy` and `memmove`; `ptr::copy` stays sound when guest ranges overlap.
fn builtin_memcpy(ctx: &mut HelperContext) -> Result<u64, Stop> {
    let (dst, src, len) = (ctx.args.r1, ctx.args.r2, ctx.args.r3);
    if len == 0 {
        return Ok(dst);
    }
    let Ok(len) = usize::try_from(len) else {
        return Err(Stop::MemoryFault(dst));
    };
    let src_ptr = ctx
        .memory
        .host_ptr(src, len, Perms::R)
        .map_err(|e| Stop::MemoryFault(e.addr))?;
    let dst_ptr = ctx
        .memory
        .host_ptr(dst, len, Perms::W)
        .map_err(|e| Stop::MemoryFault(e.addr))?;
    // SAFETY: `host_ptr` checked both ranges; `ptr::copy` allows overlap.
    unsafe { std::ptr::copy(src_ptr.as_ptr(), dst_ptr.as_ptr(), len) };
    Ok(dst)
}

fn builtin_memcmp(ctx: &mut HelperContext) -> Result<u64, Stop> {
    let (a, b, len) = (ctx.args.r1, ctx.args.r2, ctx.args.r3);
    if len == 0 {
        return Ok(0);
    }
    let Ok(len) = usize::try_from(len) else {
        return Err(Stop::MemoryFault(a));
    };
    let mut pa = ctx
        .memory
        .host_ptr(a, len, Perms::R)
        .map_err(|e| Stop::MemoryFault(e.addr))?
        .as_ptr() as *const u8;
    let mut pb = ctx
        .memory
        .host_ptr(b, len, Perms::R)
        .map_err(|e| Stop::MemoryFault(e.addr))?
        .as_ptr() as *const u8;
    let mut rem = len;
    // Compare 8 bytes at a time through raw pointers so shared or raw memory is never borrowed as `&[u8]`.
    while rem >= 8 {
        // SAFETY: `host_ptr` checked `rem <= len` readable bytes from both pointers.
        let (wa, wb) = unsafe { (pa.cast::<u64>().read_unaligned(), pb.cast::<u64>().read_unaligned()) };
        if wa != wb {
            break;
        }
        // SAFETY: `rem >= 8`, both stay within the checked range.
        unsafe {
            pa = pa.add(8);
            pb = pb.add(8);
        }
        rem -= 8;
    }
    for i in 0..rem {
        // SAFETY: `i < rem`, within the checked range.
        let (ba, bb) = unsafe { (*pa.add(i), *pb.add(i)) };
        if ba != bb {
            return Ok((i32::from(ba) - i32::from(bb)) as i64 as u64);
        }
    }
    Ok(0)
}

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

/// Maximum format string length accepted by `bpf_trace_printk`.
const MAX_PRINTK_FMT: usize = 4096;

/// Register `trace_printk`, passing each formatted line to `sink`.
///
/// Supports the kernel's conversions: `%d %i %u %x %X %p %c %s %%` with `l`/`ll` length modifiers, and up to three
/// arguments. Returns the formatted length, or -EINVAL if the format string isn't readable or exceeds 4096 bytes. The
/// format string and `%s` arguments are read with the guest's permissions.
pub fn register_print(helpers: &mut HelperRegistry, sink: impl Fn(&str) + Send + Sync + 'static) {
    let print = move |ctx: &mut HelperContext| {
        if ctx.args.r2 > MAX_PRINTK_FMT as u64 {
            return Ok(-EINVAL as u64);
        }
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

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R1, R2};

    use super::*;
    use crate::{Image, Vm};

    #[test]
    fn trace_printk_rejects_oversized_fmt() {
        let vm = Vm::new();
        vm.enable_print(|_| panic!("sink must not be called for oversized format string"));

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 0)
            .mov64_imm(R2, (MAX_PRINTK_FMT + 1) as i32)
            .call(BPF_FUNC_TRACE_PRINTK as i32)
            .exit();
        let mut prog = vm.load_image(Image::from_code(asm.assemble().unwrap())).unwrap();
        assert_eq!(prog.call("main", &[]).unwrap(), (-EINVAL) as u64);
    }

    #[test]
    fn mem_builtins_check_perms_and_keep_tag() {
        use crate::{ExecError, Import, Perms, VmError};

        let vm = Vm::new();
        let call_named = |name: &str| {
            let mut asm = Assembler::new();
            asm.call(0).exit();
            let mut img = Image::from_code(asm.assemble().unwrap());
            img.add_call(0, Import::name(name));
            vm.load_image(img).unwrap()
        };

        let mut p_set = call_named("memset");
        let rw = p_set.memory_mut().map(32, Perms::RW).unwrap().base();
        let ro = p_set.memory_mut().map_bytes(b"abcdef", 8, Perms::R).unwrap().base();
        assert_eq!(p_set.call("main", &[rw, 0x5A, 12]).unwrap(), rw);
        assert_eq!(p_set.call("main", &[0, 0xFF, 0]).unwrap(), 0);
        assert_eq!(p_set.memory().bytes(rw, 13).unwrap(), &[0x5A; 12].into_iter().chain([0]).collect::<Vec<_>>()[..]);
        assert!(matches!(p_set.call("main", &[ro, 1, 4]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));

        // Overlapping memcpy stays sound and returns tagged dst
        let mut p_cpy = call_named("memcpy");
        let buf = p_cpy.memory_mut().map_bytes(b"abcdefgh", 16, Perms::RW).unwrap().base();
        assert_eq!(p_cpy.call("main", &[buf + 2, buf, 6]).unwrap(), buf + 2);
        assert_eq!(p_cpy.memory().bytes(buf, 8).unwrap(), b"ababcdef");

        let mut p_cmp = call_named("memcmp");
        let a = p_cmp
            .memory_mut()
            .map_bytes(b"0123456789ab", 16, Perms::R)
            .unwrap()
            .base();
        let b = p_cmp
            .memory_mut()
            .map_bytes(b"0123456789ac", 16, Perms::R)
            .unwrap()
            .base();
        assert_eq!(p_cmp.call("main", &[a, a, 12]).unwrap(), 0);
        assert!((p_cmp.call("main", &[a, b, 12]).unwrap() as i64) < 0);
        assert!((p_cmp.call("main", &[b, a, 12]).unwrap() as i64) > 0);
    }
}
