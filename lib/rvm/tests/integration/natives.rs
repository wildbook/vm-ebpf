//! Native functions: checked pointers, signature/resolver rejections, `__host` pointers, resolver caching,
//! `&extern` tokens, `GENERAL` FFI marshalling, and aware native failures.

use rvm::{
    ExecError, Image, Import, LinkError, MemoryError, NativeArg, NativeImport, NativeSig, Passthrough, Program,
    Resolved, Vm, VmConfig, VmError, STACK_REGION,
};

use crate::common::object;

extern "C" fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

extern "C" fn five(a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
    a + 10 * b + 100 * c + 1000 * d + 10_000 * e
}

/// # Safety
///
/// `buf` must point to `len` readable bytes, or `len` be 0.
unsafe extern "C" fn sum(buf: *const u8, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    bytes.iter().map(|&b| u64::from(b)).sum()
}

/// # Safety
///
/// `buf` must point to `len` writable bytes.
unsafe extern "C" fn fill(buf: *mut u8, len: u64, byte: u64) -> u64 {
    unsafe { buf.write_bytes(byte as u8, len as usize) };
    0
}

/// # Safety
///
/// `p` must point to a readable byte.
unsafe extern "C" fn first(p: *const u8) -> u64 {
    unsafe { p.read() }.into()
}

const SUM: NativeSig = NativeSig::new(&[NativeArg::Read(Some(2)), NativeArg::Int]);
const FILL: NativeSig = NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int, NativeArg::Int]);
const FIRST: NativeSig = NativeSig::new(&[NativeArg::Read(None)]);

fn vm_with_sigs(config: VmConfig, add_sig: NativeSig, sum_sig: NativeSig) -> Vm {
    let natives = [
        ("nat_add", add as *const (), add_sig),
        ("nat_five", five as *const (), NativeSig::ints(5)),
        ("nat_sum", sum as *const (), sum_sig),
        ("nat_fill", fill as *const (), FILL),
        ("nat_first", first as *const (), FIRST),
    ];
    // SAFETY: each function takes its signature's arguments, never unwinds, and accesses only checked bytes.
    unsafe { Vm::with_natives(config, &natives) }.unwrap()
}

fn load(vm: &Vm) -> Program {
    vm.load_elf(&object("tests/native_calls.o")).unwrap()
}

fn fault(result: rvm::Result<u64>) -> MemoryError {
    match result {
        Err(VmError::Exec(ExecError::MemoryFault { error, .. })) => error,
        other => panic!("expected a memory fault, got {other:?}"),
    }
}

/// Checked native pointers resolve to host addresses and fault on overruns, bad tags, null, or read-only writes.
#[test]
fn pointer_arguments_resolve() {
    let mut program = load(&vm_with_sigs(VmConfig::default(), NativeSig::ints(2), SUM));
    assert_eq!(program.call("add", &[2, 3]).unwrap(), 5);
    assert_eq!(program.call("five", &[]).unwrap(), 54_321);
    assert_eq!(program.call("sum", &[]).unwrap(), 136);
    assert_eq!(program.call("fill", &[]).unwrap(), 24);
    assert_eq!(program.call("sum_empty", &[]).unwrap(), 0);

    let stack_end = program.memory().region_base(STACK_REGION) + program.memory().region_len(STACK_REGION) as u64;
    assert_eq!(
        fault(program.call("overrun", &[])),
        MemoryError {
            addr: stack_end,
            size: 1
        }
    );
    for addr in [rvm::region_tag(5) | 0x1234, 0x1234, 0] {
        assert_eq!(fault(program.call("first", &[addr])), MemoryError { addr, size: 1 });
    }
    let err = fault(program.call("fill_rodata", &[]));
    assert_eq!(err.addr >> rvm::REGION_SHIFT, rvm::RODATA_REGION as u64);
}

/// Image loading checks declared BTF prototypes against registered/resolved signatures, and rejects declined or null
/// resolver results.
#[test]
fn signature_and_resolver_rejections() {
    let image = Vm::new()
        .prepare_elf(&object("tests/native_calls.o"))
        .unwrap()
        .to_bytes();

    let err = vm_with_sigs(VmConfig::default(), NativeSig::ints(3), SUM)
        .load_image_bytes(&image)
        .unwrap_err();
    assert!(
        matches!(&err, VmError::Link(LinkError::SignatureMismatch { name, declared: 2, host: 3 }) if name == "nat_add"),
        "{err}"
    );

    let read_one = NativeSig::new(&[NativeArg::Read(None), NativeArg::Int]);
    let write = NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int]);
    for sum_sig in [NativeSig::ints(2), read_one, write] {
        let err = vm_with_sigs(VmConfig::default(), NativeSig::ints(2), sum_sig)
            .load_image_bytes(&image)
            .unwrap_err();
        assert!(matches!(&err, VmError::Link(LinkError::NativeMismatch { name, .. }) if name == "nat_sum"), "{err}");
    }

    let vm = Vm::new();
    // SAFETY: resolver returns None
    unsafe { vm.set_native_resolver(|_| None) };
    assert!(matches!(vm.load_image_bytes(&image).unwrap_err(), VmError::Link(LinkError::UnresolvedSymbol(_))));

    let vm = Vm::new();
    // SAFETY: load fails before binding because func is null
    unsafe {
        vm.set_native_resolver(|_| {
            Some(Resolved {
                func: std::ptr::null(),
                sig: None,
            })
        });
    }
    assert!(matches!(vm.load_image_bytes(&image).unwrap_err(), VmError::InvalidArgument(_)));
}

/// A native function follows `__host` pointers that a plugin placed in a struct with `HOST()`, in every memory mode.
#[test]
fn native_follows_host_pointer_in_struct() {
    #[repr(C)]
    struct IoVec {
        base: *const u8,
        len: u64,
    }

    unsafe extern "C" fn sum_iovec(parts: *const IoVec, byte_len: u64) -> u64 {
        let vecs = unsafe { std::slice::from_raw_parts(parts, byte_len as usize / size_of::<IoVec>()) };
        vecs.iter()
            .flat_map(|v| unsafe { std::slice::from_raw_parts(v.base, v.len as usize) })
            .map(|&b| u64::from(b))
            .sum()
    }

    let sig = NativeSig::new(&[NativeArg::Read(Some(2)), NativeArg::Int]);
    // SAFETY: `sum_parts` fills `parts` with host pointers to live stack and `.rodata` bytes
    let (on, untagged) = unsafe { (Passthrough::on(), Passthrough::untagged()) };
    for passthrough in [Passthrough::OFF, on, untagged] {
        let vm = Vm::with_config(VmConfig {
            passthrough,
            ..VmConfig::default()
        })
        .unwrap();
        // SAFETY: `sum_iovec` reads only checked bytes and valid `IoVec` slices
        unsafe { vm.register_native("sum_iovec", sum_iovec as *const (), sig) }.unwrap();
        let mut program = vm.load_elf(&object("tests/host_ptr.o")).unwrap();
        assert_eq!(program.call("sum_parts", &[]).unwrap(), 1 + 2 + 3 + 4 + 10 + 20 + 30);
    }
}

/// A native resolver binds and caches imports once per VM, strips or checks pointers (in registers and stack slots),
/// passes small structs by value, coexists with host closures, and falls back to `RAW` without BTF.
#[test]
fn native_resolver_binds_and_caches() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    extern "C" fn res_add(a: u64, b: u64) -> u64 {
        a.wrapping_mul(10).wrapping_add(b)
    }
    extern "C" fn alias_target(x: u64) -> u64 {
        x.wrapping_mul(7).wrapping_add(3)
    }
    unsafe extern "C" fn c_strlen(s: *const u8) -> u64 {
        if s.is_null() {
            return 0xffff;
        }
        let mut len = 0usize;
        while unsafe { *s.add(len) } != 0 {
            len += 1;
        }
        len as u64
    }
    unsafe extern "C" fn res_stack_sum(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, buf: *const u8) -> u64 {
        let bytes = unsafe { std::slice::from_raw_parts(buf, 4) };
        a + b + c + d + e + f + bytes.iter().map(|&x| u64::from(x)).sum::<u64>()
    }
    #[repr(C)]
    struct S8 {
        a: u32,
        b: u32,
    }
    extern "C" fn res_small_struct(d: S8) -> S8 {
        S8 { a: d.a + 1, b: d.b + 2 }
    }
    extern "C" fn res_plain(a: u64, b: u64) -> u64 {
        a ^ b
    }

    let lookup = |imp: &NativeImport<'_>, checked: bool| -> Option<Resolved> {
        let (func, sig) = match (imp.dll, imp.name) {
            (Some("host.dll"), "res_add") => (res_add as *const (), NativeSig::ints(2)),
            (Some("host.dll"), "alias_target") => (alias_target as *const (), NativeSig::ints(1)),
            (Some("ucrtbase.dll"), "strlen") => (c_strlen as *const (), NativeSig::new(&[NativeArg::Read(None)])),
            (Some("host.dll"), "res_stack_sum") => (
                res_stack_sum as *const (),
                NativeSig::new(&[
                    NativeArg::Int,
                    NativeArg::Int,
                    NativeArg::Int,
                    NativeArg::Int,
                    NativeArg::Int,
                    NativeArg::Int,
                    NativeArg::Read(None),
                ]),
            ),
            (Some("host.dll"), "res_small_struct") => (res_small_struct as *const (), NativeSig::ints(1)),
            (None, "res_plain") => (res_plain as *const (), NativeSig::ints(2)),
            _ => return None,
        };
        Some(Resolved {
            func,
            sig: checked.then_some(sig),
        })
    };

    let image = Vm::new().prepare_elf(&object("tests/resolver.o")).unwrap();
    let image_bytes = image.to_bytes();
    assert_eq!(Image::from_bytes(&image_bytes).unwrap(), image);

    // SAFETY: `resolver.c` only passes valid stack, `.rodata`, null, or the host string below.
    for passthrough in [Passthrough::OFF, unsafe { Passthrough::untagged() }] {
        let vm = Vm::with_config(VmConfig {
            passthrough,
            ..VmConfig::default()
        })
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        // SAFETY: all resolved functions match `resolver.c`
        unsafe {
            vm.set_native_resolver(move |imp| {
                count.fetch_add(1, Ordering::Relaxed);
                lookup(imp, false)
            });
        }

        let mut program = vm.load_image_bytes(&image_bytes).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 6);
        assert_eq!(program.call("call_add", &[3, 4]).unwrap(), 77);
        assert_eq!(program.call("call_aliased", &[6]).unwrap(), 45);
        assert_eq!(program.call("call_strlen_rodata", &[]).unwrap(), 14);
        assert_eq!(program.call("call_strlen_stack", &[b'd' as u64]).unwrap(), 4);
        assert_eq!(program.call("call_strlen_ptr", &[0]).unwrap(), 0xffff);
        assert_eq!(program.call("call_strlen_ptr", &[c"raw-host".as_ptr() as u64]).unwrap(), 8);
        assert_eq!(program.call("call_stack_sum", &[5]).unwrap(), 45 + 65);
        assert_eq!(program.call("call_small_struct", &[10]).unwrap(), (13u64 << 32) | 11);
        assert_eq!(program.call("call_plain", &[0x55, 0x0f]).unwrap(), 0x5a);

        // Second load reuses cached entries without calling the resolver again.
        let mut again = vm.load_image_bytes(&image_bytes).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 6);
        assert_eq!(again.call("call_add", &[2, 9]).unwrap(), 121);
    }

    // `sig: Some` enforces checked bounds; host closures coexist with resolved natives.
    let mixed = Vm::new();
    mixed.register_extern("res_plain", |(a, b): (u64, u64)| a.wrapping_add(b));
    // SAFETY: resolved functions match `resolver.c`
    unsafe { mixed.set_native_resolver(move |imp| lookup(imp, true)) };
    let mut prog = mixed.load_image_bytes(&image_bytes).unwrap();
    assert_eq!(prog.call("call_plain", &[20, 22]).unwrap(), 42);
    assert_eq!(prog.call("call_strlen_rodata", &[]).unwrap(), 14);
    assert!(matches!(prog.call("call_strlen_ptr", &[0]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));

    // No-BTF import (`proto: None`) uses the `RAW` trampoline.
    let mut raw_img = Image::from_code(vec![0x85, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0]);
    raw_img.add_call(0, Import::name("raw_add"));
    let raw_vm = Vm::new();
    // SAFETY: `res_add` takes two integer arguments
    unsafe {
        raw_vm.set_native_resolver(|imp| {
            (imp.name == "raw_add" && imp.proto.is_none()).then_some(Resolved {
                func: res_add as *const (),
                sig: None,
            })
        });
    }
    assert_eq!(raw_vm.load_image(raw_img).unwrap().call("main", &[7, 8]).unwrap(), 78);

    // Real DLL resolution on Windows: `ucrtbase.dll!strlen`.
    #[cfg(windows)]
    {
        let win_vm = Vm::new();
        // SAFETY: `ucrtbase.dll!strlen` matches `resolver.c`
        unsafe {
            win_vm.set_native_resolver(move |imp| {
                if imp.dll == Some("ucrtbase.dll") {
                    return ucrt_proc(imp.name).map(|func| Resolved { func, sig: None });
                }
                lookup(imp, false)
            });
        }
        let mut win_prog = win_vm.load_image_bytes(&image_bytes).unwrap();
        assert_eq!(win_prog.call("call_strlen_rodata", &[]).unwrap(), 14);
    }
}

/// `&extern` tokens call registered natives (plain, checked with fault, and 6-arg stack) with `RawCalls::OFF`.
#[test]
fn tokens_call_natives_without_raw_calls() {
    extern "C" fn tok_nat(a: u64, b: u64) -> u64 {
        a.wrapping_mul(b)
    }
    extern "C" fn tok_stack(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
        a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6
    }

    let vm = Vm::new();
    vm.register_extern("tok_host", |(a, b): (u64, u64)| a.wrapping_add(b));
    // SAFETY: each native matches its signature and reads only checked bytes
    unsafe {
        vm.register_native("tok_nat", tok_nat as *const (), NativeSig::ints(2))
            .unwrap();
        vm.register_native("tok_checked", sum as *const (), SUM).unwrap();
        vm.register_native("tok_stack", tok_stack as *const (), NativeSig::ints(6))
            .unwrap();
    }

    let mut prog = vm.load_elf(&object("tests/tokens.o")).unwrap();
    assert_eq!(prog.call("call_code_token", &[1, 6, 7]).unwrap(), 42);
    assert_eq!(prog.call("call_checked_token", &[0]).unwrap(), 10);
    assert!(matches!(prog.call("call_checked_token", &[1]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));
    assert_eq!(prog.call("call_stack_token", &[1]).unwrap(), 1 + 2 * 2 + 3 * 3 + 4 * 4 + 5 * 5 + 6 * 6);
}

#[cfg(windows)]
fn ucrt_proc(name: &str) -> Option<*const ()> {
    use std::ffi::CString;

    unsafe extern "system" {
        fn LoadLibraryA(name: *const i8) -> *mut std::ffi::c_void;
        fn GetProcAddress(module: *mut std::ffi::c_void, name: *const i8) -> *const ();
    }
    let dll = CString::new("ucrtbase.dll").ok()?;
    let sym = CString::new(name).ok()?;
    let module = unsafe { LoadLibraryA(dll.as_ptr()) };
    if module.is_null() {
        return None;
    }
    let proc = unsafe { GetProcAddress(module, sym.as_ptr()) };
    (!proc.is_null()).then_some(proc)
}

#[cfg(not(feature = "ffi"))]
#[test]
fn general_ffi_requires_feature() {
    extern "C" fn stub() -> u64 {
        0
    }

    let vm = Vm::new();
    // SAFETY: load fails before binding because `ffi` is disabled
    unsafe {
        vm.set_native_resolver(|_| {
            Some(Resolved {
                func: stub as *const (),
                sig: None,
            })
        });
    }
    let err = vm.load_elf(&object("tests/ffi_general.o")).unwrap_err();
    assert!(matches!(err, VmError::Link(LinkError::NativeMismatch { .. })), "{err}");
}

/// `GENERAL` marshalling behind `ffi`: odd small struct (3 B), wide struct (12 B), sret struct (24 B), float/double
/// args and returns across XMM/stack, variadics (`NativeSig::variadic` and resolver), tokens, and real `ucrtbase`.
#[cfg(feature = "ffi")]
#[test]
fn general_ffi_shapes_and_variadics() {
    use rvm::Perms;

    #[repr(C)]
    struct S3 {
        a: u8,
        b: u8,
        c: u8,
    }
    #[repr(C)]
    struct S12 {
        a: u32,
        b: u32,
        c: u32,
    }
    #[repr(C)]
    struct S24 {
        a: u64,
        b: u64,
        c: u64,
    }

    extern "C" fn take_s3_s12(a: S3, b: S12, k: u64) -> u64 {
        u64::from(a.a)
            + u64::from(a.b) * 10
            + u64::from(a.c) * 100
            + u64::from(b.a)
            + u64::from(b.b)
            + u64::from(b.c)
            + k
    }
    unsafe extern "C" fn take_s12_ptr(s: S12, buf: *const u8, len: u64) -> u64 {
        let sum: u64 = unsafe { std::slice::from_raw_parts(buf, len as usize) }
            .iter()
            .map(|&x| u64::from(x))
            .sum();
        u64::from(s.a) + u64::from(s.b) * 10 + u64::from(s.c) * 100 + sum
    }
    extern "C" fn ret_s3(x: u64) -> S3 {
        S3 {
            a: x as u8,
            b: (x + 1) as u8,
            c: (x + 2) as u8,
        }
    }
    extern "C" fn ret_s12(x: u64) -> S12 {
        let x = x as u32;
        S12 {
            a: x,
            b: x + 1,
            c: x + 2,
        }
    }
    extern "C" fn ret_s24(x: u64, y: u64) -> S24 {
        S24 {
            a: x + 1,
            b: y + 2,
            c: x + y + 3,
        }
    }
    extern "C" fn nat_f32(a: f32, b: f64) -> f32 {
        a + (b as f32) * 2.0
    }
    extern "C" fn nat_f64_6(a: f64, b: f32, c: f64, d: f32, e: f64, f: f64) -> f64 {
        a + f64::from(b) + c + f64::from(d) + e + f
    }
    unsafe extern "C" fn var_mix(tag: *const u8, count: u64, n: u64, d: f64, extra: u64) -> u64 {
        u64::from(unsafe { *tag }) + count * 100 + n + (d as u64) * 10 + extra
    }
    extern "C" fn fake_sqrt(x: f64) -> f64 {
        x.sqrt()
    }
    unsafe extern "C" fn fake_snprintf(buf: *mut u8, size: u64, _fmt: *const u8, a: u64, b: u64) -> i32 {
        let text = format!("{a}+{b}");
        let n = text.len().min((size as usize).saturating_sub(1));
        unsafe {
            std::ptr::copy_nonoverlapping(text.as_ptr(), buf, n);
            *buf.add(n) = 0;
        }
        text.len() as i32
    }

    let resolve_fn = |imp: &NativeImport<'_>| -> Option<Resolved> {
        let func: *const () = match (imp.dll, imp.name) {
            (None, "take_s3_s12") => take_s3_s12 as *const (),
            (None, "take_s12_ptr") => take_s12_ptr as *const (),
            (None, "ret_s3") => ret_s3 as *const (),
            (None, "ret_s12") => ret_s12 as *const (),
            (None, "ret_s24") => ret_s24 as *const (),
            (None, "nat_f32") => nat_f32 as *const (),
            (None, "nat_f64_6") => nat_f64_6 as *const (),
            (None, "var_mix") => var_mix as *const (),
            (Some("ucrtbase.dll"), "sqrt") => {
                #[cfg(windows)]
                {
                    ucrt_proc("sqrt").unwrap_or(fake_sqrt as *const ())
                }
                #[cfg(not(windows))]
                {
                    fake_sqrt as *const ()
                }
            }
            (Some("ucrtbase.dll"), "_snprintf") => {
                #[cfg(windows)]
                {
                    ucrt_proc("_snprintf").unwrap_or(fake_snprintf as *const ())
                }
                #[cfg(not(windows))]
                {
                    fake_snprintf as *const ()
                }
            }
            _ => return None,
        };
        Some(Resolved { func, sig: None })
    };

    let bytes = Vm::new()
        .prepare_elf(&object("tests/ffi_general.o"))
        .unwrap()
        .to_bytes();

    // SAFETY: `ffi_general.c` passes valid stack pointers and matches all prototypes above.
    for (i, passthrough) in [Passthrough::OFF, unsafe { Passthrough::untagged() }]
        .into_iter()
        .enumerate()
    {
        let vm = Vm::with_config(VmConfig {
            passthrough,
            ..VmConfig::default()
        })
        .unwrap();
        if i == 0 {
            let sig = NativeSig::variadic(&[NativeArg::Read(None), NativeArg::Int]);
            // SAFETY: `var_mix` reads one byte at `tag` and never unwinds
            unsafe { vm.register_native("var_mix", var_mix as *const (), sig) }.unwrap();
        }
        // SAFETY: all resolved functions match `ffi_general.c`
        unsafe { vm.set_native_resolver(resolve_fn) };

        let mut prog = vm.load_image_bytes(&bytes).unwrap();
        assert_eq!(prog.call("test_take_s3_s12", &[9]).unwrap(), 1 + 20 + 300 + 600 + 9);
        assert_eq!(prog.call("test_take_s12_ptr", &[5, 6]).unwrap(), 5 + 60 + 700 + 26);
        assert_eq!(prog.call("test_ret_s3", &[4]).unwrap(), 4 + 50 + 600);
        assert_eq!(prog.call("test_ret_s12", &[3]).unwrap(), 3 + 40 + 500);
        assert_eq!(prog.call("test_ret_s12_token", &[3]).unwrap(), 3 + 40 + 500);
        assert_eq!(prog.call("test_ret_s24", &[10, 20]).unwrap(), 11 + 22 * 2 + 33 * 3);

        let base = prog.memory_mut().map(64, Perms::RW).unwrap().base();
        for (off, bits) in [
            (0, u64::from(1.5f32.to_bits())),
            (8, 2.25f64.to_bits()),
            (16, 3.5f64.to_bits()),
            (24, u64::from(4.25f32.to_bits())),
            (32, 5.0f64.to_bits()),
            (40, 6.5f64.to_bits()),
            (48, 7.0f64.to_bits()),
        ] {
            prog.memory_mut().write(base + off, bits).unwrap();
        }

        let f32_bits = prog.call("test_f32", &[base, base + 8]).unwrap();
        assert_eq!((f32::from_bits(f32_bits as u32), f32_bits >> 32), (6.0f32, 0));
        let f64_bits = prog
            .call("test_f64_6", &[base + 8, base, base + 16, base + 24, base + 32, base + 40])
            .unwrap();
        assert_eq!(f64::from_bits(f64_bits), 23.0);
        assert_eq!(f64::from_bits(prog.call("test_sqrt", &[base + 8]).unwrap()), 1.5);
        assert_eq!(prog.call("test_var_mix", &[base + 48, 9]).unwrap(), u64::from(b't') + 300 + 9 + 70 + 42);

        let expected_hash = b"12+34".iter().fold(5000u64, |h, &ch| h * 31 + u64::from(ch));
        assert_eq!(prog.call("test_snprintf", &[12, 34]).unwrap(), expected_hash);
    }
}

/// Aware natives fail the guest call with `rvm::fail` or `rvm::fail_code` (directly and via tokens); first failure wins.
#[cfg(feature = "ffi")]
#[test]
fn aware_native_can_fail_call() {
    use rvm::HostError;

    #[derive(Debug, PartialEq, Eq)]
    struct Boom(u64);
    impl std::fmt::Display for Boom {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "boom {}", self.0)
        }
    }
    impl std::error::Error for Boom {}

    assert!(!rvm::fail_code(1) && !rvm::fail(Boom(0)));

    extern "C" fn checked_add(a: u64, b: u64) -> u64 {
        match a {
            100 => {
                assert!(rvm::fail_code(777) && rvm::fail_code(999));
                0
            }
            200 => {
                assert!(rvm::fail(Boom(b)));
                0
            }
            _ => a + b,
        }
    }
    extern "C" fn unused_stack(_: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
        0
    }

    let vm = vm_with_sigs(VmConfig::default(), NativeSig::ints(2).aware(), SUM);
    // SAFETY: `checked_add` takes 2 u64s and never unwinds
    unsafe { vm.register_native("nat_add", checked_add as *const (), NativeSig::ints(2).aware()) }.unwrap();
    let mut prog = load(&vm);
    assert_eq!(prog.call("add", &[10, 5]).unwrap(), 15);
    assert!(matches!(prog.call("add", &[100, 5]), Err(VmError::Host(HostError::Native { code: 777 }))));
    let Err(VmError::Host(HostError::Failed(inner))) = prog.call("add", &[200, 42]) else {
        panic!("expected HostError::Failed");
    };
    assert_eq!(inner.downcast_ref::<Boom>(), Some(&Boom(42)));
    assert_eq!(prog.call("add", &[3, 4]).unwrap(), 7);

    // Token call via `tokens.o`
    let tok_vm = Vm::new();
    tok_vm.register_extern("tok_host", |(a, b): (u64, u64)| a + b);
    // SAFETY: signatures match `tokens.o`
    unsafe {
        tok_vm
            .register_native("tok_nat", checked_add as *const (), NativeSig::ints(2).aware())
            .unwrap();
        tok_vm.register_native("tok_checked", sum as *const (), SUM).unwrap();
        tok_vm
            .register_native("tok_stack", unused_stack as *const (), NativeSig::ints(6))
            .unwrap();
    }
    let mut tok_prog = tok_vm.load_elf(&object("tests/tokens.o")).unwrap();
    assert!(matches!(
        tok_prog.call("call_code_token", &[1, 100, 9]),
        Err(VmError::Host(HostError::Native { code: 777 }))
    ));
    assert_eq!(tok_prog.call("call_code_token", &[1, 3, 4]).unwrap(), 7);
}
