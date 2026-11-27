//! Native functions: signature checks at link and image load, pointer arguments in tagged and untagged mode,
//! re-entry and instruction limits.

use std::cell::RefCell;

use rvm::{
    ExecError, LinkError, MemoryError, NativeArg, NativeSig, Passthrough, Plugin, Program, Vm, VmConfig, VmError,
    WeakPlugin, STACK_REGION,
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

thread_local! {
    /// The plugin that `reenter` calls back into.
    static REENTERED: RefCell<Option<WeakPlugin>> = const { RefCell::new(None) };
}

/// 1 if a call back into the plugin that called it finds the plugin busy, else 0.
extern "C" fn reenter(x: u64) -> u64 {
    let plugin = REENTERED.with_borrow(|p| p.as_ref().and_then(WeakPlugin::upgrade));
    let busy = plugin.map(|p| p.call("add", &[x, 1]));
    matches!(busy, Some(Err(VmError::PluginBusy(_)))).into()
}

const SUM: NativeSig = NativeSig::new(&[NativeArg::Read(Some(2)), NativeArg::Int]);
const FILL: NativeSig = NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int, NativeArg::Int]);
const FIRST: NativeSig = NativeSig::new(&[NativeArg::Read(None)]);

/// The natives `bpf/tests/native_calls.c` imports, with `nat_add` and `nat_sum` under the signatures given.
fn natives(add_sig: NativeSig, sum_sig: NativeSig) -> [(&'static str, *const (), NativeSig); 6] {
    [
        ("nat_add", add as *const (), add_sig),
        ("nat_five", five as *const (), NativeSig::ints(5)),
        ("nat_sum", sum as *const (), sum_sig),
        ("nat_fill", fill as *const (), FILL),
        ("nat_first", first as *const (), FIRST),
        ("nat_reenter", reenter as *const (), NativeSig::ints(1)),
    ]
}

/// A VM with the natives of `bpf/tests/native_calls.c` under their own signatures.
fn vm_with(config: VmConfig) -> Vm {
    vm_with_sigs(config, NativeSig::ints(2), SUM)
}

fn vm_with_sigs(config: VmConfig, add_sig: NativeSig, sum_sig: NativeSig) -> Vm {
    // SAFETY: each function takes its signature's arguments, never unwinds, and reads or writes only the bytes its
    // pointer arguments' checks cover; the untagged test passes only addresses of live bytes.
    unsafe { Vm::with_natives(config, &natives(add_sig, sum_sig)) }.unwrap()
}

fn load(vm: &Vm) -> Program {
    vm.load_elf(&object("tests/native_calls.o")).unwrap()
}

/// The guest's pointers reach the natives as host addresses of the bytes they point to, and a pointer whose bytes
/// the guest may not access faults at the call.
#[test]
fn pointer_arguments_resolve() {
    let mut program = load(&vm_with(VmConfig::default()));
    assert_eq!(program.call("add", &[2, 3]).unwrap(), 5);
    assert_eq!(program.call("five", &[]).unwrap(), 54_321);
    assert_eq!(program.call("sum", &[]).unwrap(), 136);
    assert_eq!(program.call("fill", &[]).unwrap(), 24);
    assert_eq!(program.call("sum_empty", &[]).unwrap(), 0);

    // the first byte past the stack, where the 1 MiB buffer leaves it
    let stack_end = program.memory().region_base(STACK_REGION) + program.memory().region_len(STACK_REGION) as u64;
    assert_eq!(
        fault(program.call("overrun", &[])),
        MemoryError {
            addr: stack_end,
            size: 1
        }
    );
    // a forged address, and one under no tag
    let forged = rvm::region_tag(5) | 0x1234;
    for addr in [forged, 0x1234, 0] {
        assert_eq!(fault(program.call("first", &[addr])), MemoryError { addr, size: 1 });
    }
    // a write through a pointer to read-only bytes
    let err = fault(program.call("fill_rodata", &[]));
    assert_eq!(err.addr >> rvm::REGION_SHIFT, rvm::RODATA_REGION as u64);
}

fn fault(result: rvm::Result<u64>) -> MemoryError {
    match result {
        Err(VmError::Exec(ExecError::MemoryFault { error, .. })) => error,
        other => panic!("expected a memory fault, got {other:?}"),
    }
}

/// Untagged, guest pointers are host addresses already, and every argument reaches the native unchecked.
#[test]
fn untagged_arguments_pass_unchanged() {
    // SAFETY: the guest passes only pointers into its own memory, and `host_byte`'s address
    let config = VmConfig {
        passthrough: unsafe { Passthrough::untagged() },
        ..VmConfig::default()
    };
    let mut program = load(&vm_with(config));
    assert_eq!(program.call("sum", &[]).unwrap(), 136);
    assert_eq!(program.call("fill", &[]).unwrap(), 24);

    let host_byte = 42u8;
    assert_eq!(program.call("first", &[(&raw const host_byte) as u64]).unwrap(), 42);
}

/// Linking compares each extern's BTF with the native's signature.
#[test]
fn signature_mismatch_at_link() {
    let elf = object("tests/native_calls.o");
    let err = vm_with_sigs(VmConfig::default(), NativeSig::ints(3), SUM)
        .load_elf(&elf)
        .unwrap_err();
    assert!(
        matches!(&err, VmError::Link(LinkError::SignatureMismatch { name, declared: 2, host: 3 }) if name == "nat_add"),
        "{err}"
    );

    // an integer where the extern has a pointer, and a length argument other than the borrow tag's
    let read_one = NativeSig::new(&[NativeArg::Read(None), NativeArg::Int]);
    for sum_sig in [NativeSig::ints(2), read_one] {
        let err = vm_with_sigs(VmConfig::default(), NativeSig::ints(2), sum_sig)
            .load_elf(&elf)
            .unwrap_err();
        assert!(matches!(&err, VmError::Link(LinkError::NativeMismatch { name, .. }) if name == "nat_sum"), "{err}");
    }
}

/// An image records the signatures it was linked against, and loading compares them with the VM's.
#[test]
fn signature_mismatch_at_image_load() {
    let image = vm_with(VmConfig::default())
        .prepare_elf(&object("tests/native_calls.o"))
        .unwrap()
        .to_bytes();

    let vm = vm_with_sigs(VmConfig::default(), NativeSig::ints(3), SUM);
    let err = vm.load_image_bytes(&image).unwrap_err();
    assert!(
        matches!(&err, VmError::Link(LinkError::SignatureMismatch { name, declared: 2, host: 3 }) if name == "nat_add"),
        "{err}"
    );

    let write = NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int]);
    let err = vm_with_sigs(VmConfig::default(), NativeSig::ints(2), write)
        .load_image_bytes(&image)
        .unwrap_err();
    assert!(matches!(&err, VmError::Link(LinkError::NativeMismatch { name, .. }) if name == "nat_sum"), "{err}");

    let mut program = vm_with(VmConfig::default()).load_image_bytes(&image).unwrap();
    assert_eq!(program.call("sum", &[]).unwrap(), 136);
}

/// A native that calls back into the plugin it runs for finds it busy.
#[test]
fn reentry_is_plugin_busy() {
    let plugin = Plugin::new("natives", load(&vm_with(VmConfig::default())));
    REENTERED.set(Some(plugin.downgrade()));
    assert_eq!(plugin.call("reenter", &[5]).unwrap(), 1);
}

/// A native call counts as one instruction of the guest's limit.
#[cfg(feature = "fuel")]
#[test]
fn instruction_limit_counts_native_calls() {
    let limited = |limit| VmConfig {
        instruction_limit: limit,
        ..VmConfig::default()
    };
    assert_eq!(load(&vm_with(limited(1_000_000))).call("count", &[100]).unwrap(), 5050);

    let err = load(&vm_with(limited(100))).call("count", &[100]).unwrap_err();
    assert!(matches!(err, VmError::Exec(ExecError::InstructionLimit { limit: 100 })), "{err}");
}

/// A native function follows `__host` pointers that a plugin placed in a struct with `HOST()`, in every memory mode.
#[test]
fn native_follows_host_pointer_in_struct() {
    #[repr(C)]
    struct IoVec {
        base: *const u8,
        len: u64,
    }

    /// # Safety
    ///
    /// `parts` must point to `byte_len` readable bytes holding valid `IoVec`s.
    unsafe extern "C" fn sum_iovec(parts: *const IoVec, byte_len: u64) -> u64 {
        let count = byte_len as usize / size_of::<IoVec>();
        let vecs = unsafe { std::slice::from_raw_parts(parts, count) };
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
        // SAFETY: `sum_iovec` reads only `byte_len` bytes at `parts` and the valid slices in `parts`
        unsafe { vm.register_native("sum_iovec", sum_iovec as *const (), sig) }.unwrap();
        let mut program = vm.load_elf(&object("tests/host_ptr.o")).unwrap();
        assert_eq!(program.call("sum_parts", &[]).unwrap(), 1 + 2 + 3 + 4 + 10 + 20 + 30);
    }
}

/// A native resolver binds imports at load time, caches each name once per VM, strips pointers in tagged programs when
/// returning `sig: None`, checks them when returning `sig: Some`, passes 1/2/4/8-byte structs by value, and coexists
/// with host closures and no-BTF raw calls.
#[test]
fn native_resolver_binds_and_caches() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rvm::{Image, Import, NativeImport, Resolved};

    extern "C" fn res_add(a: u64, b: u64) -> u64 {
        a.wrapping_mul(10).wrapping_add(b)
    }

    extern "C" fn alias_target(x: u64) -> u64 {
        x.wrapping_mul(7).wrapping_add(3)
    }

    /// # Safety
    ///
    /// `s` must be null or point to a NUL-terminated string.
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

    /// # Safety
    ///
    /// `buf` must point to 4 readable bytes.
    unsafe extern "C" fn res_stack_sum(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, buf: *const u8) -> u64 {
        let bytes = unsafe { std::slice::from_raw_parts(buf, 4) };
        a + b + c + d + e + f + bytes.iter().map(|&x| u64::from(x)).sum::<u64>()
    }

    #[repr(C)]
    struct S1 {
        a: u8,
    }
    #[repr(C)]
    struct S2 {
        a: u16,
    }
    #[repr(C)]
    struct S4 {
        a: u16,
        b: u16,
    }
    #[repr(C)]
    struct S8 {
        a: u32,
        b: u32,
    }

    extern "C" fn res_small_structs(a: S1, b: S2, c: S4, d: S8) -> S8 {
        S8 {
            a: u32::from(a.a) + u32::from(b.a) + u32::from(c.a) + d.a,
            b: u32::from(c.b) + d.b,
        }
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
            (Some("host.dll"), "res_small_structs") => (res_small_structs as *const (), NativeSig::ints(4)),
            (None, "res_plain") => (res_plain as *const (), NativeSig::ints(2)),
            _ => return None,
        };
        Some(Resolved {
            func,
            sig: checked.then_some(sig),
        })
    };

    // Prepare in an empty VM (no natives, no host closures, no resolver).
    let image_bytes = Vm::new().prepare_elf(&object("tests/resolver.o")).unwrap().to_bytes();

    // SAFETY: `resolver.c` only passes valid stack, `.rodata`, null, or the host string below.
    let (on, untagged) = unsafe { (Passthrough::on(), Passthrough::untagged()) };
    for passthrough in [Passthrough::OFF, on, untagged] {
        let vm = Vm::with_config(VmConfig {
            passthrough,
            ..VmConfig::default()
        })
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        // SAFETY: all resolved functions match the prototypes in `resolver.c`
        unsafe {
            vm.set_native_resolver(move |imp| {
                count.fetch_add(1, Ordering::Relaxed);
                lookup(imp, false)
            });
        }

        let mut program = vm.load_image_bytes(&image_bytes).unwrap();
        // Six unique imports resolved once each, even though `res_add` has two call sites.
        assert_eq!(calls.load(Ordering::Relaxed), 6);

        assert_eq!(program.call("call_add", &[3, 4]).unwrap(), (3 * 10 + 4) + (4 * 10 + 3));
        assert_eq!(program.call("call_aliased", &[6]).unwrap(), 45);
        assert_eq!(program.call("call_strlen_rodata", &[]).unwrap(), 14);
        assert_eq!(program.call("call_strlen_stack", &[b'd' as u64]).unwrap(), 4);
        assert_eq!(program.call("call_strlen_ptr", &[0]).unwrap(), 0xffff);
        assert_eq!(program.call("call_stack_sum", &[5]).unwrap(), (5 + 6 + 7 + 8 + 9 + 10) + (10 + 20 + 30 + 5));
        assert_eq!(program.call("call_small_structs", &[10]).unwrap(), (((13u64 + 15) << 32) | (10 + 11 + 12 + 14)));
        assert_eq!(program.call("call_plain", &[0x55, 0x0f]).unwrap(), 0x5a);

        // Passing a raw host pointer through a STRIP pointer parameter preserves it untouched.
        let host_str = b"raw-host\0";
        assert_eq!(program.call("call_strlen_ptr", &[host_str.as_ptr() as u64]).unwrap(), 8);

        // Second load in the same VM reuses cached entries without calling the resolver again.
        let mut again = vm.load_image_bytes(&image_bytes).unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 6);
        assert_eq!(again.call("call_add", &[2, 9]).unwrap(), (2 * 10 + 9) + (9 * 10 + 2));
    }

    // Returning `sig: Some` enforces checked bounds in tagged mode (null pointer faults before entering `c_strlen`).
    let checked_vm = Vm::new();
    // SAFETY: all resolved functions match their signatures
    unsafe { checked_vm.set_native_resolver(move |imp| lookup(imp, true)) };
    let mut checked = checked_vm.load_image_bytes(&image_bytes).unwrap();
    assert_eq!(checked.call("call_strlen_rodata", &[]).unwrap(), 14);
    assert!(matches!(checked.call("call_strlen_ptr", &[0]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));

    // The same prepared image loads when `res_plain` is a host closure and the rest come from the resolver.
    let mixed = Vm::new();
    mixed.register_extern("res_plain", |(a, b): (u64, u64)| a.wrapping_add(b));
    // SAFETY: resolved functions match `resolver.c`
    unsafe { mixed.set_native_resolver(move |imp| lookup(imp, false)) };
    let mut mixed_prog = mixed.load_image_bytes(&image_bytes).unwrap();
    assert_eq!(mixed_prog.call("call_plain", &[20, 22]).unwrap(), 42);
    assert_eq!(mixed_prog.call("call_aliased", &[6]).unwrap(), 45);

    // A no-BTF import (`proto: None`) resolved without a signature uses the `RAW` trampoline handler.
    let raw_code = [
        0x85, 0x00, 0, 0, 0, 0, 0, 0, // call
        0x95, 0x00, 0, 0, 0, 0, 0, 0, // exit
    ];
    let mut raw_img = Image::from_code(raw_code.to_vec());
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
    let mut raw_prog = raw_vm.load_image(raw_img).unwrap();
    assert_eq!(raw_prog.call("main", &[7, 8]).unwrap(), 78);

    // End-to-end real DLL resolution on Windows: `ucrtbase.dll!strlen` via LoadLibraryA + GetProcAddress.
    #[cfg(windows)]
    {
        use std::ffi::CString;

        unsafe extern "system" {
            fn LoadLibraryA(name: *const i8) -> *mut std::ffi::c_void;
            fn GetProcAddress(module: *mut std::ffi::c_void, name: *const i8) -> *const ();
        }

        let win_vm = Vm::new();
        // SAFETY: `ucrtbase.dll!strlen` is `size_t strlen(const char *)`, matching `resolver.c`
        unsafe {
            win_vm.set_native_resolver(move |imp| {
                if imp.dll == Some("ucrtbase.dll") {
                    let dll = CString::new(imp.dll?).ok()?;
                    let sym = CString::new(imp.name).ok()?;
                    let module = LoadLibraryA(dll.as_ptr());
                    if module.is_null() {
                        return None;
                    }
                    let proc = GetProcAddress(module, sym.as_ptr());
                    return (!proc.is_null()).then_some(Resolved { func: proc, sig: None });
                }
                lookup(imp, false)
            });
        }
        let mut win_prog = win_vm.load_image_bytes(&image_bytes).unwrap();
        assert_eq!(win_prog.call("call_strlen_rodata", &[]).unwrap(), 14);
        assert_eq!(win_prog.call("call_strlen_stack", &[b'!' as u64]).unwrap(), 4);
    }
}

/// `&extern` tokens call registered natives (plain, checked, and 6-arg stack) and host closures with `RawCalls::OFF`
/// and `Passthrough::OFF`, faulting on a bad checked pointer just like a direct native call.
#[test]
fn tokens_call_natives_without_raw_calls() {
    extern "C" fn tok_nat(a: u64, b: u64) -> u64 {
        a.wrapping_mul(b)
    }
    /// # Safety
    ///
    /// `buf` must point to `len` readable bytes.
    unsafe extern "C" fn tok_checked(buf: *const u8, len: u64) -> u64 {
        unsafe { std::slice::from_raw_parts(buf, len as usize) }
            .iter()
            .map(|&b| u64::from(b))
            .sum()
    }
    extern "C" fn tok_stack(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
        a + b * 2 + c * 3 + d * 4 + e * 5 + f * 6
    }

    let vm = Vm::new();
    vm.register_extern("tok_host", |(a, b): (u64, u64)| a.wrapping_add(b));
    let checked_sig = NativeSig::new(&[NativeArg::Read(Some(2)), NativeArg::Int]);
    // SAFETY: each native matches its signature and reads only checked bytes
    unsafe {
        vm.register_native("tok_nat", tok_nat as *const (), NativeSig::ints(2))
            .unwrap();
        vm.register_native("tok_checked", tok_checked as *const (), checked_sig)
            .unwrap();
        vm.register_native("tok_stack", tok_stack as *const (), NativeSig::ints(6))
            .unwrap();
    }

    let bytes = Vm::new().prepare_elf(&object("tests/tokens.o")).unwrap().to_bytes();
    let mut prog = vm.load_image_bytes(&bytes).unwrap();
    assert_eq!(prog.call("call_code_token", &[0, 6, 7]).unwrap(), 13);
    assert_eq!(prog.call("call_code_token", &[1, 6, 7]).unwrap(), 42);
    assert_eq!(prog.call("call_ro_token", &[0, 6, 7]).unwrap(), 13);
    assert_eq!(prog.call("call_ro_token", &[1, 6, 7]).unwrap(), 42);
    assert_eq!(prog.call("call_rw_token", &[0, 6, 7]).unwrap(), 42);
    assert_eq!(prog.call("call_rw_token", &[1, 6, 7]).unwrap(), 13);
    assert_eq!(prog.call("call_checked_token", &[0]).unwrap(), 10);
    assert!(matches!(prog.call("call_checked_token", &[1]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));
    assert_eq!(prog.call("call_stack_token", &[1]).unwrap(), 1 + 2 * 2 + 3 * 3 + 4 * 4 + 5 * 5 + 6 * 6);
}

#[cfg(not(feature = "ffi"))]
#[test]
fn general_ffi_requires_feature() {
    use rvm::Resolved;

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

/// `GENERAL` marshalling behind the `ffi` feature: 3/5/7/12/16-byte struct args, 3/5/7/12/16/24-byte struct returns,
/// float/double args and returns (including stack slots), variadics (resolver and `NativeSig::variadic`), tokens, and
/// real `ucrtbase` exports (`sqrt`, `_snprintf`).
#[cfg(feature = "ffi")]
#[test]
fn general_ffi_shapes_and_variadics() {
    use rvm::{NativeImport, Perms, Resolved};

    #[repr(C)]
    struct S3 {
        a: u8,
        b: u8,
        c: u8,
    }
    #[repr(C)]
    struct S5 {
        b: [u8; 5],
    }
    #[repr(C)]
    struct S7 {
        b: [u8; 7],
    }
    #[repr(C)]
    struct S12 {
        a: u32,
        b: u32,
        c: u32,
    }
    #[repr(C)]
    struct S16 {
        a: u64,
        b: u64,
    }
    #[repr(C)]
    struct S24 {
        a: u64,
        b: u64,
        c: u64,
    }

    extern "C" fn take_s3_s5(a: S3, b: S5, k: u64) -> u64 {
        u64::from(a.a) + u64::from(a.b) * 10 + u64::from(a.c) * 100 + b.b.iter().map(|&x| u64::from(x)).sum::<u64>() + k
    }
    extern "C" fn take_s7_s12(a: S7, b: S12, k: u64) -> u64 {
        a.b.iter().map(|&x| u64::from(x)).sum::<u64>() + u64::from(b.a) + u64::from(b.b) + u64::from(b.c) + k
    }
    unsafe extern "C" fn take_s16_ptr(s: S16, buf: *const u8, len: u64) -> u64 {
        let sum: u64 = unsafe { std::slice::from_raw_parts(buf, len as usize) }
            .iter()
            .map(|&x| u64::from(x))
            .sum();
        s.a + s.b * 10 + sum
    }
    extern "C" fn ret_s3(x: u64) -> S3 {
        S3 {
            a: x as u8,
            b: (x + 1) as u8,
            c: (x + 2) as u8,
        }
    }
    extern "C" fn ret_s5(x: u64) -> S5 {
        let b = x as u8;
        S5 {
            b: [b, b + 1, b + 2, b + 3, b + 4],
        }
    }
    extern "C" fn ret_s7(x: u64) -> S7 {
        let b = x as u8;
        S7 {
            b: [b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6],
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
    extern "C" fn ret_s16(x: u64) -> S16 {
        S16 {
            a: x * 7 + 1,
            b: x * 11 + 2,
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
        let first = unsafe { *tag } as u64;
        first + count * 100 + n + (d as u64) * 10 + extra
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

    let resolve_fn = |imp: &NativeImport<'_>| -> Option<Resolved> {
        let func: *const () = match (imp.dll, imp.name) {
            (None, "take_s3_s5") => take_s3_s5 as *const (),
            (None, "take_s7_s12") => take_s7_s12 as *const (),
            (None, "take_s16_ptr") => take_s16_ptr as *const (),
            (None, "ret_s3") => ret_s3 as *const (),
            (None, "ret_s5") => ret_s5 as *const (),
            (None, "ret_s7") => ret_s7 as *const (),
            (None, "ret_s12") => ret_s12 as *const (),
            (None, "ret_s16") => ret_s16 as *const (),
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
    let (on, untagged) = unsafe { (Passthrough::on(), Passthrough::untagged()) };
    for (i, passthrough) in [Passthrough::OFF, on, untagged].into_iter().enumerate() {
        let vm = Vm::with_config(VmConfig {
            passthrough,
            ..VmConfig::default()
        })
        .unwrap();
        // On the first pass, register `var_mix` explicitly with `NativeSig::variadic` to test checked named pointers.
        if i == 0 {
            let sig = NativeSig::variadic(&[NativeArg::Read(None), NativeArg::Int]);
            // SAFETY: `var_mix` reads one byte at `tag` and never unwinds
            unsafe { vm.register_native("var_mix", var_mix as *const (), sig) }.unwrap();
        }
        // SAFETY: all resolved functions match `ffi_general.c`
        unsafe { vm.set_native_resolver(resolve_fn) };

        let mut prog = vm.load_image_bytes(&bytes).unwrap();
        assert_eq!(prog.call("test_take_small_odd", &[7]).unwrap(), 1 + 20 + 300 + 150 + 7);
        assert_eq!(prog.call("test_take_mid_wide", &[9]).unwrap(), 28 + 600 + 9);
        assert_eq!(prog.call("test_take_s16_ptr", &[5, 6]).unwrap(), 5 + 60 + 26);
        assert_eq!(prog.call("test_ret_s3", &[4]).unwrap(), 4 + 50 + 600);
        assert_eq!(prog.call("test_ret_s5", &[2]).unwrap(), 2 + 3 + 4 + 5 + 6);
        assert_eq!(prog.call("test_ret_s7", &[1]).unwrap(), 1 + 2 + 3 + 4 + 5 + 6 + 7);
        assert_eq!(prog.call("test_ret_s12", &[3]).unwrap(), 3 + 40 + 500);
        assert_eq!(prog.call("test_ret_s16", &[5]).unwrap(), (5 * 7 + 1) ^ ((5 * 11 + 2) * 3));
        assert_eq!(prog.call("test_ret_s16_token", &[5]).unwrap(), (5 * 7 + 1) ^ ((5 * 11 + 2) * 3));
        assert_eq!(prog.call("test_ret_s24", &[10, 20]).unwrap(), 11 + 22 * 2 + 33 * 3);

        // Float and double arguments & returns (values stored in guest memory since BPF has no FP ops).
        let mem_f = prog.memory_mut().map(64, Perms::RW).unwrap();
        let base = mem_f.base();
        prog.memory_mut().write(base, 1.5f32.to_bits()).unwrap();
        prog.memory_mut().write(base + 8, 2.25f64.to_bits()).unwrap();
        prog.memory_mut().write(base + 16, 3.5f64.to_bits()).unwrap();
        prog.memory_mut().write(base + 24, 4.25f32.to_bits()).unwrap();
        prog.memory_mut().write(base + 32, 5.0f64.to_bits()).unwrap();
        prog.memory_mut().write(base + 40, 6.5f64.to_bits()).unwrap();

        let f32_bits = prog.call("test_f32", &[base, base + 8]).unwrap();
        assert_eq!(f32::from_bits(f32_bits as u32), 1.5f32 + 2.25f32 * 2.0);
        assert_eq!(f32_bits >> 32, 0);

        let f64_bits = prog
            .call("test_f64_6", &[base + 8, base, base + 16, base + 24, base + 32, base + 40])
            .unwrap();
        assert_eq!(f64::from_bits(f64_bits), 2.25 + 1.5 + 3.5 + 4.25 + 5.0 + 6.5);

        let sqrt_bits = prog.call("test_sqrt", &[base + 8]).unwrap();
        assert_eq!(f64::from_bits(sqrt_bits), 1.5);

        // Variadic mix (`"tag"` starts with b't' = 116)
        prog.memory_mut().write(base + 48, 7.0f64.to_bits()).unwrap();
        assert_eq!(prog.call("test_var_mix", &[base + 48, 9]).unwrap(), u64::from(b't') + 300 + 9 + 70 + 42);

        // Real `ucrtbase!_snprintf`: `"12+34"` has len 5
        let mut expected_hash = 5u64 * 1000;
        for &ch in b"12+34" {
            expected_hash = expected_hash * 31 + u64::from(ch);
        }
        assert_eq!(prog.call("test_snprintf", &[12, 34]).unwrap(), expected_hash);
    }
}
