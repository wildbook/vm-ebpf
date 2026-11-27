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
