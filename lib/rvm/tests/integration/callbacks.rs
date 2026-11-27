//! Native-to-guest callbacks: Miri-checked `call_guest` nested runs, automatic scoped thunks (`qsort`, float/struct
//! callback ABIs, `&extern` tokens), retained callbacks (`rvm_callback`, `CALLS_BACK`, `Plugin::replace`, cross-thread
//! idle/busy), and pool exhaustion.

use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(all(windows, not(miri)))]
use rvm::Passthrough;
#[cfg(not(miri))]
use rvm::Plugin;
use rvm::{ExecError, NativeArg, NativeSig, Perms, Vm, VmConfig, VmError};

use crate::common::object;

#[repr(C)]
#[derive(Clone, Copy)]
struct S3 {
    a: u8,
    b: u8,
    c: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct S12 {
    x: u32,
    y: u32,
    z: u32,
}

extern "C" fn dummy_qsort(_base: *mut u8, _n: u64, _sz: u64, _cmp: *const ()) -> u64 {
    0
}

extern "C" fn call_float_cb(
    cb: extern "C" fn(f64, f32, u64, f64, f32) -> f64,
    a: f64,
    b: f32,
    c: u64,
    d: f64,
    e: f32,
) -> f64 {
    cb(a, b, c, d, e)
}

extern "C" fn call_struct_cb(cb: extern "C" fn(S3, S12, u64) -> u64, s3: S3, s12: S12, k: u64) -> u64 {
    cb(s3, s12, k)
}

extern "C" fn nat_double(x: u64) -> u64 {
    x.wrapping_mul(2)
}

extern "C" fn apply_u64(cb: Option<extern "C" fn(u64) -> u64>, x: u64) -> u64 {
    match cb {
        Some(f) => f(x),
        None => 999,
    }
}

static STORED_CB: AtomicU64 = AtomicU64::new(0);
#[cfg(not(miri))]
static THUNK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

extern "C" fn fire_cb(x: u64) -> u64 {
    let addr = STORED_CB.load(Ordering::Acquire);
    if addr == 0 {
        return 0;
    }
    // SAFETY: test stores a live callback thunk pointer with signature `extern "C" fn(u64) -> u64`
    let f: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(addr as usize) };
    f(x)
}

extern "C" fn host_call_guest(cb: u64, arg: u64) -> u64 {
    rvm::call_guest(cb, &[arg]).unwrap_or(0)
}

static REMAP_ADDR: AtomicU64 = AtomicU64::new(0);

/// Register the non-qsort externs of `bpf/tests/callbacks.c` on `vm`.
fn register_callback_natives(vm: &Vm, with_dummy_qsort: bool) {
    vm.enable_callbacks();
    vm.register_extern_with_memory("host_remap", |mem, (): ()| {
        let addr = REMAP_ADDR.load(Ordering::Acquire);
        mem.write::<u64>(addr, 123)
            .expect("write mapped region inside callback");
        addr
    });
    // SAFETY: signatures match `bpf/tests/callbacks.c` and none unwind
    unsafe {
        if with_dummy_qsort {
            vm.register_native(
                "qsort",
                dummy_qsort as *const (),
                NativeSig::new(&[
                    NativeArg::Write(None),
                    NativeArg::Int,
                    NativeArg::Int,
                    NativeArg::Read(None),
                ]),
            )
            .unwrap();
        }
        vm.register_native("nat_double", nat_double as *const (), NativeSig::ints(1))
            .unwrap();
        vm.register_native(
            "apply_u64",
            apply_u64 as *const (),
            NativeSig::new(&[NativeArg::Read(None), NativeArg::Int]),
        )
        .unwrap();
        vm.register_native("fire_cb", fire_cb as *const (), NativeSig::ints(1))
            .unwrap();
        vm.register_native("host_call_guest", host_call_guest as *const (), NativeSig::ints(2).aware())
            .unwrap();
        vm.set_native_resolver(|imp| match imp.name {
            "call_float_cb" => Some(rvm::Resolved {
                func: call_float_cb as *const (),
                sig: None,
            }),
            "call_struct_cb" => Some(rvm::Resolved {
                func: call_struct_cb as *const (),
                sig: None,
            }),
            _ => None,
        });
    }
}

/// Miri-safe test of nested runs via `rvm::call_guest`: normal return, 2-level nesting, depth-8 `StackOverflow`,
/// memory fault inside callback, fuel exhaustion inside callback, `gotox` switch inside callback, and memory
/// remapping with window revalidation.
#[test]
fn call_guest_nested_runs() {
    assert_eq!(rvm::call_guest(0, &[]), None);

    let vm = Vm::with_config(VmConfig {
        instruction_limit: if cfg!(feature = "fuel") { 500 } else { 0 },
        ..VmConfig::default()
    })
    .unwrap();
    register_callback_natives(&vm, true);
    let mut prog = vm.load_elf(&object("tests/callbacks.o")).unwrap();

    // Basic nested call: guest_double(20) = 41
    assert_eq!(prog.call("run_call_guest", &[0, 20]).unwrap(), 41);

    // Multi-level nesting: guest_recurse(3) nests 4 frames (run_call_guest -> recurse(3) -> 2 -> 1 -> 0)
    assert_eq!(prog.call("run_call_guest", &[1, 3]).unwrap(), 4);

    // Depth-8 limit: guest_recurse(8) pushes 9 nested frames -> StackOverflow
    assert!(matches!(prog.call("run_call_guest", &[1, 8]), Err(VmError::Exec(ExecError::StackOverflow { .. }))));

    // Memory fault inside callback propagates cleanly and restores frames for subsequent calls
    assert!(matches!(prog.call("run_call_guest", &[2, 0]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));
    assert_eq!(prog.call("run_call_guest", &[0, 5]).unwrap(), 11);

    // Fuel exhaustion inside callback stops outer run with InstructionLimit
    #[cfg(feature = "fuel")]
    assert!(matches!(
        prog.call("run_call_guest", &[3, 10_000]),
        Err(VmError::Exec(ExecError::InstructionLimit { limit: 500 }))
    ));

    // Callback calling a host closure that touches guest memory, then reading stack after return
    let region = prog.memory_mut().map(64, Perms::RW).unwrap();
    REMAP_ADDR.store(region.base(), Ordering::Release);
    assert_eq!(prog.call("run_remap_and_read", &[10]).unwrap(), 10 + 77 + 55);

    // Dense switch (`gotox` -> `JumpIndirect`) inside a callback runs through `call_nested_on`
    assert_eq!(prog.call("run_call_guest", &[5, 6]).unwrap(), 70);

    // Bad guest code address fails the outer call
    assert!(matches!(
        prog.call("run_call_guest", &[99, 0xdead]),
        Err(VmError::Exec(ExecError::BadCodeAddress { target: 0xdead, .. }))
    ));
}

#[cfg(all(windows, not(miri)))]
#[test]
fn qsort_and_scoped_callback_abis() {
    let _guard = THUNK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use std::ffi::CString;

    unsafe extern "system" {
        fn LoadLibraryA(name: *const i8) -> *mut std::ffi::c_void;
        fn GetProcAddress(module: *mut std::ffi::c_void, name: *const i8) -> *const ();
    }

    let modes = [
        Passthrough::OFF,
        // SAFETY: test passes only valid pointers
        unsafe { Passthrough::on() },
        // SAFETY: test passes only valid pointers
        unsafe { Passthrough::untagged() },
    ];
    for mode in modes {
        let vm = Vm::with_config(VmConfig {
            passthrough: mode,
            ..VmConfig::default()
        })
        .unwrap();
        register_callback_natives(&vm, false);
        // SAFETY: resolving `ucrtbase.dll!qsort` and our test C natives
        unsafe {
            vm.set_native_resolver(|imp| match imp.name {
                "call_float_cb" => Some(rvm::Resolved {
                    func: call_float_cb as *const (),
                    sig: None,
                }),
                "call_struct_cb" => Some(rvm::Resolved {
                    func: call_struct_cb as *const (),
                    sig: None,
                }),
                name => {
                    let dll = imp.dll?;
                    let c_dll = CString::new(dll).ok()?;
                    let c_sym = CString::new(name).ok()?;
                    let module = LoadLibraryA(c_dll.as_ptr());
                    if module.is_null() {
                        return None;
                    }
                    let addr = GetProcAddress(module, c_sym.as_ptr());
                    (!addr.is_null()).then_some(rvm::Resolved { func: addr, sig: None })
                }
            });
        }

        let mut prog = vm.load_elf(&object("tests/callbacks.o")).unwrap();

        // Real ucrtbase.dll!qsort sorting {42, 7, 99, 1, 15, 3} -> {1, 3, 7, 15, 42, 99}
        let expected_qsort = 1 + 3 * 10 + 7 * 100 + 15 * 1000 + 42 * 10000 + 99 * 100000;
        assert_eq!(prog.call("test_qsort", &[]).unwrap(), expected_qsort, "mode={mode:?}");

        // Float/double callback args (xmm0..xmm3 + stack arg 5) and double return (xmm0)
        let expected_float = 1.5f64.to_bits()
            ^ (u64::from(2.25f32.to_bits()) << 1)
            ^ (3u64 << 2)
            ^ (4.0f64.to_bits() >> 1)
            ^ (u64::from(5.5f32.to_bits()) << 3);
        assert_eq!(prog.call("test_float_cb", &[]).unwrap(), expected_float, "mode={mode:?}");

        // By-reference S3 (3 B) and S12 (12 B) structs unmarshalled into guest registers
        let expected_struct = 1 + 2 * 2 + 3 * 3 + 4 + 5 * 10 + 6 * 100 + 7 * 1000;
        assert_eq!(prog.call("test_struct_cb", &[7]).unwrap(), expected_struct, "mode={mode:?}");

        // `&extern` native token passed as Callback resolves to the native's real function pointer
        assert_eq!(prog.call("test_token_as_cb", &[21]).unwrap(), 42, "mode={mode:?}");

        // Null callback passes through unchanged
        assert_eq!(prog.call("test_null_cb", &[21]).unwrap(), 999, "mode={mode:?}");
    }
}

#[cfg(not(miri))]
#[test]
fn retained_callbacks_replace_cross_thread_and_pool_limit() {
    let _guard = THUNK_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let vm = Vm::new();
    register_callback_natives(&vm, true);

    let plugin = Plugin::new("cb", vm.load_elf(&object("tests/callbacks.o")).unwrap());

    // Pool exhaustion test (64 slots alive, 65th returns NULL, free & reallocate succeeds)
    assert_eq!(plugin.call("test_pool_exhaustion", &[]).unwrap(), 1);

    // Retained exported and static callbacks
    let exp_thunk = plugin.call("make_exported_cb", &[]).unwrap();
    let static_thunk = plugin.call("make_static_cb", &[]).unwrap();
    assert_ne!(exp_thunk, 0);
    assert_ne!(static_thunk, 0);

    // 1. Synchronous CALLS_BACK invocation (Case 1)
    STORED_CB.store(exp_thunk, Ordering::Release);
    assert_eq!(plugin.call("run_fire_cb", &[5]).unwrap(), 5 * 2 + 1);

    // 2. Later invocation on an idle Plugin from another thread (Case 2)
    let exp_fn: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(exp_thunk as usize) };
    let static_fn: extern "C" fn(u64) -> u64 = unsafe { std::mem::transmute(static_thunk as usize) };
    let t = std::thread::spawn(move || (exp_fn(6), static_fn(6)));
    assert_eq!(t.join().unwrap(), (6 * 2 + 1, 106));
    assert!(plugin.take_callback_error().is_none());

    // 3. Cross-thread invocation while Plugin is busy fails cleanly and records PluginBusy
    {
        let _busy = plugin.lock().unwrap();
        let t = std::thread::spawn(move || exp_fn(7));
        assert_eq!(t.join().unwrap(), 0);
    }
    assert!(matches!(plugin.take_callback_error(), Some(VmError::PluginBusy(name)) if name == "cb"));
    assert!(plugin.take_callback_error().is_none());

    // 4. Plugin::replace: exported callback follows new program (FACTOR=10), static callback dies
    plugin
        .replace(vm.load_elf(&object("tests/callbacks_v2.o")).unwrap())
        .unwrap();
    assert_eq!(exp_fn(5), 5 * 10 + 1);
    assert_eq!(plugin.call("run_fire_cb", &[5]).unwrap(), 5 * 10 + 1);
    assert_eq!(static_fn(5), 0);

    // Clean up retained exported callback and verify Program::drop frees any remaining slots
    plugin.call("free_cb", &[exp_thunk]).unwrap();
    STORED_CB.store(0, Ordering::Release);
}
