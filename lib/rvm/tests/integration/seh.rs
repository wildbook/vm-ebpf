//! `VmConfig::catch`: exceptions in native functions and access violations of raw guest accesses fail the call, and
//! what the guards must pass on ends the process.
//!
//! The natives are functions of system DLLs: a guard catches only below a native function outside the image that
//! holds rvm, which a function of this test binary is not.

use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::process::Command;
use std::sync::OnceLock;

use ebpf_asm::Assembler;
use rvm::{Catch, ExecError, HostError, Image, Import, NativeSig, Passthrough, Plugin, Program, Vm, VmConfig, VmError};

use crate::common::object;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *const ();
    fn VirtualAlloc(addr: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
}

const ACCESS_VIOLATION: u32 = 0xC000_0005;
const BREAKPOINT: u32 = 0x8000_0003;

/// The function `name` of the loaded system DLL `dll`.
fn system(dll: &str, name: &str) -> *const () {
    let (dll, name) = (CString::new(dll).unwrap(), CString::new(name).unwrap());
    let func = unsafe { GetProcAddress(GetModuleHandleA(dll.as_ptr()), name.as_ptr()) };
    assert!(!func.is_null(), "{name:?} of {dll:?}");
    func
}

extern "win64" fn unused(_: u64) -> u64 {
    0
}

/// A VM with the natives `bpf/tests/seh.c` imports and the host function of `bpf/tests/seh_host.c`.
fn vm(config: VmConfig) -> Vm {
    let natives = [
        ("nat_strlen", system("ntdll.dll", "strlen"), NativeSig::ints(1)),
        ("nat_raise", system("kernel32.dll", "RaiseException"), NativeSig::ints(4)),
        ("nat_break", system("kernel32.dll", "DebugBreak"), NativeSig::ints(0)),
        ("nat_sort", system("ntdll.dll", "qsort"), NativeSig::ints(4)),
        // the C host of rvmrt's test has these two
        ("nat_throw", unused as *const (), NativeSig::ints(1)),
        ("nat_recurse", unused as *const (), NativeSig::ints(1)),
    ];
    // SAFETY: each takes integer arguments in the Windows x64 convention; the tests pass the pointers among them
    let vm = unsafe { Vm::with_natives(config, &natives) }.unwrap();
    // SAFETY: the tests pass an address that is readable, or want the fault
    vm.register_extern("host_read", |p: u64| unsafe { (p as *const u64).read_volatile() });
    vm
}

fn catching(catch: Catch, config: VmConfig) -> VmConfig {
    VmConfig { catch, ..config }
}

const NATIVES: Catch = Catch {
    native_exceptions: true,
    raw_faults: false,
};
const RAW: Catch = Catch {
    native_exceptions: false,
    raw_faults: true,
};

/// A configuration without an instruction limit, and with the `fuel` feature one with a limit, whose runs take the
/// metered handlers.
fn limits() -> Vec<VmConfig> {
    // 0 is no limit
    let limits: &[u64] = match cfg!(feature = "fuel") {
        true => &[0, 1_000_000],
        false => &[0],
    };
    let config = |&instruction_limit| VmConfig {
        instruction_limit,
        ..VmConfig::default()
    };
    limits.iter().map(config).collect()
}

fn seh_program(vm: &Vm) -> Program {
    vm.load_elf(&object("tests/seh.o")).unwrap()
}

/// 64 KiB of address space that is reserved and never committed, so every access to it is an access violation.
fn unmapped() -> u64 {
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_NOACCESS: u32 = 1;
    let reserved = unsafe { VirtualAlloc(std::ptr::null_mut(), 1 << 16, MEM_RESERVE, PAGE_NOACCESS) };
    assert!(!reserved.is_null());
    reserved as u64
}

/// The code and the native's name of the exception that failed `result`.
fn exception(result: rvm::Result<u64>) -> (u32, String) {
    match result {
        Err(VmError::Exec(ExecError::NativeException { code, native, .. })) => (code, native),
        other => panic!("{other:?}"),
    }
}

/// An access violation and a raised exception in a native function fail the call, here and through a plugin that
/// calls the faulting one, and every plugin is callable afterwards.
#[test]
fn native_exceptions_fail_the_call() {
    for config in limits() {
        let vm = vm(catching(NATIVES, config));
        let plugin = Plugin::new("faulty", seh_program(&vm));
        vm.export(&plugin, "text_len").unwrap();
        // main: text_len(r1) in the plugin
        let mut asm = Assembler::new();
        asm.call(0).exit();
        let mut image = Image::from_code(asm.assemble().unwrap());
        image.externs.push((0, Import::Name("text_len".into())));
        let caller = Plugin::new("caller", vm.load_image(image).unwrap());
        let text = c"four".as_ptr() as u64;

        for _ in 0..2 {
            assert_eq!(exception(plugin.call("text_len", &[0])), (ACCESS_VIOLATION, "nat_strlen".into()));
            assert_eq!(exception(plugin.call("raise", &[0xE000_0001])), (0xE000_0001, "nat_raise".into()));
            assert_eq!(plugin.call("text_len", &[text]).unwrap(), 5);

            let err = caller.call("main", &[0]).unwrap_err();
            let VmError::Host(HostError::Plugin {
                plugin: name, error, ..
            }) = err
            else {
                panic!("{err:?}")
            };
            assert_eq!((name.as_str(), exception(Err(*error)).0), ("faulty", ACCESS_VIOLATION));
            assert_eq!(caller.call("main", &[text]).unwrap(), 5);
        }
    }
}

/// With passthrough, a guest access of every kind at an unmapped address fails with the fault that the same access
/// gives where the address is in no region at all, and the same accesses work on mapped memory.
#[test]
fn raw_faults_are_memory_faults() {
    let bad = unmapped();
    // func, the arguments after the pointer, an offset of the pointer
    let accesses: [(&str, &[u64], u64); 31] = [
        ("load8", &[], 0),
        ("load16", &[], 0x100),
        ("load32", &[], 0),
        ("load64", &[], 8),
        ("store8", &[1], 0),
        ("store16", &[1], 2),
        ("store32", &[1], 0),
        ("store64", &[1], 0),
        ("clear32", &[], 4),
        ("clear64", &[], 0),
        ("loads8", &[], 1),
        ("loads16", &[], 0),
        ("loads32", &[], 0),
        ("add64", &[1], 0),
        ("add32", &[1], 4),
        ("or64", &[1], 0),
        ("and32", &[1], 0),
        ("xor64", &[1], 8),
        ("swap64", &[1], 0),
        ("swap32", &[1], 0),
        ("cas64", &[0, 1], 0),
        ("cas32", &[0, 1], 0),
        ("acquire8", &[], 3),
        ("acquire64", &[], 0),
        ("release16", &[1], 0),
        ("release64", &[1], 0),
        ("fused", &[8], 0),
        ("fused", &[16], 0),
        ("nested", &[], 0),
        // an atomic at an address that isn't aligned faults before it touches memory
        ("add64", &[1], 1),
        ("acquire64", &[], 4),
    ];
    let mut checked = seh_program(&vm(VmConfig::default()));

    for passthrough in unsafe { [Passthrough::on(), Passthrough::untagged()] } {
        for config in limits() {
            let config = VmConfig { passthrough, ..config };
            let mut program = seh_program(&vm(catching(RAW, config)));
            // twice: the first access of a kind takes its window, the next ones run in it
            for _ in 0..2 {
                for (func, rest, offset) in accesses {
                    let args: Vec<u64> = [bad + offset].into_iter().chain(rest.iter().copied()).collect();
                    let fault = |result: rvm::Result<u64>| match result {
                        Err(VmError::Exec(ExecError::MemoryFault { pc, error })) => (pc, error),
                        other => panic!("{func}{args:x?}: {other:?}"),
                    };
                    assert_eq!(fault(program.call(func, &args)), fault(checked.call(func, &args)), "{func}");
                }
                mapped_accesses(&mut program);
            }
        }
    }
}

/// The accesses of `bpf/tests/seh.c` on host memory that is mapped.
fn mapped_accesses(program: &mut Program) {
    #[repr(C, align(8))]
    struct Cells {
        wide: u64,
        word: u32,
        half: u16,
        bytes: [u8; 2],
    }

    let mut cells = Cells {
        wide: 0x8877_6655_4433_2211,
        word: 0x8000_0001,
        half: 0xfffe,
        bytes: [0x80, 0x7f],
    };
    // `as` exposes the provenance of the pointers the guest uses
    let (wide, word) = (&raw mut cells.wide as u64, &raw mut cells.word as u64);
    let (half, bytes) = (&raw mut cells.half as u64, &raw mut cells.bytes as u64);
    let mut call = |func: &str, args: &[u64]| program.call(func, args).unwrap();

    assert_eq!(call("load64", &[wide]), 0x8877_6655_4433_2211);
    assert_eq!(call("load32", &[word]), 0x8000_0001);
    assert_eq!(call("load16", &[half]), 0xfffe);
    assert_eq!(call("load8", &[bytes + 1]), 0x7f);
    assert_eq!(call("loads32", &[word]), 0xffff_ffff_8000_0001);
    assert_eq!(call("loads16", &[half]), 0xffff_ffff_ffff_fffe);
    assert_eq!(call("loads8", &[bytes]), 0xffff_ffff_ffff_ff80);
    assert_eq!(call("acquire64", &[wide]), 0x8877_6655_4433_2211);
    assert_eq!(call("acquire8", &[bytes]), 0x80);
    assert_eq!(call("fused", &[wide, 4]), 0x8877_6655 + wide);
    assert_eq!(call("nested", &[wide - 8]), 0x8877_6655_4433_2212);

    assert_eq!(call("add64", &[wide, 1]), 0x8877_6655_4433_2211);
    assert_eq!(call("or64", &[wide, 0xf]), 0x8877_6655_4433_2212);
    assert_eq!(call("xor64", &[wide, 0xff]), 0x8877_6655_4433_221f);
    assert_eq!(call("swap64", &[wide, 5]), 0x8877_6655_4433_22e0);
    assert_eq!(call("cas64", &[wide, 6, 9]), 5);
    assert_eq!(call("cas64", &[wide, 5, 9]), 5);
    assert_eq!(call("add32", &[word, 0x8000_0000]), 0x8000_0001);
    assert_eq!(call("and32", &[word, 0xff]), 1);
    assert_eq!(call("swap32", &[word, 3]), 1);
    assert_eq!(call("cas32", &[word, 3, 0xffff_ffff]), 3);
    call("release16", &[half, 0x1234]);
    call("store8", &[bytes, 0x11]);
    // SAFETY: the guest is done with the cells
    let cells = unsafe { (&raw const cells).read_volatile() };
    assert_eq!((cells.wide, cells.word, cells.half, cells.bytes), (9, 0xffff_ffff, 0x1234, [0x11, 0x7f]));

    call("store64", &[wide, 1]);
    call("release64", &[wide + 8, 2]);
    call("store32", &[word, 3]);
    call("store16", &[half, 4]);
    call("clear64", &[wide]);
    call("clear32", &[word]);
    assert_eq!(call("load64", &[wide]), 7);
    assert_eq!(call("load64", &[word]), 7 | 4 << 32);
}

/// The panic of a host function unwinds through the guard of raw accesses as through an unguarded call, and the
/// program runs afterwards.
#[test]
fn host_panic_unwinds_through_the_raw_guard() {
    // SAFETY: the guest dereferences no pointer
    let passthrough = unsafe { Passthrough::on() };
    let vm = Vm::with_config(VmConfig {
        passthrough,
        catch: RAW,
        ..VmConfig::default()
    })
    .unwrap();
    vm.register_extern("host_read", |p: u64| {
        assert!(p != 0, "host_read failed");
        p
    });
    let mut program = vm.load_elf(&object("tests/seh_host.o")).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| program.call("via_host", &[0]))).is_err());
    assert_eq!(program.call("via_host", &[5]).unwrap(), 5);
}

/// Runs the test `name` of this binary in a process of its own, where it does what must end the process, and
/// returns that process's exit code.
fn in_child(name: &str) -> u32 {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap()
        .status;
    status.code().unwrap() as u32
}

const CHILD: &str = "RVM_SEH_CHILD";

fn is_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// A breakpoint in a native function is the debugger's: the guard passes it on, and without a debugger it ends the
/// process.
#[test]
fn breakpoint_passes_on() {
    if !is_child() {
        assert_eq!(in_child("seh::breakpoint_passes_on"), BREAKPOINT);
        return;
    }
    let mut program = seh_program(&vm(catching(NATIVES, VmConfig::default())));
    let _ = program.call("debug_break", &[]);
    std::process::exit(0);
}

/// The plugin that `compare` calls into.
static INNER: OnceLock<Plugin> = OnceLock::new();

/// A `qsort` callback that calls a plugin whose host function reads a null pointer.
extern "C" fn compare(_: *const c_void, _: *const c_void) -> i32 {
    let _ = INNER.get().unwrap().call("via_host", &[0]);
    0
}

/// A guarded native that calls back into a plugin whose call faults in a host function: the exception lies below
/// frames of rvm, which hold the inner plugin's lock, so the guard passes it on and the process ends.
#[test]
fn fault_below_a_reentered_plugin_passes_on() {
    if !is_child() {
        assert_eq!(in_child("seh::fault_below_a_reentered_plugin_passes_on"), ACCESS_VIOLATION);
        return;
    }
    let vm = vm(catching(NATIVES, VmConfig::default()));
    let inner = Plugin::new("inner", vm.load_elf(&object("tests/seh_host.o")).unwrap());
    INNER.set(inner).unwrap();
    let mut outer = seh_program(&vm);
    let mut values = [2u64, 1];
    let _ = outer.call("sort", &[values.as_mut_ptr() as u64, compare as *const () as u64]);
    std::process::exit(0);
}

/// The same native and callback without the fault: the call back into the plugin works under the guard.
#[test]
fn reentered_plugin_runs_under_the_guard() {
    extern "C" fn ascending(a: *const c_void, b: *const c_void) -> i32 {
        static VALUE: u64 = 3;
        let read = INNER_OK.get().unwrap().call("via_host", &[&raw const VALUE as u64]);
        assert_eq!(read.unwrap(), 3);
        // SAFETY: `qsort` passes two of its elements
        unsafe { (*a.cast::<u64>()).cmp(&*b.cast::<u64>()) as i32 }
    }
    static INNER_OK: OnceLock<Plugin> = OnceLock::new();

    let vm = vm(catching(NATIVES, VmConfig::default()));
    let inner = Plugin::new("inner", vm.load_elf(&object("tests/seh_host.o")).unwrap());
    INNER_OK.set(inner).unwrap();
    let mut outer = seh_program(&vm);
    let mut values = [2u64, 1];
    outer
        .call("sort", &[values.as_mut_ptr() as u64, ascending as *const () as u64])
        .unwrap();
    assert_eq!(values, [1, 2]);
}
