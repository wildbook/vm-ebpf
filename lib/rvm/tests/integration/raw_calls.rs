//! Raw calls: what a `callx` through an address without a region tag does with [`RawCalls`] on and off, over the
//! guest in `bpf/tests/raw_calls.c`.

use rvm::{ExecError, Passthrough, Program, RawCalls, Vm, VmConfig, VmError};

use crate::common::object;

extern "win64" fn zero() -> u64 {
    7
}

extern "win64" fn one(a: u64) -> u64 {
    a + 1
}

extern "win64" fn five(a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
    a + 10 * b + 100 * c + 1000 * d + 10_000 * e
}

/// # Safety
///
/// `buf` must point to `len` readable bytes.
unsafe extern "win64" fn sum(buf: *const u8, len: u64) -> u64 {
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    bytes.iter().map(|&b| u64::from(b)).sum()
}

/// `struct host_api` in the guest.
#[repr(C)]
struct HostApi {
    zero: extern "win64" fn() -> u64,
    one: extern "win64" fn(u64) -> u64,
    five: extern "win64" fn(u64, u64, u64, u64, u64) -> u64,
    sum: unsafe extern "win64" fn(*const u8, u64) -> u64,
}

static API: HostApi = HostApi { zero, one, five, sum };

/// The guest in a VM with helper 100, loaded with `passthrough` and `raw_calls`.
fn load(passthrough: Passthrough, raw_calls: RawCalls) -> Program {
    let config = VmConfig {
        passthrough,
        raw_calls,
        ..VmConfig::default()
    };
    let vm = Vm::with_config(config).unwrap();
    vm.register_helper(100, |x: u64| x * 2);
    vm.load_elf(&object("tests/raw_calls.o")).unwrap()
}

/// Raw calls on.
fn on() -> RawCalls {
    // SAFETY: the tests pass the guest only the functions above, with the arguments they take
    unsafe { RawCalls::on() }
}

/// An untagged guest reads a table of function pointers in a host struct and calls each, with 0, 1 and 5 integers
/// and with a pointer into its stack.
#[test]
fn table_of_function_pointers() {
    // SAFETY: the guest reads `API` and its own stack
    let mut program = load(unsafe { Passthrough::untagged() }, on());
    let api = &raw const API as u64;
    assert_eq!(program.call("through_table", &[api]).unwrap(), 7 + 11 + 54_321 + 10);
}

/// A function pointer in an argument is called whatever the memory mode, and the other targets of a `callx` keep
/// their meaning: the guest's own functions, and helper IDs below 64 KiB.
#[test]
fn callback_argument() {
    let mut program = load(Passthrough::OFF, on());
    assert_eq!(program.call("call_back", &[API.one as usize as u64, 41]).unwrap(), 43);
    assert_eq!(program.call("call_own", &[21]).unwrap(), 43);
    assert_eq!(program.call("call_back", &[100, 21]).unwrap(), 43);

    let err = program.call("call_low", &[1]).unwrap_err();
    assert!(matches!(err, VmError::Exec(ExecError::UnknownHelper { id: 0x1234, .. })), "{err}");
}

/// A guest with tagged pointers strips the tag of the pointer a native function follows.
#[test]
fn untag_passes_the_host_address() {
    let mut program = load(Passthrough::OFF, on());
    assert_eq!(program.call("sum_untagged", &[API.sum as usize as u64]).unwrap(), 10);
}

/// Without raw calls, an untagged target is a helper ID if it fits one and no code address otherwise. `call_high`
/// also shows that `NATIVE_AT` keeps all 64 bits of its address.
#[test]
fn off_is_a_helper_id_or_a_bad_address() {
    // SAFETY: nothing the guest runs here reads memory
    for passthrough in [Passthrough::OFF, unsafe { Passthrough::untagged() }] {
        let mut program = load(passthrough, RawCalls::OFF);
        for (func, target) in [("call_back", API.one as usize as u64), ("call_high", 0x7ff8_1234_0000)] {
            let err = program.call(func, &[target, 0]).unwrap_err();
            assert!(
                matches!(err, VmError::Exec(ExecError::BadCodeAddress { target: t, .. }) if t == target),
                "{func}: {err}"
            );
        }

        let err = program.call("call_back", &[0x10000, 0]).unwrap_err();
        assert!(matches!(err, VmError::Exec(ExecError::UnknownHelper { id: 0x10000, .. })), "{err}");
        assert_eq!(program.call("call_back", &[100, 21]).unwrap(), 43);
    }
}

/// A loader gives one program raw calls and untagged memory in a VM whose other programs have neither.
#[test]
fn switches_per_program() {
    let vm = Vm::new();
    let elf = object("tests/raw_calls.o");
    // SAFETY: as in `table_of_function_pointers`
    let untagged = unsafe { Passthrough::untagged() };
    let mut trusted = vm
        .loader()
        .passthrough(untagged)
        .raw_calls(on())
        .load_elf(&elf)
        .unwrap();
    let mut checked = vm.load_elf(&elf).unwrap();

    let api = &raw const API as u64;
    assert_eq!(trusted.call("through_table", &[api]).unwrap(), 7 + 11 + 54_321 + 10);
    let err = checked.call("through_table", &[api]).unwrap_err();
    assert!(matches!(err, VmError::Exec(ExecError::MemoryFault { .. })), "{err}");
    let err = checked.call("call_back", &[API.one as usize as u64, 41]).unwrap_err();
    assert!(matches!(err, VmError::Exec(ExecError::BadCodeAddress { .. })), "{err}");
}
