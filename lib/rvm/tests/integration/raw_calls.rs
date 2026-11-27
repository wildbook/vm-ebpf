//! Raw calls: what a `callx` through an address without a region tag does with [`RawCalls`] on and off, over the
//! guest in `bpf/tests/raw_calls.c`.

use rvm::{ExecError, Passthrough, Program, RawCalls, Vm, VmConfig, VmError};

use crate::common::object;

extern "C" fn zero() -> u64 {
    7
}

extern "C" fn one(a: u64) -> u64 {
    a + 1
}

extern "C" fn five(a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
    a + 10 * b + 100 * c + 1000 * d + 10_000 * e
}

/// # Safety
///
/// `buf` must point to `len` readable bytes.
unsafe extern "C" fn sum(buf: *const u8, len: u64) -> u64 {
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    bytes.iter().map(|&b| u64::from(b)).sum()
}

/// `struct host_api` in the guest.
#[repr(C)]
struct HostApi {
    zero: extern "C" fn() -> u64,
    one: extern "C" fn(u64) -> u64,
    five: extern "C" fn(u64, u64, u64, u64, u64) -> u64,
    sum: unsafe extern "C" fn(*const u8, u64) -> u64,
}

static API: HostApi = HostApi { zero, one, five, sum };

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

fn on() -> RawCalls {
    // SAFETY: the tests pass the guest only the functions above, with the arguments they take
    unsafe { RawCalls::on() }
}

/// Raw calls dispatch vtable entries, callbacks, guest functions, helper IDs below 64 KiB, and `HOST()` pointers.
#[test]
fn raw_calls_dispatch() {
    // SAFETY: the guest reads `API` and its own stack
    let mut untagged = load(unsafe { Passthrough::untagged() }, on());
    assert_eq!(untagged.call("through_table", &[&raw const API as u64]).unwrap(), 7 + 11 + 54_321 + 10);

    let mut tagged = load(Passthrough::OFF, on());
    assert_eq!(tagged.call("call_back", &[API.one as usize as u64, 41]).unwrap(), 43);
    assert_eq!(tagged.call("call_own", &[21]).unwrap(), 43);
    assert_eq!(tagged.call("call_back", &[100, 21]).unwrap(), 43);
    assert_eq!(tagged.call("sum_host", &[API.sum as usize as u64]).unwrap(), 10);

    let err = tagged.call("call_low", &[1]).unwrap_err();
    assert!(matches!(err, VmError::Exec(ExecError::UnknownHelper { id: 0x1234, .. })), "{err}");
}

/// Without raw calls, an untagged target is a helper ID if it fits one and no code address otherwise; `Loader` switches
/// per program.
#[test]
fn raw_calls_off_and_per_program() {
    let mut off = load(Passthrough::OFF, RawCalls::OFF);
    for (func, target) in [("call_back", API.one as usize as u64), ("call_high", 0x7ff8_1234_0000)] {
        let err = off.call(func, &[target, 0]).unwrap_err();
        assert!(
            matches!(err, VmError::Exec(ExecError::BadCodeAddress { target: t, .. }) if t == target),
            "{func}: {err}"
        );
    }
    assert!(matches!(
        off.call("call_back", &[0x10000, 0]),
        Err(VmError::Exec(ExecError::UnknownHelper { id: 0x10000, .. }))
    ));
    assert_eq!(off.call("call_back", &[100, 21]).unwrap(), 43);

    let vm = Vm::new();
    let elf = object("tests/raw_calls.o");
    // SAFETY: as above
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
    assert!(matches!(checked.call("through_table", &[api]), Err(VmError::Exec(ExecError::MemoryFault { .. }))));
    assert!(matches!(
        checked.call("call_back", &[API.one as usize as u64, 41]),
        Err(VmError::Exec(ExecError::BadCodeAddress { .. }))
    ));
}
