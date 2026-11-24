//! Native functions: signature checks at link and image load, pointer arguments in tagged and untagged mode,
//! re-entry and instruction limits.

use std::cell::RefCell;

use rvm::{
    ExecError, LinkError, MemoryError, NativeArg, NativeSig, Passthrough, Plugin, Program, Vm, VmConfig, VmError,
    WeakPlugin, STACK_REGION,
};

use crate::common::object;

extern "win64" fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

extern "win64" fn five(a: u64, b: u64, c: u64, d: u64, e: u64) -> u64 {
    a + 10 * b + 100 * c + 1000 * d + 10_000 * e
}

/// # Safety
///
/// `buf` must point to `len` readable bytes, or `len` be 0.
unsafe extern "win64" fn sum(buf: *const u8, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    bytes.iter().map(|&b| u64::from(b)).sum()
}

/// # Safety
///
/// `buf` must point to `len` writable bytes.
unsafe extern "win64" fn fill(buf: *mut u8, len: u64, byte: u64) -> u64 {
    unsafe { buf.write_bytes(byte as u8, len as usize) };
    0
}

/// # Safety
///
/// `p` must point to a readable byte.
unsafe extern "win64" fn first(p: *const u8) -> u64 {
    unsafe { p.read() }.into()
}

thread_local! {
    /// The plugin that `reenter` calls back into.
    static REENTERED: RefCell<Option<WeakPlugin>> = const { RefCell::new(None) };
}

/// 1 if a call back into the plugin that called it finds the plugin busy, else 0.
extern "win64" fn reenter(x: u64) -> u64 {
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
