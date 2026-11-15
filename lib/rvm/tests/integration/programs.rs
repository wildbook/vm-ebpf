//! Clang-compiled programs exercising atomics, maps and the standard helpers.

use rvm::Vm;

use crate::common::object;

/// Every atomic form clang emits (bpf/atomics.c), with the expected values worked
/// out by hand from the RFC 9669 semantics.
#[test]
fn test_clang_atomics() {
    let mut program = Vm::new().load_elf(&object("atomics.o")).unwrap();

    assert_eq!(program.call("run", &[5]).unwrap(), 1058);

    let bss = rvm::region_base(rvm::DATA_REGION);
    assert_eq!(program.memory().read::<u64>(bss).unwrap(), 9);
    assert_eq!(program.memory().read::<u32>(bss + 8).unwrap(), 0xFFFF_FFFF);
}

/// Pointers in `.data` and `.rodata` (bpf/data_ptrs.c) are relocated at link time,
/// including an addend into the middle of an array.
#[test]
fn data_pointers_are_relocated() {
    let mut program = Vm::new().load_elf(&object("data_ptrs.o")).unwrap();
    assert_eq!(program.call("deref", &[]).unwrap(), 42 + 10 + 30);
}

/// Array and hash maps from bpf/maps.c, used from the guest and the host.
#[test]
fn test_maps() {
    const EEXIST: u64 = (-17i64) as u64;
    const E2BIG: u64 = (-7i64) as u64;
    const ENOENT: u64 = (-2i64) as u64;

    let mut program = Vm::new().load_elf(&object("maps.o")).unwrap();

    // Array: the guest increments a value in place through the looked-up pointer.
    assert_eq!(program.call("count", &[1]).unwrap(), 1);
    assert_eq!(program.call("count", &[5]).unwrap(), 2);
    assert_eq!(program.call("count", &[2]).unwrap(), 1);
    let counters = program.map("counters").unwrap();
    assert_eq!(counters.get(&1u32.to_le_bytes()), Some(&2u64.to_le_bytes()[..]));
    assert_eq!(counters.get(&4u32.to_le_bytes()), None); // out of range

    // Hash: NOEXIST inserts, capacity is 2, delete frees a slot.
    assert_eq!(program.call("remember", &[7]).unwrap(), 0);
    assert_eq!(program.call("remember", &[7]).unwrap(), EEXIST);
    assert_eq!(program.call("remember", &[8]).unwrap(), 0);
    assert_eq!(program.call("remember", &[9]).unwrap(), E2BIG);
    assert_eq!(program.call("recall", &[8]).unwrap(), 80);
    assert_eq!(program.call("forget", &[7]).unwrap(), 0);
    assert_eq!(program.call("forget", &[7]).unwrap(), ENOENT);
    assert_eq!(program.call("recall", &[7]).unwrap(), u64::MAX);

    // The host sees and edits the same values.
    let mut seen = program.map("seen").unwrap();
    assert_eq!(seen.get(&8u64.to_le_bytes()), Some(&80u64.to_le_bytes()[..]));
    seen.update(&9u64.to_le_bytes(), &99u64.to_le_bytes(), rvm::BPF_ANY)
        .unwrap();
    assert_eq!(program.call("recall", &[9]).unwrap(), 99);
}

/// The standard helpers only link once enabled, and trace_printk formats like the kernel.
#[test]
fn test_std_helpers() {
    use std::sync::{Arc, Mutex};

    let elf = object("std_helpers.o");

    let err = Vm::new().load_elf(&elf).unwrap_err().to_string();
    assert!(err.contains("ktime_get_ns"), "{err}");

    let lines = Arc::new(Mutex::new(Vec::new()));
    let vm = Vm::new();
    vm.enable_time();
    vm.enable_random();
    let sink = lines.clone();
    vm.enable_print(move |line| sink.lock().unwrap().push(line.to_string()));
    let mut program = vm.load_elf(&elf).unwrap();

    program.call("report", &[300]).unwrap();
    assert_eq!(*lines.lock().unwrap(), ["x=300 neg=-300 hex=12c"]);
    assert_eq!(program.call("draws_differ", &[]).unwrap(), 1);
}
