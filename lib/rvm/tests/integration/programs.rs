//! Clang-compiled programs exercising atomics, maps, data relocations, CO-RE and the
//! standard helpers.

use rvm::{ExecError, Perms, Vm, VmError, FIRST_FREE_REGION};

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

/// CO-RE against a host whose `struct event` moved `pid` and lacks `flags`
/// (bpf/core_guard.c): field accesses follow the host layout, an existence check
/// takes the fallback, and an unguarded access to the missing field fails when run.
#[test]
fn core_relocations_follow_host_layout() {
    let mut vm = Vm::new();
    let u64_t = vm.types().int("u64", 8, false);
    let u32_t = vm.types().int("u32", 4, false);
    let event_ty = vm.types().add_struct("event", 16);
    vm.types().member(event_ty, "timestamp", 0, u64_t);
    vm.types().member(event_ty, "pid", 12, u32_t);
    let mut program = vm.load_elf(&object("core_guard.o")).unwrap();

    let event = program.memory_mut().map(FIRST_FREE_REGION, 16, Perms::R);
    program.memory_mut().write::<u32>(event + 12, 77).unwrap();

    assert_eq!(program.call("read_pid", &[event]).unwrap(), 77);
    assert_eq!(program.call("read_flags", &[event]).unwrap(), 0xdead);
    let err = program.call("read_flags_unguarded", &[event]).unwrap_err();
    assert!(matches!(err, VmError::Exec(ExecError::UnresolvedCoreRelo { .. })), "{err}");
}

/// A host can ship its actual layout as BTF compiled from a C header
/// (bpf/host_event.c), instead of describing it field by field: `append_btf` reads
/// the struct straight out of the compiled object.
#[test]
fn core_relocations_follow_appended_host_btf() {
    let host_module = rvm::Module::from_elf("host_event", &object("host_event.o")).unwrap();
    let mut vm = Vm::new();
    vm.types().append_btf(host_module.btf_data.as_ref().unwrap()).unwrap();
    let mut program = vm.load_elf(&object("core_guard.o")).unwrap();

    // Host layout: flags(0), pid(4), timestamp(8); every field present, reordered.
    let event = program.memory_mut().map(FIRST_FREE_REGION, 16, Perms::R);
    program.memory_mut().write::<u32>(event, 0xABCD).unwrap(); // flags
    program.memory_mut().write::<u32>(event + 4, 77).unwrap(); // pid

    assert_eq!(program.call("read_pid", &[event]).unwrap(), 77);
    assert_eq!(program.call("read_flags", &[event]).unwrap(), 0xABCD);
    assert_eq!(program.call("read_flags_unguarded", &[event]).unwrap(), 0xABCD);
}

/// A CO-RE bitfield read (bpf/core_bitfield.c) written out in `bpf_core_read.h`'s
/// `BPF_CORE_READ_BITFIELD` style, exercising `FieldLShiftU64`/`FieldRShiftU64`/
/// `FieldSigned` together: the host's bitfield sits at a different bit position than
/// the one the program was compiled against, and is signed.
#[test]
fn core_relocations_read_signed_bitfield() {
    let mut vm = Vm::new();
    let u32_t = vm.types().int("unsigned int", 4, false);
    let i32_t = vm.types().int("int", 4, true);
    let bits = vm.types().add_struct("bits", 4);
    vm.types().bitfield_member(bits, "reserved", 0, 20, u32_t);
    vm.types().bitfield_member(bits, "b", 20, 12, i32_t);
    let mut program = vm.load_elf(&object("core_bitfield.o")).unwrap();

    // b = -5 (12-bit two's complement) at bit 20, with arbitrary bits below it.
    let word: u32 = (0xABCDE) | (0xFFBu32 << 20);
    let ptr = program.memory_mut().map(FIRST_FREE_REGION, 4, Perms::R);
    program.memory_mut().write::<u32>(ptr, word).unwrap();

    assert_eq!(program.call("read_b", &[ptr]).unwrap(), -5i64 as u64);
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
