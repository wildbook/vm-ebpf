//! Plugins: exports, reloads, re-entrancy, and sharing maps/regions/borrows.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rvm::{
    HostError, Image, Import, LimitedCall, LinkError, Passthrough, Plugin, Program, ValueSpacing, Vm, VmError,
    WeakPlugin,
};

use crate::common::object;

/// The instruction limit covers a whole call tree: what an export runs counts against the program that called it.
#[cfg(feature = "fuel")]
#[test]
fn instruction_limit_covers_plugin_calls() {
    use ebpf_asm::{Assembler, R0, R1, R6};
    use rvm::{ExecError, VmConfig, DEFAULT_INSTRUCTION_LIMIT};

    const SPINS: i32 = if cfg!(miri) { 200 } else { 200_000 };
    const CALLS: i32 = if cfg!(miri) { 5 } else { 50 };
    const LIMIT: u64 = if cfg!(miri) { 1_000 } else { DEFAULT_INSTRUCTION_LIMIT };

    // spin(n): count n down to 0, 2 n + 2 instructions
    let mut asm = Assembler::new();
    let spin = asm.label();
    asm.bind(spin);
    asm.sub64_imm(R1, 1).jne_imm(R1, 0, spin);
    asm.mov64_imm(R0, 1).exit();
    let vm = Vm::with_config(VmConfig {
        instruction_limit: LIMIT,
        ..VmConfig::default()
    })
    .unwrap();
    let callee = Plugin::new("callee", vm.load_image(Image::from_code(asm.assemble().unwrap())).unwrap());
    vm.export(&callee, "main").unwrap();

    // main: call main(SPINS) in the callee CALLS times, 4 CALLS + 3 instructions of its own
    let mut asm = Assembler::new();
    let again = asm.label();
    asm.mov64_imm(R6, CALLS);
    asm.bind(again);
    asm.mov64_imm(R1, SPINS).call(0).sub64_imm(R6, 1).jne_imm(R6, 0, again);
    asm.mov64_imm(R0, 0).exit();
    let mut image = Image::from_code(asm.assemble().unwrap());
    image.add_call(2, Import::name("main"));
    let mut caller = vm.load_image(image).unwrap();

    // the third call into the callee runs out of what the first two left
    let err = caller.call("main", &[]).unwrap_err();
    let VmError::Host(HostError::Plugin { error, .. }) = &err else {
        panic!("{err}")
    };
    assert!(matches!(**error, VmError::Exec(ExecError::InstructionLimit { .. })), "{err}");

    let main = caller.func("main").unwrap();
    let LimitedCall { result, instructions } = caller.call_func_with_limit(main, &[], 0);
    let total = (4 * CALLS + 3 + CALLS * (2 * SPINS + 2)) as u64;
    assert_eq!((result.unwrap(), instructions), (0, total));
    let LimitedCall { result, instructions } = caller.call_func_with_limit(main, &[], LIMIT);
    assert!(result.is_err());
    assert_eq!(instructions, LIMIT);
}

#[cfg(not(feature = "fuel"))]
#[test]
fn instruction_limit_needs_fuel() {
    use ebpf_asm::{Assembler, R0};
    use rvm::VmConfig;

    let config = VmConfig {
        instruction_limit: 1,
        ..VmConfig::default()
    };
    assert!(matches!(Vm::with_config(config), Err(VmError::FuelNotEnabled)));

    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 1).exit();
    let mut program = Vm::new().load_image(Image::from_code(asm.assemble().unwrap())).unwrap();
    let main = program.func("main").unwrap();
    let LimitedCall { result, instructions } = program.call_func_with_limit(main, &[], 1);
    assert!(matches!(result, Err(VmError::FuelNotEnabled)), "{result:?}");
    assert_eq!(instructions, 0);
    assert_eq!(program.call_func_with_limit(main, &[], 0).result.unwrap(), 1);
}

#[test]
fn plugin_exports_and_handles_follow_replace() {
    let vm = Vm::new();
    vm.register_extern("host_reenter", |x: u64| x);

    // B imports a_scale, so it links only after A exports it.
    assert!(matches!(
        vm.load_elf(&object("tests/plugin_b.o")).unwrap_err(),
        VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "a_scale"
    ));

    let a = Plugin::new("a", vm.load_elf(&object("tests/plugin_a_v1.o")).unwrap());
    vm.export(&a, "a_scale").unwrap();
    let b = Plugin::new("b", vm.load_elf(&object("tests/plugin_b.o")).unwrap());
    let scale_fn = a.func("a_scale").unwrap();
    let raw_func = a.lock().unwrap().func("a_scale").unwrap();
    assert_eq!((b.call("b_run", &[5]).unwrap(), scale_fn.call(&[5]).unwrap()), (11, 10));

    // Replacing A's code is picked up by B and `PluginFunc`, while the old `Func` handle fails as foreign.
    a.replace(vm.load_elf(&object("tests/plugin_a_v2.o")).unwrap()).unwrap();
    assert_eq!((b.call("b_run", &[5]).unwrap(), scale_fn.call(&[5]).unwrap()), (16, 15));
    assert!(matches!(a.lock().unwrap().call_func(raw_func, &[5]), Err(VmError::ForeignFunc)));

    // A program without the function fails the handle, which recovers once a later program defines it again.
    a.replace(vm.load_elf(&object("tests/maps.o")).unwrap()).unwrap();
    assert!(matches!(
        scale_fn.call(&[5]).unwrap_err(),
        VmError::FunctionNotFound { plugin: Some(p), func } if p == "a" && func == "a_scale"
    ));
    a.replace(vm.load_elf(&object("tests/plugin_a_v1.o")).unwrap()).unwrap();
    assert_eq!(scale_fn.call(&[5]).unwrap(), 10);
}

#[test]
fn reentrant_call_and_replace_fail_instead_of_deadlocking() {
    let vm = Vm::new();
    let a = Plugin::new("a", vm.load_elf(&object("tests/plugin_a_v1.o")).unwrap());
    vm.export(&a, "a_scale").unwrap();

    // host_reenter calls back into b, and tries to replace it, while b is running. It holds b weakly: a strong handle
    // inside the Vm's own helper table would never be freed.
    let is_busy = |e: Option<&VmError>| matches!(e, Some(VmError::PluginBusy(n)) if n == "b");
    let b_slot: Arc<OnceLock<WeakPlugin>> = Arc::default();
    let spare: Arc<Mutex<Option<Program>>> = Arc::default();
    let busy = Arc::new(Mutex::new((false, false)));
    let (slot, next, seen) = (b_slot.clone(), spare.clone(), busy.clone());
    vm.register_extern("host_reenter", move |x: u64| {
        let b = slot.get().unwrap().upgrade().unwrap();
        let call = b.call("b_run", &[x]);
        let replace = b.replace(next.lock().unwrap().take().unwrap());
        *seen.lock().unwrap() = (is_busy(call.as_ref().err()), is_busy(replace.as_ref().err()));
        call
    });
    let b = Plugin::new("b", vm.load_elf(&object("tests/plugin_b.o")).unwrap());
    b_slot.set(b.downgrade()).unwrap();
    *spare.lock().unwrap() = Some(vm.load_elf(&object("tests/plugin_b.o")).unwrap());

    // the host function returns the nested call's error, which fails the outer call
    let err = b.call("b_reenter", &[5]).unwrap_err();
    let VmError::Host(HostError::Failed(inner)) = &err else {
        panic!("{err}")
    };
    assert!(is_busy(inner.downcast_ref()), "{err}");
    assert_eq!(*busy.lock().unwrap(), (true, true));
    assert_eq!(b.call("b_run", &[5]).unwrap(), 11);
}

#[test]
fn shared_map_is_one_instance_across_plugins() {
    let vm = Vm::new();
    let x = Plugin::new("x", vm.load_elf(&object("tests/shared_counter.o")).unwrap());
    let y = Plugin::new("y", vm.load_elf(&object("tests/shared_counter.o")).unwrap());
    assert_eq!((x.call("bump", &[]).unwrap(), y.call("bump", &[]).unwrap()), (1, 1)); // private

    // SAFETY: the plugins run on this thread only.
    unsafe { vm.share_map("hits", ValueSpacing::CacheLine) };
    let x = Plugin::new("x", vm.load_elf(&object("tests/shared_counter.o")).unwrap());
    let y = Plugin::new("y", vm.load_elf(&object("tests/shared_counter.o")).unwrap());
    assert_eq!(x.call("bump", &[]).unwrap(), 1);
    assert_eq!(y.call("bump", &[]).unwrap(), 2);
    let mut x = x.lock().unwrap();
    let mut hits = x.map("hits").unwrap();
    assert_eq!(hits.get_as::<u32, u64>(0), Ok(Some(2)));
    // other programs may write a shared value while the host holds a reference to it
    assert_eq!(hits.get(&0u32.to_le_bytes()), Err(rvm::MapError::Shared));
    hits.update_as(0u32, 9u64, rvm::BPF_ANY).unwrap();
    drop(x);
    assert_eq!(y.call("bump", &[]).unwrap(), 10);

    assert!(matches!(
        vm.load_elf(&object("tests/shared_counter_u32.o")).unwrap_err(),
        VmError::Link(LinkError::MapMismatch(name)) if name == "hits"
    ));
}

/// Two plugins on two threads bump one shared counter with guest atomics.
#[test]
fn shared_map_atomics_across_threads() {
    const N: u64 = if cfg!(miri) { 100 } else { 10_000 };
    let vm = Vm::new();
    // SAFETY: `bump` only touches the value with an atomic add.
    unsafe { vm.share_map("hits", ValueSpacing::CacheLine) };
    let plugins = ["x", "y"].map(|name| Plugin::new(name, vm.load_elf(&object("tests/shared_counter.o")).unwrap()));

    std::thread::scope(|s| {
        for plugin in &plugins {
            s.spawn(|| (0..N).for_each(|_| _ = plugin.call("bump", &[]).unwrap()));
        }
    });
    assert_eq!(plugins[0].call("bump", &[]).unwrap(), 2 * N + 1);
}

/// Two plugins on two threads pass messages through a shared region (bpf/tests/acq_rel.c): the producer writes a
/// payload and publishes it with store-release, the consumer reads it after a load-acquire and acknowledges it the same
/// way. Acquire and release accesses that aren't aligned fault.
#[test]
fn shared_region_acquire_release() {
    const N: u64 = if cfg!(miri) { 50 } else { 2_000 };
    const WORDS: u64 = 6;
    let vm = Vm::new();
    // SAFETY: each plugin touches the payload only after a load-acquire shows the other one is done with it.
    let region = unsafe { vm.share_region(128, rvm::Perms::RW) }.unwrap();
    let [producer, consumer] =
        ["x", "y"].map(|name| Plugin::new(name, vm.load_elf(&object("tests/acq_rel.o")).unwrap()));
    let mailbox = region.base();

    std::thread::scope(|s| {
        s.spawn(|| {
            for n in 1..=N {
                while producer.call("publish", &[mailbox, n]).unwrap() == 0 {
                    std::hint::spin_loop();
                }
            }
        });
        for n in 1..=N {
            let sum = loop {
                match consumer.call("consume", &[mailbox, n]).unwrap() {
                    0 => std::hint::spin_loop(),
                    sum => break sum,
                }
            };
            assert_eq!(sum, n * WORDS * WORDS + WORDS * (WORDS - 1) / 2, "message {n}");
        }
    });

    let scratch = mailbox + 64;
    let misaligned: [(&str, &[u64]); 2] = [("load_u64", &[scratch + 4]), ("store_u16", &[scratch + 1, 7])];
    for (func, args) in misaligned {
        let err = consumer.call(func, args).unwrap_err();
        assert!(matches!(err, VmError::Exec(rvm::ExecError::MemoryFault { .. })), "{func}: {err}");
    }
}

/// Buffers tagged `borrow`/`borrow_ro` cross plugins for the duration of a call.
#[test]
fn borrowed_buffers() {
    let vm = Vm::new();
    let callee = Plugin::new("callee", vm.load_elf(&object("tests/borrow_callee.o")).unwrap());
    for func in ["sum", "fill", "poke", "sum_keyed"] {
        vm.export(&callee, func).unwrap();
    }
    let caller = Plugin::new("caller", vm.load_elf(&object("tests/borrow_caller.o")).unwrap());

    // sum reads the caller's array, fill writes it back: 10 * 1000 + 7 + 7
    assert_eq!(caller.call("run", &[]).unwrap(), 10_014);
    // a 16-byte struct ahead of the buffer moves it and its length up one register
    assert_eq!(caller.call("run_keyed", &[]).unwrap(), 10 + 20 + 10);

    // a length past the caller's memory fails before the callee runs
    let err = caller.call("overrun", &[]).unwrap_err().to_string();
    assert!(err.contains("callee::sum") && err.contains("no access"), "{err}");

    // a read-only borrow faults on write, and the slot is unmapped afterwards
    let err = caller.call("write_ro", &[]).unwrap_err().to_string();
    assert!(err.contains("callee::poke") && err.contains("memory fault"), "{err}");
    assert_eq!(callee.lock().unwrap().memory().region_len(rvm::BORROW_FIRST_REGION), 0);

    // an empty buffer may be null, as C passes it: sum(NULL, 0)
    #[rustfmt::skip]
    let code = [
        0xb7, 0x01, 0, 0, 0, 0, 0, 0, // r1 = 0
        0xb7, 0x02, 0, 0, 0, 0, 0, 0, // r2 = 0
        0x85, 0x00, 0, 0, 0, 0, 0, 0, // call sum
        0x95, 0x00, 0, 0, 0, 0, 0, 0, // exit
    ];
    let mut image = Image::from_code(code.to_vec());
    image.add_call(2, Import::name("sum"));
    assert_eq!(vm.load_image(image).unwrap().call("main", &[]).unwrap(), 0);
}

/// Plugins of different passthrough modes in one VM: each reaches a shared region at its own address and faults on
/// the other's, and a borrowed buffer arrives at an address of the callee's mode.
#[test]
fn plugins_of_different_modes() {
    // SAFETY: the untagged plugins read and write only the shared region, their own memory and the borrowed buffers
    let untagged = unsafe { Passthrough::untagged() };

    let vm = Vm::new();
    // SAFETY: one thread
    let shared = unsafe { vm.share_region(64, rvm::Perms::RW) }.unwrap();
    let ro = unsafe { vm.share_region(64, rvm::Perms::R) }.unwrap();
    let elf = object("tests/shared_region.o");
    let mut checked = vm.load_elf(&elf).unwrap();
    let mut raw = vm.loader().passthrough(untagged).load_elf(&elf).unwrap();
    let (checked_addr, raw_addr) = (shared.base(), shared.base_for(untagged));

    checked.call("put", &[checked_addr, 5]).unwrap();
    assert_eq!(raw.call("get", &[raw_addr]).unwrap(), 5);
    assert_eq!(shared.read::<u64>(0).unwrap(), 5);
    assert!(matches!(
        checked.call("put", &[ro.base(), 1]),
        Err(VmError::Exec(rvm::ExecError::MemoryFault { .. }))
    ));
    for (program, addr) in [(&mut checked, raw_addr), (&mut raw, checked_addr)] {
        let err = program.call("get", &[addr]).unwrap_err();
        assert!(matches!(err, VmError::Exec(rvm::ExecError::MemoryFault { .. })), "{err}");
    }

    for (callee_mode, caller_mode) in [(untagged, Passthrough::OFF), (Passthrough::OFF, untagged)] {
        let vm = Vm::new();
        let callee = vm.loader().passthrough(callee_mode);
        let callee = Plugin::new("callee", callee.load_elf(&object("tests/borrow_callee.o")).unwrap());
        for func in ["sum", "fill", "poke", "sum_keyed"] {
            vm.export(&callee, func).unwrap();
        }
        let caller = vm.loader().passthrough(caller_mode);
        let mut caller = caller.load_elf(&object("tests/borrow_caller.o")).unwrap();
        assert_eq!(caller.call("run", &[]).unwrap(), 10_014);
    }
}

/// A host function that panics during a call with a borrowed buffer leaves the buffer unmapped and both plugins
/// unlocked.
#[test]
fn panic_during_borrowed_call() {
    let vm = Vm::new();
    let fail = Arc::new(AtomicBool::new(true));
    let failing = fail.clone();
    vm.register_extern("host_peek", move |first: u64| {
        assert!(!failing.load(Ordering::Relaxed), "host_peek failed");
        first
    });
    let callee = Plugin::new("callee", vm.load_elf(&object("tests/borrow_host.o")).unwrap());
    vm.export(&callee, "peek").unwrap();
    let caller = Plugin::new("caller", vm.load_elf(&object("tests/borrow_host_caller.o")).unwrap());

    assert!(catch_unwind(AssertUnwindSafe(|| caller.call("run", &[]))).is_err());
    assert_eq!(callee.lock().unwrap().memory().region_len(rvm::BORROW_FIRST_REGION), 0);

    fail.store(false, Ordering::Relaxed);
    assert_eq!(caller.call("run", &[]).unwrap(), 42);
}

/// Borrowing a buffer larger than `MAX_REGION_LEN` from a passthrough caller returns a `MemoryError` instead of
/// aborting inside `map_host_any`.
#[test]
fn borrow_over_max_region_len_under_passthrough_returns_error() {
    use ebpf_asm::{Assembler, R1, R2};

    let vm = Vm::new();
    let callee = Plugin::new("callee", vm.load_elf(&object("tests/borrow_callee.o")).unwrap());
    vm.export(&callee, "sum").unwrap();

    let mut asm = Assembler::new();
    asm.lddw(R1, rvm::RAW_START as i64)
        .lddw(R2, (rvm::MAX_REGION_LEN + 1) as i64)
        .call(0)
        .exit();
    let mut image = Image::from_code(asm.assemble().unwrap());
    image.add_call(4, Import::name("sum"));
    // SAFETY: the guest never dereferences the raw address; the borrow check rejects the oversize length before mapping
    let passthrough = unsafe { Passthrough::on() };
    let mut caller = vm.loader().passthrough(passthrough).load_image(image).unwrap();
    let err = caller.call("main", &[]).unwrap_err();
    let VmError::Host(HostError::Plugin { error, .. }) = &err else {
        panic!("expected plugin error, got {err:?}");
    };
    assert!(
        matches!(
            **error,
            VmError::Memory(rvm::MemoryError {
                addr,
                size,
            }) if addr == rvm::RAW_START && size == rvm::MAX_REGION_LEN + 1
        ),
        "{err:?}"
    );
}

/// A failed image load must not commit newly created shared maps or poison their names for later loads.
#[test]
fn failed_load_does_not_poison_shared_map() {
    use ebpf_asm::{Assembler, R0};

    let vm = Vm::new();
    // SAFETY: single-threaded test
    unsafe { vm.share_map("hits", ValueSpacing::CacheLine) };

    // Build an image that declares "hits" with a wrong value_size (4 instead of 8) AND imports a missing extern.
    let mut asm = Assembler::new();
    asm.call(0).mov64_imm(R0, 0).exit();
    let mut bad_extern = Image::from_code(asm.assemble().unwrap());
    bad_extern.maps.push(rvm::MapDef {
        name: "hits".into(),
        kind: rvm::MapKind::Array,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    });
    bad_extern.add_call(0, Import::name("does_not_exist"));
    assert!(vm.load_image(bad_extern).is_err());

    // Also fail inside `Maps::new` on a second map (duplicate / invalid def) after the shared map entry.
    let mut asm = Assembler::new();
    asm.mov64_imm(R0, 0).exit();
    let mut bad_second_map = Image::from_code(asm.assemble().unwrap());
    bad_second_map.maps.push(rvm::MapDef {
        name: "hits".into(),
        kind: rvm::MapKind::Array,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    });
    bad_second_map.maps.push(rvm::MapDef {
        name: "broken".into(),
        kind: rvm::MapKind::Array,
        key_size: 8, // invalid: array maps require 4-byte keys
        value_size: 8,
        max_entries: 1,
    });
    assert!(vm.load_image(bad_second_map).is_err());

    // Loading the real `shared_counter.o` (which declares "hits" with value_size 8) must still succeed.
    let mut prog = vm.load_elf(&object("tests/shared_counter.o")).unwrap();
    assert_eq!(prog.call("bump", &[]).unwrap(), 1);
}

/// A caught panic inside a metered plugin export must restore the caller's fuel state so subsequent calls still meter.
#[cfg(feature = "fuel")]
#[test]
fn panic_in_metered_export_restores_caller_fuel() {
    use ebpf_asm::{Assembler, R0, R1};
    use rvm::{ExecError, VmConfig};

    let vm = Vm::with_config(VmConfig {
        instruction_limit: 50,
        ..VmConfig::default()
    })
    .unwrap();
    let should_panic = Arc::new(AtomicBool::new(true));
    let flag = should_panic.clone();
    vm.register_extern("maybe_panic", move |_: ()| {
        assert!(!flag.load(Ordering::Relaxed), "boom");
        0u64
    });

    // Callee: calls `maybe_panic`, then loops `r1` times.
    let mut asm = Assembler::new();
    let spin = asm.label();
    asm.call(0);
    asm.bind(spin);
    asm.sub64_imm(R1, 1).jne_imm(R1, 0, spin);
    asm.mov64_imm(R0, 7).exit();
    let mut callee_img = Image::from_code(asm.assemble().unwrap());
    callee_img.add_call(0, Import::name("maybe_panic"));
    let callee = Plugin::new("callee", vm.load_image(callee_img).unwrap());
    vm.export(&callee, "main").unwrap();

    // Caller: calls callee::main(r1).
    let mut asm = Assembler::new();
    asm.call(0).exit();
    let mut caller_img = Image::from_code(asm.assemble().unwrap());
    caller_img.add_call(0, Import::name("main"));
    let mut caller = vm.load_image(caller_img).unwrap();

    // First call unwinds while `call_with_fuel` is active.
    assert!(catch_unwind(AssertUnwindSafe(|| caller.call("main", &[1]))).is_err());

    // Subsequent call with a tight limit must still run out of fuel (not reuse stale `CallerFuel::Left`).
    should_panic.store(false, Ordering::Relaxed);
    let err = caller.call("main", &[100]).unwrap_err();
    let VmError::Host(HostError::Plugin { error, .. }) = &err else {
        panic!("expected plugin limit error, got {err:?}");
    };
    assert!(matches!(**error, VmError::Exec(ExecError::InstructionLimit { .. })), "{err:?}");
    assert_eq!(caller.call("main", &[2]).unwrap(), 7);
}
