//! Plugins: exports, reloads, re-entrancy, and sharing maps/regions/borrows.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rvm::{HelperError, Image, Import, LinkError, Program, Vm, VmError, WeakPlugin};

use crate::common::object;

/// The instruction limit covers a whole call tree: what an export runs counts against the program that called it.
#[cfg(feature = "fuel")]
#[test]
fn instruction_limit_covers_plugin_calls() {
    use ebpf_asm::{Assembler, R0, R1, R6};
    use rvm::{ExecError, Plugin, VmConfig, DEFAULT_INSTRUCTION_LIMIT};

    const SPINS: i32 = 200_000;
    const CALLS: i32 = 50;

    // spin(n): count n down to 0, 2 n + 2 instructions
    let mut asm = Assembler::new();
    let spin = asm.create_label();
    asm.set_label(&spin).unwrap();
    asm.sub64_imm(R1, 1).jne_imm(R1, 0, &spin);
    asm.mov64_imm(R0, 1).exit();
    let vm = Vm::with_config(VmConfig {
        instruction_limit: DEFAULT_INSTRUCTION_LIMIT,
        ..VmConfig::default()
    })
    .unwrap();
    let callee = Plugin::new("callee", vm.load(Image::from_code(asm.assemble().unwrap())).unwrap());
    vm.export(&callee, "main").unwrap();

    // main: call main(SPINS) in the callee CALLS times, 4 CALLS + 3 instructions of its own
    let mut asm = Assembler::new();
    let again = asm.create_label();
    asm.mov64_imm(R6, CALLS);
    asm.set_label(&again).unwrap();
    asm.mov64_imm(R1, SPINS).call(0).sub64_imm(R6, 1).jne_imm(R6, 0, &again);
    asm.mov64_imm(R0, 0).exit();
    let mut image = Image::from_code(asm.assemble().unwrap());
    image.externs.push((2, Import::Name("main".into())));
    let mut caller = vm.load(image).unwrap();

    // the third call into the callee runs out of what the first two left
    let err = caller.call("main", &[]).unwrap_err();
    let VmError::Helper(HelperError::Plugin { error, .. }) = &err else {
        panic!("{err}")
    };
    assert!(matches!(**error, VmError::Exec(ExecError::InstructionLimit(_))), "{err}");

    let main = caller.func("main").unwrap();
    let (result, used) = caller.call_func_with_limit(main, &[], 0);
    let total = (4 * CALLS + 3 + CALLS * (2 * SPINS + 2)) as u64;
    assert_eq!((result.unwrap(), used), (0, total));
    let (result, used) = caller.call_func_with_limit(main, &[], DEFAULT_INSTRUCTION_LIMIT);
    assert!(result.is_err());
    assert_eq!(used, DEFAULT_INSTRUCTION_LIMIT);
}

#[test]
fn default_has_no_instruction_limit() {
    use ebpf_asm::{Assembler, R0, R1};

    // 2 n + 3 instructions for n = DEFAULT_INSTRUCTION_LIMIT
    let mut asm = Assembler::new();
    let spin = asm.create_label();
    asm.mov64_imm(R1, rvm::DEFAULT_INSTRUCTION_LIMIT as i32);
    asm.set_label(&spin).unwrap();
    asm.sub64_imm(R1, 1).jne_imm(R1, 0, &spin);
    asm.mov64_imm(R0, 1).exit();
    let mut program = Vm::new().load(Image::from_code(asm.assemble().unwrap())).unwrap();
    assert_eq!(program.call("main", &[]).unwrap(), 1);
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
    let mut program = Vm::new().load(Image::from_code(asm.assemble().unwrap())).unwrap();
    let main = program.func("main").unwrap();
    let (result, used) = program.call_func_with_limit(main, &[], 1);
    assert!(matches!(result, Err(VmError::FuelNotEnabled)), "{result:?}");
    assert_eq!(used, 0);
    assert_eq!(program.call_func_with_limit(main, &[], 0).0.unwrap(), 1);
}

#[test]
fn plugin_calls_export_and_survives_reload() {
    let vm = Vm::new();
    vm.register_fn("host_reenter", |x: u64| x);

    // B imports a_scale, so it links only after A exports it.
    assert!(matches!(
        vm.load_plugin("b", &object("tests/plugin_b.o")).unwrap_err(),
        VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "a_scale"
    ));

    let a = vm.load_plugin("a", &object("tests/plugin_a.o")).unwrap();
    vm.export(&a, "a_scale").unwrap();
    let b = vm.load_plugin("b", &object("tests/plugin_b.o")).unwrap();
    assert_eq!(b.call("b_run", &[5]).unwrap(), 11);
    let scale = a.lock().unwrap().func("a_scale").unwrap();
    let direct = a.lock().unwrap().call_func(scale, &[5]).unwrap();
    assert_eq!(direct, a.call("a_scale", &[5]).unwrap());

    // Replacing A's code is picked up by B's next call without relinking B.
    a.replace(vm.load_elf(&object("tests/plugin_a3.o")).unwrap()).unwrap();
    assert_eq!(b.call("b_run", &[5]).unwrap(), 16);
    // A handle into the replaced program fails instead of running the new one at its pc.
    assert!(matches!(a.lock().unwrap().call_func(scale, &[5]), Err(VmError::ForeignFunc)));
}

#[test]
fn plugin_func_follows_replace() {
    let vm = Vm::new();
    let a = vm.load_plugin("a", &object("tests/plugin_a.o")).unwrap();
    let scale = a.func("a_scale").unwrap();
    assert_eq!(scale.call(&[5]).unwrap(), 10);

    a.replace(vm.load_elf(&object("tests/plugin_a3.o")).unwrap()).unwrap();
    assert_eq!(scale.call(&[5]).unwrap(), 15);

    // A program without the function fails the call, and the handle recovers when a later program has it again.
    a.replace(vm.load_elf(&object("tests/maps.o")).unwrap()).unwrap();
    let err = scale.call(&[5]).unwrap_err();
    assert!(
        matches!(&err, VmError::FunctionNotFound { plugin: Some(p), func } if p == "a" && func == "a_scale"),
        "{err}"
    );
    a.replace(vm.load_elf(&object("tests/plugin_a.o")).unwrap()).unwrap();
    assert_eq!(scale.call(&[5]).unwrap(), 10);
}

#[test]
fn reentrant_call_and_replace_fail_instead_of_deadlocking() {
    let vm = Vm::new();
    let a = vm.load_plugin("a", &object("tests/plugin_a.o")).unwrap();
    vm.export(&a, "a_scale").unwrap();

    // host_reenter calls back into b, and tries to replace it, while b is running. It holds b weakly: a strong handle
    // inside the Vm's own helper table would never be freed.
    let is_busy = |e: Option<&VmError>| matches!(e, Some(VmError::PluginBusy(n)) if n == "b");
    let b_slot: Arc<OnceLock<WeakPlugin>> = Arc::default();
    let spare: Arc<Mutex<Option<Program>>> = Arc::default();
    let busy = Arc::new(Mutex::new((false, false)));
    let (slot, next, seen) = (b_slot.clone(), spare.clone(), busy.clone());
    vm.register_fn("host_reenter", move |x: u64| {
        let b = slot.get().unwrap().upgrade().unwrap();
        let call = b.call("b_run", &[x]);
        let replace = b.replace(next.lock().unwrap().take().unwrap());
        *seen.lock().unwrap() = (is_busy(call.as_ref().err()), is_busy(replace.as_ref().err()));
        call
    });
    let b = vm.load_plugin("b", &object("tests/plugin_b.o")).unwrap();
    b_slot.set(b.downgrade()).unwrap();
    *spare.lock().unwrap() = Some(vm.load_elf(&object("tests/plugin_b.o")).unwrap());

    // the host function returns the nested call's error, which fails the outer call
    let err = b.call("b_reenter", &[5]).unwrap_err();
    let VmError::Helper(HelperError::Host(inner)) = &err else {
        panic!("{err}")
    };
    assert!(is_busy(inner.downcast_ref()), "{err}");
    assert_eq!(*busy.lock().unwrap(), (true, true));
    assert_eq!(b.call("b_run", &[5]).unwrap(), 11);
}

#[test]
fn shared_map_is_one_instance_across_plugins() {
    let vm = Vm::new();
    let x = vm.load_plugin("x", &object("tests/shared_counter.o")).unwrap();
    let y = vm.load_plugin("y", &object("tests/shared_counter.o")).unwrap();
    assert_eq!((x.call("bump", &[]).unwrap(), y.call("bump", &[]).unwrap()), (1, 1)); // private

    // SAFETY: the plugins run on this thread only.
    unsafe { vm.share_map("hits", true) };
    let x = vm.load_plugin("x", &object("tests/shared_counter.o")).unwrap();
    let y = vm.load_plugin("y", &object("tests/shared_counter.o")).unwrap();
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
        vm.load_plugin("z", &object("tests/shared_counter_u32.o")).unwrap_err(),
        VmError::Link(LinkError::MapMismatch(name)) if name == "hits"
    ));
}

/// Two plugins on two threads bump one shared counter with guest atomics.
#[test]
fn shared_map_atomics_across_threads() {
    const N: u64 = 10_000;
    let vm = Vm::new();
    // SAFETY: `bump` only touches the value with an atomic add.
    unsafe { vm.share_map("hits", true) };
    let plugins = ["x", "y"].map(|name| vm.load_plugin(name, &object("tests/shared_counter.o")).unwrap());

    std::thread::scope(|s| {
        for plugin in &plugins {
            s.spawn(|| (0..N).for_each(|_| _ = plugin.call("bump", &[]).unwrap()));
        }
    });
    assert_eq!(plugins[0].call("bump", &[]).unwrap(), 2 * N + 1);
}

/// One plugin writes through a pointer into a shared region, another reads it.
#[test]
fn shared_region_is_visible_to_every_plugin() {
    let vm = Vm::new();
    // SAFETY: the plugins run on this thread only.
    let rw = unsafe { vm.share_region(rvm::FIRST_FREE_REGION, 64, rvm::Perms::RW) }.unwrap();
    let ro = unsafe { vm.share_region(rvm::FIRST_FREE_REGION + 1, 64, rvm::Perms::R) }.unwrap();
    assert!(unsafe { vm.share_region(rvm::FIRST_FREE_REGION, 64, rvm::Perms::RW) }.is_err());

    let x = vm.load_plugin("x", &object("tests/shared_region.o")).unwrap();
    let y = vm.load_plugin("y", &object("tests/shared_region.o")).unwrap();
    let slot = rw.base() + 8;
    x.call("put", &[slot, 42]).unwrap();
    assert_eq!(y.call("get", &[slot]).unwrap(), 42);
    assert_eq!(rw.read::<u64>(8).unwrap(), 42);

    let err = x.call("put", &[ro.base(), 1]).unwrap_err();
    assert!(matches!(err, VmError::Exec(rvm::ExecError::MemoryFault { .. })), "{err}");
}

/// Two plugins on two threads pass messages through a shared region (bpf/tests/acq_rel.c): the producer writes a
/// payload and publishes it with store-release, the consumer reads it after a load-acquire and acknowledges it the same
/// way. Acquire and release accesses that aren't aligned fault.
#[test]
fn shared_region_acquire_release() {
    const N: u64 = 2_000;
    const WORDS: u64 = 6;
    let vm = Vm::new();
    // SAFETY: each plugin touches the payload only after a load-acquire shows the other one is done with it.
    let region = unsafe { vm.share_region(rvm::FIRST_FREE_REGION, 128, rvm::Perms::RW) }.unwrap();
    let [producer, consumer] = ["x", "y"].map(|name| vm.load_plugin(name, &object("tests/acq_rel.o")).unwrap());
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
    let callee = vm.load_plugin("callee", &object("tests/borrow_callee.o")).unwrap();
    for func in ["sum", "fill", "poke"] {
        vm.export(&callee, func).unwrap();
    }
    let caller = vm.load_plugin("caller", &object("tests/borrow_caller.o")).unwrap();

    // sum reads the caller's array, fill writes it back: 10 * 1000 + 7 + 7
    assert_eq!(caller.call("run", &[]).unwrap(), 10_014);

    // a length past the caller's memory fails before the callee runs
    let err = caller.call("overrun", &[]).unwrap_err().to_string();
    assert!(err.contains("callee::sum") && err.contains("no access"), "{err}");

    // a read-only borrow faults on write, and the slot is unmapped afterwards
    let err = caller.call("write_ro", &[]).unwrap_err().to_string();
    assert!(err.contains("callee::poke") && err.contains("memory fault"), "{err}");
    let slot = rvm::region_base(rvm::BORROW_FIRST_REGION);
    assert!(callee.lock().unwrap().memory().bytes(slot, 1).is_err());

    // an empty buffer may be null, as C passes it: sum(NULL, 0)
    #[rustfmt::skip]
    let code = [
        0xb7, 0x01, 0, 0, 0, 0, 0, 0, // r1 = 0
        0xb7, 0x02, 0, 0, 0, 0, 0, 0, // r2 = 0
        0x85, 0x00, 0, 0, 0, 0, 0, 0, // call sum
        0x95, 0x00, 0, 0, 0, 0, 0, 0, // exit
    ];
    let mut image = Image::from_code(code.to_vec());
    image.externs.push((2, Import::Name("sum".into())));
    assert_eq!(vm.load(image).unwrap().call("main", &[]).unwrap(), 0);
}

/// A host function that panics during a call with a borrowed buffer leaves the buffer unmapped and both plugins
/// unlocked.
#[test]
fn panic_during_borrowed_call() {
    let vm = Vm::new();
    let fail = Arc::new(AtomicBool::new(true));
    let failing = fail.clone();
    vm.register_fn("host_peek", move |first: u64| {
        assert!(!failing.load(Ordering::Relaxed), "host_peek failed");
        first
    });
    let callee = vm.load_plugin("callee", &object("tests/borrow_host.o")).unwrap();
    vm.export(&callee, "peek").unwrap();
    let caller = vm.load_plugin("caller", &object("tests/borrow_host_caller.o")).unwrap();

    assert!(catch_unwind(AssertUnwindSafe(|| caller.call("run", &[]))).is_err());
    let slot = rvm::region_base(rvm::BORROW_FIRST_REGION);
    assert!(callee.lock().unwrap().memory().bytes(slot, 1).is_err());

    fail.store(false, Ordering::Relaxed);
    assert_eq!(caller.call("run", &[]).unwrap(), 42);
}
