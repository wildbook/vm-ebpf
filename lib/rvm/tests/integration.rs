//! Integration tests for rvm with real eBPF ELF files.
//!
//! These tests load the compiled `bpf/example.o` and verify
//! that functions execute correctly.

use rvm::Vm;

/// Load the example ELF file.
fn load_example_elf() -> Vec<u8> {
    // The path is relative to the workspace root
    let paths = ["bpf/example.o", "../../../bpf/example.o", "../../bpf/example.o"];

    for path in paths {
        if let Ok(bytes) = std::fs::read(path) {
            return bytes;
        }
    }

    panic!(
        "Could not find bpf/example.o. Compile it with:\n\
         clang -target bpf -O2 -c bpf/example.c -o bpf/example.o"
    );
}

#[test]
fn test_simple_add() {
    let elf_bytes = load_example_elf();
    let vm = Vm::new();
    let mut program = vm.load_elf(&elf_bytes).expect("Failed to load ELF");

    // Test basic addition
    assert_eq!(program.call("simple_add", &[10, 20]).unwrap(), 30);
    assert_eq!(program.call("simple_add", &[100, 200]).unwrap(), 300);
    assert_eq!(program.call("simple_add", &[0, 0]).unwrap(), 0);

    // Test with large numbers
    assert_eq!(program.call("simple_add", &[1, u64::MAX - 1]).unwrap(), u64::MAX);
}

#[test]
fn test_return_magic() {
    let elf_bytes = load_example_elf();
    let vm = Vm::new();
    let mut program = vm.load_elf(&elf_bytes).expect("Failed to load ELF");

    const MAGIC: u64 = 0xDEADBEEFCAFEBABE;
    assert_eq!(program.call("return_magic", &[]).unwrap(), MAGIC);
}

#[test]
fn test_function_discovery() {
    let elf_bytes = load_example_elf();
    let vm = Vm::new();
    let program = vm.load_elf(&elf_bytes).expect("Failed to load ELF");

    // Check that expected functions exist
    assert!(program.has_function("simple_add"));
    assert!(program.has_function("return_magic"));
    assert!(program.has_function("bpf_main"));

    // Check that non-existent functions don't exist
    assert!(!program.has_function("nonexistent"));
}

#[test]
fn test_function_not_found() {
    let elf_bytes = load_example_elf();
    let vm = Vm::new();
    let mut program = vm.load_elf(&elf_bytes).expect("Failed to load ELF");

    let result = program.call("nonexistent", &[]);
    assert!(result.is_err());
}

#[test]
fn test_multiple_calls() {
    let elf_bytes = load_example_elf();
    let vm = Vm::new();
    let mut program = vm.load_elf(&elf_bytes).expect("Failed to load ELF");

    // Make multiple calls to verify state is handled correctly
    for i in 0..10 {
        let a = i * 10;
        let b = i * 5;
        let expected = a + b;
        assert_eq!(
            program.call("simple_add", &[a, b]).unwrap(),
            expected,
            "Failed on iteration {}: {} + {} != {}",
            i,
            a,
            b,
            expected
        );
    }
}

#[test]
fn test_module_parsing() {
    let elf_bytes = load_example_elf();
    let vm = Vm::new();

    // Test that we can parse the module without linking
    let module = vm.parse_module("test", &elf_bytes).expect("Failed to parse module");

    // Check that sections were parsed
    assert!(!module.sections.is_empty());

    // Check that symbols were parsed
    assert!(!module.symbols.is_empty());

    // Check that exports include our functions
    assert!(module.exports.contains_key("simple_add"));
    assert!(module.exports.contains_key("return_magic"));
    assert!(module.exports.contains_key("bpf_main"));
}

#[test]
fn test_symbol_lookup_matches_name() {
    let module = Vm::new().parse_module("test", &load_example_elf()).unwrap();
    for name in ["call_count", "last_result", "simple_add", "MAGIC_VALUE"] {
        assert_eq!(module.symbol(name).map(|s| s.name.as_str()), Some(name));
    }
}

/// `bpf_main` writes globals through relocations; they must not land on other code.
#[test]
fn test_bpf_main_globals_do_not_clobber_code() {
    let mut program = Vm::new().load_elf(&load_example_elf()).unwrap();
    let scratch = program.memory_mut().map(rvm::FIRST_FREE_REGION, 4096, rvm::Perms::RW);
    let ctx = scratch;
    let out = ctx + 64;
    let mem = program.memory_mut();
    mem.write(ctx, 5u64).unwrap(); // value_a
    mem.write(ctx + 8, 7u64).unwrap(); // value_b
    mem.write(ctx + 16, 2u32).unwrap(); // operation = mul

    assert_eq!(program.call("bpf_main", &[ctx, out]).unwrap(), 0);
    assert_eq!(program.memory().read::<u64>(out).unwrap(), 35);
    assert_eq!(program.call("simple_add", &[2, 3]).unwrap(), 5);
}

#[test]
fn test_memory_survives_fault() {
    let mut program = Vm::new().load_elf(&load_example_elf()).unwrap();
    assert!(program.call("bpf_main", &[0xFFFF_FFFF_0000, 0xFFFF_FFFF_0000]).is_err());
    assert_eq!(program.call("simple_add", &[2, 3]).unwrap(), 5);
}

// ==================== Linking & Externs ====================

mod linking {
    use rvm::{LinkError, Vm, VmError};

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../bpf/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    /// Vm with everything link_main.o imports: helper 100 and `host_add`.
    fn full_vm() -> Vm {
        let vm = Vm::new();
        vm.register_helper(100, |x: u64| x * 2);
        vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);
        vm
    }

    fn link(vm: &Vm) -> rvm::Result<rvm::Program> {
        let main = vm.parse_module("main", &read("link_main.o"))?;
        let lib = vm.parse_module("lib", &read("link_lib.o"))?;
        vm.link(&[&main, &lib])
    }

    #[test]
    fn cross_module_call_helper_and_extern() {
        let mut program = link(&full_vm()).unwrap();
        // host_add(lib_scale(7), helper_double(7)) = 21 + 14
        assert_eq!(program.call("run", &[7]).unwrap(), 35);
        assert_eq!(program.call("lib_scale", &[5]).unwrap(), 15);
    }

    #[test]
    fn missing_extern_fails_link() {
        let vm = Vm::new();
        vm.register_helper(100, |x: u64| x * 2);
        assert!(matches!(
            link(&vm).unwrap_err(),
            VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "host_add"
        ));
    }

    #[test]
    fn missing_helper_fails_link() {
        let vm = Vm::new();
        vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);
        assert!(matches!(link(&vm).unwrap_err(), VmError::Link(LinkError::UnknownHelper(100))));
    }

    #[test]
    fn extern_arity_mismatch_fails_link() {
        let vm = Vm::new();
        vm.register_helper(100, |x: u64| x * 2);
        vm.register_fn("host_add", |x: u64| x);
        assert!(matches!(
            link(&vm).unwrap_err(),
            VmError::Link(LinkError::SignatureMismatch {
                declared: 2,
                host: 1,
                ..
            })
        ));
    }

    /// Re-registering a function reaches already linked programs at their next call.
    #[test]
    fn replacing_extern_rebinds_linked_calls() {
        let vm = full_vm();
        let mut program = link(&vm).unwrap();
        assert_eq!(program.call("run", &[7]).unwrap(), 21 + 14);
        vm.register_fn("host_add", |(a, b): (u64, u64)| a * b);
        assert_eq!(program.call("run", &[7]).unwrap(), 21 * 14);
    }
}

mod plugins {
    use std::sync::{Arc, Mutex, OnceLock};

    use rvm::{LinkError, Plugin, Vm, VmError};

    fn read(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../bpf/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn plugin_calls_export_and_survives_reload() {
        let vm = Vm::new();
        vm.register_fn("host_reenter", |x: u64| x);

        // B imports a_scale, so it links only after A exports it.
        assert!(matches!(
            vm.load_plugin("b", &read("plugin_b.o")).unwrap_err(),
            VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "a_scale"
        ));

        let a = vm.load_plugin("a", &read("plugin_a.o")).unwrap();
        vm.export(&a, "a_scale").unwrap();
        let b = vm.load_plugin("b", &read("plugin_b.o")).unwrap();
        assert_eq!(b.call("b_run", &[5]).unwrap(), 11);

        // Replacing A's code is picked up by B's next call without relinking B.
        a.replace(vm.load_elf(&read("plugin_a3.o")).unwrap());
        assert_eq!(b.call("b_run", &[5]).unwrap(), 16);
    }

    #[test]
    fn reentrant_call_fails_instead_of_deadlocking() {
        let vm = Vm::new();
        let a = vm.load_plugin("a", &read("plugin_a.o")).unwrap();
        vm.export(&a, "a_scale").unwrap();

        // host_reenter calls back into b while b is running.
        let b_slot: Arc<OnceLock<Plugin>> = Arc::default();
        let error = Arc::new(Mutex::new(None));
        let (slot, err) = (b_slot.clone(), error.clone());
        vm.register_fn("host_reenter", move |x: u64| {
            let result = slot.get().unwrap().call("b_run", &[x]);
            *err.lock().unwrap() = result.as_ref().err().map(ToString::to_string);
            result
        });
        let b = b_slot.get_or_init(|| vm.load_plugin("b", &read("plugin_b.o")).unwrap());

        assert_eq!(b.call("b_reenter", &[5]).unwrap(), u64::MAX);
        assert_eq!(error.lock().unwrap().as_deref(), Some("plugin b is already running a call"));
        assert_eq!(b.call("b_run", &[5]).unwrap(), 11);
    }
}

/// Every atomic form clang emits (bpf/atomics.c), with the expected values worked
/// out by hand from the RFC 9669 semantics.
#[test]
fn test_clang_atomics() {
    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/atomics.o")).unwrap();
    let mut program = Vm::new().load_elf(&elf).unwrap();

    assert_eq!(program.call("run", &[5]).unwrap(), 1058);

    let bss = rvm::region_base(rvm::DATA_REGION);
    assert_eq!(program.memory().read::<u64>(bss).unwrap(), 9);
    assert_eq!(program.memory().read::<u32>(bss + 8).unwrap(), 0xFFFF_FFFF);
}

/// Array and hash maps from bpf/maps.c, used from the guest and the host.
#[test]
fn test_maps() {
    const EEXIST: u64 = (-17i64) as u64;
    const E2BIG: u64 = (-7i64) as u64;
    const ENOENT: u64 = (-2i64) as u64;

    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/maps.o")).unwrap();
    let mut program = Vm::new().load_elf(&elf).unwrap();

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

    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/std_helpers.o")).unwrap();

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

// ==================== Memory Safety Tests ====================

mod memory_safety {
    use ebpf_asm::{Assembler, R0, R1, R10, R2, R6};
    use rvm::{ExecError, Executor, HelperRegistry, Instruction, Perms, VmError, VmMemory};

    /// Assemble `asm` into an instruction slice the executor can run directly.
    fn assemble(asm: &mut Assembler) -> Vec<Instruction> {
        asm.assemble_to_u64().unwrap().into_iter().map(Instruction).collect()
    }

    #[test]
    fn test_memory_out_of_bounds_read() {
        // Test that reading beyond memory bounds returns an error.
        // 0x7FFFFFFF falls in region 0, which is never mapped.
        let mut memory = VmMemory::new();

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 0x7FFFFFFF); // Large address, unmapped region 0
        asm.ldxdw(R0, R1, 0); // Try to load from that address
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for OOB read, got {:?}", result);

        match result {
            Err(VmError::Exec(ExecError::MemoryFault(_))) => {
                // Expected
            }
            Err(e) => panic!("Expected MemoryFault, got {:?}", e),
            Ok(_) => panic!("Expected error for OOB read"),
        }
    }

    #[test]
    fn test_memory_out_of_bounds_write() {
        // Test that writing beyond memory bounds returns an error.
        let mut memory = VmMemory::new();

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 0x7FFFFFFF); // Large address, unmapped region 0
        asm.mov64_imm(R2, 42);
        asm.stxdw(R1, 0, R2); // Try to store to that address
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for OOB write, got {:?}", result);

        match result {
            Err(VmError::Exec(ExecError::MemoryFault(_))) => {
                // Expected
            }
            Err(e) => panic!("Expected MemoryFault, got {:?}", e),
            Ok(_) => panic!("Expected error for OOB write"),
        }
    }

    #[test]
    fn test_memory_boundary_read() {
        // Test reading at the exact boundary of a mapped region.
        let mut memory = VmMemory::new();
        let base = memory.map(1, 256, Perms::RW);

        let mut asm = Assembler::new();
        // Region is 256 bytes, trying to read 8 bytes at offset 250 should fail
        // (250 + 8 = 258 > 256)
        asm.lddw(R1, (base + 250) as i64);
        asm.ldxdw(R0, R1, 0);
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, base + 256);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for boundary read, got {:?}", result);
    }

    #[test]
    fn test_stack_overflow_deep_recursion() {
        // Test that deep BPF-to-BPF recursion triggers stack overflow
        // MAX_CALL_DEPTH is 8 in executor.rs
        let mut memory = VmMemory::new();
        let stack_top = memory.map(1, 512, Perms::RW) + 512;

        let mut asm = Assembler::new();
        // Create an infinite recursive function
        let mut func_start = asm.create_label();
        asm.set_label(&mut func_start).unwrap();
        asm.call_local(&func_start); // Call self recursively
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, stack_top);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for stack overflow, got {:?}", result);

        match result {
            Err(VmError::Exec(ExecError::StackOverflow)) => {
                // Expected
            }
            Err(e) => panic!("Expected StackOverflow, got {:?}", e),
            Ok(_) => panic!("Expected error for stack overflow"),
        }
    }

    #[test]
    fn test_instruction_limit_infinite_loop() {
        // Test that instruction limit is enforced on infinite loops
        let mut memory = VmMemory::new();

        let mut asm = Assembler::new();
        let mut loop_start = asm.create_label();
        asm.set_label(&mut loop_start).unwrap();
        asm.ja(&loop_start); // Infinite loop
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, 256);
        executor.set_instruction_limit(100);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for instruction limit, got {:?}", result);

        match result {
            Err(VmError::Exec(ExecError::InstructionLimit(count))) => {
                assert!(count >= 100, "Expected instruction count >= 100, got {}", count);
            }
            Err(e) => panic!("Expected InstructionLimit, got {:?}", e),
            Ok(_) => panic!("Expected error for instruction limit"),
        }
    }

    #[test]
    fn test_invalid_program_counter() {
        // Test that jumping to invalid PC is caught
        let mut memory = VmMemory::new();

        let mut asm = Assembler::new();
        // Create a forward label that we never set (will result in offset 0)
        // But we can manually create a jump to an invalid location
        // by jumping beyond the program
        asm.mov64_imm(R0, 0);
        // We'll just exit normally but start execution at invalid PC
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, 256);

        // Try to start execution at a very high PC
        let result = executor.call(1000, &[]);
        assert!(result.is_err(), "Expected error for invalid PC, got {:?}", result);

        match result {
            Err(VmError::Exec(ExecError::InvalidPc(_))) => {
                // Expected
            }
            Err(e) => panic!("Expected InvalidPc, got {:?}", e),
            Ok(_) => panic!("Expected error for invalid PC"),
        }
    }

    #[test]
    fn test_stack_access_valid() {
        // Test that valid stack access works correctly
        let mut memory = VmMemory::new();
        let stack_top = memory.map(1, 1024, Perms::RW) + 1024;

        let mut asm = Assembler::new();
        // Store value to stack (r10 is frame pointer, points to stack top)
        asm.mov64_imm(R1, 0x12345678);
        asm.stxdw(R10, -8, R1); // Store at [r10 - 8]
        asm.ldxdw(R0, R10, -8); // Load back
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, stack_top);

        let result = executor.call(0, &[]);
        assert!(result.is_ok(), "Expected valid stack access, got {:?}", result);
        assert_eq!(result.unwrap(), 0x12345678);
    }

    #[test]
    fn test_negative_address_wrap() {
        // Test that negative addresses (which wrap to large u64) are caught:
        // 0 - 8 wraps to a region index far beyond MAX_REGIONS, so it stays unmapped.
        let mut memory = VmMemory::new();

        let mut asm = Assembler::new();
        asm.mov64_imm(R6, 0); // Set r6 to 0
        asm.ldxdw(R0, R6, -8); // Load from address -8 (wraps to 0xFFF...F8)
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        // This should fail because 0 - 8 wraps to a huge address
        assert!(result.is_err(), "Expected error for negative address, got {:?}", result);
    }

    #[test]
    fn test_helper_not_found() {
        // Test that calling an unregistered helper returns an error
        let mut memory = VmMemory::new();

        let mut asm = Assembler::new();
        asm.call(999); // Call helper ID 999 which isn't registered
        asm.exit();
        let code = assemble(&mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for unknown helper, got {:?}", result);
    }
}
