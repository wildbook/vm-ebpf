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

// ==================== Memory Safety Tests ====================

mod memory_safety {
    use ebpf_asm::{Assembler, R0, R1, R10, R2, R6};
    use rvm::{ExecError, Executor, HelperRegistry, Memory, VmError, VmMemory};

    /// Helper to load assembled instructions into memory and create an executor.
    fn create_executor_with_program(memory: &mut VmMemory, asm: &mut Assembler) {
        let instructions = asm.assemble_to_u64().unwrap();
        for (i, insn) in instructions.iter().enumerate() {
            memory.store_u64((i * 8) as u64, *insn).unwrap();
        }
    }

    #[test]
    fn test_memory_out_of_bounds_read() {
        // Test that reading beyond memory bounds returns an error
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        // Try to load from address 0xFFFFFFFF (way beyond bounds)
        asm.mov64_imm(R1, 0x7FFFFFFF); // Large address
        asm.ldxdw(R0, R1, 0); // Try to load from that address
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);

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
        // Test that writing beyond memory bounds returns an error
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        // Try to store to address 0xFFFFFFFF (way beyond bounds)
        asm.mov64_imm(R1, 0x7FFFFFFF); // Large address
        asm.mov64_imm(R2, 42);
        asm.stxdw(R1, 0, R2); // Try to store to that address
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);

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
        // Test reading at the exact boundary of memory
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        // Memory is 256 bytes, trying to read 8 bytes at offset 250 should fail
        // (250 + 8 = 258 > 256)
        asm.mov64_imm(R1, 250);
        asm.ldxdw(R0, R1, 0);
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for boundary read, got {:?}", result);
    }

    #[test]
    fn test_stack_overflow_deep_recursion() {
        // Test that deep BPF-to-BPF recursion triggers stack overflow
        // MAX_CALL_DEPTH is 8 in executor.rs
        let mut memory = VmMemory::new(512);

        let mut asm = Assembler::new();
        // Create an infinite recursive function
        let mut func_start = asm.create_label();
        asm.set_label(&mut func_start).unwrap();
        asm.call_local(&func_start); // Call self recursively
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 512);

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
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        let mut loop_start = asm.create_label();
        asm.set_label(&mut loop_start).unwrap();
        asm.ja(&loop_start); // Infinite loop

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);
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
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        // Create a forward label that we never set (will result in offset 0)
        // But we can manually create a jump to an invalid location
        // by jumping beyond the program
        asm.mov64_imm(R0, 0);
        // We'll just exit normally but start execution at invalid PC
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);

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
        let mut memory = VmMemory::new(1024);
        let stack_top = 1024u64;

        let mut asm = Assembler::new();
        // Store value to stack (r10 is frame pointer, points to stack top)
        asm.mov64_imm(R1, 0x12345678);
        asm.stxdw(R10, -8, R1); // Store at [r10 - 8]
        asm.ldxdw(R0, R10, -8); // Load back
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, stack_top);

        let result = executor.call(0, &[]);
        assert!(result.is_ok(), "Expected valid stack access, got {:?}", result);
        assert_eq!(result.unwrap(), 0x12345678);
    }

    #[test]
    fn test_negative_address_wrap() {
        // Test that negative addresses (which wrap to large u64) are caught
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        // Load from r10-8 where r10 is 0 (not set), causing underflow
        asm.mov64_imm(R6, 0); // Set r6 to 0
        asm.ldxdw(R0, R6, -8); // Load from address -8 (wraps to 0xFFF...F8)
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        // This should fail because 0 - 8 wraps to a huge address
        assert!(result.is_err(), "Expected error for negative address, got {:?}", result);
    }

    #[test]
    fn test_helper_not_found() {
        // Test that calling an unregistered helper returns an error
        let mut memory = VmMemory::new(256);

        let mut asm = Assembler::new();
        asm.call(999); // Call helper ID 999 which isn't registered
        asm.exit();

        create_executor_with_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 256);

        let result = executor.call(0, &[]);
        assert!(result.is_err(), "Expected error for unknown helper, got {:?}", result);
    }
}
