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
