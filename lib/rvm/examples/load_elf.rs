//! Load ELF example: Load and execute a real compiled eBPF ELF file.
//!
//! This example demonstrates loading an actual eBPF object file compiled
//! from C source code using clang.
//!
//! The example uses `bpf/example.o` which contains several functions:
//! - `simple_add(a, b)` - Returns a + b
//! - `return_magic()` - Returns 0xDEADBEEFCAFEBABE
//! - `bpf_main(ctx, out)` - More complex calculator
//!
//! Run with: cargo run --example load_elf
//!
//! Note: This example requires `bpf/example.o` to exist. Compile it with:
//!   clang -target bpf -O2 -c bpf/example.c -o bpf/example.o

use rvm::Vm;

fn main() {
    println!("=== Load ELF Example ===\n");

    // Load the ELF file
    let elf_bytes = match std::fs::read("bpf/example.o") {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Could not read bpf/example.o: {e}");
            eprintln!("\nMake sure to compile the BPF program first:");
            eprintln!("  clang -target bpf -O2 -c bpf/example.c -o bpf/example.o");
            return;
        }
    };

    let len = elf_bytes.len();
    println!("Loaded ELF file: {len} bytes\n");

    // Create a VM and load the ELF
    let vm = Vm::new();

    let mut program = match vm.load_elf(&elf_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading ELF: {e:?}");
            return;
        }
    };

    // Print available functions
    println!("Available functions:");
    for name in program.function_names() {
        if let Some(info) = program.function(name) {
            let pc = info.pc;
            let size = info.size;
            println!("  {name} @ PC={pc} (size={size})");
        }
    }
    println!();

    // Test simple_add function
    println!("--- Testing simple_add ---");
    test_simple_add(&mut program);

    // Test return_magic function
    println!("\n--- Testing return_magic ---");
    test_return_magic(&mut program);

    println!("\nAll tests completed!");
}

fn test_simple_add(program: &mut rvm::Program) {
    // simple_add takes two u64 arguments in r1 and r2, returns sum in r0
    let test_cases: &[(u64, u64, u64)] = &[
        (10, 20, 30),
        (100, 200, 300),
        (0, 0, 0),
        (1, u64::MAX - 1, u64::MAX), // Edge case: max value
    ];

    for (a, b, expected) in test_cases {
        match program.call("simple_add", &[*a, *b]) {
            Ok(result) => {
                let status = if result == *expected { "OK" } else { "FAIL" };
                println!("  simple_add({a}, {b}) = {result} (expected: {expected}) [{status}]");
                if result != *expected {
                    eprintln!("    ERROR: Result mismatch!");
                }
            }
            Err(e) => {
                eprintln!("  simple_add({a}, {b}) = ERROR: {e:?}");
            }
        }
    }
}

fn test_return_magic(program: &mut rvm::Program) {
    // return_magic takes no arguments, returns 0xDEADBEEFCAFEBABE
    const MAGIC: u64 = 0xDEADBEEFCAFEBABE;

    match program.call("return_magic", &[]) {
        Ok(result) => {
            let status = if result == MAGIC { "OK" } else { "FAIL" };
            println!("  return_magic() = 0x{result:016X} (expected: 0x{MAGIC:016X}) [{status}]");
            if result != MAGIC {
                eprintln!("    ERROR: Result mismatch!");
            }
        }
        Err(e) => {
            eprintln!("  return_magic() = ERROR: {e:?}");
        }
    }
}
