//! CO-RE (Compile Once - Run Everywhere) relocation example.
//!
//! This example demonstrates how CO-RE relocations adjust struct field
//! accesses at load time to match the host's actual struct layout.
//!
//! The BPF program (`bpf/core_example.c`) is compiled with one struct layout,
//! but we register a DIFFERENT layout in the host's type registry. CO-RE
//! relocations patch the field offsets so the program works correctly.
//!
//! ## How CO-RE Works
//!
//! 1. **Compile time**: The BPF program is compiled with:
//!    ```c
//!    struct event {
//!        u64 timestamp;  // offset 0
//!        u32 pid;        // offset 8
//!        u32 uid;        // offset 12
//!        u32 flags;      // offset 16
//!        ...
//!    };
//!    ```
//!
//! 2. **Load time**: The host registers its actual layout:
//!    ```rust
//!    vm.types()
//!        .register_struct("event")
//!        .field("flags", 0, 4)      // flags moved to offset 0!
//!        .field("pid", 4, 4)        // pid at offset 4
//!        .field("timestamp", 16, 8) // timestamp at offset 16!
//!        ...
//!    ```
//!
//! 3. **Relocation**: The loader patches instructions to use the new offsets.
//!    A load from `evt->timestamp` that was compiled as offset 0 gets
//!    patched to offset 16.
//!
//! Run with: cargo run --example core_reloc
//!
//! Note: Requires `bpf/core_example.o`. Compile with:
//!   clang -target bpf -O2 -g -c bpf/core_example.c -o bpf/core_example.o

use rvm::Vm;

/// Compile-time layout (what the BPF program was compiled with)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct CompileTimeEvent {
    timestamp: u64, // offset 0
    pid: u32,       // offset 8
    uid: u32,       // offset 12
    flags: u32,     // offset 16
    _pad: u32,      // offset 20
    data: u64,      // offset 24
}

/// Runtime layout (what the host application actually uses)
/// Note: Fields are in a DIFFERENT order!
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RuntimeEvent {
    flags: u32,     // offset 0  (was 16)
    pid: u32,       // offset 4  (was 8)
    uid: u32,       // offset 8  (was 12)
    _pad: u32,      // offset 12
    timestamp: u64, // offset 16 (was 0)
    data: u64,      // offset 24 (unchanged)
}

fn main() {
    println!("=== CO-RE Relocation Example ===\n");

    // Load the ELF file
    let elf_bytes = match std::fs::read("bpf/core_example.o") {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: Could not read bpf/core_example.o: {}", e);
            eprintln!("\nCompile with:");
            eprintln!("  clang -target bpf -O2 -g -c bpf/core_example.c -o bpf/core_example.o");
            return;
        }
    };

    println!("Loaded ELF file: {} bytes\n", elf_bytes.len());

    // First, test WITHOUT CO-RE (using compile-time layout)
    println!("--- Test 1: Without CO-RE (compile-time layout) ---\n");
    test_without_core(&elf_bytes);

    // Then, test WITH CO-RE (using different runtime layout)
    println!("\n--- Test 2: With CO-RE (runtime layout differs!) ---\n");
    test_with_core(&elf_bytes);

    println!("\nCO-RE demonstration complete!");
}

fn test_without_core(elf_bytes: &[u8]) {
    // Create VM without registering types (no CO-RE)
    let vm = Vm::new();

    let mut program = match vm.load_elf(elf_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading ELF: {:?}", e);
            return;
        }
    };

    // Create event with compile-time layout
    let event = CompileTimeEvent {
        timestamp: 0x1122334455667788,
        pid: 1234,
        uid: 5678,
        flags: 0xABCD,
        _pad: 0,
        data: 0xDEADBEEF,
    };

    println!("Compile-time layout:");
    println!("  timestamp @ offset 0:  0x{:016X}", event.timestamp);
    println!("  pid       @ offset 8:  {}", event.pid);
    println!("  flags     @ offset 16: 0x{:04X}", event.flags);
    println!("  data      @ offset 24: 0x{:08X}", event.data);

    // Write event to program memory at a known location
    let event_ptr = write_event_to_memory(&mut program, &event);
    println!("\n  Event written to memory at address 0x{:X}\n", event_ptr);

    // Call the functions
    test_function(&mut program, "no_core_add", &[10, 32], Some(42), "10 + 32");
    test_function(&mut program, "read_timestamp", &[event_ptr], Some(event.timestamp), "timestamp");
    test_function(&mut program, "read_pid", &[event_ptr], Some(event.pid as u64), "pid");
    test_function(&mut program, "read_flags", &[event_ptr], Some(event.flags as u64), "flags");
}

fn test_with_core(elf_bytes: &[u8]) {
    // Create VM and register the RUNTIME struct layout
    let mut vm = Vm::new();

    // Register the runtime layout - fields are in different positions!
    vm.types()
        .register_struct("event")
        .field("flags", 0, 4) // flags at offset 0 (was 16)
        .field("pid", 4, 4) // pid at offset 4 (was 8)
        .field("uid", 8, 4) // uid at offset 8 (was 12)
        .field("_pad", 12, 4)
        .field("timestamp", 16, 8) // timestamp at offset 16 (was 0!)
        .field("data", 24, 8)
        .size(32);

    println!("Registered runtime layout in type registry:");
    println!("  flags     @ offset 0");
    println!("  pid       @ offset 4");
    println!("  uid       @ offset 8");
    println!("  timestamp @ offset 16  <- MOVED from 0!");
    println!("  data      @ offset 24\n");

    let mut program = match vm.load_elf(elf_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error loading ELF: {:?}", e);
            return;
        }
    };

    // Create event with RUNTIME layout (fields reordered)
    let event = RuntimeEvent {
        flags: 0xABCD,                 // offset 0
        pid: 1234,                     // offset 4
        uid: 5678,                     // offset 8
        _pad: 0,                       // offset 12
        timestamp: 0x1122334455667788, // offset 16
        data: 0xDEADBEEF,              // offset 24
    };

    println!("Runtime layout (different from compile-time!):");
    println!("  flags     @ offset 0:  0x{:04X}", event.flags);
    println!("  pid       @ offset 4:  {}", event.pid);
    println!("  uid       @ offset 8:  {}", event.uid);
    println!("  timestamp @ offset 16: 0x{:016X}", event.timestamp);
    println!("  data      @ offset 24: 0x{:08X}", event.data);

    // Write event to program memory
    let event_ptr = write_runtime_event_to_memory(&mut program, &event);
    println!("\n  Event written to memory at address 0x{:X}\n", event_ptr);

    // If CO-RE worked, the relocated program should read correct values
    // from the new offsets!
    println!("Testing with CO-RE relocations:");
    test_function(&mut program, "no_core_add", &[100, 23], Some(123), "100 + 23");

    // These should work if CO-RE patched the offsets correctly
    test_function(
        &mut program,
        "read_timestamp",
        &[event_ptr],
        Some(event.timestamp),
        "timestamp (CO-RE should relocate offset 0 -> 16)",
    );
    test_function(
        &mut program,
        "read_pid",
        &[event_ptr],
        Some(event.pid as u64),
        "pid (CO-RE should relocate offset 8 -> 4)",
    );
    test_function(
        &mut program,
        "read_flags",
        &[event_ptr],
        Some(event.flags as u64),
        "flags (CO-RE should relocate offset 16 -> 0)",
    );
}

fn test_function(program: &mut rvm::Program, name: &str, args: &[u64], expected: Option<u64>, desc: &str) {
    match program.call(name, args) {
        Ok(result) => {
            let status = match expected {
                Some(exp) if result == exp => "OK",
                Some(_) => "MISMATCH",
                None => "?",
            };
            println!("  {}({}) = 0x{:X} [{}]", name, desc, result, status);
            if let Some(exp) = expected {
                if result != exp {
                    println!("    Expected: 0x{:X}", exp);
                }
            }
        }
        Err(e) => {
            println!("  {}({}) = ERROR: {:?}", name, desc, e);
        }
    }
}

fn write_event_to_memory(program: &mut rvm::Program, event: &CompileTimeEvent) -> u64 {
    use rvm::Memory;

    // Find a safe location after code (use a fixed high address)
    let event_addr: u64 = 0x1000; // 4KB offset

    // Ensure memory is large enough
    let mem = program.memory_mut();
    if mem.len() < (event_addr as usize + 32) {
        mem.resize(event_addr as usize + 256);
    }

    // Write fields at compile-time offsets
    let _ = mem.store_u64(event_addr + 0, event.timestamp);
    let _ = mem.store_u32(event_addr + 8, event.pid);
    let _ = mem.store_u32(event_addr + 12, event.uid);
    let _ = mem.store_u32(event_addr + 16, event.flags);
    let _ = mem.store_u32(event_addr + 20, event._pad);
    let _ = mem.store_u64(event_addr + 24, event.data);

    event_addr
}

fn write_runtime_event_to_memory(program: &mut rvm::Program, event: &RuntimeEvent) -> u64 {
    use rvm::Memory;

    let event_addr: u64 = 0x1000;

    let mem = program.memory_mut();
    if mem.len() < (event_addr as usize + 32) {
        mem.resize(event_addr as usize + 256);
    }

    // Write fields at RUNTIME offsets (different from compile-time!)
    let _ = mem.store_u32(event_addr + 0, event.flags); // flags first
    let _ = mem.store_u32(event_addr + 4, event.pid);
    let _ = mem.store_u32(event_addr + 8, event.uid);
    let _ = mem.store_u32(event_addr + 12, event._pad);
    let _ = mem.store_u64(event_addr + 16, event.timestamp); // timestamp later
    let _ = mem.store_u64(event_addr + 24, event.data);

    event_addr
}
