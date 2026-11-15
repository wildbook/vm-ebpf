//! eBPF Loader Example
//!
//! This program demonstrates loading and executing a C-compiled eBPF program using
//! the `rvm` embeddable eBPF runtime:
//! - `vm.parse_module`: parses the ELF file into sections, symbols, exports and
//!   relocations (`rvm::Module`).
//! - `vm.link_one`: lays out memory, applies relocations and produces an
//!   executable `rvm::Program`.
//! - `program.call`: executes an exported function by name.
//!
//! Usage:
//!   cargo run --bin loader
//!
//! The program expects `bpf/example.o` to exist (compile with `make -C bpf example.o`)

use anyhow::{Context, Result};
use rvm::{Module, Perms, Program, Vm};

fn main() -> Result<()> {
    println!("=== eBPF Loader Example ===\n");

    let elf_path = "bpf/example.o";
    println!("Attempting to load: {elf_path}");

    let elf_bytes = match std::fs::read(elf_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Failed to read {elf_path}: {e}");
            println!("\nTo compile the eBPF program, run:");
            println!("  clang -target bpf -O2 -c bpf/example.c -o bpf/example.o");
            println!("\nOr use the Makefile:");
            println!("  make -C bpf example.o");

            println!("\nTrying fallback: bpf.o");
            std::fs::read("bpf.o").context("No eBPF object file found. Please compile one first.")?
        }
    };

    let len = elf_bytes.len();
    println!("Loaded {len} bytes\n");

    let vm = Vm::new();

    println!("=== Parsing ELF ===");
    let module = vm.parse_module("example", &elf_bytes)?;
    print_module_info(&module);

    println!("\n=== Linking ===");
    let mut program = vm.link_one(&module)?;
    println!("  Stack region: {} bytes", program.memory().region_len(rvm::STACK_REGION));
    println!("  Stack top: 0x{:x}", program.stack_top());
    print_function_table(&program);

    // 1. Run the 'simple_add' function which just adds two numbers
    println!("\n=== Test 1: Running 'simple_add(100, 200)' ===");
    run_and_report(&mut program, "simple_add", &[100, 200], |result| {
        println!("simple_add(100, 200) = {result}");
        if result == 300 {
            println!("Correct! 100 + 200 = 300");
        }
    });

    // 2. Run the 'return_magic' function which returns the magic value
    println!("\n=== Test 2: Running 'return_magic()' ===");
    run_and_report(&mut program, "return_magic", &[], |result| {
        println!("return_magic() = 0x{result:016X}");
        if result == 0xDEADBEEFCAFEBABE {
            println!("Correct! Got the magic value.");
        }
    });

    // 3. Run the main 'bpf_main' entry point: 10 * 20 via `struct input_ctx` / `struct output_result`.
    //    Both structs live in a host-mapped scratch region, separate from the stack.
    println!("\n=== Test 3: Running 'bpf_main' (op=mul, 10 * 20) ===");
    let scratch = program.memory_mut().map(rvm::FIRST_FREE_REGION, 4096, Perms::RW);
    let ctx = scratch;
    let out = ctx + 64;
    let mem = program.memory_mut();
    mem.write(ctx, 10u64)?; // value_a
    mem.write(ctx + 8, 20u64)?; // value_b
    mem.write(ctx + 16, 2u32)?; // operation = mul
    let status = program.call("bpf_main", &[ctx, out])?;
    let product: u64 = program.memory().read(out)?;

    println!("\n=== All tests complete ===");
    println!("bpf_main returned {status}, out->result = {product}");

    Ok(())
}

/// Print section, export, import and relocation info from a parsed `rvm::Module`.
fn print_module_info(module: &Module) {
    println!("\n=== Section map ===");
    for section in &module.sections {
        let exec = if section.is_executable() { " [EXEC]" } else { "" };
        println!("  {section}{exec}");
    }

    println!("\n=== Exports ===");
    for (name, export) in &module.exports {
        let section_idx = export.section_idx;
        let offset = export.offset;
        let suffix = if export.is_function { " (func)" } else { "" };
        println!("  {name} @ section[{section_idx}]+0x{offset:x}{suffix}");
    }

    if !module.imports.is_empty() {
        println!("\n=== Imports ===");
        for import in &module.imports {
            println!("  {}", import.name);
        }
    }

    println!("\n=== Relocations ===");
    for reloc in &module.relocations {
        let symbol_name = module
            .symbol_by_idx(reloc.symbol_idx)
            .map(|s| s.name.as_str())
            .unwrap_or("<unknown>");
        let section_idx = reloc.section_idx;
        let offset = reloc.offset;
        let rel_type = reloc.rel_type;
        let addend = reloc.addend;
        println!("  type={rel_type} section[{section_idx}]+0x{offset:x} -> {symbol_name} (addend={addend})");
    }
}

/// Print the linked program's function table.
fn print_function_table(program: &Program) {
    println!("\n=== Function table ===");
    let mut functions: Vec<_> = program.functions().values().collect();
    functions.sort_by_key(|f| f.pc);
    for function in functions {
        let name = &function.name;
        let pc = function.pc;
        let size = function.size;
        println!("  {name:20} pc={pc:<6} size={size} bytes");
    }
}

/// Call `name` with `args`, print the entry point and arguments, then report the result.
fn run_and_report(program: &mut Program, name: &str, args: &[u64], on_ok: impl FnOnce(u64)) {
    if let Some(info) = program.function(name) {
        let pc = info.pc;
        let byte_offset = pc * 8;
        println!("Entry PC: {pc} (byte offset: 0x{byte_offset:x})");
    }
    println!("Stack pointer (r10): 0x{:x}", program.stack_top());
    for (i, &arg) in args.iter().take(5).enumerate() {
        let reg = i + 1;
        println!("Argument r{reg}: 0x{arg:x} ({arg})");
    }
    println!();

    match program.call(name, args) {
        Ok(result) => {
            println!("Return value (r0): {result} (0x{result:x})");
            on_ok(result);
        }
        Err(e) => println!("Error: {e}"),
    }
}
