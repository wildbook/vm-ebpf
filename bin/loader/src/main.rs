//! Loads `bpf/examples/example.o`, prints what `Vm::parse_module` and `Vm::link_one` produce, and calls its exported
//! functions.
//! Exits with an error when a call fails or returns the wrong value.

use anyhow::{ensure, Context, Result};
use rvm::{Module, Perms, Program, Vm};

fn main() -> Result<()> {
    let elf_path = "bpf/examples/example.o";
    let elf_bytes =
        std::fs::read(elf_path).with_context(|| format!("reading {elf_path}; bpf/CMakeLists.txt builds it"))?;
    let len = elf_bytes.len();
    println!("Loaded {elf_path}: {len} bytes");

    let vm = Vm::new();

    println!("\n=== Parsing ELF ===");
    let module = vm.parse_module("example", &elf_bytes)?;
    print_module_info(&module);

    println!("\n=== Linking ===");
    let mut program = vm.link_one(&module)?;
    println!("  Stack region: {} bytes", program.memory().region_len(rvm::STACK_REGION));
    println!("  Stack top: 0x{:x}", program.stack_top());
    print_function_table(&program);

    println!("\n=== simple_add(100, 200) ===");
    let sum = run_and_report(&mut program, "simple_add", &[100, 200])?;
    ensure!(sum == 300, "simple_add(100, 200) returned {sum}, expected 300");

    println!("\n=== return_magic() ===");
    let magic = run_and_report(&mut program, "return_magic", &[])?;
    ensure!(magic == 0xDEADBEEFCAFEBABE, "return_magic() returned 0x{magic:016X}, expected 0xDEADBEEFCAFEBABE");

    // `struct input_ctx` and `struct output_result` live in a host-mapped scratch region.
    println!("\n=== bpf_main (op=mul, 10 * 20) ===");
    let ctx = program.memory_mut().map(rvm::FIRST_FREE_REGION, 4096, Perms::RW);
    let out = ctx + 64;
    let mem = program.memory_mut();
    mem.write(ctx, 10u64)?; // value_a
    mem.write(ctx + 8, 20u64)?; // value_b
    mem.write(ctx + 16, 2u32)?; // operation = mul
    let status = program.call("bpf_main", &[ctx, out])?;
    let product: u64 = program.memory().read(out)?;
    println!("bpf_main returned {status}, out->result = {product}");
    ensure!(status == 0 && product == 200, "bpf_main returned {status}, result {product}; expected 0, 200");

    Ok(())
}

/// Print section, export, import and relocation info from a parsed `rvm::Module`.
fn print_module_info(module: &Module) {
    println!("\n=== Section map ===");
    for section in &module.sections {
        let exec = if section.kind == rvm::SectionKind::Code {
            " [EXEC]"
        } else {
            ""
        };
        println!("  {section}{exec}");
    }

    println!("\n=== Exports ===");
    let mut exports: Vec<_> = module.exports.iter().collect();
    exports.sort_unstable_by_key(|(name, _)| *name);
    for (name, export) in exports {
        let section_idx = export.section_idx;
        let offset = export.offset;
        let suffix = if export.is_function { " (func)" } else { "" };
        println!("  {name} @ section[{section_idx}]+0x{offset:x}{suffix}");
    }

    if !module.imports.is_empty() {
        println!("\n=== Imports ===");
        for import in &module.imports {
            println!("  {import}");
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
    let mut functions: Vec<_> = program.functions().iter().collect();
    functions.sort_by_key(|(_, f)| f.pc);
    for (name, function) in functions {
        let pc = function.pc;
        let size = function.size;
        println!("  {name:20} pc={pc:<6} size={size} bytes");
    }
}

/// Call `name` with `args`, printing the entry point, arguments and result.
fn run_and_report(program: &mut Program, name: &str, args: &[u64]) -> Result<u64> {
    if let Some(info) = program.function(name) {
        let pc = info.pc;
        let byte_offset = pc * 8;
        println!("Entry PC: {pc} (byte offset: 0x{byte_offset:x})");
    }
    println!("Stack pointer (r10): 0x{:x}", program.stack_top());
    for (i, &arg) in args.iter().enumerate() {
        let reg = i + 1;
        println!("Argument r{reg}: 0x{arg:x} ({arg})");
    }

    let result = program.call(name, args).with_context(|| format!("calling {name}"))?;
    println!("Return value (r0): {result} (0x{result:x})");
    Ok(result)
}
