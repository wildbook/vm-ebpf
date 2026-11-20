//! Loads `bpf/prebuilt/examples/example.o`, prints what `Module::from_elf` and `Vm::load_modules` produce, and calls
//! its exported functions. Exits with an error when a call fails or returns the wrong value.

use std::mem::offset_of;

use anyhow::{ensure, Context, Result};
use rvm::{Module, Perms, Pod, Program, Vm};

const ELF_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/example.o");

/// `operation` of `struct input_ctx` that multiplies.
const OP_MUL: u32 = 2;

fn main() -> Result<()> {
    let elf_bytes = std::fs::read(ELF_PATH)
        .with_context(|| format!("reading {ELF_PATH}; `cmake --build --preset update-prebuilt` rebuilds it"))?;
    let len = elf_bytes.len();
    println!("Loaded {ELF_PATH}: {len} bytes");

    let vm = Vm::new();

    println!("\n=== Parsing ELF ===");
    let module = Module::from_elf(&elf_bytes)?;
    print_module_info(&module);

    println!("\n=== Linking ===");
    let mut program = vm.load_modules(&[&module])?;
    println!("  Stack region: {} bytes", program.memory().region_len(rvm::STACK_REGION));
    println!("  Stack top: 0x{:x}", stack_top(&program));
    print_function_table(&program);

    println!("\n=== simple_add(100, 200) ===");
    let sum = run_and_report(&mut program, "simple_add", &[100, 200])?;
    ensure!(sum == 300, "simple_add(100, 200) returned {sum}, expected 300");

    println!("\n=== return_magic() ===");
    let magic = run_and_report(&mut program, "return_magic", &[])?;
    ensure!(magic == 0xDEADBEEFCAFEBABE, "return_magic() returned 0x{magic:016X}, expected 0xDEADBEEFCAFEBABE");

    // `struct input_ctx` and `struct output_result` live in a host-mapped scratch region.
    println!("\n=== bpf_main (op=mul, 10 * 20) ===");
    let ctx = program.memory_mut().map(rvm::FIRST_FREE_REGION, 4096, Perms::RW)?;
    let out = ctx + 64;
    let input = InputCtx {
        value_a: 10,
        value_b: 20,
        operation: OP_MUL,
        flags: 0,
    };
    program.memory_mut().write_bytes(ctx, input.as_bytes())?;
    let status = program.call("bpf_main", &[ctx, out])?;
    let product: u64 = program.memory().read(out + offset_of!(OutputResult, result) as u64)?;
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
    let mut functions: Vec<_> = program.functions().collect();
    functions.sort_by_key(|(_, f)| f.pc);
    for (name, function) in functions {
        let pc = function.pc;
        let size = function.size;
        println!("  {name:20} pc={pc:<6} size={size} bytes");
    }
}

/// The initial r10: the end of the stack region.
fn stack_top(program: &Program) -> u64 {
    rvm::region_base(rvm::STACK_REGION) + program.memory().region_len(rvm::STACK_REGION) as u64
}

/// Call `name` with `args`, printing the entry point, arguments and result.
fn run_and_report(program: &mut Program, name: &str, args: &[u64]) -> Result<u64> {
    if let Some(info) = program.function_info(name) {
        let pc = info.pc;
        let byte_offset = pc * rvm::INSN_SIZE;
        println!("Entry PC: {pc} (byte offset: 0x{byte_offset:x})");
    }
    println!("Stack pointer (r10): 0x{:x}", stack_top(program));
    for (i, &arg) in args.iter().enumerate() {
        let reg = i + 1;
        println!("Argument r{reg}: 0x{arg:x} ({arg})");
    }

    let result = program.call(name, args).with_context(|| format!("calling {name}"))?;
    println!("Return value (r0): {result} (0x{result:x})");
    Ok(result)
}

/// `struct input_ctx` in `bpf/examples/example.c`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InputCtx {
    value_a: u64,
    value_b: u64,
    operation: u32,
    flags: u32,
}

// SAFETY: integer fields only, and the `u32`s fill the struct's last 8 bytes, so there is no padding.
unsafe impl Pod for InputCtx {}

/// `struct output_result` in `bpf/examples/example.c`.
#[repr(C)]
struct OutputResult {
    result: u64,
    status: u32,
    reserved: u32,
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use btf::Btf;

    use super::*;

    /// `bpf_main` reads and writes these structs in host memory, so their layouts must match the C structs.
    #[test]
    fn context_structs_match_the_program() {
        let module = Module::from_elf(&std::fs::read(ELF_PATH).unwrap()).unwrap();
        let btf = Btf::parse(module.btf_data.as_deref().unwrap()).unwrap();

        let input_ctx = vec![
            ("value_a", offset_of!(InputCtx, value_a)),
            ("value_b", offset_of!(InputCtx, value_b)),
            ("operation", offset_of!(InputCtx, operation)),
            ("flags", offset_of!(InputCtx, flags)),
        ];
        assert_eq!(btf.struct_layout("input_ctx"), Some((size_of::<InputCtx>(), input_ctx)));
        let output_result = vec![
            ("result", offset_of!(OutputResult, result)),
            ("status", offset_of!(OutputResult, status)),
            ("reserved", offset_of!(OutputResult, reserved)),
        ];
        assert_eq!(btf.struct_layout("output_result"), Some((size_of::<OutputResult>(), output_result)));
    }
}
