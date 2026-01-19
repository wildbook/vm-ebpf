//! eBPF Loader Example
//!
//! This program demonstrates loading and executing a C-compiled eBPF program using:
//! - `constelf`: ELF parsing and relocation handling
//! - `rvm-core`: eBPF virtual machine execution
//! - `btf`: (optional) BTF/CO-RE support
//!
//! The loader:
//! 1. Parses the ELF file to extract code and data sections
//! 2. Allocates a flat memory region and maps sections
//! 3. Applies relocations (R_BPF_64_64 for 64-bit addresses)
//! 4. Initializes the VM context with stack and registers
//! 5. Executes the eBPF program
//!
//! Usage:
//!   cargo run --bin loader
//!
//! The program expects `bpf/example.o` to exist (compile with `make -C bpf example.o`)

use std::collections::HashMap;
use std::ops::ControlFlow;

use anyhow::{anyhow, bail, Context as _, Result};
use constelf::file::ElfFile;
use constelf::raw::{reloc, shf, sht};
use constelf::relocs::ElfRelocsChunk;
use rvm_core::{Context, Flow, Memory};

/// Memory implementation for the eBPF VM
///
/// Provides a flat byte array with bounds checking.
/// The memory layout is:
/// - [0, code_end): Executable code sections
/// - [code_end, data_end): Data sections (.data, .rodata, .bss)
/// - [data_end, stack_end): Stack space
#[derive(Default)]
pub struct VmMemory {
    data: Vec<u8>,
}

impl VmMemory {
    pub fn new(size: usize) -> Self {
        Self { data: vec![0u8; size] }
    }

    pub fn with_data(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Write a slice of bytes to memory at the given offset
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        if offset + bytes.len() > self.data.len() {
            bail!("write out of bounds: offset={}, len={}, capacity={}", offset, bytes.len(), self.data.len());
        }
        self.data[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Read bytes from memory
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > self.data.len() {
            bail!("read out of bounds: offset={}, len={}, capacity={}", offset, len, self.data.len());
        }
        Ok(&self.data[offset..offset + len])
    }
}

impl Memory for VmMemory {
    type Err = &'static str;

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Err> {
        self.data.get(addr as usize).copied().ok_or("load_u8: out of bounds")
    }

    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
        self.data
            .get_mut(addr as usize)
            .map(|b| *b = value)
            .ok_or("store_u8: out of bounds")
    }

    fn load_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        let i = addr as usize;
        if i + 2 > self.data.len() {
            return Err("load_u16: out of bounds");
        }
        Ok(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
    }

    fn load_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        let i = addr as usize;
        if i + 4 > self.data.len() {
            return Err("load_u32: out of bounds");
        }
        Ok(u32::from_le_bytes([self.data[i], self.data[i + 1], self.data[i + 2], self.data[i + 3]]))
    }

    fn load_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        let i = addr as usize;
        if i + 8 > self.data.len() {
            return Err("load_u64: out of bounds");
        }
        Ok(u64::from_le_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
            self.data[i + 4],
            self.data[i + 5],
            self.data[i + 6],
            self.data[i + 7],
        ]))
    }

    fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        let i = addr as usize;
        if i + 2 > self.data.len() {
            return Err("store_u16: out of bounds");
        }
        self.data[i..i + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        let i = addr as usize;
        if i + 4 > self.data.len() {
            return Err("store_u32: out of bounds");
        }
        self.data[i..i + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        let i = addr as usize;
        if i + 8 > self.data.len() {
            return Err("store_u64: out of bounds");
        }
        self.data[i..i + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

/// Information about a loaded section
#[derive(Debug, Clone)]
struct SectionInfo {
    /// Index in the ELF section header table
    index: usize,
    /// Name of the section
    name: String,
    /// Virtual address in our memory layout
    vaddr: u64,
    /// Size in bytes
    size: u64,
    /// Whether this section is executable (contains code)
    executable: bool,
}

/// A loaded eBPF program ready for execution
struct LoadedProgram {
    /// The VM memory containing code, data, and stack
    memory: VmMemory,
    /// Map from section index to section info
    sections: HashMap<usize, SectionInfo>,
    /// Entry point address (in instruction units, not bytes)
    entry_pc: u64,
    /// Stack pointer (points to end of stack)
    stack_ptr: u64,
}

/// Load an eBPF ELF file into memory
fn load_elf(elf_bytes: &[u8]) -> Result<LoadedProgram> {
    // Parse ELF
    let elf = ElfFile::new(elf_bytes).map_err(|e| anyhow!("Failed to parse ELF file: {:?}", e))?;
    let sections = elf.sections().map_err(|e| anyhow!("Failed to get sections: {:?}", e))?;

    // First pass: calculate total memory needed
    const PAGE_SIZE: usize = 8; // Align to 8 bytes (instruction size)
    const BASE_ADDR: usize = 0; // Start at address 0
    const STACK_SIZE: usize = 512; // eBPF stack size

    let mut total_size = BASE_ADDR;
    let mut section_map: HashMap<usize, SectionInfo> = HashMap::new();

    // Find the entry point section (look for "prog", "simple", or ".text")
    let mut _entry_section_idx = None;
    let mut entry_section_offset = 0u64;

    for (idx, header) in sections.headers().iter().enumerate() {
        // Only process sections that need memory allocation
        if (header.sh_flags & shf::ALLOC as u64) == 0 {
            continue;
        }

        let name = sections
            .name(header)
            .map_err(|e| anyhow!("Failed to get section name: {:?}", e))?;
        let name_str = name.to_str().unwrap_or("<invalid>");

        // Align to PAGE_SIZE
        total_size = total_size.next_multiple_of(PAGE_SIZE);

        let section_info = SectionInfo {
            index: idx,
            name: name_str.to_string(),
            vaddr: total_size as u64,
            size: header.sh_size,
            executable: (header.sh_flags & shf::EXECINSTR as u64) != 0,
        };

        // Track potential entry points
        if section_info.executable && _entry_section_idx.is_none() {
            // Prefer "prog" section, but fall back to first executable section
            if name_str == "prog" || name_str == ".text" || name_str == "simple" {
                _entry_section_idx = Some(idx);
                entry_section_offset = section_info.vaddr;
            }
        }

        println!(
            "  Section [{}]: {} @ 0x{:x} ({} bytes){}",
            idx,
            name_str,
            section_info.vaddr,
            section_info.size,
            if section_info.executable { " [EXEC]" } else { "" }
        );

        section_map.insert(idx, section_info);
        total_size += header.sh_size as usize;
    }

    // If no named entry point found, use first executable section
    if _entry_section_idx.is_none() {
        for info in section_map.values() {
            if info.executable {
                _entry_section_idx = Some(info.index);
                entry_section_offset = info.vaddr;
                break;
            }
        }
    }

    // Add stack space
    total_size = total_size.next_multiple_of(PAGE_SIZE);
    let stack_start = total_size;
    total_size += STACK_SIZE;
    let stack_end = total_size;

    println!("  Stack: 0x{:x} - 0x{:x} ({} bytes)", stack_start, stack_end, STACK_SIZE);
    println!("  Total memory: {} bytes", total_size);

    // Allocate memory
    let mut memory = VmMemory::new(total_size);

    // Second pass: copy section data
    for (idx, header) in sections.headers().iter().enumerate() {
        if let Some(info) = section_map.get(&idx) {
            if header.sh_type != sht::NOBITS {
                // Copy section data (not for .bss which is NOBITS)
                let section = sections
                    .by_index(idx)
                    .ok_or_else(|| anyhow!("Section {} not found", idx))?;
                let bytes = section
                    .bytes()
                    .map_err(|e| anyhow!("Failed to get section bytes: {:?}", e))?;
                memory.write_bytes(info.vaddr as usize, bytes)?;
            }
        }
    }

    // Third pass: apply relocations
    let mut reloc_iter = elf
        .relocs()
        .iter()
        .map_err(|e| anyhow!("Failed to get relocations: {:?}", e))?;

    let symtab = sections
        .symtab()
        .map_err(|e| anyhow!("Failed to get symbol table: {:?}", e))?;

    loop {
        let (next, chunk) = reloc_iter.into_next();
        reloc_iter = next;

        let Some(chunk) = chunk else {
            break;
        };

        // Get the target section for this relocation chunk
        let target_idx = chunk.target_idx();
        let Some(target_info) = section_map.get(&target_idx) else {
            continue; // Relocations for non-ALLOC sections, skip
        };

        let relocs = match chunk.relocs().map_err(|e| anyhow!("Failed to get relocs: {:?}", e))? {
            ElfRelocsChunk::Rel(r) => r,
            ElfRelocsChunk::Rela(_) => continue, // TODO: Handle RELA
            ElfRelocsChunk::None => continue,
        };

        for r in relocs {
            let r_off = r.r_offset;
            let r_sym = r.sym();
            let r_typ = r.typ();

            let symbol = symtab
                .get(r_sym as usize)
                .ok_or_else(|| anyhow!("Symbol {} not found", r_sym))?;

            match r_typ {
                reloc::bpf::BPF_64_64 => {
                    // Get the section where the symbol is defined
                    let sym_sect_idx = symbol.st_shndx as usize;
                    let sym_sect_info = section_map
                        .get(&sym_sect_idx)
                        .ok_or_else(|| anyhow!("Symbol section {} not mapped", sym_sect_idx))?;

                    // Calculate final address: section base + symbol offset
                    let sym_addr = sym_sect_info.vaddr + symbol.st_value;

                    // R_BPF_64_64 patches the imm32 fields of a LD_IMM64 instruction
                    // The instruction is at target_section_addr + r_offset
                    let insn_addr = target_info.vaddr + r_off;

                    // Write lower 32 bits to imm of first instruction (offset +4)
                    let lo = (sym_addr as u32).to_le_bytes();
                    memory.write_bytes((insn_addr + 4) as usize, &lo)?;

                    // Write upper 32 bits to imm of second instruction (offset +12)
                    let hi = ((sym_addr >> 32) as u32).to_le_bytes();
                    memory.write_bytes((insn_addr + 12) as usize, &hi)?;

                    println!("  Relocation: R_BPF_64_64 at 0x{:x} -> 0x{:x}", insn_addr, sym_addr);
                }
                _ => {
                    println!("  Warning: Unsupported relocation type {}", r_typ);
                }
            }
        }
    }

    // Calculate entry point in instruction units (each instruction is 8 bytes)
    let entry_pc = entry_section_offset / 8;

    Ok(LoadedProgram {
        memory,
        sections: section_map,
        entry_pc,
        stack_ptr: stack_end as u64,
    })
}

/// Execute the eBPF program
fn run_program(prog: &mut LoadedProgram, args: &[u64]) -> Result<u64> {
    let mut ctx = Context::new(std::mem::take(&mut prog.memory));

    // Set up argument registers (r1-r5)
    for (i, &arg) in args.iter().take(5).enumerate() {
        ctx.regs[i + 1] = arg;
    }

    // Set up frame pointer (r10) to point to end of stack
    ctx.regs[10] = prog.stack_ptr;

    // Execute starting at entry point
    let mut pc = prog.entry_pc;

    println!("\n=== Executing eBPF program ===");
    println!("Entry PC: {} (byte offset: 0x{:x})", pc, pc * 8);
    println!("Stack pointer (r10): 0x{:x}", ctx.regs[10]);
    for (i, &arg) in args.iter().take(5).enumerate() {
        println!("Argument r{}: 0x{:x} ({})", i + 1, arg, arg);
    }
    println!();

    let mut instruction_count = 0u64;
    const MAX_INSTRUCTIONS: u64 = 100_000;

    loop {
        if instruction_count > MAX_INSTRUCTIONS {
            bail!("Exceeded maximum instruction count ({MAX_INSTRUCTIONS})");
        }
        instruction_count += 1;

        let instr = ctx
            .data
            .load_pc(pc)
            .map_err(|e| anyhow!("Failed to load instruction at PC {}: {}", pc, e))?;
        pc += 1;

        let flow = match rvm_core::step(&mut ctx, instr) {
            ControlFlow::Break(flow) => flow,
            ControlFlow::Continue(instr) => {
                // Two-instruction LD_IMM64
                let second = ctx
                    .data
                    .load_pc(pc)
                    .map_err(|e| anyhow!("Failed to load second instruction at PC {}: {}", pc, e))?;
                pc += 1;
                rvm_core::step_ld64(&mut ctx, instr, second)
            }
        };

        match flow {
            Flow::Next => continue,
            Flow::Exit => {
                println!("Program exited after {} instructions", instruction_count);
                println!("Return value (r0): {} (0x{:x})", ctx.regs[0], ctx.regs[0]);

                // Return memory to the program struct for inspection
                prog.memory = ctx.data;
                return Ok(ctx.regs[0]);
            }
            Flow::Jump(offset) => pc = pc.wrapping_add_signed(offset),
            Flow::Call(offset) => {
                // BPF-to-BPF call: save return address and jump
                // For simplicity, we use a recursive approach here
                // A production implementation would maintain a call stack
                println!("  [Call] PC {} -> offset {} (target {})", pc - 1, offset, pc.wrapping_add_signed(offset));

                // Push return address conceptually
                // The called function will use the same context
                let target_pc = pc.wrapping_add_signed(offset);

                // For now, just update PC (proper call semantics would save state)
                pc = target_pc;
            }
            Flow::CallExt(helper_id) => {
                // External helper function call
                // In a real implementation, this would dispatch to helper functions
                println!("  [Helper] ID {} called", helper_id);

                // Simple helper stubs
                match helper_id {
                    1 => {
                        // bpf_trace_printk style: just print r1
                        println!("    -> trace: {}", ctx.regs[1]);
                        ctx.regs[0] = 0;
                    }
                    _ => {
                        println!("    -> unknown helper, returning 0");
                        ctx.regs[0] = 0;
                    }
                }
            }
            Flow::FailCpu => bail!("CPU fault at PC {}", pc - 1),
            Flow::FailMem(e) => bail!("Memory fault at PC {}: {}", pc - 1, e),
            Flow::Missing => bail!("Unimplemented instruction at PC {}", pc - 1),
        }
    }
}

fn main() -> Result<()> {
    println!("=== eBPF Loader Example ===\n");

    // Try to load the example.o file
    let elf_path = "bpf/example.o";

    println!("Attempting to load: {}", elf_path);

    let elf_bytes = match std::fs::read(elf_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Failed to read {}: {}", elf_path, e);
            println!("\nTo compile the eBPF program, run:");
            println!("  clang -target bpf -O2 -c bpf/example.c -o bpf/example.o");
            println!("\nOr use the Makefile:");
            println!("  make -C bpf example.o");

            // Fall back to the existing bpf.o if available
            println!("\nTrying fallback: bpf.o");
            std::fs::read("bpf.o").context("No eBPF object file found. Please compile one first.")?
        }
    };

    println!("Loaded {} bytes\n", elf_bytes.len());

    // Load the ELF file
    println!("=== Loading ELF sections ===");
    let mut prog = load_elf(&elf_bytes)?;

    // Display loaded sections
    println!("\n=== Section map ===");
    let mut sorted_sections: Vec<_> = prog.sections.values().collect();
    sorted_sections.sort_by_key(|s| s.vaddr);
    for section in sorted_sections {
        println!(
            "  {:20} @ 0x{:04x} - 0x{:04x} ({:4} bytes){}",
            section.name,
            section.vaddr,
            section.vaddr + section.size,
            section.size,
            if section.executable { " [EXEC]" } else { "" }
        );
    }

    // Demonstrate running different entry points

    // 1. Run the 'simple' function which just adds two numbers
    println!("\n=== Test 1: Running 'simple_add(100, 200)' ===");
    if let Some(simple_section) = prog.sections.values().find(|s| s.name == "simple") {
        let simple_pc = simple_section.vaddr / 8;
        let mut prog_copy = LoadedProgram {
            memory: VmMemory::with_data(prog.memory.data.clone()),
            sections: prog.sections.clone(),
            entry_pc: simple_pc,
            stack_ptr: prog.stack_ptr,
        };
        match run_program(&mut prog_copy, &[100, 200, 0, 0, 0]) {
            Ok(result) => {
                println!("simple_add(100, 200) = {}", result);
                if result == 300 {
                    println!("Correct! 100 + 200 = 300");
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("'simple' section not found");
    }

    // 2. Run the 'const' function which returns the magic value
    println!("\n=== Test 2: Running 'return_magic()' ===");
    if let Some(const_section) = prog.sections.values().find(|s| s.name == "const") {
        let const_pc = const_section.vaddr / 8;
        let mut prog_copy = LoadedProgram {
            memory: VmMemory::with_data(prog.memory.data.clone()),
            sections: prog.sections.clone(),
            entry_pc: const_pc,
            stack_ptr: prog.stack_ptr,
        };
        match run_program(&mut prog_copy, &[]) {
            Ok(result) => {
                println!("return_magic() = 0x{:016X}", result);
                if result == 0xDEADBEEFCAFEBABE {
                    println!("Correct! Got the magic value.");
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    } else {
        println!("'const' section not found");
    }

    // 3. Run the main 'prog' function
    println!("\n=== Test 3: Running main 'bpf_main' ===");
    let result = run_program(&mut prog, &[10, 20, 0, 0])?;

    println!("\n=== All tests complete ===");
    println!("Final result from bpf_main: {}", result);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_memory_basic() {
        let mut mem = VmMemory::new(64);

        // Test u8
        mem.store_u8(0, 0x42).unwrap();
        assert_eq!(mem.load_u8(0).unwrap(), 0x42);

        // Test u64
        mem.store_u64(8, 0xDEADBEEFCAFEBABE).unwrap();
        assert_eq!(mem.load_u64(8).unwrap(), 0xDEADBEEFCAFEBABE);

        // Test bounds
        assert!(mem.load_u8(100).is_err());
    }

    #[test]
    fn test_vm_memory_write_bytes() {
        let mut mem = VmMemory::new(64);
        let data = [1, 2, 3, 4, 5, 6, 7, 8];

        mem.write_bytes(0, &data).unwrap();

        assert_eq!(mem.load_u64(0).unwrap(), 0x0807060504030201);
    }
}
