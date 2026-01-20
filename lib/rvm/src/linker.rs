//! Linker for combining multiple eBPF modules.
//!
//! The linker resolves symbol references between modules, applies relocations,
//! and produces a linked program ready for execution.

use std::collections::HashMap;

use btf::{apply_core_relocations, Btf};
use constelf::raw::reloc;

use crate::error::{LinkError, Result, VmError};
use crate::helper::HelperRegistry;
use crate::memory::VmMemory;
use crate::module::{Module, Relocation};
use crate::program::{FunctionInfo, Program};
use crate::section::SectionKind;
use crate::types::TypeRegistry;
use crate::vm::VmConfig;

/// Memory layout information for a module.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ModuleLayout {
    /// Base address for this module's code.
    code_base: u64,
    /// Base address for this module's data.
    data_base: u64,
    /// Map from original section index to new virtual address.
    section_addrs: HashMap<usize, u64>,
}

/// Linker for eBPF modules.
#[allow(dead_code)]
pub struct Linker<'a> {
    helpers: &'a HelperRegistry,
    types: &'a TypeRegistry,
    config: &'a VmConfig,
}

impl<'a> Linker<'a> {
    /// Create a new linker.
    pub fn new(helpers: &'a HelperRegistry, types: &'a TypeRegistry, config: &'a VmConfig) -> Self {
        Self { helpers, types, config }
    }

    /// Link multiple modules into a single program.
    pub fn link(&self, modules: &[&Module]) -> Result<Program> {
        if modules.is_empty() {
            return Err(VmError::InvalidArgument("no modules to link".to_string()));
        }

        // Phase 1: Calculate memory layout
        let (memory_size, layouts) = self.calculate_layout(modules)?;

        // Phase 2: Allocate memory and copy sections
        let mut memory = VmMemory::new(memory_size);
        self.copy_sections(modules, &layouts, &mut memory)?;

        // Phase 3: Build global symbol table
        let global_symbols = self.build_symbol_table(modules, &layouts)?;

        // Phase 4: Apply relocations
        self.apply_relocations(modules, &layouts, &global_symbols, &mut memory)?;

        // Phase 5: Apply CO-RE relocations
        self.apply_core_relocations(modules, &layouts, &mut memory)?;

        // Phase 6: Build function table
        let functions = self.build_function_table(modules, &layouts)?;

        // Calculate stack pointer (end of memory)
        let stack_top = memory_size as u64;

        Ok(Program::new(memory, functions, stack_top))
    }

    /// Calculate memory layout for all modules.
    fn calculate_layout(&self, modules: &[&Module]) -> Result<(usize, Vec<ModuleLayout>)> {
        const ALIGNMENT: usize = 8;
        let mut current_addr: usize = ALIGNMENT; // Start after null page
        let mut layouts = Vec::new();

        for module in modules {
            let mut layout = ModuleLayout {
                code_base: current_addr as u64,
                data_base: 0,
                section_addrs: HashMap::new(),
            };

            // First, lay out code sections
            for (idx, section) in module.sections.iter().enumerate() {
                if section.kind == SectionKind::Code {
                    // Align to section alignment
                    let align = section.align.max(1) as usize;
                    current_addr = (current_addr + align - 1) & !(align - 1);

                    layout.section_addrs.insert(idx, current_addr as u64);
                    current_addr += section.size as usize;
                }
            }

            // Then, lay out data sections
            layout.data_base = current_addr as u64;
            for (idx, section) in module.sections.iter().enumerate() {
                if section.is_allocatable() && section.kind != SectionKind::Code {
                    let align = section.align.max(1) as usize;
                    current_addr = (current_addr + align - 1) & !(align - 1);

                    layout.section_addrs.insert(idx, current_addr as u64);
                    current_addr += section.size as usize;
                }
            }

            layouts.push(layout);
        }

        // Add stack space at the end
        current_addr = (current_addr + ALIGNMENT - 1) & !(ALIGNMENT - 1);
        current_addr += self.config.stack_size;

        Ok((current_addr, layouts))
    }

    /// Copy section data into memory.
    fn copy_sections(&self, modules: &[&Module], layouts: &[ModuleLayout], memory: &mut VmMemory) -> Result<()> {
        for (module, layout) in modules.iter().zip(layouts.iter()) {
            for (idx, section) in module.sections.iter().enumerate() {
                if let Some(&vaddr) = layout.section_addrs.get(&idx) {
                    if !section.data.is_empty() {
                        memory
                            .write_bytes(vaddr as usize, &section.data)
                            .map_err(|e| VmError::Memory(e))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Build a global symbol table from all modules.
    fn build_symbol_table(&self, modules: &[&Module], layouts: &[ModuleLayout]) -> Result<HashMap<String, u64>> {
        let mut symbols = HashMap::new();

        for (module, layout) in modules.iter().zip(layouts.iter()) {
            for (name, export) in &module.exports {
                if let Some(&section_addr) = layout.section_addrs.get(&export.section_idx) {
                    let addr = section_addr + export.offset;

                    // Check for duplicates
                    if let Some(&existing) = symbols.get(name) {
                        if existing != addr {
                            return Err(LinkError::DuplicateSymbol(name.clone()).into());
                        }
                    }

                    symbols.insert(name.clone(), addr);
                }
            }
        }

        Ok(symbols)
    }

    /// Apply ELF relocations.
    fn apply_relocations(
        &self,
        modules: &[&Module],
        layouts: &[ModuleLayout],
        global_symbols: &HashMap<String, u64>,
        memory: &mut VmMemory,
    ) -> Result<()> {
        for (module, layout) in modules.iter().zip(layouts.iter()) {
            for reloc_entry in &module.relocations {
                self.apply_relocation(module, layout, global_symbols, reloc_entry, memory)?;
            }
        }
        Ok(())
    }

    /// Apply a single relocation.
    fn apply_relocation(
        &self,
        module: &Module,
        layout: &ModuleLayout,
        global_symbols: &HashMap<String, u64>,
        reloc: &Relocation,
        memory: &mut VmMemory,
    ) -> Result<()> {
        // Get the symbol being referenced
        let symbol = module
            .symbol_by_idx(reloc.symbol_idx)
            .ok_or_else(|| LinkError::InvalidReference(format!("symbol index {}", reloc.symbol_idx)))?;

        // Get the address where we're patching
        let section_addr = layout
            .section_addrs
            .get(&reloc.section_idx)
            .ok_or_else(|| LinkError::InvalidReference(format!("section index {}", reloc.section_idx)))?;
        let patch_addr = *section_addr + reloc.offset;

        // Calculate the symbol's resolved address
        let sym_addr = if symbol.is_defined() {
            // Symbol is defined in this module
            let sym_section_idx = symbol.section_idx.unwrap();
            let sym_section_addr = layout
                .section_addrs
                .get(&sym_section_idx)
                .ok_or_else(|| LinkError::InvalidReference(format!("symbol section {}", sym_section_idx)))?;
            *sym_section_addr + symbol.value
        } else if let Some(&addr) = global_symbols.get(&symbol.name) {
            // Symbol is defined in another module
            addr
        } else {
            // Symbol is not found - might be a helper call
            // For now, we'll skip and let the executor handle CallExt
            return Ok(());
        };

        // Apply based on relocation type
        match reloc.rel_type {
            reloc::bpf::BPF_64_64 => {
                // LD_IMM64 instruction: patch the imm32 fields of two instructions
                // First instruction: lower 32 bits at offset +4
                // Second instruction: upper 32 bits at offset +12
                let lo = (sym_addr as u32).to_le_bytes();
                let hi = ((sym_addr >> 32) as u32).to_le_bytes();

                memory
                    .write_bytes((patch_addr + 4) as usize, &lo)
                    .map_err(|e| VmError::Memory(e))?;
                memory
                    .write_bytes((patch_addr + 12) as usize, &hi)
                    .map_err(|e| VmError::Memory(e))?;
            }
            reloc::bpf::BPF_64_32 => {
                // 32-bit relative call - patch the imm32 field
                // This is typically used for BPF-to-BPF calls
                // The imm is a relative offset in instructions (not bytes)
                let call_addr = patch_addr; // Address of the call instruction
                let target_addr = sym_addr;

                // Calculate relative offset in instructions
                // call is at call_addr, next instruction is at call_addr + 8
                // target is at target_addr
                // relative offset = (target - (call + 8)) / 8
                let next_insn = call_addr + 8;
                let rel_offset = ((target_addr as i64 - next_insn as i64) / 8) as i32;

                let imm_bytes = rel_offset.to_le_bytes();
                memory
                    .write_bytes((patch_addr + 4) as usize, &imm_bytes)
                    .map_err(|e| VmError::Memory(e))?;
            }
            _ => {
                // Unknown relocation type - skip for now
            }
        }

        Ok(())
    }

    /// Apply CO-RE relocations.
    fn apply_core_relocations(
        &self,
        modules: &[&Module],
        layouts: &[ModuleLayout],
        memory: &mut VmMemory,
    ) -> Result<()> {
        for (module, layout) in modules.iter().zip(layouts.iter()) {
            // Skip if no BTF data
            let Some(btf_data) = &module.btf_data else {
                continue;
            };

            // Parse BTF
            let btf = match Btf::parse(btf_data) {
                Ok(b) => b,
                Err(_) => continue, // Skip if BTF parsing fails
            };

            // Parse BTF.ext for CO-RE relocations
            let Some(btf_ext_data) = &module.btf_ext_data else {
                continue;
            };

            let btf_ext = match btf::BtfExt::parse(btf_ext_data, btf.strings()) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Apply CO-RE relocations for each code section
            for section in module.code_sections() {
                let Some(&section_addr) = layout.section_addrs.get(&section.elf_index) else {
                    continue;
                };

                // Get relocations for this section
                let Some(relos) = btf_ext.relos_for_section(&section.name) else {
                    continue;
                };

                // Convert memory region to instruction slice
                let section_size = section.size as usize;
                if section_size == 0 || section_size % 8 != 0 {
                    continue;
                }

                let num_insns = section_size / 8;
                let mem_slice = memory
                    .bytes_mut(section_addr as usize, section_size)
                    .map_err(|e| VmError::Memory(e))?;

                // Convert to u64 slice for patching
                // Safety: We've verified alignment and size
                let insns: &mut [u64] =
                    unsafe { std::slice::from_raw_parts_mut(mem_slice.as_mut_ptr() as *mut u64, num_insns) };

                // Apply relocations
                let _ = apply_core_relocations(insns, &btf, self.types, relos);
            }
        }

        Ok(())
    }

    /// Build the function table.
    fn build_function_table(
        &self,
        modules: &[&Module],
        layouts: &[ModuleLayout],
    ) -> Result<HashMap<String, FunctionInfo>> {
        let mut functions = HashMap::new();

        for (module, layout) in modules.iter().zip(layouts.iter()) {
            for (name, export) in &module.exports {
                if !export.is_function {
                    continue;
                }

                let Some(&section_addr) = layout.section_addrs.get(&export.section_idx) else {
                    continue;
                };

                let addr = section_addr + export.offset;
                let pc = addr / 8; // Convert byte address to instruction index

                functions.insert(
                    name.clone(),
                    FunctionInfo {
                        name: name.clone(),
                        pc,
                        size: export.size,
                    },
                );
            }
        }

        // If no named functions, try to find entry points by section name
        if functions.is_empty() {
            for (module, layout) in modules.iter().zip(layouts.iter()) {
                for (idx, section) in module.sections.iter().enumerate() {
                    if section.kind == SectionKind::Code {
                        if let Some(&addr) = layout.section_addrs.get(&idx) {
                            let pc = addr / 8;
                            functions.insert(
                                section.name.clone(),
                                FunctionInfo {
                                    name: section.name.clone(),
                                    pc,
                                    size: section.size,
                                },
                            );
                        }
                    }
                }
            }
        }

        Ok(functions)
    }
}
