//! Module representation for eBPF programs.
//!
//! A module represents a single parsed ELF file with its sections, symbols,
//! imports, and exports. Modules are combined by the linker to create an
//! executable program.

use std::ffi::CStr;

use constelf::file::ElfFile;
use constelf::raw::{reloc, shf, sht, stb, stt};
use hashbrown::HashMap;

use crate::error::{Result, VmError};
use crate::section::{section_kind_from_name, Section, SectionKind};
use crate::symbol::{Export, Symbol, SymbolBinding, SymbolKind};

/// Relocation entry for a module.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Section index being relocated.
    pub section_idx: usize,
    /// Offset within the section.
    pub offset: u64,
    /// Symbol index this relocation references.
    pub symbol_idx: usize,
    /// Relocation type.
    pub rel_type: u32,
    /// Byte offset added to the symbol address. For REL relocations this is
    /// decoded from the instruction's `imm` at parse time.
    pub addend: i64,
}

/// A parsed eBPF ELF module.
#[derive(Debug)]
pub struct Module {
    /// Module name (user-provided or derived from file).
    pub name: String,

    /// All sections in the module.
    pub sections: Vec<Section>,

    /// All symbols in the module.
    pub symbols: Vec<Symbol>,

    /// Exports (defined global symbols).
    pub exports: HashMap<String, Export>,

    /// Imports (undefined global symbols).
    pub imports: Vec<String>,

    /// Relocations.
    pub relocations: Vec<Relocation>,

    /// BTF data (if present).
    pub btf_data: Option<Vec<u8>>,

    /// BTF.ext data (if present).
    pub btf_ext_data: Option<Vec<u8>>,

    /// Map from symbol name to index.
    symbol_by_name: HashMap<String, usize>,
}

impl Module {
    /// Create a new empty module.
    fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sections: Vec::new(),
            symbols: Vec::new(),
            exports: HashMap::new(),
            imports: Vec::new(),
            relocations: Vec::new(),
            btf_data: None,
            btf_ext_data: None,
            symbol_by_name: HashMap::new(),
        }
    }

    /// Parse a module from ELF bytes.
    pub fn from_elf(name: impl Into<String>, elf_bytes: &[u8]) -> Result<Self> {
        let name = name.into();
        let elf = ElfFile::new(elf_bytes).map_err(|e| VmError::Elf(format!("{e:?}")))?;

        let elf_sections = elf
            .sections()
            .map_err(|e| VmError::Elf(format!("failed to get sections: {e:?}")))?;

        let mut module = Self::new(&name);

        // First pass: collect sections
        for (idx, header) in elf_sections.headers().iter().enumerate() {
            let section_name = elf_sections
                .name(header)
                .map_err(|e| VmError::Elf(format!("failed to get section name: {e:?}")))?;
            let name_str = section_name.to_str().unwrap_or("");

            // Determine section kind
            let kind = if (header.sh_flags & shf::EXECINSTR as u64) != 0 {
                SectionKind::Code
            } else {
                section_kind_from_name(name_str)
            };

            // Handle BTF sections specially
            if name_str == ".BTF" {
                if let Some(sect) = elf_sections.by_index(idx) {
                    module.btf_data = sect.bytes().ok().map(|b| b.to_vec());
                }
                continue;
            }
            if name_str == ".BTF.ext" {
                if let Some(sect) = elf_sections.by_index(idx) {
                    module.btf_ext_data = sect.bytes().ok().map(|b| b.to_vec());
                }
                continue;
            }

            // Skip non-ALLOC sections (except we already handled BTF)
            if (header.sh_flags & shf::ALLOC as u64) == 0 {
                continue;
            }

            // Get section data
            let data = if header.sh_type == sht::NOBITS {
                Vec::new() // .bss has no data
            } else if let Some(sect) = elf_sections.by_index(idx) {
                sect.bytes()
                    .map_err(|e| VmError::Elf(format!("failed to get section bytes: {e:?}")))?
                    .to_vec()
            } else {
                Vec::new()
            };

            let section = Section {
                name: name_str.to_string(),
                kind,
                data,
                size: header.sh_size,
                align: header.sh_addralign.max(1),
                elf_index: idx,
            };

            module.sections.push(section);
        }

        // Second pass: collect symbols
        if let Ok(symtab) = elf_sections.symtab() {
            // Get symbol string table
            let strtab = elf_sections.sym_strtab().ok();

            for (sym_idx, sym) in symtab.iter().enumerate() {
                // Get symbol name from string table
                let sym_name = match (sym.st_name != 0, strtab) {
                    (true, Some(strtab)) => get_string_from_table(strtab, sym.st_name as usize),
                    _ => String::new(),
                };

                if sym_name.is_empty() && sym.st_shndx == 0 {
                    // Keep a placeholder so `symbols` stays indexed by ELF symbol index.
                    module.symbols.push(Symbol::new(""));
                    continue;
                }

                let binding = match sym.bind() {
                    b if b == stb::LOCAL => SymbolBinding::Local,
                    b if b == stb::GLOBAL => SymbolBinding::Global,
                    b if b == stb::WEAK => SymbolBinding::Weak,
                    _ => SymbolBinding::Local,
                };

                let kind = match sym.typ() {
                    t if t == stt::NOTYPE => SymbolKind::None,
                    t if t == stt::OBJECT => SymbolKind::Object,
                    t if t == stt::FUNC => SymbolKind::Function,
                    t if t == stt::SECTION => SymbolKind::Section,
                    t if t == stt::FILE => SymbolKind::File,
                    _ => SymbolKind::None,
                };

                // Map ELF section index to our section index
                let section_idx = if sym.st_shndx == 0 {
                    None // Undefined
                } else {
                    // Find the section by its ELF index
                    module
                        .sections
                        .iter()
                        .position(|s| s.elf_index == sym.st_shndx as usize)
                };

                let symbol = Symbol {
                    name: sym_name.clone(),
                    binding,
                    kind,
                    section_idx,
                    value: sym.st_value,
                    size: sym.st_size,
                };

                if !sym_name.is_empty() {
                    module.symbol_by_name.insert(sym_name.clone(), sym_idx);
                }

                // Track exports and imports
                if symbol.is_export() {
                    if let Some(sect_idx) = section_idx {
                        let export = Export::new(sect_idx, sym.st_value).with_size(sym.st_size);
                        let export = if kind == SymbolKind::Function {
                            export.as_function()
                        } else {
                            export
                        };
                        module.exports.insert(sym_name.clone(), export);
                    }
                } else if symbol.is_undefined() {
                    module.imports.push(sym_name.clone());
                }

                module.symbols.push(symbol);
            }
        }

        // Third pass: collect relocations
        let mut reloc_iter = elf
            .relocs()
            .iter()
            .map_err(|e| VmError::Elf(format!("failed to get relocations: {e:?}")))?;

        loop {
            let (next, chunk) = reloc_iter.into_next();
            reloc_iter = next;

            let Some(chunk) = chunk else {
                break;
            };

            // Find the target section in our list
            let target_elf_idx = chunk.target_idx();
            let Some(section_idx) = module.sections.iter().position(|s| s.elf_index == target_elf_idx) else {
                continue; // Relocations for non-ALLOC sections
            };

            // Get relocations
            use constelf::relocs::ElfRelocsChunk;
            match chunk
                .relocs()
                .map_err(|e| VmError::Elf(format!("failed to get relocs: {e:?}")))?
            {
                ElfRelocsChunk::Rel(relocs) => {
                    let data = &module.sections[section_idx].data;
                    for r in relocs {
                        let addend = rel_implicit_addend(data, r.r_offset, r.typ()).ok_or_else(|| {
                            let off = r.r_offset;
                            VmError::Elf(format!("relocation offset {off:#x} out of bounds"))
                        })?;
                        module.relocations.push(Relocation {
                            section_idx,
                            offset: r.r_offset,
                            symbol_idx: r.sym() as usize,
                            rel_type: r.typ(),
                            addend,
                        });
                    }
                }
                ElfRelocsChunk::Rela(relocs) => {
                    for r in relocs {
                        module.relocations.push(Relocation {
                            section_idx,
                            offset: r.r_offset,
                            symbol_idx: r.sym() as usize,
                            rel_type: r.typ(),
                            addend: r.r_addend,
                        });
                    }
                }
                ElfRelocsChunk::None => continue,
            }
        }

        Ok(module)
    }

    /// Get a symbol by name.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbol_by_name.get(name).map(|&idx| &self.symbols[idx])
    }

    /// Get a symbol by index.
    pub fn symbol_by_idx(&self, idx: usize) -> Option<&Symbol> {
        self.symbols.get(idx)
    }
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let module_name = &self.name;
        let section_count = self.sections.len();
        writeln!(f, "Module: {module_name}")?;
        writeln!(f, "  Sections: {section_count}")?;
        for section in &self.sections {
            writeln!(f, "    {section}")?;
        }
        let export_count = self.exports.len();
        writeln!(f, "  Exports: {export_count}")?;
        for (name, export) in &self.exports {
            let section_idx = export.section_idx;
            let offset = export.offset;
            let suffix = if export.is_function { " (func)" } else { "" };
            writeln!(f, "    {name} @ section[{section_idx}]+0x{offset:x}{suffix}")?;
        }
        let import_count = self.imports.len();
        writeln!(f, "  Imports: {import_count}")?;
        for name in &self.imports {
            writeln!(f, "    {name}")?;
        }
        let relo_count = self.relocations.len();
        let btf_size = self.btf_data.as_ref().map(|d| d.len()).unwrap_or(0);
        writeln!(f, "  Relocations: {relo_count}")?;
        writeln!(f, "  BTF: {btf_size}")?;
        Ok(())
    }
}

/// Extract a null-terminated string from a string table at the given offset.
fn get_string_from_table(table: &[u8], offset: usize) -> String {
    if offset >= table.len() {
        return String::new();
    }

    match CStr::from_bytes_until_nul(&table[offset..]) {
        Ok(cstr) => cstr.to_string_lossy().into_owned(),
        Err(_) => String::new(),
    }
}

/// Byte addend that a REL relocation stores in the place it patches.
fn rel_implicit_addend(data: &[u8], offset: u64, typ: u32) -> Option<i64> {
    let at = usize::try_from(offset).ok()?;
    let bytes = |skip: usize, len: usize| data.get(at.checked_add(skip)?..)?.get(..len);
    Some(match typ {
        // LD_IMM64: imm is a byte offset from the symbol.
        reloc::bpf::BPF_64_64 => i64::from(u32::from_le_bytes(bytes(4, 4)?.try_into().ok()?)),
        // Call: target = sym + (imm + 1) instructions (named functions use imm = -1).
        reloc::bpf::BPF_64_32 => (i64::from(i32::from_le_bytes(bytes(4, 4)?.try_into().ok()?)) + 1) * 8,
        // A pointer in data: the stored 8 bytes are the offset from the symbol.
        reloc::bpf::BPF_64_ABS64 => i64::from_le_bytes(bytes(0, 8)?.try_into().ok()?),
        _ => 0,
    })
}
