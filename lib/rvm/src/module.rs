//! Module representation for eBPF programs.
//!
//! A module represents a single parsed ELF file with its sections, symbols,
//! imports, and exports. Modules are combined by the linker to create an
//! executable program.

use std::collections::HashMap;
use std::ffi::CStr;

use constelf::file::ElfFile;
use constelf::raw::{shf, sht, stb, stt};

use crate::error::{ElfError, Result};
use crate::section::{section_kind_from_name, Section, SectionKind};
use crate::symbol::{Export, Import, Symbol, SymbolBinding, SymbolKind};

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
    /// Addend (for RELA relocations).
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
    pub imports: Vec<Import>,

    /// Relocations.
    pub relocations: Vec<Relocation>,

    /// BTF data (if present).
    pub btf_data: Option<Vec<u8>>,

    /// BTF.ext data (if present).
    pub btf_ext_data: Option<Vec<u8>>,

    /// Map from section name to index.
    section_by_name: HashMap<String, usize>,

    /// Map from symbol name to index.
    symbol_by_name: HashMap<String, usize>,
}

impl Module {
    /// Create a new empty module.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sections: Vec::new(),
            symbols: Vec::new(),
            exports: HashMap::new(),
            imports: Vec::new(),
            relocations: Vec::new(),
            btf_data: None,
            btf_ext_data: None,
            section_by_name: HashMap::new(),
            symbol_by_name: HashMap::new(),
        }
    }

    /// Parse a module from ELF bytes.
    pub fn from_elf(name: impl Into<String>, elf_bytes: &[u8]) -> Result<Self> {
        let name = name.into();
        let elf = ElfFile::new(elf_bytes).map_err(|e| ElfError::InvalidFormat(format!("{:?}", e)))?;

        let elf_sections = elf
            .sections()
            .map_err(|e| ElfError::InvalidFormat(format!("failed to get sections: {:?}", e)))?;

        let mut module = Self::new(&name);

        // First pass: collect sections
        for (idx, header) in elf_sections.headers().iter().enumerate() {
            let section_name = elf_sections
                .name(header)
                .map_err(|e| ElfError::InvalidFormat(format!("failed to get section name: {:?}", e)))?;
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
                    if let Ok(bytes) = sect.bytes() {
                        module.btf_data = Some(bytes.to_vec());
                    }
                }
                continue;
            }
            if name_str == ".BTF.ext" {
                if let Some(sect) = elf_sections.by_index(idx) {
                    if let Ok(bytes) = sect.bytes() {
                        module.btf_ext_data = Some(bytes.to_vec());
                    }
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
                    .map_err(|e| ElfError::InvalidFormat(format!("failed to get section bytes: {:?}", e)))?
                    .to_vec()
            } else {
                Vec::new()
            };

            let section = Section::new(name_str, kind)
                .with_data(data)
                .with_size(header.sh_size)
                .with_align(header.sh_addralign.max(1))
                .with_elf_index(idx);

            let section_idx = module.sections.len();
            module.section_by_name.insert(name_str.to_string(), section_idx);
            module.sections.push(section);
        }

        // Second pass: collect symbols
        if let Ok(symtab) = elf_sections.symtab() {
            // Get symbol string table
            let strtab = elf_sections.sym_strtab().ok();

            for (sym_idx, sym) in symtab.iter().enumerate() {
                // Get symbol name from string table
                let sym_name = if sym.st_name != 0 {
                    if let Some(strtab) = strtab {
                        get_string_from_table(strtab, sym.st_name as usize)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                if sym_name.is_empty() && sym.st_shndx == 0 {
                    continue; // Skip null symbols
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

                let symbol = Symbol::new(&sym_name)
                    .with_binding(binding)
                    .with_kind(kind)
                    .with_value(sym.st_value)
                    .with_size(sym.st_size);

                let symbol = if let Some(idx) = section_idx {
                    symbol.with_section(idx)
                } else {
                    symbol
                };

                if !sym_name.is_empty() {
                    module.symbol_by_name.insert(sym_name.clone(), sym_idx);
                }

                // Track exports and imports
                if symbol.is_export() {
                    if let Some(sect_idx) = section_idx {
                        let export = Export::new(&sym_name, sect_idx, sym.st_value).with_size(sym.st_size);
                        let export = if kind == SymbolKind::Function {
                            export.as_function()
                        } else {
                            export
                        };
                        module.exports.insert(sym_name.clone(), export);
                    }
                } else if symbol.is_import() {
                    module.imports.push(Import::symbol(&sym_name));
                }

                module.symbols.push(symbol);
            }
        }

        // Third pass: collect relocations
        let mut reloc_iter = elf
            .relocs()
            .iter()
            .map_err(|e| ElfError::InvalidFormat(format!("failed to get relocations: {:?}", e)))?;

        loop {
            let (next, chunk) = reloc_iter.into_next();
            reloc_iter = next;

            let Some(chunk) = chunk else {
                break;
            };

            // Find the target section in our list
            let target_elf_idx = chunk.target_idx();
            let section_idx = match module.sections.iter().position(|s| s.elf_index == target_elf_idx) {
                Some(idx) => idx,
                None => continue, // Relocations for non-ALLOC sections
            };

            // Get relocations
            use constelf::relocs::ElfRelocsChunk;
            match chunk
                .relocs()
                .map_err(|e| ElfError::InvalidFormat(format!("failed to get relocs: {:?}", e)))?
            {
                ElfRelocsChunk::Rel(relocs) => {
                    for r in relocs {
                        module.relocations.push(Relocation {
                            section_idx,
                            offset: r.r_offset,
                            symbol_idx: r.sym() as usize,
                            rel_type: r.typ(),
                            addend: 0,
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

    /// Get a section by name.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.section_by_name.get(name).map(|&idx| &self.sections[idx])
    }

    /// Get a section by index.
    pub fn section_by_idx(&self, idx: usize) -> Option<&Section> {
        self.sections.get(idx)
    }

    /// Get a symbol by name.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbol_by_name.get(name).map(|&idx| &self.symbols[idx])
    }

    /// Get a symbol by index.
    pub fn symbol_by_idx(&self, idx: usize) -> Option<&Symbol> {
        self.symbols.get(idx)
    }

    /// Check if a symbol is exported.
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.contains_key(name)
    }

    /// Get an export by name.
    pub fn export(&self, name: &str) -> Option<&Export> {
        self.exports.get(name)
    }

    /// Get all code sections.
    pub fn code_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.kind == SectionKind::Code)
    }

    /// Get all data sections (including rodata and bss).
    pub fn data_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|s| s.is_allocatable() && !s.is_executable())
    }

    /// Get total size of allocatable sections.
    pub fn allocatable_size(&self) -> u64 {
        self.sections
            .iter()
            .filter(|s| s.is_allocatable())
            .map(|s| s.size)
            .sum()
    }

    /// Get function exports.
    pub fn function_exports(&self) -> impl Iterator<Item = (&String, &Export)> {
        self.exports.iter().filter(|(_, e)| e.is_function)
    }
}

impl std::fmt::Display for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Module: {}", self.name)?;
        writeln!(f, "  Sections: {}", self.sections.len())?;
        for section in &self.sections {
            writeln!(f, "    {}", section)?;
        }
        writeln!(f, "  Exports: {}", self.exports.len())?;
        for (name, export) in &self.exports {
            writeln!(
                f,
                "    {} @ section[{}]+0x{:x}{}",
                name,
                export.section_idx,
                export.offset,
                if export.is_function { " (func)" } else { "" }
            )?;
        }
        writeln!(f, "  Imports: {}", self.imports.len())?;
        for import in &self.imports {
            writeln!(f, "    {}", import.name)?;
        }
        writeln!(f, "  Relocations: {}", self.relocations.len())?;
        writeln!(f, "  BTF: {}", self.btf_data.as_ref().map(|d| d.len()).unwrap_or(0))?;
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
