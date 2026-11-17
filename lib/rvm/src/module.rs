//! A parsed eBPF ELF file: its loadable sections, symbols, exports, imports and relocations, for the linker.

use std::ffi::CStr;

use constelf::err::ElfError;
use constelf::file::ElfFile;
use constelf::raw::{reloc, shf, sht, stb, stt};
use constelf::relocs::ElfRelocsChunk;
use hashbrown::HashMap;

use crate::error::{Result, VmError};
use crate::section::{section_kind_from_name, Section, SectionKind};
use crate::symbol::{Export, Symbol};

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
    /// Byte offset added to the symbol address. For REL relocations this is decoded from the instruction's `imm` at
    /// parse time.
    pub addend: i64,
}

/// A parsed eBPF ELF module.
#[derive(Debug, Default)]
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
}

impl Module {
    /// Parse a module from ELF bytes.
    pub fn from_elf(name: impl Into<String>, elf_bytes: &[u8]) -> Result<Self> {
        let name = name.into();
        let elf = ElfFile::new(elf_bytes).map_err(|e| VmError::Elf(format!("{e:?}")))?;

        let elf_sections = elf
            .sections()
            .map_err(|e| VmError::Elf(format!("failed to get sections: {e:?}")))?;

        let mut module = Self {
            name,
            ..Default::default()
        };

        // sections
        for (idx, header) in elf_sections.headers().iter().enumerate() {
            let section_name = elf_sections
                .name(header)
                .map_err(|e| VmError::Elf(format!("failed to get section name: {e:?}")))?;
            let name_str = section_name.to_str().unwrap_or("");

            let kind = if (header.sh_flags & shf::EXECINSTR as u64) != 0 {
                SectionKind::Code
            } else {
                section_kind_from_name(name_str)
            };

            match name_str {
                ".BTF" => {
                    if let Some(sect) = elf_sections.by_index(idx) {
                        module.btf_data = sect.bytes().ok().map(|b| b.to_vec());
                    }
                    continue;
                }
                ".BTF.ext" => {
                    if let Some(sect) = elf_sections.by_index(idx) {
                        module.btf_ext_data = sect.bytes().ok().map(|b| b.to_vec());
                    }
                    continue;
                }
                _ => {}
            }

            // clang emits `.jumptables` without SHF_ALLOC
            if (header.sh_flags & shf::ALLOC as u64) == 0 && kind != SectionKind::JumpTable {
                continue;
            }

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

        // symbols, indexed like the ELF symbol table
        let symtab = match elf_sections.symtab() {
            Ok(symtab) => Some(symtab),
            Err(ElfError::SectionMissing) => None,
            Err(e) => return Err(VmError::Elf(format!("failed to get symbols: {e:?}"))),
        };
        if let Some(symtab) = symtab {
            let strtab = elf_sections.sym_strtab().ok();

            for sym in symtab.iter() {
                let sym_name = match (sym.st_name != 0, strtab) {
                    (true, Some(strtab)) => get_string_from_table(strtab, sym.st_name as usize),
                    _ => String::new(),
                };

                if sym_name.is_empty() && sym.st_shndx == 0 {
                    // Keep a placeholder so `symbols` stays indexed by ELF symbol index.
                    module.symbols.push(Symbol {
                        name: String::new(),
                        section_idx: None,
                        value: 0,
                    });
                    continue;
                }

                // Weak binds like a local reference for export/import purposes.
                let is_global = sym.bind() == stb::GLOBAL;
                let is_function = sym.typ() == stt::FUNC;

                let section_idx = if sym.st_shndx == 0 {
                    None
                } else {
                    module
                        .sections
                        .iter()
                        .position(|s| s.elf_index == sym.st_shndx as usize)
                };

                match (is_global, section_idx) {
                    (true, Some(sect_idx)) => {
                        module.exports.insert(
                            sym_name.clone(),
                            Export {
                                section_idx: sect_idx,
                                offset: sym.st_value,
                                size: sym.st_size,
                                is_function,
                            },
                        );
                    }
                    (true, None) => module.imports.push(sym_name.clone()),
                    (false, _) => {}
                }

                module.symbols.push(Symbol {
                    name: sym_name,
                    section_idx,
                    value: sym.st_value,
                });
            }
        }

        // relocations
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

            let target_elf_idx = chunk.target_idx();
            let Some(section_idx) = module.sections.iter().position(|s| s.elf_index == target_elf_idx) else {
                continue; // relocations for sections that aren't loaded
            };

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
            }
        }

        Ok(module)
    }

    /// Get a symbol by name.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Get a symbol by index.
    pub fn symbol_by_idx(&self, idx: usize) -> Option<&Symbol> {
        self.symbols.get(idx)
    }
}

/// Extract a null-terminated string from a string table at the given offset.
fn get_string_from_table(table: &[u8], offset: usize) -> String {
    table
        .get(offset..)
        .and_then(|b| CStr::from_bytes_until_nul(b).ok())
        .map(|cstr| cstr.to_string_lossy().into_owned())
        .unwrap_or_default()
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
