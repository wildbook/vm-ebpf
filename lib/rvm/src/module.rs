//! A parsed eBPF ELF file: its loadable sections, symbols, exports, imports and relocations, for the linker.

use constelf::cstr_at;
use constelf::err::ElfError;
use constelf::file::ElfFile;
use constelf::raw::{reloc, shf, sht, stb, stt};
use constelf::relocs::ElfRelocsChunk;
use constelf::sections::ElfSections;
use hashbrown::HashMap;

use crate::error::{LinkError, Result};
use crate::image::INSN_SIZE;
use crate::section::{section_kind_from_name, Section, SectionKind, LEGACY_MAPS_SECTION, MAPS_SECTION};
use crate::symbol::{Export, Symbol};

/// A relocation in one of the module's sections.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Index into [`Module::sections`] of the section the relocation patches.
    pub section_idx: usize,
    /// Byte offset of the patch within that section.
    pub offset: u64,
    /// Index into [`Module::symbols`].
    pub symbol_idx: usize,
    /// `R_BPF_*` type.
    pub rel_type: u32,
    /// Byte offset added to the symbol address. For REL relocations this is decoded from the instruction's `imm` at
    /// parse time.
    pub addend: i64,
}

/// A parsed eBPF ELF module.
#[derive(Debug, Default)]
pub struct Module {
    /// The name given to [`Module::from_elf`].
    pub name: String,

    /// The allocated sections and `.jumptables`, in ELF order.
    pub sections: Vec<Section>,

    /// Indexed like the ELF symbol table.
    pub symbols: Vec<Symbol>,

    /// Defined global symbols by name.
    pub exports: HashMap<String, Export>,

    /// Names of undefined global symbols.
    pub imports: Vec<String>,

    pub relocations: Vec<Relocation>,

    /// Contents of `.BTF`.
    pub btf_data: Option<Vec<u8>>,

    /// Contents of `.BTF.ext`.
    pub btf_ext_data: Option<Vec<u8>>,
}

impl Module {
    /// Parse a module from ELF bytes.
    pub fn from_elf(name: impl Into<String>, elf_bytes: &[u8]) -> Result<Self> {
        let elf = ElfFile::new(elf_bytes)?;
        let elf_sections = elf.sections()?;

        let mut module = Self {
            name: name.into(),
            ..Default::default()
        };
        module.parse_sections(elf_sections)?;
        module.parse_symbols(elf_sections)?;
        module.parse_relocations(elf)?;
        Ok(module)
    }

    /// Collect the loadable sections and the raw BTF and BTF.ext blobs.
    fn parse_sections(&mut self, elf_sections: ElfSections<'_>) -> Result<()> {
        for (idx, sect) in elf_sections.iter().enumerate() {
            let name = sect.name()?.to_string_lossy();

            let btf = match &*name {
                ".BTF" => Some(&mut self.btf_data),
                ".BTF.ext" => Some(&mut self.btf_ext_data),
                _ => None,
            };
            if let Some(btf) = btf {
                *btf = Some(sect.bytes()?.to_vec());
                continue;
            }

            if name == LEGACY_MAPS_SECTION {
                let msg = format!("legacy `{LEGACY_MAPS_SECTION}` section; declare maps in `{MAPS_SECTION}` with BTF");
                return Err(LinkError::InvalidMap(msg).into());
            }

            let kind = if (sect.sh_flags & shf::EXECINSTR as u64) != 0 {
                SectionKind::Code
            } else {
                section_kind_from_name(&name)
            };
            // clang emits `.jumptables` without SHF_ALLOC
            if (sect.sh_flags & shf::ALLOC as u64) == 0 && kind != SectionKind::JumpTable {
                continue;
            }

            let data = if sect.sh_type == sht::NOBITS {
                Vec::new() // .bss has no data
            } else {
                sect.bytes()?.to_vec()
            };

            self.sections.push(Section {
                name: name.into_owned(),
                kind,
                data,
                size: sect.sh_size,
                align: sect.sh_addralign.max(1),
                elf_index: idx,
            });
        }
        Ok(())
    }

    /// Collect symbols, indexed like the ELF symbol table, and sort the globals into exports and imports.
    fn parse_symbols(&mut self, elf_sections: ElfSections<'_>) -> Result<()> {
        let symtab = match elf_sections.symtab() {
            Ok(symtab) => symtab,
            Err(ElfError::SectionMissing) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let strtab = elf_sections.sym_strtab().ok();

        for sym in symtab.iter() {
            let name = match (sym.st_name != 0, strtab) {
                (true, Some(strtab)) => cstr_at(strtab, sym.st_name as usize)
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                _ => String::new(),
            };

            if name.is_empty() && sym.st_shndx == 0 {
                // Keep a placeholder so `symbols` stays indexed by ELF symbol index.
                self.symbols.push(Symbol {
                    name,
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
                self.section_of(sym.st_shndx as usize)
            };

            match (is_global, section_idx) {
                (true, Some(sect_idx)) => {
                    self.exports.insert(
                        name.clone(),
                        Export {
                            section_idx: sect_idx,
                            offset: sym.st_value,
                            size: sym.st_size,
                            is_function,
                        },
                    );
                }
                (true, None) => self.imports.push(name.clone()),
                (false, _) => {}
            }

            self.symbols.push(Symbol {
                name,
                section_idx,
                value: sym.st_value,
            });
        }
        Ok(())
    }

    /// Collect relocations against loaded sections, decoding REL addends from the bytes they patch.
    fn parse_relocations(&mut self, elf: ElfFile<'_>) -> Result<()> {
        for chunk in elf.relocs().iter()? {
            let Some(section_idx) = self.section_of(chunk.target_idx()) else {
                continue; // relocations for sections that aren't loaded
            };

            match chunk.relocs()? {
                ElfRelocsChunk::Rel(relocs) => {
                    let data = &self.sections[section_idx].data;
                    for r in relocs {
                        let addend = rel_implicit_addend(data, r.r_offset, r.typ()).ok_or(ElfError::InvalidData)?;
                        self.relocations.push(Relocation {
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
                        self.relocations.push(Relocation {
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
        Ok(())
    }

    /// Index in `sections` of the loaded section with ELF section index `elf_index`.
    fn section_of(&self, elf_index: usize) -> Option<usize> {
        self.sections.iter().position(|s| s.elf_index == elf_index)
    }

    /// The first symbol called `name`.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// The symbol at `idx` in the ELF symbol table.
    pub fn symbol_by_idx(&self, idx: usize) -> Option<&Symbol> {
        self.symbols.get(idx)
    }
}

/// Byte addend that a REL relocation stores in the place it patches.
fn rel_implicit_addend(data: &[u8], offset: u64, typ: u32) -> Option<i64> {
    let at = usize::try_from(offset).ok()?;
    let imm = || data.get(at.checked_add(4)?..)?.first_chunk::<4>().copied();
    Some(match typ {
        // LD_IMM64: imm is a byte offset from the symbol.
        reloc::bpf::BPF_64_64 => i64::from(u32::from_le_bytes(imm()?)),
        // Call: target = sym + (imm + 1) instructions (named functions use imm = -1).
        reloc::bpf::BPF_64_32 => (i64::from(i32::from_le_bytes(imm()?)) + 1) * INSN_SIZE as i64,
        // A pointer in data: the stored 8 bytes are the offset from the symbol.
        reloc::bpf::BPF_64_ABS64 => i64::from_le_bytes(*data.get(at..)?.first_chunk::<8>()?),
        _ => 0,
    })
}
