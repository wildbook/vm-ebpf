//! A parsed eBPF ELF file: its loadable sections, symbols, exports, imports and relocations, for the linker.

use std::fmt;

use constelf::raw::{reloc, shf, sht, stb, stt};
use constelf::{cstr_at, ElfError, ElfFile, ElfRelocs, ElfSections};
use hashbrown::HashMap;

use crate::error::{LinkError, Result};
use crate::image::INSN_SIZE;
use crate::section::{section_kind_from_name, Section, SectionKind, LEGACY_MAPS_SECTION, MAPS_SECTION};
use crate::symbol::{Export, Symbol};

/// A parsed eBPF ELF module, for [`Vm::prepare_modules`](crate::Vm::prepare_modules) and
/// [`Vm::load_modules`](crate::Vm::load_modules). Its `Display` lists the sections, exports, imports and relocations.
#[derive(Debug, Default)]
pub struct Module {
    /// The allocated sections and `.jumptables`, in ELF order.
    pub(crate) sections: Vec<Section>,

    /// Indexed like the ELF symbol table.
    pub(crate) symbols: Vec<Symbol>,

    /// Defined global symbols by name.
    pub(crate) exports: HashMap<String, Export>,

    /// Names of undefined global symbols.
    pub(crate) imports: Vec<String>,

    pub(crate) relocations: Vec<Relocation>,

    /// Contents of `.BTF`.
    pub(crate) btf_data: Option<Vec<u8>>,

    /// Contents of `.BTF.ext`.
    pub(crate) btf_ext_data: Option<Vec<u8>>,
}

impl Module {
    /// Parse a module from ELF bytes.
    pub fn from_elf(elf_bytes: &[u8]) -> Result<Self> {
        let elf = ElfFile::new(elf_bytes)?;
        let elf_sections = elf.sections()?;

        let mut module = Self::default();
        module.parse_sections(elf_sections)?;
        module.parse_symbols(elf_sections)?;
        module.parse_relocations(elf)?;
        Ok(module)
    }

    /// The contents of the `.BTF` section, which [`BtfBuilder::append_btf`](crate::BtfBuilder::append_btf) takes.
    pub fn btf(&self) -> Option<&[u8]> {
        self.btf_data.as_deref()
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
            if name == ".debug_str" {
                check_compiler(sect.bytes()?)?;
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
        for chunk in elf.relocs()? {
            let Some(section_idx) = self.section_of(chunk.target_idx()) else {
                continue; // relocations for sections that aren't loaded
            };

            match chunk.relocs()? {
                ElfRelocs::Rel(relocs) => {
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
                ElfRelocs::Rela(relocs) => {
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

    /// The symbol at `idx` in the ELF symbol table.
    pub(crate) fn symbol_by_idx(&self, idx: usize) -> Option<&Symbol> {
        self.symbols.get(idx)
    }
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "sections:")?;
        for (idx, section) in self.sections.iter().enumerate() {
            writeln!(f, "  [{idx}] {section}")?;
        }

        writeln!(f, "exports:")?;
        let mut exports: Vec<_> = self.exports.iter().collect();
        exports.sort_unstable_by_key(|(name, _)| *name);
        for (name, export) in exports {
            let Export {
                section_idx, offset, ..
            } = export;
            let suffix = if export.is_function { " (func)" } else { "" };
            writeln!(f, "  {name} @ section[{section_idx}]+0x{offset:x}{suffix}")?;
        }

        writeln!(f, "imports:")?;
        for import in &self.imports {
            writeln!(f, "  {import}")?;
        }

        writeln!(f, "relocations:")?;
        for reloc in &self.relocations {
            let Relocation {
                section_idx,
                offset,
                rel_type,
                addend,
                ..
            } = reloc;
            let symbol = self.symbol_by_idx(reloc.symbol_idx).map_or("<unknown>", |s| &s.name);
            writeln!(f, "  type={rel_type} section[{section_idx}]+0x{offset:x} -> {symbol} (addend={addend})")?;
        }
        Ok(())
    }
}

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

/// The oldest clang whose calling convention rvm follows: it returns a struct of up to 16 bytes in r0 and r2, where
/// older versions return it through a pointer in r1.
const MIN_CLANG: u32 = 23;

/// Fails if `debug_str`, the NUL-terminated strings of the object's debug info, contains a producer string naming a
/// clang older than [`MIN_CLANG`] (`clang version 22.1.8 (...)`). Strings that look like file paths are skipped so a
/// directory name cannot trigger a false positive.
fn check_compiler(debug_str: &[u8]) -> Result<()> {
    const MARK: &[u8] = b"clang version ";

    for entry in debug_str.split(|&b| b == 0) {
        if entry.contains(&b'/') || entry.contains(&b'\\') {
            continue;
        }
        let Some(at) = entry.windows(MARK.len()).position(|window| window == MARK) else {
            continue;
        };
        let rest = &entry[at + MARK.len()..];
        let len = rest.iter().take_while(|b| b.is_ascii_digit() || **b == b'.').count();
        let version = String::from_utf8_lossy(&rest[..len]);
        let major = version.split('.').next().and_then(|major| major.parse::<u32>().ok());
        if major.is_some_and(|major| major < MIN_CLANG) {
            return Err(LinkError::UnsupportedCompiler(version.into_owned()).into());
        }
    }
    Ok(())
}
