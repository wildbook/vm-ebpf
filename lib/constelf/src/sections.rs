use std::ffi::CStr;
use std::mem;
use std::ops::Deref;

use super::file::ElfFile;
use super::ElfResult;
use crate::err::{self, ElfError};
use crate::raw::{self, Elf64Ehdr, Elf64Shdr};
use crate::symtab::ElfSymTab;
use crate::{const_for, ensure, tryopt, tryres, util};

#[derive(Copy, Clone)]
pub struct ElfSections<'a> {
    file: ElfFile<'a>,
    headers: &'a [Elf64Shdr],
}

#[derive(Copy, Clone)]
pub struct ElfSection<'a> {
    pub all: ElfSections<'a>,
    pub raw: &'a Elf64Shdr,
}

impl<'a> std::fmt::Debug for ElfSection<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ElfSection") //
            .field(self.raw())
            .finish()
    }
}

impl<'a> ElfSection<'a> {
    pub const fn name(self) -> ElfResult<&'a CStr> {
        self.all.name(self.raw)
    }

    pub const fn bytes(self) -> ElfResult<&'a [u8]> {
        self.all.bytes(self.raw)
    }

    pub const fn raw(self) -> &'a Elf64Shdr {
        self.raw
    }
}

impl<'a> Deref for ElfSection<'a> {
    type Target = Elf64Shdr;

    fn deref(&self) -> &'a Self::Target {
        self.raw()
    }
}

impl<'a> ElfSections<'a> {
    pub const fn new(file: ElfFile<'a>, ehdr: &'a Elf64Ehdr) -> ElfResult<Self> {
        ensure!(ElfError::Sections, ehdr.e_shentsize as usize == mem::size_of::<Elf64Shdr>());

        let len = ehdr.e_shentsize as usize * ehdr.e_shnum as usize;
        let Ok(bytes) = util::derva_slice(file.image(), ehdr.e_shoff as usize, len) else {
            return Err(ElfError::Sections);
        };
        let Some(headers) = util::cast_slice(bytes) else {
            return Err(ElfError::Sections);
        };

        Ok(Self { file, headers })
    }

    pub const fn headers(self) -> &'a [Elf64Shdr] {
        self.headers
    }

    pub const fn header_by_index(self, index: usize) -> Option<&'a Elf64Shdr> {
        let slice = self.headers();
        if index < slice.len() {
            Some(&slice[index])
        } else {
            None
        }
    }

    pub const fn by_index(self, index: usize) -> Option<ElfSection<'a>> {
        Some(ElfSection {
            all: self,
            raw: tryopt!(self.header_by_index(index)),
        })
    }

    pub const fn symtab(self) -> ElfResult<ElfSymTab<'a>> {
        const_for!(header in &self.headers() => {
            if header.sh_type == raw::sht::SYMTAB {
                let bytes = tryres!(self.bytes(header));
                let Some(raw) = util::cast_slice(bytes) else {
                    return Err(ElfError::InvalidData);
                };

                return Ok(ElfSymTab { raw });
            }
        });

        Err(err::ElfError::SectionMissing)
    }

    pub const fn bytes(self, header: &Elf64Shdr) -> ElfResult<&'a [u8]> {
        let beg = header.sh_offset as usize;
        let len = header.sh_size as usize;
        util::derva_slice(self.file.image(), beg, len)
    }

    pub const fn name(self, header: &Elf64Shdr) -> ElfResult<&'a CStr> {
        let Some(nsect) = self.header_by_index(self.file.header().e_shstrndx as usize) else {
            return Err(ElfError::SectionMissing);
        };

        let ndata = tryres!(self.bytes(nsect));
        match util::cstr_at(ndata, header.sh_name as usize) {
            Some(name) => Ok(name),
            None => Err(ElfError::InvalidData),
        }
    }

    pub fn iter(self) -> impl Iterator<Item = ElfSection<'a>> {
        self.headers().iter().map(move |raw| ElfSection { all: self, raw })
    }

    /// Get the symbol string table (.strtab section).
    pub const fn sym_strtab(self) -> ElfResult<&'a [u8]> {
        const_for!(header in &self.headers() => {
            if header.sh_type == raw::sht::STRTAB {
                if let Ok(name) = self.name(header) {
                    if util::slice_eq(name.to_bytes(), b".strtab") {
                        return self.bytes(header);
                    }
                }
            }
        });

        Err(err::ElfError::SectionMissing)
    }
}
