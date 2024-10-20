use std::ffi::CStr;
use std::mem;
use std::ops::Deref;

use super::file::ElfFile;
use super::ElfResult;
use crate::err::{self, ElfError};
use crate::raw::{self, Elf64Ehdr, Elf64Shdr, Elf64Sym};
use crate::symtab::ElfSymTab;
use crate::{ensure, tryopt, tryres, util};

#[derive(Copy, Clone)]
pub struct ElfSections<'a> {
    file: ElfFile<'a>,
    ehdr: &'a Elf64Ehdr,
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
    #[rustfmt::skip]
    pub const fn new(file: ElfFile<'a>, ehdr: &'a Elf64Ehdr) -> ElfResult<Self> {
        ensure!(ElfError::Sections, ehdr.e_shoff as usize <= file.image().len());
        ensure!(ElfError::Sections, ehdr.e_shoff as usize + ehdr.e_shentssize as usize * ehdr.e_shnum as usize <= file.image().len());
        ensure!(ElfError::Sections, ehdr.e_shentssize as usize == mem::size_of::<Elf64Shdr>());

        Ok(Self { file, ehdr })
    }
}

impl<'a> ElfSections<'a> {
    pub const fn len(self) -> usize {
        self.ehdr.e_shnum as usize
    }

    pub const fn headers(self) -> &'a [Elf64Shdr] {
        let beg = self.ehdr.e_shoff as usize;
        let len = self.ehdr.e_shnum as usize;
        let ptr = unsafe { self.file.image().as_ptr().add(beg).cast() };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub const fn header_by_index(self, index: usize) -> Option<&'a Elf64Shdr> {
        let slice: &[Elf64Shdr] = self.headers();
        match index < slice.len() {
            true => Some(&slice[index]),
            false => None,
        }
    }

    pub const fn by_index(self, index: usize) -> Option<ElfSection<'a>> {
        Some(ElfSection {
            all: self,
            raw: tryopt!(self.header_by_index(index)),
        })
    }

    pub const fn by_name(self, name: &[u8]) -> Option<ElfSection<'a>> {
        let headers = self.headers();

        let mut i = 0;
        while i < headers.len() {
            let header = &headers[i];
            i += 1;

            if let Ok(snm) = self.name(header) {
                if util::slice_eq(snm.to_bytes(), name) {
                    return Some(ElfSection { all: self, raw: header });
                }
            }
        }

        None
    }

    pub const fn string_table(self) -> ElfResult<&'a [u8]> {
        match self.header_by_index(self.ehdr.e_shstrndx as usize) {
            Some(sect) => self.bytes(sect),
            None => Err(err::ElfError::Sections),
        }
    }

    pub const fn symtab(self) -> ElfResult<ElfSymTab<'a>> {
        let headers = self.headers();

        let mut i = 0;
        while i < headers.len() {
            let header = &headers[i];
            i += 1;

            if header.sh_type == raw::sht::SYMTAB {
                let bytes = tryres!(self.bytes(header));
                assert!(bytes.len() % mem::size_of::<Elf64Sym>() == 0);
                // assert!(bytes.as_ptr().is_aligned_to(align_of::<Elf64Sym>()));

                let ptr = bytes.as_ptr().cast::<Elf64Sym>();
                let len = bytes.len() / mem::size_of::<Elf64Sym>();
                let raw = unsafe { std::slice::from_raw_parts(ptr, len) };

                return Ok(ElfSymTab { raw });
            }
        }

        Err(err::ElfError::SectionMissing)
    }

    pub const fn bytes(self, header: &Elf64Shdr) -> ElfResult<&'a [u8]> {
        let beg = header.sh_offset as usize;
        let len = header.sh_size as usize;
        util::derva_slice(self.file.image(), beg, len)
    }

    pub const fn name(self, header: &Elf64Shdr) -> ElfResult<&'a CStr> {
        let nsect = match self.header_by_index(self.file.header().e_shstrndx as usize) {
            Some(nsect) => nsect,
            None => return Err(err::ElfError::SectionMissing),
        };

        let ndata = tryres!(self.bytes(nsect));
        let ndata = match util::slice_from(ndata, header.sh_name as usize) {
            Some(ndata) => ndata,
            None => return Err(err::ElfError::InvalidData),
        };

        match CStr::from_bytes_until_nul(ndata) {
            Ok(name) => Ok(name),
            Err(_) => Err(err::ElfError::InvalidData),
        }
    }

    pub fn iter(self) -> impl Iterator<Item = ElfSection<'a>> {
        self.headers().iter().map(move |raw| ElfSection { all: self, raw })
    }
}
