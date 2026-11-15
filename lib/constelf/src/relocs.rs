use std::mem;

use crate::file::ElfFile;
use crate::raw::{sht, Elf64Rel, Elf64Rela, Elf64Shdr};
use crate::sections::{ElfSection, ElfSections};
use crate::{err, tryres, ElfResult};

#[derive(Copy, Clone, Debug)]
pub enum ElfRelocsChunk<'a> {
    Rel(&'a [Elf64Rel]),
    Rela(&'a [Elf64Rela]),
}

#[derive(Copy, Clone)]
pub struct ElfRelocSections<'a> {
    pub sects: ElfSections<'a>,
    pub index: usize,
}

impl<'a> ElfRelocSections<'a> {
    pub const fn into_next(mut self) -> (Self, Option<ElfRelocSection<'a>>) {
        loop {
            let Some(src) = self.sects.header_by_index(self.index) else {
                return (self, None);
            };

            self.index += 1;

            // Handle both REL and RELA section types
            if src.sh_type != sht::REL && src.sh_type != sht::RELA {
                continue;
            }

            let Some(dst) = self.sects.header_by_index(src.sh_info as usize) else {
                // Invalid sh_info reference - skip this relocation section
                continue;
            };

            let rel = ElfRelocSection {
                sects: self.sects,
                source: src,
                target: dst,
            };

            return (self, Some(rel));
        }
    }
}

impl<'a> Iterator for ElfRelocSections<'a> {
    type Item = ElfRelocSection<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (next, res) = self.into_next();
        *self = next;
        res
    }
}

#[derive(Copy, Clone)]
pub struct ElfRelocSection<'a> {
    sects: ElfSections<'a>,
    source: &'a Elf64Shdr,
    target: &'a Elf64Shdr,
}

impl<'a> std::fmt::Debug for ElfRelocSection<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElfRelocSection")
            .field("source", &self.source)
            .field("target", &self.target)
            .finish()
    }
}

impl<'a> ElfRelocSection<'a> {
    pub const fn source(self) -> ElfSection<'a> {
        ElfSection {
            all: self.sects,
            raw: self.source,
        }
    }

    pub const fn target(self) -> ElfSection<'a> {
        ElfSection {
            all: self.sects,
            raw: self.target,
        }
    }

    pub const fn target_idx(self) -> usize {
        self.source.sh_info as usize
    }

    pub const fn relocs(self) -> ElfResult<ElfRelocsChunk<'a>> {
        let bytes = tryres!(self.sects.bytes(self.source));

        match self.source.sh_type {
            sht::REL => {
                if bytes.len() % mem::size_of::<Elf64Rel>() != 0 {
                    return Err(err::ElfError::InvalidData);
                }

                let ptr = bytes.as_ptr().cast::<Elf64Rel>();
                let len = bytes.len() / mem::size_of::<Elf64Rel>();

                let slc = unsafe { std::slice::from_raw_parts(ptr, len) };

                Ok(ElfRelocsChunk::Rel(slc))
            }
            sht::RELA => {
                if bytes.len() % mem::size_of::<Elf64Rela>() != 0 {
                    return Err(err::ElfError::InvalidData);
                }

                let ptr = bytes.as_ptr().cast::<Elf64Rela>();
                let len = bytes.len() / mem::size_of::<Elf64Rela>();

                let slc = unsafe { std::slice::from_raw_parts(ptr, len) };

                Ok(ElfRelocsChunk::Rela(slc))
            }
            _ => Err(err::ElfError::Unsupported),
        }
    }
}

#[derive(Copy, Clone)]
pub struct ElfRelocs<'a>(pub ElfFile<'a>);

impl<'a> ElfRelocs<'a> {
    pub const fn iter(self) -> ElfResult<ElfRelocSections<'a>> {
        Ok(ElfRelocSections {
            sects: tryres!(self.0.sections()),
            index: 0,
        })
    }
}
