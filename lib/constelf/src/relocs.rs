use crate::err::ElfError;
use crate::raw::{sht, Elf64Rel, Elf64Rela, Elf64Shdr};
use crate::sections::{ElfSection, ElfSections};
use crate::util::cast_slice;
use crate::{tryres, ElfResult};

/// Iterator over the `SHT_REL` and `SHT_RELA` sections of a file.
#[derive(Copy, Clone)]
pub struct ElfRelocSections<'a> {
    sects: ElfSections<'a>,
    index: usize,
}

impl<'a> ElfRelocSections<'a> {
    pub(crate) const fn new(sects: ElfSections<'a>) -> Self {
        Self { sects, index: 0 }
    }

    /// [`Iterator::next`] for const contexts: the iterator past the next relocation section, and that section.
    pub const fn into_next(mut self) -> (Self, Option<ElfRelocSection<'a>>) {
        loop {
            let Some(source) = self.sects.header_by_index(self.index) else {
                return (self, None);
            };
            self.index += 1;

            if source.sh_type != sht::REL && source.sh_type != sht::RELA {
                continue;
            }
            // a relocation section whose `sh_info` names no section is skipped
            let Some(target) = self.sects.header_by_index(source.sh_info as usize) else {
                continue;
            };

            let section = ElfRelocSection {
                sects: self.sects,
                source,
                target,
            };
            return (self, Some(section));
        }
    }
}

impl<'a> Iterator for ElfRelocSections<'a> {
    type Item = ElfRelocSection<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (next, section) = self.into_next();
        *self = next;
        section
    }
}

/// A relocation section (`source`) and the section its relocations apply to (`target`).
#[derive(Copy, Clone)]
pub struct ElfRelocSection<'a> {
    sects: ElfSections<'a>,
    source: &'a Elf64Shdr,
    target: &'a Elf64Shdr,
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

    /// Section index of [`target`](Self::target).
    pub const fn target_idx(self) -> usize {
        self.source.sh_info as usize
    }

    pub const fn relocs(self) -> ElfResult<ElfRelocsChunk<'a>> {
        let bytes = tryres!(self.sects.bytes(self.source));

        let chunk = match self.source.sh_type {
            sht::REL => match cast_slice(bytes) {
                Some(rel) => ElfRelocsChunk::Rel(rel),
                None => return Err(ElfError::InvalidData),
            },
            sht::RELA => match cast_slice(bytes) {
                Some(rela) => ElfRelocsChunk::Rela(rela),
                None => return Err(ElfError::InvalidData),
            },
            _ => unreachable!(), // `into_next` yields only these two types
        };

        Ok(chunk)
    }
}

impl std::fmt::Debug for ElfRelocSection<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElfRelocSection")
            .field("source", &self.source)
            .field("target", &self.target)
            .finish()
    }
}

/// The entries of one relocation section.
#[derive(Copy, Clone, Debug)]
pub enum ElfRelocsChunk<'a> {
    Rel(&'a [Elf64Rel]),
    Rela(&'a [Elf64Rela]),
}
