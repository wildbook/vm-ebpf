use std::mem;

use crate::file::ElfFile;
use crate::raw::{sht, Elf64Rel, Elf64Shdr};
use crate::sections::{ElfSection, ElfSections};
use crate::{err, tryres, ElfResult};

#[derive(Copy, Clone, Debug)]
pub enum ElfRelocsChunk<'a> {
    None,
    Elf64(&'a [Elf64Rel]),
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

            if src.sh_type != sht::REL {
                continue;
            }

            let Some(dst) = self.sects.header_by_index(src.sh_info as usize) else {
                panic!("todo: do we need to handle this or can we just `continue`?");
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
        if self.source.sh_type != sht::REL {
            return Err(err::ElfError::Unsupported);
        }

        let bytes = tryres!(self.sects.bytes(self.source));

        if bytes.len() % mem::size_of::<Elf64Rel>() != 0 {
            return Err(err::ElfError::InvalidData);
        }

        let ptr = bytes.as_ptr().cast::<Elf64Rel>();
        let len = bytes.len() / mem::size_of::<Elf64Rel>();

        let slc = unsafe { std::slice::from_raw_parts(ptr, len) };

        Ok(ElfRelocsChunk::Elf64(slc))
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

    pub const fn from_section(self, source: &'a Elf64Shdr) -> ElfResult<ElfRelocSection<'a>> {
        if source.sh_type != sht::REL {
            return Err(err::ElfError::Unsupported);
        }

        let sects = tryres!(self.0.sections());

        let Some(target) = sects.by_index(source.sh_info as usize) else {
            return Err(err::ElfError::InvalidData);
        };

        Ok(ElfRelocSection {
            sects,
            source,
            target: target.raw(),
        })
    }

    /// note: a section can have multiple relocation sections, this only returns the first one.
    pub const fn for_section(self, target: &'a Elf64Shdr) -> ElfResult<Option<ElfRelocSection<'a>>> {
        let sects = tryres!(self.0.sections());
        let heads = sects.headers();

        let mut i = 0;
        while i < heads.len() {
            let src = &heads[i];
            i += 1;

            if src.sh_type != sht::REL {
                continue;
            }

            let Some(tgt) = sects.by_index(src.sh_info as usize) else {
                return Err(err::ElfError::InvalidData);
            };

            if tgt.raw().sh_offset != target.sh_offset {
                continue;
            }

            return Ok(Some(ElfRelocSection {
                sects,
                source: src,
                target: tgt.raw(),
            }));
        }

        Ok(None)
    }

    pub const fn num_chunks(self) -> ElfResult<usize> {
        let sects = tryres!(self.0.sections());
        let heads = sects.headers();

        let mut out = 0;
        let mut i = 0;
        while i < heads.len() {
            if heads[i].sh_type == sht::REL {
                out += 1;
            }

            i += 1;
        }

        Ok(out)
    }

    /// Calling this function in a loop instead of `.chunks()` is expensive, but possible in `const` context.
    pub fn chunk_by_index(self, idx: usize) -> Option<ElfResult<ElfRelocSection<'a>>> {
        let sects = match self.0.sections() {
            Ok(res) => res,
            Err(e) => return Some(Err(e)),
        };

        let heads = sects.headers();

        let mut chunk_idx = 0;

        let mut i = 0;
        while i < heads.len() {
            let hdr = &heads[i];
            i += 1;

            if hdr.sh_type != sht::REL {
                continue;
            }

            if chunk_idx != idx {
                chunk_idx += 1;
                continue;
            }

            return Some(self.from_section(hdr));
        }

        None
    }
}
