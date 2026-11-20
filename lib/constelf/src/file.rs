use std::mem;

use crate::err::{ElfError, ErrHeader};
use crate::raw::Elf64Ehdr;
use crate::relocs::ElfRelocSections;
use crate::sections::ElfSections;
use crate::util::cast_slice;
use crate::{ensure, tryres, ElfResult};

/// A relocatable eBPF object, with its ELF header checked.
#[derive(Clone, Copy)]
pub struct ElfFile<'a>(&'a [u8]);

impl<'a> ElfFile<'a> {
    /// Checks that `data` starts with the ELF header of a relocatable 64-bit little-endian eBPF object. Sections,
    /// symbols and relocations are checked when they are read.
    pub const fn new(data: &'a [u8]) -> ElfResult<Self> {
        // `header` relies on this length check
        ensure!(ElfError::Header(ErrHeader::Size), data.len() >= mem::size_of::<Elf64Ehdr>());

        let file = ElfFile(data);
        tryres!(file.header().validate());
        Ok(file)
    }

    /// The whole file.
    pub const fn image(self) -> &'a [u8] {
        self.0
    }

    pub const fn header(self) -> &'a Elf64Ehdr {
        let (head, _) = self.0.split_at(mem::size_of::<Elf64Ehdr>());
        match cast_slice(head) {
            Some([ehdr]) => ehdr,
            _ => unreachable!(),
        }
    }

    pub const fn sections(self) -> ElfResult<ElfSections<'a>> {
        ElfSections::new(self)
    }

    /// The relocation sections, each with the section it applies to.
    pub const fn relocs(self) -> ElfResult<ElfRelocSections<'a>> {
        match self.sections() {
            Ok(sections) => Ok(ElfRelocSections::new(sections)),
            Err(e) => Err(e),
        }
    }
}

impl std::fmt::Debug for ElfFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElfFile").field("header", &self.header()).finish()
    }
}
