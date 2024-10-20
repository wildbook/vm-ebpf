use std::mem;

use super::ElfResult;
use crate::err::{self, ElfError, ErrHeader};
use crate::raw::Elf64Ehdr;
use crate::relocs::ElfRelocs;
use crate::sections::ElfSections;
use crate::{ensure, relocs, tryres, util};

#[derive(Clone, Copy)]
pub struct ElfFile<'a>(&'a [u8]);

impl<'a> std::fmt::Debug for ElfFile<'a> {
    fn fmt(&self, fout: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fout.debug_struct("ElfFile") //
            .field("header", &self.header())
            .finish()
    }
}

impl ElfFile<'_> {
    pub const fn validate(&self) -> Result<(), err::ElfError> {
        ensure!(ElfError::Header(ErrHeader::Size), self.0.len() >= mem::size_of::<Elf64Ehdr>());
        tryres!(self.header().validate());
        Ok(())
    }

    /// SAFETY: This function is responsible for validating the data that is later treated as valid.
    /// If the structure is invalid and this function does not filter it out, later code may cause undefined behavior.
    pub const fn validated(self) -> ElfResult<Self> {
        tryres!(self.validate());
        Ok(self)
    }
}

impl<'a> ElfFile<'a> {
    pub const fn new(data: &'a [u8]) -> ElfResult<Self> {
        ElfFile(data).validated()
    }

    pub const fn image(self) -> &'a [u8] {
        self.0
    }

    pub const fn header(self) -> &'a Elf64Ehdr {
        unsafe { &*(self.image().as_ptr().cast::<Elf64Ehdr>()) }
    }

    pub const fn sections(self) -> ElfResult<ElfSections<'a>> {
        ElfSections::new(self, self.header())
    }

    pub const fn derva_slice(self, beg: usize, len: usize) -> ElfResult<&'a [u8]> {
        util::derva_slice(self.image(), beg, len)
    }

    pub const fn relocs(self) -> relocs::ElfRelocs<'a> {
        ElfRelocs(self)
    }
}
