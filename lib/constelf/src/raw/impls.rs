use crate::err::{ElfError, ErrHeader};
use crate::{ensure, ensure_matches, raw, tryres, ElfResult};

impl raw::Elf64Rel {
    pub const fn sym(self) -> u32 {
        (self.r_info >> 32) as u32
    }

    pub const fn typ(self) -> u32 {
        self.r_info as u32
    }
}

impl raw::ElfIdent {
    // TODO: Remove.
    pub const fn validate(&self) -> ElfResult {
        ensure_matches!(ElfError::Header(ErrHeader::Ident), &self.ei_magic, b"\x7fELF");
        ensure_matches!(ElfError::Header(ErrHeader::Ident), self.ei_class, raw::ELFCLASS64);
        ensure_matches!(ElfError::Header(ErrHeader::Ident), self.ei_data, raw::ELFDATA2LSB);
        ensure_matches!(ElfError::Header(ErrHeader::Ident), self.ei_version, raw::E_CURRENT);
        ensure_matches!(ElfError::Header(ErrHeader::Ident), self.ei_osabi, raw::ELFOSABI_NONE);
        ensure_matches!(ElfError::Header(ErrHeader::Ident), self.ei_abiverssion, 0);

        Ok(())
    }
}

impl raw::Elf64Ehdr {
    pub const fn validate(&self) -> ElfResult {
        tryres!(self.e_ident.validate());
        ensure!(ElfError::Header(ErrHeader::Header), self.e_type == raw::ET_REL);
        ensure!(ElfError::Header(ErrHeader::Header), self.e_machine == raw::EM_BPF);
        ensure!(ElfError::Header(ErrHeader::Header), self.e_version == raw::EV_CURRENT);

        Ok(())
    }
}
