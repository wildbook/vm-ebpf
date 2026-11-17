use core::error::Error;
use core::fmt::{self, Display};

/// Which part of the ELF header failed validation.
#[derive(Debug, Copy, Clone)]
pub enum ErrHeader {
    /// `e_type`, `e_machine` or `e_version` don't describe a relocatable eBPF object.
    Header,
    /// `e_ident` doesn't describe a 64-bit little-endian System V ELF file.
    Ident,
    /// The file is shorter than an ELF header.
    Size,
}

#[derive(Debug, Copy, Clone)]
pub enum ElfError {
    Header(ErrHeader),
    /// An offset or range points outside the file.
    DeRvaBounds,
    /// The requested section doesn't exist.
    SectionMissing,
    /// The section header table lies outside the file or has the wrong entry size.
    Sections,
    /// A section's contents are malformed.
    InvalidData,
    /// Relocations were requested from a section that is neither `SHT_REL` nor `SHT_RELA`.
    Unsupported,
}

impl Error for ElfError {}
impl Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::Header(ErrHeader::Header) => write!(f, "not a relocatable eBPF object"),
            ElfError::Header(ErrHeader::Ident) => write!(f, "not a 64-bit little-endian System V ELF file"),
            ElfError::Header(ErrHeader::Size) => write!(f, "file is shorter than an ELF header"),
            ElfError::DeRvaBounds => write!(f, "offset points outside the file"),
            ElfError::SectionMissing => write!(f, "section not found"),
            ElfError::Sections => write!(f, "section header table is out of bounds or has the wrong entry size"),
            ElfError::InvalidData => write!(f, "malformed section contents"),
            ElfError::Unsupported => write!(f, "section is not a relocation section"),
        }
    }
}
