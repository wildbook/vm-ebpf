use core::error::Error;
use core::fmt::{self, Display};

/// Why reading an ELF object failed.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// The file is shorter than an ELF header.
    TooShort,
    /// `e_ident` doesn't describe a 64-bit little-endian System V ELF file.
    BadIdent,
    /// `e_type`, `e_machine` or `e_version` don't describe a relocatable eBPF object.
    NotBpfObject,
    /// The section header table lies outside the file or has the wrong entry size.
    BadSectionTable,
    /// An offset or range points outside the file.
    OutOfBounds,
    /// The requested section doesn't exist.
    SectionMissing,
    /// A section's contents are malformed.
    InvalidData,
}

impl Error for ElfError {}

impl Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ElfError::TooShort => "file is shorter than an ELF header",
            ElfError::BadIdent => "not a 64-bit little-endian System V ELF file",
            ElfError::NotBpfObject => "not a relocatable eBPF object",
            ElfError::BadSectionTable => "section header table is out of bounds or has the wrong entry size",
            ElfError::OutOfBounds => "offset points outside the file",
            ElfError::SectionMissing => "section not found",
            ElfError::InvalidData => "malformed section contents",
        })
    }
}
