use core::error::Error;
use core::fmt::{self, Display};

#[derive(Debug, Copy, Clone)]
pub enum ErrHeader {
    Header, // ElfHeader field was invalid
    Ident,  // ElfIdent field was invalid

    Size,
    Other,
}

#[derive(Debug, Copy, Clone)]
pub enum ElfError {
    Header(ErrHeader),
    DeRvaBounds,
    SectionMissing,
    Sections,
    InvalidData,
    Unsupported,
}

impl Error for ElfError {}
impl Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::Header(e) => write!(f, "Header error: {:?}", e),
            ElfError::DeRvaBounds => write!(f, "DeRva out of bounds"),
            ElfError::SectionMissing => write!(f, "Section missing"),
            ElfError::Sections => write!(f, "Sections error"),
            ElfError::InvalidData => write!(f, "Invalid data"),
            ElfError::Unsupported => write!(f, "Unsupported"),
        }
    }
}
