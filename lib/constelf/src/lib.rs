//! A reader for relocatable eBPF ELF objects whose functions are `const fn`, so an object can be read at compile time.
//!
//! [`ElfFile::new`] checks the ELF header. From the file come its [sections](ElfFile::sections), with the symbol
//! table, and its [relocation sections](ElfFile::relocs). Every offset and length is checked against the file when it
//! is read, so no call panics on a malformed object. [`raw`] holds the ELF structs and constants.

mod err;
mod file;
mod macros;
mod relocs;
mod sections;
mod symtab;
mod util;

pub mod raw;

pub use err::ElfError;
pub use file::ElfFile;
pub(crate) use macros::{const_for, ensure, ensure_matches, tryopt, tryres};
pub use relocs::{ElfRelocSection, ElfRelocSections, ElfRelocs};
pub use sections::{ElfSection, ElfSections};
pub use symtab::ElfSymTab;
pub use util::cstr_at;

pub type ElfResult<T = ()> = Result<T, ElfError>;
