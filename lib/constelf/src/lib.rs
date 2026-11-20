//! A reader for relocatable eBPF ELF objects whose functions are `const fn`, so an object can be read at compile time.
//!
//! [`file::ElfFile::new`] checks the ELF header. From the file come its [sections](file::ElfFile::sections), with the
//! symbol table, and its [relocation sections](file::ElfFile::relocs). Every offset and length is checked against the
//! file when it is read, so no call panics on a malformed object.

mod macros;
mod util;

pub mod err;
pub mod file;
pub mod raw;
pub mod relocs;
pub mod sections;
pub mod symtab;

pub(crate) use macros::{const_for, ensure, ensure_matches, tryopt, tryres};
pub use util::cstr_at;

pub type ElfResult<T = ()> = Result<T, err::ElfError>;
