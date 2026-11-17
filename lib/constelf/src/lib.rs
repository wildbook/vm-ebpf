mod util;
pub use util::cstr_at;

pub mod err;
pub mod raw;

pub mod file;
mod macros;
pub(crate) use macros::{ensure, ensure_matches, tryopt, tryres};
pub mod relocs;
pub mod sections;
pub mod symtab;

pub type ElfResult<T = ()> = Result<T, err::ElfError>;
