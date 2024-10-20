mod util;

pub mod err;
pub mod raw;

pub mod file;
pub mod macros;
pub mod relocs;
pub mod sections;
pub mod symtab;

pub type ElfResult<T = ()> = Result<T, err::ElfError>;
