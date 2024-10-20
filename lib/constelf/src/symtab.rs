// typedef struct {
// 	Elf64_Word	st_name;
// 	unsigned char	st_info;
// 	unsigned char	st_other;
// 	Elf64_Half	st_shndx;
// 	Elf64_Addr	st_value;
// 	Elf64_Xword	st_size;
// } Elf64_Sym;

use crate::raw::Elf64Sym;

#[derive(Debug, Copy, Clone)]
pub struct ElfSymTab<'a> {
    pub raw: &'a [Elf64Sym],
}

impl ElfSymTab<'_> {
    pub const fn new(raw: &[Elf64Sym]) -> ElfSymTab {
        ElfSymTab { raw }
    }

    pub const fn len(&self) -> usize {
        self.raw.len()
    }

    pub const fn get(&self, idx: usize) -> Option<&Elf64Sym> {
        match idx < self.len() {
            true => Some(&self.raw[idx]),
            false => None,
        }
    }
}
