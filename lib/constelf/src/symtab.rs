use crate::raw::Elf64Sym;

#[derive(Debug, Copy, Clone)]
pub struct ElfSymTab<'a> {
    pub raw: &'a [Elf64Sym],
}

impl ElfSymTab<'_> {
    pub fn iter(&self) -> impl Iterator<Item = &Elf64Sym> {
        self.raw.iter()
    }
}
