//! Symbols of a parsed eBPF module.

/// A symbol in an eBPF module.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    /// Index into [`Module::sections`](crate::Module::sections) of the section that defines the symbol; `None` for an
    /// undefined symbol.
    pub section_idx: Option<usize>,
    /// Byte offset within the section.
    pub value: u64,
}

/// A defined global symbol, which other modules can refer to by name.
#[derive(Debug, Clone)]
pub struct Export {
    /// Index into [`Module::sections`](crate::Module::sections) of the section that defines the symbol.
    pub section_idx: usize,
    /// Byte offset within the section.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    pub is_function: bool,
}
