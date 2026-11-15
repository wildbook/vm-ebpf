//! Symbol representation for eBPF programs.

/// A symbol in an eBPF module.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name.
    pub name: String,
    /// Section index where the symbol is defined (None for undefined/external).
    pub section_idx: Option<usize>,
    /// Value (offset within section, or absolute address after linking).
    pub value: u64,
}

/// An export (defined symbol that can be referenced by other modules).
#[derive(Debug, Clone)]
pub struct Export {
    /// Section index where the symbol is defined.
    pub section_idx: usize,
    /// Offset within the section.
    pub offset: u64,
    /// Size of the symbol.
    pub size: u64,
    /// Whether this is a function.
    pub is_function: bool,
}
