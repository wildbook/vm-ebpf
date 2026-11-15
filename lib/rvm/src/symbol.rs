//! Symbol representation for eBPF programs.

use std::fmt;

/// Symbol binding (local, global, weak).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolBinding {
    /// Local symbol (not visible outside the module).
    Local,
    /// Global symbol (visible to other modules).
    Global,
    /// Weak symbol (can be overridden).
    Weak,
}

/// Symbol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// No type specified.
    None,
    /// Data object (variable, array, etc.).
    Object,
    /// Function.
    Function,
    /// Section.
    Section,
    /// File name.
    File,
}

/// A symbol in an eBPF module.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name.
    pub name: String,
    /// Symbol binding.
    pub binding: SymbolBinding,
    /// Symbol kind.
    pub kind: SymbolKind,
    /// Section index where the symbol is defined (None for undefined/external).
    pub section_idx: Option<usize>,
    /// Value (offset within section, or absolute address after linking).
    pub value: u64,
    /// Size of the symbol (for objects).
    pub size: u64,
}

impl Symbol {
    /// Create a new symbol.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            binding: SymbolBinding::Local,
            kind: SymbolKind::None,
            section_idx: None,
            value: 0,
            size: 0,
        }
    }

    /// Check if this symbol is defined (has a section).
    pub fn is_defined(&self) -> bool {
        self.section_idx.is_some()
    }

    /// Check if this symbol is undefined (external reference).
    pub fn is_undefined(&self) -> bool {
        self.section_idx.is_none() && self.binding == SymbolBinding::Global
    }

    /// Check if this symbol is exported (global and defined).
    pub fn is_export(&self) -> bool {
        self.binding == SymbolBinding::Global && self.is_defined()
    }
}

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let binding = match self.binding {
            SymbolBinding::Local => "local",
            SymbolBinding::Global => "global",
            SymbolBinding::Weak => "weak",
        };
        let kind = match self.kind {
            SymbolKind::None => "none",
            SymbolKind::Object => "object",
            SymbolKind::Function => "func",
            SymbolKind::Section => "section",
            SymbolKind::File => "file",
        };
        let section = match self.section_idx {
            Some(idx) => format!("sect[{idx}]"),
            None => "UND".to_string(),
        };
        let name = &self.name;
        let value = self.value;
        let size = self.size;
        write!(f, "{name} {binding} {kind} {section} value=0x{value:x} size={size}")
    }
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

impl Export {
    /// Create a new export.
    pub fn new(section_idx: usize, offset: u64) -> Self {
        Self {
            section_idx,
            offset,
            size: 0,
            is_function: false,
        }
    }

    /// Set the size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Mark as a function.
    pub fn as_function(mut self) -> Self {
        self.is_function = true;
        self
    }
}
