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

    /// Check if this symbol is a function.
    pub fn is_function(&self) -> bool {
        self.kind == SymbolKind::Function
    }

    /// Check if this symbol is exported (global and defined).
    pub fn is_export(&self) -> bool {
        self.binding == SymbolBinding::Global && self.is_defined()
    }

    /// Check if this symbol is an import (global and undefined).
    pub fn is_import(&self) -> bool {
        self.binding == SymbolBinding::Global && self.is_undefined()
    }

    /// Set the binding.
    pub fn with_binding(mut self, binding: SymbolBinding) -> Self {
        self.binding = binding;
        self
    }

    /// Set the kind.
    pub fn with_kind(mut self, kind: SymbolKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the section index.
    pub fn with_section(mut self, section_idx: usize) -> Self {
        self.section_idx = Some(section_idx);
        self
    }

    /// Set the value.
    pub fn with_value(mut self, value: u64) -> Self {
        self.value = value;
        self
    }

    /// Set the size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
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
            Some(idx) => format!("sect[{}]", idx),
            None => "UND".to_string(),
        };
        write!(f, "{} {} {} {} value=0x{:x} size={}", self.name, binding, kind, section, self.value, self.size)
    }
}

/// An import reference (undefined symbol that needs resolution).
#[derive(Debug, Clone)]
pub struct Import {
    /// Name of the imported symbol.
    pub name: String,
    /// Whether this is a helper function call (by ID).
    pub is_helper: bool,
    /// Helper ID (if is_helper is true).
    pub helper_id: Option<u32>,
}

impl Import {
    /// Create a new symbol import.
    pub fn symbol(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            is_helper: false,
            helper_id: None,
        }
    }

    /// Create a new helper function import.
    pub fn helper(id: u32) -> Self {
        Self {
            name: format!("__helper_{}", id),
            is_helper: true,
            helper_id: Some(id),
        }
    }
}

/// An export (defined symbol that can be referenced by other modules).
#[derive(Debug, Clone)]
pub struct Export {
    /// Name of the exported symbol.
    pub name: String,
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
    pub fn new(name: impl Into<String>, section_idx: usize, offset: u64) -> Self {
        Self {
            name: name.into(),
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
