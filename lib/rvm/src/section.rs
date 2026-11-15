//! Section representation for eBPF programs.

use std::fmt;

/// Section type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// Executable code.
    Code,
    /// Initialized data (.data).
    Data,
    /// Read-only data (.rodata).
    RoData,
    /// Uninitialized data (.bss).
    Bss,
    /// Maps section.
    Maps,
    /// Other/unknown.
    Other,
}

/// A section in an eBPF module.
#[derive(Clone)]
pub struct Section {
    /// Section name.
    pub name: String,
    /// Section kind.
    pub kind: SectionKind,
    /// Section data (empty for .bss).
    pub data: Vec<u8>,
    /// Size in bytes.
    pub size: u64,
    /// Alignment requirement.
    pub align: u64,
    /// Original section index in the ELF.
    pub elf_index: usize,
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("align", &self.align)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:20} {:8?} ({:6} bytes)", self.name, self.kind, self.size)
    }
}

/// Determine section kind from name.
pub fn section_kind_from_name(name: &str) -> SectionKind {
    // Check for well-known section names
    if name == ".text" || name.starts_with(".text.") {
        return SectionKind::Code;
    }
    if name == ".data" || name.starts_with(".data.") {
        return SectionKind::Data;
    }
    if name == ".rodata" || name.starts_with(".rodata.") {
        return SectionKind::RoData;
    }
    if name == ".bss" || name.starts_with(".bss.") {
        return SectionKind::Bss;
    }
    if name == ".maps" || name == "maps" {
        return SectionKind::Maps;
    }

    // eBPF programs often use section names like "prog", "xdp", "kprobe", etc.
    // These are typically code sections
    if !name.starts_with('.') && !name.is_empty() {
        return SectionKind::Code;
    }

    SectionKind::Other
}
