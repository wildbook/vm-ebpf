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
    /// BTF type information.
    Btf,
    /// BTF.ext (CO-RE relocations, etc.).
    BtfExt,
    /// Maps section.
    Maps,
    /// Other/unknown.
    Other,
}

impl SectionKind {
    /// Check if this section contains executable code.
    pub fn is_executable(&self) -> bool {
        matches!(self, Self::Code)
    }

    /// Check if this section is writable.
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::Data | Self::Bss)
    }

    /// Check if this section should be loaded into VM memory.
    pub fn is_allocatable(&self) -> bool {
        matches!(self, Self::Code | Self::Data | Self::RoData | Self::Bss)
    }
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
    /// Virtual address (assigned during linking).
    pub vaddr: u64,
    /// Size in bytes.
    pub size: u64,
    /// Alignment requirement.
    pub align: u64,
    /// Original section index in the ELF.
    pub elf_index: usize,
}

impl Section {
    /// Create a new section.
    pub fn new(name: impl Into<String>, kind: SectionKind) -> Self {
        Self {
            name: name.into(),
            kind,
            data: Vec::new(),
            vaddr: 0,
            size: 0,
            align: 8, // Default to 8-byte alignment for eBPF
            elf_index: 0,
        }
    }

    /// Create a section with data.
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.size = data.len() as u64;
        self.data = data;
        self
    }

    /// Set the size (for .bss sections).
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set the alignment.
    pub fn with_align(mut self, align: u64) -> Self {
        self.align = align;
        self
    }

    /// Set the ELF index.
    pub fn with_elf_index(mut self, index: usize) -> Self {
        self.elf_index = index;
        self
    }

    /// Check if this section is executable.
    pub fn is_executable(&self) -> bool {
        self.kind.is_executable()
    }

    /// Check if this section is writable.
    pub fn is_writable(&self) -> bool {
        self.kind.is_writable()
    }

    /// Check if this section should be loaded into VM memory.
    pub fn is_allocatable(&self) -> bool {
        self.kind.is_allocatable()
    }

    /// Get the end address (vaddr + size).
    pub fn end_addr(&self) -> u64 {
        self.vaddr + self.size
    }
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("vaddr", &format_args!("0x{:x}", self.vaddr))
            .field("size", &self.size)
            .field("align", &self.align)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:20} {:8?} @ 0x{:08x} - 0x{:08x} ({:6} bytes)",
            self.name,
            self.kind,
            self.vaddr,
            self.end_addr(),
            self.size
        )
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
    if name == ".BTF" {
        return SectionKind::Btf;
    }
    if name == ".BTF.ext" {
        return SectionKind::BtfExt;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_kind_from_name() {
        assert_eq!(section_kind_from_name(".text"), SectionKind::Code);
        assert_eq!(section_kind_from_name(".text.my_func"), SectionKind::Code);
        assert_eq!(section_kind_from_name(".data"), SectionKind::Data);
        assert_eq!(section_kind_from_name(".rodata"), SectionKind::RoData);
        assert_eq!(section_kind_from_name(".bss"), SectionKind::Bss);
        assert_eq!(section_kind_from_name(".BTF"), SectionKind::Btf);
        assert_eq!(section_kind_from_name(".BTF.ext"), SectionKind::BtfExt);
        assert_eq!(section_kind_from_name("xdp"), SectionKind::Code);
        assert_eq!(section_kind_from_name("kprobe/sys_open"), SectionKind::Code);
    }
}
