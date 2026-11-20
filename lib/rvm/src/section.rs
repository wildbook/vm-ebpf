//! Sections of a parsed eBPF module.

use std::fmt;

/// What the linker does with a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// Executable code.
    Code,
    /// Initialized data (`.data`).
    Data,
    /// Read-only data (`.rodata`).
    RoData,
    /// Zeroed data (`.bss`).
    Bss,
    /// Map definitions (`.maps`).
    Maps,
    /// Jump tables for `gotox` (`.jumptables`): byte offsets into the code section that references them.
    JumpTable,
    /// An allocated section the linker has no use for.
    Other,
}

/// A section in an eBPF module.
#[derive(Clone)]
pub struct Section {
    pub name: String,
    pub kind: SectionKind,
    /// Contents; empty for `.bss`.
    pub data: Vec<u8>,
    /// Size in bytes.
    pub size: u64,
    /// Alignment in bytes, at least 1.
    pub align: u64,
    /// Section index in the ELF file.
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
        // the derived `Debug` of `SectionKind` ignores the width
        let kind = format!("{:?}", self.kind);
        write!(f, "{:20} {kind:9} ({:6} bytes)", self.name, self.size)
    }
}

/// Section of the libbpf map definitions, which the module's BTF describes as a DataSec of the same name.
pub const MAPS_SECTION: &str = ".maps";

/// Section of pre-BTF `struct bpf_map_def` map definitions, which libbpf 1.0 dropped and rvm rejects.
pub const LEGACY_MAPS_SECTION: &str = "maps";

/// Section kind from its name, for sections not flagged executable.
pub fn section_kind_from_name(name: &str) -> SectionKind {
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
    if name == MAPS_SECTION {
        return SectionKind::Maps;
    }
    if name == ".jumptables" {
        return SectionKind::JumpTable;
    }

    // program sections such as SEC("xdp") or SEC("kprobe/...")
    if !name.starts_with('.') && !name.is_empty() {
        return SectionKind::Code;
    }

    SectionKind::Other
}
