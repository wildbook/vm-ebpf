#![allow(non_camel_case_types)]

//! This module consists of definitions, nothing more.
//! Any implementations go in the [`impls`] child module.

mod impls;

pub type Elf64Half = u16;
pub type Elf64Word = u32;
pub type Elf64Xword = u64;
pub type Elf64Addr = u64;
pub type Elf64Off = u64;
pub type Elf64Section = u16;

pub const E_CURRENT: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFOSABI_NONE: u8 = 0;
pub const ET_REL: u16 = 1;
pub const EM_BPF: u16 = 247;
pub const EV_CURRENT: u32 = 1;

#[rustfmt::skip]
pub mod reloc {
    pub mod bpf {
        pub const BPF_64_64:       u32 = 1;  // R_BPF_64_64
        pub const BPF_64_ABS64:    u32 = 2;  // R_BPF_64_ABS64
        pub const BPF_64_ABS32:    u32 = 3;  // R_BPF_64_ABS32
        pub const BPF_64_NODYLD32: u32 = 4;  // R_BPF_64_NODYLD32
        pub const BPF_64_32:       u32 = 10; // R_BPF_64_32
    }

    pub mod x86_64 {
        pub const X86_64_NONE: u32 = 0;
        pub const X86_64_64: u32 = 1;
        pub const X86_64_PC32: u32 = 2;
        pub const X86_64_GOT32: u32 = 3;
        pub const X86_64_PLT32: u32 = 4;
        pub const X86_64_COPY: u32 = 5;
        pub const X86_64_GLOB_DAT: u32 = 6;
        pub const X86_64_JUMP_SLOT: u32 = 7;
        pub const X86_64_RELATIVE: u32 = 8;
        pub const X86_64_GOTPCREL: u32 = 9;
        pub const X86_64_32: u32 = 10;
        pub const X86_64_32S: u32 = 11;
        pub const X86_64_16: u32 = 12;
        pub const X86_64_PC16: u32 = 13;
        pub const X86_64_8: u32 = 14;
        pub const X86_64_PC8: u32 = 15;
        pub const X86_64_DTPMOD64: u32 = 16;
        pub const X86_64_DTPOFF64: u32 = 17;
        pub const X86_64_TPOFF64: u32 = 18;
        pub const X86_64_TLSGD: u32 = 19;
        pub const X86_64_TLSLD: u32 = 20;
        pub const X86_64_DTPOFF32: u32 = 21;
        pub const X86_64_GOTTPOFF: u32 = 22;
        pub const X86_64_TPOFF32: u32 = 23;
        pub const X86_64_PC64: u32 = 24;
        pub const X86_64_GOTOFF64: u32 = 25;
        pub const X86_64_GOTPC32: u32 = 26;
        pub const X86_64_GOT64: u32 = 27;
        pub const X86_64_GOTPCREL64: u32 = 28;
        pub const X86_64_GOTPC64: u32 = 29;
        pub const X86_64_GOTPLT64: u32 = 30;
        pub const X86_64_PLTOFF64: u32 = 31;
        pub const X86_64_SIZE32: u32 = 32;
        pub const X86_64_SIZE64: u32 = 33;
        pub const X86_64_GOTPC32_TLSDESC: u32 = 34;
        pub const X86_64_TLSDESC_CALL: u32 = 35;
        pub const X86_64_TLSDESC: u32 = 36;
        pub const X86_64_IRELATIVE: u32 = 37;
        pub const X86_64_RELATIVE64: u32 = 38;
        pub const X86_64_GOTPCRELX: u32 = 41;
        pub const X86_64_REX_GOTPCRELX: u32 = 42;
        pub const X86_64_NUM: u32 = 43;
    }
}

#[rustfmt::skip]
pub mod shf {
    pub const WRITE:            u32 = 1 << 0;   /* Writable */
    pub const ALLOC:            u32 = 1 << 1;   /* Occupies memory during execution */
    pub const EXECINSTR:        u32 = 1 << 2;   /* Executable */
    pub const MERGE:            u32 = 1 << 4;   /* Might be merged */
    pub const STRINGS:          u32 = 1 << 5;   /* Contains nul-terminated strings */
    pub const INFO_LINK:        u32 = 1 << 6;   /* `sh_info' contains SHT index */
    pub const LINK_ORDER:       u32 = 1 << 7;   /* Preserve order after combining */
    pub const OS_NONCONFORMING: u32 = 1 << 8;   /* Non-standard OS specific handling required */
    pub const GROUP:            u32 = 1 << 9;   /* Section is member of a group.  */
    pub const TLS:              u32 = 1 << 10;  /* Section hold thread-local data.  */
    pub const MASKOS:           u32 = 0x0ff00000; /* OS-specific.  */
    pub const MASKPROC:         u32 = 0xf0000000; /* Processor-specific */
    pub const ORDERED:          u32 = 1 << 30;  /* Special ordering requirement (Solaris).  */
    pub const EXCLUDE:          u32 = 1 << 31;  /* Section is excluded unless referenced or allocated (Solaris).*/
}

#[rustfmt::skip]
pub mod sht {
    pub const NULL:            u32 = 0x0; /* Inactive section header */
    pub const PROGBITS:        u32 = 0x1; /* Information defined by the program */
    pub const SYMTAB:          u32 = 0x2; /* Symbol table - not DLL */
    pub const STRTAB:          u32 = 0x3; /* String table */
    pub const RELA:            u32 = 0x4; /* Explicit addend relocations, Elf64_Rela */
    pub const HASH:            u32 = 0x5; /* Symbol hash table */
    pub const DYNAMIC:         u32 = 0x6; /* Information for dynamic linking */
    pub const NOTE:            u32 = 0x7; /* A Note section */
    pub const NOBITS:          u32 = 0x8; /* Like SHT_PROGBITS with no data */
    pub const REL:             u32 = 0x9; /* Implicit addend relocations, Elf64_Rel */
    pub const SHLIB:           u32 = 0xA; /* Currently unspecified semantics */
    pub const DYNSYM:          u32 = 0xB; /* Symbol table for a DLL */
    pub const INIT_ARRAY:      u32 = 0xE; /* Array of constructors */
    pub const FINI_ARRAY:      u32 = 0xF; /* Array of deconstructors */
    pub const PREINIT_ARRAY:   u32 = 0x10; /* Array of pre-constructors */
    pub const GROUP:           u32 = 0x11; /* Section group */
    pub const SYMTAB_SHNDX:    u32 = 0x12; /* Extended section indeces */
    pub const NUM:             u32 = 0x13; /* Number of defined types */

    pub const LOOS:            u32 = 0x60000000; /* Lowest OS-specific section type */
    pub const HIOS:            u32 = 0x6fffffff; /* Highest OS-specific section type */
    pub const LOPROC:          u32 = 0x70000000; /* Start of processor-specific section type */
    pub const HIPROC:          u32 = 0x7fffffff; /* End of processor-specific section type */
    pub const LOUSER:          u32 = 0x80000000; /* Start of application-specific */
    pub const HIUSER:          u32 = 0x8fffffff; /* End of application-specific */
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Rel {
    pub r_offset: Elf64Addr,
    pub r_info: Elf64Xword,
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Rela {
    pub r_offset: Elf64Addr,
    pub r_info: Elf64Xword,
    pub r_addend: i64,
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct ElfIdent {
    pub ei_magic: [u8; 4],
    pub ei_class: u8,
    pub ei_data: u8,
    pub ei_version: u8,
    pub ei_osabi: u8,
    pub ei_abiverssion: u8,
    pub ei_pad: [u8; 7],
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Ehdr {
    pub e_ident: ElfIdent,
    pub e_type: Elf64Half,
    pub e_machine: Elf64Half,
    pub e_version: Elf64Word,
    pub e_entry: Elf64Addr,
    pub e_phoff: Elf64Off,
    pub e_shoff: Elf64Off,
    pub e_flags: Elf64Word,
    pub e_ehsize: Elf64Half,
    pub e_phentsize: Elf64Half,
    pub e_phnum: Elf64Half,
    pub e_shentssize: Elf64Half,
    pub e_shnum: Elf64Half,
    pub e_shstrndx: Elf64Half,
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Shdr {
    pub sh_name: Elf64Word,
    pub sh_type: Elf64Word,
    pub sh_flags: Elf64Xword,
    pub sh_addr: Elf64Addr,
    pub sh_offset: Elf64Off,
    pub sh_size: Elf64Xword,
    pub sh_link: Elf64Word,
    pub sh_info: Elf64Word,
    pub sh_addralign: Elf64Xword,
    pub sh_entsize: Elf64Xword,
}

#[repr(packed)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64Sym {
    pub st_name: Elf64Word,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: Elf64Section,
    pub st_value: Elf64Addr,
    pub st_size: Elf64Xword,
}
