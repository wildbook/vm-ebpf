//! BTF (BPF Type Format) parsing library for embeddable eBPF VMs.
//!
//! This crate provides:
//! - Parsing of BTF sections from eBPF ELF files
//! - A type registry for host applications to register their struct layouts
//! - CO-RE (Compile Once - Run Everywhere) relocation support
//!
//! # Non-Kernel Use Case
//!
//! Unlike kernel eBPF, this library is designed for embedding eBPF in user applications.
//! The host application defines "target" types (like a kernel would), and eBPF programs
//! compiled with BTF have their field accesses relocated to match the host's actual layouts.
//!
//! # Example
//!
//! ```ignore
//! use btf::{Btf, TypeRegistry};
//!
//! // Host application registers its struct layout
//! let mut registry = TypeRegistry::new();
//! registry.register_struct("my_event", &[
//!     ("timestamp", 0, 8),  // offset 0, size 8
//!     ("pid", 8, 4),        // offset 8, size 4
//!     ("data", 16, 64),     // offset 16, size 64
//! ]);
//!
//! // Parse BTF from eBPF program
//! let btf = Btf::parse(btf_section_bytes)?;
//!
//! // Apply CO-RE relocations
//! let relocations = parse_btf_ext(btf_ext_bytes)?;
//! apply_core_relocations(&mut instructions, &btf, &registry, &relocations)?;
//! ```

mod core_relo;
mod parse;
mod raw;
mod registry;
mod strings;
mod types;

#[cfg(test)]
mod integration_tests;

pub use core_relo::{apply_core_relocations, BtfExt, CoreRelo, CoreReloError, CoreReloKind};
pub use parse::{Btf, BtfError};
pub use raw::*;
pub use registry::{EnumDef, EnumVariant, StructDef, StructField, TypeRegistry};
pub use strings::BtfStrings;
pub use types::*;
