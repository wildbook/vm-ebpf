//! BTF (BPF Type Format) parsing library for embeddable eBPF VMs.
//!
//! This crate provides:
//! - Parsing of BTF sections from eBPF ELF files
//! - A builder for host applications to describe their types as BTF
//! - CO-RE (Compile Once - Run Everywhere) relocation support
//!
//! # Host types as the target
//!
//! The host application's types stand in for the kernel's: eBPF programs compiled with BTF have their field accesses
//! relocated to match the host's actual layouts, as kernel CO-RE relocates a program's accesses against the running
//! kernel's BTF.
//!
//! # Example
//!
//! ```ignore
//! use btf::{apply_core_relocations, Btf, BtfBuilder, BtfExt};
//!
//! // Host application describes its struct layout as BTF
//! let mut host = BtfBuilder::new();
//! let u64_t = host.int("u64", 8, false);
//! let u32_t = host.int("u32", 4, false);
//! let event = host.add_struct("my_event", 24);
//! host.member(event, "timestamp", 0, u64_t);
//! host.member(event, "pid", 8, u32_t);
//! host.member(event, "data", 16, u64_t);
//! let target_bytes = host.encode();
//! let target = Btf::parse(&target_bytes)?;
//!
//! // Parse BTF and CO-RE relocations from the eBPF program
//! let local = Btf::parse(btf_section_bytes)?;
//! let btf_ext = BtfExt::parse(btf_ext_bytes, local.strings())?;
//! let relocations = btf_ext.relos_for_section(".text").unwrap_or(&[]);
//!
//! apply_core_relocations(&mut instructions, &local, &target, relocations)?;
//! ```

mod builder;
mod core_relo;
mod ext;
mod parse;
mod patch;
mod raw;
mod strings;
mod types;

pub use builder::BtfBuilder;
pub use core_relo::{apply_core_relocations, CoreReloError, Unresolved};
pub use ext::{BtfExt, CoreRelo, CoreReloKind};
pub use parse::{Btf, BtfError};
pub use patch::CORE_POISON_HELPER;
pub use raw::{BtfKind, BTF_INT_SIGNED, BTF_MAGIC, BTF_VERSION, TYPE_HEADER_LEN};
pub use strings::BtfStrings;
pub use types::*;
