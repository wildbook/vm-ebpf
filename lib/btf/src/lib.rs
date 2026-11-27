//! BTF (BPF Type Format) for an embeddable eBPF VM: a parser for `.BTF` and `.BTF.ext`, a builder for the host's own
//! types, and CO-RE (Compile Once, Run Everywhere) relocation.
//!
//! The host's types stand in for the kernel's. A program compiled with BTF has its field accesses relocated to the
//! host's layouts, as kernel CO-RE relocates a program's accesses against the BTF of the running kernel.
//!
//! ```ignore
//! use btf::{apply_core_relocations, Btf, BtfBuilder, BtfExt};
//!
//! // the host describes its struct layout as BTF
//! let mut host = BtfBuilder::new();
//! let u64_t = host.add_int("u64", 8, false);
//! let u32_t = host.add_int("u32", 4, false);
//! let event = host.add_struct("my_event", 24);
//! host.member(event, "timestamp", 0, u64_t);
//! host.member(event, "pid", 8, u32_t);
//! host.member(event, "data", 16, u64_t);
//! let target_bytes = host.encode();
//! let target = Btf::parse(&target_bytes)?;
//!
//! // the program's BTF and CO-RE relocations, from its `.BTF` and `.BTF.ext` sections
//! let local = Btf::parse(btf_section_bytes)?;
//! let btf_ext = BtfExt::parse(btf_ext_bytes, local.strings())?;
//! let relocations = btf_ext.relos_for_section(".text").unwrap_or(&[]);
//!
//! let unresolved = apply_core_relocations(&mut instructions, &local, &target, relocations)?;
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
pub use ext::{BtfExt, CoreRelo, CoreReloKind, FuncInfo};
pub use parse::{Btf, BtfError};
pub use patch::CORE_POISON_HELPER;
pub use raw::{BtfKind, BTF_FUNC_EXTERN, BTF_FUNC_GLOBAL, BTF_FUNC_STATIC, BTF_INT_SIGNED};
pub use strings::BtfStrings;
pub use types::{BtfType, EnumValue, Member, Param, VarSecInfo};
