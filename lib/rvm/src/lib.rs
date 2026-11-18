//! # rvm: embeddable eBPF runtime
//!
//! `rvm` is an embeddable eBPF virtual machine library for Rust.
//!
//! ## Quick Start
//!
//! ```ignore
//! use rvm::Vm;
//!
//! // Create a VM and register helpers
//! let vm = Vm::new();
//!
//! // Register a helper function (type-safe); IDs 1 to 7 are the standard helpers
//! vm.register_helper(100, |x: u64| {
//!     println!("eBPF called helper with: {}", x);
//!     x * 2
//! });
//!
//! // Describe the host's types, as BTF, for CO-RE
//! #[repr(C)]
//! struct Event {
//!     timestamp: u64,
//!     pid: u32,
//! }
//! vm.with_types(|types| rvm::host_struct!(types, Event as "event" { timestamp, pid }));
//!
//! // Load and execute an eBPF program
//! let program = vm.load_elf(&elf_bytes)?;
//! let result = program.call("main", &[])?;
//!
//! // Or link ahead of time, ship the image, and load it without the linker
//! let image = vm.prepare(&elf_bytes)?.to_bytes();
//! let program = vm.load_image(&image)?;
//! ```
//!
//! ## Components
//!
//! - [`Vm`]: the entry point. Holds the shared helper table, type registry, and the maps and regions shared across the
//!   programs it loads.
//! - `Module`: a parsed eBPF ELF file, not yet linked.
//! - [`Image`]: a linked program, before binding and allocation; serializable. [`Vm::load`] also takes one built
//!   around raw bytecode.
//! - [`Program`]: a loaded, executable program with its own memory, maps and function table.
//! - [`Plugin`]: a loaded program that other programs can call into.
//! - `HostTypes`: the host's types, as BTF, for CO-RE relocations; `host_struct!` fills it from Rust struct
//!   definitions.
//!
//! ## Cargo features
//!
//! - `link` (default): ELF parsing, CO-RE and the linker (`Module`, `HostTypes`, `Vm::prepare`, `Vm::load_elf` and
//!   friends). Without it, rvm loads prepared images only.
//! - `maps` (default): guest maps, with the map helpers (IDs 1 to 3), `Program::map` and `Vm::share_map`. Without it,
//!   an image that declares maps fails to load.
//! - `fixed-hash-seed`: guest hash maps use a fixed hash seed, for reproducible benchmarks.

#![feature(rust_preserve_none_cc)]
#![cfg_attr(feature = "link", feature(reentrant_lock))]

mod error;
mod executor;
mod helper;
#[cfg(feature = "link")]
mod host_type;
mod image;
mod layout;
#[cfg(feature = "link")]
mod linker;
mod map_def;
#[cfg(feature = "maps")]
mod maps;
mod memory;
#[cfg(feature = "link")]
mod module;
mod plugin;
mod program;
mod published;
#[cfg(feature = "link")]
mod section;
mod std_helpers;
#[cfg(feature = "link")]
mod symbol;
mod sync;
mod vm;

#[cfg(feature = "link")]
pub use btf::{BtfBuilder, BtfError, CoreReloError};
pub use error::{ExecError, HelperError, LinkError, MemoryError, Result, VmError};
pub use executor::DEFAULT_FRAME_SIZE;
pub use helper::{FromArgs, IntoReturn};
#[cfg(feature = "link")]
#[doc(hidden)]
pub use host_type::__host_field_type;
#[cfg(feature = "link")]
pub use host_type::{HostType, HostTypes};
pub use image::{Image, Import};
pub use layout::{
    BORROW_FIRST_REGION, BORROW_REGIONS, CODE_REGION, DATA_REGION, FIRST_FREE_REGION, MAPS_REGION, RODATA_REGION,
    SHARED_MAPS_FIRST_REGION, STACK_REGION,
};
pub use map_def::{MapDef, MapKind};
#[cfg(feature = "maps")]
pub use maps::{Entries, MapError, MapIter, MapKey, MapRef, BPF_ANY, BPF_EXIST, BPF_NOEXIST};
pub use memory::{
    region_base, GuestMemory, Perms, Pod, Scalar, SharedRegion, VmMemory, MAX_REGIONS, MAX_REGION_LEN, REGION_SHIFT,
};
#[cfg(feature = "link")]
pub use module::Module;
pub use plugin::{Plugin, PluginFunc, WeakPlugin};
pub use program::{Borrow, Func, FunctionInfo, Program};
pub use rvm_core::{AtomicOp, MAX_CALL_DEPTH};
#[cfg(feature = "link")]
pub use section::{Section, SectionKind};
pub use std_helpers::{
    BPF_FUNC_GET_PRANDOM_U32, BPF_FUNC_KTIME_GET_NS, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM,
    BPF_FUNC_MAP_UPDATE_ELEM, BPF_FUNC_TRACE_PRINTK,
};
#[cfg(feature = "link")]
pub use symbol::{Export, Symbol};
pub use sync::TryLockGuard;
pub use vm::{Vm, VmConfig};
