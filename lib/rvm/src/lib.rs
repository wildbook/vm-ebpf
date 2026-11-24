//! # rvm: embeddable eBPF runtime
//!
//! `rvm` is an embeddable eBPF virtual machine library for Rust. It links eBPF ELF objects against host functions and
//! host types, and runs their functions in an interpreter.
//!
//! ## Quick Start
//!
//! ```ignore
//! use rvm::Vm;
//!
//! let vm = Vm::new();
//!
//! // A host function the program calls by helper ID; pick an ID that no standard helper (`BPF_FUNC_*`) uses
//! vm.register_helper(100, |x: u64| {
//!     println!("eBPF called helper with: {}", x);
//!     x * 2
//! });
//! // A host function the program declares as `extern u64 host_add(u64 a, u64 b);`
//! vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);
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
//! let mut program = vm.load_elf(&elf_bytes)?;
//! let result = program.call("main", &[])?;
//!
//! // Or link ahead of time, ship the image, and load it without the linker
//! let image = vm.prepare_elf(&elf_bytes)?.to_bytes();
//! let mut program = vm.load_image_bytes(&image)?;
//! ```
//!
//! ## Loading
//!
//! | From | To an [`Image`] | To a [`Program`] |
//! |---|---|---|
//! | one ELF file | `Vm::prepare_elf` | `Vm::load_elf` |
//! | several `Module`s | `Vm::prepare_modules` | `Vm::load_modules` |
//! | an [`Image`] | | [`Vm::load_image`] |
//! | bytes from [`Image::to_bytes`] | [`Image::from_bytes`] | [`Vm::load_image_bytes`] |
//!
//! The ELF and module rows need the `link` feature.
//!
//! ## Components
//!
//! - [`Vm`]: the entry point. Holds the host functions, the host types, and the maps and regions shared across the
//!   programs it loads.
//! - `Module`: a parsed eBPF ELF file, not yet linked.
//! - [`Image`]: a linked program, before binding and allocation; serializable. [`Vm::load_image`] also takes one
//!   built around raw bytecode.
//! - [`Program`]: a loaded, executable program with its own memory, maps and function table.
//! - [`Plugin`]: a loaded program that other programs can call into; [`Plugin::new`] wraps one.
//! - `HostTypes`: the host's types, as BTF, for CO-RE relocations; `host_struct!` fills it from Rust struct
//!   definitions.
//!
//! ## Cargo features
//!
//! The features are described in the `[features]` table of rvm's `Cargo.toml`.

#![feature(rust_preserve_none_cc)]
#![cfg_attr(feature = "link", feature(reentrant_lock))]

#[cfg(test)]
mod bpf_sources;
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
#[cfg(feature = "link")]
mod section;
mod std_helpers;
#[cfg(feature = "link")]
mod symbol;
mod sync;
mod vm;

#[cfg(feature = "link")]
pub use btf::{BtfBuilder, BtfError, CoreReloError};
#[cfg(feature = "maps")]
pub use bytemuck::{Pod, Zeroable};
pub use error::{ExecError, HostError, LinkError, MemoryError, Result, VmError};
pub use executor::DEFAULT_FRAME_SIZE;
pub use helper::{FromArgs, IntoReturn};
#[cfg(feature = "link")]
#[doc(hidden)]
pub use host_type::__host_field_type;
#[cfg(feature = "link")]
pub use host_type::{HostType, HostTypes};
pub use image::{Image, Import, INSN_SIZE};
pub use layout::{
    BORROW_FIRST_REGION, BORROW_REGIONS, CODE_REGION, DATA_REGION, MAPS_REGION, RODATA_REGION,
    SHARED_MAPS_FIRST_REGION, STACK_REGION,
};
pub use map_def::{MapDef, MapKind};
#[cfg(feature = "maps")]
pub use maps::{Entries, MapError, MapIter, MapKey, MapRef, ValueSpacing, BPF_ANY, BPF_EXIST, BPF_NOEXIST};
pub use memory::{
    region_tag, GuestMemory, Perms, Region, Scalar, SharedRegion, VmMemory, MAX_REGIONS, MAX_REGION_LEN, RAW_END,
    RAW_START, REGION_SHIFT,
};
#[cfg(feature = "link")]
pub use module::Module;
pub use plugin::{Plugin, PluginFunc, WeakPlugin};
pub use program::{Borrow, Func, FunctionInfo, LimitedCall, Program, ProgramMemory};
pub use rvm_core::{AtomicOp, NativeArg, NativeSig, MAX_CALL_DEPTH, MAX_NATIVE_ARGS};
pub use std_helpers::{
    BPF_FUNC_GET_PRANDOM_U32, BPF_FUNC_KTIME_GET_NS, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM,
    BPF_FUNC_MAP_UPDATE_ELEM, BPF_FUNC_TRACE_PRINTK,
};
pub use sync::TryLockGuard;
pub use vm::{Passthrough, Vm, VmConfig, DEFAULT_INSTRUCTION_LIMIT, DEFAULT_MEMORY_LIMIT};
