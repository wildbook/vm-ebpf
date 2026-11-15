//! # rvm - Embeddable eBPF Runtime
//!
//! `rvm` is an embeddable eBPF virtual machine library for Rust.
//!
//! ## Features
//!
//! - **Type-safe helpers**: Register host functions with automatic argument extraction
//! - **CO-RE support**: Compile-Once, Run-Everywhere with BTF type registration
//! - **Multi-module linking**: Dynamic linking of multiple eBPF ELF files
//! - **Memory safe**: Bounds-checked memory access with configurable limits
//!
//! ## Quick Start
//!
//! ```ignore
//! use rvm::Vm;
//!
//! // Create a VM and register helpers
//! let mut vm = Vm::new();
//!
//! // Register a helper function (type-safe)
//! vm.register_helper(1, |x: u64| {
//!     println!("eBPF called helper with: {}", x);
//!     x * 2
//! });
//!
//! // Register types for CO-RE
//! vm.types()
//!     .register_struct("event")
//!     .field("timestamp", 0, 8)
//!     .field("pid", 8, 4)
//!     .size(12);
//!
//! // Load and execute an eBPF program
//! let program = vm.load_elf(&elf_bytes)?;
//! let result = program.call("main", &[])?;
//! ```
//!
//! ## Components
//!
//! - [`Vm`]: the entry point. Holds the shared helper table, type registry, and the
//!   maps and regions shared across the programs it links.
//! - [`Module`]: a parsed eBPF ELF file, not yet linked.
//! - [`Program`]: a linked, executable program with its own memory, maps and
//!   function table.
//! - [`Plugin`]: a linked program that other programs can call into.
//! - [`HelperRegistry`]: the extern table of host functions callable from eBPF.
//! - [`TypeRegistry`]: type information for CO-RE relocations.

mod error;
mod executor;
mod helper;
mod layout;
mod linker;
mod maps;
mod memory;
mod module;
mod plugin;
mod program;
mod section;
mod std_helpers;
mod symbol;
mod vm;

// Public API re-exports

pub use btf::TypeRegistry;
pub use error::{ExecError, HelperError, LinkError, MemoryError, Result, VmError};
pub use executor::{Executor, DEFAULT_FRAME_SIZE, MAX_CALL_DEPTH};
pub use helper::{FromArgs, HelperArgs, HelperContext, HelperRegistry, IntoReturn, SharedHelpers};
pub use layout::{
    BORROW_FIRST_REGION, DATA_REGION, FIRST_FREE_REGION, MAPS_REGION, RODATA_REGION, SHARED_MAPS_FIRST_REGION,
    STACK_REGION,
};
pub use maps::{
    MapDef, MapError, MapKind, MapRef, Maps, BPF_ANY, BPF_EXIST, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM,
    BPF_FUNC_MAP_UPDATE_ELEM, BPF_NOEXIST,
};
pub use memory::{
    region_base, Memory, Perms, Scalar, SharedBuffer, SharedRegion, VmMemory, MAX_REGIONS, MAX_REGION_LEN, REGION_SHIFT,
};
pub use module::Module;
pub use plugin::Plugin;
pub use program::{Borrow, FunctionInfo, Program};
pub use rvm_core::{instructions_from_bytes, AtomicOp, Instruction};
pub use section::{Section, SectionKind};
pub use std_helpers::{BPF_FUNC_GET_PRANDOM_U32, BPF_FUNC_KTIME_GET_NS, BPF_FUNC_TRACE_PRINTK};
pub use symbol::{Export, Symbol, SymbolBinding, SymbolKind};
pub use vm::{Vm, VmConfig};
