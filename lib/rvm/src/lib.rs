//! # rvm - Embeddable eBPF Runtime
//!
//! `rvm` is a production-ready embeddable eBPF virtual machine library for Rust.
//! It provides a high-level API similar to scripting language runtimes like
//! rlua or rhai, making it easy to embed eBPF execution in your applications.
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
//! ## Architecture
//!
//! The library is organized into several key components:
//!
//! - [`Vm`]: The main entry point. Holds helper registry and type registry.
//! - [`Module`]: A parsed eBPF ELF file (not yet linked).
//! - [`Program`]: A linked, executable program with function table.
//! - [`HelperRegistry`]: Collection of registered helper functions.
//! - [`TypeRegistry`]: Type information for CO-RE relocations.
//!
//! ## Execution Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                          Vm                                 │
//! │  ┌──────────────────┐  ┌──────────────────┐                 │
//! │  │  HelperRegistry  │  │   TypeRegistry   │                 │
//! │  │  (id → fn)       │  │  (CO-RE types)   │                 │
//! │  └──────────────────┘  └──────────────────┘                 │
//! └─────────────────────────────────────────────────────────────┘
//!                             │
//!                             │ load_module() / parse_module()
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        Module                               │
//! │  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
//! │  │  Sections  │  │  Symbols   │  │ Relocations│            │
//! │  │ (code/data)│  │(imports/   │  │ (ELF/CO-RE)│            │
//! │  │            │  │ exports)   │  │            │            │
//! │  └────────────┘  └────────────┘  └────────────┘            │
//! └─────────────────────────────────────────────────────────────┘
//!                             │
//!                             │ link()
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        Program                              │
//! │  ┌────────────────────┐  ┌────────────────────┐            │
//! │  │      VmMemory      │  │   Function Table   │            │
//! │  │  (code+data+stack) │  │  (name → pc)       │            │
//! │  └────────────────────┘  └────────────────────┘            │
//! └─────────────────────────────────────────────────────────────┘
//!                             │
//!                             │ call() / run()
//!                             ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                       Executor                              │
//! │  ┌────────────────────────────────────────────────────────┐│
//! │  │  Context (registers) ←→ rvm_core::run() ←→ Memory     ││
//! │  │                           │                            ││
//! │  │                           ▼                            ││
//! │  │                  Flow::CallKfunc(slot)                 ││
//! │  │                           │                            ││
//! │  │                           ▼                            ││
//! │  │             HelperRegistry.call_slot(slot)             ││
//! │  └────────────────────────────────────────────────────────┘│
//! └─────────────────────────────────────────────────────────────┘
//! ```

// Module declarations
mod error;
mod executor;
mod helper;
mod linker;
mod maps;
mod memory;
mod module;
mod plugin;
mod program;
mod section;
mod std_helpers;
mod symbol;
mod types;
mod vm;

// Public API re-exports

// Main entry point
// Errors
pub use error::{ElfError, ExecError, HelperError, LinkError, MemoryError, Result, VmError};
pub use executor::{Executor, DEFAULT_FRAME_SIZE, MAX_CALL_DEPTH};
// Helper functions
pub use helper::{
    into_dyn_helper, into_dyn_helper_with_ctx, DynHelper, FromArgs, HelperArgs, HelperContext, HelperFn,
    HelperRegistry, IntoReturn, SharedHelpers,
};
// Low-level re-exports for advanced users
pub use linker::{Linker, DATA_REGION, FIRST_FREE_REGION, RODATA_REGION, STACK_REGION};
pub use maps::{
    MapDef, MapError, MapKind, MapRef, Maps, BPF_ANY, BPF_EXIST, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM,
    BPF_FUNC_MAP_UPDATE_ELEM, BPF_NOEXIST, MAPS_REGION, SHARED_MAPS_FIRST_REGION,
};
// Memory
pub use memory::{
    region_base, Memory, Perms, Scalar, SharedBuffer, SharedRegion, VmMemory, MAX_REGIONS, MAX_REGION_LEN, REGION_SHIFT,
};
// Module loading
pub use module::Module;
pub use plugin::{Plugin, BORROW_FIRST_REGION};
// Program and execution
pub use program::{Borrow, FunctionInfo, Program};
pub use rvm_core::{instructions_from_bytes, AtomicOp, Instruction};
pub use section::{Section, SectionKind};
pub use std_helpers::{BPF_FUNC_GET_PRANDOM_U32, BPF_FUNC_KTIME_GET_NS, BPF_FUNC_TRACE_PRINTK};
pub use symbol::{Export, Import, Symbol, SymbolBinding, SymbolKind};
// Types (CO-RE)
pub use types::TypeRegistry;
pub use vm::{Vm, VmConfig};

/// Prelude module for convenient imports.
///
/// ```ignore
/// use rvm::prelude::*;
/// ```
pub mod prelude {
    pub use crate::error::{Result, VmError};
    pub use crate::helper::{FromArgs, IntoReturn};
    pub use crate::program::Program;
    pub use crate::vm::Vm;
}
