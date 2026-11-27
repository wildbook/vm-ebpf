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
//! The ELF and module rows need the `link` feature. [`Vm::loader`] has the same four functions for a program that
//! gets its own [`Passthrough`] mode or [`RawCalls`] switch.
//!
//! ## Compiler
//!
//! Programs come from clang 23.1.6 or newer, as `clang -target bpf -mcpu=v4 -O2 -g -fno-slp-vectorize` writes them,
//! and rvm follows the calling convention of that clang: five argument registers, up to seven more arguments on the
//! stack, a result of up to 8 bytes in r0, and a result of 9 to 16 bytes in r0 and r2. Loading fails for an object
//! whose debug info names an older clang, which returns structs another way, and for code that passes a thirteenth
//! argument.
//!
//! ## Arguments
//!
//! A call passes up to 12 arguments, each 64 bits: the first five in r1 to r5 and the others on the stack, as clang
//! compiles a call with more than five. That holds for every call but one through a helper ID, which passes five:
//!
//! | Call | Arguments 6 to 12 |
//! |---|---|
//! | between the functions of a program, direct or through a pointer | the callee reads what the caller stored |
//! | of a host function ([`Vm::register_extern`]) | further elements of the argument tuple |
//! | of a native function ([`Vm::register_native`]) | on the native stack, pointers checked as [`NativeSig`] says |
//! | through a pointer to native code ([`RawCalls`]) | on the native stack, in a program with such a call anywhere |
//! | of another plugin's function ([`Vm::export`]) | where the calling program's BTF declares them |
//! | from the host ([`Program::call`]) | further elements of `args` |
//!
//! A function that reads an argument its caller didn't pass gets 0 from the host, and from a caller in the program
//! what the last call from the same call depth passed in that position, or 0.
//!
//! Clang 23.1 doesn't extend a negative `char` or `short` constant or forwarded narrow parameter past 32 bits when a
//! caller passes it on the stack, and a callee that clang compiled reads all 64 bits of it. From the sixth argument
//! on, the functions of a program therefore take `int` or wider types. Host and native functions get such an argument
//! as a register would hold it, with its value in the low 32 bits.
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
#[cfg(feature = "callbacks")]
mod callbacks;
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
mod proto;
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
pub use image::{CallbackInfo, Image, Import, INSN_SIZE};
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
pub use proto::{ArgKind, Proto, ReturnKind};
pub use rvm_core::{AtomicOp, NativeArg, NativeSig, MAX_CALL_DEPTH, MAX_NATIVE_ARGS};
pub use std_helpers::{
    BPF_FUNC_GET_PRANDOM_U32, BPF_FUNC_KTIME_GET_NS, BPF_FUNC_MAP_DELETE_ELEM, BPF_FUNC_MAP_LOOKUP_ELEM,
    BPF_FUNC_MAP_UPDATE_ELEM, BPF_FUNC_TRACE_PRINTK,
};
pub use sync::TryLockGuard;
pub use vm::{
    Loader, NativeImport, Passthrough, RawCalls, Resolved, Vm, VmConfig, DEFAULT_INSTRUCTION_LIMIT,
    DEFAULT_MEMORY_LIMIT,
};

/// Mark the innermost aware native call on the current thread as failed with numeric `code`, which the guest call
/// reports as `HostError::Native { code }`. Returns `false` if no aware native call is active.
#[cfg(feature = "ffi")]
pub fn fail_code(code: u64) -> bool {
    rvm_core::fail_code(code)
}

/// Mark the innermost aware native call on the current thread as failed with `error`, which the guest call reports as
/// `HostError::Failed`. Returns `false` if no aware native call is active.
#[cfg(feature = "ffi")]
pub fn fail(error: impl std::error::Error + Send + Sync + 'static) -> bool {
    rvm_core::fail_error(Box::new(error))
}

/// Call a plugin function at guest code address `func` inside the innermost aware native call on the current thread,
/// sharing its registers, stack, memory, and fuel.
///
/// Returns `Some(r0)` on normal return, or `None` if no aware native call with callback context is active on this
/// thread, if it had already failed, or if the callback failed (in which case the error is recorded so the outer run
/// stops with it).
#[cfg(feature = "callbacks")]
pub fn call_guest(func: u64, args: &[u64]) -> Option<u64> {
    if !rvm_core::has_active_callback() {
        return None;
    }
    if args.len() > executor::REG_ARGS {
        rvm_core::fail_error(Box::new(VmError::TooManyArgs(args.len())));
        return None;
    }
    let Some(pc) = executor::code_index(func) else {
        rvm_core::fail_error(Box::new(VmError::Exec(ExecError::BadCodeAddress { pc: 0, target: func })));
        return None;
    };
    let mut regs = [0u64; executor::REG_ARGS];
    regs[..args.len()].copy_from_slice(args);
    match rvm_core::call_active(None, pc, &regs) {
        Some(Ok(r0)) => Some(r0),
        _ => None,
    }
}
