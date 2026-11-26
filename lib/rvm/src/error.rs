//! Error types for the rvm runtime.
//!
//! An error that wraps another one shows it in its `Display` and returns `None` from `source()`, so a chain printer
//! such as anyhow prints each message once.

use std::fmt;

use crate::executor::MAX_ARGS;
#[cfg(feature = "maps")]
use crate::maps::MapError;

/// Result type alias for rvm operations.
pub type Result<T> = std::result::Result<T, VmError>;

/// Errors that can occur in the rvm runtime.
#[derive(Debug)]
#[non_exhaustive]
pub enum VmError {
    #[cfg(feature = "link")]
    Elf(constelf::ElfError),

    #[cfg(feature = "link")]
    Btf(btf::BtfError),

    /// A malformed image, or one written by another rvm version.
    InvalidImage(String),

    Link(LinkError),

    Exec(ExecError),

    Host(HostError),

    Memory(MemoryError),

    #[cfg(feature = "maps")]
    Map(MapError),

    /// No function `func`, in the plugin `plugin` if the lookup went through one.
    FunctionNotFound {
        plugin: Option<String>,
        func: String,
    },

    /// No map with this name.
    #[cfg(feature = "maps")]
    MapNotFound(String),

    /// A function handle looked up in another program.
    ForeignFunc,

    /// A region handle from another memory, such as the memory of a program that
    /// [`Plugin::replace`](crate::Plugin::replace) swapped out.
    ForeignRegion,

    /// Every host region is taken: in the program for [`VmMemory::map`](crate::VmMemory::map), in the VM for
    /// [`Vm::share_region`](crate::Vm::share_region). A region the VM shares is taken in every program linked
    /// afterwards.
    NoFreeRegion,

    /// A call with more arguments than the 5 that eBPF functions take.
    TooManyArgs(usize),

    InvalidArgument(String),

    /// The program needs more memory than [`VmConfig::memory_limit`](crate::VmConfig::memory_limit), the value,
    /// allows.
    MemoryLimit(usize),

    /// The allocator refused this many bytes.
    OutOfMemory(usize),

    /// A non-zero instruction limit in a build without the `fuel` feature, which can't enforce it.
    FuelNotEnabled,

    /// The program's code, rodata or data (named) exceeds [`MAX_REGION_LEN`](crate::MAX_REGION_LEN) bytes.
    ProgramTooLarge(&'static str),

    /// The plugin is already running a call.
    PluginBusy(String),

    /// An export outlived the plugin it calls into.
    PluginUnloaded(String),

    /// A link or ELF load ran inside the [`Vm::with_types`](crate::Vm::with_types) closure of the same VM.
    #[cfg(feature = "link")]
    TypesBusy,
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "link")]
            Self::Elf(e) => write!(f, "ELF error: {e}"),
            #[cfg(feature = "link")]
            Self::Btf(e) => write!(f, "BTF error: {e}"),
            Self::InvalidImage(msg) => write!(f, "invalid image: {msg}"),
            Self::Link(e) => write!(f, "link error: {e}"),
            Self::Exec(e) => write!(f, "execution error: {e}"),
            Self::Host(e) => write!(f, "{e}"),
            Self::Memory(e) => write!(f, "memory error: {e}"),
            #[cfg(feature = "maps")]
            Self::Map(e) => write!(f, "map error: {e}"),
            Self::FunctionNotFound { plugin: None, func } => write!(f, "function not found: {func}"),
            Self::FunctionNotFound {
                plugin: Some(plugin),
                func,
            } => write!(f, "function not found: {plugin}::{func}"),
            #[cfg(feature = "maps")]
            Self::MapNotFound(name) => write!(f, "map not found: {name}"),
            Self::ForeignFunc => write!(f, "function handle belongs to another program; look the function up again"),
            Self::ForeignRegion => write!(f, "region handle belongs to another memory"),
            Self::NoFreeRegion => write!(f, "every host region is taken"),
            Self::TooManyArgs(count) => write!(f, "{count} arguments, but eBPF functions take at most {MAX_ARGS}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::MemoryLimit(limit) => {
                write!(f, "program needs more than {limit} bytes of memory; raise VmConfig::memory_limit to allow it")
            }
            Self::OutOfMemory(bytes) => write!(f, "failed to allocate {bytes} bytes"),
            Self::FuelNotEnabled => {
                write!(f, "instruction limits need rvm's `fuel` feature; enable it or set the limit to 0")
            }
            Self::ProgramTooLarge(region) => {
                write!(f, "program {region} exceeds {} bytes", crate::memory::MAX_REGION_LEN)
            }
            Self::PluginBusy(name) => write!(f, "plugin {name} is already running a call"),
            Self::PluginUnloaded(name) => write!(f, "plugin {name} was unloaded"),
            #[cfg(feature = "link")]
            Self::TypesBusy => write!(f, "cannot link inside Vm::with_types; link after the closure returns"),
        }
    }
}

impl std::error::Error for VmError {}

#[cfg(feature = "link")]
impl From<constelf::ElfError> for VmError {
    fn from(e: constelf::ElfError) -> Self {
        Self::Elf(e)
    }
}

#[cfg(feature = "link")]
impl From<btf::BtfError> for VmError {
    fn from(e: btf::BtfError) -> Self {
        Self::Btf(e)
    }
}

impl From<LinkError> for VmError {
    fn from(e: LinkError) -> Self {
        Self::Link(e)
    }
}

impl From<ExecError> for VmError {
    fn from(e: ExecError) -> Self {
        Self::Exec(e)
    }
}

impl From<HostError> for VmError {
    fn from(e: HostError) -> Self {
        Self::Host(e)
    }
}

impl From<MemoryError> for VmError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

#[cfg(feature = "maps")]
impl From<MapError> for VmError {
    fn from(e: MapError) -> Self {
        Self::Map(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkError {
    /// No module defines the symbol, and the VM has no extern of that name.
    UnresolvedSymbol(String),
    /// A call to a helper ID that isn't registered.
    UnknownHelper(u32),
    /// An extern declares a different number of argument registers than the host function takes. `declared` counts
    /// registers, not parameters: a struct of 9 to 16 bytes takes two, and a returned struct of more than 16 bytes
    /// adds a result pointer.
    SignatureMismatch { name: String, declared: usize, host: u8 },
    /// An extern declares a result of 9 to 16 bytes, which comes back in r0 and r2, and the host function sets only
    /// r0 (`wide`), or the reverse. A function another plugin exports sets only r0.
    ReturnMismatch { name: String, wide: bool },
    /// An extern or image disagrees with the native function's signature in what isn't the register count, or the
    /// extern has no BTF to check it against.
    NativeMismatch { name: String, reason: String },
    /// A host-bound extern needs more argument registers than the five eBPF has.
    TooManyRegisters { name: String, registers: usize },
    /// The instruction at `pc` passes or takes an argument on the stack, through r11, as clang does from the sixth
    /// argument register on. `function` is the exported function it lies in, if any.
    StackArguments { pc: u64, function: Option<String> },
    /// The object's debug info names a clang older than 23 as its compiler, here by version. Such a clang returns
    /// small structs by another convention.
    #[cfg(feature = "link")]
    UnsupportedCompiler(String),
    /// A program declares a shared map with a different layout than the existing one.
    #[cfg(feature = "maps")]
    MapMismatch(String),
    /// Two different definitions of one symbol or map name.
    DuplicateSymbol(String),
    /// A relocation, symbol or tag that points outside its module or section, or at something it can't refer to.
    InvalidReference(String),
    /// A map definition no program can use, maps that don't fit in guest memory, or any map when rvm is built without
    /// the `maps` feature.
    InvalidMap(String),
    /// A malformed or unsupported CO-RE relocation.
    #[cfg(feature = "link")]
    CoreRelo(btf::CoreReloError),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedSymbol(name) => write!(f, "unresolved symbol: {name}"),
            Self::UnknownHelper(id) => match crate::std_helpers::helper_name(*id) {
                Some(name) => write!(f, "call to unregistered helper {id} ({name})"),
                None => write!(f, "call to unregistered helper {id}"),
            },
            Self::SignatureMismatch { name, declared, host } => {
                write!(f, "extern {name} takes {declared} argument registers but the host function takes {host}")
            }
            Self::ReturnMismatch { name, wide: true } => {
                write!(f, "extern {name} returns 9 to 16 bytes in r0 and r2, but the host function sets only r0")
            }
            Self::ReturnMismatch { name, wide: false } => {
                write!(
                    f,
                    "the host function {name} sets r0 and r2, which only an extern that returns 9 to 16 bytes reads"
                )
            }
            Self::NativeMismatch { name, reason } => write!(f, "native {name}: {reason}"),
            Self::TooManyRegisters { name, registers } => {
                write!(f, "extern {name} takes {registers} argument registers, but eBPF passes at most {MAX_ARGS}")
            }
            Self::StackArguments { pc, function } => {
                let place = function.as_ref().map(|name| format!(" in {name}")).unwrap_or_default();
                write!(
                    f,
                    "instruction {pc}{place} passes or takes an argument on the stack, through r11, which rvm doesn't \
                     support: a call has at most {MAX_ARGS} argument registers"
                )
            }
            #[cfg(feature = "link")]
            Self::UnsupportedCompiler(version) => {
                write!(f, "the object comes from clang {version}, and rvm takes objects from clang 23 or newer")
            }
            #[cfg(feature = "maps")]
            Self::MapMismatch(name) => write!(f, "shared map {name} is declared with a different layout"),
            Self::DuplicateSymbol(name) => write!(f, "duplicate symbol: {name}"),
            Self::InvalidReference(msg) => write!(f, "invalid reference: {msg}"),
            Self::InvalidMap(msg) => write!(f, "invalid map: {msg}"),
            #[cfg(feature = "link")]
            Self::CoreRelo(e) => write!(f, "CO-RE relocation: {e}"),
        }
    }
}

impl std::error::Error for LinkError {}

/// Execution errors. `pc` is the index of the instruction that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecError {
    /// An invalid or reserved instruction.
    InvalidInstruction { pc: u64 },
    /// A valid instruction that rvm doesn't implement.
    Unimplemented { pc: u64 },
    /// A load or store outside the mapped regions or their permissions.
    MemoryFault { pc: u64, error: MemoryError },
    /// The call ran `limit` instructions without finishing.
    InstructionLimit { limit: u64 },
    /// The call at `pc` exceeds [`MAX_CALL_DEPTH`](crate::MAX_CALL_DEPTH) nested calls, or finds `r10` lower than
    /// [`VmConfig::frame_size`](crate::VmConfig::frame_size).
    StackOverflow { pc: u64 },
    /// Execution reached `pc`, an instruction index outside the code.
    InvalidPc { pc: u64 },
    /// Ran an instruction whose CO-RE relocation the host couldn't resolve.
    UnresolvedCoreRelo { pc: u64 },
    /// `callx` or `gotox` at `pc` targeted something other than an instruction in the program (or, for `callx`, a
    /// helper ID).
    BadCodeAddress { pc: u64, target: u64 },
    /// A call to helper `id`, which isn't registered. Linking catches these; raw bytecode and `callx` reach it.
    UnknownHelper { pc: u64, id: u32 },
    /// A call to a named extern in a slot the VM's table lacks, which only raw bytecode can contain.
    UnknownExtern { pc: u64, slot: u32 },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstruction { pc } => write!(f, "instruction {pc} is invalid"),
            Self::Unimplemented { pc } => write!(f, "instruction {pc} is not implemented"),
            Self::MemoryFault { pc, error } => write!(f, "memory fault at instruction {pc}: {error}"),
            Self::InstructionLimit { limit } => write!(f, "the call ran its limit of {limit} instructions"),
            Self::StackOverflow { pc } => write!(f, "the call at instruction {pc} overflows the call stack"),
            Self::InvalidPc { pc } => write!(f, "execution left the code at instruction index {pc}"),
            Self::UnresolvedCoreRelo { pc } => {
                write!(f, "instruction {pc} uses a type or field the host doesn't have (CO-RE)")
            }
            Self::BadCodeAddress { pc, target } => {
                write!(f, "instruction {pc} branches to {target:#x}, which is not an instruction in the program")
            }
            Self::UnknownHelper { pc, id } => write!(f, "instruction {pc} calls helper {id}, which is not registered"),
            Self::UnknownExtern { pc, slot } => {
                write!(f, "instruction {pc} calls extern slot {slot}, which does not exist")
            }
        }
    }
}

impl std::error::Error for ExecError {}

/// A failed call from a program to a host function.
#[derive(Debug)]
#[non_exhaustive]
pub enum HostError {
    /// The host function returned this `Err`. Host functions that want the guest to see an error code return it as
    /// `i64` instead.
    Failed(Box<dyn std::error::Error + Send + Sync>),
    /// A call into `func`, which `plugin` exports, failed.
    Plugin {
        plugin: String,
        func: String,
        error: Box<VmError>,
    },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(e) => write!(f, "host function failed: {e}"),
            Self::Plugin { plugin, func, error } => write!(f, "{plugin}::{func}: {error}"),
        }
    }
}

impl std::error::Error for HostError {}

/// Guest memory access outside the mapped regions or their permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryError {
    pub addr: u64,
    pub size: usize,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no access to {} bytes at {:#x}", self.size, self.addr)
    }
}

impl std::error::Error for MemoryError {}
