//! Error types for the rvm runtime.

use std::fmt;

/// Result type alias for rvm operations.
pub type Result<T> = std::result::Result<T, VmError>;

/// Errors that can occur in the rvm runtime.
#[derive(Debug)]
pub enum VmError {
    /// ELF parsing error.
    #[cfg(feature = "link")]
    Elf(String),

    /// BTF parsing error.
    #[cfg(feature = "link")]
    Btf(btf::BtfError),

    /// A malformed image, or one written by another rvm version.
    InvalidImage(String),

    /// Linking error.
    Link(LinkError),

    /// Execution error.
    Exec(ExecError),

    /// Helper function error.
    Helper(HelperError),

    /// Memory access error.
    Memory(MemoryError),

    /// Function not found.
    FunctionNotFound(String),

    /// Invalid argument.
    InvalidArgument(String),

    /// The program's code, rodata or data (named) exceeds [`MAX_REGION_LEN`](crate::MAX_REGION_LEN) bytes.
    ProgramTooLarge(&'static str),

    /// The plugin is already running a call.
    PluginBusy(String),

    /// An export outlived the plugin it calls into.
    PluginUnloaded(String),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "link")]
            Self::Elf(msg) => write!(f, "ELF error: {msg}"),
            #[cfg(feature = "link")]
            Self::Btf(e) => write!(f, "BTF error: {e}"),
            Self::InvalidImage(msg) => write!(f, "invalid image: {msg}"),
            Self::Link(e) => write!(f, "link error: {e}"),
            Self::Exec(e) => write!(f, "execution error: {e}"),
            Self::Helper(e) => write!(f, "helper error: {e}"),
            Self::Memory(e) => write!(f, "memory error: {e}"),
            Self::FunctionNotFound(name) => write!(f, "function not found: {name}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::ProgramTooLarge(region) => {
                write!(f, "program {region} exceeds {} bytes", crate::memory::MAX_REGION_LEN)
            }
            Self::PluginBusy(name) => write!(f, "plugin {name} is already running a call"),
            Self::PluginUnloaded(name) => write!(f, "plugin {name} was unloaded"),
        }
    }
}

impl std::error::Error for VmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(feature = "link")]
        if let Self::Btf(e) = self {
            return Some(e);
        }
        None
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

impl From<HelperError> for VmError {
    fn from(e: HelperError) -> Self {
        Self::Helper(e)
    }
}

impl From<MemoryError> for VmError {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}

/// Linking errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// Unresolved symbol.
    UnresolvedSymbol(String),
    /// A call to a helper ID that isn't registered.
    UnknownHelper(u32),
    /// An extern's declared parameter count differs from the host function's.
    SignatureMismatch { name: String, declared: usize, host: u8 },
    /// A program declares a shared map with a different layout than the existing one.
    MapMismatch(String),
    /// Duplicate symbol.
    DuplicateSymbol(String),
    /// Invalid reference.
    InvalidReference(String),
    /// A map definition no program can use, or maps that don't fit in guest memory.
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
                write!(f, "extern {name} declares {declared} parameters but the host function takes {host}")
            }
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

/// Execution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// Invalid instruction.
    CpuFault,
    /// Memory fault.
    MemoryFault(String),
    /// Unimplemented instruction.
    Unimplemented,
    /// Instruction limit exceeded.
    #[cfg(feature = "fuel")]
    InstructionLimit(u64),
    /// Stack overflow.
    StackOverflow,
    /// Invalid program counter.
    InvalidPc(u64),
    /// Ran an instruction whose CO-RE relocation the host couldn't resolve.
    UnresolvedCoreRelo { pc: u64 },
    /// `callx` or `gotox` at `pc` targeted something other than an instruction in the program (or, for `callx`, a
    /// helper ID).
    BadCodeAddress { pc: u64, target: u64 },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuFault => write!(f, "invalid instruction"),
            Self::MemoryFault(msg) => write!(f, "memory fault: {msg}"),
            Self::Unimplemented => write!(f, "instruction not implemented"),
            #[cfg(feature = "fuel")]
            Self::InstructionLimit(count) => write!(f, "instruction limit exceeded: {count}"),
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::InvalidPc(pc) => write!(f, "invalid program counter: {pc}"),
            Self::UnresolvedCoreRelo { pc } => {
                write!(f, "instruction {pc} uses a type or field the host doesn't have (CO-RE)")
            }
            Self::BadCodeAddress { pc, target } => {
                write!(f, "instruction {pc} branches to {target:#x}, which is not an instruction in the program")
            }
        }
    }
}

impl std::error::Error for ExecError {}

/// Helper function errors.
#[derive(Debug)]
pub enum HelperError {
    /// Unknown helper ID.
    UnknownHelper(u32),
    /// Unknown extern table slot.
    UnknownSlot(u32),
    /// Helper returned an error.
    Failed(String),
    /// A call into a function another plugin exports failed.
    Plugin {
        plugin: String,
        func: String,
        error: Box<VmError>,
    },
}

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownHelper(id) => write!(f, "unknown helper: {id}"),
            Self::UnknownSlot(slot) => write!(f, "unknown extern slot: {slot}"),
            Self::Failed(msg) => write!(f, "helper failed: {msg}"),
            Self::Plugin { plugin, func, error } => write!(f, "{plugin}::{func}: {error}"),
        }
    }
}

impl std::error::Error for HelperError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plugin { error, .. } => Some(&**error),
            _ => None,
        }
    }
}

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
