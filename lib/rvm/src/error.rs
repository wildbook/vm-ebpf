//! Error types for the rvm runtime.

use std::fmt;

/// Result type alias for rvm operations.
pub type Result<T> = std::result::Result<T, VmError>;

/// Errors that can occur in the rvm runtime.
#[derive(Debug)]
pub enum VmError {
    /// ELF parsing error.
    Elf(ElfError),

    /// BTF parsing error.
    Btf(btf::BtfError),

    /// CO-RE relocation error.
    CoreRelo(btf::CoreReloError),

    /// Linking error.
    Link(LinkError),

    /// Execution error.
    Exec(ExecError),

    /// Helper function error.
    Helper(HelperError),

    /// Memory access error.
    Memory(MemoryError),

    /// Module not found.
    ModuleNotFound(String),

    /// Function not found.
    FunctionNotFound(String),

    /// Symbol not found.
    SymbolNotFound(String),

    /// Invalid argument.
    InvalidArgument(String),

    /// The plugin is already running a call.
    PluginBusy(String),

    /// An export outlived the plugin it calls into.
    PluginUnloaded(String),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf(e) => write!(f, "ELF error: {e}"),
            Self::Btf(e) => write!(f, "BTF error: {e}"),
            Self::CoreRelo(e) => write!(f, "CO-RE relocation error: {e}"),
            Self::Link(e) => write!(f, "link error: {e}"),
            Self::Exec(e) => write!(f, "execution error: {e}"),
            Self::Helper(e) => write!(f, "helper error: {e}"),
            Self::Memory(e) => write!(f, "memory error: {e}"),
            Self::ModuleNotFound(name) => write!(f, "module not found: {name}"),
            Self::FunctionNotFound(name) => write!(f, "function not found: {name}"),
            Self::SymbolNotFound(name) => write!(f, "symbol not found: {name}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::PluginBusy(name) => write!(f, "plugin {name} is already running a call"),
            Self::PluginUnloaded(name) => write!(f, "plugin {name} was unloaded"),
        }
    }
}

impl std::error::Error for VmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Btf(e) => Some(e),
            Self::CoreRelo(e) => Some(e),
            _ => None,
        }
    }
}

impl From<btf::BtfError> for VmError {
    fn from(e: btf::BtfError) -> Self {
        Self::Btf(e)
    }
}

impl From<btf::CoreReloError> for VmError {
    fn from(e: btf::CoreReloError) -> Self {
        Self::CoreRelo(e)
    }
}

impl From<ElfError> for VmError {
    fn from(e: ElfError) -> Self {
        Self::Elf(e)
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

/// ELF loading errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// Invalid ELF format.
    InvalidFormat(String),
    /// Section not found.
    SectionNotFound(String),
    /// Invalid relocation.
    InvalidRelocation(String),
    /// Unsupported feature.
    Unsupported(String),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid ELF format: {msg}"),
            Self::SectionNotFound(name) => write!(f, "section not found: {name}"),
            Self::InvalidRelocation(msg) => write!(f, "invalid relocation: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
        }
    }
}

impl std::error::Error for ElfError {}

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
    /// Circular dependency.
    CircularDependency(String),
    /// Invalid reference.
    InvalidReference(String),
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
            Self::CircularDependency(msg) => write!(f, "circular dependency: {msg}"),
            Self::InvalidReference(msg) => write!(f, "invalid reference: {msg}"),
        }
    }
}

impl std::error::Error for LinkError {}

/// Execution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// CPU fault (invalid instruction, etc.).
    CpuFault(String),
    /// Memory fault.
    MemoryFault(String),
    /// Unimplemented instruction.
    Unimplemented(String),
    /// Instruction limit exceeded.
    InstructionLimit(u64),
    /// Stack overflow.
    StackOverflow,
    /// Invalid program counter.
    InvalidPc(u64),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuFault(msg) => write!(f, "CPU fault: {msg}"),
            Self::MemoryFault(msg) => write!(f, "memory fault: {msg}"),
            Self::Unimplemented(msg) => write!(f, "unimplemented: {msg}"),
            Self::InstructionLimit(count) => write!(f, "instruction limit exceeded: {count}"),
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::InvalidPc(pc) => write!(f, "invalid program counter: {pc}"),
        }
    }
}

impl std::error::Error for ExecError {}

/// Helper function errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    /// Unknown helper ID.
    UnknownHelper(u32),
    /// Unknown extern table slot.
    UnknownSlot(u32),
    /// Helper returned an error.
    Failed(String),
    /// Invalid arguments.
    InvalidArgs(String),
}

impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownHelper(id) => write!(f, "unknown helper: {id}"),
            Self::UnknownSlot(slot) => write!(f, "unknown extern slot: {slot}"),
            Self::Failed(msg) => write!(f, "helper failed: {msg}"),
            Self::InvalidArgs(msg) => write!(f, "invalid arguments: {msg}"),
        }
    }
}

impl std::error::Error for HelperError {}

/// Memory access errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    /// Out of bounds access.
    OutOfBounds { addr: u64, size: usize },
    /// Alignment error.
    Alignment { addr: u64, required: usize },
    /// Read-only memory.
    ReadOnly { addr: u64 },
    /// Allocation failed.
    AllocationFailed { size: usize },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds { addr, size } => {
                write!(f, "out of bounds: addr=0x{addr:x}, size={size}")
            }
            Self::Alignment { addr, required } => {
                write!(f, "alignment error: addr=0x{addr:x}, required={required}")
            }
            Self::ReadOnly { addr } => write!(f, "read-only memory: addr=0x{addr:x}"),
            Self::AllocationFailed { size } => write!(f, "allocation failed: size={size}"),
        }
    }
}

impl std::error::Error for MemoryError {}
