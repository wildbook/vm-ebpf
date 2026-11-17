//! Linked eBPF program ready for execution.
//!
//! A `Program` is a loaded [`crate::Image`]: the executable code, data, maps and
//! function table.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hashbrown::HashMap;
use rvm_core::Code;

use crate::error::{Result, VmError};
use crate::executor::Executor;
use crate::helper::{HelperRegistry, SharedHelpers};
use crate::layout::STACK_REGION;
use crate::maps::{MapRef, Maps};
use crate::memory::{region_base, VmMemory};
use crate::vm::VmConfig;

/// Information about an executable function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Program counter (instruction index) where the function starts.
    pub pc: u64,
    /// Size of the function in bytes.
    pub size: u64,
    /// Pointer parameters that callers in other plugins lend for one call.
    pub borrows: Vec<Borrow>,
}

/// A pointer parameter tagged `borrow:N` (writable) or `borrow_ro:N` in BTF, where
/// parameter `N` holds the buffer's length in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Borrow {
    pub arg: u8,
    pub len_arg: u8,
    pub writable: bool,
}

/// A function of one [`Program`], looked up by name once so that repeated calls skip
/// the lookup. See [`Program::func`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Func {
    program: u64,
    pc: u64,
}

/// A linked eBPF program ready for execution.
///
/// Holds the code (outside guest memory), guest memory regions (stack, data),
/// and function table. Use `call()` to execute a function by name, or look it up
/// once with `func()` and call it with `call_func()`.
///
/// # Example
///
/// ```ignore
/// let program = vm.load_elf(&elf_bytes)?;
///
/// // Call with no arguments
/// let result = program.call("main", &[])?;
///
/// // Call with arguments (passed in r1-r5)
/// let result = program.call("process", &[ctx_ptr, len])?;
///
/// // Skip the name lookup on repeated calls
/// let process = program.func("process")?;
/// let result = program.call_func(process, &[ctx_ptr, len])?;
/// ```
#[derive(Debug)]
pub struct Program {
    /// Tells this program's [`Func`] handles from other programs'.
    id: u64,
    /// Instructions; not addressable by the guest.
    code: Code,
    /// Guest memory regions (stack, data, maps). See [`crate::layout`] for the layout.
    memory: VmMemory,
    maps: Maps,
    /// Function table: name -> function info.
    functions: HashMap<String, FunctionInfo>,
    /// Stack top address (r10 initial value).
    stack_top: u64,
    /// The VM's extern table, and this program's copy of it at `helpers_version`.
    shared_helpers: Arc<SharedHelpers>,
    helpers: HelperRegistry,
    helpers_version: u64,
    /// Maximum instructions per call (0 = unlimited).
    #[cfg(feature = "fuel")]
    instruction_limit: u64,
    /// Stack bytes per call frame.
    frame_size: u64,
}

impl Program {
    /// Create a new program. Loading an image is the usual caller.
    pub fn new(
        code: Code,
        memory: VmMemory,
        maps: Maps,
        functions: HashMap<String, FunctionInfo>,
        shared_helpers: Arc<SharedHelpers>,
        helpers: (HelperRegistry, u64),
        config: &VmConfig,
    ) -> Self {
        let stack_top = region_base(STACK_REGION) + memory.region_len(STACK_REGION) as u64;
        let (helpers, helpers_version) = helpers;
        Self {
            id: NEXT_PROGRAM_ID.fetch_add(1, Ordering::Relaxed),
            code,
            memory,
            maps,
            functions,
            stack_top,
            shared_helpers,
            helpers,
            helpers_version,
            #[cfg(feature = "fuel")]
            instruction_limit: config.instruction_limit,
            frame_size: config.frame_size as u64,
        }
    }

    /// The program's code, prepared for execution.
    pub fn code(&self) -> &Code {
        &self.code
    }

    /// Get guest memory.
    pub fn memory(&self) -> &VmMemory {
        &self.memory
    }

    /// Get mutable access to memory.
    pub fn memory_mut(&mut self) -> &mut VmMemory {
        &mut self.memory
    }

    /// Host access to the map called `name`.
    pub fn map(&mut self, name: &str) -> Option<MapRef<'_>> {
        let handle = self.maps.handle(name)?;
        Some(MapRef::new(&mut self.maps, &mut self.memory, handle))
    }

    /// Get the function table.
    pub fn functions(&self) -> &HashMap<String, FunctionInfo> {
        &self.functions
    }

    /// Get information about a function by name.
    pub fn function(&self, name: &str) -> Option<&FunctionInfo> {
        self.functions.get(name)
    }

    /// Get the stack top address.
    pub fn stack_top(&self) -> u64 {
        self.stack_top
    }

    /// Call a function by name; arguments go in r1-r5.
    #[inline]
    pub fn call(&mut self, name: &str, args: &[u64]) -> Result<u64> {
        let pc = self.func(name)?.pc;
        self.call_pc(pc, args)
    }

    /// The function called `name`, for [`Program::call_func`].
    #[inline]
    pub fn func(&self, name: &str) -> Result<Func> {
        let info = self
            .functions
            .get(name)
            .ok_or_else(|| VmError::FunctionNotFound(name.to_string()))?;
        Ok(Func {
            program: self.id,
            pc: info.pc,
        })
    }

    /// Call a function looked up with [`Program::func`]; arguments go in r1-r5.
    ///
    /// A handle from another program fails with [`VmError::InvalidArgument`].
    #[inline]
    pub fn call_func(&mut self, func: Func, args: &[u64]) -> Result<u64> {
        if func.program != self.id {
            let msg = "function handle belongs to another program; look the function up again";
            return Err(VmError::InvalidArgument(msg.to_string()));
        }
        self.call_pc(func.pc, args)
    }

    #[inline]
    fn call_pc(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        if self.shared_helpers.version() != self.helpers_version {
            self.refresh_helpers();
        }

        let mut executor = Executor::new(&self.code, &mut self.memory, &self.helpers, self.stack_top);
        #[cfg(feature = "fuel")]
        executor.set_instruction_limit(self.instruction_limit);
        executor.set_frame_size(self.frame_size);
        executor.set_maps(&mut self.maps);
        executor.call(pc, args)
    }

    #[cold]
    #[inline(never)]
    fn refresh_helpers(&mut self) {
        (self.helpers, self.helpers_version) = self.shared_helpers.snapshot();
    }
}

/// A [`Func`] that follows its function into whichever program it is called with, for
/// handles that outlive the program they were looked up in. Callers serialize access
/// per slot, e.g. under a plugin's lock.
#[derive(Debug)]
pub struct FuncSlot {
    program: AtomicU64,
    pc: AtomicU64,
}

impl FuncSlot {
    pub fn new(func: Func) -> Self {
        Self {
            program: AtomicU64::new(func.program),
            pc: AtomicU64::new(func.pc),
        }
    }

    /// Call the function in `program`, looking `name` up again if the slot holds a
    /// function of another program.
    #[inline]
    pub fn call(&self, program: &mut Program, name: &str, args: &[u64]) -> Result<u64> {
        let mut pc = self.pc.load(Ordering::Relaxed);
        if self.program.load(Ordering::Relaxed) != program.id {
            pc = program.func(name)?.pc;
            self.pc.store(pc, Ordering::Relaxed);
            self.program.store(program.id, Ordering::Relaxed);
        }
        program.call_pc(pc, args)
    }
}

static NEXT_PROGRAM_ID: AtomicU64 = AtomicU64::new(0);
