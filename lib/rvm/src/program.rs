//! Linked eBPF program ready for execution.
//!
//! A `Program` is the result of linking one or more `Module`s together.
//! It contains the executable code, data, and function table.

use std::collections::HashMap;
use std::sync::Arc;

use rvm_core::Instruction;

use crate::error::{Result, VmError};
use crate::executor::Executor;
use crate::helper::{HelperRegistry, SharedHelpers};
use crate::maps::{MapRef, Maps};
use crate::memory::VmMemory;

/// Information about an executable function.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name.
    pub name: String,
    /// Program counter (instruction index) where the function starts.
    pub pc: u64,
    /// Size of the function in bytes.
    pub size: u64,
}

/// A linked eBPF program ready for execution.
///
/// Holds the code (outside guest memory), guest memory regions (stack, data),
/// and function table. Use `call()` to execute a function by name.
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
/// ```
#[derive(Debug)]
pub struct Program {
    /// Instructions; not addressable by the guest.
    code: Box<[Instruction]>,
    /// Guest memory regions (stack, data, maps). See [`crate::linker`] for the layout.
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
    instruction_limit: u64,
    /// Stack bytes per call frame.
    frame_size: u64,
}

impl Program {
    /// Create a new program. The linker is the usual caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: Box<[Instruction]>,
        memory: VmMemory,
        maps: Maps,
        functions: HashMap<String, FunctionInfo>,
        stack_top: u64,
        shared_helpers: Arc<SharedHelpers>,
        helpers: HelperRegistry,
        helpers_version: u64,
        instruction_limit: u64,
        frame_size: u64,
    ) -> Self {
        Self {
            code,
            memory,
            maps,
            functions,
            stack_top,
            shared_helpers,
            helpers,
            helpers_version,
            instruction_limit,
            frame_size,
        }
    }

    /// The program's instructions.
    pub fn code(&self) -> &[Instruction] {
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

    /// List all function names.
    pub fn function_names(&self) -> impl Iterator<Item = &str> {
        self.functions.keys().map(|s| s.as_str())
    }

    /// Check if a function exists.
    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    /// Get the entry point: "main" if it exists, otherwise the lowest-addressed function.
    pub fn entry_point(&self) -> Option<&FunctionInfo> {
        self.functions
            .get("main")
            .or_else(|| self.functions.values().min_by_key(|f| (f.pc, &f.name)))
    }

    /// Call a function by name; arguments go in r1-r5.
    pub fn call(&mut self, name: &str, args: &[u64]) -> Result<u64> {
        let pc = self
            .functions
            .get(name)
            .ok_or_else(|| VmError::FunctionNotFound(name.to_string()))?
            .pc;
        self.call_pc(pc, args)
    }

    /// Call the entry point function.
    pub fn run(&mut self, args: &[u64]) -> Result<u64> {
        let pc = self
            .entry_point()
            .ok_or_else(|| VmError::FunctionNotFound("no entry point".to_string()))?
            .pc;
        self.call_pc(pc, args)
    }

    fn call_pc(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        if self.shared_helpers.version() != self.helpers_version {
            (self.helpers, self.helpers_version) = self.shared_helpers.snapshot();
        }

        let mut executor = Executor::new(&self.code, &mut self.memory, &self.helpers, self.stack_top);
        executor.set_instruction_limit(self.instruction_limit);
        executor.set_frame_size(self.frame_size);
        executor.set_maps(&mut self.maps);
        executor.call(pc, args)
    }
}
