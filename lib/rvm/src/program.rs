//! Linked eBPF program ready for execution.
//!
//! A `Program` is the result of linking one or more `Module`s together.
//! It contains the executable code, data, and function table.

use std::collections::HashMap;

use crate::error::{Result, VmError};
use crate::executor::Executor;
use crate::helper::HelperRegistry;
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
/// Contains the memory layout (code + data + stack) and function table.
/// Use `call()` to execute a function by name.
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
    /// Program memory (code, data, stack).
    memory: VmMemory,
    /// Function table: name -> function info.
    functions: HashMap<String, FunctionInfo>,
    /// Stack top address (r10 initial value).
    stack_top: u64,
}

impl Program {
    /// Create a new program.
    pub fn new(memory: VmMemory, functions: HashMap<String, FunctionInfo>, stack_top: u64) -> Self {
        Self {
            memory,
            functions,
            stack_top,
        }
    }

    /// Get the memory region.
    pub fn memory(&self) -> &VmMemory {
        &self.memory
    }

    /// Get mutable access to memory.
    pub fn memory_mut(&mut self) -> &mut VmMemory {
        &mut self.memory
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

    /// Get the entry point (first function, or "main" if it exists).
    pub fn entry_point(&self) -> Option<&FunctionInfo> {
        // Prefer "main" if it exists
        if let Some(main) = self.functions.get("main") {
            return Some(main);
        }
        // Otherwise return the first function
        self.functions.values().next()
    }

    /// Call a function by name with no helpers.
    ///
    /// This is a convenience method that creates an empty helper registry.
    /// For programs that use helpers, use `call_with_helpers` instead.
    pub fn call(&mut self, name: &str, args: &[u64]) -> Result<u64> {
        let helpers = HelperRegistry::new();
        self.call_with_helpers(name, args, &helpers, u64::MAX)
    }

    /// Call a function with a helper registry.
    pub fn call_with_helpers(
        &mut self,
        name: &str,
        args: &[u64],
        helpers: &HelperRegistry,
        instruction_limit: u64,
    ) -> Result<u64> {
        let func = self
            .functions
            .get(name)
            .ok_or_else(|| VmError::FunctionNotFound(name.to_string()))?
            .clone();

        let mut executor = Executor::new(&mut self.memory, helpers, self.stack_top);
        executor.set_instruction_limit(instruction_limit);
        executor.call(func.pc, args)
    }

    /// Call the entry point function.
    pub fn run(&mut self, args: &[u64]) -> Result<u64> {
        let entry = self
            .entry_point()
            .ok_or_else(|| VmError::FunctionNotFound("no entry point".to_string()))?
            .clone();

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut self.memory, &helpers, self.stack_top);
        executor.call(entry.pc, args)
    }

    /// Run the entry point with helpers.
    pub fn run_with_helpers(&mut self, args: &[u64], helpers: &HelperRegistry, instruction_limit: u64) -> Result<u64> {
        let entry = self
            .entry_point()
            .ok_or_else(|| VmError::FunctionNotFound("no entry point".to_string()))?
            .clone();

        let mut executor = Executor::new(&mut self.memory, helpers, self.stack_top);
        executor.set_instruction_limit(instruction_limit);
        executor.call(entry.pc, args)
    }
}
