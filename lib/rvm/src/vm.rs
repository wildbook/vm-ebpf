//! The main VM entry point.
//!
//! The `Vm` struct is the central registry for helper functions, types,
//! and configuration. Use it to load modules and create linked programs.
//!
//! # Example
//!
//! ```ignore
//! use rvm::Vm;
//!
//! let mut vm = Vm::new();
//!
//! // Register a helper function
//! vm.register_helper(1, |x: u64| {
//!     println!("Got: {}", x);
//!     0u64
//! });
//!
//! // Register types for CO-RE
//! vm.types()
//!     .register_struct("event")
//!     .field("timestamp", 0, 8)
//!     .field("pid", 8, 4)
//!     .size(12);
//!
//! // Load and link a module
//! let module = vm.load_module("main", elf_bytes)?;
//! let program = vm.link(&[&module])?;
//!
//! // Execute a function
//! let result = program.call("my_func", &[42])?;
//! ```

use std::collections::HashMap;

use crate::error::{Result, VmError};
use crate::helper::{DynHelper, FromArgs, HelperRegistry, IntoReturn};
use crate::linker::Linker;
use crate::module::Module;
use crate::program::Program;
use crate::std_helpers;
use crate::types::TypeRegistry;

/// Configuration for the VM.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Maximum number of instructions to execute (0 = no limit).
    pub instruction_limit: u64,
    /// Stack size in bytes.
    pub stack_size: usize,
    /// Whether to enable debug output.
    pub debug: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            instruction_limit: 1_000_000,
            stack_size: 512,
            debug: false,
        }
    }
}

/// The main eBPF virtual machine.
///
/// This is the entry point for using the rvm library. It holds:
/// - Registered helper functions
/// - Type registry for CO-RE relocations
/// - Configuration
///
/// Use it to load modules and link them into executable programs.
pub struct Vm {
    /// Helper function registry.
    helpers: HelperRegistry,
    /// Type registry for CO-RE.
    types: TypeRegistry,
    /// VM configuration.
    config: VmConfig,
    /// Loaded modules.
    modules: HashMap<String, Module>,
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

impl Vm {
    /// Create a new VM with default configuration.
    pub fn new() -> Self {
        Self {
            helpers: HelperRegistry::new(),
            types: TypeRegistry::new(),
            config: VmConfig::default(),
            modules: HashMap::new(),
        }
    }

    /// Create a new VM with custom configuration.
    pub fn with_config(config: VmConfig) -> Self {
        Self {
            helpers: HelperRegistry::new(),
            types: TypeRegistry::new(),
            config,
            modules: HashMap::new(),
        }
    }

    /// Get the VM configuration.
    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    /// Get a mutable reference to the VM configuration.
    pub fn config_mut(&mut self) -> &mut VmConfig {
        &mut self.config
    }

    // =========================================================================
    // Helper Registration
    // =========================================================================

    /// Register a helper function with type-safe argument extraction.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Single argument
    /// vm.register_helper(1, |x: u64| x * 2);
    ///
    /// // Multiple arguments
    /// vm.register_helper(2, |(a, b): (u64, u64)| a + b);
    ///
    /// // No arguments
    /// vm.register_helper(3, |_: ()| 42u64);
    /// ```
    pub fn register_helper<F, A, R>(&mut self, id: u32, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.register(id, func);
    }

    /// Register a raw dynamic helper function.
    pub fn register_helper_raw(&mut self, id: u32, helper: DynHelper) {
        self.helpers.register_raw(id, helper);
    }

    /// Register an extern function that programs import by name
    /// (`extern u64 name(...);` in C). Unresolved names fail at link time.
    pub fn register_fn<F, A, R>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.register_fn(name, func);
    }

    /// Enable `ktime_get_ns` (helper 5).
    pub fn enable_time(&mut self) {
        std_helpers::register_time(&mut self.helpers);
    }

    /// Enable `get_prandom_u32` (helper 7).
    pub fn enable_random(&mut self) {
        std_helpers::register_random(&mut self.helpers);
    }

    /// Enable `trace_printk` (helper 6); each formatted line goes to `sink`.
    pub fn enable_print(&mut self, sink: impl Fn(&str) + Send + Sync + 'static) {
        std_helpers::register_print(&mut self.helpers, sink);
    }

    /// Get the helper registry.
    pub fn helpers(&self) -> &HelperRegistry {
        &self.helpers
    }

    /// Get a mutable reference to the helper registry.
    pub fn helpers_mut(&mut self) -> &mut HelperRegistry {
        &mut self.helpers
    }

    // =========================================================================
    // Type Registration (CO-RE)
    // =========================================================================

    /// Get the type registry for CO-RE support.
    ///
    /// # Example
    ///
    /// ```ignore
    /// vm.types()
    ///     .register_struct("event")
    ///     .field("timestamp", 0, 8)
    ///     .field("pid", 8, 4)
    ///     .size(12);
    /// ```
    pub fn types(&mut self) -> &mut TypeRegistry {
        &mut self.types
    }

    /// Get an immutable reference to the type registry.
    pub fn types_ref(&self) -> &TypeRegistry {
        &self.types
    }

    // =========================================================================
    // Module Loading
    // =========================================================================

    /// Load a module from ELF bytes.
    ///
    /// The module is parsed but not yet linked. Use `link()` to create
    /// an executable program from one or more modules.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let module = vm.load_module("main", &elf_bytes)?;
    /// ```
    pub fn load_module(&mut self, name: &str, elf_bytes: &[u8]) -> Result<&Module> {
        let module = Module::from_elf(name, elf_bytes)?;
        self.modules.insert(name.to_string(), module);
        self.modules
            .get(name)
            .ok_or_else(|| VmError::ModuleNotFound(name.to_string()))
    }

    /// Load a module and return it without storing in the VM.
    ///
    /// This is useful when you want to manage module lifetimes yourself.
    pub fn parse_module(&self, name: &str, elf_bytes: &[u8]) -> Result<Module> {
        Module::from_elf(name, elf_bytes)
    }

    /// Get a loaded module by name.
    pub fn module(&self, name: &str) -> Option<&Module> {
        self.modules.get(name)
    }

    /// Get all loaded modules.
    pub fn modules(&self) -> impl Iterator<Item = (&String, &Module)> {
        self.modules.iter()
    }

    // =========================================================================
    // Linking
    // =========================================================================

    /// Link modules into an executable program.
    ///
    /// This resolves all imports and exports between modules, applies
    /// relocations (including CO-RE), and produces a ready-to-execute program.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let utils = vm.parse_module("utils", &utils_elf)?;
    /// let main = vm.parse_module("main", &main_elf)?;
    ///
    /// // Link with dependency resolution
    /// let program = vm.link(&[&utils, &main])?;
    /// ```
    pub fn link(&self, modules: &[&Module]) -> Result<Program> {
        Linker::new(&self.helpers, &self.types, &self.config).link(modules)
    }

    /// Link a single module into a program.
    ///
    /// Convenience method for the common case of a single module.
    pub fn link_one(&self, module: &Module) -> Result<Program> {
        self.link(&[module])
    }

    // =========================================================================
    // Convenience Methods
    // =========================================================================

    /// Load, link, and prepare a single ELF file.
    ///
    /// This is a convenience method that combines `parse_module` and `link`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let program = vm.load_elf(&elf_bytes)?;
    /// let result = program.call("main", &[])?;
    /// ```
    pub fn load_elf(&self, elf_bytes: &[u8]) -> Result<Program> {
        let module = self.parse_module("main", elf_bytes)?;
        self.link_one(&module)
    }
}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("helpers", &self.helpers)
            .field("types", &format_args!("<TypeRegistry>"))
            .field("config", &self.config)
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_creation() {
        let vm = Vm::new();
        assert_eq!(vm.helpers().len(), 0);
    }

    #[test]
    fn test_helper_registration() {
        let mut vm = Vm::new();

        vm.register_helper(1, |x: u64| x * 2);
        vm.register_helper(2, |(a, b): (u64, u64)| a + b);

        assert!(vm.helpers().has(1));
        assert!(vm.helpers().has(2));
        assert!(!vm.helpers().has(3));
    }

    #[test]
    fn test_type_registration() {
        let mut vm = Vm::new();

        vm.types()
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("pid", 8, 4)
            .size(12);

        assert!(vm.types_ref().has_struct("event"));
        assert_eq!(vm.types_ref().field_offset("event", "pid"), Some(8));
    }
}
