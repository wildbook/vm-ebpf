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
use std::sync::Arc;

use crate::error::{Result, VmError};
use crate::helper::{DynHelper, FromArgs, IntoReturn, SharedHelpers};
use crate::linker::Linker;
use crate::maps::SharedMaps;
use crate::module::Module;
use crate::plugin::Plugin;
use crate::program::Program;
use crate::types::TypeRegistry;
use crate::{maps, std_helpers};

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
    /// Extern table shared with every program this VM links.
    helpers: Arc<SharedHelpers>,
    /// Maps shared by name between the programs this VM links.
    shared_maps: SharedMaps,
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
        Self::with_config(VmConfig::default())
    }

    /// Create a new VM with custom configuration.
    ///
    /// Only the map helpers (1 to 3) are registered; they touch nothing outside the VM.
    pub fn with_config(config: VmConfig) -> Self {
        let helpers = Arc::new(SharedHelpers::default());
        helpers.update(maps::register_helpers);
        Self {
            helpers,
            shared_maps: SharedMaps::default(),
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
    //
    // Changes reach programs linked earlier at their next call. Replacing a
    // function keeps its slot, so linked call sites stay valid.

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
    pub fn register_helper<F, A, R>(&self, id: u32, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.register(id, func));
    }

    /// Register a raw dynamic helper function.
    pub fn register_helper_raw(&self, id: u32, helper: DynHelper) {
        self.helpers.update(|h| h.register_raw(id, helper));
    }

    /// Register an extern function that programs import by name
    /// (`extern u64 name(...);` in C). Unresolved names fail at link time.
    pub fn register_fn<F, A, R>(&self, name: impl Into<String>, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.register_fn(name, func));
    }

    /// Enable `ktime_get_ns` (helper 5).
    pub fn enable_time(&self) {
        self.helpers.update(std_helpers::register_time);
    }

    /// Enable `get_prandom_u32` (helper 7).
    pub fn enable_random(&self) {
        self.helpers.update(std_helpers::register_random);
    }

    /// Enable `trace_printk` (helper 6); each formatted line goes to `sink`.
    pub fn enable_print(&self, sink: impl Fn(&str) + Send + Sync + 'static) {
        self.helpers.update(|h| std_helpers::register_print(h, sink));
    }

    /// The extern table shared with linked programs.
    pub fn helpers(&self) -> &SharedHelpers {
        &self.helpers
    }

    /// Share maps called `name` between every program linked afterwards: they bind to
    /// one instance, created by the first program that declares it, and later
    /// declarations must match its layout. `pad_values` puts each value on its own
    /// cache line, so atomics on neighbouring values from different threads don't
    /// contend.
    ///
    /// Values live at the same guest address in every program, from region
    /// [`crate::SHARED_MAPS_FIRST_REGION`] up.
    ///
    /// # Safety
    ///
    /// Programs that run at the same time on different threads may only touch the
    /// map's values with atomic instructions; plain guest loads and stores to a value
    /// another thread writes concurrently are a data race.
    pub unsafe fn share_map(&self, name: &str, pad_values: bool) {
        self.shared_maps.declare(name, pad_values);
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
        Linker::new(&self.helpers, &self.shared_maps, &self.types, &self.config).link(modules)
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

    // =========================================================================
    // Plugins
    // =========================================================================

    /// Load an ELF file as a plugin that other programs can call into.
    pub fn load_plugin(&self, name: &str, elf_bytes: &[u8]) -> Result<Plugin> {
        let module = self.parse_module(name, elf_bytes)?;
        Ok(Plugin::new(name, self.link_one(&module)?))
    }

    /// Publish `func` from `plugin` as an extern of the same name.
    ///
    /// Programs linked afterwards can import it; programs that already import it pick
    /// up the new target at their next call.
    pub fn export(&self, plugin: &Plugin, func: &str) -> Result<()> {
        if !plugin.lock()?.has_function(func) {
            return Err(VmError::FunctionNotFound(format!("{}::{func}", plugin.name())));
        }
        let helper = plugin.export_fn(func);
        self.helpers.update(|h| h.register_fn_raw(func, helper));
        Ok(())
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
