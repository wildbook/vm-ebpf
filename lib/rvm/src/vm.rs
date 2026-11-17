//! The main VM entry point.
//!
//! The `Vm` struct is the central registry for helper functions, types,
//! and configuration. Use it to prepare images and load them as programs.
//! See the crate documentation for a usage example.

use std::sync::{Arc, Mutex};

#[cfg(feature = "link")]
use btf::BtfBuilder;

use crate::error::{Result, VmError};
use crate::executor::DEFAULT_FRAME_SIZE;
use crate::helper::{FromArgs, IntoReturn, SharedHelpers};
use crate::image::{self, Image};
use crate::layout::{BORROW_FIRST_REGION, FIRST_FREE_REGION};
#[cfg(feature = "link")]
use crate::linker;
use crate::maps::SharedMaps;
use crate::memory::{Perms, SharedBuffer, SharedRegion, MAX_REGION_LEN};
#[cfg(feature = "link")]
use crate::module::Module;
use crate::plugin::Plugin;
use crate::program::Program;
use crate::{maps, std_helpers};

/// Configuration for the VM.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Maximum number of instructions to execute (0 = no limit).
    #[cfg(feature = "fuel")]
    pub instruction_limit: u64,
    /// Stack bytes reserved per call frame.
    pub frame_size: usize,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "fuel")]
            instruction_limit: 1_000_000,
            frame_size: DEFAULT_FRAME_SIZE as usize,
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
    /// Buffers mapped into every program this VM links.
    shared_regions: Mutex<Vec<SharedRegion>>,
    /// Host BTF the program's own BTF resolves CO-RE relocations against.
    #[cfg(feature = "link")]
    types: BtfBuilder,
    /// VM configuration.
    config: VmConfig,
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
            shared_regions: Mutex::default(),
            #[cfg(feature = "link")]
            types: BtfBuilder::new(),
            config,
        }
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
    /// As [`VmMemory::map_shared`](crate::VmMemory::map_shared), for every program
    /// linked afterwards.
    pub unsafe fn share_map(&self, name: &str, pad_values: bool) {
        self.shared_maps.declare(name, pad_values);
    }

    /// Allocate `len` zeroed bytes and map them as region `region` into every program
    /// linked afterwards, so plugins can exchange data through plain pointers.
    /// `region` must lie in `FIRST_FREE_REGION..BORROW_FIRST_REGION` and not be
    /// shared already.
    ///
    /// # Safety
    ///
    /// As [`VmMemory::map_shared`](crate::VmMemory::map_shared), for every program
    /// linked afterwards.
    pub unsafe fn share_region(&self, region: usize, len: usize, perms: Perms) -> Result<SharedRegion> {
        let mut regions = self.shared_regions.lock().unwrap_or_else(|e| e.into_inner());
        let usable = (FIRST_FREE_REGION..BORROW_FIRST_REGION).contains(&region);
        if !usable || regions.iter().any(|r| r.region() == region) || len == 0 || len > MAX_REGION_LEN {
            return Err(VmError::InvalidArgument(format!("cannot share region {region} with {len} bytes")));
        }
        let shared = SharedRegion::new(region, perms, Arc::new(SharedBuffer::new(len)));
        regions.push(shared.clone());
        Ok(shared)
    }

    // =========================================================================
    // Loading
    // =========================================================================

    /// Load an image written by [`Image::to_bytes`] as a program.
    ///
    /// Binds the image's extern calls by name or helper ID in this VM, allocates
    /// its memory and maps, and maps the maps and regions this VM shares. Fails on
    /// a malformed image, one written by another rvm version, or an extern this VM
    /// lacks.
    pub fn load_image(&self, bytes: &[u8]) -> Result<Program> {
        self.load(Image::from_bytes(bytes)?)
    }

    /// Load an image as a plugin that other programs can call into.
    pub fn load_plugin_image(&self, name: &str, bytes: &[u8]) -> Result<Plugin> {
        Ok(Plugin::new(name, self.load_image(bytes)?))
    }

    fn load(&self, image: Image) -> Result<Program> {
        let shared_regions = self.shared_regions.lock().unwrap_or_else(|e| e.into_inner());
        image::load(image, &self.helpers, &self.shared_maps, &shared_regions, &self.config)
    }

    /// Publish `func` from `plugin` as an extern of the same name.
    ///
    /// Programs linked afterwards can import it; programs that already import it pick
    /// up the new target at their next call.
    pub fn export(&self, plugin: &Plugin, func: &str) -> Result<()> {
        if plugin.lock()?.function(func).is_none() {
            return Err(VmError::FunctionNotFound(format!("{}::{func}", plugin.name())));
        }
        let helper = plugin.export_fn(func);
        self.helpers.update(|h| h.register_fn_raw(func, helper));
        Ok(())
    }
}

/// ELF parsing, CO-RE and linking.
#[cfg(feature = "link")]
impl Vm {
    /// Get the host's BTF builder, for describing its types to CO-RE.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let event = vm.types().add_struct("event", 12);
    /// let u64_t = vm.types().int("u64", 8, false);
    /// let u32_t = vm.types().int("u32", 4, false);
    /// vm.types().member(event, "timestamp", 0, u64_t);
    /// vm.types().member(event, "pid", 8, u32_t);
    /// ```
    pub fn types(&mut self) -> &mut BtfBuilder {
        &mut self.types
    }

    /// Parse a module from ELF bytes, for [`Vm::link`] or [`Vm::prepare_modules`].
    pub fn parse_module(&self, name: &str, elf_bytes: &[u8]) -> Result<Module> {
        Module::from_elf(name, elf_bytes)
    }

    /// Link one ELF file into an image, to load later with [`Vm::load_image`].
    ///
    /// Externs and helper IDs must be registered here as they will be in the
    /// loading VM, so the link checks signatures and fails on unknown names early;
    /// CO-RE resolves against [`Vm::types`].
    pub fn prepare(&self, elf_bytes: &[u8]) -> Result<Image> {
        let module = self.parse_module("main", elf_bytes)?;
        self.prepare_modules(&[&module])
    }

    /// Link modules into one image, resolving symbols between them.
    pub fn prepare_modules(&self, modules: &[&Module]) -> Result<Image> {
        linker::link(&self.helpers.read(), &self.types, modules)
    }

    /// Link modules into an executable program: [`Vm::prepare_modules`], then load.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let utils = vm.parse_module("utils", &utils_elf)?;
    /// let main = vm.parse_module("main", &main_elf)?;
    /// let program = vm.link(&[&utils, &main])?;
    /// ```
    pub fn link(&self, modules: &[&Module]) -> Result<Program> {
        self.load(self.prepare_modules(modules)?)
    }

    /// Link a single module into a program.
    pub fn link_one(&self, module: &Module) -> Result<Program> {
        self.link(&[module])
    }

    /// Parse and link a single ELF file into a program.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let program = vm.load_elf(&elf_bytes)?;
    /// let result = program.call("main", &[])?;
    /// ```
    pub fn load_elf(&self, elf_bytes: &[u8]) -> Result<Program> {
        self.load(self.prepare(elf_bytes)?)
    }

    /// Load an ELF file as a plugin that other programs can call into.
    pub fn load_plugin(&self, name: &str, elf_bytes: &[u8]) -> Result<Plugin> {
        let module = self.parse_module(name, elf_bytes)?;
        Ok(Plugin::new(name, self.link_one(&module)?))
    }
}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("helpers", &self.helpers)
            .field("config", &self.config)
            .finish()
    }
}
