//! [`Vm`], the entry point. See the crate documentation for a usage example.

#[cfg(feature = "link")]
use std::cell::RefCell;
#[cfg(feature = "link")]
use std::sync::ReentrantLock;
use std::sync::{Arc, Mutex};

use crate::error::{Result, VmError};
use crate::executor::DEFAULT_FRAME_SIZE;
use crate::helper::{FromArgs, IntoReturn, SharedHelpers};
#[cfg(feature = "link")]
use crate::host_type::HostTypes;
use crate::image::{self, Image};
use crate::layout::{BORROW_FIRST_REGION, FIRST_FREE_REGION};
#[cfg(feature = "link")]
use crate::linker;
use crate::maps::SharedMaps;
use crate::memory::{GuestMemory, Perms, SharedBuffer, SharedRegion, MAX_REGION_LEN};
#[cfg(feature = "link")]
use crate::module::Module;
use crate::plugin::Plugin;
use crate::program::Program;
use crate::sync::lock;
use crate::{maps, std_helpers};

/// Configuration for the VM.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Maximum number of instructions to execute (0 = no limit).
    #[cfg(feature = "fuel")]
    pub instruction_limit: u64,
    /// Stack bytes reserved per call frame. Loading fails with [`VmError::InvalidArgument`] if the stack for
    /// [`MAX_CALL_DEPTH`](crate::MAX_CALL_DEPTH) nested calls exceeds [`MAX_REGION_LEN`] bytes.
    pub frame_size: u64,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "fuel")]
            instruction_limit: 1_000_000,
            frame_size: DEFAULT_FRAME_SIZE,
        }
    }
}

/// The entry point: holds the helper table, the host types for CO-RE, and the maps and regions shared between the
/// programs it links and loads.
pub struct Vm {
    /// Extern table shared with every program this VM links.
    helpers: Arc<SharedHelpers>,
    /// Maps shared by name between the programs this VM links.
    shared_maps: SharedMaps,
    /// Buffers mapped into every program this VM links.
    shared_regions: Mutex<Vec<SharedRegion>>,
    /// Host BTF the program's own BTF resolves CO-RE relocations against. Reentrant, so that a link inside
    /// [`Vm::with_types`] finds the cell borrowed and fails instead of deadlocking.
    #[cfg(feature = "link")]
    types: ReentrantLock<RefCell<HostTypes>>,
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
            types: ReentrantLock::default(),
            config,
        }
    }

    // =========================================================================
    // Helper Registration
    // =========================================================================
    //
    // Changes reach programs linked earlier at their next call. Replacing a function keeps its slot, so linked call
    // sites stay valid.

    /// Register a helper function with type-safe argument extraction.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Single argument
    /// vm.register_helper(100, |x: u64| x * 2);
    ///
    /// // Multiple arguments
    /// vm.register_helper(101, |(a, b): (u64, u64)| a + b);
    ///
    /// // No arguments
    /// vm.register_helper(102, |_: ()| 42u64);
    /// ```
    pub fn register_helper<F, A, R>(&self, id: u32, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.register_helper(id, func));
    }

    /// Register an extern function that programs import by name (`extern u64 name(...);` in C). Unresolved names fail
    /// at link time.
    pub fn register_fn<F, A, R>(&self, name: impl Into<String>, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.register_fn(name, func));
    }

    /// Register an extern function that reads or writes the calling program's memory, such as
    /// `void log(const char *msg, u64 len);` in C. `func` gets the program's memory, where every access needs the
    /// guest's permissions and fails on a bad pointer, followed by the typed arguments.
    ///
    /// # Example
    ///
    /// ```ignore
    /// vm.register_fn_with_memory("log", |mem, (msg, len): (u64, u64)| {
    ///     let msg = mem.read_vec(msg, len as usize)?;
    ///     println!("{}", String::from_utf8_lossy(&msg));
    ///     Ok::<_, rvm::MemoryError>(())
    /// });
    /// ```
    pub fn register_fn_with_memory<F, A, R>(&self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut GuestMemory, A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.register_fn_with_memory(name, func));
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

    /// Share maps called `name` between every program linked afterwards: they bind to one instance, created by the
    /// first program that declares it, and later declarations must match its layout. `pad_values` puts each value on
    /// its own cache line, so atomics on neighbouring values from different threads don't contend.
    ///
    /// Values live at the same guest address in every program, from region [`crate::SHARED_MAPS_FIRST_REGION`] up.
    ///
    /// # Safety
    ///
    /// As [`Vm::share_region`], for the maps' values.
    pub unsafe fn share_map(&self, name: &str, pad_values: bool) {
        self.shared_maps.declare(name, pad_values);
    }

    /// Allocate `len` zeroed bytes and map them as region `region` into every program linked afterwards, so plugins can
    /// exchange data through plain pointers. `region` must lie in `FIRST_FREE_REGION..BORROW_FIRST_REGION` and not be
    /// shared already.
    ///
    /// # Safety
    ///
    /// For every program linked afterwards: while a value from [`MapRef::entries`](crate::MapRef::entries) over a
    /// shared map is borrowed, neither another program that maps the map nor a [`SharedRegion`] over the region may
    /// access its bytes. Code on different threads may only touch bytes another thread writes concurrently with
    /// atomics, guest load-acquire and store-release among them; other guest stores, map helper writes and host writes
    /// all count as plain stores, and host reads, including [`GuestMemory`] and [`SharedRegion`] copies, as plain
    /// loads.
    pub unsafe fn share_region(&self, region: usize, len: usize, perms: Perms) -> Result<SharedRegion> {
        let mut regions = lock(&self.shared_regions);
        let invalid = |msg: String| Err(VmError::InvalidArgument(msg));
        if !(FIRST_FREE_REGION..BORROW_FIRST_REGION).contains(&region) {
            return invalid(format!("region {region} is outside {FIRST_FREE_REGION}..{BORROW_FIRST_REGION}"));
        }
        if regions.iter().any(|r| r.region() == region) {
            return invalid(format!("region {region} is already shared"));
        }
        if len == 0 || len > MAX_REGION_LEN {
            return invalid(format!("region length {len} is not in 1..={MAX_REGION_LEN}"));
        }
        let buffer = Arc::new(SharedBuffer::new(len));
        // SAFETY: the VM only maps its own handle and never reads or writes through it.
        let (own, host) =
            unsafe { (SharedRegion::new(region, perms, buffer.clone()), SharedRegion::new(region, perms, buffer)) };
        regions.push(own);
        Ok(host)
    }

    // =========================================================================
    // Loading
    // =========================================================================

    /// Load an image written by [`Image::to_bytes`] as a program; [`Vm::load`] with the parsed image.
    pub fn load_image(&self, bytes: &[u8]) -> Result<Program> {
        self.load(Image::from_bytes(bytes)?)
    }

    /// Load an image as a program: from `Vm::prepare`, [`Image::from_bytes`], or built by hand around raw bytecode,
    /// whose `call <id>` instructions reach the helpers registered here by ID.
    ///
    /// Binds the image's extern calls by name or helper ID in this VM, allocates its memory and maps, and maps the maps
    /// and regions this VM shares. Fails on a malformed image or an extern this VM lacks.
    ///
    /// # Example
    ///
    /// ```
    /// use rvm::{FunctionInfo, Image, Vm};
    ///
    /// // r0 = r1 + 10
    /// let code = [0xbf, 0x10, 0, 0, 0, 0, 0, 0, 0x07, 0, 0, 0, 10, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    /// let main = FunctionInfo { pc: 0, size: code.len() as u64, borrows: Vec::new() };
    /// let image = Image { code: code.to_vec(), functions: vec![("main".into(), main)], ..Image::default() };
    /// let mut program = Vm::new().load(image)?;
    /// assert_eq!(program.call("main", &[32])?, 42);
    /// # Ok::<_, rvm::VmError>(())
    /// ```
    pub fn load(&self, image: Image) -> Result<Program> {
        image::load(image, &self.helpers, &self.shared_maps, &lock(&self.shared_regions), &self.config)
    }

    /// Publish `func` from `plugin` as an extern of the same name.
    ///
    /// Programs linked afterwards can import it; programs that already import it pick up the new target at their next
    /// call.
    pub fn export(&self, plugin: &Plugin, func: &str) -> Result<()> {
        let helper = plugin.export_fn(func)?;
        self.helpers.update(|h| h.register_fn_raw(func, helper));
        Ok(())
    }
}

/// ELF parsing, CO-RE and linking.
#[cfg(feature = "link")]
impl Vm {
    /// Run `f` on the host's types, as BTF, for CO-RE; returns what `f` returns. Linking reads the same types, so a
    /// link or ELF load through this VM inside `f` fails with [`VmError::TypesBusy`], and `with_types` inside `f`
    /// panics.
    ///
    /// # Example
    ///
    /// ```
    /// #[repr(C)]
    /// struct Event {
    ///     timestamp: u64,
    ///     pid: u32,
    /// }
    ///
    /// let vm = rvm::Vm::new();
    /// vm.with_types(|types| rvm::host_struct!(types, Event as "event" { timestamp, pid }));
    /// ```
    pub fn with_types<R>(&self, f: impl FnOnce(&mut HostTypes) -> R) -> R {
        f(&mut self.types.lock().borrow_mut())
    }

    /// Link one ELF file into an image, to load later with [`Vm::load`] or, written out, [`Vm::load_image`].
    ///
    /// Externs and helper IDs must be registered here as they will be in the loading VM, so the link checks signatures
    /// and fails on unknown names early; CO-RE resolves against the types from [`Vm::with_types`].
    pub fn prepare(&self, elf_bytes: &[u8]) -> Result<Image> {
        let module = Module::from_elf("main", elf_bytes)?;
        self.prepare_modules(&[&module])
    }

    /// Link modules into one image, resolving symbols between them.
    pub fn prepare_modules(&self, modules: &[&Module]) -> Result<Image> {
        let types = self.types.lock();
        let types = types.try_borrow().map_err(|_| VmError::TypesBusy)?;
        linker::link(&self.helpers.read(), &types, modules)
    }

    /// Link modules into an executable program: [`Vm::prepare_modules`], then load.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let utils = Module::from_elf("utils", &utils_elf)?;
    /// let main = Module::from_elf("main", &main_elf)?;
    /// let program = vm.link(&[&utils, &main])?;
    /// ```
    pub fn link(&self, modules: &[&Module]) -> Result<Program> {
        self.load(self.prepare_modules(modules)?)
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
        let module = Module::from_elf(name, elf_bytes)?;
        Ok(Plugin::new(name, self.link(&[&module])?))
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
