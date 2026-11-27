//! [`Vm`], the entry point. See the crate documentation for a usage example.

#[cfg(feature = "link")]
use std::cell::RefCell;
use std::ptr::NonNull;
#[cfg(feature = "link")]
use std::sync::ReentrantLock;
use std::sync::{Arc, Mutex};

use rvm_core::{Native, NativeFn, NativeSig};

use crate::error::{Result, VmError};
use crate::executor::DEFAULT_FRAME_SIZE;
use crate::helper::{FromArgs, HelperRegistry, HostFn, IntoReturn, SharedHelpers};
#[cfg(feature = "link")]
use crate::host_type::HostTypes;
use crate::image::{self, Image};
use crate::layout::free_host_region;
#[cfg(feature = "link")]
use crate::linker;
#[cfg(feature = "maps")]
use crate::maps::{self, SharedMaps, ValueSpacing};
use crate::memory::{region_tag, GuestMemory, Perms, SharedBuffer, SharedRegion, VmMemory, MAX_REGION_LEN};
#[cfg(feature = "link")]
use crate::module::Module;
use crate::plugin::Plugin;
use crate::program::Program;
use crate::std_helpers;
use crate::sync::{lock, Published};

/// A [`VmConfig::instruction_limit`] for hosts that want one; [`VmConfig::default`] has none.
pub const DEFAULT_INSTRUCTION_LIMIT: u64 = 1_000_000;

/// [`VmConfig::memory_limit`] in [`VmConfig::default`].
pub const DEFAULT_MEMORY_LIMIT: usize = 256 << 20;

/// Configuration for the VM.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Maximum number of instructions one call into a program may execute, with 0 (the default) for no limit.
    /// Instructions that plugins run for it through their exports count too, so the limit covers the whole call tree;
    /// a plugin's own limit still caps the calls into it. Limits above `i64::MAX` count as `i64::MAX`. The count is
    /// exact: the interpreter charges a basic block as it enters it, but stops at the instruction the limit runs out
    /// at. A call without a limit counts nothing, and the plugins it calls run under their own limits. Without the
    /// `fuel` feature the interpreter doesn't count instructions, and [`Vm::with_config`] rejects any limit but 0.
    pub instruction_limit: u64,
    /// Stack bytes reserved per call frame. Loading fails with [`VmError::InvalidArgument`] if the stack for
    /// [`MAX_CALL_DEPTH`](crate::MAX_CALL_DEPTH) nested calls exceeds [`MAX_REGION_LEN`] bytes.
    pub frame_size: u64,
    /// Most bytes one program may allocate: its code, stack, data, map values and hash map keys, the shared maps it
    /// creates included. Linking and loading check it before they allocate and fail with [`VmError::MemoryLimit`].
    pub memory_limit: usize,
    /// Whether guests reach host memory through raw pointers; off by default. See [`Passthrough::on`]. A
    /// [`Loader`] sets it for one program.
    pub passthrough: Passthrough,
    /// Whether a `callx` through a raw address calls native code; off by default. See [`RawCalls::on`]. A
    /// [`Loader`] sets it for one program.
    pub raw_calls: RawCalls,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            instruction_limit: 0,
            frame_size: DEFAULT_FRAME_SIZE,
            memory_limit: DEFAULT_MEMORY_LIMIT,
            passthrough: Passthrough::OFF,
            raw_calls: RawCalls::OFF,
        }
    }
}

/// Whether a program reaches host memory through raw pointers, for [`VmConfig::passthrough`] and
/// [`Loader::passthrough`].
///
/// A guest address is the host address of its byte with the region's index as a tag in the top bits (see
/// [`region_tag`](crate::region_tag)), and the untagged addresses form region 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Passthrough(Mode);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Off,
    On,
    Untagged,
}

impl Passthrough {
    /// A guest address without a region tag faults, as any unmapped address does.
    pub const OFF: Self = Self(Mode::Off);

    /// A guest address without a region tag, from [`RAW_START`](crate::RAW_START) (64 KiB) up to
    /// [`RAW_END`](crate::RAW_END) (2^47), is the host address: the guest's loads, stores and atomics there go straight
    /// to host memory, unchecked. A host hands a guest such a pointer as a plain integer, in a helper's return value or
    /// a field of a host struct the guest reads. Addresses below 64 KiB still fault, so null pointers and small
    /// offsets from them stay guest faults.
    ///
    /// Everything else keeps its region: the stack, data, maps, borrows and shared regions have their bounds,
    /// permissions and faults as before. Host functions see the guest's view: [`GuestMemory`] and the map helpers
    /// accept raw pointers, for keys and values too, and [`VmMemory::bytes`](crate::VmMemory::bytes) refuses those
    /// outside the program's regions.
    ///
    /// # Safety
    ///
    /// Every program loaded with it can read and write any memory of the process it can name, as native code
    /// could, with nothing checking what it does. The host must make sure that every access a guest makes through a
    /// raw address is sound: that the memory is mapped, that the guest's writes keep the host's values valid, and that
    /// they don't race other threads or conflict with references the host holds. A guest that strips the tag of one of
    /// its pointers, truncates it to 32 bits or computes a pointer from an integer reaches whatever host memory lies
    /// there.
    ///
    /// The interpreter reaches a raw address through a pointer of exposed provenance
    /// ([`std::ptr::with_exposed_provenance_mut`]), so the host must expose the provenance of each pointer it hands a
    /// guest, which casting it to an integer with `as` does.
    pub const unsafe fn on() -> Self {
        Self(Mode::On)
    }

    /// [`on`](Self::on), and every region's tag is 0: guest pointers into the stack, data, maps and shared regions
    /// are plain host addresses too, and every guest access goes through region 0. No bounds or permissions hold for
    /// guest accesses then, the program's own memory included; the regions only tell the host functions apart.
    ///
    /// # Safety
    ///
    /// As [`on`](Self::on), for every guest access.
    pub const unsafe fn untagged() -> Self {
        Self(Mode::Untagged)
    }

    /// Whether guests reach host memory through raw pointers.
    pub const fn is_on(self) -> bool {
        !matches!(self.0, Mode::Off)
    }

    /// Whether guest pointers carry no tags.
    pub(crate) const fn is_untagged(self) -> bool {
        matches!(self.0, Mode::Untagged)
    }

    /// The guest address of the host byte at `ptr` in region `idx`.
    pub(crate) fn address(self, idx: usize, ptr: NonNull<u8>) -> u64 {
        let tag = match self.0 {
            Mode::Untagged => 0,
            _ => region_tag(idx),
        };
        tag | ptr.addr().get() as u64
    }
}

/// Whether a `callx` of a program calls native code through a raw address, for [`VmConfig::raw_calls`] and
/// [`Loader::raw_calls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawCalls(bool);

impl RawCalls {
    /// A `callx` through an address without a region tag calls the helper with that ID, and fails with
    /// [`ExecError::UnknownHelper`](crate::ExecError::UnknownHelper) or
    /// [`ExecError::BadCodeAddress`](crate::ExecError::BadCodeAddress) if there is none.
    pub const OFF: Self = Self(false);

    /// A `callx` through an address without a region tag, from [`RAW_START`](crate::RAW_START) (64 KiB) up to
    /// [`RAW_END`](crate::RAW_END) (2^47), calls the native function at that address: a function pointer that the
    /// host put in a struct, passed as an argument or returned from a host function. The call passes r1 to r5 in the
    /// Windows x64 convention, the first four also in xmm0 to xmm3, and puts rax in r0. In a program that passes a
    /// sixth argument on the stack in any call, it also passes the seven stack arguments of the calling function as
    /// arguments 6 to 12, as that function stored them last. It works with every [`Passthrough`] mode.
    ///
    /// The addresses of the program's own functions keep their meaning, and so do helper IDs below 64 KiB. A helper
    /// ID from 64 KiB up is reachable through `call <id>` only.
    ///
    /// - Arguments reach the function as the registers hold them. Nothing declares what a `callx` passes, so no
    ///   pointer is checked or converted: a pointer into the program's memory keeps its region tag, unless the
    ///   program is [untagged](Passthrough::untagged) or strips the tag itself (`UNTAG` in `bpf/rvm_bpf.h`).
    /// - The function runs unmetered: its call counts as one instruction against the instruction limit, and nothing
    ///   interrupts it.
    /// - A function that calls back into the plugin that called it gets [`VmError::PluginBusy`].
    /// - Control Flow Guard doesn't check the call.
    ///
    /// # Safety
    ///
    /// The program is as trusted as native code, whatever its [`Passthrough`] mode: it can call any address in the
    /// process with any arguments, and nothing validates the target. A `callx` through an address that isn't a
    /// function, such as a data pointer of an untagged program, runs the bytes there. The host must make sure that
    /// every call the program makes is sound: that the target is a function of the Windows x64 convention, that it is
    /// sound for the arguments it gets, on the thread that runs the program, and that it stays loaded during the call.
    ///
    /// The functions the program calls must never unwind: no Rust panic with an unwinding ABI, C++ exception, SEH
    /// unwind or `longjmp` may leave them.
    pub const unsafe fn on() -> Self {
        Self(true)
    }

    /// Whether a `callx` calls native code through a raw address.
    pub const fn is_on(self) -> bool {
        self.0
    }
}

/// The entry point: holds the host functions, the host types for CO-RE, and the maps and regions shared between the
/// programs it links and loads.
pub struct Vm {
    /// Extern table shared with every program this VM links.
    helpers: Arc<SharedHelpers>,
    /// Maps and regions shared between the programs this VM links.
    shared: Shared,
    /// Host BTF the program's own BTF resolves CO-RE relocations against. Reentrant, so that a link inside
    /// [`Vm::with_types`] finds the cell borrowed and fails instead of deadlocking.
    #[cfg(feature = "link")]
    types: ReentrantLock<RefCell<HostTypes>>,
    config: VmConfig,
}

impl Default for Vm {
    fn default() -> Self {
        Self::new()
    }
}

impl Vm {
    /// A VM with [`VmConfig::default`].
    pub fn new() -> Self {
        Self::build(VmConfig::default())
    }

    /// A VM with `config`. Its only helpers are the map helpers with the `maps` feature, which touch nothing outside
    /// the VM. Without the `fuel` feature, a non-zero [`VmConfig::instruction_limit`] fails with
    /// [`VmError::FuelNotEnabled`].
    pub fn with_config(config: VmConfig) -> Result<Self> {
        Self::check(&config)?;
        Ok(Self::build(config))
    }

    /// [`with_config`](Self::with_config) with `natives` registered as [`register_native`](Self::register_native)
    /// registers each, without the lock that later registrations take.
    ///
    /// # Safety
    ///
    /// As [`register_native`](Self::register_native), for each function.
    pub unsafe fn with_natives(config: VmConfig, natives: &[(&str, *const (), NativeSig)]) -> Result<Self> {
        Self::check(&config)?;
        let mut registry = HelperRegistry::default();
        for &(name, func, sig) in natives {
            registry.put_native(name.to_string(), native(name, func, sig)?)?;
        }
        Ok(Self::with_registry(config, registry))
    }

    fn check(config: &VmConfig) -> Result<()> {
        match !rvm_core::METERED && config.instruction_limit != 0 {
            true => Err(VmError::FuelNotEnabled),
            false => Ok(()),
        }
    }

    fn build(config: VmConfig) -> Self {
        Self::with_registry(config, HelperRegistry::default())
    }

    fn with_registry(
        config: VmConfig,
        #[cfg_attr(not(feature = "maps"), expect(unused_mut))] mut registry: HelperRegistry,
    ) -> Self {
        #[cfg(feature = "maps")]
        maps::register_helpers(&mut registry);
        Self {
            helpers: Arc::new(SharedHelpers::new(registry)),
            shared: Shared::default(),
            #[cfg(feature = "link")]
            types: ReentrantLock::default(),
            config,
        }
    }

    // Host functions: changes reach programs linked earlier at their next call. Replacing a function keeps its slot,
    // so linked call sites stay valid.

    /// Register a host function that programs call by helper ID (`call <id>`). `func` takes the arguments as a `u64`,
    /// a tuple of up to five, or `()`: a call by ID passes r1 to r5 only, and a longer tuple gets 0 in the rest. With
    /// the `maps` feature, IDs 1 to 3 replace the built-in map helpers.
    ///
    /// # Example
    ///
    /// ```
    /// let vm = rvm::Vm::new();
    /// vm.register_helper(100, |x: u64| x * 2);
    /// vm.register_helper(101, |(a, b): (u64, u64)| a + b);
    /// vm.register_helper(102, |_: ()| 42u64);
    /// ```
    pub fn register_helper<F, A, R>(&self, id: u32, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.put_id(id, HostFn::typed(func)));
    }

    /// [`register_helper`](Self::register_helper) for a function that reads or writes the calling program's memory;
    /// see [`register_extern_with_memory`](Self::register_extern_with_memory).
    pub fn register_helper_with_memory<F, A, R>(&self, id: u32, func: F)
    where
        F: Fn(&mut GuestMemory, A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.put_id(id, HostFn::with_memory(func)));
    }

    /// Register a host function that programs import by name (`extern u64 name(u64 a, u64 b);` in C). `func` takes
    /// the arguments as a `u64`, a tuple of up to twelve, or `()`. A program that imports a name the VM lacks fails
    /// to link.
    ///
    /// Each argument is one register, or from the sixth on one 8-byte slot of the caller's stack arguments, and
    /// linking checks their number against the extern's BTF. A struct of up to 8 bytes arrives in one argument and
    /// one of 9 to 16 bytes in two, little endian. An argument that C declares narrower than 64 bits has its value
    /// in the low bits, and the bits above 32 are not defined: cast it to the declared type.
    ///
    /// The result follows clang 23. Up to 8 bytes come back in r0, so `func` returns a struct of that size as an
    /// integer. A struct of 9 to 16 bytes comes back in r0 and r2, so `func` returns `(u64, u64)`, bytes 0 to 7
    /// first, and linking fails for a function that returns one register where the extern takes two, or the reverse.
    /// For a larger struct the guest passes the address to write it to as the first argument, which needs
    /// [`register_extern_with_memory`](Self::register_extern_with_memory).
    ///
    /// # Example
    ///
    /// ```
    /// let vm = rvm::Vm::new();
    /// vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);
    /// ```
    pub fn register_extern<F, A, R>(&self, name: impl Into<String>, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.update(|h| h.put_name(name.into(), HostFn::typed(func)));
    }

    /// [`register_extern`](Self::register_extern) for a function that reads or writes the calling program's memory,
    /// such as `void log(const char *msg, u64 len);` in C. `func` gets the program's memory, where every access needs
    /// the guest's permissions and fails on a bad pointer, followed by the arguments. An `Err` from `func` fails the
    /// program's call with [`HostError::Failed`](crate::HostError::Failed).
    ///
    /// # Example
    ///
    /// ```
    /// let vm = rvm::Vm::new();
    /// vm.register_extern_with_memory("log", |mem, (msg, len): (u64, u64)| {
    ///     let msg = mem.read_vec(msg, len as usize)?;
    ///     println!("{}", String::from_utf8_lossy(&msg));
    ///     Ok::<_, rvm::MemoryError>(())
    /// });
    /// ```
    pub fn register_extern_with_memory<F, A, R>(&self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut GuestMemory, A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers
            .update(|h| h.put_name(name.into(), HostFn::with_memory(func)));
    }

    /// Register `func`, a native function that programs import by name as they import a host function
    /// (`extern u64 name(...);` in C), and that the interpreter calls directly in the Windows x64 convention, its
    /// result in r0: with r1 to r5, and for a function of 6 to 12 arguments also with the stack arguments of the
    /// caller. `sig` says which arguments are pointers to guest bytes, and how many bytes.
    ///
    /// Linking checks the extern's BTF against `sig`: the same number of argument registers, integers or enums where
    /// `sig` has integers and pointers where it has pointers, nothing else, and on a pointer that a `BORROW` or
    /// `BORROW_RO` tag marks, the same length argument and access. The extern may return nothing, an integer, a
    /// pointer, or a struct of 1, 2, 4 or 8 bytes, which the convention returns in rax; every other struct fails to
    /// link. An image records `sig`, and loading it checks `sig` against the loading VM's. Registering a name again
    /// replaces the function, which programs linked earlier call from their next call on; it fails with
    /// [`VmError::InvalidArgument`] if `sig` differs, as it does for a null `func`. A name with both a native and a
    /// host function binds to the native.
    ///
    /// Pointer arguments: unless the program's [`Passthrough`] is `untagged`, a call checks each pointer that `sig`
    /// declares before it calls `func`. The guest must be allowed to read the bytes, and for [`NativeArg::Write`](crate::NativeArg::Write) to
    /// write them too: one byte at the pointer, or as many as its length argument holds. `func` then gets the host
    /// address of the bytes, and a failed check stops the guest's call with
    /// [`ExecError::MemoryFault`](crate::ExecError::MemoryFault) at the call. Untagged, every argument reaches `func`
    /// as the register holds it. Pointers inside guest memory, such as the fields of a struct the guest fills, keep
    /// their region tags, so a function that follows them needs `untagged`. A returned pointer reaches the guest as the
    /// host address, which guest loads and stores resolve only with [`Passthrough::on`] or `untagged`.
    ///
    /// `func` runs unmetered: its call counts as one instruction against the instruction limit, and nothing
    /// interrupts it. It has no way to fail the guest's call, and one that calls back into the plugin that called it
    /// gets [`VmError::PluginBusy`].
    ///
    /// # Safety
    ///
    /// `func` must:
    /// - be callable as `unsafe extern "win64" fn(u64, ...) -> u64` with the `sig.args()` integer or pointer arguments,
    ///   returning in rax;
    /// - never unwind: no Rust panic with an unwinding ABI, C++ exception, SEH unwind or `longjmp` may leave it;
    /// - stay loaded while any call of it may run, one that started before it was replaced included;
    /// - be safe to run on any thread, on several at once;
    /// - stay sound for any argument values the guest passes. The checks cover only the pointers `sig` declares, and
    ///   none in `untagged` mode, so integer arguments and the contents of guest memory are the guest's choice.
    ///
    /// # Example
    ///
    /// ```
    /// use rvm::{NativeArg, NativeSig, Vm};
    ///
    /// extern "win64" fn add(a: u64, b: u64) -> u64 {
    ///     a.wrapping_add(b)
    /// }
    ///
    /// // Fills `len` bytes at `buf` with `byte`.
    /// unsafe extern "win64" fn fill(buf: *mut u8, len: u64, byte: u64) -> u64 {
    ///     unsafe { buf.write_bytes(byte as u8, len as usize) };
    ///     0
    /// }
    ///
    /// const FILL: NativeSig = NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int, NativeArg::Int]);
    ///
    /// let vm = Vm::new();
    /// // SAFETY: both take their arguments in the Windows x64 convention and never unwind, and `fill` writes only
    /// // the bytes the call checks, which it does with passthrough off.
    /// unsafe {
    ///     vm.register_native("add", add as *const (), NativeSig::ints(2))?;
    ///     vm.register_native("fill", fill as *const (), FILL)?;
    /// }
    /// # Ok::<_, rvm::VmError>(())
    /// ```
    pub unsafe fn register_native(&self, name: impl Into<String>, func: *const (), sig: NativeSig) -> Result<()> {
        let name = name.into();
        let native = native(&name, func, sig)?;
        self.helpers.update(|h| h.put_native(name, native))
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
    /// first program that declares it, and later declarations must match its layout.
    ///
    /// Values live at the same guest address in every program of one [`Passthrough`] mode, from region
    /// [`crate::SHARED_MAPS_FIRST_REGION`] up.
    ///
    /// # Safety
    ///
    /// As [`Vm::share_region`], for the maps' values.
    #[cfg(feature = "maps")]
    pub unsafe fn share_map(&self, name: &str, spacing: ValueSpacing) {
        self.shared.maps.declare(name, spacing);
    }

    /// Allocate `len` zeroed bytes and map them at a free host region, at the same guest address in every program
    /// of one [`Passthrough`] mode that is linked afterwards, so plugins can exchange data through plain pointers.
    /// The region stays shared as long as the VM lives, and programs linked afterwards can't map their own memory
    /// there. Fails with [`VmError::NoFreeRegion`] if the VM shares every host region already, and with
    /// [`VmError::InvalidArgument`] unless `len` is in `1..=`[`MAX_REGION_LEN`].
    ///
    /// # Safety
    ///
    /// For every program linked afterwards: while a value from `MapRef::entries` over a shared map is borrowed,
    /// neither another program that maps the map nor a [`SharedRegion`] over the region may access its bytes. Code on
    /// different threads may only touch bytes another thread writes concurrently with atomics, guest load-acquire and
    /// store-release among them; other guest stores, map helper writes and host writes all count as plain stores, and
    /// host reads, including [`GuestMemory`] and [`SharedRegion`] copies, as plain loads.
    ///
    /// # Example
    ///
    /// ```
    /// use rvm::{Image, Perms, Vm};
    ///
    /// let vm = Vm::new();
    /// // SAFETY: the program runs on this thread only.
    /// let mut shared = unsafe { vm.share_region(64, Perms::R) }?;
    /// shared.write(0, 42u64)?;
    ///
    /// // r0 = *(u64 *)r1
    /// let code = [0x79, 0x10, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    /// let mut program = vm.load_image(Image::from_code(code.to_vec()))?;
    /// assert_eq!(program.call("main", &[shared.base()])?, 42);
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub unsafe fn share_region(&self, len: usize, perms: Perms) -> Result<SharedRegion> {
        self.shared.regions.add(len, perms, self.config.passthrough)
    }

    /// Load an image as a program: from `Vm::prepare_elf` (with the `link` feature), [`Image::from_bytes`], or built by
    /// hand around raw bytecode, whose `call <id>` instructions reach the helpers registered here by ID.
    ///
    /// Binds the image's extern calls by name or helper ID in this VM, allocates its memory and maps, and maps the maps
    /// and regions this VM shares. Fails on a malformed image or an extern this VM lacks.
    ///
    /// # Example
    ///
    /// ```
    /// use rvm::{Image, Vm};
    ///
    /// // r0 = r1 + 10
    /// let code = [0xbf, 0x10, 0, 0, 0, 0, 0, 0, 0x07, 0, 0, 0, 10, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    /// let mut program = Vm::new().load_image(Image::from_code(code.to_vec()))?;
    /// assert_eq!(program.call("main", &[32])?, 42);
    /// # Ok::<_, rvm::VmError>(())
    /// ```
    pub fn load_image(&self, image: Image) -> Result<Program> {
        image::load(image, &self.helpers, &self.shared, &self.config)
    }

    /// [`load_image`](Self::load_image) straight from the bytes [`Image::to_bytes`] wrote, without the copy that
    /// [`Image::from_bytes`] makes.
    pub fn load_image_bytes(&self, bytes: &[u8]) -> Result<Program> {
        image::load_bytes(bytes, &self.helpers, &self.shared, &self.config)
    }

    /// A [`Loader`], which loads programs with a [`Passthrough`] mode or a [`RawCalls`] switch other than this VM's.
    pub fn loader(&self) -> Loader<'_> {
        Loader {
            vm: self,
            config: self.config.clone(),
        }
    }

    /// Publish `func` from `plugin` as an extern of the same name.
    ///
    /// Programs linked afterwards can import it; programs that already import it pick up the new target at their next
    /// call. A call passes up to 12 arguments: those past the fifth reach `func` where the importing program has BTF
    /// that declares them. The caller gets r0, so a result of up to 8 bytes: an import that declares a struct of 9 to
    /// 16 bytes as the result fails to link with [`LinkError::ReturnMismatch`](crate::LinkError::ReturnMismatch).
    pub fn export(&self, plugin: &Plugin, func: &str) -> Result<()> {
        let export = HostFn::raw_stack(plugin.export_fn(func)?);
        self.helpers.update(|h| h.put_name(func.to_string(), export));
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

    /// Link one ELF file into an image, to load later with [`Vm::load_image`] or, written out,
    /// [`Vm::load_image_bytes`].
    ///
    /// Externs and helper IDs must be registered here as they will be in the loading VM, so the link checks signatures
    /// and fails on unknown names early; CO-RE resolves against the types from [`Vm::with_types`].
    pub fn prepare_elf(&self, elf_bytes: &[u8]) -> Result<Image> {
        let module = Module::from_elf(elf_bytes)?;
        self.prepare_modules(&[&module])
    }

    /// Link modules into one image, resolving symbols between them.
    pub fn prepare_modules(&self, modules: &[&Module]) -> Result<Image> {
        let types = self.types.lock();
        let types = types.try_borrow().map_err(|_| VmError::TypesBusy)?;
        linker::link(&self.helpers.read(), &types, modules, self.config.memory_limit)
    }

    /// Link modules into an executable program: [`Vm::prepare_modules`], then [`Vm::load_image`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let utils = Module::from_elf(&utils_elf)?;
    /// let main = Module::from_elf(&main_elf)?;
    /// let program = vm.load_modules(&[&utils, &main])?;
    /// ```
    pub fn load_modules(&self, modules: &[&Module]) -> Result<Program> {
        self.load_image(self.prepare_modules(modules)?)
    }

    /// Parse and link a single ELF file into a program: [`Vm::prepare_elf`], then [`Vm::load_image`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut program = vm.load_elf(&elf_bytes)?;
    /// let result = program.call("main", &[])?;
    /// ```
    pub fn load_elf(&self, elf_bytes: &[u8]) -> Result<Program> {
        self.load_image(self.prepare_elf(elf_bytes)?)
    }
}

/// Loads programs into a [`Vm`] with a [`Passthrough`] mode and a [`RawCalls`] switch of their own; from
/// [`Vm::loader`]. Both start as the VM's.
///
/// # Example
///
/// ```
/// use rvm::{Image, Passthrough, Vm};
///
/// // r0 = *(u64 *)r1
/// let code = [0x79, 0x10, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
/// let value = 42u64;
/// let addr = &raw const value as u64;
///
/// let vm = Vm::new();
/// // SAFETY: the program reads only `value` through a raw pointer
/// let passthrough = unsafe { Passthrough::on() };
/// let mut trusted = vm.loader().passthrough(passthrough).load_image(Image::from_code(code.to_vec()))?;
/// assert_eq!(trusted.call("main", &[addr])?, 42);
///
/// // the VM's own mode checks every address
/// let mut checked = vm.load_image(Image::from_code(code.to_vec()))?;
/// assert!(checked.call("main", &[addr]).is_err());
/// # Ok::<_, rvm::VmError>(())
/// ```
pub struct Loader<'a> {
    vm: &'a Vm,
    /// The VM's, but for the passthrough mode and the raw calls switch.
    config: VmConfig,
}

impl Loader<'_> {
    /// Load with `passthrough` instead of [`VmConfig::passthrough`].
    ///
    /// Programs of different modes work in one VM. Each program gets the addresses of its own memory, of its maps,
    /// of the shared regions and of the buffers it borrows in its own mode, so calls between plugins, borrows and
    /// shared maps work across modes. A pointer that a program stores in shared memory or passes to another plugin
    /// as a plain argument is an address in its own mode, which only programs of the same mode can follow. Another
    /// program faults on it, and one with [`Passthrough::on`] follows the host address that an untagged program
    /// stored, unchecked. [`SharedRegion::base`] is a shared region's address in the VM's mode, and
    /// [`SharedRegion::base_for`] its address in another.
    pub fn passthrough(mut self, passthrough: Passthrough) -> Self {
        self.config.passthrough = passthrough;
        self
    }

    /// Load with `raw_calls` instead of [`VmConfig::raw_calls`].
    pub fn raw_calls(mut self, raw_calls: RawCalls) -> Self {
        self.config.raw_calls = raw_calls;
        self
    }

    /// [`Vm::load_image`].
    pub fn load_image(&self, image: Image) -> Result<Program> {
        image::load(image, &self.vm.helpers, &self.vm.shared, &self.config)
    }

    /// [`Vm::load_image_bytes`].
    pub fn load_image_bytes(&self, bytes: &[u8]) -> Result<Program> {
        image::load_bytes(bytes, &self.vm.helpers, &self.vm.shared, &self.config)
    }

    /// [`Vm::load_modules`].
    #[cfg(feature = "link")]
    pub fn load_modules(&self, modules: &[&Module]) -> Result<Program> {
        self.load_image(self.vm.prepare_modules(modules)?)
    }

    /// [`Vm::load_elf`].
    #[cfg(feature = "link")]
    pub fn load_elf(&self, elf_bytes: &[u8]) -> Result<Program> {
        self.load_image(self.vm.prepare_elf(elf_bytes)?)
    }
}

/// `func` with `sig`, as the extern table keeps a native function; fails on a null `func`.
fn native(name: &str, func: *const (), sig: NativeSig) -> Result<Native> {
    if func.is_null() {
        return Err(VmError::InvalidArgument(format!("native {name}: null function")));
    }
    // SAFETY: a non-null code pointer, which calls cast to the signature the registration's contract promises
    let func = unsafe { std::mem::transmute::<*const (), NativeFn>(func) };
    Ok(Native { func, sig })
}

impl std::fmt::Debug for Vm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vm")
            .field("helpers", &self.helpers)
            .field("config", &self.config)
            .finish()
    }
}

/// What a VM maps into every program it links.
#[derive(Default)]
pub struct Shared {
    /// Maps shared by name.
    #[cfg(feature = "maps")]
    pub maps: SharedMaps,
    /// Buffers mapped at the same region in every program.
    pub regions: SharedRegions,
}

/// The buffers a VM maps at the same region in every program it links.
#[derive(Default)]
pub struct SharedRegions {
    list: Published<[Mapping]>,
    // serializes `add`, so none is lost; loads never take it
    writer: Mutex<()>,
}

/// A shared buffer and where it goes. The VM never reads or writes the buffer, so it keeps no [`SharedRegion`].
#[derive(Clone)]
struct Mapping {
    region: usize,
    perms: Perms,
    buffer: Arc<SharedBuffer>,
}

impl SharedRegions {
    /// [`Vm::share_region`]; its contract binds the programs that map the buffer, not this call. The handle's base
    /// is the buffer's guest address in a program of `passthrough`.
    fn add(&self, len: usize, perms: Perms, passthrough: Passthrough) -> Result<SharedRegion> {
        let _writer = lock(&self.writer);
        let list = self.list.get();

        if len == 0 || len > MAX_REGION_LEN {
            let msg = format!("region length {len} is not in 1..={MAX_REGION_LEN}");
            return Err(VmError::InvalidArgument(msg));
        }
        let region = free_host_region(list.iter().fold(0, |taken, m| taken | 1 << m.region))?;

        let buffer = Arc::new(SharedBuffer::new(len)?);
        let mapping = Mapping {
            region,
            perms,
            buffer: buffer.clone(),
        };
        drop(self.list.replace(list.iter().cloned().chain([mapping]).collect()));
        // SAFETY: the host's handle is the only `SharedRegion` over `buffer`.
        Ok(unsafe { SharedRegion::new(region, passthrough, perms, buffer) })
    }

    /// Map every shared region into `memory`.
    ///
    /// # Safety
    ///
    /// As [`Vm::share_region`].
    pub unsafe fn map_into(&self, memory: &mut VmMemory) {
        for m in self.list.get().iter() {
            unsafe { memory.map_shared(m.region, m.buffer.clone(), m.perms) };
        }
    }
}
