//! Host functions callable from eBPF: typed registration and slot dispatch.

use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hashbrown::HashMap;
use rvm_core::{Context, Native, NativeSig};

use crate::error::{HostError, VmError};
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{GuestMemory, VmMemory};
use crate::sync::{lock, Published};

/// Registers r1-r5 at the time of a helper call.
#[derive(Debug, Clone, Copy)]
pub struct HelperArgs {
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub r4: u64,
    pub r5: u64,
}

impl HelperArgs {
    pub fn from_regs(regs: &[u64; 16]) -> Self {
        Self {
            r1: regs[1],
            r2: regs[2],
            r3: regs[3],
            r4: regs[4],
            r5: regs[5],
        }
    }
}

/// What a raw host function sees: the argument registers, the calling program's memory, and its maps and fuel.
pub struct HelperContext<'a> {
    pub args: HelperArgs,
    pub memory: &'a mut VmMemory,
    pub host: &'a mut HostState,
}

/// What host functions reach of the calling program besides its memory.
#[derive(Debug, Default)]
pub struct HostState {
    #[cfg(feature = "maps")]
    pub maps: Maps,
    /// The instructions the calling program has left, for host functions that run guest code on its behalf.
    pub fuel: CallerFuel,
}

/// What a guest call has left of its instruction limit, as the host functions it calls see it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum CallerFuel {
    /// The caller runs without a limit.
    #[default]
    Unmetered,
    /// The caller runs with a limit and knows what it has left only once it stops. A host function that needs that
    /// stops with [`Stop::FuelWanted`]: the executor then stops the caller and calls the function again with
    /// [`CallerFuel::Left`].
    Unknown,
    /// The instructions the caller has left. It continues with what the function leaves here.
    Left(u64),
}

/// Typed helper arguments, read from r1 onwards.
pub trait FromArgs: Sized {
    /// Number of argument registers (r1..) this type reads.
    const ARITY: u8;

    /// Extract arguments from the helper args.
    fn from_args(args: &HelperArgs) -> Self;
}

/// Implements `FromArgs` for a tuple reading `$arity` registers starting at r1.
macro_rules! tuple_args {
    ($(($($reg:ident),*) $arity:literal);* $(;)?) => {$(
        impl FromArgs for ($(tuple_args!(@unit $reg),)*) {
            const ARITY: u8 = $arity;
            fn from_args(args: &HelperArgs) -> Self {
                ($(args.$reg,)*)
            }
        }
    )*};
    (@unit $reg:ident) => { u64 };
}

impl FromArgs for () {
    const ARITY: u8 = 0;
    fn from_args(_args: &HelperArgs) -> Self {}
}

tuple_args! {
    (r1) 1;
    (r1, r2) 2;
    (r1, r2, r3) 3;
    (r1, r2, r3, r4) 4;
    (r1, r2, r3, r4, r5) 5;
}

// Single-argument shorthands.
macro_rules! single_arg {
    ($($ty:ty),*) => {$(
        impl FromArgs for $ty {
            const ARITY: u8 = 1;
            fn from_args(args: &HelperArgs) -> Self {
                args.r1 as $ty
            }
        }
    )*};
}

single_arg!(u64, u32, i64, i32);

/// The value a host function returns to the guest, or the error that fails the guest call.
///
/// `Err` fails the call into the guest with [`HostError::Failed`], which holds the error. A host function that wants
/// the guest to see an error code returns it as an `i64`.
///
/// The guest declares the function in C. Clang takes a result of up to 8 bytes from r0, a struct or union included,
/// with the first byte in the lowest bits. It takes one of 9 to 16 bytes from r0 and r2, which a `(u64, u64)` fills:
/// bytes 0 to 7, then the rest.
pub trait IntoReturn {
    /// Whether the value fills r0 and r2.
    const WIDE: bool = false;

    /// The new r0. A [`WIDE`](Self::WIDE) value puts its second half in `r2`.
    fn into_return(self, r2: &mut u64) -> Result<u64, HostError>;
}

impl IntoReturn for () {
    #[inline]
    fn into_return(self, _r2: &mut u64) -> Result<u64, HostError> {
        Ok(0)
    }
}

macro_rules! into_return {
    ($($ty:ty),*) => {$(
        impl IntoReturn for $ty {
            #[inline]
            fn into_return(self, _r2: &mut u64) -> Result<u64, HostError> {
                Ok(self as u64)
            }
        }
    )*};
}

into_return!(u64, u32, i64, i32, bool);

impl IntoReturn for (u64, u64) {
    const WIDE: bool = true;

    #[inline]
    fn into_return(self, r2: &mut u64) -> Result<u64, HostError> {
        *r2 = self.1;
        Ok(self.0)
    }
}

impl<T: IntoReturn, E: Into<Box<dyn Error + Send + Sync>>> IntoReturn for Result<T, E> {
    const WIDE: bool = T::WIDE;

    #[inline]
    fn into_return(self, r2: &mut u64) -> Result<u64, HostError> {
        match self {
            Ok(value) => value.into_return(r2),
            Err(error) => Err(failed(error)),
        }
    }
}

// Host functions convert their errors on the failure path only; keep that code out of the call path.
#[cold]
#[inline(never)]
fn failed(error: impl Into<Box<dyn Error + Send + Sync>>) -> HostError {
    HostError::Failed(error.into())
}

/// Why a host function call stops the guest call that made it.
pub enum Stop {
    Failed(HostError),
    /// The function asks for the caller's remaining instructions while [`HostState::fuel`] is
    /// [`CallerFuel::Unknown`]; the executor calls it again with them there.
    FuelWanted,
    /// A call to a helper ID that isn't registered.
    UnknownHelper(u32),
    /// A call to an extern table slot that doesn't exist.
    UnknownSlot(u32),
}

impl From<HostError> for Stop {
    #[inline]
    fn from(error: HostError) -> Self {
        Self::Failed(error)
    }
}

/// How [`HostFn::call`] reaches a host function: with its closure, the caller's context, its [`HostState`] and the
/// place for the reason of a stop. It returns the new r0, or `None` once it stored the reason. Four arguments, so that
/// every one of them arrives in a register, and an `Option<u64>`, which returns in two.
type Trampoline = unsafe fn(*const (), &mut Context<VmMemory>, &mut HostState, &mut Option<Stop>) -> Option<u64>;

/// A host function, called directly through `call` with `data` as its closure.
#[derive(Clone)]
pub struct HostFn {
    call: Trampoline,
    data: *const (),
    // keeps `data` alive; the call path never touches it
    _owner: Arc<dyn Send + Sync>,
    // argument count, if registered with typed arguments; `None` for raw helpers, which read registers themselves. Only
    // the linker reads it and `wide`.
    #[cfg_attr(not(feature = "link"), allow(dead_code))]
    arity: Option<u8>,
    // whether the function sets r2 as well as r0: `IntoReturn::WIDE`
    #[cfg_attr(not(feature = "link"), allow(dead_code))]
    wide: bool,
}

// SAFETY: `data` points into `_owner`, which is `Send + Sync` and lives as long as the `HostFn`.
unsafe impl Send for HostFn {}
unsafe impl Sync for HostFn {}

impl HostFn {
    /// `func` called through `call`, which must take `data` as a pointer to an `F`.
    fn with_trampoline<F: Send + Sync + 'static>(func: F, call: Trampoline, arity: Option<u8>, wide: bool) -> Self {
        let owner = Arc::new(func);
        Self {
            call,
            data: Arc::as_ptr(&owner).cast(),
            _owner: owner,
            arity,
            wide,
        }
    }

    /// A function that reads its arguments from the registers itself and reaches the caller's memory, maps and fuel.
    /// Its result is r0.
    pub fn raw<F>(func: F) -> Self
    where
        F: Fn(&mut HelperContext) -> Result<u64, Stop> + Send + Sync + 'static,
    {
        /// # Safety
        ///
        /// `data` must point to a live `F`.
        unsafe fn trampoline<F>(
            data: *const (),
            ctx: &mut Context<VmMemory>,
            host: &mut HostState,
            stop: &mut Option<Stop>,
        ) -> Option<u64>
        where
            F: Fn(&mut HelperContext) -> Result<u64, Stop>,
        {
            let mut helper_ctx = HelperContext {
                args: HelperArgs::from_regs(&ctx.regs),
                memory: &mut *ctx.memory,
                host,
            };
            finish(unsafe { (*data.cast::<F>())(&mut helper_ctx) }, stop)
        }

        Self::with_trampoline(func, trampoline::<F>, None, false)
    }

    /// A function of the typed arguments.
    pub fn typed<F, A, R>(func: F) -> Self
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs,
        R: IntoReturn,
    {
        /// # Safety
        ///
        /// `data` must point to a live `F`.
        unsafe fn trampoline<F, A, R>(
            data: *const (),
            ctx: &mut Context<VmMemory>,
            _host: &mut HostState,
            stop: &mut Option<Stop>,
        ) -> Option<u64>
        where
            F: Fn(A) -> R,
            A: FromArgs,
            R: IntoReturn,
        {
            let args = A::from_args(&HelperArgs::from_regs(&ctx.regs));
            let result = unsafe { (*data.cast::<F>())(args) };
            finish(result.into_return(&mut ctx.regs[2]), stop)
        }

        Self::with_trampoline(func, trampoline::<F, A, R>, Some(A::ARITY), R::WIDE)
    }

    /// A function of the caller's memory and the typed arguments.
    pub fn with_memory<F, A, R>(func: F) -> Self
    where
        F: Fn(&mut GuestMemory, A) -> R + Send + Sync + 'static,
        A: FromArgs,
        R: IntoReturn,
    {
        /// # Safety
        ///
        /// `data` must point to a live `F`.
        unsafe fn trampoline<F, A, R>(
            data: *const (),
            ctx: &mut Context<VmMemory>,
            _host: &mut HostState,
            stop: &mut Option<Stop>,
        ) -> Option<u64>
        where
            F: Fn(&mut GuestMemory, A) -> R,
            A: FromArgs,
            R: IntoReturn,
        {
            let args = A::from_args(&HelperArgs::from_regs(&ctx.regs));
            let result = unsafe { (*data.cast::<F>())(&mut GuestMemory::new(ctx.memory), args) };
            finish(result.into_return(&mut ctx.regs[2]), stop)
        }

        Self::with_trampoline(func, trampoline::<F, A, R>, Some(A::ARITY), R::WIDE)
    }
}

/// The r0 of a host function call that returned `result`, or `None` once the reason it stops the caller is in `stop`.
#[inline(always)]
fn finish<E: Into<Stop>>(result: Result<u64, E>, stop: &mut Option<Stop>) -> Option<u64> {
    match result {
        Ok(r0) => Some(r0),
        Err(reason) => {
            *stop = Some(reason.into());
            None
        }
    }
}

/// Extern table: host functions callable from eBPF, stored in dense slots.
///
/// A function sits under a numeric helper ID (standard BPF helpers, `call <id>`) or under a name (extern functions
/// declared in the program). The linker rewrites every call into a slot call, so linked programs dispatch by index.
/// Putting a function under an ID or name that has one replaces it in its slot, which keeps linked call sites valid
/// (hot reload).
///
/// Native functions have a table of their own, which the interpreter calls straight from the call's handler. A name
/// with both a native and a host function binds to the native.
#[derive(Default, Clone)]
pub struct HelperRegistry {
    slots: Vec<HostFn>,
    by_id: Vec<(u32, u32)>, // (helper ID, slot)
    by_name: HashMap<String, u32>,
    natives: Vec<Native>,
    // by index; few enough to search
    native_names: Vec<String>,
}

impl HelperRegistry {
    /// Put `func` under helper ID `id`: in the slot of the function the ID had, or in a new slot.
    pub fn put_id(&mut self, id: u32, func: HostFn) {
        let found = self.slot_of_id(id);
        let slot = self.put(found, func);
        if found.is_none() {
            self.by_id.push((id, slot));
        }
    }

    /// Put `func` under `name`: in the slot of the function the name had, or in a new slot.
    pub fn put_name(&mut self, name: String, func: HostFn) {
        let slot = self.by_name.get(&name).copied();
        let slot = self.put(slot, func);
        self.by_name.insert(name, slot);
    }

    /// Put `native` under `name`: in the index of the native the name had, which must have the same signature, or at a
    /// new index. The caller of [`Vm::register_native`](crate::Vm::register_native) vouches for the function.
    pub fn put_native(&mut self, name: String, native: Native) -> Result<(), VmError> {
        let Some(index) = self.native_names.iter().position(|n| *n == name) else {
            self.natives.push(native);
            self.native_names.push(name);
            return Ok(());
        };
        let old = &mut self.natives[index];
        if old.sig != native.sig {
            let msg = format!("native {name} is registered with another signature");
            return Err(VmError::InvalidArgument(msg));
        }
        *old = native;
        Ok(())
    }

    /// The index and signature of the native function `name`.
    pub fn native(&self, name: &str) -> Option<(u32, NativeSig)> {
        let index = self.native_names.iter().position(|n| n == name)?;
        Some((index as u32, self.natives[index].sig))
    }

    /// The native functions, by index.
    #[inline(always)]
    pub fn natives(&self) -> &[Native] {
        &self.natives
    }

    /// Replace the function in `slot`, or append a new slot.
    fn put(&mut self, slot: Option<u32>, func: HostFn) -> u32 {
        match slot {
            Some(slot) => {
                self.slots[slot as usize] = func;
                slot
            }
            None => {
                self.slots.push(func);
                (self.slots.len() - 1) as u32
            }
        }
    }

    /// Argument count of the function in `slot`, if it was registered with typed arguments.
    #[cfg(feature = "link")]
    pub fn arity(&self, slot: u32) -> Option<u8> {
        self.slots.get(slot as usize)?.arity
    }

    /// Whether the function in `slot` sets r2 as well as r0.
    #[cfg(feature = "link")]
    pub fn wide(&self, slot: u32) -> bool {
        self.slots.get(slot as usize).is_some_and(|func| func.wide)
    }

    /// Slot of a helper ID.
    pub fn slot_of_id(&self, id: u32) -> Option<u32> {
        self.by_id.iter().find(|e| e.0 == id).map(|e| e.1)
    }

    /// Slot of a named extern function.
    pub fn slot_of_name(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Call the function in `slot` with the caller's context and host state: the new r0, or `None` once the reason it
    /// stops the caller is in `stop`.
    #[inline]
    pub fn call_slot(
        &self,
        slot: u32,
        ctx: &mut Context<VmMemory>,
        host: &mut HostState,
        stop: &mut Option<Stop>,
    ) -> Option<u64> {
        let Some(func) = self.slots.get(slot as usize) else {
            *stop = Some(Stop::UnknownSlot(slot));
            return None;
        };
        // SAFETY: `HostFn::with_trampoline` paired `call` with a `data` pointer of the type it expects.
        unsafe { (func.call)(func.data, ctx, host, stop) }
    }
}

impl std::fmt::Debug for HelperRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperRegistry")
            .field("slots", &self.slots.len())
            .field("ids", &self.by_id)
            .field("names", &self.by_name)
            .field("natives", &self.native_names)
            .finish()
    }
}

/// The extern table a [`crate::Vm`] shares with the programs it links.
///
/// Every change publishes a new table and bumps a version. A program keeps its own copy of the table and re-copies it
/// on entry when the version moved, so helper calls never touch a lock and a change takes effect at each program's
/// next call.
#[derive(Debug, Default)]
pub struct SharedHelpers {
    current: Published<HelperRegistry>,
    // serializes updates, so none is lost; readers never take it
    writer: Mutex<()>,
    version: AtomicU64,
}

impl SharedHelpers {
    /// A table that starts as `registry`.
    pub fn new(registry: HelperRegistry) -> Self {
        Self {
            current: Published::new(Arc::new(registry)),
            writer: Mutex::new(()),
            version: AtomicU64::new(0),
        }
    }

    /// Apply `f` to a copy of the table and publish the result.
    pub fn update<R>(&self, f: impl FnOnce(&mut HelperRegistry) -> R) -> R {
        let _writer = lock(&self.writer);
        let mut registry = HelperRegistry::clone(&self.current.get());
        let result = f(&mut registry);
        drop(self.current.replace(Arc::new(registry)));
        self.version.fetch_add(1, Ordering::Release);
        result
    }

    /// The current version.
    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// The current table.
    #[cfg(feature = "link")]
    pub fn read(&self) -> Arc<HelperRegistry> {
        self.current.get()
    }

    /// A copy of the current table.
    pub fn snapshot(&self) -> Snapshot {
        // the table is published before the version moves, so reading the version first never pairs it with an older
        // table
        let version = self.version();
        Snapshot {
            table: HelperRegistry::clone(&self.current.get()),
            version,
        }
    }
}

/// A copy of the extern table a [`SharedHelpers`] held.
pub struct Snapshot {
    pub table: HelperRegistry,
    /// A version no newer than `table`, so comparing it against [`SharedHelpers::version`] never misses a change.
    pub version: u64,
}
