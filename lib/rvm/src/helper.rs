//! Host functions callable from eBPF: typed registration and slot dispatch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard};

use hashbrown::HashMap;

use crate::error::HelperError;
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{GuestMemory, VmMemory};
use crate::sync::{read, write};

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
    /// Create from a register array.
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

/// What a raw host function sees: the argument registers, the calling program's memory and its maps.
pub struct HelperContext<'a> {
    /// Helper arguments (r1-r5).
    pub args: HelperArgs,
    /// Memory access.
    pub memory: &'a mut VmMemory,
    /// The calling program's maps (if it has any).
    #[cfg(feature = "maps")]
    pub maps: Option<&'a mut Maps>,
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

/// The value a host function puts in r0, or the error that fails the guest call.
///
/// `Err` fails the call into the guest with [`HelperError`], via `E: Into<HelperError>`. A host function that wants the
/// guest to see an error code returns it as an `i64`.
pub trait IntoReturn {
    fn into_return(self) -> Result<u64, HelperError>;
}

impl IntoReturn for () {
    #[inline]
    fn into_return(self) -> Result<u64, HelperError> {
        Ok(0)
    }
}

macro_rules! into_return {
    ($($ty:ty),*) => {$(
        impl IntoReturn for $ty {
            #[inline]
            fn into_return(self) -> Result<u64, HelperError> {
                Ok(self as u64)
            }
        }
    )*};
}

into_return!(u64, u32, i64, i32, bool);

impl<T: IntoReturn, E: Into<HelperError>> IntoReturn for Result<T, E> {
    #[inline]
    fn into_return(self) -> Result<u64, HelperError> {
        self.map_err(Into::into)?.into_return()
    }
}

/// A registered function, called directly through `call` with `data` as its closure.
#[derive(Clone)]
struct Slot {
    call: unsafe fn(*const (), &mut HelperContext) -> Result<u64, HelperError>,
    data: *const (),
    // keeps `data` alive; the call path never touches it
    _owner: Arc<dyn Send + Sync>,
    // argument count, if registered with typed arguments; `None` for raw helpers, which read registers themselves. Only
    // the linker reads it.
    #[cfg_attr(not(feature = "link"), allow(dead_code))]
    arity: Option<u8>,
}

// SAFETY: `data` points into `_owner`, which is `Send + Sync` and lives as long as the slot.
unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

impl Slot {
    fn new<F>(func: F, arity: Option<u8>) -> Self
    where
        F: Fn(&mut HelperContext) -> Result<u64, HelperError> + Send + Sync + 'static,
    {
        /// # Safety
        ///
        /// `data` must point to a live `F`.
        unsafe fn trampoline<F>(data: *const (), ctx: &mut HelperContext) -> Result<u64, HelperError>
        where
            F: Fn(&mut HelperContext) -> Result<u64, HelperError>,
        {
            unsafe { (*data.cast::<F>())(ctx) }
        }

        let owner = Arc::new(func);
        Self {
            call: trampoline::<F>,
            data: Arc::as_ptr(&owner).cast(),
            _owner: owner,
            arity,
        }
    }

    fn typed<F, A, R>(func: F) -> Self
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs,
        R: IntoReturn,
    {
        Self::new(move |ctx| func(A::from_args(&ctx.args)).into_return(), Some(A::ARITY))
    }

    fn with_memory<F, A, R>(func: F) -> Self
    where
        F: Fn(&mut GuestMemory, A) -> R + Send + Sync + 'static,
        A: FromArgs,
        R: IntoReturn,
    {
        let call = move |ctx: &mut HelperContext| {
            let args = A::from_args(&ctx.args);
            func(&mut GuestMemory::new(ctx.memory), args).into_return()
        };
        Self::new(call, Some(A::ARITY))
    }
}

/// Extern table: host functions callable from eBPF, stored in dense slots.
///
/// Functions are registered either by numeric helper ID (standard BPF helpers, `call <id>`) or by name (extern
/// functions declared in the program). The linker rewrites every call into a slot call, so linked programs dispatch by
/// index. Re-registering an ID or name replaces the function in its existing slot, which keeps linked call sites valid
/// (hot reload).
#[derive(Default, Clone)]
pub struct HelperRegistry {
    slots: Vec<Slot>,
    by_id: Vec<(u32, u32)>, // (helper ID, slot)
    by_name: HashMap<String, u32>,
}

impl HelperRegistry {
    /// Register a helper function by ID, with typed arguments.
    pub fn register_helper<F, A, R>(&mut self, id: u32, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.put_id(id, Slot::typed(func));
    }

    /// Register a helper function by ID that reads its arguments and memory from the context.
    pub fn register_helper_raw<F, R>(&mut self, id: u32, func: F)
    where
        F: Fn(&mut HelperContext) -> R + Send + Sync + 'static,
        R: IntoReturn + 'static,
    {
        self.put_id(id, Slot::new(move |ctx| func(ctx).into_return(), None));
    }

    /// Register an extern function by name, with typed arguments.
    pub fn register_fn<F, A, R>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.put_name(name.into(), Slot::typed(func));
    }

    /// Register an extern function by name that reads or writes the calling program's memory through [`GuestMemory`],
    /// with typed arguments.
    pub fn register_fn_with_memory<F, A, R>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut GuestMemory, A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        self.put_name(name.into(), Slot::with_memory(func));
    }

    /// Register a raw extern function by name, called directly with the context.
    pub fn register_fn_raw<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut HelperContext) -> Result<u64, HelperError> + Send + Sync + 'static,
    {
        self.put_name(name.into(), Slot::new(func, None));
    }

    /// Replace the function registered under `id`, or append a new slot.
    fn put_id(&mut self, id: u32, helper: Slot) {
        let found = self.slot_of_id(id);
        let slot = self.put(found, helper);
        if found.is_none() {
            self.by_id.push((id, slot));
        }
    }

    /// Replace the function registered under `name`, or append a new slot.
    fn put_name(&mut self, name: String, helper: Slot) {
        let slot = self.by_name.get(&name).copied();
        let slot = self.put(slot, helper);
        self.by_name.insert(name, slot);
    }

    /// Replace the function in `slot`, or append a new slot.
    fn put(&mut self, slot: Option<u32>, helper: Slot) -> u32 {
        match slot {
            Some(slot) => {
                self.slots[slot as usize] = helper;
                slot
            }
            None => {
                self.slots.push(helper);
                (self.slots.len() - 1) as u32
            }
        }
    }

    /// Argument count of the function in `slot`, if it was registered with typed arguments.
    #[cfg(feature = "link")]
    pub fn arity(&self, slot: u32) -> Option<u8> {
        self.slots.get(slot as usize)?.arity
    }

    /// Slot of a helper ID.
    pub fn slot_of_id(&self, id: u32) -> Option<u32> {
        self.by_id.iter().find(|e| e.0 == id).map(|e| e.1)
    }

    /// Slot of a named extern function.
    pub fn slot_of_name(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Call the function in `slot`.
    #[inline]
    pub fn call_slot(&self, slot: u32, ctx: &mut HelperContext) -> Result<u64, HelperError> {
        // not `ok_or`, which builds and drops the error on every call
        let Some(helper) = self.slots.get(slot as usize) else {
            return Err(HelperError::UnknownSlot(slot));
        };
        // SAFETY: `Slot::new` paired `call` with a `data` pointer of the type it expects.
        unsafe { (helper.call)(helper.data, ctx) }
    }
}

impl std::fmt::Debug for HelperRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperRegistry")
            .field("slots", &self.slots.len())
            .field("ids", &self.by_id)
            .field("names", &self.by_name)
            .finish()
    }
}

/// The extern table a [`crate::Vm`] shares with the programs it links.
///
/// Every change bumps a version. A program keeps its own copy of the table and re-copies it on entry when the version
/// moved, so helper calls never touch a lock and a change takes effect at each program's next call.
#[derive(Debug, Default)]
pub struct SharedHelpers {
    registry: RwLock<HelperRegistry>,
    version: AtomicU64,
}

impl SharedHelpers {
    /// Apply `f` to the table and publish the result.
    pub fn update<R>(&self, f: impl FnOnce(&mut HelperRegistry) -> R) -> R {
        let mut registry = write(&self.registry);
        let result = f(&mut registry);
        self.version.fetch_add(1, Ordering::Release);
        result
    }

    /// The current version.
    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Read access to the current table.
    pub fn read(&self) -> RwLockReadGuard<'_, HelperRegistry> {
        read(&self.registry)
    }

    /// A copy of the table and the version it belongs to.
    pub fn snapshot(&self) -> (HelperRegistry, u64) {
        let registry = self.read();
        (registry.clone(), self.version())
    }
}
