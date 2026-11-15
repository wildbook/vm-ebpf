//! Helper function support for the eBPF VM.
//!
//! This module provides type-safe helper function registration and dispatch.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use hashbrown::HashMap;

use crate::error::HelperError;
use crate::maps::Maps;
use crate::memory::VmMemory;

/// Arguments passed to a helper function.
///
/// Contains the values of registers r1-r5 at the time of the call.
#[derive(Debug, Clone, Copy)]
pub struct HelperArgs {
    pub r1: u64,
    pub r2: u64,
    pub r3: u64,
    pub r4: u64,
    pub r5: u64,
}

impl HelperArgs {
    /// Create new helper arguments.
    pub fn new(r1: u64, r2: u64, r3: u64, r4: u64, r5: u64) -> Self {
        Self { r1, r2, r3, r4, r5 }
    }

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

/// Context available to helper functions.
pub struct HelperContext<'a, M = VmMemory> {
    /// Helper arguments (r1-r5).
    pub args: HelperArgs,
    /// Memory access.
    pub memory: &'a mut M,
    /// The calling program's maps (if it has any).
    pub maps: Option<&'a mut Maps>,
}

/// Trait for extracting typed arguments from helper args.
///
/// This trait enables type-safe argument extraction from the raw u64 registers.
pub trait FromArgs: Sized {
    /// Number of argument registers (r1..) this type reads.
    const ARITY: u8;

    /// Extract arguments from the helper args.
    fn from_args(args: &HelperArgs) -> Self;
}

impl FromArgs for () {
    const ARITY: u8 = 0;
    fn from_args(_args: &HelperArgs) -> Self {}
}

impl FromArgs for (u64,) {
    const ARITY: u8 = 1;
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1,)
    }
}

impl FromArgs for (u64, u64) {
    const ARITY: u8 = 2;
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2)
    }
}

impl FromArgs for (u64, u64, u64) {
    const ARITY: u8 = 3;
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2, args.r3)
    }
}

impl FromArgs for (u64, u64, u64, u64) {
    const ARITY: u8 = 4;
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2, args.r3, args.r4)
    }
}

impl FromArgs for (u64, u64, u64, u64, u64) {
    const ARITY: u8 = 5;
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2, args.r3, args.r4, args.r5)
    }
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

/// Trait for converting return values to u64 for r0.
pub trait IntoReturn {
    /// Convert to the u64 return value.
    fn into_return(self) -> u64;
}

impl IntoReturn for () {
    fn into_return(self) -> u64 {
        0
    }
}

impl IntoReturn for u64 {
    fn into_return(self) -> u64 {
        self
    }
}

impl IntoReturn for u32 {
    fn into_return(self) -> u64 {
        self as u64
    }
}

impl IntoReturn for i64 {
    fn into_return(self) -> u64 {
        self as u64
    }
}

impl IntoReturn for i32 {
    fn into_return(self) -> u64 {
        self as u64
    }
}

impl IntoReturn for bool {
    fn into_return(self) -> u64 {
        self as u64
    }
}

impl<T: IntoReturn, E> IntoReturn for Result<T, E> {
    fn into_return(self) -> u64 {
        match self {
            Ok(v) => v.into_return(),
            Err(_) => u64::MAX, // -1 in two's complement
        }
    }
}

/// A registered function, called directly through `call` with `data` as its closure.
struct Slot<M> {
    call: unsafe fn(*const (), &mut HelperContext<M>) -> Result<u64, HelperError>,
    data: *const (),
    // keeps `data` alive; the call path never touches it
    _owner: Arc<dyn Send + Sync>,
}

// SAFETY: `data` points into `_owner`, which is `Send + Sync` and lives as long as the slot.
unsafe impl<M> Send for Slot<M> {}
unsafe impl<M> Sync for Slot<M> {}

impl<M> Clone for Slot<M> {
    fn clone(&self) -> Self {
        Self {
            call: self.call,
            data: self.data,
            _owner: self._owner.clone(),
        }
    }
}

impl<M: 'static> Slot<M> {
    fn new<F>(func: F) -> Self
    where
        F: Fn(&mut HelperContext<M>) -> Result<u64, HelperError> + Send + Sync + 'static,
    {
        /// # Safety
        ///
        /// `data` must point to a live `F`.
        unsafe fn trampoline<M, F>(data: *const (), ctx: &mut HelperContext<M>) -> Result<u64, HelperError>
        where
            F: Fn(&mut HelperContext<M>) -> Result<u64, HelperError>,
        {
            unsafe { (*data.cast::<F>())(ctx) }
        }

        let owner = Arc::new(func);
        Self {
            call: trampoline::<M, F>,
            data: Arc::as_ptr(&owner).cast(),
            _owner: owner,
        }
    }

    fn typed<F, A, R>(func: F) -> Self
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs,
        R: IntoReturn,
    {
        Self::new(move |ctx| Ok(func(A::from_args(&ctx.args)).into_return()))
    }
}

/// Extern table: host functions callable from eBPF, stored in dense slots.
///
/// Functions are registered either by numeric helper ID (standard BPF helpers,
/// `call <id>`) or by name (extern functions declared in the program). The linker
/// rewrites every call into a slot call, so linked programs dispatch by index.
/// Re-registering an ID or name replaces the function in its existing slot, which
/// keeps linked call sites valid (hot reload).
pub struct HelperRegistry<M = VmMemory> {
    slots: Vec<Slot<M>>,
    // argument count per slot; `None` for raw and context helpers, which read registers themselves
    arities: Vec<Option<u8>>,
    by_id: HashMap<u32, u32>,
    by_name: HashMap<String, u32>,
}

impl<M> Default for HelperRegistry<M> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            arities: Vec::new(),
            by_id: HashMap::new(),
            by_name: HashMap::new(),
        }
    }
}

impl<M> Clone for HelperRegistry<M> {
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
            arities: self.arities.clone(),
            by_id: self.by_id.clone(),
            by_name: self.by_name.clone(),
        }
    }
}

impl HelperRegistry {
    /// Create a new empty registry for [`VmMemory`]; use `default()` for other memories.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<M: 'static> HelperRegistry<M> {
    /// Register a helper function by ID.
    ///
    /// # Example
    ///
    /// ```ignore
    /// registry.register(1, |arg: u64| -> u64 {
    ///     println!("Got: {}", arg);
    ///     0
    /// });
    /// ```
    pub fn register<F, A, R>(&mut self, id: u32, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        let slot = self.by_id.get(&id).copied();
        let slot = self.put(slot, Slot::typed(func), Some(A::ARITY));
        self.by_id.insert(id, slot);
    }

    /// Register a helper that needs access to the context.
    pub fn register_with_ctx<F, R>(&mut self, id: u32, func: F)
    where
        F: Fn(&mut HelperContext<M>) -> R + Send + Sync + 'static,
        R: IntoReturn + 'static,
    {
        let slot = self.by_id.get(&id).copied();
        let slot = self.put(slot, Slot::new(move |ctx| Ok(func(ctx).into_return())), None);
        self.by_id.insert(id, slot);
    }

    /// Register an extern function by name.
    pub fn register_fn<F, A, R>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(A) -> R + Send + Sync + 'static,
        A: FromArgs + 'static,
        R: IntoReturn + 'static,
    {
        let name = name.into();
        let slot = self.by_name.get(&name).copied();
        let slot = self.put(slot, Slot::typed(func), Some(A::ARITY));
        self.by_name.insert(name, slot);
    }

    /// Register a raw extern function by name, called directly with the context.
    pub fn register_fn_raw<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut HelperContext<M>) -> Result<u64, HelperError> + Send + Sync + 'static,
    {
        let name = name.into();
        let slot = self.by_name.get(&name).copied();
        let slot = self.put(slot, Slot::new(func), None);
        self.by_name.insert(name, slot);
    }

    /// Replace the function in `slot`, or append a new slot.
    fn put(&mut self, slot: Option<u32>, helper: Slot<M>, arity: Option<u8>) -> u32 {
        match slot {
            Some(slot) => {
                self.slots[slot as usize] = helper;
                self.arities[slot as usize] = arity;
                slot
            }
            None => {
                self.slots.push(helper);
                self.arities.push(arity);
                (self.slots.len() - 1) as u32
            }
        }
    }

    /// Argument count of the function in `slot`, if it was registered with typed arguments.
    pub fn arity(&self, slot: u32) -> Option<u8> {
        self.arities.get(slot as usize).copied().flatten()
    }

    /// Slot of a helper ID.
    pub fn slot_of_id(&self, id: u32) -> Option<u32> {
        self.by_id.get(&id).copied()
    }

    /// Slot of a named extern function.
    pub fn slot_of_name(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Call a helper by ID.
    pub fn call(&self, id: u32, ctx: &mut HelperContext<M>) -> Result<u64, HelperError> {
        let slot = self.slot_of_id(id).ok_or(HelperError::UnknownHelper(id))?;
        self.call_slot(slot, ctx)
    }

    /// Call the function in `slot`.
    #[inline]
    pub fn call_slot(&self, slot: u32, ctx: &mut HelperContext<M>) -> Result<u64, HelperError> {
        let helper = self.slots.get(slot as usize).ok_or(HelperError::UnknownSlot(slot))?;
        // SAFETY: `Slot::new` paired `call` with a `data` pointer of the type it expects.
        unsafe { (helper.call)(helper.data, ctx) }
    }

    /// Check if a helper ID is registered.
    pub fn has(&self, id: u32) -> bool {
        self.by_id.contains_key(&id)
    }
}

impl<M> std::fmt::Debug for HelperRegistry<M> {
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
/// Every change bumps a version. A program keeps its own copy of the table and
/// re-copies it on entry when the version moved, so helper calls never touch a lock
/// and a change takes effect at each program's next call.
#[derive(Debug, Default)]
pub struct SharedHelpers {
    registry: RwLock<HelperRegistry>,
    version: AtomicU64,
}

impl SharedHelpers {
    /// Apply `f` to the table and publish the result.
    pub fn update<R>(&self, f: impl FnOnce(&mut HelperRegistry) -> R) -> R {
        let mut registry = self.registry.write().unwrap_or_else(PoisonError::into_inner);
        let result = f(&mut registry);
        self.version.fetch_add(1, Ordering::Release);
        result
    }

    /// The current version.
    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// A copy of the table and the version it belongs to.
    pub fn snapshot(&self) -> (HelperRegistry, u64) {
        let registry = self.registry.read().unwrap_or_else(PoisonError::into_inner);
        (registry.clone(), self.version())
    }
}
