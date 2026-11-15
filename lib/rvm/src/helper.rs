//! Helper function support for the eBPF VM.
//!
//! This module provides type-safe helper function registration and dispatch.
//!
//! # Example
//!
//! ```ignore
//! use rvm::{Vm, HelperFn};
//!
//! fn my_print(arg: u64) -> u64 {
//!     println!("Value: {}", arg);
//!     0
//! }
//!
//! let mut vm = Vm::new();
//! vm.register_helper(1, HelperFn::new(my_print));
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::HelperError;
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

    /// Get argument by index (0-4 for r1-r5).
    pub fn arg(&self, idx: usize) -> u64 {
        match idx {
            0 => self.r1,
            1 => self.r2,
            2 => self.r3,
            3 => self.r4,
            4 => self.r5,
            _ => 0,
        }
    }
}

/// Context available to helper functions.
pub struct HelperContext<'a, M = VmMemory> {
    /// Helper arguments (r1-r5).
    pub args: HelperArgs,
    /// Memory access (if available).
    pub memory: Option<&'a mut M>,
}

impl<'a, M> HelperContext<'a, M> {
    /// Create a new helper context.
    pub fn new(args: HelperArgs) -> Self {
        Self { args, memory: None }
    }

    /// Create a helper context with memory access.
    pub fn with_memory(args: HelperArgs, memory: &'a mut M) -> Self {
        Self {
            args,
            memory: Some(memory),
        }
    }
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

/// Type-erased helper function.
pub type DynHelper<M = VmMemory> = Arc<dyn Fn(&mut HelperContext<M>) -> Result<u64, HelperError> + Send + Sync>;

/// A wrapper for type-safe helper functions.
///
/// This allows registering functions with typed signatures while storing
/// them uniformly in the VM.
pub struct HelperFn<F, A, R> {
    func: F,
    _marker: std::marker::PhantomData<(A, R)>,
}

impl<F, A, R> HelperFn<F, A, R>
where
    F: Fn(A) -> R,
    A: FromArgs,
    R: IntoReturn,
{
    /// Create a new helper function wrapper.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }

    /// Call the helper function.
    pub fn call(&self, args: &HelperArgs) -> u64 {
        let typed_args = A::from_args(args);
        let result = (self.func)(typed_args);
        result.into_return()
    }
}

/// Convert a typed function into a dynamic helper.
pub fn into_dyn_helper<M: 'static, F, A, R>(func: F) -> DynHelper<M>
where
    F: Fn(A) -> R + Send + Sync + 'static,
    A: FromArgs + 'static,
    R: IntoReturn + 'static,
{
    Arc::new(move |ctx: &mut HelperContext<M>| {
        let typed_args = A::from_args(&ctx.args);
        let result = func(typed_args);
        Ok(result.into_return())
    })
}

/// Convert a function that takes HelperContext into a dynamic helper.
pub fn into_dyn_helper_with_ctx<M: 'static, F, R>(func: F) -> DynHelper<M>
where
    F: Fn(&mut HelperContext<M>) -> R + Send + Sync + 'static,
    R: IntoReturn + 'static,
{
    Arc::new(move |ctx: &mut HelperContext<M>| {
        let result = func(ctx);
        Ok(result.into_return())
    })
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

    /// Register a raw dynamic helper by ID.
    pub fn register_raw(&mut self, id: u32, helper: DynHelper<M>) {
        let slot = self.by_id.get(&id).copied();
        let slot = self.put(slot, Slot::new(move |ctx| helper(ctx)), None);
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

    /// Register an extern function by name that needs access to the context.
    pub fn register_fn_with_ctx<F, R>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&mut HelperContext<M>) -> R + Send + Sync + 'static,
        R: IntoReturn + 'static,
    {
        let name = name.into();
        let slot = self.by_name.get(&name).copied();
        let slot = self.put(slot, Slot::new(move |ctx| Ok(func(ctx).into_return())), None);
        self.by_name.insert(name, slot);
    }

    /// Register a raw dynamic extern function by name.
    pub fn register_fn_raw(&mut self, name: impl Into<String>, helper: DynHelper<M>) {
        let name = name.into();
        let slot = self.by_name.get(&name).copied();
        let slot = self.put(slot, Slot::new(move |ctx| helper(ctx)), None);
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

    /// Check if a named extern function is registered.
    pub fn has_fn(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Number of slots.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_args() {
        let args = HelperArgs::new(1, 2, 3, 4, 5);

        assert_eq!(<u64>::from_args(&args), 1);
        assert_eq!(<(u64, u64)>::from_args(&args), (1, 2));
        assert_eq!(<(u64, u64, u64)>::from_args(&args), (1, 2, 3));
    }

    #[test]
    fn test_into_return() {
        assert_eq!(42u64.into_return(), 42);
        assert_eq!(42u32.into_return(), 42);
        assert_eq!((-1i64).into_return(), u64::MAX);
        assert_eq!(true.into_return(), 1);
        assert_eq!(false.into_return(), 0);
    }

    #[test]
    fn test_helper_fn() {
        let helper = HelperFn::new(|(a, b): (u64, u64)| a + b);
        let args = HelperArgs::new(10, 20, 0, 0, 0);
        assert_eq!(helper.call(&args), 30);
    }

    #[test]
    fn test_helper_registry() {
        let mut registry = HelperRegistry::new();

        registry.register(1, |x: u64| x * 2);
        registry.register(2, |(a, b): (u64, u64)| a + b);

        let args1 = HelperArgs::new(21, 0, 0, 0, 0);
        let args2 = HelperArgs::new(10, 20, 0, 0, 0);

        let mut ctx1 = HelperContext::new(args1);
        let mut ctx2 = HelperContext::new(args2);

        assert_eq!(registry.call(1, &mut ctx1).unwrap(), 42);
        assert_eq!(registry.call(2, &mut ctx2).unwrap(), 30);
        assert!(registry.call(99, &mut ctx1).is_err());
    }
}
