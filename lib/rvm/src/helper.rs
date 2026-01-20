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
pub struct HelperContext<'a> {
    /// Helper arguments (r1-r5).
    pub args: HelperArgs,
    /// Memory access (if available).
    pub memory: Option<&'a mut VmMemory>,
}

impl<'a> HelperContext<'a> {
    /// Create a new helper context.
    pub fn new(args: HelperArgs) -> Self {
        Self { args, memory: None }
    }

    /// Create a helper context with memory access.
    pub fn with_memory(args: HelperArgs, memory: &'a mut VmMemory) -> Self {
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
    /// Extract arguments from the helper args.
    fn from_args(args: &HelperArgs) -> Self;
}

// Implement FromArgs for tuples of different arities
impl FromArgs for () {
    fn from_args(_args: &HelperArgs) -> Self {}
}

impl FromArgs for u64 {
    fn from_args(args: &HelperArgs) -> Self {
        args.r1
    }
}

impl FromArgs for (u64,) {
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1,)
    }
}

impl FromArgs for (u64, u64) {
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2)
    }
}

impl FromArgs for (u64, u64, u64) {
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2, args.r3)
    }
}

impl FromArgs for (u64, u64, u64, u64) {
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2, args.r3, args.r4)
    }
}

impl FromArgs for (u64, u64, u64, u64, u64) {
    fn from_args(args: &HelperArgs) -> Self {
        (args.r1, args.r2, args.r3, args.r4, args.r5)
    }
}

// Also support extracting as other integer types
impl FromArgs for u32 {
    fn from_args(args: &HelperArgs) -> Self {
        args.r1 as u32
    }
}

impl FromArgs for i64 {
    fn from_args(args: &HelperArgs) -> Self {
        args.r1 as i64
    }
}

impl FromArgs for i32 {
    fn from_args(args: &HelperArgs) -> Self {
        args.r1 as i32
    }
}

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
pub type DynHelper = Box<dyn Fn(&mut HelperContext) -> Result<u64, HelperError> + Send + Sync>;

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
pub fn into_dyn_helper<F, A, R>(func: F) -> DynHelper
where
    F: Fn(A) -> R + Send + Sync + 'static,
    A: FromArgs + 'static,
    R: IntoReturn + 'static,
{
    Box::new(move |ctx: &mut HelperContext| {
        let typed_args = A::from_args(&ctx.args);
        let result = func(typed_args);
        Ok(result.into_return())
    })
}

/// Convert a function that takes HelperContext into a dynamic helper.
pub fn into_dyn_helper_with_ctx<F, R>(func: F) -> DynHelper
where
    F: Fn(&mut HelperContext) -> R + Send + Sync + 'static,
    R: IntoReturn + 'static,
{
    Box::new(move |ctx: &mut HelperContext| {
        let result = func(ctx);
        Ok(result.into_return())
    })
}

/// A collection of registered helper functions.
#[derive(Default)]
pub struct HelperRegistry {
    helpers: std::collections::HashMap<u32, DynHelper>,
}

impl HelperRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

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
        self.helpers.insert(id, into_dyn_helper(func));
    }

    /// Register a helper that needs access to the context.
    pub fn register_with_ctx<F, R>(&mut self, id: u32, func: F)
    where
        F: Fn(&mut HelperContext) -> R + Send + Sync + 'static,
        R: IntoReturn + 'static,
    {
        self.helpers.insert(id, into_dyn_helper_with_ctx(func));
    }

    /// Register a raw dynamic helper.
    pub fn register_raw(&mut self, id: u32, helper: DynHelper) {
        self.helpers.insert(id, helper);
    }

    /// Call a helper by ID.
    pub fn call(&self, id: u32, ctx: &mut HelperContext) -> Result<u64, HelperError> {
        let helper = self.helpers.get(&id).ok_or(HelperError::UnknownHelper(id))?;
        helper(ctx)
    }

    /// Check if a helper is registered.
    pub fn has(&self, id: u32) -> bool {
        self.helpers.contains_key(&id)
    }

    /// Get the number of registered helpers.
    pub fn len(&self) -> usize {
        self.helpers.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.helpers.is_empty()
    }
}

impl std::fmt::Debug for HelperRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperRegistry")
            .field("count", &self.helpers.len())
            .field("ids", &self.helpers.keys().collect::<Vec<_>>())
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
