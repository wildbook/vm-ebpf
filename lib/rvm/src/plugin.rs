//! Programs that call each other.
//!
//! A [`Plugin`] is a linked program behind a lock. [`crate::Vm::export`] publishes one
//! of its functions as a named extern, so programs linked afterwards can import it
//! like a host function. The call runs in the exporting plugin, with its memory,
//! maps and helpers.
//!
//! Arguments and the result are plain values: a pointer from one plugin means nothing
//! in another's memory. A call into a plugin that is already running, from the host
//! or through a chain of plugin calls, fails with [`VmError::PluginBusy`] instead of
//! deadlocking.

use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};

use crate::error::{HelperError, Result, VmError};
use crate::helper::{DynHelper, HelperContext};
use crate::program::Program;

/// A linked program that other programs can call into.
#[derive(Clone)]
pub struct Plugin {
    name: Arc<str>,
    program: Arc<Mutex<Program>>,
}

impl Plugin {
    pub fn new(name: impl Into<Arc<str>>, program: Program) -> Self {
        Self {
            name: name.into(),
            program: Arc::new(Mutex::new(program)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Call `func` with arguments in r1-r5.
    pub fn call(&self, func: &str, args: &[u64]) -> Result<u64> {
        self.lock()?.call(func, args)
    }

    /// Exclusive access to the program, e.g. for its maps or memory.
    pub fn lock(&self) -> Result<MutexGuard<'_, Program>> {
        try_lock(&self.program, &self.name)
    }

    /// Swap in a new build of this plugin. Exports keep working; they find their
    /// function by name in the new program. Blocks until a running call finishes.
    pub fn replace(&self, program: Program) {
        *self.program.lock().unwrap_or_else(|e| e.into_inner()) = program;
    }

    /// The extern that calls `func` in this plugin.
    pub fn export_fn(&self, func: &str) -> DynHelper {
        let program: Weak<Mutex<Program>> = Arc::downgrade(&self.program);
        let name = self.name.clone();
        let func: Arc<str> = func.into();

        Arc::new(move |ctx: &mut HelperContext| {
            let failed = |e: VmError| HelperError::Failed(format!("{name}::{func}: {e}"));
            let program = program
                .upgrade()
                .ok_or_else(|| failed(VmError::PluginUnloaded(name.to_string())))?;
            let mut program = try_lock(&program, &name).map_err(failed)?;
            let a = ctx.args;
            program.call(&func, &[a.r1, a.r2, a.r3, a.r4, a.r5]).map_err(failed)
        })
    }
}

fn try_lock<'a>(program: &'a Mutex<Program>, name: &str) -> Result<MutexGuard<'a, Program>> {
    match program.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(VmError::PluginBusy(name.to_string())),
        // a panic inside a helper poisons the lock; the program state is still usable
        Err(TryLockError::Poisoned(e)) => Ok(e.into_inner()),
    }
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin").field("name", &self.name).finish()
    }
}
