//! Programs that call each other.
//!
//! A [`Plugin`] is a linked program behind a lock. [`crate::Vm::export`] publishes one
//! of its functions as a named extern, so programs linked afterwards can import it
//! like a host function. The call runs in the exporting plugin, with its memory,
//! maps and helpers.
//!
//! Arguments and the result are plain values: a pointer from one plugin means nothing
//! in another's memory, unless the exported function tags the parameter as a borrow
//! (see [`Borrow`]). Then the caller's buffer is mapped into the callee at a
//! [`BORROW_FIRST_REGION`] slot for the duration of the call, and the callee gets
//! that address instead. A call into a plugin that is already running, from the host
//! or through a chain of plugin calls, fails with [`VmError::PluginBusy`] instead of
//! deadlocking.

use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};

use crate::error::{HelperError, Result, VmError};
use crate::helper::HelperContext;
use crate::layout::BORROW_FIRST_REGION;
use crate::memory::{region_base, Perms};
use crate::program::{Borrow, Func, Program};

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

    /// Look up `func` for [`Plugin::call_func`]. [`Plugin::replace`] invalidates the
    /// handle.
    pub fn func(&self, func: &str) -> Result<Func> {
        self.lock()?.func(func)
    }

    /// Call a function looked up with [`Plugin::func`]; arguments go in r1-r5.
    pub fn call_func(&self, func: Func, args: &[u64]) -> Result<u64> {
        self.lock()?.call_func(func, args)
    }

    /// Exclusive access to the program, e.g. for its maps or memory.
    pub fn lock(&self) -> Result<MutexGuard<'_, Program>> {
        try_lock(&self.program, &self.name)
    }

    /// Swap in a new build of this plugin. Exports keep working; they find their
    /// function by name in the new program. Blocks until a running call finishes.
    pub fn replace(&self, program: Program) {
        *self.program.lock().unwrap_or_else(|e| e.into_inner()) = program;
        self.program.clear_poison();
    }

    /// A handle that doesn't keep the plugin alive. Host functions that call back into
    /// a plugin should hold this: they live in the `Vm` that every plugin's program
    /// refers to, so a strong handle would be a cycle that frees neither.
    pub fn downgrade(&self) -> WeakPlugin {
        WeakPlugin {
            name: self.name.clone(),
            program: Arc::downgrade(&self.program),
        }
    }

    /// The extern that calls `func` in this plugin.
    pub fn export_fn(
        &self,
        func: &str,
    ) -> impl Fn(&mut HelperContext) -> std::result::Result<u64, HelperError> + Send + Sync + 'static {
        let program: Weak<Mutex<Program>> = Arc::downgrade(&self.program);
        let name = self.name.clone();
        let func: Arc<str> = func.into();

        move |ctx: &mut HelperContext| -> std::result::Result<u64, HelperError> {
            let failed = |e: VmError| HelperError::Failed(format!("{name}::{func}: {e}"));
            let program = program
                .upgrade()
                .ok_or_else(|| failed(VmError::PluginUnloaded(name.to_string())))?;
            let mut program = try_lock(&program, &name).map_err(failed)?;

            let a = ctx.args;
            let mut args = [a.r1, a.r2, a.r3, a.r4, a.r5];
            let borrows = program.function(&func).map(|f| f.borrows.clone()).unwrap_or_default();
            if borrows.is_empty() {
                return program.call(&func, &args).map_err(failed);
            }

            let caller = &*ctx.memory;
            let mut mapped = Ok(());
            for &Borrow { arg, len_arg, writable } in &borrows {
                let (addr, len) = (args[arg as usize], args[len_arg as usize] as usize);
                // the caller must itself be allowed what the callee gets
                let perms = if writable { Perms::RW } else { Perms::R };
                let ptr = match caller.host_ptr(addr, len, perms) {
                    Ok(ptr) => ptr,
                    Err(e) => {
                        mapped = Err(failed(e.into()));
                        break;
                    }
                };
                let region = BORROW_FIRST_REGION + arg as usize;
                // SAFETY: the caller is blocked in this call; the regions are unmapped
                // before it returns, or on the next lock after a panic.
                unsafe { program.memory_mut().map_host(region, ptr, len, perms) };
                args[arg as usize] = region_base(region);
            }

            let result = mapped.and_then(|()| program.call(&func, &args).map_err(failed));
            for borrow in &borrows {
                program.memory_mut().unmap(BORROW_FIRST_REGION + borrow.arg as usize);
            }
            result
        }
    }
}

/// A [`Plugin`] handle that doesn't keep it alive; see [`Plugin::downgrade`].
#[derive(Clone)]
pub struct WeakPlugin {
    name: Arc<str>,
    program: Weak<Mutex<Program>>,
}

impl WeakPlugin {
    /// The plugin, unless every [`Plugin`] handle to it was dropped.
    pub fn upgrade(&self) -> Option<Plugin> {
        Some(Plugin {
            name: self.name.clone(),
            program: self.program.upgrade()?,
        })
    }
}

fn try_lock<'a>(program: &'a Mutex<Program>, name: &str) -> Result<MutexGuard<'a, Program>> {
    match program.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(VmError::PluginBusy(name.to_string())),
        // a panic during a call poisons the lock and may have skipped unmapping borrowed
        // caller memory, which may be gone by now
        Err(TryLockError::Poisoned(e)) => {
            let mut guard = e.into_inner();
            for region in BORROW_FIRST_REGION..BORROW_FIRST_REGION + 5 {
                guard.memory_mut().unmap(region);
            }
            program.clear_poison();
            Ok(guard)
        }
    }
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin").field("name", &self.name).finish()
    }
}
