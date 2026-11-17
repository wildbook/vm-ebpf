//! Programs that call each other.
//!
//! A [`Plugin`] is a linked program behind a lock. [`crate::Vm::export`] publishes one of its functions as a named
//! extern, so programs linked afterwards can import it like a host function. The call runs in the exporting plugin,
//! with its memory, maps and helpers.
//!
//! Arguments and the result are plain values: a pointer from one plugin means nothing in another's memory, unless the
//! exported function tags the parameter as a borrow (see [`Borrow`]). Then the caller's buffer is mapped into the
//! callee at a [`BORROW_FIRST_REGION`] slot for the duration of the call, and the callee gets that address instead. A
//! call into a plugin that is already running, from the host or through a chain of plugin calls, fails with
//! [`VmError::PluginBusy`] instead of deadlocking. So does [`Plugin::replace`] while the plugin runs.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError, Weak};

use crate::error::{HelperError, Result, VmError};
use crate::helper::HelperContext;
use crate::layout::{BORROW_FIRST_REGION, BORROW_REGIONS};
use crate::memory::{region_base, Perms};
use crate::program::{Borrow, Func, FuncSlot, Program};

/// A linked program that other programs can call into.
#[derive(Clone)]
pub struct Plugin {
    name: Arc<str>,
    program: Arc<Mutex<Program>>,
}

impl Plugin {
    /// Wrap `program` as the plugin `name`; errors from calls into it carry the name.
    pub fn new(name: impl Into<Arc<str>>, program: Program) -> Self {
        Self {
            name: name.into(),
            program: Arc::new(Mutex::new(program)),
        }
    }

    /// The name given to [`Plugin::new`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Call `func` with arguments in r1-r5.
    pub fn call(&self, func: &str, args: &[u64]) -> Result<u64> {
        self.lock()?.call(func, args)
    }

    /// Look up `func` for [`Plugin::call_func`]. [`Plugin::replace`] invalidates the handle; [`Plugin::named_func`]
    /// gives one that follows the replacement.
    pub fn func(&self, func: &str) -> Result<Func> {
        self.lock()?.func(func)
    }

    /// Call a function looked up with [`Plugin::func`]; arguments go in r1-r5.
    pub fn call_func(&self, func: Func, args: &[u64]) -> Result<u64> {
        self.lock()?.call_func(func, args)
    }

    /// Look up `func` for repeated calls through [`NamedFunc::call`]. After [`Plugin::replace`], the next call looks
    /// `func` up again in the new program. The handle keeps the plugin alive.
    pub fn named_func(&self, func: &str) -> Result<NamedFunc> {
        let slot = FuncSlot::new(self.func(func)?);
        Ok(NamedFunc {
            plugin: self.clone(),
            name: func.into(),
            func: slot,
        })
    }

    /// Exclusive access to the program, e.g. for its maps or memory.
    pub fn lock(&self) -> Result<MutexGuard<'_, Program>> {
        try_lock(&self.program, &self.name)
    }

    /// Swap in a new build of this plugin. Exports keep working; they find their function by name in the new program.
    /// Fails with [`VmError::PluginBusy`] while a call into the plugin runs, on any thread.
    pub fn replace(&self, program: Program) -> Result<()> {
        *self.lock()? = program;
        Ok(())
    }

    /// A handle that doesn't keep the plugin alive. Host functions that call back into a plugin should hold this: they
    /// live in the `Vm` that every plugin's program refers to, so a strong handle would be a cycle that frees neither.
    pub fn downgrade(&self) -> WeakPlugin {
        WeakPlugin {
            name: self.name.clone(),
            program: Arc::downgrade(&self.program),
        }
    }

    /// The extern that calls `func` in this plugin. Fails with [`VmError::FunctionNotFound`] if the plugin lacks it.
    pub fn export_fn(
        &self,
        func: &str,
    ) -> Result<impl Fn(&mut HelperContext) -> std::result::Result<u64, HelperError> + Send + Sync + 'static> {
        let target = ExportTarget::find(&*self.lock()?, func)
            .ok_or_else(|| VmError::FunctionNotFound(format!("{}::{func}", self.name)))?;
        let target = Mutex::new(target);
        let program: Weak<Mutex<Program>> = Arc::downgrade(&self.program);
        let name = self.name.clone();
        let func: Arc<str> = func.into();

        Ok(move |ctx: &mut HelperContext| -> std::result::Result<u64, HelperError> {
            let failed = |error: VmError| HelperError::Plugin {
                plugin: name.to_string(),
                func: func.to_string(),
                error: Box::new(error),
            };
            let program = program
                .upgrade()
                .ok_or_else(|| failed(VmError::PluginUnloaded(name.to_string())))?;
            let mut program = try_lock(&program, &name).map_err(failed)?;

            // only touched under the plugin lock, so this never waits
            let target = {
                let mut target = target.lock().unwrap_or_else(PoisonError::into_inner);
                if !program.owns(target.entry) {
                    *target = ExportTarget::find(&program, &func)
                        .ok_or_else(|| failed(VmError::FunctionNotFound(func.to_string())))?;
                }
                *target
            };

            let a = ctx.args;
            let mut args = [a.r1, a.r2, a.r3, a.r4, a.r5];
            if target.borrow_count == 0 {
                return program.call_func(target.entry, &args).map_err(failed);
            }

            let caller = &*ctx.memory;
            let mut mapped = Ok(());
            for &Borrow { arg, len_arg, writable } in target.borrows() {
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
                // SAFETY: the caller is blocked in this call; the regions are unmapped before it returns, or on the
                // next lock after a panic.
                unsafe { program.memory_mut().map_host(region, ptr, len, perms) };
                args[arg as usize] = region_base(region);
            }

            let result = mapped.and_then(|()| program.call_func(target.entry, &args).map_err(failed));
            for borrow in target.borrows() {
                program.memory_mut().unmap(BORROW_FIRST_REGION + borrow.arg as usize);
            }
            result
        })
    }
}

/// An exported function as found in one program, kept until [`Plugin::replace`] swaps the program.
#[derive(Clone, Copy)]
struct ExportTarget {
    entry: Func,
    /// Image loading checks that borrowed parameters are distinct argument registers, so there are at most 5.
    borrows: [Borrow; BORROW_REGIONS],
    borrow_count: usize,
}

impl ExportTarget {
    fn find(program: &Program, func: &str) -> Option<Self> {
        let (entry, info) = program.func_with_info(func)?;
        let unused = Borrow {
            arg: 0,
            len_arg: 0,
            writable: false,
        };
        let mut borrows = [unused; BORROW_REGIONS];
        borrows[..info.borrows.len()].copy_from_slice(&info.borrows);
        Some(Self {
            entry,
            borrows,
            borrow_count: info.borrows.len(),
        })
    }

    fn borrows(&self) -> &[Borrow] {
        &self.borrows[..self.borrow_count]
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

/// A function of a [`Plugin`] that follows [`Plugin::replace`]; see [`Plugin::named_func`].
#[derive(Debug)]
pub struct NamedFunc {
    plugin: Plugin,
    name: Arc<str>,
    func: FuncSlot,
}

impl NamedFunc {
    /// Call the function in the plugin's current program; arguments go in r1-r5. Fails with
    /// [`VmError::FunctionNotFound`] if that program lacks it.
    pub fn call(&self, args: &[u64]) -> Result<u64> {
        self.func.call(&mut *self.plugin.lock()?, &self.name, args)
    }
}

fn try_lock<'a>(program: &'a Mutex<Program>, name: &str) -> Result<MutexGuard<'a, Program>> {
    match program.try_lock() {
        Ok(guard) => Ok(guard),
        Err(TryLockError::WouldBlock) => Err(VmError::PluginBusy(name.to_string())),
        // a panic during a call poisons the lock and may have skipped unmapping borrowed caller memory, which may be
        // gone by now
        Err(TryLockError::Poisoned(e)) => {
            let mut guard = e.into_inner();
            for region in BORROW_FIRST_REGION..BORROW_FIRST_REGION + BORROW_REGIONS {
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

impl std::fmt::Debug for WeakPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeakPlugin").field("name", &self.name).finish()
    }
}
