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

use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Weak};

use crate::error::{HelperError, Result, VmError};
use crate::executor::MAX_ARGS;
use crate::helper::HelperContext;
use crate::layout::{BORROW_FIRST_REGION, BORROW_REGIONS};
use crate::memory::{region_base, Perms, VmMemory};
use crate::program::{Borrow, Func, FuncSlot, FunctionInfo, Program};
use crate::sync::{TryLock, TryLockGuard};

/// A linked program that other programs can call into.
#[derive(Clone)]
pub struct Plugin {
    name: Arc<str>,
    program: Arc<TryLock<Program>>,
}

impl Plugin {
    /// Wrap `program` as the plugin `name`; errors from calls into it carry the name.
    pub fn new(name: impl Into<Arc<str>>, program: Program) -> Self {
        Self {
            name: name.into(),
            program: Arc::new(TryLock::new(program)),
        }
    }

    /// The name given to [`Plugin::new`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Call `func` with arguments in r1-r5.
    pub fn call(&self, func: &str, args: &[u64]) -> Result<u64> {
        self.lock()?.call(func, args).map_err(|e| in_plugin(e, &self.name))
    }

    /// Look up `func` for repeated calls through [`PluginFunc::call`]. After [`Plugin::replace`], the next call looks
    /// `func` up again in the new program. The handle keeps the plugin alive.
    pub fn func(&self, func: &str) -> Result<PluginFunc> {
        let found = self.lock()?.func(func).map_err(|e| in_plugin(e, &self.name))?;
        Ok(PluginFunc {
            plugin: self.clone(),
            func: FuncSlot::new(found, func.into()),
        })
    }

    /// Exclusive access to the program, e.g. for its maps or memory. Fails with [`VmError::PluginBusy`] while a call
    /// into the plugin runs or another guard is alive.
    pub fn lock(&self) -> Result<TryLockGuard<'_, Program>> {
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
    pub(crate) fn export_fn(
        &self,
        func: &str,
    ) -> Result<impl Fn(&mut HelperContext) -> std::result::Result<u64, HelperError> + Send + Sync + 'static> {
        let slot = ExportSlot::find(&*self.lock()?, func).ok_or_else(|| not_found(&self.name, func))?;
        let program = Arc::downgrade(&self.program);
        let name = self.name.clone();
        Ok(move |ctx: &mut HelperContext| call_export(&program, &name, &slot, ctx))
    }
}

/// Call the export in `slot` of the plugin `name` with the arguments in `ctx`.
#[inline]
fn call_export(
    program: &Weak<TryLock<Program>>,
    name: &Arc<str>,
    slot: &ExportSlot,
    ctx: &mut HelperContext,
) -> std::result::Result<u64, HelperError> {
    // The caller's remaining instructions bound the callee and pay for what it runs. Asking for them stops the caller,
    // which only a call into another plugin pays for. Without metering there is nothing to ask for.
    let mut unmetered = 0;
    let fuel = match ctx.host.fuel.as_mut() {
        _ if !rvm_core::METERED => &mut unmetered,
        Some(fuel) => fuel,
        None => return Err(HelperError::FuelWanted),
    };

    let failed = |error: VmError| HelperError::Plugin {
        plugin: name.to_string(),
        func: slot.func.name().to_string(),
        error: Box::new(error),
    };
    let program = program
        .upgrade()
        .ok_or_else(|| failed(VmError::PluginUnloaded(name.to_string())))?;
    let mut program = try_lock(&program, name).map_err(failed)?;
    let (entry, borrows) = slot
        .get(&program)
        .ok_or_else(|| failed(not_found(name, slot.func.name())))?;

    let a = ctx.args;
    let args = [a.r1, a.r2, a.r3, a.r4, a.r5];
    if borrows.is_empty() {
        return program.call_func_charged(entry, &args, fuel).map_err(failed);
    }
    call_with_borrows(&mut program, entry, args, borrows, ctx.memory, fuel).map_err(failed)
}

/// Call `entry` in `callee` with the `caller`'s buffers that `borrows` names mapped into the callee's borrow regions,
/// charging the call to `fuel`.
fn call_with_borrows(
    callee: &mut Program,
    entry: Func,
    mut args: [u64; MAX_ARGS],
    borrows: Borrows,
    caller: &VmMemory,
    fuel: &mut u64,
) -> Result<u64> {
    let callee = UnmapBorrows {
        program: callee,
        borrows,
    };
    for Borrow { arg, len_arg, writable } in borrows {
        let (addr, len) = (args[arg as usize], args[len_arg as usize] as usize);
        // the caller must itself be allowed what the callee gets
        let perms = if writable { Perms::RW } else { Perms::R };
        // an empty buffer, such as `(NULL, 0)` from C, maps an empty region whatever the pointer
        let ptr = match len {
            0 => NonNull::dangling(),
            _ => caller.host_ptr(addr, len, perms)?,
        };
        let region = borrow_region(arg);
        // SAFETY: the caller is blocked in this call, and `callee` unmaps the region before the call returns or
        // unwinds.
        unsafe { callee.program.memory_any().map_host_any(region, ptr, len, perms) };
        args[arg as usize] = region_base(region);
    }
    callee.program.call_func_charged(entry, &args, fuel)
}

/// The borrow region of the pointer parameter `arg`.
fn borrow_region(arg: u8) -> usize {
    BORROW_FIRST_REGION + usize::from(arg)
}

/// The callee of a call with borrowed buffers. Unmaps the borrow regions when it goes out of scope, also when a host
/// function panics during the call.
struct UnmapBorrows<'a> {
    program: &'a mut Program,
    borrows: Borrows,
}

impl Drop for UnmapBorrows<'_> {
    fn drop(&mut self) {
        for borrow in self.borrows {
            let region = borrow_region(borrow.arg);
            self.program.memory_any().unmap_any(region);
        }
    }
}

/// An exported function as last found in the plugin's program, with its borrows; [`Plugin::replace`] makes the next call
/// look it up again. Only used under the plugin lock, which orders its relaxed accesses.
struct ExportSlot {
    func: FuncSlot,
    borrows: AtomicU64,
}

impl ExportSlot {
    fn find(program: &Program, func: &str) -> Option<Self> {
        let (entry, info) = program.func_with_info(func)?;
        Some(Self {
            func: FuncSlot::new(entry, func.into()),
            borrows: AtomicU64::new(Borrows::new(&info.borrows).0),
        })
    }

    /// The function in `program` and its borrows.
    #[inline]
    fn get(&self, program: &Program) -> Option<(Func, Borrows)> {
        let followed = |info: &FunctionInfo| self.borrows.store(Borrows::new(&info.borrows).0, Relaxed);
        let entry = self.func.get(program, followed)?;
        Some((entry, Borrows(self.borrows.load(Relaxed))))
    }
}

/// The borrowed parameters of a function, packed for [`ExportSlot`]: one byte per borrow from the low byte up, as
/// `0x80 | arg | len_arg << 3 | writable << 6`, then zero bytes.
#[derive(Clone, Copy)]
struct Borrows(u64);

impl Borrows {
    fn new(borrows: &[Borrow]) -> Self {
        // image loading checks that borrowed parameters are distinct argument registers
        assert!(borrows.len() <= BORROW_REGIONS);
        let mut packed = 0;
        for b in borrows.iter().rev() {
            let byte = 0x80 | b.arg | b.len_arg << 3 | u8::from(b.writable) << 6;
            packed = packed << 8 | u64::from(byte);
        }
        Self(packed)
    }

    #[inline]
    fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Iterator for Borrows {
    type Item = Borrow;

    #[inline]
    fn next(&mut self) -> Option<Borrow> {
        let b = self.0 as u8;
        if b == 0 {
            return None;
        }
        self.0 >>= 8;
        Some(Borrow {
            arg: b & 7,
            len_arg: b >> 3 & 7,
            writable: b & 0x40 != 0,
        })
    }
}

/// A [`Plugin`] handle that doesn't keep it alive; see [`Plugin::downgrade`].
#[derive(Clone)]
pub struct WeakPlugin {
    name: Arc<str>,
    program: Weak<TryLock<Program>>,
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

/// A function of a [`Plugin`] that follows [`Plugin::replace`]; see [`Plugin::func`].
#[derive(Debug)]
pub struct PluginFunc {
    plugin: Plugin,
    func: FuncSlot,
}

impl PluginFunc {
    /// Call the function in the plugin's current program; arguments go in r1-r5. Fails with
    /// [`VmError::FunctionNotFound`] if that program lacks it.
    pub fn call(&self, args: &[u64]) -> Result<u64> {
        self.func.call(&mut *self.plugin.lock()?, &self.plugin.name, args)
    }

    /// [`call`](Self::call) with [`Program::call_with_limit`].
    pub fn call_with_limit(&self, args: &[u64], limit: u64) -> (Result<u64>, u64) {
        let mut program = match self.plugin.lock() {
            Ok(program) => program,
            Err(error) => return (Err(error), 0),
        };
        match self.func.get(&program, |_| ()) {
            Some(func) => program.call_with_limit(func, args, limit),
            None => (Err(not_found(&self.plugin.name, self.func.name())), 0),
        }
    }
}

pub fn not_found(plugin: &str, func: &str) -> VmError {
    VmError::FunctionNotFound {
        plugin: Some(plugin.to_string()),
        func: func.to_string(),
    }
}

/// `error`, naming `plugin` if it is a failed lookup in the plugin's program.
#[cold]
#[inline(never)]
fn in_plugin(error: VmError, plugin: &str) -> VmError {
    match error {
        VmError::FunctionNotFound { plugin: None, func } => not_found(plugin, &func),
        error => error,
    }
}

// `name` by reference to the `Arc`: the call path then passes an address instead of loading the name
#[inline]
fn try_lock<'a>(program: &'a TryLock<Program>, name: &Arc<str>) -> Result<TryLockGuard<'a, Program>> {
    program.try_lock().ok_or_else(|| busy(name))
}

#[cold]
#[inline(never)]
fn busy(name: &Arc<str>) -> VmError {
    VmError::PluginBusy(name.to_string())
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
