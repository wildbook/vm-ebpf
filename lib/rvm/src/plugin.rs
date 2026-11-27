//! Programs that call each other.
//!
//! A [`Plugin`] is a linked program behind a lock. [`crate::Vm::export`] publishes one of its functions as a named
//! extern, so programs linked afterwards can import it like a host function. The call runs in the exporting plugin,
//! with its memory, maps and helpers.
//!
//! Arguments and the result are plain values: a pointer from one plugin means nothing in another's memory, unless the
//! exported function tags the parameter as a borrow (see [`Borrow`]). Then the caller's buffer is mapped into the
//! callee at a [`BORROW_FIRST_REGION`] slot for the duration of the call, and the callee gets that address instead.
//! A call passes up to 12 arguments: those past the fifth where the importing program declares the function with
//! them, in its BTF. The result is the callee's r0, which holds up to 8 bytes. A struct of more than 16 bytes comes
//! back through a pointer into the caller's memory, which the callee can follow only where both plugins are untagged.
//!
//! A call into a plugin that is already running, from the host or through a chain of plugin calls, fails with
//! [`VmError::PluginBusy`] instead of deadlocking. So does [`Plugin::replace`] while the plugin runs.

use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Weak};

use crate::error::{HostError, MemoryError, Result, VmError};
use crate::executor::{MAX_ARGS, REG_ARGS};
use crate::helper::{CallerFuel, HelperContext, Stop};
use crate::layout::{BORROW_FIRST_REGION, BORROW_REGIONS};
use crate::memory::{Perms, VmMemory, MAX_REGION_LEN};
use crate::program::{Borrow, Func, FuncSlot, FunctionInfo, LimitedCall, Program};
use crate::sync::{TryLock, TryLockGuard};

/// A linked program that other programs can call into.
///
/// # Example
///
/// ```ignore
/// let math = Plugin::new("math", vm.load_elf(&math_elf)?);
/// // programs linked from here on can declare `extern u64 scale(u64 x);` and call it
/// vm.export(&math, "scale")?;
/// let game = Plugin::new("game", vm.load_elf(&game_elf)?);
///
/// let tick = game.func("on_tick")?;
/// tick.call(&[1])?;
/// // exports and function handles follow the new program
/// math.replace(vm.load_elf(&math_v2_elf)?)?;
/// tick.call(&[2])?;
/// ```
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

    /// Call `func` with arguments as for [`Program::call`].
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
    ) -> Result<impl Fn(&mut HelperContext) -> std::result::Result<u64, Stop> + Send + Sync + 'static> {
        let slot = ExportSlot::find(&*self.lock()?, func).ok_or_else(|| not_found(&self.name, func))?;
        let program = Arc::downgrade(&self.program);
        let name = self.name.clone();
        Ok(move |ctx: &mut HelperContext| call_export(&program, &name, &slot, ctx))
    }
}

/// Call the export in `slot` of the plugin `name` with the arguments in `ctx`.
// Always inline: the two trampolines of the export then each keep the code of their own kind of call, with stack
// arguments or without.
#[inline(always)]
fn call_export(
    program: &Weak<TryLock<Program>>,
    name: &Arc<str>,
    slot: &ExportSlot,
    ctx: &mut HelperContext,
) -> std::result::Result<u64, Stop> {
    // A caller with a limit pays for what the callee runs, and its remaining instructions bound the callee. Asking for
    // them stops the caller, which only a call into another plugin pays for. A caller without a limit leaves the
    // callee its own.
    let fuel = match &mut ctx.host.fuel {
        CallerFuel::Unmetered => None,
        CallerFuel::Left(fuel) => Some(fuel),
        CallerFuel::Unknown => return Err(Stop::FuelWanted),
    };

    let failed = |error: VmError| {
        Stop::Failed(HostError::Plugin {
            plugin: name.to_string(),
            func: slot.func.name().to_string(),
            error: Box::new(error),
        })
    };
    let program = program
        .upgrade()
        .ok_or_else(|| failed(VmError::PluginUnloaded(name.to_string())))?;
    let mut program = try_lock(&program, name).map_err(failed)?;
    let (entry, borrows) = slot
        .get(&program)
        .ok_or_else(|| failed(not_found(name, slot.func.name())))?;

    // five arguments, or all twelve from a call that passes arguments on the stack
    let a = ctx.args;
    let mut regs = [a.r1, a.r2, a.r3, a.r4, a.r5];
    let mut all = [0; MAX_ARGS];
    let args: &mut [u64] = match a.stack {
        None => &mut regs,
        Some(stack) => {
            all[..REG_ARGS].copy_from_slice(&regs);
            all[REG_ARGS..].copy_from_slice(stack);
            &mut all
        }
    };
    if borrows.is_empty() {
        return program.call_func_charged(entry, args, fuel).map_err(failed);
    }
    call_with_borrows(&mut program, entry, args, borrows, ctx.memory, fuel).map_err(failed)
}

/// Call `entry` in `callee` with `args`, and with the `caller`'s buffers that `borrows` names among them mapped into
/// the callee's borrow regions, charging the call to `fuel` if the caller is metered.
fn call_with_borrows(
    callee: &mut Program,
    entry: Func,
    args: &mut [u64],
    borrows: Borrows,
    caller: &VmMemory,
    fuel: Option<&mut u64>,
) -> Result<u64> {
    let callee = UnmapBorrows {
        program: callee,
        borrows,
    };
    for (index, Borrow { arg, len_arg, writable }) in borrows.enumerate() {
        let (arg, len_arg) = (usize::from(arg), usize::from(len_arg));
        let (Some(&addr), Some(&len)) = (args.get(arg), args.get(len_arg)) else {
            return Err(not_passed(arg.max(len_arg), args.len()));
        };
        if len > MAX_REGION_LEN as u64 {
            return Err(MemoryError {
                addr,
                size: len.min(usize::MAX as u64) as usize,
            }
            .into());
        }
        let len = len as usize;
        // the caller must itself be allowed what the callee gets
        let perms = if writable { Perms::RW } else { Perms::R };
        // an empty buffer, such as `(NULL, 0)` from C, maps an empty region whatever the pointer
        let ptr = match len {
            0 => NonNull::dangling(),
            _ => caller.host_ptr(addr, len, perms)?,
        };
        let region = borrow_region(index);
        // the callee sees the caller's bytes at their host address, under the borrow region's tag
        // SAFETY: the caller is blocked in this call, and `callee` unmaps the region before the call returns or
        // unwinds.
        args[arg] = unsafe { callee.program.memory_any().map_host_any(region, ptr, len, perms) };
    }
    callee.program.call_func_charged(entry, args, fuel)
}

/// The error of a call with `passed` arguments to a function that borrows through its argument at position `arg`,
/// which the call doesn't pass: the importing program has no BTF that declares the arguments past the fifth.
#[cold]
fn not_passed(arg: usize, passed: usize) -> VmError {
    let msg = format!("the function borrows a buffer through argument {}, and the call passes {passed}", arg + 1);
    VmError::InvalidArgument(msg)
}

/// The borrow region of the borrowed parameter at `index` among those of its function.
fn borrow_region(index: usize) -> usize {
    BORROW_FIRST_REGION + index
}

/// The callee of a call with borrowed buffers. Unmaps the borrow regions when it goes out of scope, also when a host
/// function panics during the call.
struct UnmapBorrows<'a> {
    program: &'a mut Program,
    borrows: Borrows,
}

impl Drop for UnmapBorrows<'_> {
    fn drop(&mut self) {
        for index in 0..self.borrows.count() {
            self.program.memory_any().unmap_any(borrow_region(index));
        }
    }
}

/// An exported function as last found in the plugin's program, with its borrows; [`Plugin::replace`] makes the next
/// call look it up again. Only used under the plugin lock, which orders its relaxed accesses.
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

/// The borrowed parameters of a function, packed for [`ExportSlot`]: 12 bits per borrow from the low bits up, as
/// `0x800 | arg | len_arg << 4 | writable << 8`, then zero bits.
#[derive(Clone, Copy)]
struct Borrows(u64);

impl Borrows {
    /// The bits of one borrow.
    const BITS: u32 = 12;

    fn new(borrows: &[Borrow]) -> Self {
        // image loading checks that a function borrows through at most `BORROW_REGIONS` distinct argument positions,
        // each below 16
        assert!(borrows.len() <= BORROW_REGIONS);
        let mut packed = 0;
        for b in borrows.iter().rev() {
            let bits = 0x800 | u64::from(b.arg) | u64::from(b.len_arg) << 4 | u64::from(b.writable) << 8;
            packed = packed << Self::BITS | bits;
        }
        Self(packed)
    }

    #[inline]
    fn is_empty(self) -> bool {
        self.0 == 0
    }
}

const _: () = assert!(BORROW_REGIONS as u32 * Borrows::BITS <= u64::BITS && MAX_ARGS <= 16);

impl Iterator for Borrows {
    type Item = Borrow;

    #[inline]
    fn next(&mut self) -> Option<Borrow> {
        let bits = self.0 & ((1 << Self::BITS) - 1);
        if bits == 0 {
            return None;
        }
        self.0 >>= Self::BITS;
        Some(Borrow {
            arg: (bits & 15) as u8,
            len_arg: (bits >> 4 & 15) as u8,
            writable: bits & 0x100 != 0,
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
    /// Call the function in the plugin's current program, with arguments as for [`Program::call`]. Fails with
    /// [`VmError::FunctionNotFound`] if that program lacks it.
    pub fn call(&self, args: &[u64]) -> Result<u64> {
        self.func.call(&mut *self.plugin.lock()?, &self.plugin.name, args)
    }

    /// [`call`](Self::call) with [`Program::call_func_with_limit`].
    pub fn call_with_limit(&self, args: &[u64], limit: u64) -> LimitedCall {
        let mut program = match self.plugin.lock() {
            Ok(program) => program,
            Err(error) => return LimitedCall::failed(error),
        };
        match self.func.get(&program, |_| ()) {
            Some(func) => program.call_func_with_limit(func, args, limit),
            None => LimitedCall::failed(not_found(&self.plugin.name, self.func.name())),
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
