//! Native-to-guest callback thunk pool, unmarshalling, and `rvm_callback` / `rvm_callback_free` builtins.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use rvm_core::{call_active, set_thunk_handler, thunk_addr, thunk_index, THUNK_COUNT};

use crate::error::VmError;
use crate::executor::{code_index, REG_ARGS};
use crate::helper::{HelperContext, HelperRegistry, HostFn, Stop};
use crate::image::CallbackInfo;
use crate::plugin::{not_found, WeakPlugin};
use crate::program::Program;
use crate::proto::{ArgKind, Proto, ReturnKind};
use crate::sync::{TryLock, TryLockGuard};

/// Unmarshalling rule for one C parameter of a guest callback.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CallbackArg {
    /// Integer, pointer, or 1/2/4/8-byte struct in one integer argument slot.
    Int,
    /// `float` or `double`.
    Float,
    /// Struct of 3, 5, 6 or 7 bytes: Win64 passes a pointer to `size` bytes, loaded into 1 guest register.
    Copy1(u8),
    /// Struct of 9 to 16 bytes: Win64 passes a pointer to `size` bytes, loaded into 2 guest registers.
    Copy2(u8),
}

/// Compact unmarshalling description for a guest callback (at most 5 guest registers, no aggregate return).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallbackAbi {
    args: [CallbackArg; REG_ARGS],
    nargs: u8,
    guest_regs: u8,
}

impl CallbackAbi {
    pub fn from_proto(proto: &Proto) -> Option<Self> {
        if proto.variadic || matches!(proto.ret, ReturnKind::Agg(_)) || proto.args.len() > REG_ARGS {
            return None;
        }
        let guest_regs = proto.reg_count();
        if guest_regs > REG_ARGS {
            return None;
        }
        let mut args = [CallbackArg::Int; REG_ARGS];
        for (i, &arg) in proto.args.iter().enumerate() {
            args[i] = match arg {
                ArgKind::Int | ArgKind::Ptr | ArgKind::Callback => CallbackArg::Int,
                ArgKind::Float(4 | 8) => CallbackArg::Float,
                ArgKind::Copy(size @ (3 | 5 | 6 | 7)) => CallbackArg::Copy1(size),
                ArgKind::Copy(size @ 9..=16) => CallbackArg::Copy2(size),
                ArgKind::Float(_) | ArgKind::Copy(_) => return None,
            };
        }
        Some(Self {
            args,
            nargs: proto.args.len() as u8,
            guest_regs: guest_regs as u8,
        })
    }

    /// Unmarshal host C ABI arguments (`ints`, `floats`) into guest `r1..r5`.
    ///
    /// # Safety
    ///
    /// `ints` and `floats` must point to the argument save areas constructed by `rvm_thunk_common` for a foreign
    /// caller matching this ABI, and any by-reference struct pointers must point to valid readable memory of the
    /// declared struct size.
    unsafe fn unmarshal(&self, ints: *const u64, floats: *const u64) -> [u64; REG_ARGS] {
        let mut regs = [0u64; REG_ARGS];
        let mut g_idx = 0usize;

        #[cfg(windows)]
        {
            for (c_idx, &arg) in self.args.iter().take(usize::from(self.nargs)).enumerate() {
                match arg {
                    CallbackArg::Int => {
                        if let Some(dst) = regs.get_mut(g_idx) {
                            // SAFETY: Win64 home area + stack args hold contiguous u64 slots for each C parameter
                            *dst = unsafe { *ints.add(c_idx) };
                        }
                        g_idx += 1;
                    }
                    CallbackArg::Float => {
                        if let Some(dst) = regs.get_mut(g_idx) {
                            // Win64 passes the first 4 float args positionally in xmm0..xmm3, later ones on the stack
                            *dst = if c_idx < 4 {
                                unsafe { *floats.add(c_idx) }
                            } else {
                                unsafe { *ints.add(c_idx) }
                            };
                        }
                        g_idx += 1;
                    }
                    CallbackArg::Copy1(size) => {
                        let ptr = unsafe { *ints.add(c_idx) } as *const u8;
                        let mut word = 0u64;
                        if !ptr.is_null() {
                            let len = usize::from(size).min(8);
                            unsafe { std::ptr::copy_nonoverlapping(ptr, (&raw mut word).cast::<u8>(), len) };
                        }
                        if let Some(dst) = regs.get_mut(g_idx) {
                            *dst = word.to_le();
                        }
                        g_idx += 1;
                    }
                    CallbackArg::Copy2(size) => {
                        let ptr = unsafe { *ints.add(c_idx) } as *const u8;
                        let mut words = [0u64; 2];
                        if !ptr.is_null() {
                            let len = usize::from(size).min(16);
                            unsafe { std::ptr::copy_nonoverlapping(ptr, words.as_mut_ptr().cast::<u8>(), len) };
                        }
                        if let Some(dst) = regs.get_mut(g_idx) {
                            *dst = words[0].to_le();
                        }
                        if let Some(dst) = regs.get_mut(g_idx + 1) {
                            *dst = words[1].to_le();
                        }
                        g_idx += 2;
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            let mut i_idx = 0usize;
            let mut f_idx = 0usize;
            for &arg in self.args.iter().take(usize::from(self.nargs)) {
                match arg {
                    CallbackArg::Int => {
                        if let Some(dst) = regs.get_mut(g_idx) {
                            *dst = unsafe { *ints.add(i_idx) };
                        }
                        i_idx += 1;
                        g_idx += 1;
                    }
                    CallbackArg::Float => {
                        if let Some(dst) = regs.get_mut(g_idx) {
                            *dst = unsafe { *floats.add(f_idx) };
                        }
                        f_idx += 1;
                        g_idx += 1;
                    }
                    CallbackArg::Copy1(_) => {
                        if let Some(dst) = regs.get_mut(g_idx) {
                            *dst = unsafe { *ints.add(i_idx) };
                        }
                        i_idx += 1;
                        g_idx += 1;
                    }
                    CallbackArg::Copy2(_) => {
                        if let Some(dst) = regs.get_mut(g_idx) {
                            *dst = unsafe { *ints.add(i_idx) };
                        }
                        if let Some(dst) = regs.get_mut(g_idx + 1) {
                            *dst = unsafe { *ints.add(i_idx + 1) };
                        }
                        i_idx += 2;
                        g_idx += 2;
                    }
                }
            }
        }

        regs
    }
}

/// One address-taken plugin function compiled for callback lookup.
#[derive(Clone, Debug)]
pub struct CompiledCallback {
    pub pc: u64,
    pub name: Option<Arc<str>>,
    pub abi: CallbackAbi,
}

/// Callback metadata and retained thunk slots belonging to one [`Program`].
#[derive(Debug, Default)]
pub struct ProgramCallbacks {
    pub program_id: u64,
    entries: Box<[CompiledCallback]>,
    plugin: Option<WeakPlugin>,
    /// Retained thunk slots allocated by `rvm_callback`: `(slot_index, is_exported)`.
    retained: Vec<(u8, bool)>,
}

impl ProgramCallbacks {
    pub fn new(program_id: u64, callbacks: &[CallbackInfo]) -> Self {
        let entries: Vec<CompiledCallback> = callbacks
            .iter()
            .filter_map(|cb| {
                Some(CompiledCallback {
                    pc: cb.pc,
                    name: cb.name.as_deref().map(Arc::from),
                    abi: CallbackAbi::from_proto(&cb.proto)?,
                })
            })
            .collect();
        Self {
            program_id,
            entries: entries.into_boxed_slice(),
            plugin: None,
            retained: Vec::new(),
        }
    }

    pub fn set_plugin(&mut self, plugin: WeakPlugin) {
        self.plugin = Some(plugin);
    }

    pub fn find(&self, pc: u64) -> Option<&CompiledCallback> {
        self.entries.iter().find(|e| e.pc == pc)
    }

    /// Claim a scoped thunk slot for the plugin function at `pc` (released when the native call returns).
    pub fn claim_scoped(&self, pc: u64) -> Option<Result<(u64, u8), VmError>> {
        let entry = self.find(pc)?;
        let data = SlotData {
            program_id: self.program_id,
            pc: entry.pc,
            export_name: entry.name.clone(),
            abi: entry.abi,
            plugin: None,
        };
        Some(match claim_slot(data) {
            Some(slot) => Ok((thunk_addr(slot), slot)),
            None => Err(VmError::NoFreeCallback),
        })
    }

    /// Claim a retained thunk slot for `func` (guest code address), returning its host address or `0` if invalid or
    /// the pool is full.
    pub fn claim_retained(&mut self, func: u64) -> u64 {
        let Some(pc) = code_index(func) else {
            return 0;
        };
        let Some(entry) = self.find(pc) else {
            return 0;
        };
        let is_exported = entry.name.is_some();
        let data = SlotData {
            program_id: self.program_id,
            pc: entry.pc,
            export_name: entry.name.clone(),
            abi: entry.abi,
            plugin: self.plugin.clone(),
        };
        let Some(slot) = claim_slot(data) else {
            return 0;
        };
        self.retained.push((slot, is_exported));
        thunk_addr(slot)
    }

    /// Release a retained thunk slot owned by this program.
    pub fn free_retained(&mut self, thunk: u64) {
        let Some(slot) = thunk_index(thunk) else {
            return;
        };
        let prev = self.retained.len();
        self.retained.retain(|&(s, _)| s != slot);
        if self.retained.len() != prev {
            release_slot(slot);
        }
    }

    /// Transfer exported retained slots from `self` (an old plugin build being replaced) to `new_prog`, updating each
    /// slot's target `program_id` and `pc` in the new build. Static slots stay on `self` and are freed on drop.
    pub fn transfer_exported_to(&mut self, new_prog: &mut Program) {
        let new_id = new_prog.id();
        let mut kept = Vec::new();
        for (slot, exported) in self.retained.drain(..) {
            if !exported {
                kept.push((slot, false));
                continue;
            }
            {
                let mut guard = lock_slot(slot);
                if let Some(data) = guard.as_mut() {
                    if let Some(name) = data.export_name.as_deref() {
                        match new_prog.func(name) {
                            Ok(func) => {
                                data.program_id = new_id;
                                data.pc = func.pc();
                            }
                            Err(_) => {
                                data.program_id = 0;
                            }
                        }
                    }
                }
            }
            new_prog.push_retained_callback(slot, true);
        }
        self.retained = kept;
    }

    pub fn push_retained(&mut self, slot: u8, exported: bool) {
        self.retained.push((slot, exported));
    }
}

impl Drop for ProgramCallbacks {
    fn drop(&mut self) {
        for &(slot, _) in &self.retained {
            release_slot(slot);
        }
    }
}

/// Register the `rvm_callback` and `rvm_callback_free` builtins in `registry`.
pub fn register_builtins(registry: &mut HelperRegistry) {
    registry.put_name("rvm_callback".to_string(), HostFn::raw(builtin_callback));
    registry.put_name("rvm_callback_free".to_string(), HostFn::raw(builtin_callback_free));
}

fn builtin_callback(ctx: &mut HelperContext<'_>) -> Result<u64, Stop> {
    Ok(ctx.host.callbacks.claim_retained(ctx.args.r1))
}

fn builtin_callback_free(ctx: &mut HelperContext<'_>) -> Result<u64, Stop> {
    ctx.host.callbacks.free_retained(ctx.args.r1);
    Ok(0)
}

#[derive(Clone)]
struct SlotData {
    program_id: u64,
    pc: u64,
    export_name: Option<Arc<str>>,
    abi: CallbackAbi,
    plugin: Option<WeakPlugin>,
}

static HANDLER_SET: AtomicBool = AtomicBool::new(false);
static USED: AtomicU64 = AtomicU64::new(0);
static SLOTS: [TryLock<Option<SlotData>>; THUNK_COUNT] = [const { TryLock::new(None) }; THUNK_COUNT];

fn lock_slot(index: u8) -> TryLockGuard<'static, Option<SlotData>> {
    let slot = &SLOTS[usize::from(index) & (THUNK_COUNT - 1)];
    loop {
        if let Some(guard) = slot.try_lock() {
            return guard;
        }
        std::hint::spin_loop();
    }
}

fn claim_slot(data: SlotData) -> Option<u8> {
    if !HANDLER_SET.load(Ordering::Relaxed) {
        set_thunk_handler(thunk_dispatch);
        HANDLER_SET.store(true, Ordering::Relaxed);
    }

    let mut mask = USED.load(Ordering::Acquire);
    loop {
        let free = !mask;
        if free == 0 {
            return None;
        }
        let idx = free.trailing_zeros() as u8;
        let bit = 1u64 << idx;
        match USED.compare_exchange_weak(mask, mask | bit, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                *lock_slot(idx) = Some(data);
                return Some(idx);
            }
            Err(cur) => mask = cur,
        }
    }
}

/// Release thunk slot `index` back to the global pool.
pub fn release_slot(index: u8) {
    let old = lock_slot(index).take();
    drop(old);
    USED.fetch_and(!(1u64 << index), Ordering::Release);
}

extern "C" fn thunk_dispatch(index: u32, ints: *const u64, floats: *const u64) -> u64 {
    if index as usize >= THUNK_COUNT {
        return 0;
    }
    let idx = index as u8;
    let Some(slot) = lock_slot(idx).clone() else {
        return 0;
    };

    // SAFETY: `rvm_thunk_common` constructs valid `ints` and `floats` arrays for the caller's ABI
    let regs = unsafe { slot.abi.unmarshal(ints, floats) };

    // Case 1: synchronous nested call inside the innermost aware call of this program on this thread.
    if slot.program_id != 0 {
        if let Some(result) = call_active(Some(slot.program_id), slot.pc, &regs) {
            return result.unwrap_or(0);
        }
    }

    // Case 2: later or cross-thread call into an idle Plugin.
    if let Some(weak) = &slot.plugin {
        let Some(plugin) = weak.upgrade() else {
            release_slot(idx);
            return 0;
        };
        let Ok(mut program) = plugin.lock() else {
            plugin.set_callback_error(VmError::PluginBusy(plugin.name().to_string()));
            return 0;
        };
        let pc = match &slot.export_name {
            Some(name) => match program.func(name) {
                Ok(func) => func.pc(),
                Err(_) => {
                    plugin.set_callback_error(not_found(plugin.name(), name));
                    return 0;
                }
            },
            None if program.id() == slot.program_id => slot.pc,
            None => {
                drop(program);
                release_slot(idx);
                plugin.set_callback_error(VmError::PluginUnloaded(plugin.name().to_string()));
                return 0;
            }
        };
        let args = regs.get(..usize::from(slot.abi.guest_regs)).unwrap_or(&regs);
        return match program.call_pc_internal(pc, args) {
            Ok(r0) => r0,
            Err(err) => {
                drop(program);
                plugin.set_callback_error(err);
                0
            }
        };
    }

    // Case 3: bare Program with no matching aware call in progress.
    0
}
