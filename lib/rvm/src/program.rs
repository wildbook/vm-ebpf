//! Linked eBPF program ready for execution.
//!
//! A `Program` is a loaded [`crate::Image`]: the executable code, data, maps and function table.

use std::ops::Deref;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hashbrown::HashMap;
use rvm_core::Code;

use crate::error::{MemoryError, Result, VmError};
use crate::executor::{fuel_for, Executor, MAX_ARGS};
use crate::helper::{SharedHelpers, Snapshot};
#[cfg(feature = "maps")]
use crate::maps::{MapRef, Maps};
use crate::memory::{Perms, Scalar, VmMemory};
use crate::plugin::not_found;
use crate::vm::VmConfig;

/// Information about an executable function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Program counter (instruction index) where the function starts.
    pub pc: u64,
    /// Size of the function in bytes.
    pub size: u64,
    /// Pointer parameters that callers in other plugins lend for one call.
    pub borrows: Vec<Borrow>,
}

/// A pointer parameter tagged `borrow:N` (writable) or `borrow_ro:N` in BTF, where parameter `N` holds the buffer's
/// length in bytes. The callee sees the buffer at offset 0 of its own region, and a callee atomic at offset `o` counts
/// as aligned when the caller's address plus `o` is, since both name the same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Borrow {
    /// Index of the pointer parameter, 0 for r1.
    pub arg: u8,
    /// Index of the parameter that holds the length.
    pub len_arg: u8,
    /// Whether the callee may write the buffer (`borrow`) or only read it (`borrow_ro`).
    pub writable: bool,
}

impl Borrow {
    /// Both parameters are argument registers, and different ones.
    pub(crate) fn in_range(&self) -> bool {
        usize::from(self.arg) < MAX_ARGS && usize::from(self.len_arg) < MAX_ARGS && self.arg != self.len_arg
    }
}

/// A function of one [`Program`], looked up by name once so that repeated calls skip the lookup. See [`Program::func`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Func {
    program: u64,
    pc: u64,
}

/// A linked eBPF program ready for execution.
///
/// Holds the code (outside guest memory), guest memory regions (stack, data), and function table. Use `call()` to
/// execute a function by name, or look it up once with `func()` and call it with `call_func()`.
///
/// # Example
///
/// ```ignore
/// let mut program = vm.load_elf(&elf_bytes)?;
///
/// // Arguments go in r1-r5
/// let result = program.call("main", &[])?;
/// let result = program.call("process", &[ctx_ptr, len])?;
///
/// // Skip the name lookup on repeated calls
/// let process = program.func("process")?;
/// let result = program.call_func(process, &[ctx_ptr, len])?;
/// ```
#[derive(Debug)]
pub struct Program {
    /// Tells this program's [`Func`] handles from other programs'.
    id: u64,
    /// Instructions; not addressable by the guest.
    code: Code,
    /// Guest memory regions (stack, data, maps). See [`crate::layout`] for the layout.
    memory: VmMemory,
    functions: Functions,
    /// The VM's extern table, and the version of it that `executor` holds a copy of.
    shared_helpers: Arc<SharedHelpers>,
    helpers_version: u64,
    /// Runs the calls, with this program's maps and its copy of the extern table.
    executor: Executor,
}

impl Program {
    /// `helpers` is the copy of the VM's extern table `shared_helpers` the image was bound against.
    pub(crate) fn new(
        code: Code,
        memory: VmMemory,
        stack_top: u64,
        functions: Functions,
        shared_helpers: Arc<SharedHelpers>,
        helpers: Snapshot,
        config: &VmConfig,
    ) -> Self {
        Self {
            id: NEXT_PROGRAM_ID.fetch_add(1, Ordering::Relaxed),
            code,
            memory,
            functions,
            shared_helpers,
            helpers_version: helpers.version,
            executor: Executor::new(helpers.table, stack_top, config),
        }
    }

    /// The program's guest memory.
    pub fn memory(&self) -> &VmMemory {
        &self.memory
    }

    /// The program's guest memory, mutably, through accessors that leave the regions the program reserves alone.
    pub fn memory_mut(&mut self) -> ProgramMemory<'_> {
        ProgramMemory(&mut self.memory)
    }

    /// All of the program's guest memory, the reserved regions included.
    pub(crate) fn memory_any(&mut self) -> &mut VmMemory {
        &mut self.memory
    }

    /// The program with `maps`, whose values `memory` holds.
    #[cfg(feature = "maps")]
    pub(crate) fn with_maps(mut self, maps: Maps) -> Self {
        *self.executor.maps_mut() = maps;
        self
    }

    /// Host access to the map called `name`. Fails with [`VmError::MapNotFound`] if the program has none.
    #[cfg(feature = "maps")]
    pub fn map(&mut self, name: &str) -> Result<MapRef<'_>> {
        let maps = self.executor.maps_mut();
        let Some(handle) = maps.handle(name) else {
            return Err(VmError::MapNotFound(name.to_string()));
        };
        Ok(MapRef::new(maps, &mut self.memory, handle))
    }

    /// The exported functions, sorted by name. A function's position here is its index for [`Program::func_at`].
    pub fn functions(&self) -> impl ExactSizeIterator<Item = (&str, &FunctionInfo)> {
        self.functions.list.iter().map(|(name, info)| (name.as_str(), info))
    }

    /// The entry of the exported function called `name` in [`Program::functions`].
    pub fn function_info(&self, name: &str) -> Option<&FunctionInfo> {
        let index = self.functions.find(name)?.index;
        Some(&self.functions.list.get(index)?.1)
    }

    /// The index of the function called `name` in [`Program::functions`].
    #[inline]
    pub fn function_index(&self, name: &str) -> Option<usize> {
        Some(self.functions.find(name)?.index)
    }

    /// Call a function by name; arguments go in r1-r5.
    #[inline]
    pub fn call(&mut self, name: &str, args: &[u64]) -> Result<u64> {
        let pc = self.func(name)?.pc;
        self.call_pc(pc, args)
    }

    /// The function called `name`, for [`Program::call_func`].
    #[inline]
    pub fn func(&self, name: &str) -> Result<Func> {
        let Some(Entry { pc, .. }) = self.functions.find(name) else {
            return Err(function_not_found(name));
        };
        Ok(Func { program: self.id, pc })
    }

    /// The function at `index` in [`Program::functions`], for [`Program::call_func`]; `None` if `index` is out of
    /// range.
    #[inline]
    pub fn func_at(&self, index: usize) -> Option<Func> {
        let (_, info) = self.functions.list.get(index)?;
        Some(Func {
            program: self.id,
            pc: info.pc,
        })
    }

    /// The function called `name` and its table entry.
    #[inline]
    pub(crate) fn func_with_info(&self, name: &str) -> Option<(Func, &FunctionInfo)> {
        let Entry { index, pc } = self.functions.find(name)?;
        let (_, info) = self.functions.list.get(index)?;
        Some((Func { program: self.id, pc }, info))
    }

    /// Whether `func` was looked up in this program.
    #[inline]
    pub(crate) fn owns(&self, func: Func) -> bool {
        func.program == self.id
    }

    /// Call a function looked up with [`Program::func`]; arguments go in r1-r5.
    ///
    /// A handle from another program fails with [`VmError::ForeignFunc`].
    #[inline]
    pub fn call_func(&mut self, func: Func, args: &[u64]) -> Result<u64> {
        if !self.owns(func) {
            return Err(VmError::ForeignFunc);
        }
        self.call_pc(func.pc, args)
    }

    /// [`call_func`](Self::call_func) with an instruction limit of its own instead of
    /// [`VmConfig::instruction_limit`], 0 for none. Returns the result and the instructions the call ran, those it ran
    /// in other plugins through their exports included. Without the `fuel` feature, nothing counts them: it returns
    /// 0, and a non-zero `limit` fails with [`VmError::FuelNotEnabled`].
    pub fn call_func_with_limit(&mut self, func: Func, args: &[u64], limit: u64) -> (Result<u64>, u64) {
        if !self.owns(func) {
            return (Err(VmError::ForeignFunc), 0);
        }
        if !rvm_core::METERED && limit != 0 {
            return (Err(VmError::FuelNotEnabled), 0);
        }
        let start = fuel_for(limit);
        let mut fuel = start;
        let result = self.call_pc_fueled(func.pc, args, &mut fuel);
        (result, start - fuel)
    }

    /// [`call_func`](Self::call_func) for a host function that runs inside another call, which has `fuel` left: the
    /// call runs at most that and this program's limit, and takes what it ran from `fuel`.
    #[inline]
    pub(crate) fn call_func_charged(&mut self, func: Func, args: &[u64], fuel: &mut u64) -> Result<u64> {
        if !self.owns(func) {
            return Err(VmError::ForeignFunc);
        }
        let start = (*fuel).min(self.executor.instruction_limit());
        let mut left = start;
        let result = self.call_pc_fueled(func.pc, args, &mut left);
        *fuel -= start - left;
        result
    }

    // Out of line: the executor and interpreter compile once, in this crate, behind one call. Inlined into the
    // embedder's crate, this either calls the executor separately or compiles another copy of the interpreter, which
    // measured slower.
    //
    // The interpreter's handlers save no registers. With the default convention, this function would save and restore
    // every callee-saved register (on Windows also xmm6 to xmm15) on each call; with `rust-preserve-none`, callers keep
    // only what they need after the call, and a caller in a loop saves its own registers once.
    extern "rust-preserve-none" fn call_pc(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        if self.shared_helpers.version() != self.helpers_version {
            self.refresh_helpers();
        }
        self.executor.call(&self.code, &mut self.memory, pc, args)
    }

    /// [`call_pc`](Self::call_pc) with `*fuel` instructions, leaving what is left there. A function of its own, so that
    /// `call_pc` starts from the instruction limit and reports nothing back.
    #[inline(never)]
    fn call_pc_fueled(&mut self, pc: u64, args: &[u64], fuel: &mut u64) -> Result<u64> {
        if self.shared_helpers.version() != self.helpers_version {
            self.refresh_helpers();
        }
        self.executor.call_fueled(&self.code, &mut self.memory, pc, args, fuel)
    }

    #[cold]
    #[inline(never)]
    fn refresh_helpers(&mut self) {
        let Snapshot { table, version } = self.shared_helpers.snapshot();
        self.executor.set_helpers(table);
        self.helpers_version = version;
    }
}

/// A program's guest memory from [`Program::memory_mut`]. It reads like a [`VmMemory`], and maps and writes as one
/// except that it can't replace the memory or remap the regions the program reserves, which its maps and stack need.
pub struct ProgramMemory<'a>(&'a mut VmMemory);

impl ProgramMemory<'_> {
    /// [`VmMemory::map`].
    pub fn map(&mut self, idx: usize, len: usize, perms: Perms) -> Result<u64> {
        self.0.map(idx, len, perms)
    }

    /// [`VmMemory::map_bytes`].
    pub fn map_bytes(&mut self, idx: usize, init: &[u8], len: usize, perms: Perms) -> Result<u64> {
        self.0.map_bytes(idx, init, len, perms)
    }

    /// [`VmMemory::map_host`].
    ///
    /// # Safety
    ///
    /// As [`VmMemory::map_host`].
    pub unsafe fn map_host(&mut self, idx: usize, ptr: NonNull<u8>, len: usize, perms: Perms) -> Result<u64> {
        // SAFETY: the caller's contract.
        unsafe { self.0.map_host(idx, ptr, len, perms) }
    }

    /// [`VmMemory::unmap`].
    pub fn unmap(&mut self, idx: usize) -> Result<()> {
        self.0.unmap(idx)
    }

    /// [`VmMemory::bytes_mut`].
    pub fn bytes_mut(&mut self, addr: u64, len: usize) -> std::result::Result<&mut [u8], MemoryError> {
        self.0.bytes_mut(addr, len)
    }

    /// [`VmMemory::write_bytes`].
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> std::result::Result<(), MemoryError> {
        self.0.write_bytes(addr, data)
    }

    /// [`VmMemory::write`].
    pub fn write<T: Scalar>(&mut self, addr: u64, value: T) -> std::result::Result<(), MemoryError> {
        self.0.write(addr, value)
    }

    /// [`VmMemory::copy`].
    pub fn copy(&mut self, src: u64, dst: u64, len: usize) -> std::result::Result<(), MemoryError> {
        self.0.copy(src, dst, len)
    }
}

impl Deref for ProgramMemory<'_> {
    type Target = VmMemory;

    fn deref(&self) -> &VmMemory {
        self.0
    }
}

/// A [`Func`] in two atomics. Callers serialize access, e.g. under a plugin's lock.
#[derive(Debug)]
pub struct AtomicFunc {
    program: AtomicU64,
    pc: AtomicU64,
}

impl AtomicFunc {
    pub fn new(func: Func) -> Self {
        Self {
            program: AtomicU64::new(func.program),
            pc: AtomicU64::new(func.pc),
        }
    }

    #[inline]
    pub fn load(&self) -> Func {
        Func {
            program: self.program.load(Ordering::Relaxed),
            pc: self.pc.load(Ordering::Relaxed),
        }
    }

    #[inline]
    pub fn store(&self, func: Func) {
        self.program.store(func.program, Ordering::Relaxed);
        self.pc.store(func.pc, Ordering::Relaxed);
    }
}

/// A [`Func`] that follows its function by name into whichever program it is called with, for handles that outlive the
/// program they were looked up in. Callers serialize access per slot, e.g. under a plugin's lock.
#[derive(Debug)]
pub struct FuncSlot {
    func: AtomicFunc,
    name: Arc<str>,
}

impl FuncSlot {
    pub fn new(func: Func, name: Arc<str>) -> Self {
        Self {
            func: AtomicFunc::new(func),
            name,
        }
    }

    /// The function's name in every program.
    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    /// Call the function in `program`, looking it up again if the slot holds a function of another program. Fails
    /// with [`VmError::FunctionNotFound`] naming `plugin` if `program` lacks it.
    #[inline]
    pub fn call(&self, program: &mut Program, plugin: &Arc<str>, args: &[u64]) -> Result<u64> {
        let Some(func) = self.get(program, |_| ()) else {
            return Err(not_found(plugin, &self.name));
        };
        program.call_func(func, args)
    }

    /// The function in `program`, looked up again if the slot holds a function of another program; after such a
    /// lookup, `followed` gets the new entry. `None` if `program` lacks the function.
    #[inline]
    pub fn get(&self, program: &Program, followed: impl FnOnce(&FunctionInfo)) -> Option<Func> {
        let func = self.func.load();
        if program.owns(func) {
            Some(func)
        } else {
            self.follow(program, followed)
        }
    }

    /// Look the function up in `program`, which replaced the slot's program, and keep it.
    #[cold]
    #[inline(never)]
    fn follow(&self, program: &Program, followed: impl FnOnce(&FunctionInfo)) -> Option<Func> {
        let (func, info) = program.func_with_info(&self.name)?;
        self.func.store(func);
        followed(info);
        Some(func)
    }
}

/// A program's exported functions: sorted by name, which gives each its index, and hashed for calls by name.
#[derive(Debug)]
pub struct Functions {
    list: Vec<(String, FunctionInfo)>,
    // the pc sits in the map, which measured faster for calls by name than reading it from `list`
    by_name: HashMap<String, Entry>,
}

impl Functions {
    /// The table of `list`; `None` unless `list` is sorted by name with every name once.
    pub fn new(list: Vec<(String, FunctionInfo)>) -> Option<Self> {
        if !list.is_sorted_by(|(a, _), (b, _)| a < b) {
            return None;
        }
        let by_name = list
            .iter()
            .enumerate()
            .map(|(index, (name, info))| (name.clone(), Entry { index, pc: info.pc }))
            .collect();
        Some(Self { list, by_name })
    }

    #[inline(always)]
    fn find(&self, name: &str) -> Option<Entry> {
        self.by_name.get(name).copied()
    }
}

/// A function's position in [`Functions`] and its entry point.
#[derive(Debug, Clone, Copy)]
struct Entry {
    index: usize,
    pc: u64,
}

static NEXT_PROGRAM_ID: AtomicU64 = AtomicU64::new(0);

// out of line, so that `Program::func` stays small enough to inline
#[cold]
#[inline(never)]
fn function_not_found(name: &str) -> VmError {
    VmError::FunctionNotFound {
        plugin: None,
        func: name.to_string(),
    }
}
