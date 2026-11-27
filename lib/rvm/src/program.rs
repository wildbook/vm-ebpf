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
use crate::memory::{Perms, Region, Scalar, VmMemory};
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
///
/// Both fields are argument positions, not parameter indices: 0 to 4 for r1 to r5, then 5 to 11 for the arguments on
/// the stack. After the result pointer of a returned struct of more than 16 bytes or a struct parameter of 9 to 16
/// bytes, a parameter sits in a later position than its index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Borrow {
    /// Position of the pointer parameter, 0 for r1.
    pub arg: u8,
    /// Position of the parameter that holds the length.
    pub len_arg: u8,
    /// Whether the callee may write the buffer (`borrow`) or only read it (`borrow_ro`).
    pub writable: bool,
}

impl Borrow {
    /// Both parameters are argument positions, and different ones.
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

/// What a call with an instruction limit of its own returns; see [`Program::call_func_with_limit`].
#[derive(Debug)]
pub struct LimitedCall {
    /// The function's r0, or why the call failed.
    pub result: Result<u64>,
    /// The instructions the call ran, those it ran in other plugins through their exports included.
    pub instructions: u64,
}

impl LimitedCall {
    /// A call that failed before it ran an instruction.
    pub(crate) fn failed(error: VmError) -> Self {
        Self {
            result: Err(error),
            instructions: 0,
        }
    }
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
/// // The first five arguments go in r1-r5, up to seven more where a call passes them on the stack
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

    /// The exported functions, sorted by name.
    pub fn functions(&self) -> &[(String, FunctionInfo)] {
        &self.functions.list
    }

    /// The entry of the exported function called `name` in [`Program::functions`].
    pub fn function_info(&self, name: &str) -> Option<&FunctionInfo> {
        let index = self.functions.find(name)?.index;
        Some(&self.functions.list.get(index)?.1)
    }

    /// Call a function by name, with up to 12 arguments: the first five go in r1-r5, the others where a caller that
    /// passes them on the stack leaves them, so the function takes them as clang compiles a function of more than
    /// five parameters. An argument that the call leaves out is 0. Returns r0, which holds a result of up to 8 bytes.
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

    /// Call a function looked up with [`Program::func`], with arguments as for [`Program::call`].
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
    /// [`VmConfig::instruction_limit`], 0 for none, which also reports the instructions the call ran. Without the
    /// `fuel` feature, nothing counts them: the count is 0, and a non-zero `limit` fails with
    /// [`VmError::FuelNotEnabled`].
    pub fn call_func_with_limit(&mut self, func: Func, args: &[u64], limit: u64) -> LimitedCall {
        if !self.owns(func) {
            return LimitedCall::failed(VmError::ForeignFunc);
        }
        if !rvm_core::METERED && limit != 0 {
            return LimitedCall::failed(VmError::FuelNotEnabled);
        }
        let start = fuel_for(limit);
        let mut fuel = start;
        let result = self.call_pc_fueled(func.pc, args, &mut fuel);
        LimitedCall {
            result,
            instructions: start - fuel,
        }
    }

    /// [`call_func`](Self::call_func) for a host function that runs inside another call. With `fuel`, what that call
    /// has left if it is metered, the call runs at most that and this program's limit, and takes what it ran from
    /// `fuel`; without, it runs under this program's limit alone.
    #[inline]
    pub(crate) fn call_func_charged(&mut self, func: Func, args: &[u64], fuel: Option<&mut u64>) -> Result<u64> {
        let Some(fuel) = fuel else {
            return self.call_func(func, args);
        };
        if !self.owns(func) {
            return Err(VmError::ForeignFunc);
        }
        let limit = self.executor.instruction_limit();
        let start = limit.map_or(*fuel, |limit| limit.min(*fuel));
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
    /// `call_pc` stays a call under the executor's limit that reports nothing back.
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

/// A program's guest memory from [`Program::memory_mut`]. It reads like a [`VmMemory`] and maps and writes as one, but
/// can't replace the memory, which holds the program's stack, data and maps.
pub struct ProgramMemory<'a>(&'a mut VmMemory);

impl ProgramMemory<'_> {
    /// [`VmMemory::map`].
    ///
    /// # Example
    ///
    /// ```
    /// use rvm::{Image, Perms, Vm};
    ///
    /// // r0 = *(u64 *)r1
    /// let code = [0x79, 0x10, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    /// let mut program = Vm::new().load_image(Image::from_code(code.to_vec()))?;
    /// let input = program.memory_mut().map_bytes(&42u64.to_le_bytes(), 8, Perms::R)?;
    /// assert_eq!(program.call("main", &[input.base()])?, 42);
    /// program.memory_mut().unmap(input)?;
    /// # Ok::<_, rvm::VmError>(())
    /// ```
    pub fn map(&mut self, len: usize, perms: Perms) -> Result<Region> {
        self.0.map(len, perms)
    }

    /// [`VmMemory::map_bytes`].
    pub fn map_bytes(&mut self, init: &[u8], len: usize, perms: Perms) -> Result<Region> {
        self.0.map_bytes(init, len, perms)
    }

    /// [`VmMemory::map_host`].
    ///
    /// # Safety
    ///
    /// As [`VmMemory::map_host`].
    pub unsafe fn map_host(&mut self, ptr: NonNull<u8>, len: usize, perms: Perms) -> Result<Region> {
        // SAFETY: the caller's contract.
        unsafe { self.0.map_host(ptr, len, perms) }
    }

    /// [`VmMemory::unmap`]. A handle from the program that [`Plugin::replace`](crate::Plugin::replace) swapped out
    /// fails with [`VmError::ForeignRegion`].
    pub fn unmap(&mut self, region: Region) -> Result<()> {
        self.0.unmap(region)
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
