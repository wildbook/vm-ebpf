//! Linked eBPF program ready for execution.
//!
//! A `Program` is a loaded [`crate::Image`]: the executable code, data, maps and function table.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hashbrown::HashMap;
use rvm_core::Code;

use crate::error::{Result, VmError};
use crate::executor::Executor;
use crate::helper::{HelperRegistry, SharedHelpers};
#[cfg(feature = "maps")]
use crate::maps::{MapRef, Maps};
use crate::memory::VmMemory;
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
/// length in bytes.
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
        self.arg < 5 && self.len_arg < 5 && self.arg != self.len_arg
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
/// let program = vm.load_elf(&elf_bytes)?;
///
/// // Call with no arguments
/// let result = program.call("main", &[])?;
///
/// // Call with arguments (passed in r1-r5)
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
    #[cfg(feature = "maps")]
    maps: Maps,
    functions: Functions,
    /// Stack top address (r10 initial value).
    stack_top: u64,
    /// The VM's extern table, and this program's copy of it at `helpers_version`.
    shared_helpers: Arc<SharedHelpers>,
    helpers: HelperRegistry,
    helpers_version: u64,
    /// Maximum instructions per call; `u64::MAX` for no limit.
    #[cfg(feature = "fuel")]
    instruction_limit: u64,
    /// Stack bytes per call frame.
    frame_size: u64,
}

impl Program {
    /// `helpers` is the VM's extern table, the copy of it the image was bound against, and that copy's version.
    pub(crate) fn new(
        code: Code,
        memory: VmMemory,
        stack_top: u64,
        functions: Functions,
        helpers: (Arc<SharedHelpers>, HelperRegistry, u64),
        config: &VmConfig,
    ) -> Self {
        let (shared_helpers, helpers, helpers_version) = helpers;
        Self {
            id: NEXT_PROGRAM_ID.fetch_add(1, Ordering::Relaxed),
            code,
            memory,
            #[cfg(feature = "maps")]
            maps: Maps::default(),
            functions,
            stack_top,
            shared_helpers,
            helpers,
            helpers_version,
            // `VmConfig` says 0 for no limit
            #[cfg(feature = "fuel")]
            instruction_limit: match config.instruction_limit {
                0 => u64::MAX,
                limit => limit,
            },
            frame_size: config.frame_size,
        }
    }

    /// Get guest memory.
    pub fn memory(&self) -> &VmMemory {
        &self.memory
    }

    /// Get mutable access to memory.
    pub fn memory_mut(&mut self) -> &mut VmMemory {
        &mut self.memory
    }

    /// The program with `maps`, whose values `memory` holds.
    #[cfg(feature = "maps")]
    pub(crate) fn with_maps(self, maps: Maps) -> Self {
        Self { maps, ..self }
    }

    /// Host access to the map called `name`. Fails with [`VmError::MapNotFound`] if the program has none.
    #[cfg(feature = "maps")]
    pub fn map(&mut self, name: &str) -> Result<MapRef<'_>> {
        let handle = self
            .maps
            .handle(name)
            .ok_or_else(|| VmError::MapNotFound(name.to_string()))?;
        Ok(MapRef::new(&mut self.maps, &mut self.memory, handle))
    }

    /// The exported functions, sorted by name. A function's position here is its index for [`Program::func_at`].
    pub fn functions(&self) -> impl ExactSizeIterator<Item = (&str, &FunctionInfo)> {
        self.functions.list.iter().map(|(name, info)| (name.as_str(), info))
    }

    /// Get information about a function by name.
    pub fn function(&self, name: &str) -> Option<&FunctionInfo> {
        let (index, _) = self.functions.find(name)?;
        Some(&self.functions.list.get(index)?.1)
    }

    /// The index of the function called `name` in [`Program::functions`].
    #[inline]
    pub fn function_index(&self, name: &str) -> Option<usize> {
        Some(self.functions.find(name)?.0)
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
        let Some((_, pc)) = self.functions.find(name) else {
            return Err(VmError::FunctionNotFound {
                plugin: None,
                func: name.to_string(),
            });
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
        let (index, pc) = self.functions.find(name)?;
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

        let mut executor = Executor::new(&self.code, &mut self.memory, &self.helpers, self.stack_top);
        #[cfg(feature = "fuel")]
        executor.set_instruction_limit(self.instruction_limit);
        executor.set_frame_size(self.frame_size);
        #[cfg(feature = "maps")]
        executor.set_maps(&mut self.maps);
        executor.call(pc, args)
    }

    #[cold]
    #[inline(never)]
    fn refresh_helpers(&mut self) {
        (self.helpers, self.helpers_version) = self.shared_helpers.snapshot();
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

    /// Call the function in `program`, looking it up again if the slot holds a function of another program. Fails
    /// with [`VmError::FunctionNotFound`] naming `plugin` if `program` lacks it.
    #[inline]
    pub fn call(&self, program: &mut Program, plugin: &Arc<str>, args: &[u64]) -> Result<u64> {
        let func = self.func.load();
        let pc = if program.owns(func) {
            func.pc
        } else {
            self.follow(program, plugin)?
        };
        program.call_pc(pc, args)
    }

    /// Look the function up in `program`, which replaced the slot's program, and keep its pc.
    #[cold]
    #[inline(never)]
    fn follow(&self, program: &Program, plugin: &Arc<str>) -> Result<u64> {
        let Some((func, _)) = program.func_with_info(&self.name) else {
            return Err(not_found(plugin, &self.name));
        };
        self.func.store(func);
        Ok(func.pc)
    }
}

/// A program's exported functions: sorted by name, which gives each its index, and hashed for calls by name.
#[derive(Debug)]
pub(crate) struct Functions {
    list: Vec<(String, FunctionInfo)>,
    // name -> (index, pc); the pc sits in the map, which measured faster for calls by name than reading it from `list`
    by_name: HashMap<String, (usize, u64)>,
}

impl Functions {
    /// The table of `list`; `None` unless `list` is sorted by name with every name once.
    pub(crate) fn new(list: Vec<(String, FunctionInfo)>) -> Option<Self> {
        if !list.is_sorted_by(|(a, _), (b, _)| a < b) {
            return None;
        }
        let by_name = list
            .iter()
            .enumerate()
            .map(|(index, (name, info))| (name.clone(), (index, info.pc)))
            .collect();
        Some(Self { list, by_name })
    }

    /// The index and pc of the function called `name`.
    #[inline(always)]
    fn find(&self, name: &str) -> Option<(usize, u64)> {
        self.by_name.get(name).copied()
    }
}

static NEXT_PROGRAM_ID: AtomicU64 = AtomicU64::new(0);
