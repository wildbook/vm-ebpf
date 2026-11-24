//! Windows structured exceptions that end a run instead of the process, with the `seh` feature on Windows x64.
//!
//! Two guards catch them. Each is a frame written in assembly whose unwind information names `__C_specific_handler`
//! and a scope table: what a C compiler emits for `__try` and `__except`. The system finds a guard through the
//! function table when an exception is raised, so a call through one that raises nothing runs nothing for it. When a
//! guard's filter accepts an exception, the system unwinds the frames below the guard as it unwinds any frames,
//! calling their own handlers, and continues in the guard, which returns to its caller as from a call.
//!
//! - [`native`] guards one call of a native function, for a [`GUARDED`](crate::native::GUARDED) native call.
//! - [`enter`] guards a chain of handlers, for a run of an interpreter with
//!   [`Interpreter::set_guard`](crate::Interpreter::set_guard). It catches an access violation of a load or store
//!   that the interpreter ran in a memory window, which every access through [`load`], [`store`] and
//!   [`compare_swap`] is.
//!
//! # Which frames an unwind crosses
//!
//! A frame that an unwind crosses is gone without its code running, so it must own nothing. Each filter accepts an
//! exception only if it finds that true of the frames between the exception and its guard, and passes every other
//! exception on to the frames above, as if the guard were not there.
//!
//! - The filter of [`native`] accepts if no frame in between lies in the image that this code is linked into
//!   (`foreign_frames`). The frames are then the native function's and those of what it called, which answer for
//!   themselves. No frame of this crate or of its user is crossed: to them, a foreign function returned. A native
//!   function linked into the same image, or one that called back into that image before the exception, is not
//!   caught.
//! - The filter of [`enter`] accepts if the instruction is listed in [`RAW_ACCESSES`] and belongs to a slot of the
//!   code that its guard runs. The frames are then those of this run: the handler of the slot, the functions of
//!   `step` it called on the way to the access, and `chain`. None owns anything; they hold what they were passed.
//!   The exception of another run that a host function started below the guard belongs to other code. A host
//!   function must not start a second run of the same [`Code`](crate::Code) on the thread during a guarded one.

use std::arch::{asm, global_asm};
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ops::Range;
use std::ptr;

use crate::code::Slots;
use crate::dispatch::{Handler, Table, SPARE};
use crate::opcode::MemSize;
use crate::slot::Slot;
use crate::transfer::Ip;
use crate::{Context, Interpreter, Memory, NativeFn};

/// An exception that left a guarded native call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caught {
    /// The exception code, an NTSTATUS such as 0xC0000005 for an access violation.
    pub code: u32,
    /// The address of the instruction that raised it.
    pub address: u64,
}

impl Caught {
    pub(crate) const NONE: Self = Self { code: 0, address: 0 };
}

/// What `native_filter` works with, in the frame that calls the guard.
#[repr(C)]
struct NativeGuard {
    caught: MaybeUninit<Caught>,
    /// Where the filter unwinds a copy of the exception's context. It is not in the filter's own frame, as the
    /// filter of a stack overflow runs on what little stack is left.
    scratch: MaybeUninit<ThreadContext>,
}

/// What `access_filter` works with, in the frame that calls the guard.
#[repr(C)]
struct EnterGuard {
    /// The addresses of the slots of the code the guard runs.
    code: Range<usize>,
    /// The address the access violation accessed, and the address of the slot of its instruction.
    target: MaybeUninit<u64>,
    slot: MaybeUninit<usize>,
}

const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
const EXCEPTION_IN_PAGE_ERROR: u32 = 0xC000_0006;
const EXCEPTION_STACK_OVERFLOW: u32 = 0xC000_00FD;

/// EXCEPTION_RECORD.
#[repr(C)]
struct ExceptionRecord {
    code: u32,
    flags: u32,
    record: *mut ExceptionRecord,
    address: *mut c_void,
    params: u32,
    info: [usize; 15],
}

/// EXCEPTION_POINTERS.
#[repr(C)]
struct ExceptionPointers {
    record: *const ExceptionRecord,
    context: *const ThreadContext,
}

/// CONTEXT, of which this module reads three registers.
#[repr(C, align(16))]
struct ThreadContext([u8; 0x4d0]);

impl ThreadContext {
    const RSP: usize = 0x98;
    const R15: usize = 0xf0;
    const RIP: usize = 0xf8;

    fn get(&self, offset: usize) -> usize {
        usize::from_ne_bytes(self.0[offset..][..8].try_into().unwrap())
    }

    fn set(&mut self, offset: usize, value: usize) {
        self.0[offset..][..8].copy_from_slice(&value.to_ne_bytes());
    }
}

unsafe extern "C" {
    // `guard` points to a `Guard`, which only the filters read
    fn rvm_seh_native(func: NativeFn, args: *const u64, r0: *mut u64, guard: *mut c_void) -> u32;

    /// The first byte of the image this code is linked into, which the linker defines.
    static __ImageBase: u8;

    /// The C runtime's: puts the guard page back below the stack after a stack overflow. Returns 0 if it can't.
    fn _resetstkoflw() -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn RtlLookupFunctionEntry(pc: usize, image_base: *mut usize, history: *mut c_void) -> *mut c_void;
    fn RtlVirtualUnwind(
        handler_type: u32,
        image_base: usize,
        pc: usize,
        function: *mut c_void,
        context: *mut ThreadContext,
        handler_data: *mut *mut c_void,
        establisher_frame: *mut usize,
        context_pointers: *mut c_void,
    ) -> *mut c_void;
}

// The two guard frames.
//
// Each allocates its frame in one instruction, which `.seh_stackalloc` describes, and has no frame register, so the
// frame address that the system gives a filter (the establisher frame) is rsp after the prologue. Each keeps its
// `guard` argument in the home slot of the register it arrived in, at the offset from that frame that `NATIVE_GUARD`
// and `ENTER_GUARD` hold, where its filter finds it.
//
// The scope table after `.seh_handlerdata` is a SCOPE_TABLE: a count of 1, then the addresses of the first and past
// the last instruction the scope covers, of the filter, and of the instruction to continue at when the filter
// returns 1. All are relative to the image. The scope is the call and the `nop` after it, which keeps the return
// address inside the scope. The frame holds nothing to restore on the way to the continuation, which runs the
// same epilogue as the return.
global_asm!(
    // rvm_seh_native(func, args, r0, guard): *r0 = func(args[0], ..., args[4]); returns 0, or 1 if `native_filter`
    // accepted an exception, with `*r0` unchanged
    ".globl rvm_seh_native",
    ".def rvm_seh_native; .scl 2; .type 32; .endef",
    ".seh_proc rvm_seh_native",
    "rvm_seh_native:",
    // the callee's shadow space, its fifth argument, and 16 bytes that align rsp
    "    sub rsp, 56",
    "    .seh_stackalloc 56",
    "    .seh_endprologue",
    "    mov [rsp + 80], r8",
    "    mov [rsp + 88], r9",
    "    mov rax, rcx",
    "    mov rcx, [rdx]",
    "    mov r8, [rdx + 16]",
    "    mov r9, [rdx + 24]",
    "    mov r10, [rdx + 32]",
    "    mov rdx, [rdx + 8]",
    "    mov [rsp + 32], r10",
    ".Lrvm_seh_native_begin:",
    "    call rax",
    "    nop",
    ".Lrvm_seh_native_end:",
    "    mov rcx, [rsp + 80]",
    "    mov [rcx], rax",
    "    xor eax, eax",
    "    add rsp, 56",
    "    ret",
    ".Lrvm_seh_native_caught:",
    "    mov eax, 1",
    "    add rsp, 56",
    "    ret",
    "    .seh_handler __C_specific_handler, @except",
    "    .seh_handlerdata",
    "    .long 1",
    "    .rva .Lrvm_seh_native_begin",
    "    .rva .Lrvm_seh_native_end",
    "    .rva {native_filter}",
    "    .rva .Lrvm_seh_native_caught",
    "    .text",
    "    .seh_endproc",
    "",
    // rvm_seh_enter(body, data, guard): body(data); returns 0, or 1 if `access_filter` accepted an exception
    ".globl rvm_seh_enter",
    ".def rvm_seh_enter; .scl 2; .type 32; .endef",
    ".seh_proc rvm_seh_enter",
    "rvm_seh_enter:",
    "    sub rsp, 40",
    "    .seh_stackalloc 40",
    "    .seh_endprologue",
    "    mov [rsp + 64], r8",
    "    mov rax, rcx",
    "    mov rcx, rdx",
    ".Lrvm_seh_enter_begin:",
    "    call rax",
    "    nop",
    ".Lrvm_seh_enter_end:",
    "    xor eax, eax",
    "    add rsp, 40",
    "    ret",
    ".Lrvm_seh_enter_caught:",
    "    mov eax, 1",
    "    add rsp, 40",
    "    ret",
    "    .seh_handler __C_specific_handler, @except",
    "    .seh_handlerdata",
    "    .long 1",
    "    .rva .Lrvm_seh_enter_begin",
    "    .rva .Lrvm_seh_enter_end",
    "    .rva {access_filter}",
    "    .rva .Lrvm_seh_enter_caught",
    "    .text",
    "    .seh_endproc",
    native_filter = sym native_filter,
    access_filter = sym access_filter,
);

/// Where the frame of `rvm_seh_native` keeps its `guard`, from its establisher frame: the home slot of r9.
const NATIVE_GUARD: usize = 56 + 8 + 24;
/// Where the frame of `rvm_seh_enter` keeps its `guard`: the home slot of r8.
const ENTER_GUARD: usize = 40 + 8 + 16;

/// What a filter returns to catch the exception (EXCEPTION_EXECUTE_HANDLER) and to pass it on to the frames above
/// (EXCEPTION_CONTINUE_SEARCH).
const CATCH: i32 = 1;
const PASS: i32 = 0;

/// Calls `func` with the five values at `args` as its arguments and puts the result in `*r0`. Returns the exception
/// if one left `func` and the filter accepted it; `*r0` is then unchanged.
///
/// The filter accepts an exception of severity error (the two top bits of its code), which hardware faults,
/// failures raised with `RaiseException` and C++ exceptions have, under the frame condition of the
/// [module](self). It passes on breakpoints, single steps, guard page hits and the informational codes that
/// debuggers and runtimes exchange, which their raiser expects to continue from.
///
/// After a stack overflow it puts the guard page back, without which the thread's next overflow ends the process
/// with no exception, and aborts if that fails.
///
/// The function may take fewer than five arguments: the Windows x64 convention lets a callee ignore the registers
/// and the stack slot of arguments it doesn't have.
///
/// # Safety
///
/// `func` must be callable in the Windows x64 convention with up to five integer arguments, `args` must be valid for
/// reads of five values and `r0` for a write.
#[inline(always)]
pub unsafe fn native(func: NativeFn, args: *const u64, r0: *mut u64) -> Option<Caught> {
    let mut guard = NativeGuard {
        caught: MaybeUninit::uninit(),
        scratch: MaybeUninit::uninit(),
    };
    // SAFETY: the caller's, and the frame as the comment at its assembly describes it
    if unsafe { rvm_seh_native(func, args, r0, (&raw mut guard).cast()) } == 0 {
        return None;
    }
    core::hint::cold_path();
    // SAFETY: the guard returns 1 only after `native_filter` wrote `caught`
    let caught = unsafe { guard.caught.assume_init() };
    // The C runtime wants this called once the stack is unwound, away from the overflow, which this frame is: the
    // native call started here.
    // SAFETY: a C runtime function without arguments
    if caught.code == EXCEPTION_STACK_OVERFLOW && unsafe { _resetstkoflw() } == 0 {
        std::process::abort();
    }
    Some(caught)
}

/// The filter of `rvm_seh_native`; [`native`] states what it accepts.
unsafe extern "C" fn native_filter(pointers: *const ExceptionPointers, frame: usize) -> i32 {
    // SAFETY: the system passes the exception's record and context, and the frame holds the `guard` of the call in
    // progress (see the assembly)
    unsafe {
        let record = &*(*pointers).record;
        if record.code >> 30 != 3 {
            return PASS;
        }
        let guard = &mut *((frame + NATIVE_GUARD) as *const *mut NativeGuard).read();
        if !foreign_frames(frame, (*pointers).context, guard.scratch.as_mut_ptr()) {
            return PASS;
        }
        guard.caught.write(Caught {
            code: record.code,
            address: record.address as u64,
        });
        CATCH
    }
}

/// The frames between the context of an exception and a guard frame, innermost first: for each, the address its code
/// was at. The walk unwinds a copy of the context in `scratch`, as the system does when it looks for a handler: by
/// the unwind information of a function that has some, and for a leaf by the return address at rsp.
///
/// `next` returns `None` at the guard frame, and `arrived` says whether the walk ended there or lost its way.
struct Frames {
    scratch: *mut ThreadContext,
    /// The establisher frame of the guard: rsp in the guard's frame, which the frame below it returns to.
    guard: usize,
    arrived: bool,
}

impl Frames {
    /// # Safety
    ///
    /// `context` must be the context of an exception raised below the guard frame `guard` on this thread, and
    /// `scratch` valid for writes.
    unsafe fn new(guard: usize, context: *const ThreadContext, scratch: *mut ThreadContext) -> Self {
        // SAFETY: the caller's
        unsafe { ptr::copy_nonoverlapping(context, scratch, 1) };
        Self {
            scratch,
            guard,
            arrived: false,
        }
    }
}

impl Iterator for Frames {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        // SAFETY: `new` initialised the scratch context, which nothing else uses
        let context = unsafe { &mut *self.scratch };
        let (pc, rsp) = (context.get(ThreadContext::RIP), context.get(ThreadContext::RSP));
        if rsp >= self.guard {
            self.arrived = rsp == self.guard;
            return None;
        }

        let mut image = 0;
        // SAFETY: the stack between the exception and the guard is live, and so are the modules its frames run in
        unsafe {
            let function = RtlLookupFunctionEntry(pc, &mut image, ptr::null_mut());
            if function.is_null() {
                context.set(ThreadContext::RIP, (rsp as *const usize).read());
                context.set(ThreadContext::RSP, rsp + 8);
            } else {
                let (mut data, mut establisher) = (ptr::null_mut(), 0);
                RtlVirtualUnwind(0, image, pc, function, context, &mut data, &mut establisher, ptr::null_mut());
            }
        }
        // an unwind that doesn't move up the stack has lost its way
        if context.get(ThreadContext::RSP) <= rsp {
            return None;
        }
        Some(pc)
    }
}

/// Whether every frame between an exception and the guard frame `guard` runs code outside this image.
///
/// # Safety
///
/// As [`Frames::new`].
unsafe fn foreign_frames(guard: usize, context: *const ThreadContext, scratch: *mut ThreadContext) -> bool {
    // SAFETY: the linker's symbol is the image's DOS header, which leads to the PE header and its SizeOfImage
    let image = unsafe {
        let base = &raw const __ImageBase;
        let pe = base.add(0x3c).cast::<u32>().read_unaligned() as usize;
        let size = base.add(pe + 0x50).cast::<u32>().read_unaligned() as usize;
        base.addr()..base.addr() + size
    };
    // SAFETY: the caller's
    let mut frames = unsafe { Frames::new(guard, context, scratch) };
    frames.all(|pc| !image.contains(&pc)) && frames.arrived
}

/// The arguments of the first handler of a run, for `chain`.
struct First<'a, 'c, M: Memory, H> {
    handler: Handler<M, H>,
    ctx: &'a mut Context<'c, M>,
    code: Slots<'a>,
    ip: Ip,
    interp: &'a mut Interpreter<M, H>,
    table: &'a Table<M, H>,
    slot: Slot,
}

/// Runs the chain of handlers from `handler`, as a call of `handler` with these arguments does. If a load or store
/// of [`RAW_ACCESSES`] in the chain raises an access violation, the chain ends there: returns the address it
/// accessed and the ip of its instruction.
#[inline(never)]
pub fn enter<M: Memory, H>(
    handler: Handler<M, H>,
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    slot: Slot,
) -> Option<(u64, Ip)> {
    let mut first = First {
        handler,
        ctx,
        code,
        ip,
        interp,
        table,
        slot,
    };
    let slots = code.all().as_ptr_range();
    let mut guard = EnterGuard {
        code: slots.start.addr()..slots.end.addr(),
        target: MaybeUninit::uninit(),
        slot: MaybeUninit::uninit(),
    };
    // SAFETY: `chain` takes the `First` it is passed, and the frame is as the comment at its assembly describes it
    if unsafe { rvm_seh_enter(chain::<M, H>, (&raw mut first).cast(), (&raw mut guard).cast()) } == 0 {
        return None;
    }
    // SAFETY: the guard returns 1 only after `access_filter` wrote both
    let (target, slot) = unsafe { (guard.target.assume_init(), guard.slot.assume_init()) };
    Some((target, Ip(slot as *const Slot)))
}

/// The guard of a run and the frame between it and the handlers, in the ABI `$abi`.
macro_rules! chain {
    ($abi:literal) => {
        unsafe extern $abi {
            fn rvm_seh_enter(body: unsafe extern $abi fn(*mut c_void), data: *mut c_void, guard: *mut c_void) -> u32;
        }

        /// The body of `rvm_seh_enter`. It holds only its argument.
        unsafe extern $abi fn chain<M: Memory, H>(first: *mut c_void) {
            // SAFETY: `enter` passes a `First` that nothing else uses during the call
            let first = unsafe { first.cast::<First<M, H>>().read() };
            (first.handler)(first.ctx, first.code, first.ip, first.interp, first.table, SPARE, first.slot)
        }
    };
}

// Where panics unwind, the panic of a host function unwinds through the frame of a guarded run as through the
// handlers. Elsewhere `C-unwind` would only add a path that ends the process.
#[cfg(panic = "unwind")]
chain!("C-unwind");
#[cfg(not(panic = "unwind"))]
chain!("C");

/// One instruction that `raw_access!` assembled: its address relative to the image, and how many slots after the
/// slot in r15 its guest instruction lies.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct RawAccess {
    rva: u32,
    delta: u32,
}

// The table of those instructions is the section `.rvmex`. The linker sorts the parts of a section by the text after
// `$` in their names, so the entries of `raw_access!`, in `.rvmex$m`, lie between these two. Padding between the
// parts reads as entries with an `rva` of 0, which no instruction has.
#[used]
#[unsafe(link_section = ".rvmex$a")]
static RAW_ACCESSES: RawAccess = RawAccess { rva: 0, delta: 0 };
#[used]
#[unsafe(link_section = ".rvmex$z")]
static RAW_ACCESSES_END: RawAccess = RawAccess { rva: 0, delta: 0 };

/// The entry of the instruction at `pc`, if `raw_access!` assembled it.
fn raw_access(pc: usize) -> Option<RawAccess> {
    let rva = pc.checked_sub((&raw const __ImageBase).addr())?;
    let rva = u32::try_from(rva).ok().filter(|&rva| rva != 0)?;
    let mut entry = &raw const RAW_ACCESSES;
    while entry < &raw const RAW_ACCESSES_END {
        // SAFETY: what lies between the two statics is entries and zeroed padding (see `RAW_ACCESSES`)
        let access = unsafe { entry.read() };
        if access.rva == rva {
            return Some(access);
        }
        // SAFETY: stays within the section or at its end
        entry = unsafe { entry.add(1) };
    }
    None
}

/// The filter of `rvm_seh_enter`. It accepts an access violation at an instruction of [`RAW_ACCESSES`] under the
/// frame condition of the [module](self), and nothing else.
///
/// At such an instruction r15 holds the ip that the access was given: `raw_access!` names r15 as an input of the
/// instruction, which obliges the compiler to have the value there, wherever it kept it before. So the context of
/// the exception has the ip, and with the entry's `delta` the slot of the guest instruction.
unsafe extern "C" fn access_filter(pointers: *const ExceptionPointers, frame: usize) -> i32 {
    // SAFETY: as in `native_filter`
    unsafe {
        let record = &*(*pointers).record;
        if !matches!(record.code, EXCEPTION_ACCESS_VIOLATION | EXCEPTION_IN_PAGE_ERROR) || record.params < 2 {
            return PASS;
        }
        let context = (*pointers).context;
        let Some(access) = raw_access((*context).get(ThreadContext::RIP)) else {
            return PASS;
        };
        let guard = &mut *((frame + ENTER_GUARD) as *const *mut EnterGuard).read();
        let slot = (*context).get(ThreadContext::R15) + access.delta as usize * size_of::<Slot>();
        if !guard.code.contains(&slot) {
            return PASS;
        }
        guard.target.write(record.info[1] as u64);
        guard.slot.write(slot);
        CATCH
    }
}

/// One load or store instruction with an entry in [`RAW_ACCESSES`], which runs with `$ip` in r15 (see
/// [`access_filter`]). `$delta` is how many slots after `$ip` the guest instruction of the access lies.
// AT&T syntax: the Intel-syntax assembler drops the `$` of the section name.
macro_rules! raw_access {
    ($insn:literal, $ip:expr, $delta:expr, $($operands:tt)*) => {
        asm!(
            concat!("2: ", $insn),
            ".pushsection .rvmex$m, \"dr\"",
            ".p2align 3",
            ".long 2b@IMGREL",
            ".long {delta}",
            ".popsection",
            in("r15") $ip.addr(),
            delta = const $delta,
            $($operands)*
        )
    };
}

/// Loads the `size` bytes at `ptr + at`, zero-extended, for the guest instruction `DELTA` slots after `ip`. In a
/// run inside [`enter`], an access violation of the load ends the run there instead of the process.
///
/// # Safety
///
/// As a read of those bytes, but that they may be unmapped during a run inside [`enter`]. `ip` must be the ip of the
/// handler that calls this.
#[inline(always)]
pub unsafe fn load<const DELTA: usize>(size: MemSize, ptr: *mut u8, at: u64, ip: Ip) -> u64 {
    let v: u64;
    // SAFETY: the caller's
    unsafe {
        match size {
            MemSize::Byte => raw_access!("movzbl ({p}, {i}), {v:e}", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = lateout(reg) v, options(readonly, nostack, preserves_flags, att_syntax)),
            MemSize::Half => raw_access!("movzwl ({p}, {i}), {v:e}", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = lateout(reg) v, options(readonly, nostack, preserves_flags, att_syntax)),
            MemSize::Word => raw_access!("movl ({p}, {i}), {v:e}", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = lateout(reg) v, options(readonly, nostack, preserves_flags, att_syntax)),
            MemSize::DWord => raw_access!("movq ({p}, {i}), {v}", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = lateout(reg) v, options(readonly, nostack, preserves_flags, att_syntax)),
        }
    }
    v
}

/// Stores the low `size` bytes of `value` at `ptr + at`, as [`load`] loads.
///
/// # Safety
///
/// As a write of those bytes, with the exception and the `ip` of [`load`].
#[inline(always)]
pub unsafe fn store<const DELTA: usize>(size: MemSize, ptr: *mut u8, at: u64, value: u64, ip: Ip) {
    // SAFETY: the caller's
    unsafe {
        match size {
            MemSize::Byte => raw_access!("movb {v:l}, ({p}, {i})", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = in(reg) value, options(nostack, preserves_flags, att_syntax)),
            MemSize::Half => raw_access!("movw {v:x}, ({p}, {i})", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = in(reg) value, options(nostack, preserves_flags, att_syntax)),
            MemSize::Word => raw_access!("movl {v:e}, ({p}, {i})", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = in(reg) value, options(nostack, preserves_flags, att_syntax)),
            MemSize::DWord => raw_access!("movq {v}, ({p}, {i})", ip, DELTA, p = in(reg) ptr, i = in(reg) at,
                v = in(reg) value, options(nostack, preserves_flags, att_syntax)),
        }
    }
}

/// Atomically stores `new` in the 4 bytes at `ptr + at`, or with `wide` the 8 bytes, if they hold `expected`, for the
/// guest instruction at `ip`. Returns what they held, zero-extended. It writes the bytes either way, as
/// `lock cmpxchg` does.
///
/// # Safety
///
/// As an atomic read and write of those bytes, with the exception and the `ip` of [`load`].
#[inline(always)]
pub unsafe fn compare_swap(wide: bool, ptr: *mut u8, at: u64, expected: u64, new: u64, ip: Ip) -> u64 {
    let old: u64;
    // SAFETY: the caller's
    unsafe {
        match wide {
            false => raw_access!("lock cmpxchgl {n:e}, ({p}, {i})", ip, 0, p = in(reg) ptr, i = in(reg) at,
                n = in(reg) new, inout("rax") expected => old, options(nostack, att_syntax)),
            true => raw_access!("lock cmpxchgq {n}, ({p}, {i})", ip, 0, p = in(reg) ptr, i = in(reg) at,
                n = in(reg) new, inout("rax") expected => old, options(nostack, att_syntax)),
        }
    }
    old
}
