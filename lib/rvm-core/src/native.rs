//! Calls of native functions: a `call` that [`Code::bind_native`](crate::Code::bind_native) gave the byte of its
//! argument count ([`PLAIN`], or [`CHECKED`] where pointer arguments go through
//! [`Memory::native_ptr`](crate::Memory::native_ptr)), with the index of the function in
//! [`Host::natives`](crate::Host::natives) in `imm`. Its handler passes r1 to rN in the host C ABI (Windows x64 on
//! Windows, System V AMD64 on Unix) and puts the result in r0.
//!
//! On Windows x64, the handler saves nothing around the call: the guest registers live in memory, and the handler
//! arguments the dispatch needs afterwards are in registers the Windows x64 convention preserves (see
//! [`Handler`](crate::dispatch::Handler)). On SysV x64, LLVM spills and reloads `RDI` and `RSI` around the call.
//! Either way, it skips the windows check of other host calls, as a native function has no way to reach the memory of
//! the run.
//!
//! A function with more than five arguments takes the rest from the stack arguments of the frame
//! ([`args`](crate::args)). One handler runs every such call ([`STACK`]): it passes all twelve arguments through
//! `rvm_call_args`, in assembly, and the function ignores those it doesn't take.
//!
//! A `callx` has no signature. Where its target is the address of a native function,
//! [`Host::call_indirect`](crate::Host::call_indirect) calls it through a [`NativeCall`], which passes r1 to r5 in
//! assembly: no Rust function pointer type fits a function whose argument count the caller doesn't know. In a
//! program that stores stack arguments, it passes those too.

use std::arch::global_asm;
use std::mem::transmute;

use crate::args::{StackArgs, MAX_STACK_ARGS};
use crate::code::Slots;
use crate::dispatch::{Handler, Spare, Table};
use crate::fuel::Fuel;
use crate::interp::StopRecord;
use crate::slot::{Fields, Shape, Slot};
use crate::transfer::Ip;
use crate::{Context, Host, Interpreter, Memory, Reason};

/// The arguments a call passes in registers, r1 to r5.
const REG_ARGS: usize = 5;

/// Most arguments a native function takes: the argument registers r1 to r5 and the stack arguments.
pub const MAX_ARGS: usize = REG_ARGS + MAX_STACK_ARGS;

/// A native function as [`Native`] keeps it. A call casts it to `unsafe extern "C" fn(u64, ...) -> u64` with the
/// argument count of its [`NativeSig`].
pub type NativeFn = unsafe extern "C" fn() -> u64;

/// A native function and what it takes, an entry of [`Host::natives`](crate::Host::natives).
#[derive(Clone, Copy, Debug)]
pub struct Native {
    pub func: NativeFn,
    pub sig: NativeSig,
}

/// What a native function takes: up to [`MAX_ARGS`] arguments, each an integer or a pointer to guest bytes.
///
/// A checked call resolves each pointer to the host address of its bytes, or faults, before the function runs. It
/// checks one byte at the pointer, or with a length argument as many bytes as that argument holds.
///
/// ```
/// use rvm_core::{NativeArg, NativeSig};
///
/// // u64 add(u64 a, u64 b);
/// const ADD: NativeSig = NativeSig::ints(2);
/// // u64 fill(u8 *buf, u64 len, u64 byte);
/// const FILL: NativeSig = NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int, NativeArg::Int]);
/// assert_eq!((ADD.args(), FILL.args()), (2, 3));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NativeSig(u128);

// The bits of a `NativeSig`: the argument count, then for each argument `i + 1` a bit in `POINTERS` and `WRITES`, and
// 4 bits at `LENS + 4 * i` with 0 for one byte or the number of the integer argument that holds the length, 1 to 12.
// The fields of arguments 1 to 5 lie in the low 64 bits, which a checked call of up to five arguments reads with
// constant shifts.
const POINTERS: u32 = 8;
const WRITES: u32 = 24;
const LENS: u32 = 40;

const _: () = assert!(LENS + 4 * REG_ARGS as u32 <= u64::BITS && LENS + 4 * MAX_ARGS as u32 <= u128::BITS);

/// One argument of a [`NativeSig`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NativeArg {
    /// An integer, passed as the guest's register or stack slot holds it.
    Int,
    /// A pointer to bytes the function reads: one, or as many as the integer argument with this number (1 to 12)
    /// holds.
    Read(Option<u8>),
    /// A pointer to bytes the function reads and writes, as for [`Read`](Self::Read).
    Write(Option<u8>),
}

impl NativeSig {
    /// `args` integer arguments.
    ///
    /// # Panics
    ///
    /// Panics if `args` exceeds [`MAX_ARGS`].
    pub const fn ints(args: u8) -> Self {
        assert!(args as usize <= MAX_ARGS, "a native function takes at most 12 arguments");
        Self(args as u128)
    }

    /// The signature of `args`, or `None` for more than [`MAX_ARGS`] arguments or a length argument that isn't an
    /// integer argument of the signature.
    pub const fn try_new(args: &[NativeArg]) -> Option<Self> {
        if args.len() > MAX_ARGS {
            return None;
        }
        let mut bits = args.len() as u128;
        let mut i = 0;
        while i < args.len() {
            let (write, len) = match args[i] {
                NativeArg::Int => {
                    i += 1;
                    continue;
                }
                NativeArg::Read(len) => (false, len),
                NativeArg::Write(len) => (true, len),
            };
            let len = match len {
                None => 0,
                Some(n) if n >= 1 && (n as usize) <= args.len() && matches!(args[n as usize - 1], NativeArg::Int) => n,
                Some(_) => return None,
            };
            bits |= 1 << (POINTERS + i as u32) | (write as u128) << (WRITES + i as u32);
            bits |= (len as u128) << (LENS + 4 * i as u32);
            i += 1;
        }
        Some(Self(bits))
    }

    /// [`try_new`](Self::try_new) for a signature known to be valid, such as a constant.
    ///
    /// # Panics
    ///
    /// Panics where `try_new` returns `None`.
    pub const fn new(args: &[NativeArg]) -> Self {
        match Self::try_new(args) {
            Some(sig) => sig,
            None => panic!("more than 12 arguments, or a length argument that isn't an integer argument"),
        }
    }

    /// The number of arguments.
    pub const fn args(self) -> u8 {
        self.0 as u8
    }

    /// Argument `n`, numbered from 1, or `None` past the last.
    pub const fn arg(self, n: u8) -> Option<NativeArg> {
        if n == 0 || n > self.args() {
            return None;
        }
        let i = n as u32 - 1;
        let len = match self.0 >> (LENS + 4 * i) & 15 {
            0 => None,
            len => Some(len as u8),
        };
        Some(match (self.0 >> (POINTERS + i) & 1 != 0, self.0 >> (WRITES + i) & 1 != 0) {
            (false, _) => NativeArg::Int,
            (true, false) => NativeArg::Read(len),
            (true, true) => NativeArg::Write(len),
        })
    }

    /// Whether any argument is a pointer.
    pub const fn has_pointers(self) -> bool {
        self.0 >> POINTERS & ((1 << MAX_ARGS) - 1) != 0
    }
}

/// How a bound native call handles pointer arguments.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NativeMode {
    /// Pass every argument as the guest's registers and stack slots hold it.
    Plain,
    /// Resolve each pointer argument of [`NativeSig`] through [`Memory::native_ptr`] before the call.
    Checked,
    /// Strip each pointer argument's region tag through [`Memory::host_address`] before the call, unchecked.
    Strip,
    /// No prototype: pass r1 to r5 unchanged through `rvm_call_regs`.
    Raw,
}

/// One native call binding for [`Code::with_natives`](crate::Code::with_natives).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NativeBind {
    /// Instruction index of the `call` to bind.
    pub pc: usize,
    /// Index of the native function in [`Host::natives`](crate::Host::natives).
    pub index: u32,
    /// Argument count of the native function (0 to [`MAX_ARGS`]; ignored for [`NativeMode::Raw`]).
    pub args: u8,
    /// How pointer arguments are handled.
    pub mode: NativeMode,
}

const MODE_PLAIN: u8 = 0;
const MODE_CHECKED: u8 = 1;
const MODE_STRIP: u8 = 2;

/// The byte of a native call with 0 to 5 arguments that passes them as the registers hold them: bytes of JMP32
/// instructions that always fail, which [`Code::new`](crate::Code::new) frees.
pub const PLAIN: [u8; REG_ARGS + 1] = [0x8e, 0x96, 0xe6, 0xee, 0xf6, 0xfe];

/// The byte of a native call with 1 to 5 arguments that resolves its pointer arguments first: more bytes of
/// instructions that always fail.
pub const CHECKED: [u8; REG_ARGS] = [0x8c, 0x9d, 0x8f, 0x9b, 0xef];

/// The byte of a native call with 1 to 5 arguments that strips region tags from its pointer arguments unchecked.
pub const STRIP: [u8; REG_ARGS] = [0x33, 0x3a, 0x3b, 0x42, 0x43];

/// The bytes of a native call with 6 to 12 arguments: plain, checked, and stripped.
pub const STACK: [u8; 3] = [0x0e, 0xdf, 0x32];

/// The byte of a native call without a prototype: passes r1 to r5 through `rvm_call_regs`.
pub const RAW: u8 = 0x4a;

pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
    table[PLAIN[0] as usize] = native_call::<M, H, F, 0, MODE_PLAIN>;
    table[PLAIN[1] as usize] = native_call::<M, H, F, 1, MODE_PLAIN>;
    table[PLAIN[2] as usize] = native_call::<M, H, F, 2, MODE_PLAIN>;
    table[PLAIN[3] as usize] = native_call::<M, H, F, 3, MODE_PLAIN>;
    table[PLAIN[4] as usize] = native_call::<M, H, F, 4, MODE_PLAIN>;
    table[PLAIN[5] as usize] = native_call::<M, H, F, 5, MODE_PLAIN>;
    table[CHECKED[0] as usize] = native_call::<M, H, F, 1, MODE_CHECKED>;
    table[CHECKED[1] as usize] = native_call::<M, H, F, 2, MODE_CHECKED>;
    table[CHECKED[2] as usize] = native_call::<M, H, F, 3, MODE_CHECKED>;
    table[CHECKED[3] as usize] = native_call::<M, H, F, 4, MODE_CHECKED>;
    table[CHECKED[4] as usize] = native_call::<M, H, F, 5, MODE_CHECKED>;
    table[STRIP[0] as usize] = native_call::<M, H, F, 1, MODE_STRIP>;
    table[STRIP[1] as usize] = native_call::<M, H, F, 2, MODE_STRIP>;
    table[STRIP[2] as usize] = native_call::<M, H, F, 3, MODE_STRIP>;
    table[STRIP[3] as usize] = native_call::<M, H, F, 4, MODE_STRIP>;
    table[STRIP[4] as usize] = native_call::<M, H, F, 5, MODE_STRIP>;
    table[STACK[0] as usize] = stack_call::<M, H, F, MODE_PLAIN>;
    table[STACK[1] as usize] = stack_call::<M, H, F, MODE_CHECKED>;
    table[STACK[2] as usize] = stack_call::<M, H, F, MODE_STRIP>;
    table[RAW as usize] = raw_call::<M, H, F>;
}

/// The byte of a native call with `args` arguments and `mode`.
pub const fn byte(args: usize, mode: NativeMode) -> u8 {
    match mode {
        NativeMode::Raw => RAW,
        NativeMode::Plain if args > REG_ARGS => STACK[MODE_PLAIN as usize],
        NativeMode::Checked if args > REG_ARGS => STACK[MODE_CHECKED as usize],
        NativeMode::Strip if args > REG_ARGS => STACK[MODE_STRIP as usize],
        NativeMode::Plain => PLAIN[args],
        NativeMode::Checked if args == 0 => PLAIN[0],
        NativeMode::Checked => CHECKED[args - 1],
        NativeMode::Strip if args == 0 => PLAIN[0],
        NativeMode::Strip => STRIP[args - 1],
    }
}

const fn byte_for_mode(args: usize, mode: u8) -> u8 {
    match mode {
        MODE_CHECKED => byte(args, NativeMode::Checked),
        MODE_STRIP => byte(args, NativeMode::Strip),
        _ => byte(args, NativeMode::Plain),
    }
}

/// The handler of a native call with `N` arguments, up to five, in `MODE` (plain, checked, or stripped).
#[inline(never)]
extern "rust-preserve-none" fn native_call<M: Memory, H: Host<M>, F: Fuel, const N: usize, const MODE: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its byte
    let index = unsafe { ip.view(slot, const { Shape::of(byte_for_mode(N, MODE)) }) }.imm() as u32;
    let Some(&Native { func, sig }) = interp.host.natives().get(index as usize) else {
        core::hint::cold_path();
        return interp.stop.at(ip, Reason::CallKfunc(index));
    };

    // the arguments past `N` stay 0, which no call passes
    let mut a = [0; REG_ARGS];
    a[..N].copy_from_slice(&ctx.regs[1..=N]);
    if MODE == MODE_CHECKED {
        // `N` is a constant, so the loop unrolls and each shift of the signature is one too
        let bits = sig.0 as u64;
        for (i, arg) in a.iter_mut().enumerate().take(N) {
            if bits >> (POINTERS as usize + i) & 1 == 0 {
                continue;
            }
            let len = match bits >> (LENS as usize + 4 * i) & 15 {
                0 => 1,
                n => ctx.regs[n as usize],
            };
            let write = bits >> (WRITES as usize + i) & 1 != 0;
            match resolve(&*ctx.memory, *arg, len, write) {
                Ok(host) => *arg = host,
                Err(error) => return interp.stop.at(ip, Reason::MemoryFault(error)),
            }
        }
    } else if MODE == MODE_STRIP {
        let bits = sig.0 as u64;
        for (i, arg) in a.iter_mut().enumerate().take(N) {
            if bits >> (POINTERS as usize + i) & 1 != 0 {
                *arg = ctx.memory.host_address(*arg);
            }
        }
    }

    // SAFETY: `Code::with_natives` requires each native function a call names to take `N` arguments
    ctx.regs[0] = unsafe { call(func, N, a) };

    become_enter!(ctx, code, ip.offset(1), interp, table)
}

/// The handler of a native call with 6 to 12 arguments: r1 to r5 and the stack arguments of the frame.
#[inline(never)]
extern "rust-preserve-none" fn stack_call<M: Memory, H: Host<M>, F: Fuel, const MODE: u8>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its byte
    let index = unsafe { ip.view(slot, const { Shape::of(STACK[MODE as usize]) }) }.imm() as u32;
    let (stack, host) = interp.stack_args_and_host();
    let Some(&Native { func, sig }) = host.natives().get(index as usize) else {
        core::hint::cold_path();
        return interp.stop.at(ip, Reason::CallKfunc(index));
    };
    let func = func as usize as u64;

    // SAFETY, for all calls: `Code::with_natives` requires each native function a call names to take the arguments of
    // its signature, and a function leaves alone the arguments past its own
    ctx.regs[0] = match MODE {
        MODE_CHECKED | MODE_STRIP => {
            let mut a = [0; MAX_ARGS];
            a[..REG_ARGS].copy_from_slice(reg_args(&ctx.regs));
            a[REG_ARGS..].copy_from_slice(stack);
            if MODE == MODE_CHECKED {
                if let Err(error) = resolve_all(&*ctx.memory, sig, &mut a) {
                    return interp.stop.at(ip, Reason::MemoryFault(error));
                }
            } else {
                strip_all(&*ctx.memory, sig, &mut a);
            }
            let (regs, stack) = a.split_at(REG_ARGS);
            let regs = regs.first_chunk().expect("the first five arguments");
            let stack = stack.first_chunk().expect("the other seven");
            unsafe { rvm_call_args(func, regs, stack) }
        }
        _ => unsafe { rvm_call_args(func, reg_args(&ctx.regs), stack) },
    };

    become_enter!(ctx, code, ip.offset(1), interp, table)
}

/// The handler of [`RAW`]: calls a native function without a prototype, passing r1 to r5 through `rvm_call_regs`.
#[inline(never)]
extern "rust-preserve-none" fn raw_call<M: Memory, H: Host<M>, F: Fuel>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its byte
    let index = unsafe { ip.view(slot, const { Shape::of(RAW) }) }.imm() as u32;
    let Some(&Native { func, .. }) = interp.host.natives().get(index as usize) else {
        core::hint::cold_path();
        return interp.stop.at(ip, Reason::CallKfunc(index));
    };
    let func = func as usize as u64;
    // SAFETY: `Code::with_natives` requires the function to be sound to call through `rvm_call_regs`
    ctx.regs[0] = unsafe { rvm_call_regs(func, &ctx.regs) };

    become_enter!(ctx, code, ip.offset(1), interp, table)
}

/// Replaces each pointer argument of `sig` among `a` with its host address via [`Memory::host_address`].
fn strip_all<M: Memory>(memory: &M, sig: NativeSig, a: &mut [u64; MAX_ARGS]) {
    for n in 1..=sig.args() {
        if !matches!(sig.arg(n), Some(NativeArg::Read(_) | NativeArg::Write(_))) {
            continue;
        }
        let arg = &mut a[usize::from(n) - 1];
        *arg = memory.host_address(*arg);
    }
}

/// r1 to r5 of `regs`.
#[inline(always)]
fn reg_args(regs: &[u64; 16]) -> &[u64; REG_ARGS] {
    regs[1..].first_chunk().expect("16 registers")
}

/// Replaces each pointer argument of `sig` among the arguments `a` with the host address of its bytes, as
/// [`Memory::native_ptr`] resolves it.
fn resolve_all<M: Memory>(memory: &M, sig: NativeSig, a: &mut [u64; MAX_ARGS]) -> Result<(), M::Error> {
    for n in 1..=sig.args() {
        let (len, write) = match sig.arg(n) {
            Some(NativeArg::Read(len)) => (len, false),
            Some(NativeArg::Write(len)) => (len, true),
            Some(NativeArg::Int) | None => continue,
        };
        // a length is an integer argument, which this loop leaves as the guest passed it
        let len = len.map_or(1, |len| a[usize::from(len) - 1]);
        let arg = &mut a[usize::from(n) - 1];
        *arg = resolve(memory, *arg, len, write)?;
    }
    Ok(())
}

/// [`Memory::native_ptr`], out of line, so that each pointer argument of a checked handler costs a call rather than
/// a copy of the check.
#[inline(never)]
fn resolve<M: Memory>(memory: &M, addr: u64, len: u64, write: bool) -> Result<u64, M::Error> {
    memory.native_ptr(addr, len, write)
}

/// Call `func` with the first `n` of `a` through the function pointer type of that many arguments.
///
/// # Safety
///
/// `func` must take `n` integer or pointer arguments in the host C convention, and never unwind.
#[inline(always)]
unsafe fn call(func: NativeFn, n: usize, a: [u64; REG_ARGS]) -> u64 {
    type F1 = unsafe extern "C" fn(u64) -> u64;
    type F2 = unsafe extern "C" fn(u64, u64) -> u64;
    type F3 = unsafe extern "C" fn(u64, u64, u64) -> u64;
    type F4 = unsafe extern "C" fn(u64, u64, u64, u64) -> u64;
    type F5 = unsafe extern "C" fn(u64, u64, u64, u64, u64) -> u64;
    // SAFETY: the caller's
    unsafe {
        match n {
            0 => func(),
            1 => transmute::<NativeFn, F1>(func)(a[0]),
            2 => transmute::<NativeFn, F2>(func)(a[0], a[1]),
            3 => transmute::<NativeFn, F3>(func)(a[0], a[1], a[2]),
            4 => transmute::<NativeFn, F4>(func)(a[0], a[1], a[2], a[3]),
            _ => transmute::<NativeFn, F5>(func)(a[0], a[1], a[2], a[3], a[4]),
        }
    }
}

/// What [`Host::call_indirect`](crate::Host::call_indirect) calls a native function with, where the target of a
/// `callx` is the address of one.
pub struct NativeCall<'a, E> {
    stop: &'a mut StopRecord<E>,
    /// The `callx`.
    ip: Ip,
    /// The stack arguments of the frame, in a program that stores any.
    stack: Option<&'a StackArgs>,
}

impl<'a, E> NativeCall<'a, E> {
    pub(crate) fn new(stop: &'a mut StopRecord<E>, ip: Ip, stack: Option<&'a StackArgs>) -> Self {
        Self { stop, ip, stack }
    }

    /// Call the function at `func` with r1 to r5 of `regs` in the host C convention, the first register arguments also
    /// in xmm registers, and return its rax. No signature says what the function takes, so nothing is checked or
    /// converted.
    ///
    /// In a program that stores a stack argument anywhere, the call also passes the seven stack arguments of the
    /// frame as arguments 6 to 12, as the frame stored them last: nothing says how many this `callx` passes, and
    /// the function ignores the rest. In every other program the function gets five arguments.
    ///
    /// It first records the `callx` and `func` as the stop of the run. Nothing reads that record but a debugger,
    /// which finds the guest instruction behind a call that crashed there: the stop that ends the run replaces it.
    ///
    /// # Safety
    ///
    /// `func` must be the address of a function of the host C convention that is sound to call with whatever `regs`
    /// and the stack arguments hold, and that never unwinds.
    #[inline(always)]
    pub unsafe fn call(self, func: u64, regs: &[u64; 16]) -> u64 {
        self.stop.calling(self.ip, func);
        // SAFETY: the caller's
        match self.stack {
            None => unsafe { rvm_call_regs(func, regs) },
            Some(stack) => unsafe { rvm_call_args(func, reg_args(regs), stack) },
        }
    }
}

unsafe extern "C" {
    fn rvm_call_regs(func: u64, regs: &[u64; 16]) -> u64;
    fn rvm_call_args(func: u64, regs: &[u64; REG_ARGS], stack: &StackArgs) -> u64;
}

// rvm_call_regs(func, regs): func(regs[1], ..., regs[5]). The register arguments go to xmm registers as well, where a
// callee reads its float and double parameters, and where a variadic callee expects a copy of each register argument.
// A callee ignores the arguments it doesn't take. The unwind directives let a debugger, a profiler and exception
// dispatch walk from the callee through this frame.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
global_asm!(
    ".globl rvm_call_regs",
    ".def rvm_call_regs; .scl 2; .type 32; .endef",
    ".seh_proc rvm_call_regs",
    "rvm_call_regs:",
    // the callee's home area and its fifth argument, on an aligned stack
    "    sub rsp, 40",
    "    .seh_stackalloc 40",
    "    .seh_endprologue",
    "    mov rax, rcx",
    "    mov r10, [rdx + 40]",
    "    mov rcx, [rdx + 8]",
    "    mov r8, [rdx + 24]",
    "    mov r9, [rdx + 32]",
    "    mov rdx, [rdx + 16]",
    "    mov [rsp + 32], r10",
    "    movq xmm0, rcx",
    "    movq xmm1, rdx",
    "    movq xmm2, r8",
    "    movq xmm3, r9",
    "    call rax",
    "    add rsp, 40",
    "    ret",
    "    .seh_endproc",
);

// rvm_call_args(func, regs, stack): func(regs[0], ..., regs[4], stack[0], ..., stack[6]), as rvm_call_regs passes
// its five. It always copies all seven stack arguments, which costs less than a loop over a count and leaves the
// frame one size for the unwind directives.
#[cfg(all(target_arch = "x86_64", target_os = "windows"))]
global_asm!(
    ".globl rvm_call_args",
    ".def rvm_call_args; .scl 2; .type 32; .endef",
    ".seh_proc rvm_call_args",
    "rvm_call_args:",
    // the callee's home area and its arguments 5 to 12, on an aligned stack
    "    sub rsp, 104",
    "    .seh_stackalloc 104",
    "    .seh_endprologue",
    "    mov rax, rcx",
    "    movups xmm0, [r8]",
    "    movups xmm1, [r8 + 16]",
    "    movups xmm2, [r8 + 32]",
    "    mov r10, [r8 + 48]",
    "    mov r11, [rdx + 32]",
    "    movups [rsp + 40], xmm0",
    "    movups [rsp + 56], xmm1",
    "    movups [rsp + 72], xmm2",
    "    mov [rsp + 88], r10",
    "    mov [rsp + 32], r11",
    "    mov rcx, [rdx]",
    "    mov r8, [rdx + 16]",
    "    mov r9, [rdx + 24]",
    "    mov rdx, [rdx + 8]",
    "    movq xmm0, rcx",
    "    movq xmm1, rdx",
    "    movq xmm2, r8",
    "    movq xmm3, r9",
    "    call rax",
    "    add rsp, 104",
    "    ret",
    "    .seh_endproc",
);

#[cfg(all(target_arch = "x86_64", unix))]
macro_rules! sysv_call_asm {
    ($prefix:literal, $elf_type_regs:literal, $elf_size_regs:literal, $elf_type_args:literal, $elf_size_args:literal) => {
        global_asm!(
            concat!(".globl ", $prefix, "rvm_call_regs"),
            $elf_type_regs,
            concat!($prefix, "rvm_call_regs:"),
            "    .cfi_startproc",
            // align rsp to 16 bytes before call
            "    sub rsp, 8",
            "    .cfi_def_cfa_offset 16",
            "    mov r11, rdi",
            "    mov r10, rsi",
            "    mov rdi, [r10 + 8]",
            "    mov rsi, [r10 + 16]",
            "    mov rdx, [r10 + 24]",
            "    mov rcx, [r10 + 32]",
            "    mov r8, [r10 + 40]",
            "    movq xmm0, rdi",
            "    movq xmm1, rsi",
            "    movq xmm2, rdx",
            "    movq xmm3, rcx",
            "    movq xmm4, r8",
            "    mov eax, 5",
            "    call r11",
            "    add rsp, 8",
            "    .cfi_def_cfa_offset 8",
            "    ret",
            "    .cfi_endproc",
            $elf_size_regs,
        );

        global_asm!(
            concat!(".globl ", $prefix, "rvm_call_args"),
            $elf_type_args,
            concat!($prefix, "rvm_call_args:"),
            "    .cfi_startproc",
            // 48 bytes for stack args 7..12 plus 8 bytes for 16-byte alignment before call
            "    sub rsp, 56",
            "    .cfi_def_cfa_offset 64",
            "    mov r11, rdi",
            "    mov r10, rsi",
            "    mov r9, [rdx]",
            "    movups xmm0, [rdx + 8]",
            "    movups xmm1, [rdx + 24]",
            "    movups xmm2, [rdx + 40]",
            "    movups [rsp], xmm0",
            "    movups [rsp + 16], xmm1",
            "    movups [rsp + 32], xmm2",
            "    mov rdi, [r10]",
            "    mov rsi, [r10 + 8]",
            "    mov rdx, [r10 + 16]",
            "    mov rcx, [r10 + 24]",
            "    mov r8, [r10 + 32]",
            "    movq xmm0, rdi",
            "    movq xmm1, rsi",
            "    movq xmm2, rdx",
            "    movq xmm3, rcx",
            "    movq xmm4, r8",
            "    movq xmm5, r9",
            "    mov eax, 6",
            "    call r11",
            "    add rsp, 56",
            "    .cfi_def_cfa_offset 8",
            "    ret",
            "    .cfi_endproc",
            $elf_size_args,
        );
    };
}

#[cfg(all(target_arch = "x86_64", unix, not(target_vendor = "apple")))]
sysv_call_asm!(
    "",
    ".type rvm_call_regs, @function",
    ".size rvm_call_regs, .-rvm_call_regs",
    ".type rvm_call_args, @function",
    ".size rvm_call_args, .-rvm_call_args"
);

#[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
sysv_call_asm!("_", "", "", "", "");
