//! Calls of native functions: a `call` that [`Code::bind_native`](crate::Code::bind_native) gave the byte of its
//! argument count ([`PLAIN`], or [`CHECKED`] where pointer arguments go through
//! [`Memory::native_ptr`](crate::Memory::native_ptr)), with the index of the function in
//! [`Host::natives`](crate::Host::natives) in `imm`. Its handler passes r1 to rN in the Windows x64 convention and
//! puts the result in r0.
//!
//! The handler saves nothing around the call: the guest registers live in memory, and the handler arguments the
//! dispatch needs afterwards are in registers the Windows x64 convention preserves (see
//! [`Handler`](crate::dispatch::Handler)). It skips the windows check of other host calls, as a native function has
//! no way to the memory of the run.

use std::mem::transmute;

use crate::code::Slots;
use crate::dispatch::{Handler, Spare, Table};
use crate::fuel::Fuel;
use crate::slot::{Fields, Shape, Slot};
use crate::transfer::Ip;
use crate::{Context, Host, Interpreter, Memory, Reason};

/// Most arguments a native function takes: the argument registers r1 to r5.
pub const MAX_ARGS: usize = 5;

/// A native function as [`Native`] keeps it. A call casts it to `unsafe extern "win64" fn(u64, ...) -> u64` with the
/// argument count of its [`NativeSig`].
pub type NativeFn = unsafe extern "win64" fn() -> u64;

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
pub struct NativeSig(u64);

// The bits of a `NativeSig`, which a checked call reads with constant shifts: the argument count, then for each
// argument `i + 1` a bit in `POINTERS` and `WRITES`, and 4 bits at `LENS + 4 * i` with 0 for one byte or the number of
// the integer argument that holds the length, 1 to 5.
const POINTERS: u32 = 8;
const WRITES: u32 = 16;
const LENS: u32 = 24;

/// One argument of a [`NativeSig`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NativeArg {
    /// An integer, passed as the guest's register holds it.
    Int,
    /// A pointer to bytes the function reads: one, or as many as the integer argument with this number (1 to 5)
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
        assert!(args as usize <= MAX_ARGS, "a native function takes at most 5 arguments");
        Self(args as u64)
    }

    /// The signature of `args`, or `None` for more than [`MAX_ARGS`] arguments or a length argument that isn't an
    /// integer argument of the signature.
    pub const fn try_new(args: &[NativeArg]) -> Option<Self> {
        if args.len() > MAX_ARGS {
            return None;
        }
        let mut bits = args.len() as u64;
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
            bits |= 1 << (POINTERS + i as u32) | (write as u64) << (WRITES + i as u32);
            bits |= (len as u64) << (LENS + 4 * i as u32);
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
            None => panic!("more than 5 arguments, or a length argument that isn't an integer argument"),
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
        self.0 >> POINTERS & 0xff != 0
    }
}

/// The byte of a native call with 0 to 5 arguments that passes them as the registers hold them: bytes of JMP32
/// instructions that always fail, which [`Code::new`](crate::Code::new) frees.
pub const PLAIN: [u8; MAX_ARGS + 1] = [0x8e, 0x96, 0xe6, 0xee, 0xf6, 0xfe];

/// The byte of a native call with 1 to 5 arguments that resolves its pointer arguments first: more bytes of
/// instructions that always fail.
pub const CHECKED: [u8; MAX_ARGS] = [0x8c, 0x9d, 0x8f, 0x9b, 0xef];

pub const fn install<M: Memory, H: Host<M>, F: Fuel>(table: &mut [Handler<M, H>; 256]) {
    table[PLAIN[0] as usize] = native_call::<M, H, F, 0, false>;
    table[PLAIN[1] as usize] = native_call::<M, H, F, 1, false>;
    table[PLAIN[2] as usize] = native_call::<M, H, F, 2, false>;
    table[PLAIN[3] as usize] = native_call::<M, H, F, 3, false>;
    table[PLAIN[4] as usize] = native_call::<M, H, F, 4, false>;
    table[PLAIN[5] as usize] = native_call::<M, H, F, 5, false>;
    table[CHECKED[0] as usize] = native_call::<M, H, F, 1, true>;
    table[CHECKED[1] as usize] = native_call::<M, H, F, 2, true>;
    table[CHECKED[2] as usize] = native_call::<M, H, F, 3, true>;
    table[CHECKED[3] as usize] = native_call::<M, H, F, 4, true>;
    table[CHECKED[4] as usize] = native_call::<M, H, F, 5, true>;
}

/// The byte of a native call with `args` arguments, `checked` or not.
pub const fn byte(args: usize, checked: bool) -> u8 {
    match checked {
        true => CHECKED[args - 1],
        false => PLAIN[args],
    }
}

/// The handler of a native call with `N` arguments, which with `CHECKED` resolves the pointer arguments of the
/// function's [`NativeSig`] first.
#[inline(never)]
extern "rust-preserve-none" fn native_call<M: Memory, H: Host<M>, F: Fuel, const N: usize, const CHECKED: bool>(
    ctx: &mut Context<M>,
    code: Slots,
    ip: Ip,
    interp: &mut Interpreter<M, H>,
    table: &Table<M, H>,
    _: Spare,
    slot: Slot,
) {
    // SAFETY: a handler's ip lies below `len`, and its slot has the layout of its byte
    let index = unsafe { ip.view(slot, const { Shape::of(byte(N, CHECKED)) }) }.imm() as u32;
    let Some(&Native { func, sig }) = interp.host.natives().get(index as usize) else {
        core::hint::cold_path();
        return interp.stop.at(ip, Reason::CallKfunc(index));
    };

    // the arguments past `N` stay 0, which no call passes
    let mut a = [0; MAX_ARGS];
    a[..N].copy_from_slice(&ctx.regs[1..=N]);
    if CHECKED {
        // `N` is a constant, so the loop unrolls and each shift of the signature is one too
        let bits = sig.0;
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
    }

    // SAFETY: `Code::bind_native` requires each native function a call names to take `N` arguments
    ctx.regs[0] = unsafe { call(func, N, a) };

    become_enter!(ctx, code, ip.offset(1), interp, table)
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
/// `func` must take `n` integer or pointer arguments in the Windows x64 convention, and never unwind.
#[inline(always)]
unsafe fn call(func: NativeFn, n: usize, a: [u64; MAX_ARGS]) -> u64 {
    type F1 = unsafe extern "win64" fn(u64) -> u64;
    type F2 = unsafe extern "win64" fn(u64, u64) -> u64;
    type F3 = unsafe extern "win64" fn(u64, u64, u64) -> u64;
    type F4 = unsafe extern "win64" fn(u64, u64, u64, u64) -> u64;
    type F5 = unsafe extern "win64" fn(u64, u64, u64, u64, u64) -> u64;
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
