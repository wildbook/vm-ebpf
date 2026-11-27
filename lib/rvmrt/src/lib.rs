//! rvm as a C library: load a prepared image, map guest memory, copy bytes in and out, and call functions by name.
//!
//! `include/rvmrt.h` declares these functions for C. Images come from `rvm::Vm::prepare_elf` and
//! `rvm::Image::to_bytes`; the runtime has no helpers and no maps, only the native functions the host passes to
//! [`rvm_load_with`]. With the `fuel` feature it limits each call to `rvm::DEFAULT_INSTRUCTION_LIMIT` instructions.

use std::slice;

use rvm::{
    ExecError, Func, NativeArg, NativeSig, Passthrough, Perms, Program, RawCalls, Region, Vm, VmConfig, VmError,
    MAX_NATIVE_ARGS,
};

/// The limit of each call; 0 is no limit.
#[cfg(feature = "fuel")]
const INSTRUCTION_LIMIT: u64 = rvm::DEFAULT_INSTRUCTION_LIMIT;
#[cfg(not(feature = "fuel"))]
const INSTRUCTION_LIMIT: u64 = 0;

/// What an `rvm_program` pointer points to: a program, the handles of its functions in name order, so that a call by
/// index looks nothing up, and the regions [`rvm_map`] mapped.
pub struct RvmProgram {
    program: Program,
    funcs: Vec<Func>,
    regions: Vec<Region>,
}

impl RvmProgram {
    fn new(program: Program) -> Self {
        let handle = |(name, _): &(String, _)| program.func(name).expect("a listed function");
        let funcs = program.functions().iter().map(handle).collect();
        Self {
            program,
            funcs,
            regions: Vec::new(),
        }
    }
}

/// Result of every call that can fail; `rvm_status` in the header.
#[repr(C)]
pub enum Status {
    Ok = 0,
    /// A malformed image, one written by another rvm version, or one that needs more memory than the limit.
    Image = 1,
    /// The image imports a helper or host function that the runtime doesn't have, or declares maps.
    Link = 2,
    /// No function with this name.
    NotFound = 3,
    /// A bad argument: more than 12 call arguments, a length that can't be mapped, no free region to map, an address
    /// that [`rvm_map`] didn't return, a name that isn't UTF-8.
    Argument = 4,
    /// The call ran more instructions than the limit.
    Limit = 5,
    /// The guest faulted: an invalid instruction or memory access, or a call stack overflow. Also a read or write of
    /// bytes the guest may not read or write.
    Fault = 6,
    /// A helper failed.
    Helper = 7,
    /// Any other error.
    Other = 8,
}

impl Status {
    fn of(error: &VmError) -> Self {
        match error {
            VmError::InvalidImage(_) | VmError::ProgramTooLarge(_) | VmError::MemoryLimit(_) => Self::Image,
            VmError::Link(_) => Self::Link,
            VmError::FunctionNotFound { .. } => Self::NotFound,
            VmError::TooManyArgs(_) | VmError::InvalidArgument(_) | VmError::NoFreeRegion => Self::Argument,
            VmError::Exec(ExecError::InstructionLimit { .. }) => Self::Limit,
            VmError::Exec(ExecError::UnknownHelper { .. } | ExecError::UnknownExtern { .. }) => Self::Helper,
            VmError::Exec(_) | VmError::Memory(_) => Self::Fault,
            VmError::Host(_) => Self::Helper,
            _ => Self::Other,
        }
    }
}

/// Loads a prepared image and stores the program in `*program`.
///
/// # Safety
///
/// `image` must point to `len` readable bytes, and `program` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_load(image: *const u8, len: usize, program: *mut *mut RvmProgram) -> Status {
    let options = RvmOptions {
        size: size_of::<RvmOptions>(),
        natives: std::ptr::null(),
        native_count: 0,
        flags: 0,
    };
    unsafe { rvm_load_with(image, len, &options, program) }
}

/// A native function the image imports by name; `rvm_native` in the header.
#[repr(C)]
pub struct RvmNative {
    pub name: *const u8,
    pub name_len: usize,
    pub func: *const (),
    /// Arguments, 0 to 12.
    pub args: u8,
    /// Per argument: 0 for an integer, 1 for a pointer the function reads, 2 for one it reads and writes.
    pub kind: [u8; MAX_NATIVE_ARGS],
    /// Per pointer argument: 0 for one byte, or the number of the integer argument that holds its length.
    pub len_arg: [u8; MAX_NATIVE_ARGS],
}

/// How [`rvm_load_with`] loads an image; `rvm_options` in the header.
#[repr(C)]
pub struct RvmOptions {
    /// The caller's `sizeof(rvm_options)`, which tells the layouts of different library versions apart.
    pub size: usize,
    pub natives: *const RvmNative,
    pub native_count: usize,
    /// `RVM_UNTAGGED`, `RVM_RAW_POINTERS` and `RVM_RAW_CALLS`.
    pub flags: u32,
}

/// `RVM_UNTAGGED`: `rvm::Passthrough::untagged`.
const UNTAGGED: u32 = 1;
/// `RVM_RAW_POINTERS`: `rvm::Passthrough::on`.
const RAW_POINTERS: u32 = 2;
/// `RVM_RAW_CALLS`: `rvm::RawCalls::on`.
const RAW_CALLS: u32 = 4;

/// [`rvm_load`] with `options`: its natives registered as `rvm::Vm::register_native` registers them, and the memory
/// mode and raw calls its flags name.
///
/// # Safety
///
/// As [`rvm_load`]; `options` must point to an `rvm_options` whose `natives` point to `native_count` entries. Each
/// function must meet the contract of `rvm::Vm::register_native`, and the host those of `rvm::Passthrough::on`,
/// `rvm::Passthrough::untagged` and `rvm::RawCalls::on` for the flags it sets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_load_with(
    image: *const u8,
    len: usize,
    options: *const RvmOptions,
    program: *mut *mut RvmProgram,
) -> Status {
    // the size comes first in every layout, and says whether the rest is this one
    if unsafe { options.cast::<usize>().read() } != size_of::<RvmOptions>() {
        return Status::Argument;
    }
    let options = unsafe { &*options };
    if options.flags & !(UNTAGGED | RAW_POINTERS | RAW_CALLS) != 0 {
        return Status::Argument;
    }

    let bytes = unsafe { slice_or_empty(image, len) };
    let mut list = Vec::with_capacity(options.native_count);
    for native in unsafe { slice_or_empty(options.natives, options.native_count) } {
        let name = unsafe { str_or_none(native.name, native.name_len) };
        let (Some(name), Some(sig)) = (name, native_sig(native)) else {
            return Status::Argument;
        };
        list.push((name, native.func, sig));
    }

    // SAFETY: the caller's, for each flag
    let (passthrough, raw_calls) = unsafe {
        let passthrough = match options.flags {
            flags if flags & UNTAGGED != 0 => Passthrough::untagged(),
            flags if flags & RAW_POINTERS != 0 => Passthrough::on(),
            _ => Passthrough::OFF,
        };
        let raw_calls = match options.flags & RAW_CALLS {
            0 => RawCalls::OFF,
            _ => RawCalls::on(),
        };
        (passthrough, raw_calls)
    };
    let config = VmConfig {
        instruction_limit: INSTRUCTION_LIMIT,
        passthrough,
        raw_calls,
        ..VmConfig::default()
    };
    // SAFETY: the caller's
    let loaded = unsafe { Vm::with_natives(config, &list) }
        .and_then(|vm| vm.load_image_bytes(bytes))
        .map(|p| Box::into_raw(Box::new(RvmProgram::new(p))));
    unsafe { finish(loaded, program) }
}

/// The signature `native` describes, or `None` for an invalid one.
fn native_sig(native: &RvmNative) -> Option<NativeSig> {
    let args = native.kind.get(..usize::from(native.args))?;
    let mut list = [NativeArg::Int; MAX_NATIVE_ARGS];
    for (i, &kind) in args.iter().enumerate() {
        let len = (native.len_arg[i] != 0).then_some(native.len_arg[i]);
        list[i] = match kind {
            0 => NativeArg::Int,
            1 => NativeArg::Read(len),
            2 => NativeArg::Write(len),
            _ => return None,
        };
    }
    NativeSig::try_new(&list[..args.len()])
}

/// Frees a program from [`rvm_load`]; null is ignored.
///
/// # Safety
///
/// `program` must be null or a program from [`rvm_load`] that is not freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_free(program: *mut RvmProgram) {
    if !program.is_null() {
        drop(unsafe { Box::from_raw(program) });
    }
}

/// Maps `len` zeroed read-write bytes at an address the runtime picks, and stores that address in `*addr`.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], and `addr` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_map(program: *mut RvmProgram, len: usize, addr: *mut u64) -> Status {
    let RvmProgram { program, regions, .. } = unsafe { &mut *program };
    let mapped = program.memory_mut().map(len, Perms::RW).map(|region| {
        let base = region.base();
        regions.push(region);
        base
    });
    unsafe { finish(mapped, addr) }
}

/// Unmaps the region that [`rvm_map`] mapped at `addr`.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_unmap(program: *mut RvmProgram, addr: u64) -> Status {
    let RvmProgram { program, regions, .. } = unsafe { &mut *program };
    let Some(found) = regions.iter().position(|region| region.base() == addr) else {
        return Status::Argument;
    };
    unsafe { finish(program.memory_mut().unmap(regions.swap_remove(found)), &mut ()) }
}

/// Copies `len` bytes at guest address `addr` into `buf`. The guest must be allowed to read them, as for its own loads.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], and `buf` must point to `len` writable bytes. `buf` may be null
/// when `len` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_read(program: *const RvmProgram, addr: u64, buf: *mut u8, len: usize) -> Status {
    let program = unsafe { &(*program).program };
    if len == 0 {
        return Status::Ok;
    }
    let copied = program.memory().host_ptr(addr, len, Perms::R).map(|src| {
        // SAFETY: `host_ptr` checked that the range lies in a live region; `buf` is the caller's own memory.
        unsafe { std::ptr::copy(src.as_ptr(), buf, len) }
    });
    unsafe { finish(copied.map_err(VmError::Memory), &mut ()) }
}

/// Copies `len` bytes from `buf` to guest address `addr`. The guest must be allowed to write them, as for its own
/// stores.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], and `buf` must point to `len` readable bytes. `buf` may be null
/// when `len` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_write(program: *mut RvmProgram, addr: u64, buf: *const u8, len: usize) -> Status {
    let program = unsafe { &mut (*program).program };
    if len == 0 {
        return Status::Ok;
    }
    let memory = program.memory_mut();
    let copied = memory.host_ptr(addr, len, Perms::W).map(|dst| {
        // SAFETY: as in `rvm_read`, and `memory` borrows the program mutably.
        unsafe { std::ptr::copy(buf, dst.as_ptr(), len) }
    });
    unsafe { finish(copied.map_err(VmError::Memory), &mut ()) }
}

/// Calls the function `name` with up to 12 `args`, the first five in r1 to r5 and the others as a caller passes them
/// on the stack, and stores its r0 in `*ret`.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], `name` must point to `name_len` readable bytes, `args` to
/// `nargs` values, and `ret` must be valid for writes. `name` and `args` may be null when their length is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_call(
    program: *mut RvmProgram,
    name: *const u8,
    name_len: usize,
    args: *const u64,
    nargs: usize,
    ret: *mut u64,
) -> Status {
    let program = unsafe { &mut (*program).program };
    let Some(name) = (unsafe { str_or_none(name, name_len) }) else {
        return Status::Argument;
    };
    let args = unsafe { slice_or_empty(args, nargs) };
    unsafe { finish(program.call(name, args), ret) }
}

/// Stores the index of the function `name` in `*index`, for [`rvm_call_func`].
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], `name` must point to `name_len` readable bytes, and `index`
/// must be valid for writes. `name` may be null when `name_len` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_func(
    program: *const RvmProgram,
    name: *const u8,
    name_len: usize,
    index: *mut usize,
) -> Status {
    let functions = unsafe { &*program }.program.functions();
    let Some(name) = (unsafe { str_or_none(name, name_len) }) else {
        return Status::Argument;
    };
    let Ok(found) = functions.binary_search_by(|(listed, _)| listed.as_str().cmp(name)) else {
        return Status::NotFound;
    };
    unsafe { index.write(found) };
    Status::Ok
}

/// Calls the function at `index` with `args` as [`rvm_call`] passes them and stores its r0 in `*ret`.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], `args` must point to `nargs` values, and `ret` must be valid
/// for writes. `args` may be null when `nargs` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_call_func(
    program: *mut RvmProgram,
    index: usize,
    args: *const u64,
    nargs: usize,
    ret: *mut u64,
) -> Status {
    let RvmProgram { program, funcs, .. } = unsafe { &mut *program };
    let Some(&func) = funcs.get(index) else {
        return Status::NotFound;
    };
    let args = unsafe { slice_or_empty(args, nargs) };
    unsafe { finish(program.call_func(func, args), ret) }
}

/// The number of functions. Indices go from 0 to this count minus 1, in name order.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_function_count(program: *const RvmProgram) -> usize {
    unsafe { &*program }.funcs.len()
}

/// Stores the name of the function at `index`, which stays valid until the program is freed, in `*name` and
/// `*name_len`. The name is UTF-8 and not NUL-terminated.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], and `name` and `name_len` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_function_name(
    program: *const RvmProgram,
    index: usize,
    name: *mut *const u8,
    name_len: *mut usize,
) -> Status {
    let functions = unsafe { &*program }.program.functions();
    let Some((found, _)) = functions.get(index) else {
        return Status::NotFound;
    };
    unsafe {
        name.write(found.as_ptr());
        name_len.write(found.len());
    }
    Status::Ok
}

/// Stores the value of `result` in `*out`, or returns the error's status.
///
/// # Safety
///
/// `out` must be valid for writes.
unsafe fn finish<T>(result: rvm::Result<T>, out: *mut T) -> Status {
    match result {
        Ok(value) => {
            unsafe { out.write(value) };
            Status::Ok
        }
        Err(error) => Status::of(&error),
    }
}

/// `ptr..ptr+len` as a slice; C callers pass null for empty arrays, which `slice::from_raw_parts` doesn't allow.
///
/// # Safety
///
/// `ptr` must point to `len` readable values when `len` is not 0, and they must outlive `'a`.
unsafe fn slice_or_empty<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(ptr, len) }
}

/// [`slice_or_empty`] as a string, or `None` if the bytes aren't UTF-8.
///
/// # Safety
///
/// As [`slice_or_empty`].
unsafe fn str_or_none<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    std::str::from_utf8(unsafe { slice_or_empty(ptr, len) }).ok()
}

#[cfg(test)]
mod tests {
    use super::Status;

    /// Every function this library exports, with the C name it exports, has a declaration in the header.
    #[test]
    fn header_declares_every_function() {
        let header = include_str!("../include/rvmrt.h");
        let source = include_str!("lib.rs");
        let exported: Vec<&str> = source
            .split("pub unsafe extern \"C\" fn ")
            .skip(1)
            .map(|rest| rest.split('(').next().unwrap())
            .collect();
        assert!(exported.len() >= 11, "{exported:?}");
        for name in exported {
            assert!(header.contains(&format!(" {name}(")), "{name} is not declared in rvmrt.h");
        }
    }

    #[test]
    fn status_matches_rvmrt_h() {
        let header: Vec<(&str, i32)> = include_str!("../include/rvmrt.h")
            .lines()
            .filter_map(|line| {
                let (name, value) = line.trim().strip_suffix(',')?.split_once(" = ")?;
                Some((name, value.parse().ok()?))
            })
            .collect();
        let rust = [
            Status::Ok,
            Status::Image,
            Status::Link,
            Status::NotFound,
            Status::Argument,
            Status::Limit,
            Status::Fault,
            Status::Helper,
            Status::Other,
        ]
        .map(|status| (c_name(&status), status as i32));

        assert_eq!(header, rust);
    }

    fn c_name(status: &Status) -> &'static str {
        match status {
            Status::Ok => "RVM_OK",
            Status::Image => "RVM_ERR_IMAGE",
            Status::Link => "RVM_ERR_LINK",
            Status::NotFound => "RVM_ERR_NOT_FOUND",
            Status::Argument => "RVM_ERR_ARGUMENT",
            Status::Limit => "RVM_ERR_LIMIT",
            Status::Fault => "RVM_ERR_FAULT",
            Status::Helper => "RVM_ERR_HELPER",
            Status::Other => "RVM_ERR_OTHER",
        }
    }
}
