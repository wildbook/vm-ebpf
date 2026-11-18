//! rvm as a C library: load a prepared image, map guest memory and call functions by name.
//!
//! `include/rvmrt.h` declares these functions for C. Images come from `rvm::Vm::prepare` and `rvm::Image::to_bytes`;
//! the runtime has no helpers and no maps, and the default instruction limit of `rvm::VmConfig`.

use std::slice;

use rvm::{ExecError, Perms, Program, Vm, VmError, FIRST_FREE_REGION};

/// Result of every call that can fail; `rvm_status` in the header.
#[repr(C)]
pub enum Status {
    Ok = 0,
    /// A malformed image, or one written by another rvm version.
    Image = 1,
    /// The image imports a helper or host function that the runtime doesn't have, or declares maps.
    Link = 2,
    /// No function with this name.
    NotFound = 3,
    /// A bad argument: more than 5 call arguments, a region or length that can't be mapped, a name that isn't UTF-8.
    Argument = 4,
    /// The call ran more instructions than the limit.
    Limit = 5,
    /// The guest faulted: an invalid instruction or memory access, or a call stack overflow.
    Fault = 6,
    /// A helper failed.
    Helper = 7,
    /// Any other error.
    Other = 8,
}

impl Status {
    fn of(error: &VmError) -> Self {
        match error {
            VmError::InvalidImage(_) | VmError::ProgramTooLarge(_) => Self::Image,
            VmError::Link(_) => Self::Link,
            VmError::FunctionNotFound { .. } => Self::NotFound,
            VmError::TooManyArgs(_) | VmError::InvalidArgument(_) => Self::Argument,
            VmError::Exec(ExecError::InstructionLimit(_)) => Self::Limit,
            VmError::Exec(_) | VmError::Memory(_) => Self::Fault,
            VmError::Helper(_) => Self::Helper,
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
pub unsafe extern "C" fn rvm_load(image: *const u8, len: usize, program: *mut *mut Program) -> Status {
    let bytes = unsafe { slice_or_empty(image, len) };
    let loaded = Vm::new().load_image(bytes).map(|p| Box::into_raw(Box::new(p)));
    unsafe { finish(loaded, program) }
}

/// Frees a program from [`rvm_load`]; null is ignored.
///
/// # Safety
///
/// `program` must be null or a program from [`rvm_load`] that is not freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_free(program: *mut Program) {
    if !program.is_null() {
        drop(unsafe { Box::from_raw(program) });
    }
}

/// Maps `len` zeroed read-write bytes as host region `region`, counted from 0, and stores the region's guest address
/// in `*addr`. A region that is already mapped is replaced.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], and `addr` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_map(program: *mut Program, region: usize, len: usize, addr: *mut u64) -> Status {
    let program = unsafe { &mut *program };
    let idx = FIRST_FREE_REGION.saturating_add(region);
    unsafe { finish(program.memory_mut().map(idx, len, Perms::RW), addr) }
}

/// Calls the function `name` with `args` in r1 to r5 and stores its r0 in `*ret`.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], `name` must point to `name_len` readable bytes, `args` to
/// `nargs` values, and `ret` must be valid for writes. `name` and `args` may be null when their length is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_call(
    program: *mut Program,
    name: *const u8,
    name_len: usize,
    args: *const u64,
    nargs: usize,
    ret: *mut u64,
) -> Status {
    let program = unsafe { &mut *program };
    let Ok(name) = std::str::from_utf8(unsafe { slice_or_empty(name, name_len) }) else {
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
    program: *const Program,
    name: *const u8,
    name_len: usize,
    index: *mut usize,
) -> Status {
    let program = unsafe { &*program };
    let Ok(name) = std::str::from_utf8(unsafe { slice_or_empty(name, name_len) }) else {
        return Status::Argument;
    };
    let Some(found) = program.function_index(name) else {
        return Status::NotFound;
    };
    unsafe { index.write(found) };
    Status::Ok
}

/// Calls the function at `index` with `args` in r1 to r5 and stores its r0 in `*ret`.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], `args` must point to `nargs` values, and `ret` must be valid
/// for writes. `args` may be null when `nargs` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_call_func(
    program: *mut Program,
    index: usize,
    args: *const u64,
    nargs: usize,
    ret: *mut u64,
) -> Status {
    let program = unsafe { &mut *program };
    let Some(func) = program.func_at(index) else {
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
pub unsafe extern "C" fn rvm_function_count(program: *const Program) -> usize {
    unsafe { &*program }.functions().len()
}

/// Stores the name of the function at `index`, which stays valid until the program is freed, in `*name` and
/// `*name_len`. The name is UTF-8 and not NUL-terminated.
///
/// # Safety
///
/// `program` must be a live program from [`rvm_load`], and `name` and `name_len` must be valid for writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rvm_function_name(
    program: *const Program,
    index: usize,
    name: *mut *const u8,
    name_len: *mut usize,
) -> Status {
    let program = unsafe { &*program };
    let Some((found, _)) = program.functions().nth(index) else {
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
