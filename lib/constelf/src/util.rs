use std::ffi::CStr;
use std::mem;

use crate::err::ElfError;
use crate::raw::{Elf64Ehdr, Elf64Rel, Elf64Rela, Elf64Shdr, Elf64Sym};
use crate::{const_for, tryopt, ElfResult};

/// Types that `cast_slice` may produce: `repr(C, packed)` integer structs, valid for every bit pattern.
///
/// # Safety
///
/// The type must have alignment 1, no padding, and no invalid bit patterns.
pub unsafe trait Plain {}

unsafe impl Plain for Elf64Ehdr {}
unsafe impl Plain for Elf64Shdr {}
unsafe impl Plain for Elf64Sym {}
unsafe impl Plain for Elf64Rel {}
unsafe impl Plain for Elf64Rela {}

/// Reinterprets `bytes` as a slice of `T`, or `None` if the length is not a multiple of `size_of::<T>()`.
pub const fn cast_slice<T: Plain>(bytes: &[u8]) -> Option<&[T]> {
    const { assert!(mem::align_of::<T>() == 1 && mem::size_of::<T>() != 0) };
    if !bytes.len().is_multiple_of(mem::size_of::<T>()) {
        return None;
    }

    let len = bytes.len() / mem::size_of::<T>();
    // SAFETY: `Plain` makes any byte pattern a valid `T`, and the assert above rules out misalignment.
    Some(unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), len) })
}

pub const fn derva_slice(image: &[u8], beg: usize, len: usize) -> ElfResult<&[u8]> {
    let Some((_, tail)) = image.split_at_checked(beg) else {
        return Err(ElfError::DeRvaBounds);
    };
    match tail.split_at_checked(len) {
        Some((data, _)) => Ok(data),
        None => Err(ElfError::DeRvaBounds),
    }
}

/// The NUL-terminated string at `off` in a string table such as `.strtab` or `.shstrtab`.
pub const fn cstr_at(table: &[u8], off: usize) -> Option<&CStr> {
    let (_, tail) = tryopt!(table.split_at_checked(off));
    match CStr::from_bytes_until_nul(tail) {
        Ok(name) => Some(name),
        Err(_) => None,
    }
}

pub const fn slice_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }

    const_for!(i in 0..lhs.len() => {
        if lhs[i] != rhs[i] {
            return false;
        }
    });

    true
}
