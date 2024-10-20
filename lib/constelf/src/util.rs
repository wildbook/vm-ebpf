use crate::err::ElfError;
use crate::{tryopt, ElfResult};

pub const fn derva_slice(image: &[u8], beg: usize, len: usize) -> ElfResult<&[u8]> {
    match slice(image, beg, beg + len) {
        Some(slice) => Ok(slice),
        None => Err(ElfError::DeRvaBounds),
    }
}

pub const fn slice_from(data: &[u8], beg: usize) -> Option<&[u8]> {
    let len = tryopt!(data.len().checked_sub(beg));
    let ptr = unsafe { data.as_ptr().add(beg) };

    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

pub const fn slice_until(data: &[u8], end: usize) -> Option<&[u8]> {
    tryopt!(data.len().checked_sub(end));
    let ptr = data.as_ptr();

    Some(unsafe { std::slice::from_raw_parts(ptr, end) })
}

pub const fn slice(data: &[u8], beg: usize, end: usize) -> Option<&[u8]> {
    tryopt!(end.checked_sub(beg));

    let data = tryopt!(slice_from(data, beg));
    let data = tryopt!(slice_until(data, end - beg));

    Some(data)
}

pub const fn slice_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }

    let mut i = 0;
    while i < lhs.len() {
        if lhs[i] != rhs[i] {
            return false;
        }

        i += 1;
    }

    true
}
