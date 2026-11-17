//! BTF string table parsing.

use core::ffi::CStr;

/// BTF string table.
///
/// The string table is a sequence of null-terminated strings. The first string is always empty (null).
#[derive(Debug, Clone)]
pub struct BtfStrings<'a> {
    data: &'a [u8],
}

impl<'a> BtfStrings<'a> {
    /// Create a new string table from raw bytes.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Get a string by offset.
    ///
    /// Returns None if the offset is out of bounds or the string is unterminated or not valid UTF-8.
    pub fn get(&self, offset: u32) -> Option<&'a str> {
        let tail = self.data.get(offset as usize..)?;
        CStr::from_bytes_until_nul(tail).ok()?.to_str().ok()
    }

    /// Get a string by offset, or `""` if it is missing or invalid.
    pub fn get_or_empty(&self, offset: u32) -> &'a str {
        self.get(offset).unwrap_or("")
    }
}
