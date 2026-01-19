//! BTF string table parsing.

use core::ffi::CStr;

/// BTF string table.
///
/// The string table is a sequence of null-terminated strings.
/// The first string is always empty (null).
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
    /// Returns None if the offset is out of bounds or the string is not valid UTF-8.
    pub fn get(&self, offset: u32) -> Option<&'a str> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return None;
        }

        // Find the null terminator
        let slice = &self.data[offset..];
        let end = slice.iter().position(|&b| b == 0)?;

        core::str::from_utf8(&slice[..end]).ok()
    }

    /// Get a string by offset, returning empty string for offset 0 or errors.
    pub fn get_or_empty(&self, offset: u32) -> &'a str {
        self.get(offset).unwrap_or("")
    }

    /// Get a C string by offset.
    pub fn get_cstr(&self, offset: u32) -> Option<&'a CStr> {
        let offset = offset as usize;
        if offset >= self.data.len() {
            return None;
        }

        CStr::from_bytes_until_nul(&self.data[offset..]).ok()
    }

    /// Get the raw data.
    pub fn raw(&self) -> &'a [u8] {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_table() {
        // String table: "\0hello\0world\0"
        let data = b"\0hello\0world\0";
        let strings = BtfStrings::new(data);

        assert_eq!(strings.get(0), Some(""));
        assert_eq!(strings.get(1), Some("hello"));
        assert_eq!(strings.get(7), Some("world"));
        assert_eq!(strings.get(100), None);
    }
}
