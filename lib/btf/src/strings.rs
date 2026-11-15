//! BTF string table parsing.

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
}
