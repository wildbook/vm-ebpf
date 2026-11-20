use core::ffi::CStr;

/// A BTF string table: NUL-terminated strings, addressed by byte offset. Offset 0 holds the empty string.
#[derive(Debug, Clone)]
pub struct BtfStrings<'a> {
    data: &'a [u8],
}

impl<'a> BtfStrings<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// The string at `offset`, or `None` if the offset is out of bounds or the string is unterminated or not UTF-8.
    pub fn get(&self, offset: u32) -> Option<&'a str> {
        let tail = self.data.get(offset as usize..)?;
        CStr::from_bytes_until_nul(tail).ok()?.to_str().ok()
    }

    /// The string at `offset`, or `""` where [`get`](Self::get) returns `None`.
    pub(crate) fn get_or_empty(&self, offset: u32) -> &'a str {
        self.get(offset).unwrap_or("")
    }
}
