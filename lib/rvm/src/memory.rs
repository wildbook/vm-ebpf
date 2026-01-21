//! Memory implementation for the eBPF VM.
//!
//! This module provides the default memory implementation used by the VM,
//! as well as traits for custom memory implementations.

// Re-export the Memory trait from rvm-core
pub use rvm_core::Memory;

use crate::error::MemoryError;

/// Default memory implementation for the eBPF VM.
///
/// Provides a flat byte array with bounds checking. The memory layout is:
/// - Code sections (executable)
/// - Data sections (.data, .rodata, .bss)
/// - Stack space
///
/// # Example
///
/// ```
/// use rvm::VmMemory;
///
/// let mut mem = VmMemory::new(4096);
/// mem.write_bytes(0, &[1, 2, 3, 4]).unwrap();
/// assert_eq!(mem.read_bytes(0, 4).unwrap(), &[1, 2, 3, 4]);
/// ```
#[derive(Clone)]
pub struct VmMemory {
    data: Vec<u8>,
}

impl Default for VmMemory {
    fn default() -> Self {
        Self::new(0)
    }
}

impl VmMemory {
    /// Create a new memory region of the given size.
    pub fn new(size: usize) -> Self {
        Self { data: vec![0u8; size] }
    }

    /// Create memory from existing data.
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the total size of the memory region.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the memory is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Resize the memory region.
    pub fn resize(&mut self, new_size: usize) {
        self.data.resize(new_size, 0);
    }

    /// Write a slice of bytes to memory at the given offset.
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        let end = offset.checked_add(bytes.len()).ok_or(MemoryError::OutOfBounds {
            addr: offset as u64,
            size: bytes.len(),
        })?;

        if end > self.data.len() {
            return Err(MemoryError::OutOfBounds {
                addr: offset as u64,
                size: bytes.len(),
            });
        }

        self.data[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    /// Read bytes from memory.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Result<&[u8], MemoryError> {
        let end = offset.checked_add(len).ok_or(MemoryError::OutOfBounds {
            addr: offset as u64,
            size: len,
        })?;

        if end > self.data.len() {
            return Err(MemoryError::OutOfBounds {
                addr: offset as u64,
                size: len,
            });
        }

        Ok(&self.data[offset..end])
    }

    /// Get a mutable slice of bytes from memory.
    pub fn bytes_mut(&mut self, offset: usize, len: usize) -> Result<&mut [u8], MemoryError> {
        let end = offset.checked_add(len).ok_or(MemoryError::OutOfBounds {
            addr: offset as u64,
            size: len,
        })?;

        if end > self.data.len() {
            return Err(MemoryError::OutOfBounds {
                addr: offset as u64,
                size: len,
            });
        }

        Ok(&mut self.data[offset..end])
    }

    /// Read a value from memory.
    pub fn read<T: FromBytes>(&self, offset: usize) -> Result<T, MemoryError> {
        let bytes = self.read_bytes(offset, std::mem::size_of::<T>())?;
        Ok(T::from_le_bytes(bytes))
    }

    /// Write a value to memory.
    pub fn write<T: ToBytes>(&mut self, offset: usize, value: T) -> Result<(), MemoryError> {
        let bytes = value.to_le_bytes_vec();
        self.write_bytes(offset, &bytes)
    }

    /// Get direct access to the underlying data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable direct access to the underlying data.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Consume and return the underlying data.
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl Memory for VmMemory {
    type Err = &'static str;

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Err> {
        self.data.get(addr as usize).copied().ok_or("load_u8: out of bounds")
    }

    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
        self.data
            .get_mut(addr as usize)
            .map(|b| *b = value)
            .ok_or("store_u8: out of bounds")
    }

    fn load_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        let i = addr as usize;
        let end = i.checked_add(2).ok_or("load_u16: address overflow")?;
        if end > self.data.len() {
            return Err("load_u16: out of bounds");
        }
        Ok(u16::from_le_bytes([self.data[i], self.data[i + 1]]))
    }

    fn load_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        let i = addr as usize;
        let end = i.checked_add(4).ok_or("load_u32: address overflow")?;
        if end > self.data.len() {
            return Err("load_u32: out of bounds");
        }
        Ok(u32::from_le_bytes([self.data[i], self.data[i + 1], self.data[i + 2], self.data[i + 3]]))
    }

    fn load_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        let i = addr as usize;
        let end = i.checked_add(8).ok_or("load_u64: address overflow")?;
        if end > self.data.len() {
            return Err("load_u64: out of bounds");
        }
        Ok(u64::from_le_bytes([
            self.data[i],
            self.data[i + 1],
            self.data[i + 2],
            self.data[i + 3],
            self.data[i + 4],
            self.data[i + 5],
            self.data[i + 6],
            self.data[i + 7],
        ]))
    }

    fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        let i = addr as usize;
        let end = i.checked_add(2).ok_or("store_u16: address overflow")?;
        if end > self.data.len() {
            return Err("store_u16: out of bounds");
        }
        self.data[i..][..2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        let i = addr as usize;
        let end = i.checked_add(4).ok_or("store_u32: address overflow")?;
        if end > self.data.len() {
            return Err("store_u32: out of bounds");
        }
        self.data[i..][..4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        let i = addr as usize;
        let end = i.checked_add(8).ok_or("store_u64: address overflow")?;
        if end > self.data.len() {
            return Err("store_u64: out of bounds");
        }
        self.data[i..][..8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

/// Trait for types that can be read from bytes.
pub trait FromBytes: Sized {
    fn from_le_bytes(bytes: &[u8]) -> Self;
}

/// Trait for types that can be written to bytes.
pub trait ToBytes {
    fn to_le_bytes_vec(&self) -> Vec<u8>;
}

// Implement FromBytes for common types
impl FromBytes for u8 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        bytes[0]
    }
}

impl FromBytes for u16 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        u16::from_le_bytes([bytes[0], bytes[1]])
    }
}

impl FromBytes for u32 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

impl FromBytes for u64 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

impl FromBytes for i8 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        bytes[0] as i8
    }
}

impl FromBytes for i16 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        i16::from_le_bytes([bytes[0], bytes[1]])
    }
}

impl FromBytes for i32 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }
}

impl FromBytes for i64 {
    fn from_le_bytes(bytes: &[u8]) -> Self {
        i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    }
}

// Implement ToBytes for common types
impl ToBytes for u8 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl ToBytes for u16 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl ToBytes for u32 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl ToBytes for u64 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl ToBytes for i8 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        vec![*self as u8]
    }
}

impl ToBytes for i16 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl ToBytes for i32 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl ToBytes for i64 {
    fn to_le_bytes_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl std::fmt::Debug for VmMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmMemory").field("len", &self.data.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_read_write() {
        let mut mem = VmMemory::new(64);

        // Test u8
        mem.write(0, 0x42u8).unwrap();
        assert_eq!(mem.read::<u8>(0).unwrap(), 0x42);

        // Test u64
        mem.write(8, 0xDEADBEEFCAFEBABEu64).unwrap();
        assert_eq!(mem.read::<u64>(8).unwrap(), 0xDEADBEEFCAFEBABE);

        // Test bounds
        assert!(mem.read::<u8>(100).is_err());
    }

    #[test]
    fn test_memory_bytes() {
        let mut mem = VmMemory::new(64);
        let data = [1, 2, 3, 4, 5, 6, 7, 8];

        mem.write_bytes(0, &data).unwrap();
        assert_eq!(mem.read_bytes(0, 8).unwrap(), &data);
    }

    #[test]
    fn test_memory_trait() {
        let mut mem = VmMemory::new(64);

        mem.store_u64(0, 0x123456789ABCDEF0).unwrap();
        assert_eq!(mem.load_u64(0).unwrap(), 0x123456789ABCDEF0);
        assert_eq!(mem.load_u32(0).unwrap(), 0x9ABCDEF0);
        assert_eq!(mem.load_u16(0).unwrap(), 0xDEF0);
        assert_eq!(mem.load_u8(0).unwrap(), 0xF0);
    }
}
