//! Guest memory for the eBPF VM.
//!
//! Guest addresses are split into a region index (bits 32..) and an offset
//! (bits 0..32): `addr = (region << 32) | offset`. Each of the [`MAX_REGIONS`]
//! slots maps a byte range with its own permissions. Region 0 is never mapped,
//! so null pointers (and small offsets from them) fault.
//!
//! A guest access costs one table index, a permission test and a bounds check.
//! Host-side accessors ([`VmMemory::read`], [`VmMemory::bytes_mut`], ...) are
//! trusted and ignore permissions.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicU32, AtomicU64};

use rvm_core::AtomicOp;
// Re-export the Memory trait from rvm-core
pub use rvm_core::Memory;

use crate::error::MemoryError;

/// Number of region slots in a [`VmMemory`].
pub const MAX_REGIONS: usize = 64;

/// Bit position of the region index in a guest address.
pub const REGION_SHIFT: u32 = 32;

/// Largest region (offsets are 32 bits).
pub const MAX_REGION_LEN: usize = 1 << REGION_SHIFT;

/// Guest base address of region `idx`.
pub const fn region_base(idx: usize) -> u64 {
    (idx as u64) << REGION_SHIFT
}

/// Access permissions of a region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Perms(u8);

impl Perms {
    /// Not accessible from the guest.
    pub const NONE: Self = Self(0);
    /// Guest may read.
    pub const R: Self = Self(1);
    /// Guest may write.
    pub const W: Self = Self(2);
    /// Guest may read and write.
    pub const RW: Self = Self(3);

    #[inline(always)]
    const fn allows(self, need: Self) -> bool {
        self.0 & need.0 == need.0
    }
}

#[derive(Clone, Copy)]
struct Region {
    ptr: NonNull<u8>,
    len: usize,
    perms: Perms,
    /// Allocated by this `VmMemory` (freed on unmap/drop) vs. borrowed host memory.
    owned: bool,
}

impl Region {
    const EMPTY: Self = Self {
        ptr: NonNull::dangling(),
        len: 0,
        perms: Perms::NONE,
        owned: false,
    };
}

/// Region-mapped guest memory.
///
/// # Example
///
/// ```
/// use rvm::{region_base, Perms, VmMemory};
///
/// let mut mem = VmMemory::new();
/// let base = mem.map(1, 4096, Perms::RW);
/// assert_eq!(base, region_base(1));
/// mem.write(base + 8, 42u64).unwrap();
/// assert_eq!(mem.read::<u64>(base + 8).unwrap(), 42);
/// assert!(mem.read::<u8>(0).is_err()); // region 0 is never mapped
/// ```
pub struct VmMemory {
    regions: [Region; MAX_REGIONS],
}

// SAFETY: owned regions are plain heap allocations exclusively owned by this value.
// Host regions are only created through `map_host`, whose contract requires the
// memory to be usable from whichever thread uses this `VmMemory`.
unsafe impl Send for VmMemory {}
unsafe impl Sync for VmMemory {}

impl Default for VmMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl VmMemory {
    /// Create memory with no regions mapped.
    pub const fn new() -> Self {
        Self {
            regions: [Region::EMPTY; MAX_REGIONS],
        }
    }

    /// Map `len` zeroed bytes as region `idx`, replacing any previous mapping.
    /// Returns the region's guest base address.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is 0 or out of range, or `len` exceeds [`MAX_REGION_LEN`].
    pub fn map(&mut self, idx: usize, len: usize, perms: Perms) -> u64 {
        assert!(len <= MAX_REGION_LEN, "region too large: {len}");
        let ptr = if len == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: non-zero size, align 8.
            let raw = unsafe { alloc_zeroed(Self::layout(len)) };
            NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(Self::layout(len)))
        };
        self.set(
            idx,
            Region {
                ptr,
                len,
                perms,
                owned: true,
            },
        )
    }

    /// Map region `idx` with `len` bytes, initialized from `init` (rest zeroed).
    ///
    /// # Panics
    ///
    /// As [`map`](Self::map), and if `init` is longer than `len`.
    pub fn map_bytes(&mut self, idx: usize, init: &[u8], len: usize, perms: Perms) -> u64 {
        assert!(init.len() <= len, "init ({}) larger than region ({len})", init.len());
        let base = self.map(idx, len, perms);
        self.write_bytes(base, init).expect("freshly mapped region");
        base
    }

    /// Expose host memory as region `idx`. Guest accesses go straight to `ptr`.
    ///
    /// # Safety
    ///
    /// `ptr..ptr+len` must stay valid (and writable if `perms` allows writes) until
    /// the region is unmapped or this `VmMemory` is dropped, must not be accessed
    /// through other references in ways that conflict with guest/helper accesses
    /// while the VM runs, and must be usable from any thread that uses this memory.
    pub unsafe fn map_host(&mut self, idx: usize, ptr: NonNull<u8>, len: usize, perms: Perms) -> u64 {
        assert!(len <= MAX_REGION_LEN, "region too large: {len}");
        self.set(
            idx,
            Region {
                ptr,
                len,
                perms,
                owned: false,
            },
        )
    }

    /// Unmap region `idx`, freeing it if it was allocated by [`map`](Self::map).
    pub fn unmap(&mut self, idx: usize) {
        self.set(idx, Region::EMPTY);
    }

    /// Length of region `idx` (0 if unmapped).
    pub fn region_len(&self, idx: usize) -> usize {
        self.regions.get(idx).map_or(0, |r| r.len)
    }

    fn set(&mut self, idx: usize, region: Region) -> u64 {
        assert!(idx != 0 && idx < MAX_REGIONS, "invalid region index {idx}");
        let old = std::mem::replace(&mut self.regions[idx], region);
        Self::free(old);
        region_base(idx)
    }

    fn free(region: Region) {
        if region.owned && region.len != 0 {
            // SAFETY: allocated in `map` with this exact layout and not freed since.
            unsafe { dealloc(region.ptr.as_ptr(), Self::layout(region.len)) };
        }
    }

    fn layout(len: usize) -> Layout {
        Layout::from_size_align(len, 8).expect("region layout")
    }

    /// Resolve `addr..addr+len` to a host pointer if region perms include `need`.
    #[inline(always)]
    fn resolve(&self, addr: u64, len: usize, need: Perms) -> Option<NonNull<u8>> {
        let region = self.regions.get((addr >> REGION_SHIFT) as usize)?;
        let off = addr as u32 as usize;
        // `off < 2^32` and `len` is small or a host length, so this can't overflow on 64-bit.
        (region.perms.allows(need) && off + len <= region.len)
            // SAFETY: in bounds of the region's allocation.
            .then(|| unsafe { region.ptr.add(off) })
    }

    /// Borrow `len` bytes at guest address `addr` (host access, ignores perms).
    pub fn bytes(&self, addr: u64, len: usize) -> Result<&[u8], MemoryError> {
        let ptr = self
            .resolve(addr, len, Perms::NONE)
            .ok_or(MemoryError::OutOfBounds { addr, size: len })?;
        // SAFETY: `resolve` checked the range lies inside a live region.
        Ok(unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) })
    }

    /// Mutably borrow `len` bytes at guest address `addr` (host access, ignores perms).
    pub fn bytes_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8], MemoryError> {
        let ptr = self
            .resolve(addr, len, Perms::NONE)
            .ok_or(MemoryError::OutOfBounds { addr, size: len })?;
        // SAFETY: as `bytes`; `&mut self` guarantees exclusive access.
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), len) })
    }

    /// Copy `data` to guest address `addr` (host access).
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        self.bytes_mut(addr, data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Copy `len` bytes from guest address `src` to `dst`, which may be in different
    /// regions or overlap (host access).
    pub fn copy(&mut self, src: u64, dst: u64, len: usize) -> Result<(), MemoryError> {
        let src = self.resolve(src, len, Perms::NONE).ok_or(MemoryError::OutOfBounds { addr: src, size: len })?;
        let dst = self.resolve(dst, len, Perms::NONE).ok_or(MemoryError::OutOfBounds { addr: dst, size: len })?;
        // SAFETY: both ranges are inside live regions; `copy` allows overlap.
        unsafe { std::ptr::copy(src.as_ptr(), dst.as_ptr(), len) };
        Ok(())
    }

    /// Read a little-endian scalar at guest address `addr` (host access).
    pub fn read<T: Scalar>(&self, addr: u64) -> Result<T, MemoryError> {
        Ok(T::read_le(self.bytes(addr, T::SIZE)?))
    }

    /// Write a little-endian scalar at guest address `addr` (host access).
    pub fn write<T: Scalar>(&mut self, addr: u64, value: T) -> Result<(), MemoryError> {
        value.write_le(self.bytes_mut(addr, T::SIZE)?);
        Ok(())
    }
}

impl Drop for VmMemory {
    fn drop(&mut self) {
        for region in self.regions {
            Self::free(region);
        }
    }
}

/// Guest access: the error is the faulting address.
macro_rules! guest_access {
    ($load:ident, $store:ident, $ty:ty) => {
        #[inline(always)]
        fn $load(&self, addr: u64) -> Result<$ty, u64> {
            let ptr = self.resolve(addr, size_of::<$ty>(), Perms::R).ok_or(addr)?;
            // SAFETY: `resolve` checked bounds; guest memory has no alignment guarantee.
            Ok(<$ty>::from_le(unsafe { ptr.cast::<$ty>().read_unaligned() }))
        }

        #[inline(always)]
        fn $store(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            let ptr = self.resolve(addr, size_of::<$ty>(), Perms::W).ok_or(addr)?;
            // SAFETY: as above.
            unsafe { ptr.cast::<$ty>().write_unaligned(value.to_le()) };
            Ok(())
        }
    };
}

/// Guest atomic: a real host atomic, so regions shared with other threads stay
/// coherent. Misaligned addresses fault, as the BPF verifier would reject them.
macro_rules! guest_atomic {
    ($name:ident, $ty:ty, $atomic:ident) => {
        #[inline(always)]
        fn $name(&mut self, addr: u64, op: AtomicOp<$ty>) -> Result<$ty, u64> {
            let ptr = self.resolve(addr, size_of::<$ty>(), Perms::RW).ok_or(addr)?;
            if !ptr.cast::<$ty>().is_aligned() {
                return Err(addr);
            }
            // SAFETY: in bounds and aligned; other threads only reach this memory through
            // atomics or under the `map_host` contract.
            let cell = unsafe { $atomic::from_ptr(ptr.as_ptr().cast()) };
            Ok(match op {
                AtomicOp::Add(v) => cell.fetch_add(v, SeqCst),
                AtomicOp::Or(v) => cell.fetch_or(v, SeqCst),
                AtomicOp::And(v) => cell.fetch_and(v, SeqCst),
                AtomicOp::Xor(v) => cell.fetch_xor(v, SeqCst),
                AtomicOp::Xchg(v) => cell.swap(v, SeqCst),
                AtomicOp::CmpXchg { expected, new } => cell
                    .compare_exchange(expected, new, SeqCst, SeqCst)
                    .unwrap_or_else(|old| old),
            })
        }
    };
}

impl Memory for VmMemory {
    type Err = u64;

    guest_access!(load_u8, store_u8, u8);
    guest_access!(load_u16, store_u16, u16);
    guest_access!(load_u32, store_u32, u32);
    guest_access!(load_u64, store_u64, u64);

    guest_atomic!(atomic_u32, u32, AtomicU32);
    guest_atomic!(atomic_u64, u64, AtomicU64);
}

/// Fixed-size little-endian scalar for host-side [`VmMemory::read`]/[`VmMemory::write`].
pub trait Scalar: Copy {
    /// Size in bytes.
    const SIZE: usize;
    /// Decode from exactly `SIZE` bytes.
    fn read_le(bytes: &[u8]) -> Self;
    /// Encode into exactly `SIZE` bytes.
    fn write_le(self, bytes: &mut [u8]);
}

macro_rules! scalar {
    ($($ty:ty),*) => {$(
        impl Scalar for $ty {
            const SIZE: usize = size_of::<$ty>();
            fn read_le(bytes: &[u8]) -> Self {
                <$ty>::from_le_bytes(bytes.try_into().unwrap())
            }
            fn write_le(self, bytes: &mut [u8]) {
                bytes.copy_from_slice(&self.to_le_bytes());
            }
        }
    )*};
}

scalar!(u8, u16, u32, u64, i8, i16, i32, i64);

impl std::fmt::Debug for VmMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mapped = self
            .regions
            .iter()
            .enumerate()
            .filter(|(_, r)| r.len != 0 || r.perms != Perms::NONE)
            .map(|(i, r)| (i, r.len, r.perms));
        f.debug_list().entries(mapped).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_region_and_bounds_fault() {
        let mut mem = VmMemory::new();
        let base = mem.map(1, 16, Perms::RW);
        assert_eq!(mem.load_u8(0), Err(0));
        assert_eq!(mem.load_u8(7), Err(7));
        assert!(mem.load_u64(base + 8).is_ok());
        assert_eq!(mem.load_u64(base + 9), Err(base + 9)); // straddles the end
        assert_eq!(mem.load_u8(region_base(MAX_REGIONS)), Err(region_base(MAX_REGIONS)));
        assert_eq!(mem.load_u8(u64::MAX), Err(u64::MAX));
    }

    #[test]
    fn perms_apply_to_guest_not_host() {
        let mut mem = VmMemory::new();
        let ro = mem.map_bytes(2, &[1, 2, 3, 4], 8, Perms::R);
        assert_eq!(mem.load_u32(ro), Ok(0x0403_0201));
        assert_eq!(mem.store_u8(ro, 9), Err(ro));
        mem.write(ro, 9u8).unwrap(); // host may still patch read-only regions
        assert_eq!(mem.load_u8(ro), Ok(9));

        let wo = mem.map(3, 8, Perms::W);
        assert!(mem.store_u64(wo, 1).is_ok());
        assert_eq!(mem.load_u64(wo), Err(wo));
    }

    #[test]
    fn unaligned_little_endian_access() {
        let mut mem = VmMemory::new();
        let base = mem.map(1, 16, Perms::RW);
        mem.store_u64(base + 3, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(mem.bytes(base + 3, 2).unwrap(), &[0x88, 0x77]);
        assert_eq!(mem.load_u16(base + 4), Ok(0x6677));
    }

    #[test]
    fn host_region_aliases_host_buffer() {
        let mut buf = [0u8; 8];
        let mut mem = VmMemory::new();
        // SAFETY: `buf` outlives `mem` and isn't touched while mapped.
        let base = unsafe { mem.map_host(4, NonNull::from(&mut buf).cast(), buf.len(), Perms::RW) };
        mem.store_u32(base + 4, 0xAABB_CCDD).unwrap();
        mem.unmap(4);
        assert_eq!(mem.load_u8(base), Err(base));
        drop(mem);
        assert_eq!(buf, [0, 0, 0, 0, 0xDD, 0xCC, 0xBB, 0xAA]);
    }
}
