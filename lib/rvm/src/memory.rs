//! Guest memory for the eBPF VM.
//!
//! Guest addresses are split into a region index (bits 32..) and an offset (bits 0..32):
//! `addr = (region << 32) | offset`. Each of the [`MAX_REGIONS`] slots maps a byte range with its own permissions.
//! Region 0 is never mapped, so null pointers (and small offsets from them) fault.
//!
//! A guest load or store costs one table index and one bounds check: each region keeps a readable and a writable
//! length, which is 0 when its permissions deny that access. Host-side accessors ([`VmMemory::read`],
//! [`VmMemory::bytes_mut`], ...) are trusted and ignore permissions.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release, SeqCst};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8};
use std::sync::Arc;

use rvm_core::{AtomicOp, Memory, Window};

use crate::error::{MemoryError, VmError};
use crate::layout::{BORROW_FIRST_REGION, FIRST_FREE_REGION};

/// Number of region slots in a [`VmMemory`].
pub const MAX_REGIONS: usize = 64;

/// Bit position of the region index in a guest address.
pub const REGION_SHIFT: u32 = 32;

// address splits take the offset as `addr as u32`
const _: () = assert!(REGION_SHIFT == 32);

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

// The owned-region bitmask has one bit per slot.
const _: () = assert!(MAX_REGIONS <= 64);

/// Region-mapped guest memory.
///
/// # Example
///
/// ```
/// use rvm::{region_base, Perms, VmMemory, FIRST_FREE_REGION, STACK_REGION};
///
/// let mut mem = VmMemory::new();
/// let base = mem.map(FIRST_FREE_REGION, 4096, Perms::RW).unwrap();
/// assert_eq!(base, region_base(FIRST_FREE_REGION));
/// mem.write(base + 8, 42u64).unwrap();
/// assert_eq!(mem.read::<u64>(base + 8).unwrap(), 42);
/// assert!(mem.read::<u8>(0).is_err()); // region 0 is never mapped
/// assert!(mem.map(STACK_REGION, 4096, Perms::RW).is_err()); // reserved for the program's stack
/// ```
pub struct VmMemory {
    // Guest loads and stores read only `ptrs` and the end arrays. Invariant: each end is its region's length or 0, so
    // it never exceeds the region's allocation.
    ptrs: [NonNull<u8>; MAX_REGIONS],
    read_end: [usize; MAX_REGIONS],
    write_end: [usize; MAX_REGIONS],

    lens: [usize; MAX_REGIONS],
    perms: [Perms; MAX_REGIONS],
    // bit `idx` set: region `idx` was allocated by `map` and is freed on unmap/drop
    owned: u64,
    // buffer behind each region mapped with `map_shared`, kept alive while mapped
    shared: [Option<Arc<SharedBuffer>>; MAX_REGIONS],
    // changes with every mapping, to a value no memory had before; see `Memory`
    epoch: u64,
}

/// The last epoch any `VmMemory` took.
static EPOCH: AtomicU64 = AtomicU64::new(0);

// SAFETY: owned regions are plain heap allocations exclusively owned by this value. Host regions are only created
// through `map_host`, whose contract requires the memory to be usable from whichever thread uses this `VmMemory`.
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
            ptrs: [NonNull::dangling(); MAX_REGIONS],
            read_end: [0; MAX_REGIONS],
            write_end: [0; MAX_REGIONS],
            lens: [0; MAX_REGIONS],
            perms: [Perms::NONE; MAX_REGIONS],
            owned: 0,
            shared: [const { None }; MAX_REGIONS],
            epoch: 0,
        }
    }

    /// Map `len` zeroed bytes as region `idx`, replacing any previous mapping. Returns the region's guest base address.
    ///
    /// Fails with [`VmError::InvalidArgument`] unless `idx` is one of the regions the layout leaves to the host,
    /// [`FIRST_FREE_REGION`]`..`[`BORROW_FIRST_REGION`], and `len` is at most [`MAX_REGION_LEN`].
    pub fn map(&mut self, idx: usize, len: usize, perms: Perms) -> crate::Result<u64> {
        check_host_region(idx, len)?;
        Ok(self.map_any(idx, len, perms))
    }

    /// Map region `idx` with `len` bytes, initialized from `init` (rest zeroed). Fails as [`map`](Self::map) does, and
    /// if `init` is longer than `len`.
    pub fn map_bytes(&mut self, idx: usize, init: &[u8], len: usize, perms: Perms) -> crate::Result<u64> {
        check_host_region(idx, len)?;
        if init.len() > len {
            let msg = format!("{} initial bytes in a {len} byte region", init.len());
            return Err(VmError::InvalidArgument(msg));
        }
        Ok(self.map_bytes_any(idx, init, len, perms))
    }

    /// Expose host memory as region `idx`. Guest accesses go straight to `ptr`. Fails as [`map`](Self::map) does.
    ///
    /// # Safety
    ///
    /// `ptr..ptr+len` must stay valid (and writable if `perms` allows writes) until the region is unmapped or this
    /// `VmMemory` is dropped, must not be accessed through other references in ways that conflict with guest/helper
    /// accesses while the VM runs, and must be usable from any thread that uses this memory.
    pub unsafe fn map_host(&mut self, idx: usize, ptr: NonNull<u8>, len: usize, perms: Perms) -> crate::Result<u64> {
        check_host_region(idx, len)?;
        // SAFETY: the caller's contract.
        Ok(unsafe { self.map_host_any(idx, ptr, len, perms) })
    }

    /// Unmap region `idx`, freeing it if it was allocated by [`map`](Self::map). Fails as [`map`](Self::map) does.
    pub fn unmap(&mut self, idx: usize) -> crate::Result<()> {
        check_host_region(idx, 0)?;
        self.unmap_any(idx);
        Ok(())
    }

    /// [`map`](Self::map) for any region index, the ones the layout reserves included.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is 0 or out of range, or `len` exceeds [`MAX_REGION_LEN`].
    pub(crate) fn map_any(&mut self, idx: usize, len: usize, perms: Perms) -> u64 {
        assert!(len <= MAX_REGION_LEN, "region too large: {len}");
        let ptr = if len == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: non-zero size, align 8.
            let raw = unsafe { alloc_zeroed(Self::layout(len)) };
            NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(Self::layout(len)))
        };
        self.set(idx, ptr, len, perms, true)
    }

    /// [`map_bytes`](Self::map_bytes) for any region index; panics as [`map_any`](Self::map_any) does, and if `init` is
    /// longer than `len`.
    pub(crate) fn map_bytes_any(&mut self, idx: usize, init: &[u8], len: usize, perms: Perms) -> u64 {
        assert!(init.len() <= len, "init ({}) larger than region ({len})", init.len());
        let base = self.map_any(idx, len, perms);
        self.write_bytes(base, init).expect("freshly mapped region");
        base
    }

    /// [`map_host`](Self::map_host) for any region index; panics as [`map_any`](Self::map_any) does.
    ///
    /// # Safety
    ///
    /// As [`map_host`](Self::map_host).
    pub(crate) unsafe fn map_host_any(&mut self, idx: usize, ptr: NonNull<u8>, len: usize, perms: Perms) -> u64 {
        assert!(len <= MAX_REGION_LEN, "region too large: {len}");
        self.set(idx, ptr, len, perms, false)
    }

    /// Map `buffer` as region `idx`. This memory keeps the buffer alive while it is mapped, so other memories can map
    /// the same buffer and see the same bytes.
    ///
    /// # Safety
    ///
    /// As [`Vm::share_region`](crate::Vm::share_region).
    pub(crate) unsafe fn map_shared(&mut self, idx: usize, buffer: Arc<SharedBuffer>, perms: Perms) -> u64 {
        // SAFETY: `self.shared[idx]` keeps the buffer alive until the region is replaced.
        let base = unsafe { self.map_host_any(idx, buffer.as_ptr(), buffer.len(), perms) };
        self.shared[idx] = Some(buffer);
        base
    }

    /// [`unmap`](Self::unmap) for any region index.
    pub(crate) fn unmap_any(&mut self, idx: usize) {
        self.set(idx, NonNull::dangling(), 0, Perms::NONE, false);
    }

    /// Length of region `idx` (0 if unmapped).
    pub fn region_len(&self, idx: usize) -> usize {
        self.lens.get(idx).copied().unwrap_or(0)
    }

    fn set(&mut self, idx: usize, ptr: NonNull<u8>, len: usize, perms: Perms, owned: bool) -> u64 {
        assert!(idx != 0 && idx < MAX_REGIONS, "invalid region index {idx}");
        self.free(idx);

        self.ptrs[idx] = ptr;
        self.read_end[idx] = if perms.allows(Perms::R) { len } else { 0 };
        self.write_end[idx] = if perms.allows(Perms::W) { len } else { 0 };
        self.lens[idx] = len;
        self.perms[idx] = perms;
        if owned {
            self.owned |= 1 << idx;
        } else {
            self.owned &= !(1 << idx);
        }
        self.shared[idx] = None;
        self.epoch = EPOCH.fetch_add(1, Relaxed) + 1;
        region_base(idx)
    }

    fn free(&self, idx: usize) {
        let len = self.lens[idx];
        if self.owned & (1 << idx) != 0 && len != 0 {
            // SAFETY: allocated in `map` with this exact layout and not freed since.
            unsafe { dealloc(self.ptrs[idx].as_ptr(), Self::layout(len)) };
        }
    }

    fn layout(len: usize) -> Layout {
        Layout::from_size_align(len, 8).expect("region layout")
    }

    /// Resolve `addr..addr+len` to a host pointer if region perms include `need`.
    #[inline(always)]
    fn resolve(&self, addr: u64, len: usize, need: Perms) -> Option<NonNull<u8>> {
        let idx = (addr >> REGION_SHIFT) as usize;
        let region_len = *self.lens.get(idx)?;
        let off = addr as u32 as usize;
        (self.perms[idx].allows(need) && len <= region_len && off <= region_len - len)
            // SAFETY: in bounds of the region's allocation.
            .then(|| unsafe { self.ptrs[idx].add(off) })
    }

    /// Resolve a guest access of `size` bytes, 1 to 8, against `ends`, which is `read_end` or `write_end`.
    #[inline(always)]
    fn guest_ptr(&self, addr: u64, size: usize, ends: &[usize; MAX_REGIONS]) -> Option<NonNull<u8>> {
        let idx = (addr >> REGION_SHIFT) as usize;
        let end = *ends.get(idx)?;
        let off = addr as u32 as usize;
        // `off` is below 2^32, so the sum can't overflow
        (off + size <= end)
            // SAFETY: `end` never exceeds the region's length, so the access lies inside its allocation.
            .then(|| unsafe { self.ptrs[idx].add(off) })
    }

    /// Host pointer to `len` bytes at guest address `addr` whose region allows `need`. No reference is created, so the
    /// bytes may be shared or aliased.
    pub fn host_ptr(&self, addr: u64, len: usize, need: Perms) -> Result<NonNull<u8>, MemoryError> {
        self.resolve(addr, len, need).ok_or(MemoryError { addr, size: len })
    }

    /// Borrow `len` bytes at guest address `addr` (host access, ignores perms). Fails on a region shared with other
    /// programs, which may change its bytes during the borrow; [`read_bytes`](Self::read_bytes) copies them instead.
    pub fn bytes(&self, addr: u64, len: usize) -> Result<&[u8], MemoryError> {
        self.check_unshared(addr, len)?;
        self.slice(addr, len, Perms::NONE)
    }

    /// Borrow `len` bytes at guest address `addr` whose region allows `need`.
    pub(crate) fn slice(&self, addr: u64, len: usize, need: Perms) -> Result<&[u8], MemoryError> {
        let ptr = self.host_ptr(addr, len, need)?;
        // SAFETY: `host_ptr` checked the range lies inside a live region, which the borrow of `self` keeps mapped.
        Ok(unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) })
    }

    /// Mutably borrow `len` bytes at guest address `addr` (host access, ignores perms). Fails on a shared region, as
    /// [`bytes`](Self::bytes) does.
    pub fn bytes_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8], MemoryError> {
        self.check_unshared(addr, len)?;
        let ptr = self.host_ptr(addr, len, Perms::NONE)?;
        // SAFETY: as `slice`; `&mut self` guarantees exclusive access.
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), len) })
    }

    /// Fail unless `addr..addr+len` lies outside the regions mapped with `map_shared`.
    fn check_unshared(&self, addr: u64, len: usize) -> Result<(), MemoryError> {
        match self.shared.get((addr >> REGION_SHIFT) as usize) {
            Some(Some(_)) => Err(MemoryError { addr, size: len }),
            _ => Ok(()),
        }
    }

    /// Copy `buf.len()` bytes from guest address `addr` into `buf` (host access).
    pub fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
        let src = self.host_ptr(addr, buf.len(), Perms::NONE)?;
        // SAFETY: `host_ptr` checked the range; `ptr::copy` allows `buf` to alias a host-mapped region.
        unsafe { std::ptr::copy(src.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    /// Copy `data` to guest address `addr` (host access).
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        let dst = self.host_ptr(addr, data.len(), Perms::NONE)?;
        // SAFETY: as `read_bytes`.
        unsafe { std::ptr::copy(data.as_ptr(), dst.as_ptr(), data.len()) };
        Ok(())
    }

    /// Zero `len` bytes at guest address `addr` (host access).
    #[cfg(feature = "maps")]
    pub(crate) fn zero(&mut self, addr: u64, len: usize) -> Result<(), MemoryError> {
        let dst = self.host_ptr(addr, len, Perms::NONE)?;
        // SAFETY: `host_ptr` checked the range.
        unsafe { dst.write_bytes(0, len) };
        Ok(())
    }

    /// Copy `len` bytes from guest address `src` to `dst`, which may be in different regions or overlap (host access).
    pub fn copy(&mut self, src: u64, dst: u64, len: usize) -> Result<(), MemoryError> {
        let src = self.host_ptr(src, len, Perms::NONE)?;
        let dst = self.host_ptr(dst, len, Perms::NONE)?;
        // SAFETY: both ranges are inside live regions; `copy` allows overlap.
        unsafe { std::ptr::copy(src.as_ptr(), dst.as_ptr(), len) };
        Ok(())
    }

    /// Read a little-endian scalar at guest address `addr` (host access).
    pub fn read<T: Scalar>(&self, addr: u64) -> Result<T, MemoryError> {
        let mut bytes = [0; 8];
        let bytes = &mut bytes[..T::SIZE];
        self.read_bytes(addr, bytes)?;
        Ok(T::read_le(bytes))
    }

    /// Copy the `V` at guest address `addr` out (host access).
    #[cfg(feature = "maps")]
    pub(crate) fn read_pod<V: Pod>(&self, addr: u64) -> Result<V, MemoryError> {
        let src = self.host_ptr(addr, size_of::<V>(), Perms::NONE)?;
        // SAFETY: `host_ptr` checked the range, and `Pod` types accept every bit pattern.
        Ok(unsafe { src.cast::<V>().read_unaligned() })
    }

    /// Write a little-endian scalar at guest address `addr` (host access).
    pub fn write<T: Scalar>(&mut self, addr: u64, value: T) -> Result<(), MemoryError> {
        let mut bytes = [0; 8];
        let bytes = &mut bytes[..T::SIZE];
        value.write_le(bytes);
        self.write_bytes(addr, bytes)
    }
}

/// Fail unless region `idx` is one the layout leaves to the host and `len` fits in a region.
fn check_host_region(idx: usize, len: usize) -> crate::Result<()> {
    if !(FIRST_FREE_REGION..BORROW_FIRST_REGION).contains(&idx) {
        let msg = format!("region {idx} is reserved; the host may map {FIRST_FREE_REGION}..{BORROW_FIRST_REGION}");
        return Err(VmError::InvalidArgument(msg));
    }
    if len > MAX_REGION_LEN {
        return Err(VmError::InvalidArgument(format!("region length {len} exceeds {MAX_REGION_LEN}")));
    }
    Ok(())
}

impl Drop for VmMemory {
    fn drop(&mut self) {
        for idx in 0..MAX_REGIONS {
            self.free(idx);
        }
    }
}

/// The calling program's memory as a host function registered with [`crate::Vm::register_fn_with_memory`] sees it.
///
/// Every access needs the guest's permissions on the region, so a pointer passed to a host function reaches no more
/// than the guest's own loads and stores would. Accesses copy, so no reference into guest memory outlives the call that
/// made it.
pub struct GuestMemory<'a> {
    memory: &'a mut VmMemory,
}

impl<'a> GuestMemory<'a> {
    /// The guest's view of `memory`.
    pub(crate) fn new(memory: &'a mut VmMemory) -> Self {
        Self { memory }
    }

    /// Copy `buf.len()` bytes from guest address `addr` into `buf`.
    pub fn read_bytes(&self, addr: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
        let src = self.memory.host_ptr(addr, buf.len(), Perms::R)?;
        // SAFETY: `host_ptr` checked that the range lies inside a live region. `buf` can't overlap it: this view
        // borrows the memory mutably, and the `map_host` and `Vm::share_region` contracts forbid references into those
        // regions while guest code runs.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    /// Copy `len` bytes from guest address `addr` into a new vector. The range is checked before anything is allocated,
    /// so a guest-supplied length is safe.
    pub fn read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let src = self.memory.host_ptr(addr, len, Perms::R)?;
        let mut bytes = Vec::with_capacity(len);
        // SAFETY: as `read_bytes`; the copy initializes all `len` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(src.as_ptr(), bytes.as_mut_ptr(), len);
            bytes.set_len(len);
        }
        Ok(bytes)
    }

    /// Copy `data` to guest address `addr`.
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), MemoryError> {
        let dst = self.memory.host_ptr(addr, data.len(), Perms::W)?;
        // SAFETY: as `read_bytes`.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst.as_ptr(), data.len()) };
        Ok(())
    }

    /// Read a little-endian scalar at guest address `addr`.
    pub fn read<T: Scalar>(&self, addr: u64) -> Result<T, MemoryError> {
        let mut bytes = [0; 8];
        let bytes = &mut bytes[..T::SIZE];
        self.read_bytes(addr, bytes)?;
        Ok(T::read_le(bytes))
    }

    /// Write a little-endian scalar at guest address `addr`.
    pub fn write<T: Scalar>(&mut self, addr: u64, value: T) -> Result<(), MemoryError> {
        let mut bytes = [0; 8];
        let bytes = &mut bytes[..T::SIZE];
        value.write_le(bytes);
        self.write_bytes(addr, bytes)
    }
}

/// Zeroed, cache-line aligned host memory that several programs map at once.
#[derive(Debug)]
pub(crate) struct SharedBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: plain heap memory owned by this value; access from guests follows the `Vm::share_region` contract.
unsafe impl Send for SharedBuffer {}
unsafe impl Sync for SharedBuffer {}

impl SharedBuffer {
    /// Allocate `len` zeroed bytes.
    ///
    /// # Panics
    ///
    /// Panics if `len` is 0.
    pub fn new(len: usize) -> Self {
        assert!(len != 0, "empty shared buffer");
        let layout = Self::layout(len);
        // SAFETY: non-zero size.
        let raw = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(layout));
        Self { ptr, len }
    }

    /// Start of the buffer, valid until the buffer is dropped.
    pub fn as_ptr(&self) -> NonNull<u8> {
        self.ptr
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    fn layout(len: usize) -> Layout {
        Layout::from_size_align(len, 64).expect("shared buffer layout")
    }
}

impl Drop for SharedBuffer {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with this layout.
        unsafe { dealloc(self.ptr.as_ptr(), Self::layout(self.len)) };
    }
}

/// Apply `op` to the atomic `cell` and return the old value.
macro_rules! fetch_op {
    ($cell:expr, $op:expr) => {
        match $op {
            AtomicOp::Add(v) => $cell.fetch_add(v, SeqCst),
            AtomicOp::Or(v) => $cell.fetch_or(v, SeqCst),
            AtomicOp::And(v) => $cell.fetch_and(v, SeqCst),
            AtomicOp::Xor(v) => $cell.fetch_xor(v, SeqCst),
            AtomicOp::Xchg(v) => $cell.swap(v, SeqCst),
            AtomicOp::CmpXchg { expected, new } => $cell
                .compare_exchange(expected, new, SeqCst, SeqCst)
                .unwrap_or_else(|old| old),
        }
    };
}

/// Host atomic on a shared region, coherent with guest atomics on other threads. Misaligned offsets fail, as they do
/// for guests.
macro_rules! region_atomic {
    ($name:ident, $ty:ty, $atomic:ident) => {
        /// Apply `op` atomically to the value at `offset` and return the old value.
        pub fn $name(&mut self, offset: usize, op: AtomicOp<$ty>) -> Result<$ty, MemoryError> {
            let ptr = self.ptr(offset, size_of::<$ty>())?;
            if !ptr.cast::<$ty>().is_aligned() {
                return Err(MemoryError {
                    addr: self.base() + offset as u64,
                    size: size_of::<$ty>(),
                });
            }
            // SAFETY: in bounds and aligned; other threads reach this memory through guest atomics or under the
            // `Vm::share_region` contract.
            let cell = unsafe { $atomic::from_ptr(ptr.as_ptr().cast()) };
            Ok(fetch_op!(cell, op))
        }
    };
}

/// A buffer mapped at one region index into every program a VM links.
///
/// The host reads and writes the buffer through this handle, at offsets from the region's start and regardless of the
/// guest permissions. Accessors copy and never hand out references, so a host function may use them while guest code
/// that maps the buffer is running on the same thread. Writes and atomics take `&mut self`, so host accesses through
/// this handle never race each other.
///
/// Guest code on other threads may access the buffer at the same time, under the
/// [`Vm::share_region`](crate::Vm::share_region) contract the host accepted when it shared the region: copies count as
/// plain loads and stores there, so bytes that guests on other threads write concurrently may only be touched with
/// [`atomic_u32`](Self::atomic_u32) and [`atomic_u64`](Self::atomic_u64), which are real atomics. `AtomicOp::Or(0)`
/// reads such a value.
#[derive(Debug)]
pub struct SharedRegion {
    region: usize,
    perms: Perms,
    buffer: Arc<SharedBuffer>,
}

impl SharedRegion {
    /// # Safety
    ///
    /// While this handle is in use on one thread, no other `SharedRegion` over `buffer` may be used on another.
    pub(crate) unsafe fn new(region: usize, perms: Perms, buffer: Arc<SharedBuffer>) -> Self {
        Self { region, perms, buffer }
    }

    /// Region index, the same in every program.
    pub fn region(&self) -> usize {
        self.region
    }

    /// Guest address of the first byte.
    pub fn base(&self) -> u64 {
        region_base(self.region)
    }

    /// Guest permissions.
    pub fn perms(&self) -> Perms {
        self.perms
    }

    /// The host memory behind the region.
    pub(crate) fn buffer(&self) -> &Arc<SharedBuffer> {
        &self.buffer
    }

    /// Copy `buf.len()` bytes at `offset` into `buf`.
    pub fn read_bytes(&self, offset: usize, buf: &mut [u8]) -> Result<(), MemoryError> {
        let src = self.ptr(offset, buf.len())?;
        // SAFETY: `ptr` checked the range. `buf` can't overlap it: references into the buffer only come from
        // `MapRef::entries` over a shared map, and the `Vm::share_region` contract keeps this handle off the buffer
        // while one is alive.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    /// Copy `data` to `offset`.
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) -> Result<(), MemoryError> {
        let dst = self.ptr(offset, data.len())?;
        // SAFETY: as `read_bytes`.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), dst.as_ptr(), data.len()) };
        Ok(())
    }

    /// Read a little-endian scalar at `offset`.
    pub fn read<T: Scalar>(&self, offset: usize) -> Result<T, MemoryError> {
        let mut bytes = [0; 8];
        let bytes = &mut bytes[..T::SIZE];
        self.read_bytes(offset, bytes)?;
        Ok(T::read_le(bytes))
    }

    /// Write a little-endian scalar at `offset`.
    pub fn write<T: Scalar>(&mut self, offset: usize, value: T) -> Result<(), MemoryError> {
        let mut bytes = [0; 8];
        let bytes = &mut bytes[..T::SIZE];
        value.write_le(bytes);
        self.write_bytes(offset, bytes)
    }

    region_atomic!(atomic_u32, u32, AtomicU32);
    region_atomic!(atomic_u64, u64, AtomicU64);

    /// Host pointer to `len` bytes at `offset`.
    fn ptr(&self, offset: usize, len: usize) -> Result<NonNull<u8>, MemoryError> {
        match offset.checked_add(len) {
            // SAFETY: in bounds of the buffer.
            Some(end) if end <= self.buffer.len() => Ok(unsafe { self.buffer.as_ptr().add(offset) }),
            _ => Err(MemoryError {
                addr: self.base().wrapping_add(offset as u64),
                size: len,
            }),
        }
    }
}

/// Guest access: the error is the faulting address.
macro_rules! guest_access {
    ($load:ident, $store:ident, $ty:ty) => {
        #[inline(always)]
        fn $load(&self, addr: u64) -> Result<$ty, u64> {
            let ptr = self
                .guest_ptr(addr, size_of::<$ty>(), &self.read_end)
                .ok_or(addr)?;
            // SAFETY: `guest_ptr` checked bounds; guest memory has no alignment guarantee.
            Ok(<$ty>::from_le(unsafe { ptr.cast::<$ty>().read_unaligned() }))
        }

        #[inline(always)]
        fn $store(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            let ptr = self
                .guest_ptr(addr, size_of::<$ty>(), &self.write_end)
                .ok_or(addr)?;
            // SAFETY: as above.
            unsafe { ptr.cast::<$ty>().write_unaligned(value.to_le()) };
            Ok(())
        }
    };
}

/// Guest atomic: a real host atomic, so regions shared with other threads stay coherent. Misaligned addresses fault, as
/// the BPF verifier would reject them.
macro_rules! guest_atomic {
    ($name:ident, $ty:ty, $atomic:ident) => {
        #[inline(always)]
        fn $name(&mut self, addr: u64, op: AtomicOp<$ty>) -> Result<$ty, u64> {
            let ptr = self.resolve(addr, size_of::<$ty>(), Perms::RW).ok_or(addr)?;
            if !ptr.cast::<$ty>().is_aligned() {
                return Err(addr);
            }
            // SAFETY: in bounds and aligned; other threads only reach this memory through atomics or under the
            // `map_host` contract.
            let cell = unsafe { $atomic::from_ptr(ptr.as_ptr().cast()) };
            Ok(fetch_op!(cell, op))
        }
    };
}

/// Guest load-acquire and store-release: real host atomics behind the same region and permission checks as plain
/// loads and stores. Misaligned addresses fault, as they do for the read-modify-write atomics.
macro_rules! guest_ordered {
    ($load:ident, $store:ident, $ty:ty, $atomic:ident) => {
        #[inline(always)]
        fn $load(&self, addr: u64) -> Result<$ty, u64> {
            let ptr = self
                .guest_ptr(addr, size_of::<$ty>(), &self.read_end)
                .ok_or(addr)?;
            if !ptr.cast::<$ty>().is_aligned() {
                return Err(addr);
            }
            // SAFETY: as `guest_atomic`.
            let cell = unsafe { $atomic::from_ptr(ptr.as_ptr().cast()) };
            Ok(<$ty>::from_le(cell.load(Acquire)))
        }

        #[inline(always)]
        fn $store(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            let ptr = self
                .guest_ptr(addr, size_of::<$ty>(), &self.write_end)
                .ok_or(addr)?;
            if !ptr.cast::<$ty>().is_aligned() {
                return Err(addr);
            }
            // SAFETY: as `guest_atomic`.
            let cell = unsafe { $atomic::from_ptr(ptr.as_ptr().cast()) };
            cell.store(value.to_le(), Release);
            Ok(())
        }
    };
}

// SAFETY: `set` moves to a new epoch whenever a mapping changes, and the `Memory` methods leave the epoch alone
unsafe impl Memory for VmMemory {
    type Err = u64;

    guest_access!(load_u8, store_u8, u8);
    guest_access!(load_u16, store_u16, u16);
    guest_access!(load_u32, store_u32, u32);
    guest_access!(load_u64, store_u64, u64);

    guest_atomic!(atomic_u32, u32, AtomicU32);
    guest_atomic!(atomic_u64, u64, AtomicU64);

    guest_ordered!(load_acquire_u8, store_release_u8, u8, AtomicU8);
    guest_ordered!(load_acquire_u16, store_release_u16, u16, AtomicU16);
    guest_ordered!(load_acquire_u32, store_release_u32, u32, AtomicU32);
    guest_ordered!(load_acquire_u64, store_release_u64, u64, AtomicU64);

    fn window(&self, addr: u64) -> Window {
        let idx = (addr >> REGION_SHIFT) as usize;
        if idx >= MAX_REGIONS {
            return Window::NONE;
        }
        let (read_len, write_len) = (self.read_end[idx] as u64, self.write_end[idx] as u64);
        // SAFETY: the region's allocation backs `read_end` and `write_end` bytes until the next `set`, which moves to a
        // new epoch, or drop; `guest_ptr` resolves guest accesses to the same bytes. Epoch 0 has nothing mapped. `ptrs`
        // holds raw pointers, not references into `self`.
        unsafe { Window::new(region_base(idx), self.ptrs[idx].as_ptr(), read_len, write_len, self.epoch) }
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Fixed-size little-endian scalar of at most 8 bytes, for host-side reads and writes.
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

/// Plain data: a type whose value is exactly its bytes, for reading and writing map keys and values as Rust types.
///
/// The bytes are copied as they are, in host byte order. Guests are little endian, so fields wider than a byte only
/// read back right on a little-endian host.
///
/// # Safety
///
/// The type must have no padding bytes, and every bit pattern must be a valid value: integers, floats, arrays of them,
/// and `#[repr(C)]` structs of such fields laid out without gaps.
pub unsafe trait Pod: Copy + 'static {
    /// The value's bytes.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `Pod` types have no padding, so all `size_of::<Self>()` bytes are initialized.
        unsafe { std::slice::from_raw_parts((self as *const Self).cast(), size_of::<Self>()) }
    }

    /// The value made of `bytes`, or `None` unless there are exactly `size_of::<Self>()` of them.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // SAFETY: the length matches and `Pod` types accept every bit pattern.
        (bytes.len() == size_of::<Self>()).then(|| unsafe { bytes.as_ptr().cast::<Self>().read_unaligned() })
    }
}

macro_rules! pod {
    ($($t:ty),*) => {
        // SAFETY: primitives without padding or invalid bit patterns.
        $(unsafe impl Pod for $t {})*
    };
}

pod!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64);

// SAFETY: arrays of `Pod` have no padding between elements.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

impl std::fmt::Debug for VmMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mapped = (0..MAX_REGIONS)
            .filter(|&i| self.lens[i] != 0 || self.perms[i] != Perms::NONE)
            .map(|i| (i, self.lens[i], self.perms[i]));
        f.debug_list().entries(mapped).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_region_and_bounds_fault() {
        let mut mem = VmMemory::new();
        let base = mem.map_any(1, 16, Perms::RW);
        assert_eq!(mem.load_u8(0), Err(0));
        assert_eq!(mem.load_u8(7), Err(7));
        assert!(mem.load_u64(base + 8).is_ok());
        assert_eq!(mem.load_u64(base + 9), Err(base + 9)); // straddles the end
        assert_eq!(mem.load_u8(region_base(MAX_REGIONS)), Err(region_base(MAX_REGIONS)));
        assert_eq!(mem.load_u8(u64::MAX), Err(u64::MAX));
        // guest-controlled lengths (helper and borrow arguments) must not wrap the check
        assert!(mem.bytes(base + 8, usize::MAX - 7).is_err());
        assert!(mem.host_ptr(base, usize::MAX, Perms::NONE).is_err());
    }

    #[test]
    fn perms_apply_to_guest_not_host() {
        let mut mem = VmMemory::new();
        let ro = mem.map_bytes_any(2, &[1, 2, 3, 4], 8, Perms::R);
        assert_eq!(mem.load_u32(ro), Ok(0x0403_0201));
        assert_eq!(mem.store_u8(ro, 9), Err(ro));
        mem.write(ro, 9u8).unwrap(); // host may still patch read-only regions
        assert_eq!(mem.load_u8(ro), Ok(9));

        let wo = mem.map_any(3, 8, Perms::W);
        assert!(mem.store_u64(wo, 1).is_ok());
        assert_eq!(mem.load_u64(wo), Err(wo));
    }

    #[test]
    fn unaligned_little_endian_access() {
        let mut mem = VmMemory::new();
        let base = mem.map_any(1, 16, Perms::RW);
        mem.store_u64(base + 3, 0x1122_3344_5566_7788).unwrap();
        assert_eq!(mem.bytes(base + 3, 2).unwrap(), &[0x88, 0x77]);
        assert_eq!(mem.load_u16(base + 4), Ok(0x6677));
    }

    #[test]
    fn host_region_aliases_host_buffer() {
        let mut buf = [0u8; 8];
        let mut mem = VmMemory::new();
        // SAFETY: `buf` outlives `mem` and isn't touched while mapped.
        let base = unsafe { mem.map_host_any(4, NonNull::from(&mut buf).cast(), buf.len(), Perms::RW) };
        mem.store_u32(base + 4, 0xAABB_CCDD).unwrap();
        mem.unmap_any(4);
        assert_eq!(mem.load_u8(base), Err(base));
        drop(mem);
        assert_eq!(buf, [0, 0, 0, 0, 0xDD, 0xCC, 0xBB, 0xAA]);
    }

    // host functions reach guest memory only as far as the guest itself could
    #[test]
    fn guest_memory_needs_guest_perms() {
        let mut mem = VmMemory::new();
        let rw = mem.map_any(1, 16, Perms::RW);
        let ro = mem.map_bytes_any(2, b"hi", 8, Perms::R);
        let wo = mem.map_any(3, 8, Perms::W);
        let mut guest = GuestMemory::new(&mut mem);
        let fault = |addr, size| MemoryError { addr, size };

        guest.write(rw + 8, 0x1122_3344_5566_7788u64).unwrap();
        assert_eq!(guest.read::<u16>(rw + 8), Ok(0x7788));
        assert_eq!(guest.read_vec(ro, 2).unwrap(), b"hi");

        assert_eq!(guest.read::<u8>(0).unwrap_err(), fault(0, 1));
        assert_eq!(guest.read::<u64>(rw + 9).unwrap_err(), fault(rw + 9, 8)); // straddles the end
        assert_eq!(guest.write(ro, 1u8).unwrap_err(), fault(ro, 1));
        assert_eq!(guest.read_bytes(wo, &mut [0; 4]).unwrap_err(), fault(wo, 4));
        // fails before allocating
        assert_eq!(guest.read_vec(rw, usize::MAX).unwrap_err(), fault(rw, usize::MAX));
    }

    #[test]
    fn shared_region_bounds_and_alignment() {
        // SAFETY: the only handle over the buffer.
        let mut region = unsafe { SharedRegion::new(5, Perms::R, Arc::new(SharedBuffer::new(16))) };
        let base = region.base();
        let fault = |offset: u64, size| MemoryError {
            addr: base.wrapping_add(offset),
            size,
        };

        // guest perms don't apply to the host
        region.write(12, 7u32).unwrap();
        assert_eq!(region.atomic_u32(12, AtomicOp::Add(1)), Ok(7));
        assert_eq!(region.read::<u32>(12), Ok(8));

        assert_eq!(region.read::<u64>(12).unwrap_err(), fault(12, 8));
        assert_eq!(region.write_bytes(usize::MAX, &[0; 2]).unwrap_err(), fault(u64::MAX, 2));
        assert_eq!(region.atomic_u64(4, AtomicOp::Or(0)).unwrap_err(), fault(4, 8));
    }

    type Table = [(NonNull<u8>, usize, Perms); MAX_REGIONS];

    const PERMS: [Perms; 4] = [Perms::NONE, Perms::R, Perms::W, Perms::RW];

    // regions 1..=MAPPED cover every tested length with every perms
    const MAPPED: usize = 6 * PERMS.len();

    // Guest loads and stores check per-region ends with the perms folded in. Every access path must agree with a plain
    // perms and bounds check on the region edges.
    #[test]
    fn access_checks_match_reference() {
        // a 2^32 byte region reaches the largest offset; Miri can't allocate that much
        let large = if cfg!(miri) { 64 } else { MAX_REGION_LEN };
        let mut buf = vec![0u8; large];
        let host = NonNull::new(buf.as_mut_ptr()).unwrap();
        let mut mem = VmMemory::new();
        let mut table: Table = [(NonNull::dangling(), 0, Perms::NONE); MAX_REGIONS];

        let lens: [usize; MAPPED / PERMS.len()] = [0, 1, 7, 8, 9, large];
        let regions = lens.into_iter().flat_map(|len| PERMS.map(|p| (len, p)));
        for (idx, (len, perms)) in (1..).zip(regions) {
            // SAFETY: `buf` outlives `mem` and is only accessed through it.
            unsafe { mem.map_host_any(idx, host, len, perms) };
            table[idx] = (host, len, perms);
        }
        check_regions(&mut mem, &table);

        // replace owned regions with host ones of other perms, or unmap them
        for (idx, region) in table.iter_mut().enumerate().skip(1).take(MAPPED) {
            mem.map_any(idx, 16, Perms::RW);
            if idx % 5 == 0 {
                mem.unmap_any(idx);
                *region = (NonNull::dangling(), 0, Perms::NONE);
            } else {
                let (ptr, len, perms) = *region;
                let perms = PERMS[(perms.0 as usize + 1) % 4];
                // SAFETY: as above.
                unsafe { mem.map_host_any(idx, ptr, len, perms) };
                region.2 = perms;
            }
        }
        check_regions(&mut mem, &table);
    }

    /// Sweep offsets around 0, the region end, 2^31 and 2^32 in every mapped region, an unmapped one and indices past
    /// the table.
    fn check_regions(mem: &mut VmMemory, table: &Table) {
        // Miri is too slow for the full sweep
        let span = if cfg!(miri) { 2 } else { 16 };
        let max_off = u32::MAX as usize;
        let indices = (0..=MAPPED + 1).chain([MAX_REGIONS, MAX_REGIONS + 1, 1 << 26, max_off]);
        for idx in indices {
            let len = table.get(idx).map_or(0, |r| r.1);
            let offsets = (0..=span)
                .chain(len.saturating_sub(span)..=len + span)
                .chain((1 << 31) - span..=(1 << 31) + span)
                .chain(max_off - span..=max_off);
            for off in offsets.filter(|&off| off <= max_off) {
                check_addr(mem, table, region_base(idx) | off as u64);
            }
        }
    }

    fn check_addr(mem: &mut VmMemory, table: &Table, addr: u64) {
        let expect = |len, need| reference(table, addr, len, need);
        let fault = |len, need| expect(len, need).map(drop).ok_or(addr);

        for size in [1, 2, 4, 8] {
            let load = mem.guest_ptr(addr, size, &mem.read_end);
            assert_eq!(load, expect(size, Perms::R), "load {size} at {addr:#x}");
            let store = mem.guest_ptr(addr, size, &mem.write_end);
            assert_eq!(store, expect(size, Perms::W), "store {size} at {addr:#x}");
        }
        assert_eq!(mem.load_u8(addr).map(drop), fault(1, Perms::R));
        assert_eq!(mem.load_u16(addr).map(drop), fault(2, Perms::R));
        assert_eq!(mem.load_u32(addr).map(drop), fault(4, Perms::R));
        assert_eq!(mem.load_u64(addr).map(drop), fault(8, Perms::R));
        assert_eq!(mem.store_u8(addr, 0), fault(1, Perms::W));
        assert_eq!(mem.store_u16(addr, 0), fault(2, Perms::W));
        assert_eq!(mem.store_u32(addr, 0), fault(4, Perms::W));
        assert_eq!(mem.store_u64(addr, 0), fault(8, Perms::W));

        let atomic = |size| expect(size, Perms::RW).filter(|p| p.as_ptr().addr() % size == 0);
        assert_eq!(mem.atomic_u32(addr, AtomicOp::Add(0)).map(drop), atomic(4).map(drop).ok_or(addr));
        assert_eq!(mem.atomic_u64(addr, AtomicOp::Add(0)).map(drop), atomic(8).map(drop).ok_or(addr));

        let host_lens = [0, 1, 2, 7, 8, 9, MAX_REGION_LEN - 1, MAX_REGION_LEN, MAX_REGION_LEN + 1];
        for len in host_lens.into_iter().chain([usize::MAX - 7, usize::MAX]) {
            for need in PERMS {
                let ptr = mem.host_ptr(addr, len, need).ok();
                assert_eq!(ptr, expect(len, need), "host_ptr {len} {need:?} at {addr:#x}");
            }
            let bytes = mem.bytes(addr, len).ok().map(|b| NonNull::from(b).cast());
            assert_eq!(bytes, expect(len, Perms::NONE), "bytes {len} at {addr:#x}");
        }
    }

    /// The perms test and overflow-safe bounds check the folded ends must agree with.
    fn reference(table: &Table, addr: u64, len: usize, need: Perms) -> Option<NonNull<u8>> {
        let &(ptr, region_len, perms) = table.get((addr >> REGION_SHIFT) as usize)?;
        let off = addr as u32 as usize;
        let ok = perms.0 & need.0 == need.0 && len <= region_len && off <= region_len - len;
        ok.then(|| NonNull::new(ptr.as_ptr().wrapping_add(off)).unwrap())
    }
}
