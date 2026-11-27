//! Guest memory for the eBPF VM.
//!
//! A guest address is the host address of the byte with the index of its region as a tag in the top 6 bits:
//!
//! ```text
//!  63    58 57      47 46                                     0
//! +--------+----------+----------------------------------------+
//! | region |    0     |        host address of the byte        |
//! +--------+----------+----------------------------------------+
//! ```
//!
//! Each of the [`MAX_REGIONS`] regions maps a range of host memory with its own permissions. A guest access strips
//! nothing and translates nothing: it subtracts the region's tagged start address, `tag | start`, and checks the
//! result against the region's length, so a guest that forges a tag reaches only the range of that tag's region. Each
//! region keeps that start and, for each access size, the number of offsets at which a load and a store of that size
//! fit, which are 0 when its permissions deny that access: one shift, one subtraction and one compare per access.
//! Host-side accessors ([`VmMemory::read`], [`VmMemory::bytes_mut`], ...) are trusted and ignore permissions.
//!
//! No user-mode pointer on x64 has a bit above 46 set, so the tags keep the regions apart from host addresses.
//! Region 0, the untagged addresses, is unmapped, so null pointers and integers the guest uses as pointers fault.
//! With [`Passthrough`] it maps the host's user-mode memory from [`RAW_START`] up to [`RAW_END`] instead, and in its
//! untagged mode every region's tag is 0, so guest pointers are plain host addresses and all of them go through
//! region 0. [`CODE_REGION`] is never mapped: its tag marks code addresses.
//!
//! An access reaches the host bytes through a pointer made from their address with
//! [`ptr::with_exposed_provenance_mut`]. Mapping a region exposes the provenance of its pointer, and a host exposes the
//! provenance of each pointer it hands a guest by casting it to an integer. Region 0 has no allocation of its own to
//! derive a pointer from, and every region shares the one way to reach its bytes.
//!
//! The linker and images use link addresses, `region_tag(idx) + offset`, and loading moves each to the guest
//! address of the same byte. Guest-owned regions therefore never move after loading.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ptr::{self, NonNull};
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release, SeqCst};
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8};
use std::sync::Arc;

use rvm_core::{AtomicOp, Memory, Window};

use crate::error::{MemoryError, VmError};
use crate::layout::{free_host_region, CODE_REGION};
use crate::vm::Passthrough;

/// Number of regions in a [`VmMemory`], region 0 included.
pub const MAX_REGIONS: usize = 64;

/// Bit position of the region tag in a guest address: the tag takes the bits above it.
pub const REGION_SHIFT: u32 = u64::BITS - MAX_REGIONS.trailing_zeros();

/// Largest region a program or host maps. Addresses don't limit it; it bounds what a guest can make the host
/// allocate.
pub const MAX_REGION_LEN: usize = 1 << 32;

/// The lowest host address a guest reaches with [`Passthrough`]. The 64 KiB below it fault, so a null pointer and
/// small offsets from it stay guest faults. Windows never maps them.
pub const RAW_START: u64 = 1 << 16;

/// The end of the host addresses a guest reaches with [`Passthrough`]: user-mode addresses on x64 lie below 2^47.
pub const RAW_END: u64 = 1 << 47;

/// The tag of region `idx`: the bits its guest addresses have above the host address, and the link address of its
/// first byte.
pub const fn region_tag(idx: usize) -> u64 {
    (idx as u64) << REGION_SHIFT
}

/// Region index and offset of the link address `addr`.
#[cfg(any(feature = "link", feature = "maps"))]
pub const fn split_addr(addr: u64) -> (usize, usize) {
    (region_of(addr), (addr & (region_tag(1) - 1)) as usize)
}

/// Region index of guest address `addr`, below [`MAX_REGIONS`] whatever `addr` is.
#[inline(always)]
const fn region_of(addr: u64) -> usize {
    (addr >> REGION_SHIFT) as usize
}

// the tag takes every bit above `REGION_SHIFT`, so it always indexes the tables
const _: () = assert!(MAX_REGIONS.is_power_of_two() && region_of(u64::MAX) == MAX_REGIONS - 1);
// host addresses fit below the tag
const _: () = assert!(RAW_END <= region_tag(1));

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

// The owned-region bitmask has one bit per region.
const _: () = assert!(MAX_REGIONS <= 64);

/// Region-mapped guest memory.
///
/// # Example
///
/// ```
/// use rvm::{Perms, VmMemory};
///
/// let mut mem = VmMemory::new();
/// let region = mem.map(4096, Perms::RW).unwrap();
/// mem.write(region.base() + 8, 42u64).unwrap();
/// assert_eq!(mem.read::<u64>(region.base() + 8).unwrap(), 42);
/// assert!(mem.read::<u8>(0).is_err()); // region 0 is never mapped
///
/// let base = region.base();
/// mem.unmap(region).unwrap();
/// assert!(mem.read::<u8>(base).is_err());
/// ```
pub struct VmMemory {
    // Guest loads and stores read only `bases`, `ptrs` and the fits tables. An access of `n` bytes at `addr` lies at
    // offset `at = addr - bases[idx]` into region `idx = region_of(addr)`, and fits if `at` is below the fits entry for
    // `n` bytes, which `place` sets. Invariant: those entries never let an access reach past `lens[idx]` bytes from
    // `ptrs[idx]`, and are 0 where the region's perms deny the access.
    bases: [u64; MAX_REGIONS],
    ptrs: [NonNull<u8>; MAX_REGIONS],
    // by `size_class`, then region
    read_fits: [[u64; MAX_REGIONS]; 4],
    write_fits: [[u64; MAX_REGIONS]; 4],

    lens: [usize; MAX_REGIONS],
    perms: [Perms; MAX_REGIONS],
    // bit `idx` set: region `idx` was allocated by `map` and is freed on unmap/drop
    owned: u64,
    // buffer behind each region mapped with `map_shared`, kept alive while mapped
    shared: [Option<Arc<SharedBuffer>>; MAX_REGIONS],
    // changes with every mapping, to a value no memory had before; see `Memory`
    epoch: u64,
    // bit `idx` set: host region `idx` is mapped by `map`, `map_bytes`, `map_host` or `map_shared`
    taken: u64,
    // tells this memory's `Region` handles from other memories'
    id: u64,
    // the tags of the regions, and whether region 0 maps raw host memory
    passthrough: Passthrough,
}

/// The last epoch any `VmMemory` took.
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// The last ID any `VmMemory` took.
static LAST_ID: AtomicU64 = AtomicU64::new(0);

// SAFETY: owned regions are plain heap allocations exclusively owned by this value. Host regions are only created
// through `map_host`, whose contract requires the memory to be usable from whichever thread uses this `VmMemory`, and
// raw host addresses only through `Passthrough`, whose contract puts every guest access there on the host.
unsafe impl Send for VmMemory {}
unsafe impl Sync for VmMemory {}

impl Default for VmMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl VmMemory {
    /// Create memory with no regions mapped.
    pub fn new() -> Self {
        Self::with_passthrough(Passthrough::OFF)
    }

    /// Create memory with no regions mapped but, if `passthrough` reaches host memory, region 0. Its untagged mode
    /// gives every region the tag 0.
    pub fn with_passthrough(passthrough: Passthrough) -> Self {
        let mut memory = Self {
            bases: std::array::from_fn(|idx| passthrough.address(idx, NonNull::dangling())),
            ptrs: [NonNull::dangling(); MAX_REGIONS],
            read_fits: [[0; MAX_REGIONS]; 4],
            write_fits: [[0; MAX_REGIONS]; 4],
            lens: [0; MAX_REGIONS],
            perms: [Perms::NONE; MAX_REGIONS],
            owned: 0,
            shared: [const { None }; MAX_REGIONS],
            epoch: 0,
            taken: 0,
            id: LAST_ID.fetch_add(1, Relaxed) + 1,
            passthrough,
        };
        if passthrough.is_on() {
            let start = NonNull::new(ptr::with_exposed_provenance_mut(RAW_START as usize)).expect("RAW_START is not 0");
            // the `Passthrough` contracts leave raw accesses to the host
            memory.place(0, RAW_START, start, (RAW_END - RAW_START) as usize, Perms::RW);
        }
        memory
    }

    /// The guest address of the first byte of region `idx`: its tag and the host address of the byte.
    pub fn region_base(&self, idx: usize) -> u64 {
        self.bases[idx]
    }

    /// Map `len` zeroed bytes at a free host region. The region stays mapped until [`unmap`](Self::unmap) takes the
    /// handle back, or the memory is dropped.
    ///
    /// Fails with [`VmError::NoFreeRegion`] if every host region is taken, with [`VmError::InvalidArgument`] if `len`
    /// exceeds [`MAX_REGION_LEN`], and with [`VmError::OutOfMemory`] if the allocator refuses `len` bytes.
    pub fn map(&mut self, len: usize, perms: Perms) -> crate::Result<Region> {
        let idx = self.free_region(len)?;
        self.map_any(idx, len, perms)?;
        Ok(self.take(idx, len, perms))
    }

    /// [`map`](Self::map) with `len` bytes initialized from `init`, the rest zeroed. Fails as [`map`](Self::map) does,
    /// and if `init` is longer than `len`.
    pub fn map_bytes(&mut self, init: &[u8], len: usize, perms: Perms) -> crate::Result<Region> {
        if init.len() > len {
            let msg = format!("{} initial bytes in a {len} byte region", init.len());
            return Err(VmError::InvalidArgument(msg));
        }
        let idx = self.free_region(len)?;
        self.map_bytes_any(idx, init, len, perms)?;
        Ok(self.take(idx, len, perms))
    }

    /// Expose host memory at a free host region. Guest accesses go straight to `ptr`. Fails as [`map`](Self::map)
    /// does.
    ///
    /// # Safety
    ///
    /// `ptr..ptr+len` must stay valid (and writable if `perms` allows writes) until the region is unmapped or this
    /// `VmMemory` is dropped, must not be accessed through other references in ways that conflict with guest/helper
    /// accesses while the VM runs, and must be usable from any thread that uses this memory.
    pub unsafe fn map_host(&mut self, ptr: NonNull<u8>, len: usize, perms: Perms) -> crate::Result<Region> {
        let idx = self.free_region(len)?;
        // SAFETY: the caller's contract.
        unsafe { self.map_host_any(idx, ptr, len, perms) };
        Ok(self.take(idx, len, perms))
    }

    /// Unmap `region`, freeing its bytes if [`map`](Self::map) or [`map_bytes`](Self::map_bytes) allocated them, and
    /// its index for the next mapping. Fails with [`VmError::ForeignRegion`] if another memory mapped `region`.
    pub fn unmap(&mut self, region: Region) -> crate::Result<()> {
        if region.memory != self.id {
            return Err(VmError::ForeignRegion);
        }
        self.unmap_any(region.index);
        self.taken &= !(1 << region.index);
        Ok(())
    }

    /// The free host region that a mapping of `len` bytes goes to.
    fn free_region(&self, len: usize) -> crate::Result<usize> {
        if len > MAX_REGION_LEN {
            return Err(VmError::InvalidArgument(format!("region length {len} exceeds {MAX_REGION_LEN}")));
        }
        free_host_region(self.taken)
    }

    /// Mark host region `idx`, just mapped, as taken and return its handle.
    fn take(&mut self, idx: usize, len: usize, perms: Perms) -> Region {
        self.taken |= 1 << idx;
        Region {
            memory: self.id,
            index: idx,
            base: self.bases[idx],
            len,
            perms,
        }
    }

    /// Map `len` zeroed bytes as region `idx`, the ones the layout reserves included, replacing any previous mapping.
    /// Returns the region's guest base address. Fails only if the allocator refuses.
    ///
    /// # Panics
    ///
    /// Panics if `idx` is 0 or out of range, or `len` exceeds [`MAX_REGION_LEN`].
    pub(crate) fn map_any(&mut self, idx: usize, len: usize, perms: Perms) -> crate::Result<u64> {
        assert!(len <= MAX_REGION_LEN, "region too large: {len}");
        let ptr = if len == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: non-zero size.
            unsafe { allocate_zeroed(Self::layout(len)) }?
        };
        Ok(self.set(idx, ptr, len, perms, true))
    }

    /// [`map_any`](Self::map_any) with the region initialized from `init`; fails and panics as `map_any` does, and
    /// panics if `init` is longer than `len`.
    pub(crate) fn map_bytes_any(&mut self, idx: usize, init: &[u8], len: usize, perms: Perms) -> crate::Result<u64> {
        assert!(init.len() <= len, "init ({}) larger than region ({len})", init.len());
        let base = self.map_any(idx, len, perms)?;
        // SAFETY: `map_any` just allocated `len` bytes for region `idx`, at least `init.len()`
        unsafe { ptr::copy_nonoverlapping(init.as_ptr(), self.ptrs[idx].as_ptr(), init.len()) };
        Ok(base)
    }

    /// Expose host memory as region `idx`, as [`map_host`](Self::map_host) does; panics as [`map_any`](Self::map_any)
    /// does.
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
        self.taken |= 1 << idx;
        base
    }

    /// Unmap region `idx`, whatever mapped it.
    pub(crate) fn unmap_any(&mut self, idx: usize) {
        self.set(idx, NonNull::dangling(), 0, Perms::NONE, false);
    }

    /// Length of region `idx` (0 if unmapped).
    pub fn region_len(&self, idx: usize) -> usize {
        self.lens.get(idx).copied().unwrap_or(0)
    }

    fn set(&mut self, idx: usize, ptr: NonNull<u8>, len: usize, perms: Perms, owned: bool) -> u64 {
        assert!(idx != 0 && idx < CODE_REGION, "invalid region index {idx}");
        self.free(idx);

        self.place(idx, self.passthrough.address(idx, ptr), ptr, len, perms);
        if owned {
            self.owned |= 1 << idx;
        } else {
            self.owned &= !(1 << idx);
        }
        self.shared[idx] = None;
        self.bases[idx]
    }

    /// Make guest address `base` the start of the `len` bytes at `ptr` as region `idx`, and move to a new epoch.
    fn place(&mut self, idx: usize, base: u64, ptr: NonNull<u8>, len: usize, perms: Perms) {
        let fits = |need: Perms, size: u64| match perms.allows(need) {
            true => (len as u64).saturating_sub(size - 1),
            false => 0,
        };
        // guest accesses reach the bytes through pointers made from their addresses, under any tag
        let _ = ptr.as_ptr().expose_provenance();
        self.bases[idx] = base;
        self.ptrs[idx] = ptr;
        for (class, size) in [1, 2, 4, 8].into_iter().enumerate() {
            self.read_fits[class][idx] = fits(Perms::R, size);
            self.write_fits[class][idx] = fits(Perms::W, size);
        }
        self.lens[idx] = len;
        self.perms[idx] = perms;
        self.epoch = EPOCH.fetch_add(1, Relaxed) + 1;
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

    /// The host pointer to the byte at offset `at` into region `idx`, made from its address (see the module docs).
    #[inline(always)]
    fn host_at(&self, idx: usize, at: u64) -> *mut u8 {
        ptr::with_exposed_provenance_mut(self.ptrs[idx].as_ptr().expose_provenance() + at as usize)
    }

    /// Resolve `addr..addr+len` to a host pointer if region perms include `need`.
    #[inline(always)]
    fn resolve(&self, addr: u64, len: usize, need: Perms) -> Option<*mut u8> {
        let idx = region_of(addr);
        let at = addr.wrapping_sub(self.bases[idx]);
        let (len, region_len) = (len as u64, self.lens[idx] as u64);
        (self.perms[idx].allows(need) && len <= region_len && at <= region_len - len).then(|| self.host_at(idx, at))
    }

    /// Resolve a guest access against `fits`, the row of `read_fits` or `write_fits` for its size.
    #[inline(always)]
    fn guest_ptr(&self, addr: u64, fits: &[u64; MAX_REGIONS]) -> Option<*mut u8> {
        let idx = region_of(addr);
        let at = addr.wrapping_sub(self.bases[idx]);
        (at < fits[idx]).then(|| self.host_at(idx, at))
    }

    /// The first byte from guest address `addr` on that the guest can't access with `need`, where a range from `addr`
    /// failed to resolve: `addr` itself or the end of its region.
    #[cold]
    #[inline(never)]
    fn unreachable_byte(&self, addr: u64, need: Perms) -> u64 {
        if self.resolve(addr, 1, need).is_none() {
            return addr;
        }
        let idx = region_of(addr);
        self.bases[idx] + self.lens[idx] as u64
    }

    /// Host pointer to `len` bytes at guest address `addr` whose region allows `need`. No reference is created, so the
    /// bytes may be shared or aliased.
    pub fn host_ptr(&self, addr: u64, len: usize, need: Perms) -> Result<NonNull<u8>, MemoryError> {
        let ptr = self.resolve(addr, len, need).and_then(NonNull::new);
        ptr.ok_or(MemoryError { addr, size: len })
    }

    /// Borrow `len` bytes at guest address `addr` (host access, ignores perms). Fails on a region shared with other
    /// programs and on raw host addresses, whose bytes may change during the borrow; [`read_bytes`](Self::read_bytes)
    /// copies them instead.
    pub fn bytes(&self, addr: u64, len: usize) -> Result<&[u8], MemoryError> {
        self.check_unshared(addr, len)?;
        self.slice(addr, len, Perms::NONE)
    }

    /// Borrow `len` bytes at guest address `addr` whose region allows `need`.
    pub(crate) fn slice(&self, addr: u64, len: usize, need: Perms) -> Result<&[u8], MemoryError> {
        let ptr = self.host_ptr(addr, len, need)?;
        // SAFETY: `host_ptr` checked the range lies inside a live region, which the borrow of `self` keeps mapped, or
        // in raw host memory, which the `Passthrough` contract leaves to the host.
        Ok(unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) })
    }

    /// Mutably borrow `len` bytes at guest address `addr` (host access, ignores perms). Fails on a shared region and
    /// on raw host addresses, as [`bytes`](Self::bytes) does.
    pub fn bytes_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8], MemoryError> {
        self.check_unshared(addr, len)?;
        let ptr = self.host_ptr(addr, len, Perms::NONE)?;
        // SAFETY: as `slice`; `&mut self` guarantees exclusive access.
        Ok(unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), len) })
    }

    /// Fail if `addr..addr+len` lies in a region mapped with `map_shared`, or is raw and outside every region.
    fn check_unshared(&self, addr: u64, len: usize) -> Result<(), MemoryError> {
        let idx = match region_of(addr) {
            // a raw address is the host address: it lends only from a region whose bytes hold it, as all addresses
            // do in the untagged mode
            0 => (1..MAX_REGIONS).find(|&idx| self.holds(idx, addr, len)),
            idx => Some(idx),
        };
        match idx.filter(|&idx| self.shared[idx].is_none()) {
            Some(_) => Ok(()),
            None => Err(MemoryError { addr, size: len }),
        }
    }

    /// Whether the `len` host bytes at `host` lie in region `idx`, which is mapped.
    fn holds(&self, idx: usize, host: u64, len: usize) -> bool {
        let at = host.wrapping_sub(self.ptrs[idx].addr().get() as u64);
        let (len, region_len) = (len as u64, self.lens[idx] as u64);
        region_len != 0 && len <= region_len && at <= region_len - len
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
        read_scalar(|bytes| self.read_bytes(addr, bytes))
    }

    /// Copy the `V` at guest address `addr` out (host access).
    #[cfg(feature = "maps")]
    pub(crate) fn read_pod<V: bytemuck::Pod>(&self, addr: u64) -> Result<V, MemoryError> {
        let src = self.host_ptr(addr, size_of::<V>(), Perms::NONE)?;
        // SAFETY: `host_ptr` checked the range, and `Pod` types accept every bit pattern.
        Ok(unsafe { src.cast::<V>().read_unaligned() })
    }

    /// Write a little-endian scalar at guest address `addr` (host access).
    pub fn write<T: Scalar>(&mut self, addr: u64, value: T) -> Result<(), MemoryError> {
        write_scalar(value, |bytes| self.write_bytes(addr, bytes))
    }
}

impl Drop for VmMemory {
    fn drop(&mut self) {
        for idx in 0..MAX_REGIONS {
            self.free(idx);
        }
    }
}

/// A region the host mapped into a [`VmMemory`]; [`VmMemory::unmap`] takes it back.
#[derive(Debug)]
pub struct Region {
    memory: u64,
    index: usize,
    base: u64,
    len: usize,
    perms: Perms,
}

impl Region {
    /// Guest address of the first byte.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the region is 0 bytes long.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Guest permissions.
    pub fn perms(&self) -> Perms {
        self.perms
    }
}

/// Allocate zeroed memory for `layout`, failing with [`VmError::OutOfMemory`] if the allocator refuses.
///
/// # Safety
///
/// `layout` must have a non-zero size.
unsafe fn allocate_zeroed(layout: Layout) -> crate::Result<NonNull<u8>> {
    // SAFETY: the caller's contract.
    let raw = unsafe { alloc_zeroed(layout) };
    NonNull::new(raw).ok_or(VmError::OutOfMemory(layout.size()))
}

/// The bytes a program may still allocate while it links or loads, from
/// [`VmConfig::memory_limit`](crate::VmConfig::memory_limit).
pub struct MemoryBudget {
    limit: usize,
    left: u64,
}

impl MemoryBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            left: limit as u64,
        }
    }

    /// Count `bytes` against the budget. Fails with [`VmError::MemoryLimit`] once the total exceeds the limit.
    pub fn take(&mut self, bytes: u64) -> crate::Result<()> {
        self.left = self.left.checked_sub(bytes).ok_or(VmError::MemoryLimit(self.limit))?;
        Ok(())
    }
}

/// The calling program's memory as a host function registered with
/// [`Vm::register_extern_with_memory`](crate::Vm::register_extern_with_memory) sees it.
///
/// Every access needs the guest's permissions on the region, so a pointer passed to a host function reaches no more
/// than the guest's own loads and stores would: with [`Passthrough`](crate::Passthrough) that includes raw host
/// addresses. Accesses copy, so no reference into guest memory outlives the call that made it.
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
        // SAFETY: `host_ptr` checked that the range lies inside a live region or raw host memory, which the
        // `Passthrough` contract leaves to the host. A raw range may overlap `buf`, which `ptr::copy` allows.
        unsafe { std::ptr::copy(src.as_ptr(), buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    /// Copy `len` bytes from guest address `addr` into a new vector. The range is checked before anything is allocated,
    /// so a guest-supplied length is safe.
    pub fn read_vec(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let src = self.memory.host_ptr(addr, len, Perms::R)?;
        let mut bytes = Vec::with_capacity(len);
        // SAFETY: as `read_bytes`; the copy initializes all `len` bytes, and the new allocation's provenance isn't
        // exposed, so no raw address reaches it.
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
        unsafe { std::ptr::copy(data.as_ptr(), dst.as_ptr(), data.len()) };
        Ok(())
    }

    /// Read a little-endian scalar at guest address `addr`.
    pub fn read<T: Scalar>(&self, addr: u64) -> Result<T, MemoryError> {
        read_scalar(|bytes| self.read_bytes(addr, bytes))
    }

    /// Write a little-endian scalar at guest address `addr`.
    pub fn write<T: Scalar>(&mut self, addr: u64, value: T) -> Result<(), MemoryError> {
        write_scalar(value, |bytes| self.write_bytes(addr, bytes))
    }
}

/// Zeroed, cache-line aligned host memory that several programs map at once.
#[derive(Debug)]
pub struct SharedBuffer {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: plain heap memory owned by this value; access from guests follows the `Vm::share_region` contract.
unsafe impl Send for SharedBuffer {}
unsafe impl Sync for SharedBuffer {}

impl SharedBuffer {
    /// Allocate `len` zeroed bytes. Fails with [`VmError::OutOfMemory`] if the allocator refuses.
    ///
    /// # Panics
    ///
    /// Panics if `len` is 0.
    pub fn new(len: usize) -> crate::Result<Self> {
        assert!(len != 0, "empty shared buffer");
        let layout = Self::layout(len);
        // SAFETY: non-zero size.
        let ptr = unsafe { allocate_zeroed(layout) }?;
        Ok(Self { ptr, len })
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

/// The `$atomic` at the `*mut u8` `$ptr`, or `None` if `$ptr` is misaligned for it. `$ptr` must come from a bounds
/// check of `size_of::<$atomic>()` bytes inside a live region.
///
/// A guest address holds the host address of its byte, so this tests the guest address, in a borrow and a raw access
/// too.
macro_rules! atomic_cell {
    ($ptr:expr, $atomic:ident) => {{
        let ptr = $ptr.cast::<$atomic>();
        // SAFETY: the bounds check keeps `ptr` inside a live region or raw host memory, and the alignment is checked.
        // Other threads reach the memory only through atomics or under the `map_host`, `Vm::share_region` and
        // `Passthrough::on` contracts.
        ptr.is_aligned().then(|| unsafe { &*ptr })
    }};
}

/// Host atomic on a shared region, coherent with guest atomics on other threads. Misaligned offsets fail, as they do
/// for guests.
macro_rules! region_atomic {
    ($name:ident, $ty:ty, $atomic:ident) => {
        /// Apply `op` atomically to the value at `offset` and return the old value.
        pub fn $name(&mut self, offset: usize, op: AtomicOp<$ty>) -> Result<$ty, MemoryError> {
            let ptr = self.ptr(offset, size_of::<$ty>())?.as_ptr();
            let misaligned = || MemoryError {
                addr: self.base() + offset as u64,
                size: size_of::<$ty>(),
            };
            let cell = atomic_cell!(ptr, $atomic).ok_or_else(misaligned)?;
            Ok(fetch_op!(cell, op))
        }
    };
}

/// A buffer that [`Vm::share_region`](crate::Vm::share_region) maps into every program the VM links afterwards, at
/// the same guest address in each program of one [`Passthrough`] mode.
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
    base: u64,
    perms: Perms,
    buffer: Arc<SharedBuffer>,
}

impl SharedRegion {
    /// The host's handle on `buffer`, which every program maps as region `region`; `passthrough` is the VM's.
    ///
    /// # Safety
    ///
    /// While this handle is in use on one thread, no other `SharedRegion` over `buffer` may be used on another.
    pub(crate) unsafe fn new(region: usize, passthrough: Passthrough, perms: Perms, buffer: Arc<SharedBuffer>) -> Self {
        Self {
            region,
            base: passthrough.address(region, buffer.as_ptr()),
            perms,
            buffer,
        }
    }

    /// Guest address of the first byte in a program of the VM's [`Passthrough`] mode.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Guest address of the first byte in a program loaded with `passthrough`.
    pub fn base_for(&self, passthrough: Passthrough) -> u64 {
        passthrough.address(self.region, self.buffer.as_ptr())
    }

    /// Guest permissions.
    pub fn perms(&self) -> Perms {
        self.perms
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
        read_scalar(|bytes| self.read_bytes(offset, bytes))
    }

    /// Write a little-endian scalar at `offset`.
    pub fn write<T: Scalar>(&mut self, offset: usize, value: T) -> Result<(), MemoryError> {
        write_scalar(value, |bytes| self.write_bytes(offset, bytes))
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

/// The row of `read_fits` and `write_fits` for accesses of `size` bytes, 1 to 8.
const fn size_class(size: usize) -> usize {
    size.trailing_zeros() as usize
}

/// Guest access: the error is the faulting address.
macro_rules! guest_access {
    ($load:ident, $store:ident, $ty:ty) => {
        #[inline(always)]
        fn $load(&self, addr: u64) -> Result<$ty, u64> {
            let fits = &self.read_fits[const { size_class(size_of::<$ty>()) }];
            let ptr = self.guest_ptr(addr, fits).ok_or(addr)?;
            // SAFETY: `guest_ptr` checked bounds; guest memory has no alignment guarantee.
            Ok(<$ty>::from_le(unsafe { ptr.cast::<$ty>().read_unaligned() }))
        }

        #[inline(always)]
        fn $store(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            let fits = &self.write_fits[const { size_class(size_of::<$ty>()) }];
            let ptr = self.guest_ptr(addr, fits).ok_or(addr)?;
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
            let cell = atomic_cell!(ptr, $atomic).ok_or(addr)?;
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
            let fits = &self.read_fits[const { size_class(size_of::<$ty>()) }];
            let ptr = self.guest_ptr(addr, fits).ok_or(addr)?;
            let cell = atomic_cell!(ptr, $atomic).ok_or(addr)?;
            Ok(<$ty>::from_le(cell.load(Acquire)))
        }

        #[inline(always)]
        fn $store(&mut self, addr: u64, value: $ty) -> Result<(), u64> {
            let fits = &self.write_fits[const { size_class(size_of::<$ty>()) }];
            let ptr = self.guest_ptr(addr, fits).ok_or(addr)?;
            let cell = atomic_cell!(ptr, $atomic).ok_or(addr)?;
            cell.store(value.to_le(), Release);
            Ok(())
        }
    };
}

// SAFETY: `place` moves to a new epoch whenever a mapping changes, and the `Memory` methods leave the epoch alone
unsafe impl Memory for VmMemory {
    type Error = u64;

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
        let idx = region_of(addr);
        let len = |need| match self.perms[idx].allows(need) {
            true => self.lens[idx] as u64,
            false => 0,
        };
        // SAFETY: the region's allocation backs its readable and writable bytes until the next `place`, which moves to
        // a new epoch, or drop, and `guest_ptr` resolves guest accesses to the same bytes. Raw host memory in region 0
        // needn't be valid, which the `Passthrough` contract leaves to the host. Epoch 0 has nothing mapped. `ptrs`
        // holds raw pointers, not references into `self`.
        unsafe { Window::new(self.bases[idx], self.ptrs[idx].as_ptr(), len(Perms::R), len(Perms::W), self.epoch) }
    }

    fn epoch(&self) -> u64 {
        self.epoch
    }

    // The native function reaches the bytes in place, so they need the guest's permissions for its access, which the
    // fits of 1-byte accesses give: the region's length where its perms allow the access, else 0. Every guest address
    // is its host address under the region's tag. An empty buffer gets a canonical non-null, 16-byte-aligned dangling
    // address regardless of the guest pointer, so Rust and C natives never receive NULL or an unaligned/forged pointer.
    #[inline(always)]
    fn native_ptr(&self, addr: u64, len: u64, write: bool) -> Result<u64, u64> {
        const EMPTY_NATIVE_PTR: u64 = 16;
        if len == 0 {
            return Ok(EMPTY_NATIVE_PTR);
        }
        let idx = region_of(addr);
        let mut fits = self.read_fits[0][idx];
        if write {
            fits = fits.min(self.write_fits[0][idx]);
        }
        let at = addr.wrapping_sub(self.bases[idx]);
        let host = addr & (region_tag(1) - 1);
        match at < fits && len <= fits - at {
            true => Ok(host),
            false => Err(self.unreachable_byte(addr, if write { Perms::RW } else { Perms::R })),
        }
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

/// Decode a little-endian `T` from the bytes `read` copies into the buffer it gets.
fn read_scalar<T: Scalar>(read: impl FnOnce(&mut [u8]) -> Result<(), MemoryError>) -> Result<T, MemoryError> {
    let mut bytes = [0; 8];
    let bytes = &mut bytes[..T::SIZE];
    read(bytes)?;
    Ok(T::read_le(bytes))
}

/// Encode `value` as little-endian bytes and pass them to `write`.
fn write_scalar<T: Scalar>(value: T, write: impl FnOnce(&[u8]) -> Result<(), MemoryError>) -> Result<(), MemoryError> {
    let mut bytes = [0; 8];
    let bytes = &mut bytes[..T::SIZE];
    value.write_le(bytes);
    write(bytes)
}

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
    use crate::error::ExecError;

    #[test]
    fn null_region_and_bounds_fault() {
        let mut mem = VmMemory::new();
        let base = mem.map_any(1, 16, Perms::RW).unwrap();
        assert_eq!(mem.load_u8(0), Err(0));
        assert_eq!(mem.load_u8(7), Err(7));
        assert!(mem.load_u64(base + 8).is_ok());
        assert_eq!(mem.load_u64(base + 9), Err(base + 9)); // straddles the end
        assert_eq!(mem.load_u8(region_tag(CODE_REGION)), Err(region_tag(CODE_REGION)));
        // the region's tag on bytes outside it, and its bytes under another tag or none
        let (past, before) = (base + 16, base - 1);
        assert_eq!((mem.load_u8(past), mem.load_u8(before)), (Err(past), Err(before)));
        let (other, untagged) = (base - region_tag(1) + region_tag(2), base - region_tag(1));
        assert_eq!((mem.load_u8(other), mem.load_u8(untagged)), (Err(other), Err(untagged)));
        assert_eq!(mem.load_u8(u64::MAX), Err(u64::MAX));
        // guest-controlled lengths (helper and borrow arguments) must not wrap the check
        assert!(mem.bytes(base + 8, usize::MAX - 7).is_err());
        assert!(mem.host_ptr(base, usize::MAX, Perms::NONE).is_err());
    }

    #[test]
    fn perms_apply_to_guest_not_host() {
        let mut mem = VmMemory::new();
        let ro = mem.map_bytes_any(2, &[1, 2, 3, 4], 8, Perms::R).unwrap();
        assert_eq!(mem.load_u32(ro), Ok(0x0403_0201));
        assert_eq!(mem.store_u8(ro, 9), Err(ro));
        mem.write(ro, 9u8).unwrap(); // host may still patch read-only regions
        assert_eq!(mem.load_u8(ro), Ok(9));

        let wo = mem.map_any(3, 8, Perms::W).unwrap();
        assert!(mem.store_u64(wo, 1).is_ok());
        assert_eq!(mem.load_u64(wo), Err(wo));
    }

    #[test]
    fn unaligned_little_endian_access() {
        let mut mem = VmMemory::new();
        let base = mem.map_any(1, 16, Perms::RW).unwrap();
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

    // Accesses through other registers than r10 run through windows of the memory; this is the lib test that takes
    // Miri through them. A host call that remaps a region moves it to new host bytes: the guest reaches them at the
    // new address, and the old one faults, where a window kept past the call would read freed memory.
    #[test]
    fn data_windows_follow_remaps() {
        use ebpf_asm::{Assembler, R0, R10, R2, R3, R6, R7};

        use crate::executor::Executor;
        use crate::helper::{HelperContext, HelperRegistry, HostFn};
        use crate::layout::{FIRST_HOST_REGION, STACK_REGION};
        use crate::vm::VmConfig;

        let mut helpers = HelperRegistry::default();
        let remap =
            |ctx: &mut HelperContext| Ok(ctx.memory.map_bytes_any(FIRST_HOST_REGION, &[9], 8, Perms::RW).unwrap());
        helpers.put_id(1, HostFn::raw(remap));
        let config = VmConfig::default();

        // r6 points into the region, r2 into the stack: region[0] + stack[-4] + remapped region[0] = 7 + 5 + 9, or
        // with `old`, the old region[0] after the remap
        let run = |old: bool| {
            let mut mem = VmMemory::new();
            let base = mem.map_bytes_any(FIRST_HOST_REGION, &[7], 8, Perms::RW).unwrap();
            let len = config.frame_size as usize;
            let stack_top = mem.map_any(STACK_REGION, len, Perms::RW).unwrap() + config.frame_size;

            let mut asm = Assembler::new();
            asm.stdw(R10, -16, 0);
            asm.lddw(R6, base as i64);
            asm.mov64(R2, R10).add64_imm(R2, -8);
            asm.ldxw(R7, R6, 0);
            asm.stw(R2, 4, 5).ldxw(R3, R2, 4).add64(R7, R3);
            asm.stxw(R6, 4, R7);
            asm.call(1).ldxw(R0, if old { R6 } else { R0 }, 0).add64(R0, R7).exit();
            let code = rvm_core::Code::new(rvm_core::Instruction::decode(&asm.assemble().unwrap()));
            let result = Executor::new(helpers.clone(), stack_top, &config).call(&code, &mut mem, 0, &[]);
            (result, base)
        };
        assert_eq!(run(false).0.unwrap(), 21);
        let (result, base) = run(true);
        let Err(VmError::Exec(ExecError::MemoryFault { error, .. })) = result else {
            panic!("{result:?}")
        };
        assert_eq!(error, MemoryError { addr: base, size: 4 });
    }

    // host functions reach guest memory only as far as the guest itself could
    #[test]
    fn guest_memory_needs_guest_perms() {
        let mut mem = VmMemory::new();
        let rw = mem.map_any(1, 16, Perms::RW).unwrap();
        let ro = mem.map_bytes_any(2, b"hi", 8, Perms::R).unwrap();
        let wo = mem.map_any(3, 8, Perms::W).unwrap();
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

    // A guest address holds the host address of its byte, so a guest atomic is aligned where its host bytes are, in
    // whatever the host mapped.
    #[test]
    fn atomics_follow_guest_addresses() {
        let mut buf = [0u64; 3];
        let aligned = NonNull::from(&mut buf).cast::<u8>();
        let mut mem = VmMemory::new();
        // SAFETY: `buf` outlives `mem` and is only accessed through it.
        let base = unsafe { mem.map_host(aligned.add(1), 16, Perms::RW) }.unwrap().base();
        assert_eq!(mem.atomic_u64(base + 7, AtomicOp::Add(1)), Ok(0));
        assert_eq!(mem.atomic_u64(base, AtomicOp::Add(1)), Err(base));
    }

    #[test]
    fn shared_region_bounds_and_alignment() {
        let buffer = Arc::new(SharedBuffer::new(16).unwrap());
        // SAFETY: the only handle over the buffer.
        let mut region = unsafe { SharedRegion::new(5, Passthrough::OFF, Perms::R, buffer) };
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

    /// Per region: the guest address its bytes start at, their host address, their length and perms.
    type Table = [(u64, usize, u64, Perms); MAX_REGIONS];

    const PERMS: [Perms; 4] = [Perms::NONE, Perms::R, Perms::W, Perms::RW];

    // regions 1..=MAPPED cover every tested length with every perms
    const MAPPED: usize = 6 * PERMS.len();

    fn unmapped() -> Table {
        let dangling = NonNull::<u8>::dangling().addr().get();
        std::array::from_fn(|idx| (region_tag(idx) | dangling as u64, dangling, 0, Perms::NONE))
    }

    // Guest loads and stores check per-region fits with the perms folded in. Every access path must agree with a plain
    // perms and bounds check on the region edges.
    #[test]
    fn access_checks_match_reference() {
        // a 2^32 byte region reaches the largest offset; Miri can't allocate that much
        let large = if cfg!(miri) { 64 } else { MAX_REGION_LEN };
        let mut buf = vec![0u8; large];
        let host = NonNull::new(buf.as_mut_ptr()).unwrap();
        let mut mem = VmMemory::new();
        let mut table = unmapped();

        let lens: [usize; MAPPED / PERMS.len()] = [0, 1, 7, 8, 9, large];
        let regions = lens.into_iter().flat_map(|len| PERMS.map(|p| (len, p)));
        for (idx, (len, perms)) in (1..).zip(regions) {
            // SAFETY: `buf` outlives `mem` and is only accessed through it.
            unsafe { mem.map_host_any(idx, host, len, perms) };
            table[idx] = (mem.region_base(idx), host.addr().get(), len as u64, perms);
        }
        check_regions(&mut mem, &table, true);

        // replace owned regions with host ones of other perms, or unmap them
        for (idx, region) in table.iter_mut().enumerate().skip(1).take(MAPPED) {
            mem.map_any(idx, 16, Perms::RW).unwrap();
            if idx % 5 == 0 {
                mem.unmap_any(idx);
                *region = unmapped()[idx];
            } else {
                let perms = PERMS[(region.3 .0 as usize + 1) % 4];
                // SAFETY: as above.
                unsafe { mem.map_host_any(idx, host, region.2 as usize, perms) };
                region.3 = perms;
            }
        }
        check_regions(&mut mem, &table, true);
    }

    // With passthrough, region 0 resolves to the host address from RAW_START up to RAW_END and faults around that, and
    // the regions keep their checks.
    #[test]
    fn raw_checks_match_reference() {
        // SAFETY: the test resolves raw addresses but never accesses them.
        let mut mem = VmMemory::with_passthrough(unsafe { Passthrough::on() });
        let mut table = unmapped();
        table[0] = (RAW_START, RAW_START as usize, RAW_END - RAW_START, Perms::RW);
        let base = mem.map_any(1, 16, Perms::RW).unwrap();
        table[1] = (base, mem.ptrs[1].addr().get(), 16, Perms::RW);
        check_regions(&mut mem, &table, false);
    }

    // A guest walks a host linked list through raw pointers, adding up and bumping its values, through the data window
    // and the `Memory` methods, with its stack tagged and untagged. Miri checks that the accesses take the provenance
    // the host exposed.
    #[test]
    fn raw_pointers_reach_host_memory() {
        use ebpf_asm::{Assembler, R0, R1, R10, R2, R3};

        use crate::executor::Executor;
        use crate::helper::HelperRegistry;
        use crate::layout::STACK_REGION;
        use crate::vm::VmConfig;

        // r0 = sum of the values before the bump; each value += 1, the first one atomically, through a stack slot
        let mut asm = Assembler::new();
        let walk = asm.label();
        asm.mov64_imm(R0, 0).mov64_imm(R3, 1).atomic_add64(R1, 0, R3);
        asm.bind(walk)
            .ldxdw(R2, R1, 0)
            .add64(R0, R2)
            .add64_imm(R2, 1)
            .stxdw(R1, 0, R2);
        asm.stxdw(R10, -8, R1).ldxdw(R1, R10, -8);
        asm.ldxdw(R1, R1, 8).jne_imm(R1, 0, walk).exit();
        let code = rvm_core::Code::new(rvm_core::Instruction::decode(&asm.assemble().unwrap()));

        // SAFETY: the guest only touches `nodes` and its stack.
        for passthrough in unsafe { [Passthrough::on(), Passthrough::untagged()] } {
            let mut nodes = [[0u64; 2]; 3];
            let mut next = 0;
            for (i, node) in nodes.iter_mut().enumerate().rev() {
                *node = [i as u64 + 1, next];
                next = node.as_mut_ptr() as u64;
            }
            let mut mem = VmMemory::with_passthrough(passthrough);
            let config = VmConfig::default();
            let len = config.frame_size as usize;
            let stack_top = mem.map_any(STACK_REGION, len, Perms::RW).unwrap() + config.frame_size;

            let mut executor = Executor::new(HelperRegistry::default(), stack_top, &config);
            assert_eq!(executor.call(&code, &mut mem, 0, &[next]).unwrap(), 2 + 2 + 3);
            // the first 64 KiB fault
            assert!(executor.call(&code, &mut mem, 0, &[RAW_START - 8]).is_err());
            drop(mem);
            assert_eq!(nodes.map(|n| n[0]), [3, 3, 4]);
        }
    }

    /// Sweep the addresses around the start and end of each region's range, its bytes' start and end, and 2^31 and
    /// 2^32 bytes on. Without `access`, only resolves them.
    fn check_regions(mem: &mut VmMemory, table: &Table, access: bool) {
        // Miri is too slow for the full sweep
        let (span, regions) = match cfg!(miri) {
            true => (2, MAPPED + 2),
            false => (16, MAX_REGIONS),
        };
        for (idx, &(base, _, len, _)) in table.iter().enumerate().take(regions) {
            let anchors = [
                region_tag(idx),
                region_tag(idx + 1),
                base,
                base + len,
                base + (1 << 31),
                base + (1 << 32),
            ];
            for anchor in anchors {
                for addr in (0..=2 * span).map(|i| anchor.wrapping_add(i).wrapping_sub(span)) {
                    check_addr(mem, table, addr, access);
                }
            }
        }
    }

    fn check_addr(mem: &mut VmMemory, table: &Table, addr: u64, access: bool) {
        let expect = |len, need| reference(table, addr, len, need);
        let fault = |len, need| expect(len, need).map(drop).ok_or(addr);

        for size in [1, 2, 4, 8] {
            let load = mem.guest_ptr(addr, &mem.read_fits[size_class(size)]).map(|p| p.addr());
            assert_eq!(load, expect(size, Perms::R), "load {size} at {addr:#x}");
            let store = mem.guest_ptr(addr, &mem.write_fits[size_class(size)]).map(|p| p.addr());
            assert_eq!(store, expect(size, Perms::W), "store {size} at {addr:#x}");
        }
        let host_lens = [0, 1, 2, 7, 8, 9, MAX_REGION_LEN - 1, MAX_REGION_LEN, MAX_REGION_LEN + 1];
        for len in host_lens.into_iter().chain([usize::MAX - 7, usize::MAX]) {
            for need in PERMS {
                let ptr = mem.host_ptr(addr, len, need).ok().map(|p| p.addr().get());
                assert_eq!(ptr, expect(len, need), "host_ptr {len} {need:?} at {addr:#x}");
            }
            // raw addresses lend only from a region's bytes, which the sweep doesn't reach
            let bytes = mem.bytes(addr, len).ok().map(|b| b.as_ptr().addr());
            let borrow = expect(len, Perms::NONE).filter(|_| region_of(addr) != 0);
            assert_eq!(bytes, borrow, "bytes {len} at {addr:#x}");
        }
        if !access {
            return;
        }

        assert_eq!(mem.load_u8(addr).map(drop), fault(1, Perms::R));
        assert_eq!(mem.load_u16(addr).map(drop), fault(2, Perms::R));
        assert_eq!(mem.load_u32(addr).map(drop), fault(4, Perms::R));
        assert_eq!(mem.load_u64(addr).map(drop), fault(8, Perms::R));
        assert_eq!(mem.store_u8(addr, 0), fault(1, Perms::W));
        assert_eq!(mem.store_u16(addr, 0), fault(2, Perms::W));
        assert_eq!(mem.store_u32(addr, 0), fault(4, Perms::W));
        assert_eq!(mem.store_u64(addr, 0), fault(8, Perms::W));

        let atomic = |size| expect(size, Perms::RW).filter(|host| host % size == 0);
        assert_eq!(mem.atomic_u32(addr, AtomicOp::Add(0)).map(drop), atomic(4).map(drop).ok_or(addr));
        assert_eq!(mem.atomic_u64(addr, AtomicOp::Add(0)).map(drop), atomic(8).map(drop).ok_or(addr));
    }

    /// The host address of `len` bytes at `addr`, from a plain perms and overflow-safe bounds check.
    fn reference(table: &Table, addr: u64, len: usize, need: Perms) -> Option<usize> {
        let &(base, host, region_len, perms) = &table[(addr / region_tag(1)) as usize];
        let off = addr.checked_sub(base)?;
        let len = len as u64;
        let ok = perms.0 & need.0 == need.0 && len <= region_len && off <= region_len - len;
        ok.then(|| host + off as usize)
    }

    #[test]
    fn native_ptr_empty_returns_canonical_aligned_address() {
        let mut mem = VmMemory::new();
        let base = mem.map_any(1, 64, Perms::RW).unwrap();
        for addr in [0, 1, 0xDEAD_BEEF, base, base + 1, region_tag(7) | 0x1234] {
            for write in [false, true] {
                let ptr = mem.native_ptr(addr, 0, write).unwrap();
                assert_eq!(ptr, 16, "addr={addr:#x} write={write}");
            }
        }
    }
}
