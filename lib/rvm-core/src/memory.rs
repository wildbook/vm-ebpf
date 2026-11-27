//! What an embedder implements to give the guest its memory: [`Memory`], and the [`Window`]s through which the
//! interpreter reaches host memory without calling it.

use std::ptr;

/// The guest memory that loads and stores go to. Values are little-endian, and an address needs no alignment.
///
/// An implementation provides [`load_u8`](Self::load_u8), [`store_u8`](Self::store_u8) and
/// [`native_ptr`](Self::native_ptr). The wider loads and stores, the atomics and the acquire and release accesses
/// default to sequences of those, which is correct for memory that only one interpreter reaches; override them for
/// speed, and for memory shared between threads. A memory that hands out [`Window`]s also provides
/// [`window`](Self::window) and [`epoch`](Self::epoch).
///
/// # Safety
///
/// The interpreter accesses the host memory behind a [`Window`] from [`Memory::window`] without calling the other
/// methods, for as long as [`Memory::epoch`] returns the window's epoch. Each window must meet the contract of
/// [`Window::new`] whenever the memory is at the window's epoch. So an implementation must give each change of the
/// host memory behind its windows an epoch that no memory used before, and 0, the default, only to empty windows.
///
/// The interpreter checks the windows it holds against the epoch only when a run starts and after a
/// [`Host`](crate::Host) call, so no method of this trait may change what [`Memory::epoch`] returns. Change the epoch
/// only between runs or inside a host call.
///
/// An implementation that keeps the defaults of `window` and `epoch` meets all of this.
pub unsafe trait Memory {
    /// Why a load or store failed. [`Reason::MemoryFault`](crate::Reason::MemoryFault) carries it, so keep it small,
    /// ideally 8 bytes or less.
    type Error;

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Error>;
    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Error>;

    fn load_u16(&self, addr: u64) -> Result<u16, Self::Error> {
        let lo = self.load_u8(addr)? as u16;
        let hi = self.load_u8(addr.wrapping_add(1))? as u16;
        Ok(lo | hi << 8)
    }

    fn load_u32(&self, addr: u64) -> Result<u32, Self::Error> {
        let lo = self.load_u16(addr)? as u32;
        let hi = self.load_u16(addr.wrapping_add(2))? as u32;
        Ok(lo | hi << 16)
    }

    fn load_u64(&self, addr: u64) -> Result<u64, Self::Error> {
        let lo = self.load_u32(addr)? as u64;
        let hi = self.load_u32(addr.wrapping_add(4))? as u64;
        Ok(lo | hi << 32)
    }

    fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Error> {
        self.store_u8(addr, value as u8)?;
        self.store_u8(addr.wrapping_add(1), (value >> 8) as u8)
    }

    fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Error> {
        self.store_u16(addr, value as u16)?;
        self.store_u16(addr.wrapping_add(2), (value >> 16) as u16)
    }

    fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Error> {
        self.store_u32(addr, value as u32)?;
        self.store_u32(addr.wrapping_add(4), (value >> 32) as u32)
    }

    /// Apply `op` to the `u32` at `addr` and return the previous value.
    ///
    /// The default is a load followed by a store, which is atomic for memory that only one interpreter reaches.
    fn atomic_u32(&mut self, addr: u64, op: AtomicOp<u32>) -> Result<u32, Self::Error> {
        let old = self.load_u32(addr)?;
        if let Some(new) = op.apply(old) {
            self.store_u32(addr, new)?;
        }
        Ok(old)
    }

    /// Apply `op` to the `u64` at `addr` and return the previous value. See [`Memory::atomic_u32`].
    fn atomic_u64(&mut self, addr: u64, op: AtomicOp<u64>) -> Result<u64, Self::Error> {
        let old = self.load_u64(addr)?;
        if let Some(new) = op.apply(old) {
            self.store_u64(addr, new)?;
        }
        Ok(old)
    }

    /// Load the `u8` at `addr` with acquire ordering, for `load_acquire`.
    ///
    /// The acquire loads and release stores default to the plain loads and stores. Like [`Memory::atomic_u32`], the
    /// defaults don't check alignment; an override for memory shared between threads should fail misaligned addresses
    /// as its atomics do.
    fn load_acquire_u8(&self, addr: u64) -> Result<u8, Self::Error> {
        self.load_u8(addr)
    }

    /// See [`Memory::load_acquire_u8`].
    fn load_acquire_u16(&self, addr: u64) -> Result<u16, Self::Error> {
        self.load_u16(addr)
    }

    /// See [`Memory::load_acquire_u8`].
    fn load_acquire_u32(&self, addr: u64) -> Result<u32, Self::Error> {
        self.load_u32(addr)
    }

    /// See [`Memory::load_acquire_u8`].
    fn load_acquire_u64(&self, addr: u64) -> Result<u64, Self::Error> {
        self.load_u64(addr)
    }

    /// Store `value` at `addr` with release ordering, for `store_release`. See [`Memory::load_acquire_u8`].
    fn store_release_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Error> {
        self.store_u8(addr, value)
    }

    /// See [`Memory::store_release_u8`].
    fn store_release_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Error> {
        self.store_u16(addr, value)
    }

    /// See [`Memory::store_release_u8`].
    fn store_release_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Error> {
        self.store_u32(addr, value)
    }

    /// See [`Memory::store_release_u8`].
    fn store_release_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Error> {
        self.store_u64(addr, value)
    }

    /// The host memory that plain loads and stores near `addr` may access directly. The interpreter asks for the
    /// window around r10, and for the window around the address of a load or store that falls outside the windows it
    /// holds. It runs the plain loads and stores that fall inside its windows without calling the methods above, and
    /// uses a window only while the memory is at the window's epoch. The default is [`Window::NONE`].
    fn window(&self, addr: u64) -> Window {
        let _ = addr;
        Window::NONE
    }

    /// The epoch of the windows this memory reports now. The safety section of [`Memory`] states the rules for epochs.
    fn epoch(&self) -> u64 {
        0
    }

    /// The host address of the `len` bytes at guest address `addr`, which the native function of a checked native
    /// call ([`Code::bind_native`](crate::Code::bind_native)) gets in place of `addr` and reads, or with `write` reads
    /// and writes. Fails with the error of the first of those bytes the guest may not access so.
    ///
    /// When `len` is 0, implementations should return a canonical non-null, aligned dangling address (such as `16`)
    /// rather than forwarding an unchecked or null guest pointer, so Rust and C natives can pass the pointer directly
    /// to zero-length slice or byte operations without undefined behavior.
    ///
    /// The host bytes must stay valid for that access until the memory next changes its mapping, which no native
    /// function can do, and the address must carry provenance independent of any `&self`/`&mut self` reference to the
    /// memory (as [`Window::new`] requires), so subsequent `&mut self` calls on the memory cannot invalidate it. They
    /// may instead be host memory that the embedder lets the guest name directly, as a [`Window`] may cover.
    fn native_ptr(&self, addr: u64, len: u64, write: bool) -> Result<u64, Self::Error>;
}

/// A read-modify-write operation for [`Memory::atomic_u32`] and [`Memory::atomic_u64`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOp<T> {
    Add(T),
    Or(T),
    And(T),
    Xor(T),
    Xchg(T),
    /// Store `new` if the current value equals `expected`.
    CmpXchg {
        expected: T,
        new: T,
    },
}

macro_rules! atomic_op_apply {
    ($($ty:ty),*) => {$(
        impl AtomicOp<$ty> {
            /// The value to store given the current value `old`, or `None` to leave it.
            #[inline(always)]
            pub fn apply(self, old: $ty) -> Option<$ty> {
                Some(match self {
                    Self::Add(v) => old.wrapping_add(v),
                    Self::Or(v) => old | v,
                    Self::And(v) => old & v,
                    Self::Xor(v) => old ^ v,
                    Self::Xchg(v) => v,
                    Self::CmpXchg { expected, new } => return (old == expected).then_some(new),
                })
            }
        }
    )*};
}

atomic_op_apply!(u32, u64);

/// Host memory that guest loads and stores near some address reach directly; see [`Memory::window`].
#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub(crate) base: u64,
    pub(crate) ptr: *mut u8,
    pub(crate) read_len: u64,
    pub(crate) write_len: u64,
    pub(crate) epoch: u64,
}

impl Window {
    /// No window: every access goes through the [`Memory`] methods.
    pub const NONE: Self = Self {
        base: 0,
        ptr: ptr::null_mut(),
        read_len: 0,
        write_len: 0,
        epoch: 0,
    };

    /// The `read_len` readable and `write_len` writable bytes at guest address `base`, which are the host bytes at
    /// `ptr`, valid while the memory's [`Memory::epoch`] is `epoch`. The interpreter exposes the provenance of `ptr`
    /// and reaches the bytes through pointers made from their addresses with [`ptr::with_exposed_provenance_mut`].
    ///
    /// # Safety
    ///
    /// Whenever the memory that reports the window is at epoch `epoch`, `ptr` must be valid for reads of `read_len`
    /// bytes and for writes of `write_len` bytes, and a guest load (store) of `n` bytes at `base + i` with
    /// `i + n <= read_len` (`write_len`) on that memory must do nothing but read (write) the `n` bytes at `ptr + i`,
    /// unaligned and little-endian. `ptr` must not come from a reference to the memory, which a call of a [`Memory`]
    /// method would invalidate. [`Memory`] states the rules for epochs.
    ///
    /// A window may instead cover host addresses that the embedder lets the guest name directly, with a `ptr` of
    /// exposed provenance ([`ptr::with_exposed_provenance_mut`]). The bytes there needn't be valid: the embedder
    /// answers for every access the guest makes, as it would for native code.
    pub const unsafe fn new(base: u64, ptr: *mut u8, read_len: u64, write_len: u64, epoch: u64) -> Self {
        Self {
            base,
            ptr,
            read_len,
            write_len,
            epoch,
        }
    }
}
