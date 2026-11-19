use crate::Window;

/// The guest memory that [`run`] loads from and stores to.
///
/// # Safety
///
/// [`run`] accesses the host memory behind a [`Window`] from [`Memory::window`] without calling the other methods,
/// for as long as [`Memory::epoch`] returns the window's epoch. Each window must meet the contract of [`Window::new`]
/// whenever the memory is at the window's epoch. So an implementation must give each change of the host memory behind
/// its windows an epoch that no memory used before, and 0, the default, only to empty windows.
///
/// [`run`] checks the windows it holds against the epoch only when it starts and after a [`Host`] call, so no method of
/// this trait may change what [`Memory::epoch`] returns. Change the epoch only outside [`run`] or inside a host call.
///
/// [`run`]: crate::run
/// [`Host`]: crate::Host
pub unsafe trait Memory {
    /// [`Flow::FailMem`](crate::Flow::FailMem) carries this, so keep it small, ideally 8 bytes or less.
    type Err;

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Err>;
    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err>;

    fn load_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        let lo = self.load_u8(addr)? as u16;
        let hi = self.load_u8(addr.wrapping_add(1))? as u16;
        Ok(lo | hi << 8)
    }

    fn load_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        let lo = self.load_u16(addr)? as u32;
        let hi = self.load_u16(addr.wrapping_add(2))? as u32;
        Ok(lo | hi << 16)
    }

    fn load_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        let lo = self.load_u32(addr)? as u64;
        let hi = self.load_u32(addr.wrapping_add(4))? as u64;
        Ok(lo | hi << 32)
    }

    fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        self.store_u8(addr, value as u8)?;
        self.store_u8(addr.wrapping_add(1), (value >> 8) as u8)
    }

    fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        self.store_u16(addr, value as u16)?;
        self.store_u16(addr.wrapping_add(2), (value >> 16) as u16)
    }

    fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        self.store_u32(addr, value as u32)?;
        self.store_u32(addr.wrapping_add(4), (value >> 32) as u32)
    }

    /// Apply `op` to the `u32` at `addr` and return the previous value.
    ///
    /// The default is a load followed by a store, which is atomic for memory only this executor can reach. Override it
    /// for memory shared with other threads.
    fn atomic_u32(&mut self, addr: u64, op: AtomicOp<u32>) -> Result<u32, Self::Err> {
        let old = self.load_u32(addr)?;
        if let Some(new) = op.apply(old) {
            self.store_u32(addr, new)?;
        }
        Ok(old)
    }

    /// Apply `op` to the `u64` at `addr` and return the previous value. See [`Memory::atomic_u32`].
    fn atomic_u64(&mut self, addr: u64, op: AtomicOp<u64>) -> Result<u64, Self::Err> {
        let old = self.load_u64(addr)?;
        if let Some(new) = op.apply(old) {
            self.store_u64(addr, new)?;
        }
        Ok(old)
    }

    /// Load the `u8` at `addr` with acquire ordering, for `load_acquire`.
    ///
    /// The acquire loads and release stores default to the plain loads and stores, which are enough for memory only
    /// this executor can reach. Like [`Memory::atomic_u32`], the defaults don't check alignment; an override for
    /// memory shared with other threads should fail misaligned addresses as its atomics do.
    fn load_acquire_u8(&self, addr: u64) -> Result<u8, Self::Err> {
        self.load_u8(addr)
    }

    /// See [`Memory::load_acquire_u8`].
    fn load_acquire_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        self.load_u16(addr)
    }

    /// See [`Memory::load_acquire_u8`].
    fn load_acquire_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        self.load_u32(addr)
    }

    /// See [`Memory::load_acquire_u8`].
    fn load_acquire_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        self.load_u64(addr)
    }

    /// Store `value` at `addr` with release ordering, for `store_release`. See [`Memory::load_acquire_u8`].
    fn store_release_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
        self.store_u8(addr, value)
    }

    /// See [`Memory::store_release_u8`].
    fn store_release_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        self.store_u16(addr, value)
    }

    /// See [`Memory::store_release_u8`].
    fn store_release_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        self.store_u32(addr, value)
    }

    /// See [`Memory::store_release_u8`].
    fn store_release_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        self.store_u64(addr, value)
    }

    /// The host memory that loads and stores near `addr` may access directly. [`run`](crate::run) takes the window
    /// around r10, and the window around the address of a 4 or 8 byte load or store through another register that falls
    /// outside its windows. It runs the 4 and 8 byte loads and stores that fall inside these windows without calling
    /// the methods above, until [`Memory::epoch`] changes, and uses a window only while the memory is at the window's
    /// epoch. The default is [`Window::NONE`].
    fn window(&self, addr: u64) -> Window {
        let _ = addr;
        Window::NONE
    }

    /// The epoch of the windows this memory reports now. The safety section of [`Memory`] states the rules for epochs.
    fn epoch(&self) -> u64 {
        0
    }
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

// SAFETY: every method forwards to `M`, so the windows and epochs are those of `M`
unsafe impl<M: Memory + ?Sized> Memory for &mut M {
    type Err = M::Err;

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Err> {
        (**self).load_u8(addr)
    }
    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
        (**self).store_u8(addr, value)
    }
    fn load_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        (**self).load_u16(addr)
    }
    fn load_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        (**self).load_u32(addr)
    }
    fn load_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        (**self).load_u64(addr)
    }
    fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        (**self).store_u16(addr, value)
    }
    fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        (**self).store_u32(addr, value)
    }
    fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        (**self).store_u64(addr, value)
    }
    fn atomic_u32(&mut self, addr: u64, op: AtomicOp<u32>) -> Result<u32, Self::Err> {
        (**self).atomic_u32(addr, op)
    }
    fn atomic_u64(&mut self, addr: u64, op: AtomicOp<u64>) -> Result<u64, Self::Err> {
        (**self).atomic_u64(addr, op)
    }
    fn load_acquire_u8(&self, addr: u64) -> Result<u8, Self::Err> {
        (**self).load_acquire_u8(addr)
    }
    fn load_acquire_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        (**self).load_acquire_u16(addr)
    }
    fn load_acquire_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        (**self).load_acquire_u32(addr)
    }
    fn load_acquire_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        (**self).load_acquire_u64(addr)
    }
    fn store_release_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err> {
        (**self).store_release_u8(addr, value)
    }
    fn store_release_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        (**self).store_release_u16(addr, value)
    }
    fn store_release_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        (**self).store_release_u32(addr, value)
    }
    fn store_release_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        (**self).store_release_u64(addr, value)
    }
    fn window(&self, addr: u64) -> Window {
        (**self).window(addr)
    }
    fn epoch(&self) -> u64 {
        (**self).epoch()
    }
}
