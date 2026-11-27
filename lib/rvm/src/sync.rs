//! Locks. The std locks here ignore poisoning: every structure behind them stays valid if a holder panics.
//! [`TryLock`] never waits, and [`Published`] spins on one only for an `Arc` clone or swap.

use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(feature = "maps")]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(feature = "maps")]
pub fn read<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

#[cfg(feature = "maps")]
pub fn write<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
}

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// A lock that fails instead of waiting while it is held.
///
/// Invariant: `value` is only accessed through a [`TryLockGuard`], and at most one guard exists at a time. A guard
/// exists only after its `try_lock` changed `locked` from false to true, and its drop sets `locked` to false again.
/// The Acquire compare-exchange pairs with the Release store of the previous guard, so each guard sees every write the
/// previous guard made to `value`.
pub struct TryLock<T> {
    locked: AtomicBool,
    value: UnsafeCell<T>,
}

// SAFETY: by the invariant, one thread at a time accesses `value`, as with `Mutex<T>`.
unsafe impl<T: Send> Sync for TryLock<T> {}

impl<T> TryLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
        }
    }

    /// Exclusive access to the value, or `None` while another guard holds it.
    #[inline]
    pub fn try_lock(&self) -> Option<TryLockGuard<'_, T>> {
        self.locked.compare_exchange(false, true, Acquire, Relaxed).ok()?;
        Some(TryLockGuard {
            lock: self,
            value: PhantomData,
        })
    }
}

/// Exclusive access to a locked value, such as a plugin's program from [`Plugin::lock`](crate::Plugin::lock); unlocks
/// when dropped.
pub struct TryLockGuard<'a, T> {
    lock: &'a TryLock<T>,
    // makes the guard `Send` and `Sync` exactly when `&mut T` is
    value: PhantomData<&'a mut T>,
}

impl<T> Deref for TryLockGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: this guard is the only one (see `TryLock`), and `&self` keeps it alive.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for TryLockGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this guard is the only one (see `TryLock`), and `&mut self` keeps it alive and borrowed.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for TryLockGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.locked.store(false, Release);
    }
}

/// An `Arc<T>` that readers clone and writers replace, behind a [`TryLock`] held only for that clone or swap. Neither
/// waits on the other's work, and nothing here needs an OS lock or wait primitive.
pub struct Published<T: ?Sized> {
    value: TryLock<Arc<T>>,
}

impl<T: ?Sized> Published<T> {
    pub fn new(value: Arc<T>) -> Self {
        Self {
            value: TryLock::new(value),
        }
    }

    /// The current value.
    pub fn get(&self) -> Arc<T> {
        self.with(|value| value.clone())
    }

    /// Publish `value` and return the previous one, which the caller drops outside the lock.
    pub fn replace(&self, value: Arc<T>) -> Arc<T> {
        self.with(|current| std::mem::replace(current, value))
    }

    fn with<R>(&self, f: impl FnOnce(&mut Arc<T>) -> R) -> R {
        loop {
            if let Some(mut value) = self.value.try_lock() {
                return f(&mut value);
            }
            std::hint::spin_loop();
        }
    }
}

impl<T: ?Sized> Default for Published<T>
where
    Arc<T>: Default,
{
    fn default() -> Self {
        Self::new(Arc::default())
    }
}

impl<T: ?Sized + std::fmt::Debug> std::fmt::Debug for Published<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}
