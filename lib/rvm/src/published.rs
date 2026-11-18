//! A shared value that readers take a reference to and writers replace whole.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// An `Arc<T>` that readers clone and writers replace, behind a spin lock held only for that clone or swap. Neither
/// waits on the other's work, and nothing here needs the OS to park a thread.
pub struct Published<T: ?Sized> {
    locked: AtomicBool,
    value: UnsafeCell<Arc<T>>,
}

// SAFETY: `value` is only accessed in `with`, while the calling thread holds `locked`; sharing the `Published` shares
// the `Arc<T>`, which needs `T: Send + Sync`.
unsafe impl<T: ?Sized + Send + Sync> Sync for Published<T> {}

impl<T: ?Sized> Published<T> {
    pub fn new(value: Arc<T>) -> Self {
        Self {
            locked: AtomicBool::new(false),
            value: UnsafeCell::new(value),
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

    // `f` only clones or swaps an `Arc`, which can't panic and leave the lock held
    fn with<R>(&self, f: impl FnOnce(&mut Arc<T>) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        // SAFETY: see `impl Sync`; this thread holds `locked`
        let result = f(unsafe { &mut *self.value.get() });
        self.locked.store(false, Ordering::Release);
        result
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
