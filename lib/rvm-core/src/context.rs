//! The guest state: [`Context`].

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ptr;

use crate::slot::Reg;
use crate::step::Regs;
use crate::Memory;

/// Number of architectural eBPF registers (r0 to r15).
pub const ARCH_REGS: usize = 16;

/// Number of virtual registers reserved for promoted stack slots (r16 to r47).
pub const VIRT_REGS: usize = 32;

/// Total register slots addressable by [`Reg`] inside [`Context`].
pub const TOTAL_REGS: usize = ARCH_REGS + VIRT_REGS;

/// The state of the guest that instructions read and write: its registers and its memory.
// Aligned to 16 bytes with the registers first, as the frames of the interpreter are: `call` and `exit` move r6 to
// r10 16 bytes at a time, and a move that crosses a cache line costs them several cycles.
#[repr(C, align(16))]
pub struct Context<'a, M: Memory> {
    /// The registers:
    /// - r0: the return value of function calls, and the exit value of the program
    /// - r1 to r5: the arguments of function calls
    /// - r6 to r9: callee-saved registers, which function calls preserve
    /// - r10: the frame pointer, which guest code can't write
    /// - r11 to r15: unused; a 4-bit register index into 16 entries needs no bounds check
    pub regs: [u64; ARCH_REGS],
    /// Uninitialized virtual register slots (r16 to r47) for promoted non-escaping `r10` stack slots.
    virt: [MaybeUninit<u64>; VIRT_REGS],
    /// The guest memory.
    pub memory: &'a mut M,
}

const _: () = assert!(align_of::<[MaybeUninit<u64>; VIRT_REGS]>() == align_of::<u64>());

impl<M: Memory + Debug> Debug for Context<'_, M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("regs", &self.regs)
            .field("memory", &self.memory)
            .finish()
    }
}

impl<'a, M: Memory> Context<'a, M> {
    /// Registers of 0 over `memory`.
    pub const fn new(memory: &'a mut M) -> Self {
        Self {
            regs: [0; ARCH_REGS],
            virt: [MaybeUninit::uninit(); VIRT_REGS],
            memory,
        }
    }

    /// Read architectural or virtual register `reg` (`0..TOTAL_REGS`).
    #[inline(always)]
    pub(crate) fn reg_get(&self, reg: Reg) -> u64 {
        // SAFETY: `regs` and `virt` are contiguous at offset 0 of `#[repr(C)] Context`, `reg.get() < TOTAL_REGS`,
        // and virtual slots are initialized before entering promoted code.
        unsafe { *ptr::from_ref(self).cast::<u64>().add(usize::from(reg.get())) }
    }

    /// Write architectural or virtual register `reg` (`0..TOTAL_REGS`).
    #[inline(always)]
    pub(crate) fn reg_set(&mut self, reg: Reg, value: u64) {
        // SAFETY: `regs` and `virt` are contiguous at offset 0 of `#[repr(C)] Context` and `reg.get() < TOTAL_REGS`.
        unsafe { *ptr::from_mut(self).cast::<u64>().add(usize::from(reg.get())) = value }
    }

    /// Write virtual register `index` (`0..VIRT_REGS`).
    #[inline(always)]
    pub(crate) fn set_virt(&mut self, index: usize, value: u64) {
        debug_assert!(index < VIRT_REGS);
        // SAFETY: `index < VIRT_REGS`.
        unsafe { self.virt.get_unchecked_mut(index).write(value) };
    }

    /// Read virtual register `index` (`0..VIRT_REGS`).
    ///
    /// # Safety
    ///
    /// Virtual register `index` must have been initialized by [`Self::set_virt`].
    #[inline(always)]
    pub(crate) unsafe fn get_virt(&self, index: usize) -> u64 {
        debug_assert!(index < VIRT_REGS);
        // SAFETY: `index < VIRT_REGS` and caller guarantees initialization.
        unsafe { self.virt.get_unchecked(index).assume_init() }
    }

    /// Read-only [`RegView`] covering `regs` + `virt` without touching `memory`.
    #[inline(always)]
    pub(crate) fn regs_view(&self) -> RegView<'_> {
        RegView(ptr::from_ref(self).cast::<u64>().cast_mut(), PhantomData)
    }

    /// Mutable [`RegView`] covering `regs` + `virt` without touching `memory`.
    #[inline(always)]
    pub(crate) fn regs_view_mut(&mut self) -> RegView<'_> {
        RegView(ptr::from_mut(self).cast::<u64>(), PhantomData)
    }

    /// Split into a [`RegView`] covering `regs` + `virt` and the mutable guest memory reference.
    #[inline(always)]
    pub(crate) fn split_mut(&mut self) -> (RegView<'_>, &mut M) {
        let raw = ptr::from_mut(self);
        // SAFETY: `memory` points to external `M`, disjoint from the `[0..TOTAL_REGS * 8)` register prefix.
        // `RegView` accesses only that prefix and never touches `memory` after this read.
        let mem = unsafe { &mut **ptr::addr_of_mut!((*raw).memory) };
        (RegView(raw.cast::<u64>(), PhantomData), mem)
    }
}

/// Mutable register view over [`Context::regs`] and [`Context::virt`] with provenance covering both arrays.
pub struct RegView<'a>(*mut u64, PhantomData<&'a mut [u64; TOTAL_REGS]>);

impl Regs for RegView<'_> {
    #[inline(always)]
    fn get(&self, reg: Reg) -> u64 {
        // SAFETY: `reg.get() < TOTAL_REGS`, and virtual slots are initialized before entering promoted code.
        unsafe { *self.0.add(usize::from(reg.get())) }
    }

    #[inline(always)]
    fn set(&mut self, reg: Reg, value: u64) {
        // SAFETY: `reg.get() < TOTAL_REGS`.
        unsafe { *self.0.add(usize::from(reg.get())) = value }
    }
}

/// The index of the frame pointer, r10, in [`Context::regs`].
pub const FP: usize = 10;
