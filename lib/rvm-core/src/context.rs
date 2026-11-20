//! The guest state: [`Context`].

use crate::Memory;

/// The state of the guest that instructions read and write: its registers and its memory.
#[derive(Debug)]
pub struct Context<'a, M: Memory> {
    /// The registers:
    /// - r0: the return value of function calls, and the exit value of the program
    /// - r1 to r5: the arguments of function calls
    /// - r6 to r9: callee-saved registers, which function calls preserve
    /// - r10: the frame pointer, which guest code can't write
    /// - r11 to r15: unused; a 4-bit register index into 16 entries needs no bounds check
    pub regs: [u64; 16],
    /// The guest memory.
    pub memory: &'a mut M,
}

impl<'a, M: Memory> Context<'a, M> {
    /// Registers of 0 over `memory`.
    pub const fn new(memory: &'a mut M) -> Self {
        Self { regs: [0; 16], memory }
    }
}

/// The index of the frame pointer, r10, in [`Context::regs`].
pub const FP: usize = 10;
