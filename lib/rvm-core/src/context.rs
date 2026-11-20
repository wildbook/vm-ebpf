//! The guest state: [`Context`].

use crate::Memory;

/// The state of the guest that instructions read and write: its registers and its memory.
// Aligned to 16 bytes with the registers first, as the frames of the interpreter are: `call` and `exit` move r6 to
// r10 16 bytes at a time, and a move that crosses a cache line costs them several cycles.
#[derive(Debug)]
#[repr(C, align(16))]
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
