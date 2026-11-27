//! What one instruction does: [`step`] runs it on the registers and the memory and returns a [`Step`], which says how
//! execution goes on. The handlers call `step` with a constant opcode, so each one keeps only the code of its own
//! instruction.

mod alu;
mod jump;
mod mem;
#[cfg(test)]
mod tests;

pub use alu::alu;
pub use jump::jump;
pub use mem::{address, ld};

use crate::opcode::{Class, Source, LD_IMM64};
use crate::slot::{Fields, Reg};
use crate::{Memory, Reason};

/// The width that an ALU or jump instruction works on, by class.
pub const BITS_32: bool = false;
pub const BITS_64: bool = true;

/// How execution goes on after an instruction, as [`step`] reports it.
#[derive(Debug, PartialEq, Eq)]
pub enum Step<E> {
    /// With the next instruction.
    Next,
    /// With the instruction this many slots from the next one.
    Jump(i64),
    /// In the local function this many slots from the next instruction.
    Call(i64),
    /// In the caller, or nowhere in the entry frame.
    Exit,
    /// With the helper in `imm`.
    CallHelper,
    /// With the external function in `imm`.
    CallKfunc,
    /// With the function at the address in `dst_reg`.
    CallIndirect,
    /// With the next instruction, once [`ld_imm64`] has loaded the immediate, whose upper half the next slot holds.
    LdImm64,
    /// Nowhere.
    Stop(Reason<E>),
}

impl<E> Step<E> {
    pub const INVALID: Self = Step::Stop(Reason::InvalidInstruction);
}

/// An instruction that can't jump or call goes on with the next one or stops.
impl<E> From<Result<(), Reason<E>>> for Step<E> {
    #[inline(always)]
    fn from(result: Result<(), Reason<E>>) -> Self {
        match result {
            Ok(()) => Step::Next,
            Err(reason) => Step::Stop(reason),
        }
    }
}

/// The registers an instruction reads and writes, by the number in its `dst_reg` or `src_reg` field.
pub trait Regs {
    fn get(&self, reg: Reg) -> u64;
    fn set(&mut self, reg: Reg, value: u64);
}

// A pointer access, which unlike indexing or `get_unchecked` tells LLVM nothing about the range of `reg`: knowing it,
// LLVM extracts a register byte from the slot in RCX with a shift and a mask where a single `movzx` from CH does.
impl Regs for [u64; 16] {
    #[inline(always)]
    fn get(&self, reg: Reg) -> u64 {
        // SAFETY: a `Reg` in unpromoted code is below 16 (see `slot::Reg`)
        unsafe { *self.as_ptr().add(usize::from(reg.get())) }
    }

    #[inline(always)]
    fn set(&mut self, reg: Reg, value: u64) {
        // SAFETY: a `Reg` in unpromoted code is below 16 (see `slot::Reg`)
        unsafe { *self.as_mut_ptr().add(usize::from(reg.get())) = value }
    }
}

/// Runs the instruction `insn` on `regs` and `memory`.
#[inline(always)]
pub fn step<M: Memory, R: Regs, I: Fields>(regs: &mut R, memory: &mut M, insn: I) -> Step<M::Error> {
    use mem::{SOURCE_IMM, SOURCE_REG};

    match insn.opcode().class() {
        Class::Alu32 => alu::alu::<_, _, BITS_32>(regs, insn).into(),
        Class::Alu64 => alu::alu::<_, _, BITS_64>(regs, insn).into(),

        Class::Jmp32 => jump::<_, _, BITS_32>(regs, insn),
        Class::Jmp64 => jump::<_, _, BITS_64>(regs, insn),

        Class::Ld => mem::ld(insn),
        Class::Ldx => mem::load(regs, memory, insn).into(),

        Class::St => mem::store::<_, _, SOURCE_IMM>(regs, memory, insn).into(),
        Class::Stx => mem::store::<_, _, SOURCE_REG>(regs, memory, insn).into(),
    }
}

/// Loads the immediate of the LD_IMM64 `insn`, whose second slot holds the upper half `upper`.
#[inline(always)]
pub fn ld_imm64(regs: &mut impl Regs, insn: impl Fields, upper: i32) {
    debug_assert!(insn.opcode().0 == LD_IMM64 && insn.src_reg() == Reg::R0);

    let imm_lo = insn.imm() as u32 as u64;
    let imm_hi = upper as u32 as u64;
    regs.set(insn.dst_reg(), imm_lo | (imm_hi << 32));
}

/// The operands of the ALU or jump instruction `insn` on `BITS` bits: `dst_reg`, and `src_reg` or `imm` as its
/// source bit selects, cut to `BITS` bits.
#[inline(always)]
fn operands<R: Regs, const BITS: bool>(regs: &R, insn: impl Fields) -> (u64, u64) {
    let d = truncate::<BITS>(regs.get(insn.dst_reg()));
    let s = match (insn.opcode().source(), BITS) {
        (Source::Imm, BITS_64) => insn.imm() as i64 as u64,
        (Source::Imm, BITS_32) => insn.imm() as u32 as u64,
        (Source::Reg, _) => truncate::<BITS>(regs.get(insn.src_reg())),
    };
    (d, s)
}

/// `x` cut to `BITS` bits.
#[inline(always)]
fn truncate<const BITS: bool>(x: u64) -> u64 {
    match BITS {
        BITS_64 => x,
        BITS_32 => x as u32 as u64,
    }
}
