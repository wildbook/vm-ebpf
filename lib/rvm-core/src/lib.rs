#![feature(explicit_tail_calls, rust_preserve_none_cc)]
#![allow(incomplete_features)]

use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::ControlFlow;

use opcode::{Class, MemMode, MemSize, OpCode};

mod debug;
mod fuse;
mod stack;

pub mod opcode;

pub use fuse::Code;
pub use stack::Window;

#[cfg(test)]
mod tests;

// https://www.rfc-editor.org/rfc/rfc9669.html

#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Instruction(pub u64);

/// Decode little-endian bytecode (a trailing partial word is ignored) and prepare it for [`run`].
pub fn instructions_from_bytes(bytes: &[u8]) -> Code {
    let insns: Box<[Instruction]> = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|w| Instruction(u64::from_le_bytes(*w)))
        .collect();
    Code::new(insns)
}

impl Instruction {
    pub const fn imm(self) -> i32 {
        ((self.0 & 0xFFFFFFFF00000000) >> 32) as i32
    }

    pub const fn offset(self) -> i16 {
        ((self.0 & 0x00000000FFFF0000) >> 16) as i16
    }

    pub const fn src_reg(self) -> u8 {
        ((self.0 & 0x000000000000F000) >> 12) as u8
    }

    pub const fn dst_reg(self) -> u8 {
        ((self.0 & 0x0000000000000F00) >> 8) as u8
    }

    pub const fn opcode(self) -> OpCode {
        OpCode((self.0 & 0x00000000000000FF) as u8)
    }
}

impl Instruction {
    pub const fn from_parts(opc: OpCode, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        const _: () = assert!(Instruction::from_parts(OpCode(0xFF), 0x00, 0x00, 00, 00).0 == 0x00000000000000FF);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x0F, 0x00, 00, 00).0 == 0x0000000000000F00);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x00, 0x0F, 00, 00).0 == 0x000000000000F000);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x00, 0x00, -1, 00).0 == 0x00000000FFFF0000);
        const _: () = assert!(Instruction::from_parts(OpCode(0x00), 0x00, 0x00, 00, -1).0 == 0xFFFFFFFF00000000);

        let imm = (imm as u32 as u64) << 32;
        let off = (off as u16 as u64) << 16;
        let src = (src as u64) << 12;
        let dst = (dst as u64) << 8;
        let opc = opc.0 as u64;

        Self(imm | off | src | dst | opc)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Flow<C: Memory> {
    Next,

    Jump(i64),
    /// A program-local call, with the offset of the callee.
    Call(i64),
    Exit,

    /// Call a helper by its numeric ID (`src_reg = 0`).
    CallHelper(u32),
    /// Call an external function by ID (`src_reg = BPF_PSEUDO_KFUNC_CALL`); the runtime defines what the ID indexes
    /// (rvm: the program's extern table).
    CallKfunc(u32),

    /// An invalid or reserved instruction.
    FailCpu,
    FailMem(C::Err),

    /// A valid instruction that rvm doesn't implement.
    Missing,
    /// [`run`] used up its instruction budget before the next instruction. Only with the `fuel` feature.
    OutOfFuel,
    /// [`run`] reached a `pc` outside the code slice.
    BadPc,
    /// A local call found all [`MAX_CALL_DEPTH`] frames in use, or `r10` below the frame size.
    StackOverflow,

    /// `callx`: call through the address in `dst_reg`, which the runtime decodes.
    CallIndirect(u64),
    /// `gotox`: jump to the address in `dst_reg`, which the runtime decodes.
    JumpIndirect(u64),
}

pub trait Memory {
    /// [`Flow::FailMem`] carries this, so keep it small, ideally 8 bytes or less.
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

    /// The host memory that loads and stores near `addr` may access directly. [`run`] takes the window around r10 and
    /// runs 4 and 8 byte loads and stores through r10 that fall inside it without calling the methods above, until
    /// [`Memory::epoch`] changes. The default is [`Window::NONE`].
    fn window(&self, addr: u64) -> Window {
        let _ = addr;
        Window::NONE
    }

    /// The epoch of the windows this memory reports now; see [`Window::new`].
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

impl<M: Memory + ?Sized> Memory for &mut M {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<M: Memory> {
    // R0: return value from function calls, and exit value for eBPF programs
    // R1 - R5: arguments for function calls
    // R6 - R9: callee saved registers that function calls will preserve
    // R10: read-only frame pointer to access stack
    // R11 - R15: unused; a 4-bit register index into 16 slots needs no bounds check
    pub regs: [u64; 16],
    pub data: M,
}

impl<M: Memory> Context<M> {
    pub const fn new(data: M) -> Self {
        Self { regs: [0; 16], data }
    }
}

/// `src_reg` of a `call` instruction targeting a program-local function.
pub const BPF_PSEUDO_CALL: usize = 1;
/// `src_reg` of a `call` instruction targeting the host's extern table.
pub const BPF_PSEUDO_KFUNC_CALL: usize = 2;

mod ops {
    use crate::opcode::{AluEnd, AluOpc, JmpOpc, Source};
    use crate::{Context, Flow, Instruction, Memory, BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL};

    pub const BITS_32: bool = false;
    pub const BITS_64: bool = true;

    #[inline(always)]
    pub fn math<M: Memory, const BITS: bool>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M> {
        let opc = insn.opcode();
        let alu_opc = opc.alu_opc();
        let alu_src = opc.alu_src();
        let alu_end = opc.alu_end();

        let src_reg = insn.src_reg() as usize;
        let dst_reg = insn.dst_reg() as usize;

        let imm = insn.imm();
        let offset = insn.offset();

        let d = match BITS {
            BITS_64 => ctx.regs[dst_reg],
            BITS_32 => ctx.regs[dst_reg] & 0xFFFFFFFF,
        };

        let s = match (alu_src, BITS) {
            (Source::Imm, BITS_64) => imm as i64 as u64,
            // ALU32 treats the immediate as a 32-bit value.
            (Source::Imm, BITS_32) => imm as u32 as u64,
            (Source::Reg, BITS_64) => ctx.regs[src_reg],
            (Source::Reg, BITS_32) => ctx.regs[src_reg] & 0xFFFFFFFF,
        };

        let result = match alu_opc {
            AluOpc::Add => d.wrapping_add(s),
            AluOpc::Sub => d.wrapping_sub(s),
            AluOpc::Mul => d.wrapping_mul(s),
            // DIV (offset=0) or SDIV (offset=1)
            AluOpc::Div => match (offset, BITS) {
                (0, _) => d.checked_div(s).unwrap_or(0),
                (1, BITS_64) => {
                    let ds = d as i64;
                    let ss = s as i64;
                    if ss == 0 {
                        0
                    } else if ss == -1 && ds == i64::MIN {
                        i64::MIN as u64
                    } else {
                        (ds / ss) as u64
                    }
                }
                (1, BITS_32) => {
                    let ds = d as i32;
                    let ss = s as i32;
                    if ss == 0 {
                        0
                    } else if ss == -1 && ds == i32::MIN {
                        i32::MIN as u64
                    } else {
                        (ds / ss) as u64
                    }
                }
                _ => return Flow::FailCpu,
            },
            AluOpc::Or => d | s,
            AluOpc::And => d & s,
            AluOpc::Lsh => match BITS {
                BITS_64 => d << (s & 63),
                BITS_32 => d << (s & 31),
            },
            AluOpc::Rsh => match BITS {
                BITS_64 => d >> (s & 63),
                BITS_32 => d >> (s & 31),
            },
            AluOpc::Neg => d.wrapping_neg(),
            // MOD (offset=0) or SMOD (offset=1)
            AluOpc::Mod => match (offset, BITS) {
                (0, BITS_64) => d.checked_rem(s).unwrap_or(d),
                (0, BITS_32) => {
                    // the upper 32 bits are zeroed below
                    if s == 0 {
                        d
                    } else {
                        d % s
                    }
                }
                (1, BITS_64) => {
                    let ds = d as i64;
                    let ss = s as i64;
                    if ss == 0 {
                        d
                    } else if ss == -1 && ds == i64::MIN {
                        0u64
                    } else {
                        (ds % ss) as u64
                    }
                }
                (1, BITS_32) => {
                    let ds = d as i32;
                    let ss = s as i32;
                    if ss == 0 {
                        d // zero-extended below
                    } else if ss == -1 && ds == i32::MIN {
                        0u64
                    } else {
                        (ds % ss) as u64
                    }
                }
                _ => return Flow::FailCpu,
            },
            AluOpc::Xor => d ^ s,
            // MOV (offset=0) or MOVSX (offset=8/16/32, register source only; 32 is ALU64-only). Without the cold path,
            // LLVM merges the `offset == 0` test into the movsx switch and lowers all of it to a jump table on
            // `offset`.
            AluOpc::Mov if offset == 0 => s,
            AluOpc::Mov => {
                core::hint::cold_path();
                match (offset, alu_src, BITS) {
                    (8, Source::Reg, _) => s as i8 as i64 as u64,
                    (16, Source::Reg, _) => s as i16 as i64 as u64,
                    (32, Source::Reg, BITS_64) => s as i32 as i64 as u64,
                    _ => return Flow::FailCpu,
                }
            }
            AluOpc::Arsh => match BITS {
                BITS_64 => ((d as i64) >> (s & 63)) as u64,
                BITS_32 => ((d as i32) >> (s & 31)) as u64,
            },
            // END: width comes from imm and the result is not zero-extended by class. Guest memory is little-endian, so
            // LE truncates and BE swaps; ALU64 TO_LE is the unconditional BSWAP and ALU64 TO_BE is reserved.
            AluOpc::End => {
                let full_d = ctx.regs[dst_reg];
                let swap = match (BITS, alu_end) {
                    (BITS_32, AluEnd::ToLE) => false,
                    (BITS_32, AluEnd::ToBE) | (BITS_64, AluEnd::ToLE) => true,
                    (BITS_64, AluEnd::ToBE) => return Flow::FailCpu,
                };
                ctx.regs[dst_reg] = match (swap, imm) {
                    (false, 16) => full_d as u16 as u64,
                    (false, 32) => full_d as u32 as u64,
                    (false, 64) => full_d,
                    (true, 16) => (full_d as u16).swap_bytes() as u64,
                    (true, 32) => (full_d as u32).swap_bytes() as u64,
                    (true, 64) => full_d.swap_bytes(),
                    _ => return Flow::FailCpu,
                };
                return Flow::Next;
            }
            AluOpc::UndefE | AluOpc::UndefF => return Flow::FailCpu,
        };

        ctx.regs[dst_reg] = match BITS {
            BITS_64 => result,
            BITS_32 => result & 0xFFFFFFFF,
        };

        Flow::Next
    }

    #[inline(always)]
    pub fn jump<M: Memory, const BITS: bool>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M> {
        let opc = insn.opcode();
        let jmp_opc = opc.jmp_opc();
        let jmp_src = opc.alu_src();

        let src_reg = insn.src_reg() as usize;
        let dst_reg = insn.dst_reg() as usize;

        let imm = insn.imm();

        let d = match BITS {
            BITS_64 => ctx.regs[dst_reg],
            BITS_32 => ctx.regs[dst_reg] & 0xFFFFFFFF,
        };

        let s = match (jmp_src, BITS) {
            (Source::Imm, BITS_64) => imm as i64 as u64,
            (Source::Imm, BITS_32) => imm as u32 as u64,
            (Source::Reg, BITS_64) => ctx.regs[src_reg],
            (Source::Reg, BITS_32) => ctx.regs[src_reg] & 0xFFFFFFFF,
        };

        let cond = match jmp_opc {
            // RFC 9669 defines CALL and EXIT only in the JMP class, EXIT only with source K, and JMP32 JA only with K
            JmpOpc::Call | JmpOpc::Exit if BITS == BITS_32 => return Flow::FailCpu,
            JmpOpc::Exit if jmp_src == Source::Reg => return Flow::FailCpu,
            JmpOpc::Ja if jmp_src == Source::Reg && BITS == BITS_32 => return Flow::FailCpu,
            // `gotox`: JMP64 class only, target in dst_reg
            JmpOpc::Ja if jmp_src == Source::Reg => return Flow::JumpIndirect(d),
            // JA in JMP64 class uses offset field, JA in JMP32 class uses imm field
            JmpOpc::Ja => {
                return match BITS {
                    BITS_64 => Flow::Jump(insn.offset() as i64),
                    BITS_32 => Flow::Jump(imm as i64),
                }
            }
            JmpOpc::Jeq => d == s,
            JmpOpc::Jgt => d > s,
            JmpOpc::Jge => d >= s,
            JmpOpc::Jset => (d & s) != 0,
            JmpOpc::Jne => d != s,
            JmpOpc::Jsgt => match BITS {
                BITS_64 => (d as i64) > (s as i64),
                BITS_32 => (d as i32) > (s as i32),
            },
            JmpOpc::Jsge => match BITS {
                BITS_64 => (d as i64) >= (s as i64),
                BITS_32 => (d as i32) >= (s as i32),
            },
            JmpOpc::Jlt => d < s,
            JmpOpc::Jle => d <= s,
            JmpOpc::Jslt => match BITS {
                BITS_64 => (d as i64) < (s as i64),
                BITS_32 => (d as i32) < (s as i32),
            },
            JmpOpc::Jsle => match BITS {
                BITS_64 => (d as i64) <= (s as i64),
                BITS_32 => (d as i32) <= (s as i32),
            },

            JmpOpc::Call if jmp_src == Source::Reg => return Flow::CallIndirect(d),
            JmpOpc::Call if src_reg == 0 => return Flow::CallHelper(imm as u32),
            JmpOpc::Call if src_reg == BPF_PSEUDO_CALL => return Flow::Call(i64::from(imm)),
            JmpOpc::Call if src_reg == BPF_PSEUDO_KFUNC_CALL => return Flow::CallKfunc(imm as u32),
            JmpOpc::Call => return Flow::Missing,

            JmpOpc::Exit => return Flow::Exit,

            JmpOpc::UndefE | JmpOpc::UndefF => return Flow::FailCpu,
        };

        match cond {
            true => Flow::Jump(insn.offset() as i64),
            false => Flow::Next,
        }
    }
}

mod mem {
    use std::ops::ControlFlow;

    use crate::opcode::{MemMode, MemSize};
    use crate::{AtomicOp, Context, Flow, Instruction, Memory};

    pub const WITH_REG: bool = true;
    pub const WITH_IMM: bool = false;

    fn mem_store<M: Memory>(mem: &mut M, size: MemSize, addr: u64, value: u64) -> Result<(), M::Err> {
        match size {
            MemSize::Byte => mem.store_u8(addr, value as u8),
            MemSize::Half => mem.store_u16(addr, value as u16),
            MemSize::Word => mem.store_u32(addr, value as u32),
            MemSize::DWord => mem.store_u64(addr, value),
        }
    }

    fn mem_load<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Err> {
        match size {
            MemSize::Byte => mem.load_u8(addr).map(u64::from),
            MemSize::Half => mem.load_u16(addr).map(u64::from),
            MemSize::Word => mem.load_u32(addr).map(u64::from),
            MemSize::DWord => mem.load_u64(addr),
        }
    }

    fn mem_load_sx<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Err> {
        match size {
            MemSize::Byte => mem.load_u8(addr).map(|x| x as i8 as i64 as u64),
            MemSize::Half => mem.load_u16(addr).map(|x| x as i16 as i64 as u64),
            MemSize::Word => mem.load_u32(addr).map(|x| x as i32 as i64 as u64),
            MemSize::DWord => unreachable!("`load` fails LDX | MEMSX | DW"),
        }
    }

    fn load_acquire<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Err> {
        match size {
            MemSize::Byte => mem.load_acquire_u8(addr).map(u64::from),
            MemSize::Half => mem.load_acquire_u16(addr).map(u64::from),
            MemSize::Word => mem.load_acquire_u32(addr).map(u64::from),
            MemSize::DWord => mem.load_acquire_u64(addr),
        }
    }

    fn store_release<M: Memory>(mem: &mut M, size: MemSize, addr: u64, value: u64) -> Result<(), M::Err> {
        match size {
            MemSize::Byte => mem.store_release_u8(addr, value as u8),
            MemSize::Half => mem.store_release_u16(addr, value as u16),
            MemSize::Word => mem.store_release_u32(addr, value as u32),
            MemSize::DWord => mem.store_release_u64(addr, value),
        }
    }

    #[inline(always)]
    pub fn save<M: Memory, const X: bool>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M> {
        let val = match X {
            true => ctx.regs[usize::from(insn.src_reg())],
            false => i64::from(insn.imm()) as u64,
        };

        let dst = ctx.regs[usize::from(insn.dst_reg())];
        let addr = dst.wrapping_add_signed(i64::from(insn.offset()));

        let opc = insn.opcode();
        let size = opc.mem_size();
        let mode = opc.mem_mode();

        let result = match mode {
            MemMode::Mem => mem_store(&mut ctx.data, size, addr, val),
            MemMode::Atomic if X => return atomic(ctx, insn, size, addr, val),

            // ABS and IND exist only in the LD class
            MemMode::Imm
            | MemMode::Abs
            | MemMode::Ind
            | MemMode::MemSX
            | MemMode::Atomic
            | MemMode::UndefA
            | MemMode::UndefE => return Flow::FailCpu,
        };
        if let Err(err) = result {
            return Flow::FailMem(err);
        }

        Flow::Next
    }

    /// `STX | ATOMIC`: `imm` selects the operation. The read-modify-write operations take W and DW sizes only;
    /// [`ordered`] runs the rest.
    fn atomic<M: Memory>(ctx: &mut Context<M>, insn: Instruction, size: MemSize, addr: u64, src: u64) -> Flow<M> {
        const FETCH: i32 = 0x01;
        const ADD: i32 = 0x00;
        const OR: i32 = 0x40;
        const AND: i32 = 0x50;
        const XOR: i32 = 0xa0;
        const XCHG: i32 = 0xe0 | FETCH;
        const CMPXCHG: i32 = 0xf0 | FETCH;

        let src_reg = usize::from(insn.src_reg());
        let imm = insn.imm();

        // `CmpXchg` compares against r0 and writes the old value there instead of `src`.
        macro_rules! run {
            ($ty:ty, $method:ident) => {{
                let v = src as $ty;
                let op = match imm & !FETCH {
                    _ if imm == XCHG => AtomicOp::Xchg(v),
                    _ if imm == CMPXCHG => AtomicOp::CmpXchg {
                        expected: ctx.regs[0] as $ty,
                        new: v,
                    },
                    ADD => AtomicOp::Add(v),
                    OR => AtomicOp::Or(v),
                    AND => AtomicOp::And(v),
                    XOR => AtomicOp::Xor(v),
                    _ => return ordered(ctx, insn, size, addr, src),
                };
                match ctx.data.$method(addr, op) {
                    Ok(old) => old as u64,
                    Err(err) => return Flow::FailMem(err),
                }
            }};
        }

        let old = match size {
            MemSize::Word => run!(u32, atomic_u32),
            MemSize::DWord => run!(u64, atomic_u64),
            MemSize::Byte | MemSize::Half => return ordered(ctx, insn, size, addr, src),
        };

        match imm {
            CMPXCHG => ctx.regs[0] = old,
            _ if imm & FETCH != 0 => ctx.regs[src_reg] = old,
            _ => {}
        }
        Flow::Next
    }

    /// `STX | ATOMIC` with an `imm` that names no read-modify-write operation: load-acquire and store-release, which
    /// take every size. Load-acquire reads through `src_reg` into `dst_reg`, the reverse of the other operations.
    // outlined to keep the read-modify-write path in `atomic` short
    #[inline(never)]
    fn ordered<M: Memory>(ctx: &mut Context<M>, insn: Instruction, size: MemSize, addr: u64, src: u64) -> Flow<M> {
        const LOAD_ACQ: i32 = 0x100;
        const STORE_REL: i32 = 0x110;

        let result = match insn.imm() {
            LOAD_ACQ => {
                let base = ctx.regs[usize::from(insn.src_reg())];
                let addr = base.wrapping_add_signed(i64::from(insn.offset()));
                load_acquire(&ctx.data, size, addr).map(|val| ctx.regs[usize::from(insn.dst_reg())] = val)
            }
            STORE_REL => store_release(&mut ctx.data, size, addr, src),
            _ => return Flow::FailCpu,
        };
        match result {
            Ok(()) => Flow::Next,
            Err(err) => Flow::FailMem(err),
        }
    }

    #[inline(always)]
    pub fn load<M: Memory>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M> {
        let dst = usize::from(insn.dst_reg());

        let src = ctx.regs[usize::from(insn.src_reg())];
        let addr = src.wrapping_add_signed(i64::from(insn.offset()));

        let opc = insn.opcode();
        let size = opc.mem_size();
        let mode = opc.mem_mode();

        match match mode {
            MemMode::Mem => mem_load(&ctx.data, size, addr),
            // RFC 9669 defines MEMSX for B, H and W only
            MemMode::MemSX if !matches!(size, MemSize::DWord) => mem_load_sx(&ctx.data, size, addr),

            // ABS and IND exist only in the LD class
            MemMode::Imm
            | MemMode::Abs
            | MemMode::Ind
            | MemMode::MemSX
            | MemMode::Atomic
            | MemMode::UndefA
            | MemMode::UndefE => return Flow::FailCpu,
        } {
            Ok(val) => ctx.regs[dst] = val,
            Err(err) => return Flow::FailMem(err),
        }

        Flow::Next
    }

    /// Continues with LD_IMM64 that loads its immediate. The pseudo loads (`src_reg` other than 0) are [`Flow::Missing`]
    /// at their first slot.
    #[inline(always)]
    pub fn ld64<M: Memory>(insn: Instruction) -> ControlFlow<Flow<M>, Instruction> {
        let opc = insn.opcode();
        let size = opc.mem_size();
        let mode = opc.mem_mode();

        match (mode, size) {
            (MemMode::Imm, MemSize::DWord) if insn.src_reg() == 0 => ControlFlow::Continue(insn),
            _ => ControlFlow::Break(Flow::Missing),
        }
    }
}

#[inline(always)]
pub(crate) fn step<M: Memory>(ctx: &mut Context<M>, insn: Instruction) -> ControlFlow<Flow<M>, Instruction> {
    use mem::{WITH_IMM, WITH_REG};
    use ops::{BITS_32, BITS_64};

    match insn.opcode().class() {
        Class::Alu32 => ControlFlow::Break(ops::math::<_, BITS_32>(ctx, insn)),
        Class::Alu64 => ControlFlow::Break(ops::math::<_, BITS_64>(ctx, insn)),

        Class::Jmp32 => ControlFlow::Break(ops::jump::<_, BITS_32>(ctx, insn)),
        Class::Jmp64 => ControlFlow::Break(ops::jump::<_, BITS_64>(ctx, insn)),

        Class::LdImm => mem::ld64(insn),
        Class::LdReg => ControlFlow::Break(mem::load(ctx, insn)),

        Class::StImm => ControlFlow::Break(mem::save::<_, WITH_IMM>(ctx, insn)),
        Class::StReg => ControlFlow::Break(mem::save::<_, WITH_REG>(ctx, insn)),
    }
}

/// Host functions the `call` handler runs without leaving [`run`].
///
/// Each method gets the arguments in `ctx.regs[1..=5]` and returns the new r0. It returns `None` to stop [`run`] at the
/// `call` with [`Flow::CallHelper`] or [`Flow::CallKfunc`], having recorded whatever its caller needs to handle that.
pub trait Host<M: Memory> {
    /// Call helper `id` (`src_reg = 0`).
    fn helper(&mut self, ctx: &mut Context<M>, id: u32) -> Option<u64>;
    /// Call external function `id` (`src_reg = BPF_PSEUDO_KFUNC_CALL`).
    fn kfunc(&mut self, ctx: &mut Context<M>, id: u32) -> Option<u64>;
}

/// Maximum nesting of BPF-to-BPF calls below the entry frame.
pub const MAX_CALL_DEPTH: usize = 8;

/// The BPF-to-BPF calls in progress, which [`run`] pushes and pops, the slot where it records where it stopped, the
/// window of the stack that r10 accesses use, and the [`Host`] that runs its helper and kfunc calls.
// `repr(C)` keeps the scalars ahead of the frames, so every handler reaches them with a one-byte displacement.
#[repr(C)]
pub struct CallStack<H> {
    depth: usize,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
    stop: Stop,
    stack: stack::Cache,
    pub host: H,

    /// `frames[..depth]` are initialised.
    frames: [MaybeUninit<Frame>; MAX_CALL_DEPTH],
}

/// Caller state saved across a BPF-to-BPF call.
struct Frame {
    /// r6-r9 (callee-saved) and r10 (frame pointer).
    regs: [u64; 5],
    /// The pc of the `call`.
    call_pc: u64,
}

impl<H> CallStack<H> {
    /// An empty call stack giving each callee `frame_size` bytes below its caller's r10.
    #[inline]
    pub fn new(frame_size: u64, host: H) -> Self {
        Self {
            depth: 0,
            frame_size,
            stop: Stop { pc: 0, fuel: 0 },
            stack: stack::Cache::STALE,
            host,
            frames: [const { MaybeUninit::uninit() }; MAX_CALL_DEPTH],
        }
    }

    /// Save the caller's state for the call at `call_pc` and give the callee its stack frame. Returns false, changing
    /// nothing, on a [`Flow::StackOverflow`].
    #[inline(always)]
    #[must_use]
    pub fn push(&mut self, regs: &mut [u64; 16], call_pc: u64) -> bool {
        let Some(frame) = self.frames.get_mut(self.depth) else {
            return false;
        };
        let Some(callee_fp) = regs[10].checked_sub(self.frame_size) else {
            return false;
        };
        frame.write(Frame {
            regs: [regs[6], regs[7], regs[8], regs[9], regs[10]],
            call_pc,
        });
        self.depth += 1;
        regs[10] = callee_fp;
        true
    }

    /// Restore the caller's state and return the pc of its `call`, or `None` in the entry frame.
    #[inline(always)]
    fn pop(&mut self, regs: &mut [u64; 16]) -> Option<u64> {
        // depth 0 wraps and fails the bounds check
        let depth = self.depth.wrapping_sub(1);
        let frame = self.frames.get(depth)?;
        // SAFETY: `depth` is below `self.depth`, and `push` wrote every frame up to it
        let frame = unsafe { frame.assume_init_ref() };
        regs[6..=10].copy_from_slice(&frame.regs);
        self.depth = depth;
        Some(frame.call_pc)
    }
}

/// Where [`run`] stopped, written once when execution leaves the handler chain.
struct Stop {
    pc: u64,
    fuel: u64,
}

impl Stop {
    #[inline(always)]
    fn at<M: Memory>(&mut self, pc: u64, fuel: u64, flow: Flow<M>) -> Flow<M> {
        core::hint::cold_path();
        (self.pc, self.fuel) = (pc, fuel);
        flow
    }
}

/// Runs the instruction `insn` at `pc` and continues with the next one. A metering handler receives `fuel` already
/// charged for `insn`; the others pass it on as is.
///
/// `preserve_none` passes all arguments in registers (the Windows x64 C convention has four) and saves no registers, so
/// a tail call between handlers is a jump.
type Handler<M, H> = extern "rust-preserve-none" fn(
    &mut Context<M>,
    &[Instruction],
    Instruction,
    u64,
    u64,
    &mut CallStack<H>,
) -> Flow<M>;

/// The handler of every opcode byte. Each runs [`step`] with its opcode as a constant, so the class, operation, source,
/// mode and size matches fold away; the bytes of superinstructions and r10 accesses get theirs from [`fuse::install`].
/// With `FUEL`, the handlers meter fuel; without it, they never read it.
struct Handlers<M, H, const FUEL: bool>(PhantomData<(M, H)>);

impl<M: Memory, H: Host<M>, const FUEL: bool> Handlers<M, H, FUEL> {
    const TABLE: [Handler<M, H>; 256] = {
        macro_rules! table {
            ($($op:literal)*) => {
                [$(handler::<M, H, FUEL, $op> as Handler<M, H>,)*]
            };
        }

        let mut table = table!(
            0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f
            0x10 0x11 0x12 0x13 0x14 0x15 0x16 0x17 0x18 0x19 0x1a 0x1b 0x1c 0x1d 0x1e 0x1f
            0x20 0x21 0x22 0x23 0x24 0x25 0x26 0x27 0x28 0x29 0x2a 0x2b 0x2c 0x2d 0x2e 0x2f
            0x30 0x31 0x32 0x33 0x34 0x35 0x36 0x37 0x38 0x39 0x3a 0x3b 0x3c 0x3d 0x3e 0x3f
            0x40 0x41 0x42 0x43 0x44 0x45 0x46 0x47 0x48 0x49 0x4a 0x4b 0x4c 0x4d 0x4e 0x4f
            0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x59 0x5a 0x5b 0x5c 0x5d 0x5e 0x5f
            0x60 0x61 0x62 0x63 0x64 0x65 0x66 0x67 0x68 0x69 0x6a 0x6b 0x6c 0x6d 0x6e 0x6f
            0x70 0x71 0x72 0x73 0x74 0x75 0x76 0x77 0x78 0x79 0x7a 0x7b 0x7c 0x7d 0x7e 0x7f
            0x80 0x81 0x82 0x83 0x84 0x85 0x86 0x87 0x88 0x89 0x8a 0x8b 0x8c 0x8d 0x8e 0x8f
            0x90 0x91 0x92 0x93 0x94 0x95 0x96 0x97 0x98 0x99 0x9a 0x9b 0x9c 0x9d 0x9e 0x9f
            0xa0 0xa1 0xa2 0xa3 0xa4 0xa5 0xa6 0xa7 0xa8 0xa9 0xaa 0xab 0xac 0xad 0xae 0xaf
            0xb0 0xb1 0xb2 0xb3 0xb4 0xb5 0xb6 0xb7 0xb8 0xb9 0xba 0xbb 0xbc 0xbd 0xbe 0xbf
            0xc0 0xc1 0xc2 0xc3 0xc4 0xc5 0xc6 0xc7 0xc8 0xc9 0xca 0xcb 0xcc 0xcd 0xce 0xcf
            0xd0 0xd1 0xd2 0xd3 0xd4 0xd5 0xd6 0xd7 0xd8 0xd9 0xda 0xdb 0xdc 0xdd 0xde 0xdf
            0xe0 0xe1 0xe2 0xe3 0xe4 0xe5 0xe6 0xe7 0xe8 0xe9 0xea 0xeb 0xec 0xed 0xee 0xef
            0xf0 0xf1 0xf2 0xf3 0xf4 0xf5 0xf6 0xf7 0xf8 0xf9 0xfa 0xfb 0xfc 0xfd 0xfe 0xff
        );
        fuse::install::<M, H, FUEL>(&mut table);
        table
    };
}

/// The [`Handler`] of opcode `OP`. Each handler fetches the next instruction itself and ends in its own indirect jump,
/// so the branch predictor tracks the successors of every opcode separately.
#[inline(never)]
extern "rust-preserve-none" fn handler<M: Memory, H: Host<M>, const FUEL: bool, const OP: u8>(
    ctx: &mut Context<M>,
    code: &[Instruction],
    insn: Instruction,
    mut pc: u64,
    mut fuel: u64,
    calls: &mut CallStack<H>,
) -> Flow<M> {
    // Only jump-class opcodes jump, call or exit. Without the guards, a handler whose `step` returns from an outlined
    // call (atomics) would test for those flows too.
    let jumps = matches!(OpCode(OP).class(), Class::Jmp32 | Class::Jmp64);
    match step(ctx, Instruction(insn.0 & !0xFF | OP as u64)) {
        ControlFlow::Break(Flow::Next) => {}
        ControlFlow::Break(Flow::Jump(offset)) if jumps => pc = pc.wrapping_add_signed(offset),
        ControlFlow::Break(Flow::Call(offset)) if jumps => {
            if !calls.push(&mut ctx.regs, pc) {
                return calls.stop.at(pc, fuel, Flow::StackOverflow);
            }
            pc = pc.wrapping_add_signed(offset);
        }
        ControlFlow::Break(Flow::Exit) if jumps => match calls.pop(&mut ctx.regs) {
            Some(call_pc) => pc = call_pc,
            None => return calls.stop.at(pc, fuel, Flow::Exit),
        },
        ControlFlow::Break(Flow::CallHelper(_)) if jumps => {
            become host_call::<M, H, FUEL, false>(ctx, code, insn, pc, fuel, calls)
        }
        ControlFlow::Break(Flow::CallKfunc(_)) if jumps => {
            become host_call::<M, H, FUEL, true>(ctx, code, insn, pc, fuel, calls)
        }
        ControlFlow::Continue(first) => {
            // without a unit for the second slot, LD_IMM64 doesn't run and gets its unit back
            if FUEL && fuel == 0 {
                return calls.stop.at(pc, 1, Flow::OutOfFuel);
            }
            pc += 1;
            let Some(&second) = code.get(pc as usize) else {
                return calls.stop.at(pc, fuel, Flow::BadPc);
            };
            if FUEL {
                fuel -= 1;
            }
            step_ld64(ctx, first, second);
        }
        ControlFlow::Break(flow) => return calls.stop.at(pc, fuel, flow),
    }

    // a negative jump target wraps to a huge pc and fails the fetch
    let pc = pc.wrapping_add(1);
    match fetch::<M, H, FUEL>(code, pc, fuel) {
        Ok((next, insn)) => become next(ctx, code, insn, pc, fuel - u64::from(FUEL), calls),
        Err(flow) => calls.stop.at(pc, fuel, flow),
    }
}

/// The rest of the handler of a helper `call`, or with `KFUNC` a kfunc `call`: runs it on the host and continues with
/// the next instruction.
// Out of line, so that the handler, which also runs local calls, calls no function and needs no stack frame.
#[inline(never)]
extern "rust-preserve-none" fn host_call<M: Memory, H: Host<M>, const FUEL: bool, const KFUNC: bool>(
    ctx: &mut Context<M>,
    code: &[Instruction],
    insn: Instruction,
    pc: u64,
    fuel: u64,
    calls: &mut CallStack<H>,
) -> Flow<M> {
    let id = insn.imm() as u32;
    let (r0, flow) = match KFUNC {
        true => (calls.host.kfunc(ctx, id), Flow::CallKfunc(id)),
        false => (calls.host.helper(ctx, id), Flow::CallHelper(id)),
    };
    let Some(r0) = r0 else {
        return calls.stop.at(pc, fuel, flow);
    };
    calls.stack.revalidate(&ctx.data);
    ctx.regs[0] = r0;

    let pc = pc + 1;
    match fetch::<M, H, FUEL>(code, pc, fuel) {
        Ok((next, insn)) => become next(ctx, code, insn, pc, fuel - u64::from(FUEL), calls),
        Err(flow) => calls.stop.at(pc, fuel, flow),
    }
}

/// The instruction at `pc` and its handler, or why it can't run.
#[inline(always)]
fn fetch<M: Memory, H: Host<M>, const FUEL: bool>(
    code: &[Instruction],
    pc: u64,
    fuel: u64,
) -> Result<(Handler<M, H>, Instruction), Flow<M>> {
    if FUEL && fuel == 0 {
        return Err(Flow::OutOfFuel);
    }
    let Some(&insn) = code.get(pc as usize) else {
        return Err(Flow::BadPc);
    };
    Ok((handler_of::<M, H, FUEL>(insn), insn))
}

/// The handler of `insn` from the set that meters fuel, or the one that never reads it.
#[inline(always)]
fn handler_of<M: Memory, H: Host<M>, const FUEL: bool>(insn: Instruction) -> Handler<M, H> {
    Handlers::<M, H, FUEL>::TABLE[usize::from(insn.0 as u8)]
}

#[inline(always)]
pub(crate) fn step_ld64<M: Memory>(ctx: &mut Context<M>, insn: Instruction, second: Instruction) {
    debug_assert!(matches!(
        (insn.opcode().class(), insn.opcode().mem_mode(), insn.opcode().mem_size(), insn.src_reg()),
        (Class::LdImm, MemMode::Imm, MemSize::DWord, 0)
    ));

    // the first slot carries the low 32 bits, the second the high 32 bits
    let imm_lo = insn.imm() as u32 as u64;
    let imm_hi = second.imm() as u32 as u64;
    ctx.regs[usize::from(insn.dst_reg())] = imm_lo | (imm_hi << 32);
}

/// Whether [`run`] meters fuel, chosen by the `fuel` feature.
const METERED: bool = cfg!(feature = "fuel");

/// Execute from `*pc` until an instruction the caller must handle.
///
/// ALU, memory and jump instructions, local calls and their returns, and helper and kfunc calls that `calls.host` runs
/// stay inside the handler chain, so each one costs a single dispatch. `calls` holds the frames of the local calls in
/// progress and keeps them from one `run` to the next. Execution returns helper and kfunc calls that the host declined,
/// indirect calls and jumps, [`Flow::Exit`] from the entry frame and faults with `*pc` at the instruction that produced
/// them, and [`Flow::OutOfFuel`] or [`Flow::BadPc`] with `*pc` at the instruction that could not run. With the `fuel`
/// feature, each executed instruction consumes one unit of `fuel`, and LD_IMM64 one per slot: with one unit left, it
/// stops with [`Flow::OutOfFuel`] and that unit. Without the feature, `run` takes no `fuel` and never runs out.
#[inline]
pub fn run<M: Memory, H: Host<M>>(
    ctx: &mut Context<M>,
    code: &Code,
    pc: &mut u64,
    #[cfg(feature = "fuel")] fuel: &mut u64,
    calls: &mut CallStack<H>,
) -> Flow<M> {
    #[cfg(not(feature = "fuel"))]
    let fuel = &mut 0;

    let code = code.slots();
    calls.stack.revalidate(&ctx.data);
    let (first, insn) = match fetch::<M, H, METERED>(code, *pc, *fuel) {
        Ok(next) => next,
        Err(flow) => return flow,
    };
    let flow = first(ctx, code, insn, *pc, *fuel - u64::from(METERED), calls);
    (*pc, *fuel) = (calls.stop.pc, calls.stop.fuel);
    flow
}
