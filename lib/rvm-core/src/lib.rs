use std::fmt::Debug;
use std::ops::ControlFlow;

use opcode::{Class, OpCode};

mod consts;
mod debug;

pub mod opcode;

#[cfg(test)]
mod tests;

// https://github.com/ietf-wg-bpf/ebpf-docs/blob/9fecd435d065094050cb6c14ddc11fffac313180/rst/instruction-set.rst
// https://docs.kernel.org/6.4/bpf/instruction-set.html#bit-immediate-instructions

#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Instruction(pub u64);

/// Decode little-endian bytecode into instructions (a trailing partial word is ignored).
pub fn instructions_from_bytes(bytes: &[u8]) -> Box<[Instruction]> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|w| Instruction(u64::from_le_bytes(*w)))
        .collect()
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
    Next, // Continue

    Jump(i64), // Jump
    Call(i64), // Call
    Exit,      // Return

    /// Call a helper by its numeric ID (`src_reg = 0`).
    CallHelper(u32),
    /// Call an external function by ID (`src_reg = BPF_PSEUDO_KFUNC_CALL`); the
    /// runtime defines what the ID indexes (rvm: the program's extern table).
    CallKfunc(u32),

    FailCpu, // Invalid instruction, etc.
    FailMem(C::Err),

    Missing, // Not yet implemented.

    /// [`run`] used up its instruction budget before the next instruction.
    OutOfFuel,
    /// [`run`] reached a `pc` outside the code slice.
    BadPc,
}

pub trait Runner {
    type Err;
}

impl Runner for () {
    type Err = ();
}

pub trait Memory {
    /// The Memory implementation's error type.
    /// If possible, avoid types larger than 8 bytes.
    type Err;

    fn load_u8(&self, addr: u64) -> Result<u8, Self::Err>;
    fn store_u8(&mut self, addr: u64, value: u8) -> Result<(), Self::Err>;

    fn load_u16(&self, addr: u64) -> Result<u16, Self::Err> {
        let lo = self.load_u8(addr)? as u16;
        let hi = self.load_u8(addr + 1)? as u16;
        Ok(lo | hi << 8)
    }

    fn load_u32(&self, addr: u64) -> Result<u32, Self::Err> {
        let lo = self.load_u16(addr)? as u32;
        let hi = self.load_u16(addr + 2)? as u32;
        Ok(lo | hi << 16)
    }

    fn load_u64(&self, addr: u64) -> Result<u64, Self::Err> {
        let lo = self.load_u32(addr)? as u64;
        let hi = self.load_u32(addr + 4)? as u64;
        Ok(lo | hi << 32)
    }

    fn store_u16(&mut self, addr: u64, value: u16) -> Result<(), Self::Err> {
        self.store_u8(addr, value as u8)?;
        self.store_u8(addr + 1, (value >> 8) as u8)
    }

    fn store_u32(&mut self, addr: u64, value: u32) -> Result<(), Self::Err> {
        self.store_u16(addr, value as u16)?;
        self.store_u16(addr + 2, (value >> 16) as u16)
    }

    fn store_u64(&mut self, addr: u64, value: u64) -> Result<(), Self::Err> {
        self.store_u32(addr, value as u32)?;
        self.store_u32(addr + 4, (value >> 32) as u32)
    }

    /// Apply `op` to the `u32` at `addr` and return the previous value.
    ///
    /// The default is a load followed by a store, which is atomic for memory only
    /// this executor can reach. Override it for memory shared with other threads.
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

impl Memory for () {
    type Err = ();

    fn load_u8(&self, _addr: u64) -> Result<u8, Self::Err> {
        Err(())
    }

    fn store_u8(&mut self, _addr: u64, _value: u8) -> Result<(), Self::Err> {
        Err(())
    }
}

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
}

/// Scratch register index for storing first half of LD_IMM64 instruction.
/// This is beyond the eBPF-defined registers (r0-r10) and must not be used elsewhere.
pub const REG_SCRATCH_LD64: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<M: Memory> {
    // Expose all 16 for now; the upper ones double as interpreter scratch state (e.g. r11 for LD_IMM64).

    // R0: return value from function calls, and exit value for eBPF programs
    // R1 - R5: arguments for function calls
    // R6 - R9: callee saved registers that function calls will preserve
    // R10: read-only frame pointer to access stack
    // R11: scratch register for LD_IMM64 (internal use only, see REG_SCRATCH_LD64)
    pub regs: [u64; 16],
    pub data: M,
}

impl<M: Memory> Context<M> {
    pub const fn new(data: M) -> Self {
        Self { regs: [0; 16], data }
    }
}

pub const BITS_32: bool = false;
pub const BITS_64: bool = true;

mod alu {
    use std::ops::{BitAnd, BitOr};

    use crate::consts::jmp::{BPF_PSEUDO_CALL, BPF_PSEUDO_KFUNC_CALL};
    use crate::opcode::{AluEnd, AluOpc, JmpOpc, Source};
    use crate::{Context, Flow, Instruction, Memory};

    pub const BITS_32: bool = false;
    pub const BITS_64: bool = true;

    fn zero_extend_32_to_64(value: u64) -> u64 {
        value & 0xFFFFFFFF
    }

    pub fn math<M: Memory, const BITS: bool>(ctx: &mut Context<M>, instr: Instruction) -> Flow<M> {
        let opc = instr.opcode();
        let alu_opc = opc.alu_opc();
        let alu_src = opc.alu_src();
        let alu_end = opc.alu_end();

        let src_reg = instr.src_reg() as usize;
        let dst_reg = instr.dst_reg() as usize;

        let imm = instr.imm();
        let offset = instr.offset();

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
                (0, _) => {
                    // Unsigned division: dst = (src != 0) ? (dst / src) : 0
                    d.checked_div(s).unwrap_or(0)
                }
                (1, BITS_64) => {
                    // SDIV 64-bit: handle div by zero and LLONG_MIN / -1
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
                    // SDIV 32-bit: handle div by zero and INT_MIN / -1
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
            AluOpc::Or => d.bitor(s),
            AluOpc::And => d.bitand(s),
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
                (0, BITS_64) => {
                    // Unsigned modulo: dst = (src != 0) ? (dst % src) : dst
                    d.checked_rem(s).unwrap_or(d)
                }
                (0, BITS_32) => {
                    // Unsigned modulo 32-bit: if src==0, upper 32 bits zeroed but lower preserved
                    if s == 0 {
                        d
                    } else {
                        d % s
                    }
                }
                (1, BITS_64) => {
                    // SMOD 64-bit: handle mod by zero and LLONG_MIN % -1
                    let ds = d as i64;
                    let ss = s as i64;
                    if ss == 0 {
                        d // unchanged
                    } else if ss == -1 && ds == i64::MIN {
                        0u64
                    } else {
                        (ds % ss) as u64
                    }
                }
                (1, BITS_32) => {
                    // SMOD 32-bit: handle mod by zero and INT_MIN % -1
                    let ds = d as i32;
                    let ss = s as i32;
                    if ss == 0 {
                        d // unchanged (but will be zero-extended later)
                    } else if ss == -1 && ds == i32::MIN {
                        0u64
                    } else {
                        (ds % ss) as u64
                    }
                }
                _ => return Flow::FailCpu,
            },
            AluOpc::Xor => d ^ s,
            // MOV (offset=0) or MOVSX (offset=8/16/32, register source only; 32 is ALU64-only).
            AluOpc::Mov => match (offset, alu_src, BITS) {
                (0, _, _) => s,
                (8, Source::Reg, _) => s as i8 as i64 as u64,
                (16, Source::Reg, _) => s as i16 as i64 as u64,
                (32, Source::Reg, BITS_64) => s as i32 as i64 as u64,
                _ => return Flow::FailCpu,
            },
            AluOpc::Arsh => match BITS {
                BITS_64 => ((d as i64) >> (s & 63)) as u64,
                BITS_32 => ((d as i32) >> (s & 31)) as u64,
            },
            // END: width comes from imm and the result is not zero-extended by class.
            // Guest memory is little-endian, so LE truncates and BE swaps; ALU64 TO_LE is the
            // unconditional BSWAP and ALU64 TO_BE is reserved.
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

        // For ALU32 operations, zero-extend the 32-bit result to 64 bits
        ctx.regs[dst_reg] = match BITS {
            BITS_64 => result,
            BITS_32 => zero_extend_32_to_64(result),
        };

        Flow::Next
    }

    pub fn jump<M: Memory, const BITS: bool>(ctx: &mut Context<M>, instr: Instruction) -> Flow<M> {
        let opc = instr.opcode();
        let jmp_opc = opc.jmp_opc();
        let jmp_src = opc.alu_src();

        let src_reg = instr.src_reg() as usize;
        let dst_reg = instr.dst_reg() as usize;

        let imm = instr.imm();

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
            // JA in JMP64 class uses offset field, JA in JMP32 class uses imm field
            JmpOpc::Ja => {
                return match BITS {
                    BITS_64 => Flow::Jump(instr.offset() as i64),
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

            JmpOpc::Call if src_reg == 0 => return Flow::CallHelper(imm as u32),
            JmpOpc::Call if src_reg == BPF_PSEUDO_CALL => return Flow::Call(i64::from(imm)), // program-local function
            JmpOpc::Call if src_reg == BPF_PSEUDO_KFUNC_CALL => return Flow::CallKfunc(imm as u32),
            JmpOpc::Call => return Flow::Missing,

            JmpOpc::Exit => return Flow::Exit,

            JmpOpc::UndefE => return Flow::FailCpu,
            JmpOpc::UndefF => return Flow::FailCpu,
        };

        match cond {
            true => Flow::Jump(instr.offset() as i64),
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
            MemSize::DWord => mem.load_u64(addr),
        }
    }

    pub fn save<M: Memory, const X: bool>(ctx: &mut Context<M>, instr: Instruction) -> Flow<M> {
        let val = match X {
            true => ctx.regs[usize::from(instr.src_reg())],
            false => i64::from(instr.imm()) as u64,
        };

        let dst = ctx.regs[usize::from(instr.dst_reg())];
        let addr = dst.wrapping_add_signed(i64::from(instr.offset()));

        let opc = instr.opcode();
        let size = opc.mem_size();
        let mode = opc.mem_mode();

        let result = match mode {
            MemMode::Mem => mem_store(&mut ctx.data, size, addr, val),
            MemMode::Atomic if X => return atomic(ctx, instr, size, addr, val),

            MemMode::Imm => return Flow::Missing,
            MemMode::Abs => return Flow::Missing,
            MemMode::Ind => return Flow::Missing,

            MemMode::MemSX | MemMode::Atomic | MemMode::UndefA | MemMode::UndefE => return Flow::FailCpu,
        };
        if let Err(err) = result {
            return Flow::FailMem(err);
        }

        Flow::Next
    }

    /// `STX | ATOMIC`: `imm` selects the operation; W and DW sizes only.
    fn atomic<M: Memory>(ctx: &mut Context<M>, instr: Instruction, size: MemSize, addr: u64, src: u64) -> Flow<M> {
        const FETCH: i32 = 0x01;
        const ADD: i32 = 0x00;
        const OR: i32 = 0x40;
        const AND: i32 = 0x50;
        const XOR: i32 = 0xa0;
        const XCHG: i32 = 0xe0 | FETCH;
        const CMPXCHG: i32 = 0xf0 | FETCH;

        let src_reg = usize::from(instr.src_reg());
        let imm = instr.imm();

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
                    _ => return Flow::FailCpu,
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
            MemSize::Byte | MemSize::Half => return Flow::FailCpu,
        };

        match imm {
            CMPXCHG => ctx.regs[0] = old,
            _ if imm & FETCH != 0 => ctx.regs[src_reg] = old,
            _ => {}
        }
        Flow::Next
    }

    pub fn load<M: Memory>(ctx: &mut Context<M>, instr: Instruction) -> Flow<M> {
        let dst = usize::from(instr.dst_reg());

        let src = ctx.regs[usize::from(instr.src_reg())];
        let addr = src.wrapping_add_signed(i64::from(instr.offset()));

        let opc = instr.opcode();
        let size = opc.mem_size();
        let mode = opc.mem_mode();

        match match mode {
            MemMode::Mem => mem_load(&ctx.data, size, addr),
            MemMode::MemSX => mem_load_sx(&ctx.data, size, addr),

            MemMode::Imm => return Flow::Missing,
            MemMode::Abs => return Flow::Missing,
            MemMode::Ind => return Flow::Missing,
            MemMode::Atomic => return Flow::Missing,

            MemMode::UndefA => return Flow::FailCpu,
            MemMode::UndefE => return Flow::FailCpu,
        } {
            Ok(val) => ctx.regs[dst] = val,
            Err(err) => return Flow::FailMem(err),
        }

        Flow::Next
    }

    pub fn ld64<M: Memory>(ctx: &mut Context<M>, instr: Instruction) -> ControlFlow<Flow<M>, Instruction> {
        let opc = instr.opcode();
        let size = opc.mem_size();
        let mode = opc.mem_mode();

        match (mode, size) {
            (MemMode::Imm, MemSize::DWord) => {
                // Store first instruction's imm (low 32 bits) in scratch register
                ctx.regs[crate::REG_SCRATCH_LD64] = instr.imm() as u32 as u64;
                ControlFlow::Continue(instr)
            }
            _ => ControlFlow::Break(Flow::Missing),
        }
    }
}

#[inline(always)]
pub fn step<M: Memory>(ctx: &mut Context<M>, instr: Instruction) -> ControlFlow<Flow<M>, Instruction> {
    use alu::{BITS_32, BITS_64};
    use mem::{WITH_IMM, WITH_REG};

    match instr.opcode().class() {
        Class::Alu32 => ControlFlow::Break(alu::math::<_, BITS_32>(ctx, instr)),
        Class::Alu64 => ControlFlow::Break(alu::math::<_, BITS_64>(ctx, instr)),

        Class::Jmp32 => ControlFlow::Break(alu::jump::<_, BITS_32>(ctx, instr)),
        Class::Jmp64 => ControlFlow::Break(alu::jump::<_, BITS_64>(ctx, instr)),

        Class::LdImm => mem::ld64::<_>(ctx, instr),
        Class::LdReg => ControlFlow::Break(mem::load::<_>(ctx, instr)),

        Class::StImm => ControlFlow::Break(mem::save::<_, WITH_IMM>(ctx, instr)),
        Class::StReg => ControlFlow::Break(mem::save::<_, WITH_REG>(ctx, instr)),
    }
}

#[inline(always)]
pub fn step_ld64<M: Memory>(ctx: &mut Context<M>, instr: Instruction, second: Instruction) -> Flow<M> {
    use consts::class;
    use consts::mem::{mode, size};

    debug_assert!(instr.opcode() == OpCode(class::BPF_LD | mode::BPF_IMM | size::BPF_DW));

    let dst = usize::from(instr.dst_reg());

    // Combine low 32 bits (from scratch register, set by ld64) with high 32 bits (from second instruction)
    let imm_lo = ctx.regs[REG_SCRATCH_LD64];
    let imm_hi = second.imm() as u32 as u64;
    let imm64 = imm_lo | (imm_hi << 32);

    match instr.src_reg() {
        0 => ctx.regs[dst] = imm64,
        _ => return Flow::Missing,
    }

    Flow::Next
}

/// Execute from `*pc` until an instruction the caller must handle.
///
/// Plain ALU, memory and jump instructions stay inside this loop, so each one costs a
/// single dispatch. The loop returns [`Flow::Call`], [`Flow::Exit`], helper calls and
/// faults with `*pc` at the instruction that produced them, and [`Flow::OutOfFuel`] or
/// [`Flow::BadPc`] with `*pc` at the instruction that could not run. Each executed
/// instruction (both slots of LD_IMM64) consumes one unit of `fuel`.
#[inline]
pub fn run<M: Memory>(ctx: &mut Context<M>, code: &[Instruction], pc: &mut u64, fuel: &mut u64) -> Flow<M> {
    loop {
        if *fuel == 0 {
            return Flow::OutOfFuel;
        }
        let Some(&insn) = code.get(*pc as usize) else {
            return Flow::BadPc;
        };
        *fuel -= 1;

        let flow = match step(ctx, insn) {
            ControlFlow::Break(flow) => flow,
            ControlFlow::Continue(first) => {
                let Some(&second) = code.get(*pc as usize + 1) else {
                    *pc += 1;
                    return Flow::BadPc;
                };
                *pc += 1;
                *fuel = fuel.saturating_sub(1);
                step_ld64(ctx, first, second)
            }
        };

        match flow {
            Flow::Next => *pc += 1,
            // a negative target wraps to a huge pc and fails the next fetch
            Flow::Jump(offset) => *pc = pc.wrapping_add_signed(offset + 1),
            other => return other,
        }
    }
}
