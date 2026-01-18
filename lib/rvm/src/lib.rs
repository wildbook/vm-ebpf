use std::fmt::Debug;
use std::ops::ControlFlow;

use opcode::{Class, OpCode};

mod consts;
mod debug;

pub mod opcode;

// https://github.com/ietf-wg-bpf/ebpf-docs/blob/9fecd435d065094050cb6c14ddc11fffac313180/rst/instruction-set.rst
// https://docs.kernel.org/6.4/bpf/instruction-set.html#bit-immediate-instructions

#[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Instruction(pub u64);

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

    /// Call an external function.
    CallExt(u64),

    FailCpu, // Invalid instruction, etc.
    FailMem(C::Err),

    Missing, // Not yet implemented.
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

    fn load_pc(&self, pc: u64) -> Result<Instruction, Self::Err> {
        self.load_u64(pc * 8).map(Instruction)
    }

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
}

impl Memory for () {
    type Err = ();

    fn load_u8(&self, _addr: u64) -> Result<u8, Self::Err> {
        Err(())
    }

    fn store_u8(&mut self, _addr: u64, _value: u8) -> Result<(), Self::Err> {
        Err(())
    }
}

/// Scratch register index for storing first half of LD_IMM64 instruction.
/// This is beyond the eBPF-defined registers (r0-r10) and must not be used elsewhere.
pub const REG_SCRATCH_LD64: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context<M: Memory> {
    // There's actually just 10 registers, but we'll do 16 as it allows for optimizations (regs[idx & 0xF]).

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

        let d = match BITS {
            BITS_64 => ctx.regs[dst_reg],
            BITS_32 => ctx.regs[dst_reg] & 0xFFFFFFFF,
        };

        let s = match (alu_src, BITS) {
            (Source::Imm, _) => imm as i64 as u64,
            (Source::Reg, BITS_64) => ctx.regs[src_reg],
            (Source::Reg, BITS_32) => ctx.regs[src_reg] & 0xFFFFFFFF,
        };

        // TODO: handle overflow
        let result = match alu_opc {
            AluOpc::Add => d.wrapping_add(s),
            AluOpc::Sub => d.wrapping_sub(s),
            AluOpc::Mul => d.wrapping_mul(s),
            AluOpc::Div => d.checked_div(s).unwrap_or(0),
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
            AluOpc::Mod => d.checked_rem(s).unwrap_or(d),
            AluOpc::Xor => d ^ s,
            AluOpc::Mov => s,
            AluOpc::Arsh => match BITS {
                BITS_64 => ((d as i64) >> (s & 63)) as u64,
                BITS_32 => ((d as i32) >> (s & 31)) as u64,
            },
            AluOpc::End => match (alu_end, imm) {
                (AluEnd::ToLE, 16) => (d as u16).to_le() as u64,
                (AluEnd::ToLE, 32) => (d as u32).to_le() as u64,
                (AluEnd::ToLE, 64) => (d as u64).to_le() as u64,
                (AluEnd::ToBE, 16) => (d as u16).to_be() as u64,
                (AluEnd::ToBE, 32) => (d as u32).to_be() as u64,
                (AluEnd::ToBE, 64) => (d as u64).to_be() as u64,
                _ => return Flow::FailCpu, // unimplemented!("undefined behavior for alu_end: {alu_end:?} {imm}"),
            },

            AluOpc::UndefE => return Flow::FailCpu,
            AluOpc::UndefF => return Flow::FailCpu,
        };

        ctx.regs[dst_reg] = match BITS {
            BITS_64 => result,
            BITS_32 => zero_extend_32_to_64(result),
        };

        Flow::Next
    }

    pub fn jump<M: Memory, const BITS: bool>(ctx: &mut Context<M>, instr: Instruction) -> Flow<M> {
        let src_reg = instr.src_reg() as usize;
        let dst_reg = instr.dst_reg() as usize;

        let imm = instr.imm();
        let opc = instr.opcode();

        let d = match BITS {
            BITS_64 => ctx.regs[dst_reg],
            BITS_32 => ctx.regs[dst_reg] & 0xFFFFFFFF,
        };
        let s = match (opc.jmp_src(), BITS) {
            (Source::Imm, BITS_64) => imm as i64 as u64,
            (Source::Imm, BITS_32) => imm as u32 as u64,
            (Source::Reg, BITS_64) => ctx.regs[src_reg],
            (Source::Reg, BITS_32) => ctx.regs[src_reg] & 0xFFFFFFFF,
        };

        let cond = match opc.jmp_opc() {
            // JA uses offset field for JMP class, but imm field for JMP32 class
            JmpOpc::Ja => {
                return match BITS {
                    BITS_64 => Flow::Jump(instr.offset() as i64),
                    BITS_32 => Flow::Jump(imm as i64),
                }
            }
            JmpOpc::Jeq => d == s,
            JmpOpc::Jgt => d > s,
            JmpOpc::Jge => d >= s,
            JmpOpc::Jset => d & s != 0,
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

            JmpOpc::Call if src_reg == 0 => return Flow::CallExt(imm as u32 as u64), // helper function by static ID
            JmpOpc::Call if src_reg == BPF_PSEUDO_CALL => return Flow::Call(i64::from(imm)), // program-local function
            JmpOpc::Call if src_reg == BPF_PSEUDO_KFUNC_CALL => return Flow::CallExt(imm as u32 as u64), // helper by BTF ID
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
    use crate::{Context, Flow, Instruction, Memory};

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
            MemSize::DWord => mem.load_u64(addr).map(u64::from),
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

        match match mode {
            MemMode::Mem => mem_store(&mut ctx.data, size, addr, val),
            MemMode::MemSX => mem_store(&mut ctx.data, size, addr, val),

            MemMode::Imm => return Flow::Missing,
            MemMode::Abs => return Flow::Missing,
            MemMode::Ind => return Flow::Missing,
            MemMode::Atomic => return Flow::Missing,

            MemMode::UndefA => return Flow::FailCpu,
            MemMode::UndefE => return Flow::FailCpu,
        } {
            Ok(()) => (),
            Err(err) => return Flow::FailMem(err),
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

#[no_mangle]
#[inline(never)]
pub fn call() -> u64 {
    let mut ctx = Context::new(());

    let x = [
        Instruction(0x0000000001000001b7), //
        Instruction(0x00000000000000101f), //
        Instruction(0x000000000000000095), //
    ];

    dbg!(x);

    alu::math::<_, { BITS_64 }>(&mut ctx, x[0]);
    alu::math::<_, { BITS_64 }>(&mut ctx, x[1]);

    ctx.regs[0]
}

#[cfg(test)]
mod tests {
    use crate::{Context, Instruction};

    #[test]
    fn test_broken() {
        let mut ctx = Context::new(());
        ctx.regs[3] = 1;

        // 67 03 00 00 20 00 00 00 | r3 <<= 0x20 (64-bit)
        let instr = Instruction(0x0000002000000367);

        crate::step(&mut ctx, instr);

        assert_eq!(1_u64.checked_shl(32).unwrap_or(0), 1 << 32);
        assert_eq!(ctx.regs[3], 1 << 32);
    }
}
