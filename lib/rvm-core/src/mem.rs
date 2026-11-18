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
pub fn save<M: Memory, const X: bool>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M::Err> {
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
fn atomic<M: Memory>(ctx: &mut Context<M>, insn: Instruction, size: MemSize, addr: u64, src: u64) -> Flow<M::Err> {
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
fn ordered<M: Memory>(ctx: &mut Context<M>, insn: Instruction, size: MemSize, addr: u64, src: u64) -> Flow<M::Err> {
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
pub fn load<M: Memory>(ctx: &mut Context<M>, insn: Instruction) -> Flow<M::Err> {
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
pub fn ld64<E>(insn: Instruction) -> ControlFlow<Flow<E>, Instruction> {
    let opc = insn.opcode();
    let size = opc.mem_size();
    let mode = opc.mem_mode();

    match (mode, size) {
        (MemMode::Imm, MemSize::DWord) if insn.src_reg() == 0 => ControlFlow::Continue(insn),
        _ => ControlFlow::Break(Flow::Missing),
    }
}
