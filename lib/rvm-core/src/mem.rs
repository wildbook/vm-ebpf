use std::ops::ControlFlow;

use crate::opcode::atomic::{ADD, AND, CMPXCHG, FETCH, LOAD_ACQ, OR, STORE_REL, XCHG, XOR};
use crate::opcode::{MemMode, MemSize};
use crate::ops::Regs;
use crate::{AtomicOp, Flow, Instruction, Memory};

pub const SOURCE_REG: bool = true;
pub const SOURCE_IMM: bool = false;

/// The address `insn` accesses through the base register value `base`.
#[inline(always)]
pub fn address(base: u64, insn: Instruction) -> u64 {
    base.wrapping_add_signed(i64::from(insn.offset()))
}

pub fn store_plain<M: Memory>(mem: &mut M, size: MemSize, addr: u64, value: u64) -> Result<(), M::Err> {
    match size {
        MemSize::Byte => mem.store_u8(addr, value as u8),
        MemSize::Half => mem.store_u16(addr, value as u16),
        MemSize::Word => mem.store_u32(addr, value as u32),
        MemSize::DWord => mem.store_u64(addr, value),
    }
}

pub fn load_plain<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Err> {
    match size {
        MemSize::Byte => mem.load_u8(addr).map(u64::from),
        MemSize::Half => mem.load_u16(addr).map(u64::from),
        MemSize::Word => mem.load_u32(addr).map(u64::from),
        MemSize::DWord => mem.load_u64(addr),
    }
}

fn load_sx<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Err> {
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

/// `ST` or, with [`SOURCE_REG`], `STX`.
#[inline(always)]
pub fn store<M: Memory, R: Regs, const SOURCE: bool>(regs: &mut R, mem: &mut M, insn: Instruction) -> Flow<M::Err> {
    let val = match SOURCE {
        SOURCE_REG => regs.get(insn.src_reg()),
        SOURCE_IMM => i64::from(insn.imm()) as u64,
    };
    let addr = address(regs.get(insn.dst_reg()), insn);

    let opc = insn.opcode();
    let size = opc.mem_size();
    let mode = opc.mem_mode();

    let result = match mode {
        MemMode::Mem => store_plain(mem, size, addr, val),
        MemMode::Atomic if SOURCE == SOURCE_REG => return atomic(regs, mem, insn, size, addr, val),
        // ABS and IND exist only in the LD class
        _ => return Flow::FailCpu,
    };
    if let Err(err) = result {
        return Flow::FailMem(err);
    }

    Flow::Next
}

/// `STX | ATOMIC`: `imm` selects the operation. The read-modify-write operations take W and DW sizes only;
/// [`ordered`] runs the rest.
fn atomic<M: Memory, R: Regs>(
    regs: &mut R,
    mem: &mut M,
    insn: Instruction,
    size: MemSize,
    addr: u64,
    src: u64,
) -> Flow<M::Err> {
    let src_reg = insn.src_reg();
    let imm = insn.imm();

    // `CmpXchg` compares against r0 and writes the old value there instead of `src`.
    macro_rules! run {
        ($ty:ty, $method:ident) => {{
            let v = src as $ty;
            let op = match imm & !FETCH {
                _ if imm == XCHG => AtomicOp::Xchg(v),
                _ if imm == CMPXCHG => AtomicOp::CmpXchg {
                    expected: regs.get(0) as $ty,
                    new: v,
                },
                ADD => AtomicOp::Add(v),
                OR => AtomicOp::Or(v),
                AND => AtomicOp::And(v),
                XOR => AtomicOp::Xor(v),
                _ => return ordered(regs, mem, insn),
            };
            match mem.$method(addr, op) {
                Ok(old) => old as u64,
                Err(err) => return Flow::FailMem(err),
            }
        }};
    }

    let old = match size {
        MemSize::Word => run!(u32, atomic_u32),
        MemSize::DWord => run!(u64, atomic_u64),
        MemSize::Byte | MemSize::Half => return ordered(regs, mem, insn),
    };

    match imm {
        CMPXCHG => regs.set(0, old),
        _ if imm & FETCH != 0 => regs.set(src_reg, old),
        _ => {}
    }
    Flow::Next
}

/// `STX | ATOMIC` with an `imm` that names no read-modify-write operation: load-acquire and store-release, which
/// take every size. Load-acquire reads through `src_reg` into `dst_reg`, the reverse of the other operations.
// outlined to keep the read-modify-write path in `atomic` short; it takes only `insn` and reads the operands again,
// so that the Windows x64 ABI passes every argument in a register
#[inline(never)]
fn ordered<M: Memory, R: Regs>(regs: &mut R, mem: &mut M, insn: Instruction) -> Flow<M::Err> {
    let size = insn.opcode().mem_size();
    let result = match insn.imm() {
        LOAD_ACQ => {
            let addr = address(regs.get(insn.src_reg()), insn);
            load_acquire(mem, size, addr).map(|val| regs.set(insn.dst_reg(), val))
        }
        STORE_REL => {
            let addr = address(regs.get(insn.dst_reg()), insn);
            store_release(mem, size, addr, regs.get(insn.src_reg()))
        }
        _ => return Flow::FailCpu,
    };
    match result {
        Ok(()) => Flow::Next,
        Err(err) => Flow::FailMem(err),
    }
}

/// `LDX`.
#[inline(always)]
pub fn load<M: Memory, R: Regs>(regs: &mut R, mem: &M, insn: Instruction) -> Flow<M::Err> {
    let addr = address(regs.get(insn.src_reg()), insn);

    let opc = insn.opcode();
    let size = opc.mem_size();
    let mode = opc.mem_mode();

    let loaded = match mode {
        MemMode::Mem => load_plain(mem, size, addr),
        // RFC 9669 defines MEMSX for B, H and W only
        MemMode::MemSX if !matches!(size, MemSize::DWord) => load_sx(mem, size, addr),
        // ABS and IND exist only in the LD class
        _ => return Flow::FailCpu,
    };
    match loaded {
        Ok(val) => regs.set(insn.dst_reg(), val),
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
