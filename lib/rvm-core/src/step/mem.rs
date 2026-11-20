//! The load and store classes: LD, LDX, ST and STX, with the atomics.

use super::{Regs, Step};
use crate::opcode::atomic::{ADD, AND, CMPXCHG, FETCH, LOAD_ACQ, OR, STORE_REL, XCHG, XOR};
use crate::opcode::{MemMode, MemSize};
use crate::slot::{Fields, Reg};
use crate::{AtomicOp, Instruction, Memory, Reason};

/// Where a store takes its value from, by class.
pub const SOURCE_REG: bool = true;
pub const SOURCE_IMM: bool = false;

/// The address `insn` accesses through the base register value `base`.
#[inline(always)]
pub fn address(base: u64, insn: impl Fields) -> u64 {
    base.wrapping_add_signed(i64::from(insn.offset()))
}

fn store_plain<M: Memory>(mem: &mut M, size: MemSize, addr: u64, value: u64) -> Result<(), M::Error> {
    match size {
        MemSize::Byte => mem.store_u8(addr, value as u8),
        MemSize::Half => mem.store_u16(addr, value as u16),
        MemSize::Word => mem.store_u32(addr, value as u32),
        MemSize::DWord => mem.store_u64(addr, value),
    }
}

fn load_plain<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Error> {
    match size {
        MemSize::Byte => mem.load_u8(addr).map(u64::from),
        MemSize::Half => mem.load_u16(addr).map(u64::from),
        MemSize::Word => mem.load_u32(addr).map(u64::from),
        MemSize::DWord => mem.load_u64(addr),
    }
}

fn load_sx<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Error> {
    match size {
        MemSize::Byte => mem.load_u8(addr).map(|x| x as i8 as i64 as u64),
        MemSize::Half => mem.load_u16(addr).map(|x| x as i16 as i64 as u64),
        MemSize::Word => mem.load_u32(addr).map(|x| x as i32 as i64 as u64),
        MemSize::DWord => unreachable!("`load` fails LDX | MEMSX | DW"),
    }
}

// `ordered` is out of line already, so its two helpers inline into it: left to LLVM, they stay out of line once the
// methods of the memory inline into them, and each ordered access takes a second call.
#[inline(always)]
fn load_acquire<M: Memory>(mem: &M, size: MemSize, addr: u64) -> Result<u64, M::Error> {
    match size {
        MemSize::Byte => mem.load_acquire_u8(addr).map(u64::from),
        MemSize::Half => mem.load_acquire_u16(addr).map(u64::from),
        MemSize::Word => mem.load_acquire_u32(addr).map(u64::from),
        MemSize::DWord => mem.load_acquire_u64(addr),
    }
}

#[inline(always)]
fn store_release<M: Memory>(mem: &mut M, size: MemSize, addr: u64, value: u64) -> Result<(), M::Error> {
    match size {
        MemSize::Byte => mem.store_release_u8(addr, value as u8),
        MemSize::Half => mem.store_release_u16(addr, value as u16),
        MemSize::Word => mem.store_release_u32(addr, value as u32),
        MemSize::DWord => mem.store_release_u64(addr, value),
    }
}

/// `ST` or, with [`SOURCE_REG`], `STX`.
#[inline(always)]
pub fn store<M: Memory, R: Regs, const SOURCE: bool>(
    regs: &mut R,
    mem: &mut M,
    insn: impl Fields,
) -> Result<(), Reason<M::Error>> {
    let val = match SOURCE {
        SOURCE_REG => regs.get(insn.src_reg()),
        SOURCE_IMM => i64::from(insn.imm()) as u64,
    };
    let addr = address(regs.get(insn.dst_reg()), insn);

    let opc = insn.opcode();
    let size = opc.mem_size();
    let mode = opc.mem_mode();

    match mode {
        MemMode::Mem => store_plain(mem, size, addr, val).map_err(Reason::MemoryFault),
        MemMode::Atomic if SOURCE == SOURCE_REG => atomic(regs, mem, insn.instruction(), size, addr, val),
        // ABS and IND exist only in the LD class
        _ => Err(Reason::InvalidInstruction),
    }
}

/// `STX | ATOMIC`: `imm` selects the operation. The read-modify-write operations take W and DW sizes only;
/// [`ordered`] runs the rest.
// takes `insn` as an `Instruction`, which atomics hold in their slot as it is, so that this function receives it in a
// register when it isn't inlined
fn atomic<M: Memory, R: Regs>(
    regs: &mut R,
    mem: &mut M,
    insn: Instruction,
    size: MemSize,
    addr: u64,
    src: u64,
) -> Result<(), Reason<M::Error>> {
    let imm = insn.imm();
    let r0 = regs.get(Reg::R0);

    let old = match size {
        MemSize::Word => {
            read_modify_write(imm, src as u32, r0 as u32).map(|op| mem.atomic_u32(addr, op).map(u64::from))
        }
        MemSize::DWord => read_modify_write(imm, src, r0).map(|op| mem.atomic_u64(addr, op)),
        MemSize::Byte | MemSize::Half => None,
    };
    let Some(old) = old else {
        return ordered(regs, mem, insn);
    };
    let old = old.map_err(Reason::MemoryFault)?;

    match imm {
        CMPXCHG => regs.set(Reg::R0, old),
        _ if imm & FETCH != 0 => regs.set(Reg::low(insn.src_reg()), old),
        _ => {}
    }
    Ok(())
}

/// The read-modify-write operation that the `imm` of an atomic selects, on the value `src` of its `src_reg`, or `None`
/// if it selects none. CMPXCHG compares with `r0`.
#[inline(always)]
fn read_modify_write<T>(imm: i32, src: T, r0: T) -> Option<AtomicOp<T>> {
    Some(match imm & !FETCH {
        _ if imm == XCHG => AtomicOp::Xchg(src),
        _ if imm == CMPXCHG => AtomicOp::CmpXchg { expected: r0, new: src },
        ADD => AtomicOp::Add(src),
        OR => AtomicOp::Or(src),
        AND => AtomicOp::And(src),
        XOR => AtomicOp::Xor(src),
        _ => return None,
    })
}

/// `STX | ATOMIC` with an `imm` that names no read-modify-write operation: load-acquire and store-release, which
/// take every size. Load-acquire reads through `src_reg` into `dst_reg`, the reverse of the other operations.
// outlined to keep the read-modify-write path in `atomic` short; it takes only `insn` and reads the operands again,
// so that the Windows x64 ABI passes every argument in a register
#[inline(never)]
fn ordered<M: Memory, R: Regs>(regs: &mut R, mem: &mut M, insn: Instruction) -> Result<(), Reason<M::Error>> {
    let size = insn.opcode().mem_size();
    let (dst, src) = (Reg::low(insn.dst_reg()), Reg::low(insn.src_reg()));
    let result = match insn.imm() {
        LOAD_ACQ => {
            let addr = address(regs.get(src), insn);
            load_acquire(mem, size, addr).map(|val| regs.set(dst, val))
        }
        STORE_REL => {
            let addr = address(regs.get(dst), insn);
            store_release(mem, size, addr, regs.get(src))
        }
        _ => return Err(Reason::InvalidInstruction),
    };
    result.map_err(Reason::MemoryFault)
}

/// `LDX`.
#[inline(always)]
pub fn load<M: Memory, R: Regs>(regs: &mut R, mem: &M, insn: impl Fields) -> Result<(), Reason<M::Error>> {
    let addr = address(regs.get(insn.src_reg()), insn);

    let opc = insn.opcode();
    let size = opc.mem_size();
    let mode = opc.mem_mode();

    let loaded = match mode {
        MemMode::Mem => load_plain(mem, size, addr),
        // RFC 9669 defines MEMSX for B, H and W only
        MemMode::MemSX if !matches!(size, MemSize::DWord) => load_sx(mem, size, addr),
        // ABS and IND exist only in the LD class
        _ => return Err(Reason::InvalidInstruction),
    };
    regs.set(insn.dst_reg(), loaded.map_err(Reason::MemoryFault)?);
    Ok(())
}

/// The LD class. LD_IMM64 loads its immediate once its handler has read the upper half ([`Step::LdImm64`]). The pseudo
/// loads (`src_reg` other than 0) and the legacy packet loads are [`Reason::Unsupported`] at their first slot.
#[inline(always)]
pub fn ld<E>(insn: impl Fields) -> Step<E> {
    let opc = insn.opcode();
    let size = opc.mem_size();
    let mode = opc.mem_mode();

    match (mode, size) {
        (MemMode::Imm, MemSize::DWord) if insn.src_reg() == Reg::R0 => Step::LdImm64,
        _ => Step::Stop(Reason::Unsupported),
    }
}
