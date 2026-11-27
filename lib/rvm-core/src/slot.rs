//! The slot format: how a [`Slot`] of [`Code`](crate::Code) holds an instruction. This module is the only code that
//! writes or reads the fields of a slot.
//!
//! [`Code::new`](crate::Code::new) converts each instruction with [`Slot::new`] to the [`Layout`] of its opcode byte
//! ([`LAYOUTS`]):
//!
//! | byte    | [`Layout::Raw`]             | [`Layout::Dst`]     | [`Layout::DstSrc`] |
//! |---------|-----------------------------|---------------------|--------------------|
//! | 0       | opcode byte                 | opcode byte         | opcode byte        |
//! | 1       | `dst_reg` \| `src_reg` << 4 | `dst_reg`           | `dst_reg`          |
//! | 2, 3    | `offset`                    | `offset`            | `offset`           |
//! | 4, 5, 6 | `imm` bits 0 to 23          | `imm` bits 0 to 23  | unused             |
//! | 7       | `imm` bits 24 to 31         | `imm` bits 24 to 31 | `src_reg`          |
//!
//! - [`Layout::DstSrc`]: the instructions that read `src_reg` and no `imm`: ALU operations and conditional jumps from a
//!   register, LDX and STX but atomics.
//! - [`Layout::Dst`]: those that read no `src_reg`: ALU operations and conditional jumps with an immediate, END, `ja`,
//!   `gotox`, `callx`, `exit`, ST and LD_IMM64.
//! - [`Layout::Raw`]: those that read both (`call`, `may_goto`, atomics) and those that read no field.
//!
//! Register invariant: in [`Layout::Dst`] and [`Layout::DstSrc`], byte 1, and in [`Layout::DstSrc`] byte 7, hold a
//! register number below 16. [`Slot::new`] establishes it, [`Code::new`](crate::Code::new) is its only caller, and the
//! fields of a [`Slot`] are private to this module, so every slot holds it. A [`View`] hands those numbers out as a
//! [`Reg`], whose reads of the register file are unchecked.
//!
//! Besides, the slots with an opcode byte that [`rewrite::offset_is_zero`] names hold offset 0.
//!
//! A handler reads the fields of its slot with a [`View`], one instruction per field: its dispatch loaded the slot
//! into RCX, from which `movzx` reads `dst_reg` (CH) and one shift `src_reg` or `imm`; `offset` is a load from the
//! code.

use std::fmt::{self, Debug, Formatter};

use crate::opcode::{AluOpc, Class, JmpOpc, MemMode, OpCode, Source, LD_IMM64};
use crate::{bytes, rewrite, Instruction};

/// A register number below 16, which indexes [`Context::regs`](crate::Context::regs) without a check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reg(u8);

impl Reg {
    pub const R0: Self = Self(0);

    /// The register in the low 4 bits of `bits`.
    #[inline(always)]
    pub const fn low(bits: u8) -> Self {
        Self(bits & 0xF)
    }

    /// # Safety
    ///
    /// `n` must be below 16.
    #[inline(always)]
    const unsafe fn new_unchecked(n: u8) -> Self {
        debug_assert!(n < 16);
        Self(n)
    }

    #[inline(always)]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The fields of an instruction as [`step`](crate::step::step) reads them, from an [`Instruction`] or from a slot
/// ([`View`]).
pub trait Fields: Copy {
    fn opcode(self) -> OpCode;
    fn dst_reg(self) -> Reg;
    /// `src_reg`, which `call` reads as the kind of call.
    fn src_reg(self) -> Reg;
    fn offset(self) -> i16;
    fn imm(self) -> i32;

    /// The instruction with these fields.
    fn instruction(self) -> Instruction;
}

impl Fields for Instruction {
    #[inline(always)]
    fn opcode(self) -> OpCode {
        Instruction::opcode(self)
    }

    #[inline(always)]
    fn dst_reg(self) -> Reg {
        Reg::low(Instruction::dst_reg(self))
    }

    #[inline(always)]
    fn src_reg(self) -> Reg {
        Reg::low(Instruction::src_reg(self))
    }

    #[inline(always)]
    fn offset(self) -> i16 {
        Instruction::offset(self)
    }

    #[inline(always)]
    fn imm(self) -> i32 {
        Instruction::imm(self)
    }

    #[inline(always)]
    fn instruction(self) -> Instruction {
        self
    }
}

/// One slot of a [`Code`](crate::Code): an instruction as [`Code::new`](crate::Code::new) leaves it, in the
/// [`Layout`] of its opcode byte (see the module docs).
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C, align(8))]
pub struct Slot {
    byte: u8,
    regs: u8,
    offset: i16,
    imm: [u8; 4],
}

/// Where a [`Slot`] holds the fields of an instruction; the module docs show the bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    Raw,
    Dst,
    DstSrc,
}

/// The [`Layout`] of each opcode byte: that of the opcode it runs as ([`bytes::usual`]).
pub const LAYOUTS: [Layout; 256] = byte_table!(|byte| layout(bytes::usual(byte)));

/// The [`Layout`] of the instructions with opcode `byte`.
const fn layout(byte: u8) -> Layout {
    let opc = OpCode(byte);
    let reg = matches!(opc.source(), Source::Reg);
    match opc.class() {
        Class::Alu32 | Class::Alu64 => match opc.alu_opc() {
            // the source bit of END is the byte order, and its width is `imm`
            AluOpc::End => Layout::Dst,
            AluOpc::UndefE | AluOpc::UndefF => Layout::Raw,
            _ if reg => Layout::DstSrc,
            _ => Layout::Dst,
        },
        Class::Jmp32 | Class::Jmp64 => match opc.jmp_opc() {
            // `src_reg` of `call` is the kind of call; `may_goto` and undefined opcodes read no fields
            JmpOpc::Call if !reg => Layout::Raw,
            JmpOpc::Jcond | JmpOpc::UndefF => Layout::Raw,
            // `ja`, `gotox`, `callx` and `exit` read no `src_reg`
            JmpOpc::Ja | JmpOpc::Call | JmpOpc::Exit => Layout::Dst,
            _ if reg => Layout::DstSrc,
            _ => Layout::Dst,
        },
        Class::Ldx => Layout::DstSrc,
        Class::St => Layout::Dst,
        Class::Stx => match opc.mem_mode() {
            MemMode::Atomic => Layout::Raw,
            _ => Layout::DstSrc,
        },
        // `Code::new` leaves LD_IMM64 only where `src_reg` is 0
        Class::Ld if byte == LD_IMM64 => Layout::Dst,
        Class::Ld => Layout::Raw,
    }
}

impl Layout {
    /// The bits of an [`Instruction`] that the layout replaces: `src_reg` in byte 1 for [`Layout::Dst`] and
    /// [`Layout::DstSrc`], and byte 7 for [`Layout::DstSrc`], which takes `src_reg` there.
    const REPLACED: [u64; 3] = {
        const TOP_BYTE: u64 = 0xFF << 56;
        let mut replaced = [0; 3];
        replaced[Layout::Dst as usize] = Instruction::SRC_REG;
        replaced[Layout::DstSrc as usize] = Instruction::SRC_REG | TOP_BYTE;
        replaced
    };
}

impl Slot {
    /// A slot of zeros, in [`Layout::Raw`], for a tail call to a handler that reads the slot from the code.
    pub const UNREAD: Self = Self {
        byte: 0,
        regs: 0,
        offset: 0,
        imm: [0; 4],
    };

    /// `insn` in the layout of its opcode byte. It establishes the register invariant (see the module docs).
    pub fn new(insn: Instruction) -> Self {
        // without branches, as `Code::new` converts every slot
        let layout = LAYOUTS[usize::from(insn.byte())];
        let replaced = Layout::REPLACED[layout as usize];
        let src = u64::from(insn.src_reg());
        let bits = insn.0 & !replaced | src << 56 & replaced;
        let [byte, regs, off_lo, off_hi, imm @ ..] = bits.to_le_bytes();
        let slot = Self {
            byte,
            regs,
            offset: i16::from_le_bytes([off_lo, off_hi]),
            imm,
        };
        debug_assert!(layout == Layout::Raw || slot.regs < 16);
        debug_assert!(layout != Layout::DstSrc || slot.imm[3] < 16);
        slot
    }

    /// The opcode byte, which selects the handler.
    #[inline(always)]
    pub fn byte(self) -> u8 {
        self.byte
    }

    /// `imm`, which every layout but [`Layout::DstSrc`] keeps.
    #[inline(always)]
    pub fn imm(self) -> i32 {
        debug_assert!(LAYOUTS[usize::from(self.byte)] != Layout::DstSrc);
        i32::from_le_bytes(self.imm)
    }

    /// The instruction a slot in [`Layout::Raw`] holds.
    pub fn instruction(self) -> Instruction {
        debug_assert!(LAYOUTS[usize::from(self.byte)] == Layout::Raw);
        let [off_lo, off_hi] = self.offset.to_le_bytes();
        let [i0, i1, i2, i3] = self.imm;
        Instruction(u64::from_le_bytes([self.byte, self.regs, off_lo, off_hi, i0, i1, i2, i3]))
    }

    /// The `dst_reg` field of a slot whose layout is [`Layout::Dst`] or [`Layout::DstSrc`].
    #[inline(always)]
    pub fn dst_reg_decoded(self) -> Reg {
        debug_assert!(LAYOUTS[usize::from(self.byte)] != Layout::Raw && self.regs < 16);
        // SAFETY: `Slot::new` established `self.regs < 16` for non-Raw layouts.
        unsafe { Reg::new_unchecked(self.regs) }
    }

    /// The `src_reg` field of a slot whose layout is [`Layout::DstSrc`].
    #[inline(always)]
    pub fn src_reg_decoded(self) -> Reg {
        debug_assert!(LAYOUTS[usize::from(self.byte)] == Layout::DstSrc && self.imm[3] < 16);
        // SAFETY: `Slot::new` established `self.imm[3] < 16` for `Layout::DstSrc`.
        unsafe { Reg::new_unchecked(self.imm[3]) }
    }

    /// The `offset` field of a portable slot.
    #[inline(always)]
    pub fn offset_raw(self) -> i16 {
        self.offset
    }

    /// Re-encode a portable [`Layout::DstSrc`] slot for the threaded stream: `dst` in byte 0 (`CL`), `src` in byte 1
    /// (`CH`), and `extra` (`i32::from(offset)` or pre-scaled jump byte offset) in bytes 4..8 (`RCX >> 32`).
    #[inline(always)]
    pub fn to_threaded_dst_src(self, extra: i32) -> Self {
        debug_assert!(LAYOUTS[usize::from(self.byte)] == Layout::DstSrc);
        Self {
            byte: self.regs,
            regs: self.imm[3],
            offset: 0,
            imm: extra.to_le_bytes(),
        }
    }

    /// Pre-scaled jump or local call slot holding a byte displacement in bytes 4..8 (`RCX >> 32`).
    #[inline(always)]
    pub fn scaled_jump(byte_offset: i32) -> Self {
        Self {
            byte: 0,
            regs: 0,
            offset: 0,
            imm: byte_offset.to_le_bytes(),
        }
    }

    /// Raw 32-bit signed payload in bytes 4..8 (`RCX >> 32`).
    #[inline(always)]
    pub fn imm_i32(self) -> i32 {
        i32::from_le_bytes(self.imm)
    }

    /// Pack custom pre-decoded threaded operands: `b0` in byte 0 (`CL`), `b1` in byte 1 (`CH`), `off` in bytes 2..4,
    /// and `imm` in bytes 4..8 (`RCX >> 32`).
    #[inline(always)]
    pub fn pack(b0: u8, b1: u8, off: i16, imm: i32) -> Self {
        Self {
            byte: b0,
            regs: b1,
            offset: off,
            imm: imm.to_le_bytes(),
        }
    }

    /// Pack four byte fields (`b0..=b3`) in bytes 0..4 and `imm` in bytes 4..8 (`RCX >> 32`).
    #[inline(always)]
    pub fn pack_bytes(b0: u8, b1: u8, b2: u8, b3: u8, imm: i32) -> Self {
        Self {
            byte: b0,
            regs: b1,
            offset: i16::from_le_bytes([b2, b3]),
            imm: imm.to_le_bytes(),
        }
    }

    /// Byte 0 (`CL`) as a validated [`Reg`].
    ///
    /// # Safety
    ///
    /// Byte 0 of `self` must be `< 16`.
    #[inline(always)]
    pub unsafe fn reg0(self) -> Reg {
        // SAFETY: caller guarantees byte 0 < 16.
        unsafe { Reg::new_unchecked(self.byte) }
    }

    /// Byte 1 (`CH`) as a validated [`Reg`].
    ///
    /// # Safety
    ///
    /// Byte 1 of `self` must be `< 16`.
    #[inline(always)]
    pub unsafe fn reg1(self) -> Reg {
        // SAFETY: caller guarantees byte 1 < 16.
        unsafe { Reg::new_unchecked(self.regs) }
    }

    /// Byte 2 (low byte of `offset`) as a validated [`Reg`].
    ///
    /// # Safety
    ///
    /// Byte 2 of `self` must be `< 16`.
    #[inline(always)]
    pub unsafe fn reg2(self) -> Reg {
        // SAFETY: caller guarantees byte 2 < 16.
        unsafe { Reg::new_unchecked((self.offset as u16) as u8) }
    }

    /// Byte 3 (high byte of `offset`) as a validated [`Reg`].
    ///
    /// # Safety
    ///
    /// Byte 3 of `self` must be `< 16`.
    #[inline(always)]
    pub unsafe fn reg3(self) -> Reg {
        // SAFETY: caller guarantees byte 3 < 16.
        unsafe { Reg::new_unchecked(((self.offset as u16) >> 8) as u8) }
    }

    /// Byte 2 as a raw `u8`.
    #[inline(always)]
    pub fn byte2(self) -> u8 {
        (self.offset as u16) as u8
    }

    /// Byte 3 as a raw `u8`.
    #[inline(always)]
    pub fn byte3(self) -> u8 {
        ((self.offset as u16) >> 8) as u8
    }

    /// Pre-decoded 3-operand ALU immediate slot (`dst = src1 op imm`).
    pub fn alu3_imm(dst: Reg, src1: Reg, imm: i32) -> Self {
        Self {
            byte: src1.get(),
            regs: dst.get(),
            offset: 0,
            imm: imm.to_le_bytes(),
        }
    }

    /// Pre-decoded 3-operand ALU register slot (`dst = src1 op src2`).
    pub fn alu3_reg(dst: Reg, src1: Reg, src2: Reg) -> Self {
        Self {
            byte: src1.get(),
            regs: dst.get(),
            offset: 0,
            imm: [0, 0, 0, src2.get()],
        }
    }

    /// `src1` of a slot built by [`Self::alu3_imm`] or [`Self::alu3_reg`].
    ///
    /// # Safety
    ///
    /// `self` must have been constructed by [`Self::alu3_imm`] or [`Self::alu3_reg`].
    #[inline(always)]
    pub unsafe fn alu3_src1(self) -> Reg {
        // SAFETY: `alu3_*` stores a `Reg` (`< 16`) in `byte`.
        unsafe { Reg::new_unchecked(self.byte) }
    }

    /// `dst` of a slot built by [`Self::alu3_imm`] or [`Self::alu3_reg`].
    ///
    /// # Safety
    ///
    /// `self` must have been constructed by [`Self::alu3_imm`] or [`Self::alu3_reg`].
    #[inline(always)]
    pub unsafe fn alu3_dst(self) -> Reg {
        // SAFETY: `alu3_*` stores a `Reg` (`< 16`) in `regs`.
        unsafe { Reg::new_unchecked(self.regs) }
    }

    /// `src2` of a slot built by [`Self::alu3_reg`].
    ///
    /// # Safety
    ///
    /// `self` must have been constructed by [`Self::alu3_reg`].
    #[inline(always)]
    pub unsafe fn alu3_src2(self) -> Reg {
        // SAFETY: `alu3_reg` stores a `Reg` (`< 16`) in `imm[3]`.
        unsafe { Reg::new_unchecked(self.imm[3]) }
    }

    /// `imm` of a slot built by [`Self::alu3_imm`].
    #[inline(always)]
    pub fn alu3_imm_val(self) -> i32 {
        i32::from_le_bytes(self.imm)
    }
}

/// Shows the fields the layout keeps.
impl Debug for Slot {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // SAFETY: the layout of a slot's own byte is its layout
        let view = unsafe { View::new(self, None, Shape::of(self.byte)) };
        let layout = view.layout();
        let mut s = f.debug_struct("Slot");
        s.field("opcode", &OpCode(self.byte))
            .field("dst_reg", &view.dst_reg().get());
        if layout != Layout::Dst {
            s.field("src_reg", &view.src_reg().get());
        }
        s.field("offset", &view.offset());
        if layout != Layout::DstSrc {
            s.field("imm", &view.imm());
        }
        s.finish()
    }
}

/// What a [`View`] reads of the opcode byte its handler runs: the layout, the opcode and whether `offset` is 0. Each
/// handler passes the shape of its byte as a constant (`const { Shape::of(OP) }`), so the view's choices fold away
/// without loads from the byte tables.
#[derive(Clone, Copy)]
pub struct Shape {
    layout: Layout,
    opcode: u8,
    offset_is_zero: bool,
}

impl Shape {
    /// The shape of opcode byte `byte`: its [`LAYOUTS`] entry, [`bytes::usual`] opcode and
    /// [`rewrite::offset_is_zero`].
    pub const fn of(byte: u8) -> Self {
        Self {
            layout: LAYOUTS[byte as usize],
            opcode: bytes::usual(byte),
            offset_is_zero: rewrite::offset_is_zero(byte),
        }
    }
}

/// The fields of a [`Slot`] as the handler of an opcode byte of shape `shape` reads them: from `held`, the slot in a
/// register, where one instruction extracts them, else from the code (see the module docs). With `THREADED = true`,
/// [`Layout::DstSrc`] reads `dst` from byte 0 (`CL`), `src` from byte 1 (`CH`), and `offset` from bytes 4..8
/// (`RCX >> 32`) with no loads from the code stream.
#[derive(Clone, Copy)]
pub struct View<'a, const THREADED: bool = false> {
    slot: &'a Slot,
    held: Option<Slot>,
    shape: Shape,
}

impl<'a> View<'a, false> {
    /// `held` is the portable slot in `slot` if it is in a register. `slot` has offset 0 if `shape` says so.
    ///
    /// # Safety
    ///
    /// `slot` must have the portable layout of `shape`: `LAYOUTS[slot.byte()] == shape.layout`.
    #[inline(always)]
    pub unsafe fn new(slot: &'a Slot, held: Option<Slot>, shape: Shape) -> Self {
        debug_assert_eq!(LAYOUTS[usize::from(slot.byte)], shape.layout);
        debug_assert!(held.is_none_or(|held| held == *slot));
        debug_assert!(!shape.offset_is_zero || slot.offset == 0);
        Self { slot, held, shape }
    }
}

impl<'a> View<'a, true> {
    /// `held` is the threaded slot in `slot` if it is in a register.
    ///
    /// # Safety
    ///
    /// `slot` must have the threaded layout of `shape`.
    #[inline(always)]
    pub unsafe fn threaded(slot: &'a Slot, held: Option<Slot>, shape: Shape) -> Self {
        debug_assert!(held.is_none_or(|held| held == *slot));
        debug_assert!(match shape.layout {
            Layout::Raw => true,
            Layout::Dst => slot.regs < 16,
            Layout::DstSrc => slot.byte < 16 && slot.regs < 16,
        });
        Self { slot, held, shape }
    }
}

impl<const THREADED: bool> View<'_, THREADED> {
    #[inline(always)]
    fn layout(self) -> Layout {
        self.shape.layout
    }

    /// A register byte of [`Layout::Dst`] or [`Layout::DstSrc`].
    #[inline(always)]
    fn register(self, reg: u8) -> Reg {
        // SAFETY: the slot holds the register invariant (see the module docs) in its layout, which `View::new` /
        // `View::threaded` requires to be the one this view reads
        unsafe { Reg::new_unchecked(reg) }
    }

    #[inline(always)]
    fn byte_field(self) -> u8 {
        self.held.map_or(self.slot.byte, |held| held.byte)
    }

    #[inline(always)]
    fn regs(self) -> u8 {
        self.held.map_or(self.slot.regs, |held| held.regs)
    }

    #[inline(always)]
    fn imm_bytes(self) -> [u8; 4] {
        self.held.map_or(self.slot.imm, |held| held.imm)
    }
}

impl<const THREADED: bool> Fields for View<'_, THREADED> {
    #[inline(always)]
    fn opcode(self) -> OpCode {
        OpCode(self.shape.opcode)
    }

    #[inline(always)]
    fn dst_reg(self) -> Reg {
        match self.layout() {
            Layout::Raw => Reg::low(self.regs()),
            Layout::Dst => self.register(self.regs()),
            Layout::DstSrc if THREADED => self.register(self.byte_field()),
            Layout::DstSrc => self.register(self.regs()),
        }
    }

    #[inline(always)]
    fn src_reg(self) -> Reg {
        match self.layout() {
            Layout::Raw => Reg::low(self.regs() >> 4),
            Layout::Dst => Reg::R0,
            Layout::DstSrc if THREADED => self.register(self.regs()),
            // a load from the code, as many instructions as a shift of `held`, which the handlers that read `dst_reg`
            // from CH afterwards (LDX) would need to copy first
            Layout::DstSrc => self.register(self.slot.imm[3]),
        }
    }

    #[inline(always)]
    fn offset(self) -> i16 {
        match self.shape.offset_is_zero {
            true => 0,
            false if THREADED && matches!(self.layout(), Layout::DstSrc) => i32::from_le_bytes(self.imm_bytes()) as i16,
            false => self.slot.offset,
        }
    }

    #[inline(always)]
    fn imm(self) -> i32 {
        match self.layout() {
            Layout::DstSrc => 0,
            Layout::Raw | Layout::Dst => i32::from_le_bytes(self.imm_bytes()),
        }
    }

    #[inline(always)]
    fn instruction(self) -> Instruction {
        match self.layout() {
            Layout::Raw => self.held.unwrap_or(*self.slot).instruction().with_byte(self.opcode().0),
            Layout::Dst | Layout::DstSrc => {
                let (dst, src) = (self.dst_reg().get(), self.src_reg().get());
                Instruction::new(self.opcode(), dst, src, self.offset(), self.imm())
            }
        }
    }
}
