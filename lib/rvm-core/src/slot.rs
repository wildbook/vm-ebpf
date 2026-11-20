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
            // `src_reg` of `call` is the kind of call, and `may_goto` checks every field
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
/// register, where one instruction extracts them, else from the code (see the module docs).
#[derive(Clone, Copy)]
pub struct View<'a> {
    slot: &'a Slot,
    held: Option<Slot>,
    shape: Shape,
}

impl<'a> View<'a> {
    /// `held` is the slot in `slot` if it is in a register. `slot` has offset 0 if `shape` says so.
    ///
    /// # Safety
    ///
    /// `slot` must have the layout of `shape`: `LAYOUTS[slot.byte()] == shape.layout`.
    #[inline(always)]
    pub unsafe fn new(slot: &'a Slot, held: Option<Slot>, shape: Shape) -> Self {
        debug_assert_eq!(LAYOUTS[usize::from(slot.byte)], shape.layout);
        debug_assert!(held.is_none_or(|held| held == *slot));
        debug_assert!(!shape.offset_is_zero || slot.offset == 0);
        Self { slot, held, shape }
    }

    #[inline(always)]
    fn layout(self) -> Layout {
        self.shape.layout
    }

    /// A register byte of [`Layout::Dst`] or [`Layout::DstSrc`].
    #[inline(always)]
    fn register(self, reg: u8) -> Reg {
        // SAFETY: the slot holds the register invariant (see the module docs) in its layout, which `View::new`
        // requires to be the one this view reads
        unsafe { Reg::new_unchecked(reg) }
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

impl Fields for View<'_> {
    #[inline(always)]
    fn opcode(self) -> OpCode {
        OpCode(self.shape.opcode)
    }

    #[inline(always)]
    fn dst_reg(self) -> Reg {
        match self.layout() {
            Layout::Raw => Reg::low(self.regs()),
            Layout::Dst | Layout::DstSrc => self.register(self.regs()),
        }
    }

    #[inline(always)]
    fn src_reg(self) -> Reg {
        match self.layout() {
            Layout::Raw => Reg::low(self.regs() >> 4),
            Layout::Dst => Reg::R0,
            // a load from the code, as many instructions as a shift of `held`, which the handlers that read `dst_reg`
            // from CH afterwards (LDX) would need to copy first
            Layout::DstSrc => self.register(self.slot.imm[3]),
        }
    }

    // a load from the code; extracting it from `held` takes three instructions
    #[inline(always)]
    fn offset(self) -> i16 {
        match self.shape.offset_is_zero {
            true => 0,
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
