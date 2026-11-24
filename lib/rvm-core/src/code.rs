//! Prepared code: [`Code`], and the passes of [`Code::new`] that turn instructions into the slots the handlers run.

use std::fmt::{self, Debug, Formatter};

#[cfg(feature = "fuel")]
use crate::fuel::Rests;
use crate::opcode::{OpCode, CALL};
use crate::slot::Slot;
use crate::{bytes, fuse, native, rewrite, transfer, Instruction, MAX_NATIVE_ARGS};

/// Bytecode prepared for an [`Interpreter`](crate::Interpreter).
pub struct Code {
    /// The code, then the slots [`transfer::bound`] appends.
    slots: Box<[Slot]>,
    len: usize,
    #[cfg(feature = "fuel")]
    rests: Rests,
}

impl Code {
    /// Prepare `insns`: fail what can't run, and fuse the sequences that have a superinstruction.
    ///
    /// r10 is read-only, so an instruction that would write it fails with
    /// [`Reason::InvalidInstruction`](crate::Reason::InvalidInstruction): an ALU, ALU64 or LDX instruction, LD_IMM64
    /// or a load-acquire with `dst_reg` 10, and an atomic that fetches into `src_reg` 10.
    ///
    /// An instruction that sets a field the kernel verifier reserves fails the same way, as the verifier rejects it
    /// (`check_insn_fields` and the LD_IMM64 check in `check_and_resolve_insns`, kernel/bpf/verifier.c):
    /// - `src_reg` of ALU operations and conditional jumps with an immediate, END, ST, `ja`, `gotox`, `callx` and
    ///   `exit`, and `dst_reg` of `ja`, `exit` and `call` with an immediate;
    /// - `offset` of ALU operations but DIV, MOD and `mov` from a register, of `gotox`, `callx`, JMP32 `ja`,
    ///   LD_IMM64, and `call` but a kfunc's;
    /// - `imm` of ALU operations but END and of conditional jumps from a register, of LDX, STX, NEG, JMP `ja`,
    ///   `gotox`, `callx` and `exit`;
    /// - NEG from a register, `call` with a `src_reg` other than 0, 1 and 2, and LD_IMM64 whose second slot holds
    ///   anything but the upper half of the immediate.
    ///
    /// The verifier accepts `exit` with `src_reg` 1, which unwinds; `Code::new` fails it, as it does `may_goto` with
    /// that `src_reg`.
    ///
    /// The code keeps the allocation of `insns` if it has room for one more slot.
    ///
    /// # Panics
    ///
    /// Panics if `insns` has 2^31 slots or more.
    pub fn new(insns: impl Into<Vec<Instruction>>) -> Self {
        let mut insns = insns.into();
        let len = insns.len();
        i32::try_from(len).expect("fewer than 2^31 slots");

        rewrite::rewrite(&mut insns);
        fuse::fuse(&mut insns);
        transfer::bound(&mut insns);

        // in place, as `Slot` and `Instruction` have the same size and alignment
        let slots: Vec<Slot> = insns.into_iter().map(Slot::new).collect();
        Self {
            slots: slots.into_boxed_slice(),
            len,
            #[cfg(feature = "fuel")]
            rests: Rests::default(),
        }
    }

    /// The number of instruction slots.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Make the `call` in slot `pc` a call of the native function at `index` in
    /// [`Host::natives`](crate::Host::natives), which takes the `args` argument registers r1 to rN in the Windows x64
    /// convention and returns r0. With `checked`, the call first passes each pointer argument of the function's
    /// [`NativeSig`](crate::NativeSig) through [`Memory::native_ptr`](crate::Memory::native_ptr) and stops with
    /// [`Reason::MemoryFault`](crate::Reason::MemoryFault) where that fails. A call counts as one instruction, and its
    /// native function runs unmetered.
    ///
    /// Returns false and leaves the code as it is if slot `pc` holds no `call` or `args` exceeds
    /// [`MAX_NATIVE_ARGS`].
    ///
    /// # Safety
    ///
    /// For every run of this code, an entry at `index` in the host's `natives` must be a function callable as
    /// `unsafe extern "win64" fn(u64, ...) -> u64` with `args` arguments, with a signature of `args` arguments, and
    /// sound to call with any argument values but the pointers that `checked` resolves. It must not unwind.
    pub unsafe fn bind_native(&mut self, pc: usize, index: u32, args: u8, checked: bool) -> bool {
        let args = usize::from(args);
        let Some(slot) = self.slots[..self.len].get_mut(pc) else {
            return false;
        };
        if slot.byte() != CALL || args > MAX_NATIVE_ARGS {
            return false;
        }
        let byte = native::byte(args, checked && args != 0);
        *slot = Slot::new(Instruction::new(OpCode(byte), 0, 0, 0, index as i32));
        true
    }

    /// Bytes the load or store in slot `pc` accesses, or `None` if the slot holds none, for reporting a
    /// [`Reason::MemoryFault`](crate::Reason::MemoryFault) at `pc`.
    #[cold]
    pub fn access_size(&self, pc: u64) -> Option<usize> {
        let opc = OpCode(bytes::usual(self.slots().get(pc)?.byte()));
        opc.is_access().then(|| opc.mem_size().bytes())
    }

    /// The code and the slots after it, which all hold [`GUARD`](transfer::GUARD).
    #[inline(always)]
    pub(crate) fn slots(&self) -> Slots<'_> {
        Slots {
            first: self.slots.as_ptr(),
            code: self,
        }
    }
}

impl Debug for Code {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("slots", &self.slots)
            .field("len", &self.len)
            .finish()
    }
}

/// The slots of a [`Code`] as the handlers receive them: the pointer to the first, which every handler that needs
/// the pc of its ip reads, and the code, for the handlers that check a pc. They take two registers.
#[derive(Clone, Copy)]
pub struct Slots<'a> {
    /// `code.slots.as_ptr()`.
    first: *const Slot,
    code: &'a Code,
}

impl<'a> Slots<'a> {
    /// The pointer to the first slot, valid for reads of every slot while the code is borrowed.
    #[inline(always)]
    pub fn first(self) -> *const Slot {
        self.first
    }

    /// All slots.
    #[inline(always)]
    pub fn all(self) -> &'a [Slot] {
        &self.code.slots
    }

    /// The slot at `pc`, if there is one.
    #[inline(always)]
    pub fn get(self, pc: u64) -> Option<Slot> {
        if pc >= self.all().len() as u64 {
            return None;
        }
        // SAFETY: `pc` is below the number of slots, which `first` points to
        Some(unsafe { *self.first.add(pc as usize) })
    }

    /// The pc of the slot at address `addr`, which lies in these slots.
    #[inline(always)]
    pub fn pc_at(self, addr: usize) -> u64 {
        ((addr - self.first.addr()) / size_of::<Slot>()) as u64
    }

    /// The `rest` of each slot, which metered runs read.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub fn rests(self) -> &'a Rests {
        &self.code.rests
    }
}
