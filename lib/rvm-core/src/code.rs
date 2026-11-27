//! Prepared code: [`Code`], and the passes of [`Code::new`] that turn instructions into the slots the handlers run.

use std::fmt::{self, Debug, Formatter};

#[cfg(feature = "fuel")]
use crate::fuel::Rests;
use crate::handler::{CALL_HELPER, CALL_KFUNC};
use crate::native::{NativeBind, NativeMode};
use crate::opcode::OpCode;
use crate::slot::Slot;
use crate::{args, bytes, fuse, native, rewrite, transfer, Instruction, MAX_NATIVE_ARGS};

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
        // SAFETY: no native bindings
        unsafe { Self::with_natives(insns, &[]) }.expect("no native bindings")
    }

    /// [`Code::new`] with native call bindings applied before fusion.
    ///
    /// Each entry of `natives` binds the helper or kfunc `call` at `bind.pc` to `Host::natives()[bind.index]`. Fails
    /// with the offending `pc` if `bind.pc` is out of bounds, holds no helper or kfunc `call`, or `bind.args` exceeds
    /// [`MAX_NATIVE_ARGS`].
    ///
    /// # Safety
    ///
    /// For every run of this code, each bound `bind.index` in the host's `natives` must be callable as `bind.mode`
    /// invokes it (`unsafe extern "C" fn(u64, ...) -> u64` with `bind.args` arguments, or through `rvm_call_regs` for
    /// [`NativeMode::Raw`]), with a matching [`NativeSig`](crate::NativeSig), and sound for any argument values not
    /// checked by [`NativeMode::Checked`]. It must not unwind.
    pub unsafe fn with_natives(insns: impl Into<Vec<Instruction>>, natives: &[NativeBind]) -> Result<Self, usize> {
        let mut insns = insns.into();
        let len = insns.len();
        i32::try_from(len).expect("fewer than 2^31 slots");

        rewrite::rewrite(&mut insns);
        for &bind in natives {
            let Some(insn) = insns.get_mut(bind.pc) else {
                return Err(bind.pc);
            };
            let args = usize::from(bind.args);
            if !matches!(insn.byte(), CALL_HELPER | CALL_KFUNC)
                || (bind.mode != NativeMode::Raw && args > MAX_NATIVE_ARGS)
            {
                return Err(bind.pc);
            }
            let byte = native::byte(args, bind.mode);
            *insn = Instruction::new(OpCode(byte), 0, 0, 0, bind.index as i32);
        }
        fuse::fuse(&mut insns);
        transfer::bound(&mut insns);

        // in place, as `Slot` and `Instruction` have the same size and alignment
        let slots: Vec<Slot> = insns.into_iter().map(Slot::new).collect();
        Ok(Self {
            slots: slots.into_boxed_slice(),
            len,
            #[cfg(feature = "fuel")]
            rests: Rests::default(),
        })
    }

    /// The number of instruction slots.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Make the helper or kfunc `call` in slot `pc` a call of the native function at `index` in
    /// [`Host::natives`](crate::Host::natives). See [`Code::with_natives`] for the contract.
    ///
    /// # Safety
    ///
    /// As [`Code::with_natives`].
    pub unsafe fn bind_native(&mut self, pc: usize, index: u32, args: u8, mode: NativeMode) -> bool {
        let args = usize::from(args);
        let Some(slot) = self.slots[..self.len].get_mut(pc) else {
            return false;
        };
        if !matches!(slot.byte(), CALL_HELPER | CALL_KFUNC) || (mode != NativeMode::Raw && args > MAX_NATIVE_ARGS) {
            return false;
        }
        let byte = native::byte(args, mode);
        *slot = Slot::new(Instruction::new(OpCode(byte), 0, 0, 0, index as i32));
        true
    }

    /// Make the kfunc `call` in slot `pc` pass the stack arguments of its frame to the host, which then runs it in
    /// [`Host::call_kfunc_stack`](crate::Host::call_kfunc_stack).
    ///
    /// Returns false and leaves the code as it is if slot `pc` holds no kfunc `call`.
    pub fn pass_stack_args(&mut self, pc: usize) -> bool {
        let Some(slot) = self.slots[..self.len].get_mut(pc) else {
            return false;
        };
        if slot.byte() != CALL_KFUNC {
            return false;
        }
        let insn = slot.instruction();
        *slot = Slot::new(insn.with_byte(args::CALL));
        true
    }

    /// Whether slot `pc` holds a `call` that [`pass_stack_args`](Self::pass_stack_args) marked.
    pub fn passes_stack_args(&self, pc: u64) -> bool {
        self.slots().get(pc).is_some_and(|slot| slot.byte() == args::CALL)
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
