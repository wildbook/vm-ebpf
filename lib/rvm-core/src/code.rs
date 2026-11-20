//! Prepared code: [`Code`], and the passes of [`Code::new`] that turn instructions into the slots the handlers run.

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use crate::opcode::OpCode;
use crate::slot::Slot;
use crate::{bytes, fuel, fuse, rewrite, transfer, Instruction};

/// Bytecode prepared for an [`Interpreter`](crate::Interpreter).
pub struct Code {
    /// The slots, then what the metering keeps for them ([`fuel::store`]).
    storage: Box<[Slot]>,
    /// The number of slots: the code, then the slots [`transfer::bound`] appends.
    slots: usize,
    len: usize,
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
    /// The code keeps the allocation of `insns` if it has room for one more slot, or with the `fuel` feature for two
    /// slots per instruction and two more.
    ///
    /// # Panics
    ///
    /// Panics if `insns` has 2^31 slots or more.
    pub fn new(insns: impl Into<Vec<Instruction>>) -> Self {
        let mut insns = insns.into();
        let len = insns.len();
        i32::try_from(len).expect("fewer than 2^31 slots");

        fuel::reserve(&mut insns);
        rewrite::rewrite(&mut insns);
        fuse::fuse(&mut insns);
        transfer::bound(&mut insns);

        Self {
            slots: insns.len(),
            storage: fuel::store(insns),
            len,
        }
    }

    /// The number of instruction slots.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
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
            first: self.storage.as_ptr(),
            len: self.slots,
            code: PhantomData,
        }
    }
}

/// Shows the slots, each with the `rest` of its block if the code keeps it.
impl Debug for Code {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let code = self.slots();
        let slots = (0..self.slots as u64).filter_map(|pc| {
            let (slot, rest) = (code.get(pc)?, fuel::rest_at(code, pc));
            Some(fmt::from_fn(move |f| match rest {
                Some(rest) => write!(f, "{slot:?} rest {rest}"),
                None => write!(f, "{slot:?}"),
            }))
        });
        f.debug_struct("Code")
            .field("slots", &fmt::from_fn(|f| f.debug_list().entries(slots.clone()).finish()))
            .field("len", &self.len)
            .finish()
    }
}

/// The slots of a [`Code`] as the handlers receive them: a pointer and a length, which take two registers as a slice
/// does.
///
/// It is no slice, because a slice may only reach its own elements: a pointer made from `Slots` may reach the whole
/// storage of the code, in which [`fuel`] keeps the `rest` of each slot behind the slots.
#[derive(Clone, Copy)]
pub struct Slots<'a> {
    /// Valid for reads of `len` slots while the code is borrowed.
    first: *const Slot,
    len: usize,
    code: PhantomData<&'a Code>,
}

impl Slots<'_> {
    /// The number of slots, which the `rest` of each follows if the code keeps it.
    #[cfg(feature = "fuel")]
    #[inline(always)]
    pub fn len(self) -> usize {
        self.len
    }

    /// The pointer to the first slot, which may reach the whole storage of the code.
    #[inline(always)]
    pub fn first(self) -> *const Slot {
        self.first
    }

    /// The slot at `pc`, if there is one.
    #[inline(always)]
    pub fn get(self, pc: u64) -> Option<Slot> {
        if pc >= self.len as u64 {
            return None;
        }
        // SAFETY: `pc` is below `len`, and `first` is valid for reads of `len` slots
        Some(unsafe { *self.first.add(pc as usize) })
    }

    /// The pc of the slot at address `addr`, which lies in these slots.
    #[inline(always)]
    pub fn pc_at(self, addr: usize) -> u64 {
        ((addr - self.first.addr()) / size_of::<Slot>()) as u64
    }
}
