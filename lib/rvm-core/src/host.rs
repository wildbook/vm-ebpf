//! What an embedder implements to run the guest's calls of host functions: [`Host`].

use crate::{Context, Memory, Native};

/// The host functions that the guest calls. The interpreter runs them from inside a run, so a call that the host
/// runs costs no stop.
///
/// Each method gets the arguments in `ctx.regs[1..=5]` and returns the new r0. It returns `None` to decline: the run
/// then stops at the call with [`Reason::CallHelper`], [`Reason::CallKfunc`] or [`Reason::CallIndirect`], and the
/// caller of the run decides what the call does. A host that declines records whatever that caller needs.
///
/// A method may change the memory and its [epoch](Memory::epoch), and every register but r10.
///
/// [`Reason::CallHelper`]: crate::Reason::CallHelper
/// [`Reason::CallKfunc`]: crate::Reason::CallKfunc
/// [`Reason::CallIndirect`]: crate::Reason::CallIndirect
pub trait Host<M: Memory> {
    /// Call the helper `id` (a `call` with `src_reg` [`HELPER`](crate::opcode::call::HELPER)).
    fn call_helper(&mut self, ctx: &mut Context<M>, id: u32) -> Option<u64>;

    /// Call the external function `id` (a `call` with `src_reg` [`KFUNC`](crate::opcode::call::KFUNC)). The embedder
    /// defines what the ID names.
    fn call_kfunc(&mut self, ctx: &mut Context<M>, id: u32) -> Option<u64>;

    /// Call through `target`, the address in the `dst_reg` of a `callx`: name the guest function it addresses, or run
    /// the host function it addresses.
    fn call_indirect(&mut self, ctx: &mut Context<M>, target: u64) -> Option<Callee>;

    /// The native functions that calls bound with [`Code::bind_native`](crate::Code::bind_native) name by index. A
    /// call of an index past the end stops the run with [`Reason::CallKfunc`] and that index. The default has none.
    ///
    /// The entries must meet the contract of `bind_native` for every call in the code of a run that names them.
    fn natives(&self) -> &[Native] {
        &[]
    }
}

/// What a `callx` calls, as [`Host::call_indirect`] resolves its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Callee {
    /// The guest function at this pc, which the interpreter enters as it does a local call. A pc outside the code
    /// stops the run at the `callx` with [`Reason::CallIndirect`](crate::Reason::CallIndirect).
    Local(u64),
    /// A host function, which [`Host::call_indirect`] ran and which returned this r0.
    Host(u64),
}
