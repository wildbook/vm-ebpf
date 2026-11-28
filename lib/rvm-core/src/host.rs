//! What an embedder implements to run the guest's calls of host functions: [`Host`].

use crate::{Context, Memory, Native, NativeCall, StackArgs};

/// The host functions that the guest calls. The interpreter runs them from inside a run, so a call that the host
/// runs costs no stop.
///
/// Each method gets the arguments in `ctx.regs[1..=5]` and returns the new r0. It returns `None` to decline: the run
/// then stops at the call with [`Reason::CallHelper`], [`Reason::CallKfunc`] or [`Reason::CallIndirect`], and the
/// caller of the run decides what the call does. A host that declines records whatever that caller needs.
///
/// Arguments 6 to 12 of a call are stack arguments. Only [`call_kfunc_stack`](Self::call_kfunc_stack) gets them, and
/// the native function that a [`NativeCall`] calls.
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

    /// [`call_kfunc`](Self::call_kfunc) from a `call` that [`Code::pass_stack_args`](crate::Code::pass_stack_args)
    /// marked: `stack` holds the stack arguments as the caller stored them last, argument `5 + k` at index `k - 1`.
    /// The default drops them.
    fn call_kfunc_stack(&mut self, ctx: &mut Context<M>, id: u32, stack: &StackArgs) -> Option<u64> {
        let _ = stack;
        self.call_kfunc(ctx, id)
    }

    /// Call through `target`, the address in the `dst_reg` of a `callx`: name the guest function it addresses, or run
    /// the host function it addresses. For a target that is the address of a native function, `native` runs it.
    fn call_indirect(&mut self, ctx: &mut Context<M>, target: u64, native: NativeCall<'_, M::Error>) -> Option<Callee>;

    /// Resolve a `gotox` target address to an instruction pc in the active code, or `None` to stop the run with
    /// [`Reason::JumpIndirect`](crate::Reason::JumpIndirect).
    #[inline(always)]
    fn jump_indirect(&self, _target: u64) -> Option<u64> {
        None
    }

    /// The native functions that calls bound with [`Code::with_natives`](crate::Code::with_natives) name by index. A
    /// call of an index past the end stops the run with [`Reason::CallKfunc`](crate::Reason::CallKfunc) and that
    /// index. The default has none.
    ///
    /// The entries must meet the contract of `with_natives` for every call in the code of a run that names them.
    fn natives(&self) -> &[Native] {
        &[]
    }

    /// Program identity used to match synchronous callbacks on this thread (`0` if unnamed).
    #[cfg(feature = "callbacks")]
    fn callback_program(&self) -> u64 {
        0
    }

    /// Resolve a `GeneralArg::Callback` guest argument into a native function pointer for one call. Returns the
    /// native address and, if a scoped thunk slot was claimed, its index to pass to
    /// [`release_callback`](Self::release_callback) when the native returns.
    #[cfg(feature = "callbacks")]
    fn prepare_callback(&self, value: u64) -> Result<(u64, Option<u8>), crate::NativeFail> {
        Ok((value, None))
    }

    /// Release a scoped callback thunk slot claimed by [`prepare_callback`](Self::prepare_callback).
    #[cfg(feature = "callbacks")]
    fn release_callback(&self, slot: u8) {
        let _ = slot;
    }

    /// Run a nested guest function from an aware native call. The default runs [`Interpreter::call_nested`](crate::Interpreter::call_nested)
    /// and records any non-return stop as a failure; embedders with a resume loop override this.
    #[cfg(feature = "callbacks")]
    fn run_nested(
        ctx: &mut Context<M>,
        interp: &mut crate::Interpreter<M, Self>,
        code: &crate::Code,
        pc: u64,
        args: &[u64; 5],
        fail: &mut Option<crate::NativeFail>,
    ) -> u64
    where
        Self: Sized,
    {
        match interp.call_nested(ctx, code, pc, args) {
            Ok(r0) => r0,
            Err(stop) => {
                if fail.is_none() {
                    *fail = Some(crate::NativeFail::Code(stop.pc));
                }
                0
            }
        }
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
