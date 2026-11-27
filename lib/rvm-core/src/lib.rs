//! The eBPF instruction set ([RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html)) and an interpreter for it.
//!
//! [`Code::new`] prepares a program, and an [`Interpreter`] runs it on a [`Context`], which holds the registers and
//! the guest [`Memory`]. The interpreter keeps the frames of local calls and the [`Host`] that runs helper, kfunc and
//! `callx` calls. A run returns a [`Stop`], which says where and why it stopped.
//!
//! ```
//! use rvm_core::opcode::{AluOpc, JmpOpc, OpCode, Source};
//! use rvm_core::{Callee, Code, Context, Host, Instruction, Interpreter, Memory, NativeCall, Reason};
//!
//! struct NoMemory;
//!
//! // SAFETY: the default `window` reports no windows
//! unsafe impl Memory for NoMemory {
//!     type Error = ();
//!
//!     fn load_u8(&self, _addr: u64) -> Result<u8, ()> {
//!         Err(())
//!     }
//!
//!     fn store_u8(&mut self, _addr: u64, _value: u8) -> Result<(), ()> {
//!         Err(())
//!     }
//!
//!     fn native_ptr(&self, _addr: u64, _len: u64, _write: bool) -> Result<u64, ()> {
//!         Err(())
//!     }
//! }
//!
//! /// Declines every call, so a run stops at it.
//! struct NoHost;
//!
//! impl Host<NoMemory> for NoHost {
//!     fn call_helper(&mut self, _ctx: &mut Context<NoMemory>, _id: u32) -> Option<u64> {
//!         None
//!     }
//!
//!     fn call_kfunc(&mut self, _ctx: &mut Context<NoMemory>, _id: u32) -> Option<u64> {
//!         None
//!     }
//!
//!     fn call_indirect(
//!         &mut self,
//!         _ctx: &mut Context<NoMemory>,
//!         _target: u64,
//!         _native: NativeCall<'_, ()>,
//!     ) -> Option<Callee> {
//!         None
//!     }
//! }
//!
//! // mov r0, 7; exit
//! let code = Code::new([
//!     Instruction::new(OpCode::alu64(AluOpc::Mov, Source::Imm), 0, 0, 0, 7),
//!     Instruction::new(OpCode::jmp64(JmpOpc::Exit, Source::Imm), 0, 0, 0, 0),
//! ]);
//! let mut memory = NoMemory;
//! let mut ctx = Context::new(&mut memory);
//! let mut interpreter = Interpreter::new(0, NoHost);
//!
//! let stop = interpreter.run(&mut ctx, &code, 0);
//! assert_eq!((stop.reason, stop.pc), (Reason::Exit, 1));
//! assert_eq!(ctx.regs[0], 7);
//! ```
//!
//! # Features
//!
//! - `fuel` (default): an interpreter can limit the instructions of a run (`Interpreter::set_limit`). A run without
//!   a limit costs the same with and without the feature.
//!
//! # Modules
//!
//! The instruction set:
//! - `instruction`: [`Instruction`], an instruction as bytecode encodes it
//! - [`opcode`]: the opcode byte and its fields
//!
//! What an embedder implements:
//! - `memory`: [`Memory`], with [`Window`] and [`AtomicOp`]
//! - `host`: [`Host`]
//! - `native`: the native functions a host may give the guest, [`Native`] and [`NativeSig`]
//!
//! What one instruction does:
//! - `step`: `step`, which runs an instruction on registers and memory, by class in `step::{alu, jump, mem}`
//!
//! Prepared code, in the order [`Code::new`] works:
//! - `code`: [`Code`]
//! - `bytes`: which opcode byte a slot holds, and what it runs as
//! - `rewrite`: the first pass, which fails what can't run
//! - `fuse`: the second pass, which recognises superinstructions (`fuse::supers` is their table)
//! - `transfer`: the third pass, which proves where handlers continue without a bounds check
//! - `slot`: the format of a slot, the pre-decoded form of an instruction
//!
//! The interpreter:
//! - `interp`: [`Interpreter`], [`Stop`] and [`Reason`]
//! - `context`: [`Context`]
//! - `dispatch`: how one handler continues with the next, and the tables of handlers
//! - `handler`: the handlers of the eBPF opcodes
//! - `fuse::handler`, `windows`, `transfer`, `native`, `args`: the handlers of superinstructions, of loads and stores
//!   in a memory window, of jumps out of the code, of native calls, and of stack arguments
//! - `fuel`: metered runs
//!
//! # Words
//!
//! - An *instruction* is an [`Instruction`]: 8 bytes of eBPF bytecode. LD_IMM64 takes two.
//! - A *slot* is one element of a [`Code`]: an instruction in the layout its handler reads. A `pc` counts slots.
//! - An *opcode byte* is the first byte of a slot, which selects the handler. It is the instruction's opcode, or a
//!   byte that `Code::new` gave the slot.
//! - An *ip* is a pointer to the slot a handler runs.
//!
//! # Unsafe code
//!
//! Each invariant that unsafe code relies on is stated where it is established: the register numbers of a slot in
//! `slot`, where handlers continue in `transfer` (`Ip`), the `rest` of each slot in `fuel`, the windows in
//! [`Memory`] and `windows`, and the frames in `interp`.

#![feature(explicit_tail_calls, rust_preserve_none_cc)]
#![allow(incomplete_features)]

#[macro_use]
mod macros;
#[macro_use]
mod dispatch;

mod args;
mod bytes;
mod code;
mod context;
mod fuel;
mod fuse;
mod handler;
mod host;
mod instruction;
mod interp;
mod memory;
mod native;
mod rewrite;
mod slot;
mod step;
mod transfer;
mod windows;

pub mod opcode;

pub use args::{StackArgs, MAX_STACK_ARGS};
pub use code::Code;
pub use context::Context;
pub use host::{Callee, Host};
pub use instruction::Instruction;
pub use interp::{Interpreter, Reason, Stop, MAX_CALL_DEPTH, METERED};
pub use memory::{AtomicOp, Memory, Window};
pub use native::{
    call_bound, BoundError, Native, NativeArg, NativeBind, NativeCall, NativeFn, NativeMode, NativeSig,
    MAX_ARGS as MAX_NATIVE_ARGS,
};
#[cfg(feature = "ffi")]
pub use native::{fail_code, fail_error, GeneralArg, GeneralProto, GeneralRet, NativeFail};
