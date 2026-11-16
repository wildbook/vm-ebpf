//! Execution engine for eBPF programs.
//!
//! The executor runs eBPF bytecode using the rvm-core instruction stepping,
//! and dispatches helper function calls to the registered helpers.

use std::fmt::Debug;

use rvm_core::{run, Context, Flow, Instruction, Memory};

use crate::error::{ExecError, HelperError, Result};
use crate::helper::{HelperArgs, HelperContext, HelperRegistry};
use crate::layout::CODE_REGION;
use crate::maps::Maps;
use crate::memory::{region_base, VmMemory};

/// Maximum nesting of BPF-to-BPF calls below the entry frame.
pub const MAX_CALL_DEPTH: usize = 8;

/// Default stack bytes reserved per call frame (eBPF's `MAX_BPF_STACK`).
pub const DEFAULT_FRAME_SIZE: u64 = 512;

/// Helper ID of the call the linker plants for a CO-RE relocation the host can't
/// resolve (`btf::CORE_POISON_HELPER`).
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// Caller state saved across a BPF-to-BPF call.
#[derive(Clone, Copy, Default)]
struct Frame {
    /// r6-r9 (callee-saved) and r10 (frame pointer).
    regs: [u64; 5],
    return_pc: u64,
}

/// Executor for eBPF programs.
///
/// Handles the main execution loop, including:
/// - Instruction fetching and execution via rvm-core
/// - Helper function dispatch
/// - BPF-to-BPF function calls, each with its own stack frame
/// - Instruction limit enforcement
///
/// Code is a separate instruction slice, so the guest can neither read nor modify
/// it through memory. Generic over any [`Memory`]; memory stays borrowed, so it
/// survives errors.
pub struct Executor<'a, M: Memory = VmMemory> {
    code: &'a [Instruction],
    memory: &'a mut M,
    helpers: &'a HelperRegistry<M>,
    /// Initial r10.
    stack_top: u64,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
    /// Maximum instructions to execute (0 = unlimited).
    instruction_limit: u64,
    /// Maps passed to helpers through [`HelperContext::maps`].
    maps: Option<&'a mut Maps>,
}

impl<'a, M: Memory<Err: Debug> + 'static> Executor<'a, M> {
    /// Create a new executor.
    pub fn new(code: &'a [Instruction], memory: &'a mut M, helpers: &'a HelperRegistry<M>, stack_top: u64) -> Self {
        Self {
            code,
            memory,
            helpers,
            stack_top,
            frame_size: DEFAULT_FRAME_SIZE,
            instruction_limit: 0,
            maps: None,
        }
    }

    /// Set the instruction limit (0 = unlimited).
    pub fn set_instruction_limit(&mut self, limit: u64) {
        self.instruction_limit = limit;
    }

    /// Set the stack bytes reserved per call frame.
    pub fn set_frame_size(&mut self, size: u64) {
        self.frame_size = size;
    }

    /// Give helpers access to `maps`.
    pub fn set_maps(&mut self, maps: &'a mut Maps) {
        self.maps = Some(maps);
    }

    /// Call the function at `pc` (instruction index) with `args` in r1-r5; returns r0.
    // The whole interpreter inlines into this function. Code changes elsewhere moved
    // where it starts within a cache line, which alone moved guest timings by ~7%, so
    // it stays a separate function pinned to a line.
    #[inline(never)]
    #[rustc_align(64)]
    pub fn call(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        let mut ctx = Context::new(&mut *self.memory);
        for (i, &arg) in args.iter().take(5).enumerate() {
            ctx.regs[i + 1] = arg;
        }
        ctx.regs[10] = self.stack_top;

        let mut stack = CallStack {
            frames: [Frame::default(); MAX_CALL_DEPTH],
            depth: 0,
            frame_size: self.frame_size,
        };
        let mut pc = pc;
        let limit = match self.instruction_limit {
            0 => u64::MAX,
            limit => limit,
        };
        let mut fuel = limit;

        loop {
            pc = match run(&mut ctx, self.code, &mut pc, &mut fuel) {
                Flow::Call(offset) => {
                    stack.push(&mut ctx.regs, pc + 1)?;
                    pc.wrapping_add_signed(offset + 1)
                }
                Flow::Exit if stack.depth == 0 => return Ok(ctx.regs[0]),
                Flow::Exit => {
                    stack.depth -= 1;
                    let frame = &stack.frames[stack.depth];
                    ctx.regs[6..=10].copy_from_slice(&frame.regs);
                    frame.return_pc
                }
                // Raw bytecode path: look the helper ID up. Linked programs only use slots,
                // except for calls the linker planted for unresolved CO-RE relocations.
                Flow::CallHelper(CORE_POISON_HELPER) => {
                    return Err(ExecError::UnresolvedCoreRelo { pc }.into());
                }
                Flow::CallHelper(id) => {
                    let slot = self.helpers.slot_of_id(id).ok_or(HelperError::UnknownHelper(id))?;
                    ctx.regs[0] = call_slot(self.helpers, slot, &mut ctx, self.maps.as_deref_mut())?;
                    pc + 1
                }
                Flow::CallKfunc(slot) => {
                    ctx.regs[0] = call_slot(self.helpers, slot, &mut ctx, self.maps.as_deref_mut())?;
                    pc + 1
                }
                Flow::OutOfFuel => return Err(ExecError::InstructionLimit(limit).into()),
                Flow::BadPc => return Err(ExecError::InvalidPc(pc).into()),
                Flow::FailCpu => return Err(ExecError::CpuFault.into()),
                Flow::FailMem(err) => {
                    return Err(ExecError::MemoryFault(format!("access at {err:#x?} (pc {pc})")).into())
                }
                Flow::Missing => return Err(ExecError::Unimplemented.into()),
                Flow::CallIndirect(target) => {
                    let maps = self.maps.as_deref_mut();
                    call_indirect(target, pc, self.code, self.helpers, &mut ctx, maps, &mut stack)?
                }
                Flow::JumpIndirect(target) => jump_indirect(target, pc, self.code)?,
                // `run` handles these internally
                Flow::Next | Flow::Jump(_) => unreachable!(),
            };
        }
    }
}

/// Caller frames of the BPF-to-BPF calls in progress.
struct CallStack {
    frames: [Frame; MAX_CALL_DEPTH],
    depth: usize,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
}

impl CallStack {
    /// Save the caller's state and give the callee its stack frame.
    #[inline(always)]
    fn push(&mut self, regs: &mut [u64; 16], return_pc: u64) -> Result<()> {
        if self.depth == MAX_CALL_DEPTH {
            return Err(ExecError::StackOverflow.into());
        }
        let callee_fp = regs[10].checked_sub(self.frame_size).ok_or(ExecError::StackOverflow)?;
        self.frames[self.depth] = Frame {
            regs: [regs[6], regs[7], regs[8], regs[9], regs[10]],
            return_pc,
        };
        self.depth += 1;
        regs[10] = callee_fp;
        Ok(())
    }
}

/// `callx` at `pc`: enter the function at code address `target`, or call the helper
/// whose ID is `target`. Returns the next pc. Kept out of line so the call and exit
/// paths in [`Executor::call`] compile as they would without it.
#[cold]
#[inline(never)]
fn call_indirect<M: Memory<Err: Debug> + 'static>(
    target: u64,
    pc: u64,
    code: &[Instruction],
    helpers: &HelperRegistry<M>,
    ctx: &mut Context<&mut M>,
    maps: Option<&mut Maps>,
    stack: &mut CallStack,
) -> Result<u64> {
    if let Some(callee) = code_index(target, code) {
        stack.push(&mut ctx.regs, pc + 1)?;
        return Ok(callee);
    }

    // A helper's address is its ID, as in libbpf's `(void *)BPF_FUNC_*` helper
    // declarations.
    let id = u32::try_from(target).map_err(|_| ExecError::BadCodeAddress { pc, target })?;
    let slot = helpers.slot_of_id(id).ok_or(HelperError::UnknownHelper(id))?;
    ctx.regs[0] = call_slot(helpers, slot, ctx, maps)?;
    Ok(pc + 1)
}

/// `gotox` at `pc`: the instruction index of code address `target`.
#[cold]
#[inline(never)]
fn jump_indirect(target: u64, pc: u64, code: &[Instruction]) -> Result<u64> {
    code_index(target, code).ok_or_else(|| ExecError::BadCodeAddress { pc, target }.into())
}

/// Instruction index of the guest code address `addr`, if it is an instruction
/// boundary inside `code`.
fn code_index(addr: u64, code: &[Instruction]) -> Option<u64> {
    let offset = addr.checked_sub(region_base(CODE_REGION))?;
    (offset % 8 == 0 && offset / 8 < code.len() as u64).then_some(offset / 8)
}

/// Call the extern table entry at `slot` with the arguments in `ctx.regs[1..=5]`.
fn call_slot<M: Memory<Err: Debug> + 'static>(
    helpers: &HelperRegistry<M>,
    slot: u32,
    ctx: &mut Context<&mut M>,
    maps: Option<&mut Maps>,
) -> Result<u64> {
    let mut helper_ctx = HelperContext {
        args: HelperArgs::from_regs(&ctx.regs),
        memory: &mut *ctx.data,
        maps,
    };
    Ok(helpers.call_slot(slot, &mut helper_ctx)?)
}

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R0, R6, R7};

    use super::*;
    use crate::error::VmError;
    use crate::memory::Perms;

    fn run(asm: &mut Assembler, args: &[u64], limit: u64) -> Result<u64> {
        let code = crate::instructions_from_bytes(&asm.assemble().unwrap());
        let mut memory = VmMemory::new();
        let stack_top = memory.map(1, 512, Perms::RW) + 512;
        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, stack_top);
        executor.set_instruction_limit(limit);
        executor.call(0, args)
    }

    #[test]
    fn test_instruction_limit() {
        let mut asm = Assembler::new();
        let mut loop_label = asm.create_label();
        asm.set_label(&mut loop_label).unwrap();
        asm.ja(&loop_label);
        assert!(matches!(run(&mut asm, &[], 10), Err(VmError::Exec(ExecError::InstructionLimit(_)))));
    }

    #[test]
    fn test_running_off_code_end_is_invalid_pc() {
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 1);
        assert!(matches!(run(&mut asm, &[], 0), Err(VmError::Exec(ExecError::InvalidPc(1)))));
    }

    #[test]
    fn test_stack_overflow_deep_recursion() {
        let mut asm = Assembler::new();
        let mut func_start = asm.create_label();
        asm.set_label(&mut func_start).unwrap();
        asm.call_local(&func_start);
        asm.exit();
        assert!(matches!(run(&mut asm, &[], 0), Err(VmError::Exec(ExecError::StackOverflow))));
    }

    #[test]
    fn test_callee_saved_registers_survive_a_local_call() {
        let mut asm = Assembler::new();
        let mut callee = asm.create_label();

        asm.mov64_imm(R6, 100);
        asm.mov64_imm(R7, 200);
        asm.call_local(&callee);
        asm.mov64(R0, R6);
        asm.add64(R0, R7);
        asm.exit();

        asm.set_label(&mut callee).unwrap();
        asm.mov64_imm(R6, 0);
        asm.mov64_imm(R7, 0);
        asm.exit();

        assert_eq!(run(&mut asm, &[], 0).unwrap(), 300);
    }
}
