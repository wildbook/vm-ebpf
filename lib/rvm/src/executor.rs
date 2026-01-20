//! Execution engine for eBPF programs.
//!
//! The executor runs eBPF bytecode using the rvm-core instruction stepping,
//! and dispatches helper function calls to the registered helpers.

use std::ops::ControlFlow;

use rvm_core::{step, step_ld64, Context, Flow};

use crate::error::{ExecError, Result};
use crate::helper::{HelperArgs, HelperContext, HelperRegistry};
use crate::memory::VmMemory;

/// Maximum call stack depth for BPF-to-BPF calls.
const MAX_CALL_DEPTH: usize = 8;

/// Size of saved registers per call frame (r6-r9, return PC).
const FRAME_SIZE: usize = 5;

/// Executor for eBPF programs.
///
/// Handles the main execution loop, including:
/// - Instruction fetching and execution via rvm-core
/// - Helper function dispatch
/// - BPF-to-BPF function calls with call stack
/// - Instruction limit enforcement
pub struct Executor<'a> {
    /// Program memory.
    memory: &'a mut VmMemory,
    /// Helper registry.
    helpers: &'a HelperRegistry,
    /// Stack top address (initial r10).
    stack_top: u64,
    /// Maximum instructions to execute (0 = unlimited).
    instruction_limit: u64,
}

impl<'a> Executor<'a> {
    /// Create a new executor.
    pub fn new(memory: &'a mut VmMemory, helpers: &'a HelperRegistry, stack_top: u64) -> Self {
        Self {
            memory,
            helpers,
            stack_top,
            instruction_limit: 0,
        }
    }

    /// Set the instruction limit.
    pub fn set_instruction_limit(&mut self, limit: u64) {
        self.instruction_limit = limit;
    }

    /// Call a function at the given program counter.
    ///
    /// # Arguments
    ///
    /// * `pc` - The program counter (instruction index) to start execution at
    /// * `args` - Arguments to pass (placed in r1-r5)
    ///
    /// # Returns
    ///
    /// The return value (r0) on success.
    pub fn call(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        // Create execution context
        let mut ctx = Context::new(());

        // Set up initial registers
        // r0: return value (initially 0)
        ctx.regs[0] = 0;

        // r1-r5: arguments
        for (i, &arg) in args.iter().take(5).enumerate() {
            ctx.regs[i + 1] = arg;
        }

        // r6-r9: callee-saved (initially 0)
        // r10: frame pointer (stack top)
        ctx.regs[10] = self.stack_top;

        // Call stack for BPF-to-BPF calls
        // Each frame stores: r6, r7, r8, r9, return_pc
        let mut call_stack: Vec<[u64; FRAME_SIZE]> = Vec::with_capacity(MAX_CALL_DEPTH);

        // Current program counter
        let mut current_pc = pc;

        // Instruction counter
        let mut insn_count: u64 = 0;

        loop {
            // Check instruction limit
            if self.instruction_limit > 0 && insn_count >= self.instruction_limit {
                return Err(ExecError::InstructionLimit(insn_count).into());
            }

            // Fetch instruction
            let insn = self
                .memory
                .load_pc(current_pc)
                .map_err(|_| ExecError::InvalidPc(current_pc))?;

            insn_count += 1;

            // Execute instruction
            match step(&mut ctx, insn) {
                ControlFlow::Break(flow) => {
                    match self.handle_flow(flow, &mut ctx, &mut current_pc, &mut call_stack)? {
                        FlowResult::Continue => current_pc += 1,
                        FlowResult::Jump(new_pc) => current_pc = new_pc,
                        FlowResult::Exit => return Ok(ctx.regs[0]),
                    }
                }
                ControlFlow::Continue(_first_insn) => {
                    // LD_IMM64: need to fetch and process second instruction
                    current_pc += 1;
                    insn_count += 1;

                    let second = self
                        .memory
                        .load_pc(current_pc)
                        .map_err(|_| ExecError::InvalidPc(current_pc))?;

                    match step_ld64(&mut ctx, insn, second) {
                        Flow::Next => current_pc += 1,
                        Flow::FailCpu => {
                            return Err(ExecError::CpuFault("LD_IMM64 failed".to_string()).into());
                        }
                        Flow::FailMem(_) => {
                            return Err(ExecError::MemoryFault("LD_IMM64 memory error".to_string()).into());
                        }
                        Flow::Missing => {
                            return Err(ExecError::Unimplemented("LD_IMM64 variant".to_string()).into());
                        }
                        _ => {
                            return Err(ExecError::CpuFault("unexpected flow from LD_IMM64".to_string()).into());
                        }
                    }
                }
            }
        }
    }

    /// Handle a flow control result.
    fn handle_flow(
        &mut self,
        flow: Flow<()>,
        ctx: &mut Context<()>,
        current_pc: &mut u64,
        call_stack: &mut Vec<[u64; FRAME_SIZE]>,
    ) -> Result<FlowResult> {
        match flow {
            Flow::Next => Ok(FlowResult::Continue),

            Flow::Jump(offset) => {
                // Relative jump from next instruction
                let next_pc = (*current_pc as i64) + 1 + offset;
                if next_pc < 0 {
                    return Err(ExecError::InvalidPc(next_pc as u64).into());
                }
                Ok(FlowResult::Jump(next_pc as u64))
            }

            Flow::Call(offset) => {
                // BPF-to-BPF call
                if call_stack.len() >= MAX_CALL_DEPTH {
                    return Err(ExecError::StackOverflow.into());
                }

                // Save callee-saved registers and return address
                let frame = [
                    ctx.regs[6],
                    ctx.regs[7],
                    ctx.regs[8],
                    ctx.regs[9],
                    *current_pc + 1, // return address
                ];
                call_stack.push(frame);

                // Calculate target PC (relative from next instruction)
                let target_pc = (*current_pc as i64) + 1 + offset;
                if target_pc < 0 {
                    return Err(ExecError::InvalidPc(target_pc as u64).into());
                }

                Ok(FlowResult::Jump(target_pc as u64))
            }

            Flow::Exit => {
                // Check if we're returning from a BPF-to-BPF call
                if let Some(frame) = call_stack.pop() {
                    // Restore callee-saved registers
                    ctx.regs[6] = frame[0];
                    ctx.regs[7] = frame[1];
                    ctx.regs[8] = frame[2];
                    ctx.regs[9] = frame[3];

                    // Return to caller
                    Ok(FlowResult::Jump(frame[4]))
                } else {
                    // Top-level exit
                    Ok(FlowResult::Exit)
                }
            }

            Flow::CallExt(helper_id) => {
                // External helper call
                let args = HelperArgs::from_regs(&ctx.regs);
                let mut helper_ctx = HelperContext::with_memory(args, self.memory);

                let result = self.helpers.call(helper_id as u32, &mut helper_ctx)?;
                ctx.regs[0] = result;

                Ok(FlowResult::Continue)
            }

            Flow::FailCpu => Err(ExecError::CpuFault("invalid instruction".to_string()).into()),

            Flow::FailMem(_) => Err(ExecError::MemoryFault("memory access error".to_string()).into()),

            Flow::Missing => Err(ExecError::Unimplemented("instruction not implemented".to_string()).into()),
        }
    }
}

/// Result of handling a flow control instruction.
enum FlowResult {
    /// Continue to next instruction.
    Continue,
    /// Jump to absolute PC.
    Jump(u64),
    /// Exit program.
    Exit,
}

/// Extension trait to load instructions from VmMemory.
trait LoadPc {
    fn load_pc(&self, pc: u64) -> std::result::Result<rvm_core::Instruction, &'static str>;
}

impl LoadPc for VmMemory {
    fn load_pc(&self, pc: u64) -> std::result::Result<rvm_core::Instruction, &'static str> {
        use crate::memory::Memory;
        let addr = pc.checked_mul(8).ok_or("PC overflow")?;
        self.load_u64(addr).map(rvm_core::Instruction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VmError;
    use crate::memory::Memory;

    #[test]
    fn test_simple_exit() {
        // Create a simple program that just exits with r0 = 42
        let mut memory = VmMemory::new(64);

        // MOV r0, 42: opcode 0xb7 (ALU64 | MOV | IMM), dst=0, src=0, off=0, imm=42
        // Format: imm(32) | off(16) | src(4) | dst(4) | opc(8)
        // = (42 << 32) | 0xb7
        let mov_insn: u64 = (42u64 << 32) | 0xb7;
        memory.store_u64(0, mov_insn).unwrap();

        // EXIT: opcode 0x95
        let exit_insn: u64 = 0x95;
        memory.store_u64(8, exit_insn).unwrap();

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 64);

        let result = executor.call(0, &[]).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_with_arguments() {
        let mut memory = VmMemory::new(64);

        // MOV r0, r1: opcode 0xbf (ALU64 | MOV | REG), dst=0, src=1
        // Format: imm(32) | off(16) | src(4) | dst(4) | opc(8)
        // = (1 << 12) | 0xbf
        let mov_insn: u64 = (1u64 << 12) | 0xbf;
        memory.store_u64(0, mov_insn).unwrap();

        // EXIT
        let exit_insn: u64 = 0x95;
        memory.store_u64(8, exit_insn).unwrap();

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 64);

        let result = executor.call(0, &[123]).unwrap();
        assert_eq!(result, 123);
    }

    #[test]
    fn test_instruction_limit() {
        let mut memory = VmMemory::new(64);

        // JA -1: infinite loop (opcode 0x05, offset = -1)
        // Format: imm(32) | off(16) | src(4) | dst(4) | opc(8)
        // offset = -1 = 0xFFFF
        let ja_insn: u64 = (0xFFFFu64 << 16) | 0x05;
        memory.store_u64(0, ja_insn).unwrap();

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 64);
        executor.set_instruction_limit(10);

        let result = executor.call(0, &[]);
        assert!(matches!(result, Err(VmError::Exec(ExecError::InstructionLimit(_)))));
    }
}
