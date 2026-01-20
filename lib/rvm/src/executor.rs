//! Execution engine for eBPF programs.
//!
//! The executor runs eBPF bytecode using the rvm-core instruction stepping,
//! and dispatches helper function calls to the registered helpers.

use std::ops::ControlFlow;

use rvm_core::{step, step_ld64, Context, Flow, Memory};

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
        execute(self.memory, self.helpers, self.stack_top, pc, args, self.instruction_limit)
    }
}

/// Execute a program with the given memory.
///
/// This is a standalone function that takes ownership of memory during execution.
pub fn execute(
    memory: &mut VmMemory,
    helpers: &HelperRegistry,
    stack_top: u64,
    pc: u64,
    args: &[u64],
    instruction_limit: u64,
) -> Result<u64> {
    // Create execution context with the memory
    // We need to temporarily take the memory data out
    let mem_data = std::mem::take(memory);
    let mut ctx = Context::new(mem_data);

    // Set up initial registers
    ctx.regs[0] = 0;
    for (i, &arg) in args.iter().take(5).enumerate() {
        ctx.regs[i + 1] = arg;
    }
    ctx.regs[10] = stack_top;

    // Call stack for BPF-to-BPF calls
    let mut call_stack: Vec<[u64; FRAME_SIZE]> = Vec::with_capacity(MAX_CALL_DEPTH);

    // Current program counter
    let mut current_pc = pc;

    // Instruction counter
    let mut insn_count: u64 = 0;

    let result = loop {
        // Check instruction limit
        if instruction_limit > 0 && insn_count >= instruction_limit {
            break Err(ExecError::InstructionLimit(insn_count).into());
        }

        // Fetch instruction
        let insn = match ctx.data.load_u64(current_pc.wrapping_mul(8)) {
            Ok(v) => rvm_core::Instruction(v),
            Err(_) => break Err(ExecError::InvalidPc(current_pc).into()),
        };

        insn_count += 1;

        // Execute instruction
        match step(&mut ctx, insn) {
            ControlFlow::Break(flow) => match handle_flow(flow, &mut ctx, &mut current_pc, &mut call_stack, helpers)? {
                FlowResult::Continue => current_pc += 1,
                FlowResult::Jump(new_pc) => current_pc = new_pc,
                FlowResult::Exit => break Ok(ctx.regs[0]),
            },
            ControlFlow::Continue(_first_insn) => {
                // LD_IMM64: need to fetch and process second instruction
                current_pc += 1;
                insn_count += 1;

                let second = match ctx.data.load_u64(current_pc.wrapping_mul(8)) {
                    Ok(v) => rvm_core::Instruction(v),
                    Err(_) => break Err(ExecError::InvalidPc(current_pc).into()),
                };

                match step_ld64(&mut ctx, insn, second) {
                    Flow::Next => current_pc += 1,
                    Flow::FailCpu => {
                        break Err(ExecError::CpuFault("LD_IMM64 failed".to_string()).into());
                    }
                    Flow::FailMem(_) => {
                        break Err(ExecError::MemoryFault("LD_IMM64 memory error".to_string()).into());
                    }
                    Flow::Missing => {
                        break Err(ExecError::Unimplemented("LD_IMM64 variant".to_string()).into());
                    }
                    _ => {
                        break Err(ExecError::CpuFault("unexpected flow from LD_IMM64".to_string()).into());
                    }
                }
            }
        }
    };

    // Restore memory back
    *memory = ctx.data;

    result
}

/// Handle a flow control result.
fn handle_flow(
    flow: Flow<VmMemory>,
    ctx: &mut Context<VmMemory>,
    current_pc: &mut u64,
    call_stack: &mut Vec<[u64; FRAME_SIZE]>,
    helpers: &HelperRegistry,
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
            let mut helper_ctx = HelperContext::with_memory(args, &mut ctx.data);

            let result = helpers.call(helper_id as u32, &mut helper_ctx)?;
            ctx.regs[0] = result;

            Ok(FlowResult::Continue)
        }

        Flow::FailCpu => Err(ExecError::CpuFault("invalid instruction".to_string()).into()),

        Flow::FailMem(_) => Err(ExecError::MemoryFault("memory access error".to_string()).into()),

        Flow::Missing => Err(ExecError::Unimplemented("instruction not implemented".to_string()).into()),
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

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R0, R1};

    use super::*;
    use crate::error::VmError;

    /// Helper to load assembled instructions into memory.
    fn load_program(memory: &mut VmMemory, asm: &mut Assembler) {
        let instructions = asm.assemble_to_u64().unwrap();
        for (i, insn) in instructions.iter().enumerate() {
            memory.store_u64((i * 8) as u64, *insn).unwrap();
        }
    }

    #[test]
    fn test_simple_exit() {
        // Create a simple program that just exits with r0 = 42
        let mut memory = VmMemory::new(64);

        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 42);
        asm.exit();
        load_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 64);

        let result = executor.call(0, &[]).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn test_with_arguments() {
        let mut memory = VmMemory::new(64);

        let mut asm = Assembler::new();
        asm.mov64(R0, R1); // r0 = r1 (first argument)
        asm.exit();
        load_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 64);

        let result = executor.call(0, &[123]).unwrap();
        assert_eq!(result, 123);
    }

    #[test]
    fn test_instruction_limit() {
        let mut memory = VmMemory::new(64);

        // JA -1: infinite loop
        let mut asm = Assembler::new();
        let mut loop_label = asm.create_label();
        asm.set_label(&mut loop_label).unwrap();
        asm.ja(&loop_label); // Jump back to itself
        load_program(&mut memory, &mut asm);

        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&mut memory, &helpers, 64);
        executor.set_instruction_limit(10);

        let result = executor.call(0, &[]);
        assert!(matches!(result, Err(VmError::Exec(ExecError::InstructionLimit(_)))));
    }
}
