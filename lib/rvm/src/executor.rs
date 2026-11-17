//! Runs eBPF bytecode on rvm-core and dispatches helper calls to a
//! [`HelperRegistry`].

use std::fmt::Debug;
use std::mem::ManuallyDrop;

use rvm_core::{run, CallStack, Code, Context, Flow, Host, Memory};

use crate::error::{ExecError, HelperError, Result};
use crate::helper::{HelperArgs, HelperContext, HelperRegistry};
use crate::layout::CODE_REGION;
use crate::maps::Maps;
use crate::memory::{region_base, VmMemory};

/// Default stack bytes reserved per call frame (eBPF's `MAX_BPF_STACK`).
pub const DEFAULT_FRAME_SIZE: u64 = 512;

/// Helper ID of the call the linker plants for a CO-RE relocation the host can't
/// resolve (`btf::CORE_POISON_HELPER`).
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// Runs functions of one piece of code against one memory, with BPF-to-BPF calls
/// on their own stack frames.
///
/// Code is a separate instruction slice, so the guest can neither read nor modify
/// it through memory. Generic over any [`Memory`]; memory stays borrowed, so it
/// survives errors.
pub struct Executor<'a, M: Memory = VmMemory> {
    code: &'a Code,
    memory: &'a mut M,
    helpers: &'a HelperRegistry<M>,
    /// Initial r10.
    stack_top: u64,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
    /// Maximum instructions to execute (0 = unlimited).
    #[cfg(feature = "fuel")]
    instruction_limit: u64,
    /// Maps passed to helpers through [`HelperContext::maps`].
    maps: Option<&'a mut Maps>,
}

impl<'a, M: Memory<Err: Debug> + 'static> Executor<'a, M> {
    /// Create a new executor.
    pub fn new(code: &'a Code, memory: &'a mut M, helpers: &'a HelperRegistry<M>, stack_top: u64) -> Self {
        Self {
            code,
            memory,
            helpers,
            stack_top,
            frame_size: DEFAULT_FRAME_SIZE,
            #[cfg(feature = "fuel")]
            instruction_limit: 0,
            maps: None,
        }
    }

    /// Set the instruction limit (0 = unlimited).
    #[cfg(feature = "fuel")]
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
    pub fn call(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        let mut ctx = Context::new(&mut *self.memory);
        for (i, &arg) in args.iter().take(5).enumerate() {
            ctx.regs[i + 1] = arg;
        }
        ctx.regs[10] = self.stack_top;

        let helpers = Helpers {
            registry: self.helpers,
            maps: self.maps.as_deref_mut(),
            error: ManuallyDrop::new(None),
        };
        let mut calls = CallStack::new(self.frame_size, helpers);
        let mut pc = pc;
        #[cfg(feature = "fuel")]
        let limit = match self.instruction_limit {
            0 => u64::MAX,
            limit => limit,
        };
        #[cfg(feature = "fuel")]
        let mut fuel = limit;

        loop {
            #[cfg(feature = "fuel")]
            let flow = run(&mut ctx, self.code, &mut pc, &mut fuel, &mut calls);
            #[cfg(not(feature = "fuel"))]
            let flow = run(&mut ctx, self.code, &mut pc, &mut calls);
            pc = match flow {
                Flow::Exit => return Ok(ctx.regs[0]),
                Flow::StackOverflow => return Err(ExecError::StackOverflow.into()),
                // a call the linker planted for an unresolved CO-RE relocation
                Flow::CallHelper(CORE_POISON_HELPER) => {
                    return Err(ExecError::UnresolvedCoreRelo { pc }.into());
                }
                Flow::CallHelper(_) | Flow::CallKfunc(_) => return Err(calls.host.take_error().into()),
                #[cfg(feature = "fuel")]
                Flow::OutOfFuel => return Err(ExecError::InstructionLimit(limit).into()),
                Flow::BadPc => return Err(ExecError::InvalidPc(pc).into()),
                Flow::FailCpu => return Err(ExecError::CpuFault.into()),
                Flow::FailMem(err) => {
                    return Err(ExecError::MemoryFault(format!("access at {err:#x?} (pc {pc})")).into())
                }
                Flow::Missing => return Err(ExecError::Unimplemented.into()),
                Flow::CallIndirect(target) => call_indirect(target, pc, self.code, &mut ctx, &mut calls)?,
                Flow::JumpIndirect(target) => jump_indirect(target, pc, self.code)?,
                // `run` handles these internally
                Flow::Next | Flow::Jump(_) | Flow::Call(_) => unreachable!(),
                #[cfg(not(feature = "fuel"))]
                Flow::OutOfFuel => unreachable!(),
            };
        }
    }
}

/// The extern table and maps that helper and kfunc calls reach from inside [`run`].
struct Helpers<'a, M> {
    registry: &'a HelperRegistry<M>,
    maps: Option<&'a mut Maps>,
    /// Why the call that stopped [`run`] failed. The executor takes it as soon as
    /// `run` stops, so it never needs dropping and costs no check on the way out.
    error: ManuallyDrop<Option<HelperError>>,
}

impl<M: Memory<Err: Debug> + 'static> Helpers<'_, M> {
    /// Call the extern table entry at `slot` with the arguments in `ctx.regs[1..=5]`.
    #[inline]
    fn call_slot(&mut self, ctx: &mut Context<&mut M>, slot: u32) -> std::result::Result<u64, HelperError> {
        let mut helper_ctx = HelperContext {
            args: HelperArgs::from_regs(&ctx.regs),
            memory: &mut *ctx.data,
            maps: self.maps.as_deref_mut(),
        };
        self.registry.call_slot(slot, &mut helper_ctx)
    }

    /// The error of the helper or kfunc call that stopped [`run`].
    #[cold]
    fn take_error(&mut self) -> HelperError {
        self.error.take().expect("failed host call left no error")
    }
}

impl<M: Memory<Err: Debug> + 'static> Host<&mut M> for Helpers<'_, M> {
    // Raw bytecode calls helpers by ID; linked programs call slots only, except for
    // calls the linker planted for unresolved CO-RE relocations, which the executor
    // reports.
    #[inline]
    fn helper(&mut self, ctx: &mut Context<&mut M>, id: u32) -> Option<u64> {
        if id == CORE_POISON_HELPER {
            return None;
        }
        let Some(slot) = self.registry.slot_of_id(id) else {
            *self.error = Some(HelperError::UnknownHelper(id));
            return None;
        };
        self.kfunc(ctx, slot)
    }

    #[inline]
    fn kfunc(&mut self, ctx: &mut Context<&mut M>, slot: u32) -> Option<u64> {
        match self.call_slot(ctx, slot) {
            Ok(r0) => Some(r0),
            Err(err) => {
                *self.error = Some(err);
                None
            }
        }
    }
}

/// `callx` at `pc`: enter the function at code address `target`, or call the helper
/// whose ID is `target`. Returns the next pc.
#[cold]
#[inline(never)]
fn call_indirect<M: Memory<Err: Debug> + 'static>(
    target: u64,
    pc: u64,
    code: &Code,
    ctx: &mut Context<&mut M>,
    calls: &mut CallStack<Helpers<'_, M>>,
) -> Result<u64> {
    if let Some(callee) = code_index(target, code) {
        if !calls.push(&mut ctx.regs, pc) {
            return Err(ExecError::StackOverflow.into());
        }
        return Ok(callee);
    }

    // A helper's address is its ID, as in libbpf's `(void *)BPF_FUNC_*` helper
    // declarations.
    let id = u32::try_from(target).map_err(|_| ExecError::BadCodeAddress { pc, target })?;
    let helpers = &mut calls.host;
    let slot = helpers.registry.slot_of_id(id).ok_or(HelperError::UnknownHelper(id))?;
    ctx.regs[0] = helpers.call_slot(ctx, slot)?;
    Ok(pc + 1)
}

/// `gotox` at `pc`: the instruction index of code address `target`.
#[cold]
#[inline(never)]
fn jump_indirect(target: u64, pc: u64, code: &Code) -> Result<u64> {
    code_index(target, code).ok_or_else(|| ExecError::BadCodeAddress { pc, target }.into())
}

/// Instruction index of the guest code address `addr`, if it is an instruction
/// boundary inside `code`.
fn code_index(addr: u64, code: &Code) -> Option<u64> {
    let offset = addr.checked_sub(region_base(CODE_REGION))?;
    (offset % 8 == 0 && offset / 8 < code.len() as u64).then_some(offset / 8)
}

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R0, R1, R10, R2, R6, R7};

    use super::*;
    use crate::error::{MemoryError, VmError};
    use crate::memory::{GuestMemory, Perms};

    fn run(asm: &mut Assembler, args: &[u64]) -> Result<u64> {
        run_with(asm, args, |_| {})
    }

    fn run_with(asm: &mut Assembler, args: &[u64], setup: impl FnOnce(&mut Executor)) -> Result<u64> {
        let code = crate::instructions_from_bytes(&asm.assemble().unwrap());
        let mut memory = VmMemory::new();
        let stack_top = memory.map(1, 512, Perms::RW) + 512;
        let helpers = HelperRegistry::new();
        let mut executor = Executor::new(&code, &mut memory, &helpers, stack_top);
        setup(&mut executor);
        executor.call(0, args)
    }

    #[cfg(feature = "fuel")]
    #[test]
    fn test_instruction_limit() {
        let mut asm = Assembler::new();
        let mut loop_label = asm.create_label();
        asm.set_label(&mut loop_label).unwrap();
        asm.ja(&loop_label);
        let result = run_with(&mut asm, &[], |executor| executor.set_instruction_limit(10));
        assert!(matches!(result, Err(VmError::Exec(ExecError::InstructionLimit(_)))));
    }

    #[test]
    fn test_running_off_code_end_is_invalid_pc() {
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 1);
        assert!(matches!(run(&mut asm, &[]), Err(VmError::Exec(ExecError::InvalidPc(1)))));
    }

    #[test]
    fn test_stack_overflow_deep_recursion() {
        let mut asm = Assembler::new();
        let mut func_start = asm.create_label();
        asm.set_label(&mut func_start).unwrap();
        asm.call_local(&func_start);
        asm.exit();
        assert!(matches!(run(&mut asm, &[]), Err(VmError::Exec(ExecError::StackOverflow))));
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

        assert_eq!(run(&mut asm, &[]).unwrap(), 300);
    }

    // helper calls run inside the handler chain; this is the lib test that takes Miri
    // through that path
    #[test]
    fn test_helper_calls() {
        let run = |asm: &mut Assembler| {
            let code = crate::instructions_from_bytes(&asm.assemble().unwrap());
            let mut memory = VmMemory::new();
            let stack_top = memory.map(1, 512, Perms::RW) + 512;
            let mut helpers = HelperRegistry::new();
            helpers.register_with_ctx(1, |ctx| {
                ctx.memory.store_u64(ctx.args.r2, 7).unwrap();
                ctx.args.r1 * 2
            });
            Executor::new(&code, &mut memory, &helpers, stack_top).call(0, &[])
        };

        // the helper's r0 and its store are visible to the next instructions
        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 21);
        asm.mov64(R2, R10);
        asm.add64_imm(R2, -8);
        asm.call(1);
        asm.mov64(R6, R0);
        asm.ldxdw(R0, R10, -8);
        asm.add64(R0, R6);
        asm.exit();
        assert_eq!(run(&mut asm).unwrap(), 49);

        let mut asm = Assembler::new();
        asm.mov64(R2, R10);
        asm.add64_imm(R2, -8);
        asm.call(1);
        asm.call(2);
        asm.exit();
        assert!(matches!(run(&mut asm), Err(VmError::Helper(HelperError::UnknownHelper(2)))));
    }

    // a host function with memory access runs inside the handler chain too, and a
    // pointer the guest couldn't use itself fails the access, not the program
    #[test]
    fn test_memory_fn() {
        let mut helpers = HelperRegistry::new();
        helpers.register_fn_with_memory("bump", |mem: &mut GuestMemory, addr: u64| {
            let old = mem.read::<u64>(addr)?;
            mem.write(addr, old + 1)?;
            Ok::<_, MemoryError>(old)
        });
        let run = |addr: Option<u64>| {
            let mut asm = Assembler::new();
            asm.stdw(R10, -8, 41);
            match addr {
                Some(addr) => asm.lddw(R1, addr as i64),
                None => asm.mov64(R1, R10).add64_imm(R1, -8),
            };
            asm.call(0);
            asm.ldxdw(R6, R10, -8);
            asm.lsh64_imm(R6, 32);
            asm.mov32(R0, R0);
            asm.or64(R0, R6);
            asm.exit();

            let mut bytes = asm.assemble().unwrap();
            let (insns, _) = bytes.as_chunks_mut::<8>();
            let call = insns.iter_mut().find(|insn| insn[0] == 0x85).unwrap();
            crate::image::set_slot_call(call, helpers.slot_of_name("bump").unwrap());
            let code = crate::instructions_from_bytes(&bytes);

            let mut memory = VmMemory::new();
            let stack_top = memory.map(1, 512, Perms::RW) + 512;
            memory.map_bytes(2, &[7; 8], 8, Perms::R);
            Executor::new(&code, &mut memory, &helpers, stack_top)
                .call(0, &[])
                .unwrap()
        };

        // r0 in the low half, the stack slot in the high half
        assert_eq!(run(None), 42 << 32 | 41);
        assert_eq!(run(Some(0)), 41 << 32 | 0xffff_ffff);
        // the read-only region can be read but not written
        assert_eq!(run(Some(region_base(2))), 41 << 32 | 0xffff_ffff);
    }
}
