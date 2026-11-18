//! Runs eBPF bytecode on rvm-core and dispatches helper calls to a [`HelperRegistry`].

use std::mem::ManuallyDrop;

use rvm_core::{run, CallStack, Code, Context, Flow, Host};

use crate::error::{ExecError, HelperError, MemoryError, Result, VmError};
use crate::helper::{HelperArgs, HelperContext, HelperRegistry};
use crate::layout::CODE_REGION;
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{region_base, VmMemory};

/// Default stack bytes reserved per call frame (eBPF's `MAX_BPF_STACK`).
pub const DEFAULT_FRAME_SIZE: u64 = 512;

/// Helper ID of the call the linker plants for a CO-RE relocation the host can't resolve (`btf::CORE_POISON_HELPER`).
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// Runs functions of one piece of code against one memory, with BPF-to-BPF calls on their own stack frames.
///
/// Code is a separate instruction slice, so the guest can neither read nor modify it through memory. Memory stays
/// borrowed, so it survives errors.
pub struct Executor<'a> {
    code: &'a Code,
    memory: &'a mut VmMemory,
    helpers: &'a HelperRegistry,
    /// Initial r10.
    stack_top: u64,
    /// Bytes r10 moves down per nested call.
    frame_size: u64,
    /// Maximum instructions to execute; `u64::MAX` for no limit.
    #[cfg(feature = "fuel")]
    instruction_limit: u64,
    /// Maps passed to helpers through [`HelperContext::maps`].
    #[cfg(feature = "maps")]
    maps: Option<&'a mut Maps>,
}

impl<'a> Executor<'a> {
    /// Create a new executor.
    pub fn new(code: &'a Code, memory: &'a mut VmMemory, helpers: &'a HelperRegistry, stack_top: u64) -> Self {
        Self {
            code,
            memory,
            helpers,
            stack_top,
            frame_size: DEFAULT_FRAME_SIZE,
            #[cfg(feature = "fuel")]
            instruction_limit: u64::MAX,
            #[cfg(feature = "maps")]
            maps: None,
        }
    }

    /// Set the instruction limit; `u64::MAX` for no limit.
    #[cfg(feature = "fuel")]
    pub fn set_instruction_limit(&mut self, limit: u64) {
        self.instruction_limit = limit;
    }

    /// Set the stack bytes reserved per call frame.
    pub fn set_frame_size(&mut self, size: u64) {
        self.frame_size = size;
    }

    /// Give helpers access to `maps`.
    #[cfg(feature = "maps")]
    pub fn set_maps(&mut self, maps: &'a mut Maps) {
        self.maps = Some(maps);
    }

    /// Call the function at `pc` (instruction index) with `args` in r1-r5; returns r0. More than 5 arguments fail with
    /// [`VmError::TooManyArgs`].
    pub fn call(&mut self, pc: u64, args: &[u64]) -> Result<u64> {
        if args.len() > 5 {
            return Err(VmError::TooManyArgs(args.len()));
        }
        let mut ctx = Context::new(&mut *self.memory);
        // at most 5 stores; `copy_from_slice` calls memcpy
        for (i, &arg) in args.iter().take(5).enumerate() {
            ctx.regs[i + 1] = arg;
        }
        ctx.regs[10] = self.stack_top;

        let helpers = Helpers {
            registry: self.helpers,
            #[cfg(feature = "maps")]
            maps: self.maps.as_deref_mut(),
            error: ManuallyDrop::new(None),
        };
        let mut calls = CallStack::new(self.frame_size, helpers);
        let mut pc = pc;
        #[cfg(feature = "fuel")]
        let limit = self.instruction_limit;
        #[cfg(feature = "fuel")]
        let mut fuel = limit;

        loop {
            #[cfg(feature = "fuel")]
            let flow = run(&mut ctx, self.code, &mut pc, &mut fuel, &mut calls);
            #[cfg(not(feature = "fuel"))]
            let flow = run(&mut ctx, self.code, &mut pc, &mut calls);
            if let Flow::Exit = flow {
                return Ok(ctx.regs[0]);
            }
            #[cfg(feature = "fuel")]
            let next = resume(flow, pc, self.code, &mut ctx, &mut calls, limit);
            #[cfg(not(feature = "fuel"))]
            let next = resume(flow, pc, self.code, &mut ctx, &mut calls);
            pc = next?;
        }
    }
}

/// Where to continue after [`run`] stopped at `pc` with `flow`, which is not [`Flow::Exit`], or why the call fails.
#[cold]
#[inline(never)]
fn resume(
    flow: Flow<&mut VmMemory>,
    pc: u64,
    code: &Code,
    ctx: &mut Context<&mut VmMemory>,
    calls: &mut CallStack<Helpers<'_>>,
    #[cfg(feature = "fuel")] limit: u64,
) -> Result<u64> {
    match flow {
        Flow::StackOverflow => Err(ExecError::StackOverflow { pc }.into()),
        // a call the linker planted for an unresolved CO-RE relocation
        Flow::CallHelper(CORE_POISON_HELPER) => Err(ExecError::UnresolvedCoreRelo { pc }.into()),
        Flow::CallHelper(_) | Flow::CallKfunc(_) => Err(calls.host.take_error().into()),
        #[cfg(feature = "fuel")]
        Flow::OutOfFuel => Err(ExecError::InstructionLimit(limit).into()),
        Flow::BadPc => Err(ExecError::InvalidPc(pc).into()),
        Flow::FailCpu => Err(ExecError::CpuFault { pc }.into()),
        Flow::FailMem(addr) => Err(memory_fault(pc, addr, code)),
        Flow::Missing => Err(ExecError::Unimplemented { pc }.into()),
        Flow::CallIndirect(target) => call_indirect(target, pc, code, ctx, calls),
        Flow::JumpIndirect(target) => jump_indirect(target, pc, code),
        // `run` handles these internally, and the executor `Exit`
        Flow::Exit | Flow::Next | Flow::Jump(_) | Flow::Call(_) => unreachable!(),
        #[cfg(not(feature = "fuel"))]
        Flow::OutOfFuel => unreachable!(),
    }
}

/// The extern table and maps that helper and kfunc calls reach from inside [`run`].
struct Helpers<'a> {
    registry: &'a HelperRegistry,
    #[cfg(feature = "maps")]
    maps: Option<&'a mut Maps>,
    /// Why the call that stopped [`run`] failed. The executor takes it as soon as `run` stops, so it never needs
    /// dropping and costs no check on the way out.
    error: ManuallyDrop<Option<HelperError>>,
}

impl Helpers<'_> {
    /// Call the extern table entry at `slot` with the arguments in `ctx.regs[1..=5]`.
    #[inline]
    fn call_slot(&mut self, ctx: &mut Context<&mut VmMemory>, slot: u32) -> std::result::Result<u64, HelperError> {
        let mut helper_ctx = HelperContext {
            args: HelperArgs::from_regs(&ctx.regs),
            memory: &mut *ctx.data,
            #[cfg(feature = "maps")]
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

impl Host<&mut VmMemory> for Helpers<'_> {
    // Raw bytecode calls helpers by ID; linked programs call slots only, except for calls the linker planted for
    // unresolved CO-RE relocations, which the executor reports.
    #[inline]
    fn helper(&mut self, ctx: &mut Context<&mut VmMemory>, id: u32) -> Option<u64> {
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
    fn kfunc(&mut self, ctx: &mut Context<&mut VmMemory>, slot: u32) -> Option<u64> {
        match self.call_slot(ctx, slot) {
            Ok(r0) => Some(r0),
            Err(err) => {
                *self.error = Some(err);
                None
            }
        }
    }
}

/// `callx` at `pc`: enter the function at code address `target`, or call the helper whose ID is `target`. Returns the
/// next pc.
fn call_indirect(
    target: u64,
    pc: u64,
    code: &Code,
    ctx: &mut Context<&mut VmMemory>,
    calls: &mut CallStack<Helpers<'_>>,
) -> Result<u64> {
    if let Some(callee) = code_index(target, code) {
        if !calls.push(&mut ctx.regs, pc) {
            return Err(ExecError::StackOverflow { pc }.into());
        }
        return Ok(callee);
    }

    // A helper's address is its ID, as in libbpf's `(void *)BPF_FUNC_*` helper declarations.
    let id = u32::try_from(target).map_err(|_| ExecError::BadCodeAddress { pc, target })?;
    let helpers = &mut calls.host;
    let Some(slot) = helpers.registry.slot_of_id(id) else {
        return Err(HelperError::UnknownHelper(id).into());
    };
    ctx.regs[0] = helpers.call_slot(ctx, slot)?;
    Ok(pc + 1)
}

/// The fault of the load or store at `pc` that failed at `addr`.
fn memory_fault(pc: u64, addr: u64, code: &Code) -> VmError {
    // only loads and stores fail with `Flow::FailMem`
    let size = code.access_size(pc).expect("memory fault outside a load or store");
    ExecError::MemoryFault {
        pc,
        error: MemoryError { addr, size },
    }
    .into()
}

/// `gotox` at `pc`: the instruction index of code address `target`.
fn jump_indirect(target: u64, pc: u64, code: &Code) -> Result<u64> {
    code_index(target, code).ok_or_else(|| ExecError::BadCodeAddress { pc, target }.into())
}

/// Instruction index of the guest code address `addr`, if it is an instruction boundary inside `code`.
fn code_index(addr: u64, code: &Code) -> Option<u64> {
    let offset = addr.checked_sub(region_base(CODE_REGION))?;
    (offset % 8 == 0 && offset / 8 < code.len() as u64).then_some(offset / 8)
}

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R0, R1, R10, R2, R3, R6, R7};
    use rvm_core::instructions_from_bytes;

    use super::*;
    use crate::error::MemoryError;
    use crate::layout::STACK_REGION;
    use crate::memory::{GuestMemory, Perms};

    /// Run `code` from its first instruction on `memory` plus a one-frame stack; `setup` adjusts the executor.
    fn run_with(
        code: &[u8],
        helpers: &HelperRegistry,
        mut memory: VmMemory,
        setup: impl FnOnce(&mut Executor),
    ) -> Result<u64> {
        let code = instructions_from_bytes(code);
        let len = DEFAULT_FRAME_SIZE as usize;
        let stack_top = memory.map_any(STACK_REGION, len, Perms::RW) + DEFAULT_FRAME_SIZE;
        let mut executor = Executor::new(&code, &mut memory, helpers, stack_top);
        setup(&mut executor);
        executor.call(0, &[])
    }

    fn run(asm: &mut Assembler) -> Result<u64> {
        run_with(&asm.assemble().unwrap(), &HelperRegistry::default(), VmMemory::new(), |_| {})
    }

    #[cfg(feature = "fuel")]
    #[test]
    fn instruction_limit() {
        let mut asm = Assembler::new();
        let loop_label = asm.create_label();
        asm.set_label(&loop_label).unwrap();
        asm.ja(&loop_label);
        let code = asm.assemble().unwrap();
        let result =
            run_with(&code, &HelperRegistry::default(), VmMemory::new(), |executor| executor.set_instruction_limit(10));
        assert!(matches!(result, Err(VmError::Exec(ExecError::InstructionLimit(_)))));
    }

    #[test]
    fn running_off_code_end_is_invalid_pc() {
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 1);
        assert!(matches!(run(&mut asm), Err(VmError::Exec(ExecError::InvalidPc(1)))));
    }

    /// Load-acquire writes its `dst`, and r10 is read-only.
    #[test]
    fn load_acquire_into_r10_faults() {
        let mut asm = Assembler::new();
        asm.mov64(R1, R10).load_acquire64(R10, R1, -8).exit();
        assert!(matches!(run(&mut asm), Err(VmError::Exec(ExecError::CpuFault { pc: 1 }))));
    }

    /// The access size comes from the faulting instruction, which may sit inside a superinstruction or be an r10
    /// access, whose first slots hold rewritten opcode bytes.
    #[test]
    fn memory_fault_reports_access_size() {
        let fault = |asm: &mut Assembler| match run(asm) {
            Err(VmError::Exec(ExecError::MemoryFault { pc, error })) => (pc, error.size),
            other => panic!("{other:?}"),
        };

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 0).ldxh(R0, R1, 0).exit();
        assert_eq!(fault(&mut asm), (1, 2));

        // mov, add, ldxw: one superinstruction
        let mut asm = Assembler::new();
        asm.mov64_imm(R2, 0)
            .mov64_imm(R3, 0)
            .mov64(R1, R2)
            .add64(R1, R3)
            .ldxw(R0, R1, 0)
            .exit();
        assert_eq!(fault(&mut asm), (4, 4));

        // above the stack top
        let mut asm = Assembler::new();
        asm.stxdw(R10, 8, R1).exit();
        assert_eq!(fault(&mut asm), (0, 8));
    }

    #[test]
    fn stack_overflow_deep_recursion() {
        let mut asm = Assembler::new();
        let func_start = asm.create_label();
        asm.set_label(&func_start).unwrap();
        asm.call_local(&func_start);
        asm.exit();
        assert!(matches!(run(&mut asm), Err(VmError::Exec(ExecError::StackOverflow { .. }))));
    }

    #[test]
    fn callee_saved_registers_survive_a_local_call() {
        let mut asm = Assembler::new();
        let callee = asm.create_label();

        asm.mov64_imm(R6, 100);
        asm.mov64_imm(R7, 200);
        asm.call_local(&callee);
        asm.mov64(R0, R6);
        asm.add64(R0, R7);
        asm.exit();

        asm.set_label(&callee).unwrap();
        asm.mov64_imm(R6, 0);
        asm.mov64_imm(R7, 0);
        asm.exit();

        assert_eq!(run(&mut asm).unwrap(), 300);
    }

    // helper calls run inside the handler chain; this is the lib test that takes Miri through that path
    #[test]
    fn helper_calls() {
        let mut helpers = HelperRegistry::default();
        helpers.register_helper_raw(1, |ctx: &mut HelperContext| {
            ctx.memory.write(ctx.args.r2, 7u64).unwrap();
            ctx.args.r1 * 2
        });
        let run = |asm: &mut Assembler| run_with(&asm.assemble().unwrap(), &helpers, VmMemory::new(), |_| {});

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

    // a host function with memory access runs inside the handler chain too, and an `Err` from it fails the guest call
    #[test]
    fn memory_fn() {
        let mut helpers = HelperRegistry::default();
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

            let mut code = asm.assemble().unwrap();
            let (insns, _) = code.as_chunks_mut::<8>();
            let call = insns.iter_mut().find(|insn| insn[0] == crate::image::CALL).unwrap();
            crate::image::set_slot_call(call, helpers.slot_of_name("bump").unwrap());

            let mut memory = VmMemory::new();
            memory.map_bytes_any(2, &[7; 8], 8, Perms::R);
            run_with(&code, &helpers, memory, |_| {})
        };

        // r0 in the low half, the stack slot in the high half
        assert_eq!(run(None).unwrap(), 42 << 32 | 41);
        // an unmapped address, and a read-only region that can be read but not written
        for addr in [0, region_base(2)] {
            let err = run(Some(addr)).unwrap_err();
            let VmError::Helper(HelperError::Host(e)) = &err else {
                panic!("{err:?}")
            };
            assert_eq!(e.downcast_ref::<MemoryError>(), Some(&MemoryError { addr, size: 8 }));
        }
    }
}
