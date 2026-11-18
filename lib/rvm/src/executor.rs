//! Runs eBPF bytecode on rvm-core and dispatches helper calls to a [`HelperRegistry`].

use std::fmt;

use rvm_core::{run, CallStack, Callee, Code, Context, Flow, Host};

use crate::error::{ExecError, HelperError, MemoryError, Result, VmError};
use crate::helper::{HelperArgs, HelperContext, HelperRegistry};
use crate::image::INSN_SIZE;
use crate::layout::CODE_REGION;
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{region_base, VmMemory};
use crate::vm::VmConfig;

/// Default stack bytes reserved per call frame (eBPF's `MAX_BPF_STACK`).
pub const DEFAULT_FRAME_SIZE: u64 = 512;

/// Helper ID of the call the linker plants for a CO-RE relocation the host can't resolve (`btf::CORE_POISON_HELPER`).
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// Argument registers of a call into a guest function, r1 to r5.
pub const MAX_ARGS: usize = 5;

/// Runs the functions of one program, with BPF-to-BPF calls on their own stack frames.
///
/// Each call borrows the code and the memory, so the memory survives errors. Code is a separate instruction slice, so
/// the guest can neither read nor modify it through memory. The executor keeps what carries over from one call to the
/// next: the extern table, the maps, the frame size and the r10 window.
pub struct Executor {
    /// The frames of the local calls in progress, and the frame size, r10 window and host.
    calls: CallStack<HostCalls, u64>,
    /// Initial r10.
    stack_top: u64,
    /// Maximum instructions to execute, at most `i64::MAX`. Without the `fuel` feature, nothing counts them.
    instruction_limit: u64,
}

impl Executor {
    /// An executor whose calls start with r10 at `stack_top`, with the frame size and instruction limit of `config`.
    pub fn new(helpers: HelperRegistry, stack_top: u64, config: &VmConfig) -> Self {
        let helpers = HostCalls {
            registry: helpers,
            #[cfg(feature = "maps")]
            maps: Maps::default(),
            error: None,
        };
        Self {
            calls: CallStack::new(config.frame_size, helpers),
            stack_top,
            instruction_limit: instruction_limit(config),
        }
    }

    /// Replace the extern table that helper and kfunc calls use.
    pub fn set_helpers(&mut self, helpers: HelperRegistry) {
        self.calls.host.registry = helpers;
    }

    /// The maps passed to helpers through [`HelperContext::maps`].
    #[cfg(feature = "maps")]
    pub fn maps_mut(&mut self) -> &mut Maps {
        &mut self.calls.host.maps
    }

    /// Call the function at `pc` (instruction index) of `code` with `args` in r1-r5; returns r0. More than 5 arguments
    /// fail with [`VmError::TooManyArgs`].
    pub fn call(&mut self, code: &Code, memory: &mut VmMemory, pc: u64, args: &[u64]) -> Result<u64> {
        if args.len() > MAX_ARGS {
            return Err(VmError::TooManyArgs(args.len()));
        }

        // A call starts with fresh registers and no frames. Guest code can read and write all 16 registers, r11-r15
        // included, so each starts at a defined value: r1-r5 hold the arguments and 0 past `args.len()`, r10 the stack
        // top, the others 0. A call that failed inside a local call leaves its frames behind. The rest of `self.calls`
        // carries over: `run` writes `stop` before reading it and drops the r10 window when the memory has moved to
        // another epoch, and the executor takes the host's error whenever a host call set one.
        let mut ctx = Context::new(memory);
        // at most `MAX_ARGS` stores; `copy_from_slice` calls memcpy
        for (i, &arg) in args.iter().take(MAX_ARGS).enumerate() {
            ctx.regs[i + 1] = arg;
        }
        ctx.regs[10] = self.stack_top;
        let calls = &mut self.calls;
        calls.clear();

        let mut pc = pc;
        let mut fuel = self.instruction_limit;
        let flow = run_metered(&mut ctx, code, &mut pc, &mut fuel, calls);
        if let Flow::Exit = flow {
            return Ok(ctx.regs[0]);
        }
        run_on(flow, pc, code, &mut ctx, calls, fuel, self.instruction_limit)
    }
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Executor");
        s.field("helpers", &self.calls.host.registry);
        #[cfg(feature = "maps")]
        s.field("maps", &self.calls.host.maps);
        s.field("stack_top", &self.stack_top);
        #[cfg(feature = "fuel")]
        s.field("instruction_limit", &self.instruction_limit);
        s.finish_non_exhaustive()
    }
}

/// Continue a call after [`run`] stopped at `pc` with `flow`, which is not [`Flow::Exit`], until it returns or fails.
// Out of line, so that the call's usual path keeps nothing across `run` that only resuming needs.
#[cold]
#[inline(never)]
fn run_on(
    mut flow: Flow<u64>,
    mut pc: u64,
    code: &Code,
    ctx: &mut Context<&mut VmMemory>,
    calls: &mut CallStack<HostCalls, u64>,
    mut fuel: u64,
    limit: u64,
) -> Result<u64> {
    loop {
        pc = resume(flow, pc, code, calls, limit)?;
        flow = run_metered(ctx, code, &mut pc, &mut fuel, calls);
        if let Flow::Exit = flow {
            return Ok(ctx.regs[0]);
        }
    }
}

/// Where to continue after [`run`] stopped at `pc` with `flow`, which is not [`Flow::Exit`], or why the call fails.
#[cold]
#[inline(never)]
fn resume(flow: Flow<u64>, pc: u64, code: &Code, calls: &mut CallStack<HostCalls, u64>, limit: u64) -> Result<u64> {
    match flow {
        Flow::StackOverflow => Err(ExecError::StackOverflow { pc }.into()),
        // a call the linker planted for an unresolved CO-RE relocation
        Flow::CallHelper(CORE_POISON_HELPER) => Err(ExecError::UnresolvedCoreRelo { pc }.into()),
        Flow::CallHelper(_) | Flow::CallKfunc(_) => Err(calls.host.take_error().into()),
        Flow::OutOfFuel => Err(ExecError::InstructionLimit(limit).into()),
        Flow::BadPc => Err(ExecError::InvalidPc(pc).into()),
        Flow::FailCpu => Err(ExecError::CpuFault { pc }.into()),
        Flow::FailMem(addr) => Err(memory_fault(pc, addr, code)),
        Flow::Missing => Err(ExecError::Unimplemented { pc }.into()),
        // a host call `HostCalls::callx` ran failed, or the target addresses neither a function nor a helper
        Flow::CallIndirect(target) => match calls.host.error.take() {
            Some(error) => Err(error.into()),
            None => Err(ExecError::BadCodeAddress { pc, target }.into()),
        },
        Flow::JumpIndirect(target) => jump_indirect(target, pc, code),
        // `run` handles these internally, and the executor `Exit`
        Flow::Exit | Flow::Next | Flow::Jump(_) | Flow::Call(_) => unreachable!(),
    }
}

/// The extern table and maps that helper, kfunc and `callx` calls reach from inside [`run`].
struct HostCalls {
    registry: HelperRegistry,
    #[cfg(feature = "maps")]
    maps: Maps,
    /// Why the call that stopped [`run`] failed, until the executor takes it.
    error: Option<HelperError>,
}

impl HostCalls {
    /// Call the extern table entry at `slot` with the arguments in `ctx.regs[1..=5]`.
    #[inline]
    fn call_slot(&mut self, ctx: &mut Context<&mut VmMemory>, slot: u32) -> std::result::Result<u64, HelperError> {
        let mut helper_ctx = HelperContext {
            args: HelperArgs::from_regs(&ctx.regs),
            memory: &mut *ctx.data,
            #[cfg(feature = "maps")]
            maps: Some(&mut self.maps),
        };
        self.registry.call_slot(slot, &mut helper_ctx)
    }

    /// The error of the helper or kfunc call that stopped [`run`].
    #[cold]
    fn take_error(&mut self) -> HelperError {
        self.error.take().expect("failed host call left no error")
    }
}

impl Host<&mut VmMemory> for HostCalls {
    // Raw bytecode calls helpers by ID; linked programs call slots only, except for calls the linker planted for
    // unresolved CO-RE relocations, which the executor reports.
    #[inline]
    fn helper(&mut self, ctx: &mut Context<&mut VmMemory>, id: u32) -> Option<u64> {
        if id == CORE_POISON_HELPER {
            return None;
        }
        let Some(slot) = self.registry.slot_of_id(id) else {
            self.error = Some(HelperError::UnknownHelper(id));
            return None;
        };
        self.kfunc(ctx, slot)
    }

    #[inline]
    fn kfunc(&mut self, ctx: &mut Context<&mut VmMemory>, slot: u32) -> Option<u64> {
        match self.call_slot(ctx, slot) {
            Ok(r0) => Some(r0),
            Err(err) => {
                self.error = Some(err);
                None
            }
        }
    }

    // A code address names a guest function, which `run` checks against the code. A helper's address is its ID, as in
    // libbpf's `(void *)BPF_FUNC_*` helper declarations.
    #[inline]
    fn callx(&mut self, ctx: &mut Context<&mut VmMemory>, target: u64) -> Option<Callee> {
        if let Some(pc) = code_index(target) {
            return Some(Callee::Local(pc));
        }
        let id = u32::try_from(target).ok()?;
        let Some(slot) = self.registry.slot_of_id(id) else {
            self.error = Some(HelperError::UnknownHelper(id));
            return None;
        };
        self.kfunc(ctx, slot).map(Callee::Host)
    }
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
    let index = code_index(target).filter(|&index| index < code.len() as u64);
    index.ok_or_else(|| ExecError::BadCodeAddress { pc, target }.into())
}

/// Instruction index of the guest code address `addr`, if it is an instruction boundary in the code region. The index
/// may lie past the end of the code.
fn code_index(addr: u64) -> Option<u64> {
    let offset = addr.checked_sub(region_base(CODE_REGION))?;
    (offset % INSN_SIZE == 0).then_some(offset / INSN_SIZE)
}

/// The instruction budget of a call under `config`: `VmConfig` says 0 for no limit, and `run` takes at most
/// `i64::MAX`.
#[cfg(feature = "fuel")]
fn instruction_limit(config: &VmConfig) -> u64 {
    match config.instruction_limit {
        0 => i64::MAX as u64,
        limit => limit.min(i64::MAX as u64),
    }
}

#[cfg(not(feature = "fuel"))]
fn instruction_limit(_: &VmConfig) -> u64 {
    i64::MAX as u64
}

/// [`run`] with the budget `fuel`.
#[inline(always)]
fn run_metered(
    ctx: &mut Context<&mut VmMemory>,
    code: &Code,
    pc: &mut u64,
    #[cfg_attr(not(feature = "fuel"), expect(unused_variables))] fuel: &mut u64,
    calls: &mut CallStack<HostCalls, u64>,
) -> Flow<u64> {
    #[cfg(feature = "fuel")]
    return run(ctx, code, pc, fuel, calls);
    #[cfg(not(feature = "fuel"))]
    return run(ctx, code, pc, calls);
}

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R0, R1, R10, R2, R3, R6, R7};
    use rvm_core::instructions_from_bytes;

    use super::*;
    use crate::error::MemoryError;
    use crate::layout::STACK_REGION;
    use crate::memory::{GuestMemory, Perms};

    /// Run `code` from its first instruction on `memory` plus a one-frame stack.
    fn run_with(code: &[u8], helpers: &HelperRegistry, mut memory: VmMemory, config: &VmConfig) -> Result<u64> {
        let code = instructions_from_bytes(code);
        let len = config.frame_size as usize;
        let stack_top = memory.map_any(STACK_REGION, len, Perms::RW) + config.frame_size;
        Executor::new(helpers.clone(), stack_top, config).call(&code, &mut memory, 0, &[])
    }

    fn run(asm: &mut Assembler) -> Result<u64> {
        run_with(&asm.assemble().unwrap(), &HelperRegistry::default(), VmMemory::new(), &VmConfig::default())
    }

    #[cfg(feature = "fuel")]
    #[test]
    fn instruction_limit() {
        let mut asm = Assembler::new();
        let loop_label = asm.create_label();
        asm.set_label(&loop_label).unwrap();
        asm.ja(&loop_label);
        let code = asm.assemble().unwrap();
        let config = VmConfig {
            instruction_limit: 10,
            ..VmConfig::default()
        };
        let result = run_with(&code, &HelperRegistry::default(), VmMemory::new(), &config);
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
        let run =
            |asm: &mut Assembler| run_with(&asm.assemble().unwrap(), &helpers, VmMemory::new(), &VmConfig::default());

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

    // `callx` runs inside the handler chain too; this is the lib test that takes Miri through that path
    #[test]
    fn callx_calls() {
        let mut helpers = HelperRegistry::default();
        helpers.register_helper_raw(1, |ctx: &mut HelperContext| ctx.args.r1 * 2);
        let run =
            |asm: &mut Assembler| run_with(&asm.assemble().unwrap(), &helpers, VmMemory::new(), &VmConfig::default());
        let addr = |pc: u64| (region_base(CODE_REGION) + pc * INSN_SIZE) as i64;

        // the function at pc 8 returns r1 + 1, then helper 1 doubles it
        let mut asm = Assembler::new();
        asm.lddw(R2, addr(8)).mov64_imm(R1, 20).callx(R2);
        asm.mov64(R1, R0).mov64_imm(R3, 1).callx(R3).exit();
        asm.mov64(R0, R1).add64_imm(R0, 1).exit();
        assert_eq!(run(&mut asm).unwrap(), 42);

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 2).callx(R1).exit();
        assert!(matches!(run(&mut asm), Err(VmError::Helper(HelperError::UnknownHelper(2)))));

        // the function at pc 0 calls itself until the frames run out
        let mut asm = Assembler::new();
        asm.lddw(R1, addr(0)).callx(R1).exit();
        assert!(matches!(run(&mut asm), Err(VmError::Exec(ExecError::StackOverflow { pc: 2 }))));
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
            let call = insns.iter_mut().find(|insn| insn[0] == rvm_core::opcode::CALL).unwrap();
            crate::image::set_slot_call(call, helpers.slot_of_name("bump").unwrap());

            let mut memory = VmMemory::new();
            memory.map_bytes_any(2, &[7; 8], 8, Perms::R);
            run_with(&code, &helpers, memory, &VmConfig::default())
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
