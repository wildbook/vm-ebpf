//! Runs eBPF bytecode on rvm-core and dispatches helper calls to a [`HelperRegistry`].

use std::fmt;

use rvm_core::{
    Callee, Code, Context, Host, Interpreter, Native, NativeCall, Reason, StackArgs, MAX_STACK_ARGS, METERED,
};

use crate::error::{ExecError, MemoryError, Result, VmError};
use crate::helper::{CallerFuel, HelperRegistry, HostState, Stop};
use crate::image::INSN_SIZE;
use crate::layout::CODE_REGION;
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{region_tag, VmMemory, RAW_END, RAW_START};
use crate::vm::VmConfig;

/// Default stack bytes reserved per call frame (eBPF's `MAX_BPF_STACK`).
pub const DEFAULT_FRAME_SIZE: u64 = 512;

/// Helper ID of the call the linker plants for a CO-RE relocation the host can't resolve (`btf::CORE_POISON_HELPER`).
pub const CORE_POISON_HELPER: u32 = 0xbad2310;

/// Arguments of a call that pass in registers, r1 to r5.
pub const REG_ARGS: usize = 5;

/// Most arguments of a call: those in registers, and those the caller passes on the stack.
pub const MAX_ARGS: usize = REG_ARGS + MAX_STACK_ARGS;

/// Runs the functions of one program, with BPF-to-BPF calls on their own stack frames.
///
/// Each call borrows the code and the memory, so the memory survives errors. Code is a separate instruction slice, so
/// the guest can neither read nor modify it through memory. The executor keeps what carries over from one call to the
/// next: the extern table, the maps, the frame size, the instruction limit and the memory windows.
pub struct Executor {
    /// The frames of the local calls in progress, and the frame size, instruction limit, memory windows and host.
    interp: Interpreter<VmMemory, HostCalls>,
    /// Initial r10.
    stack_top: u64,
}

impl Executor {
    /// An executor whose calls start with r10 at `stack_top`, with the frame size, instruction limit and raw calls of
    /// `config`.
    pub fn new(helpers: HelperRegistry, stack_top: u64, config: &VmConfig) -> Self {
        let host = HostCalls {
            registry: helpers,
            state: HostState::default(),
            stop: None,
            raw_calls: config.raw_calls.is_on(),
        };
        #[cfg_attr(not(feature = "fuel"), expect(unused_mut))]
        let mut executor = Self {
            interp: Interpreter::new(config.frame_size, host),
            stack_top,
        };
        // 0 is no limit, and without the `fuel` feature `Vm::with_config` refuses any other
        #[cfg(feature = "fuel")]
        if config.instruction_limit != 0 {
            executor.set_limit(Some(config.instruction_limit));
        }
        executor
    }

    /// Replace the extern table that helper and kfunc calls use.
    pub fn set_helpers(&mut self, helpers: HelperRegistry) {
        self.interp.host.registry = helpers;
    }

    /// The maps passed to helpers through [`HostState::maps`].
    #[cfg(feature = "maps")]
    pub fn maps_mut(&mut self) -> &mut Maps {
        &mut self.interp.host.state.maps
    }

    /// The instruction limit of [`call`](Self::call), at most `i64::MAX`, if it has one.
    #[inline]
    pub fn instruction_limit(&self) -> Option<u64> {
        self.interp.limit()
    }

    /// Call the function at `pc` (instruction index) of `code` under the instruction limit; returns r0. `args` go in
    /// r1-r5 and, from the sixth on, where a caller that passes them on the stack leaves them. More than 12
    /// arguments fail with [`VmError::TooManyArgs`].
    #[inline(always)]
    pub fn call(&mut self, code: &Code, memory: &mut VmMemory, pc: u64, args: &[u64]) -> Result<u64> {
        if args.len() > REG_ARGS {
            return self.call_with_stack_args(code, memory, pc, args);
        }

        // A call starts with fresh registers in the entry frame. Guest code can read and write all 16 registers,
        // r11-r15 included, so each starts at a defined value: r1-r5 hold the arguments and 0 past `args.len()`, r10
        // the stack top, the others 0.
        let mut ctx = Context::new(memory);
        // at most `REG_ARGS` stores; `copy_from_slice` calls memcpy
        for (i, &arg) in args.iter().take(REG_ARGS).enumerate() {
            ctx.regs[i + 1] = arg;
        }
        ctx.regs[10] = self.stack_top;

        let stop = self.interp.run(&mut ctx, code, pc);
        if let Reason::Exit = stop.reason {
            return Ok(ctx.regs[0]);
        }
        run_on(stop.reason, stop.pc, code, &mut ctx, &mut self.interp)
    }

    /// [`call`](Self::call) with more than [`REG_ARGS`] arguments.
    // Out of line, so that a call with up to five arguments pays one test for the others.
    #[cold]
    #[inline(never)]
    fn call_with_stack_args(&mut self, code: &Code, memory: &mut VmMemory, pc: u64, args: &[u64]) -> Result<u64> {
        if args.len() > MAX_ARGS {
            return Err(VmError::TooManyArgs(args.len()));
        }
        let (regs, stack) = args.split_at(REG_ARGS);
        let entry = EntryArgs::new(self, stack);
        entry.executor.call(code, memory, pc, regs)
    }

    /// [`call`](Self::call) that runs at most `*fuel` instructions, the ones it runs in other plugins through their
    /// exports included, and leaves what is left in `*fuel`. Without the `fuel` feature nothing counts them, and
    /// `*fuel` stays as it is.
    pub fn call_fueled(
        &mut self,
        code: &Code,
        memory: &mut VmMemory,
        pc: u64,
        args: &[u64],
        #[cfg_attr(not(feature = "fuel"), expect(unused_variables))] fuel: &mut u64,
    ) -> Result<u64> {
        #[cfg(feature = "fuel")]
        {
            // before the budget, so that a call that runs nothing leaves `*fuel`
            if args.len() > MAX_ARGS {
                return Err(VmError::TooManyArgs(args.len()));
            }
            let budget = Budget::new(self, *fuel);
            let result = budget.executor.call(code, memory, pc, args);
            *fuel = budget.executor.interp.fuel().expect("a budget meters the call");
            result
        }
        #[cfg(not(feature = "fuel"))]
        self.call(code, memory, pc, args)
    }

    /// Meter the calls from now on with `limit`, or not at all, and tell the host functions whether their caller is
    /// metered.
    #[cfg(feature = "fuel")]
    fn set_limit(&mut self, limit: Option<u64>) {
        self.interp.set_limit(limit);
        self.interp.host.state.fuel = match limit {
            Some(_) => CallerFuel::Unknown,
            None => CallerFuel::Unmetered,
        };
    }
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Executor");
        s.field("helpers", &self.interp.host.registry);
        #[cfg(feature = "maps")]
        s.field("maps", &self.interp.host.state.maps);
        s.field("stack_top", &self.stack_top);
        if METERED {
            s.field("instruction_limit", &self.interp.limit());
        }
        s.finish_non_exhaustive()
    }
}

/// The executor with a limit of its own for one call. It restores the executor's limit when dropped, also when a host
/// function panics during the call.
#[cfg(feature = "fuel")]
struct Budget<'a> {
    executor: &'a mut Executor,
    /// The executor's limit.
    own: Option<u64>,
}

#[cfg(feature = "fuel")]
impl<'a> Budget<'a> {
    /// `executor` with a limit of `fuel`.
    fn new(executor: &'a mut Executor, fuel: u64) -> Self {
        let own = executor.interp.limit();
        executor.set_limit(Some(fuel));
        Self { executor, own }
    }
}

#[cfg(feature = "fuel")]
impl Drop for Budget<'_> {
    fn drop(&mut self) {
        self.executor.set_limit(self.own);
    }
}

/// The executor with stack arguments for the entry frame of one call. It clears them when dropped, also when a host
/// function panics during the call, so that between calls each is 0: an entry function reads 0 for a stack argument
/// that a call doesn't pass.
struct EntryArgs<'a> {
    executor: &'a mut Executor,
}

impl<'a> EntryArgs<'a> {
    /// `executor` with `stack`, at most [`MAX_STACK_ARGS`] values, as the first stack arguments of the entry frame.
    fn new(executor: &'a mut Executor, stack: &[u64]) -> Self {
        executor.interp.entry_args()[..stack.len()].copy_from_slice(stack);
        Self { executor }
    }
}

impl Drop for EntryArgs<'_> {
    fn drop(&mut self) {
        *self.executor.interp.entry_args() = [0; MAX_STACK_ARGS];
    }
}

/// Continue a call after [`Interpreter::run`] stopped at `pc` with `reason`, which is not [`Reason::Exit`], until it
/// returns or fails.
// Out of line, so that the call's usual path keeps nothing across `run` that only resuming needs.
#[cold]
#[inline(never)]
fn run_on(
    mut reason: Reason<u64>,
    mut pc: u64,
    code: &Code,
    ctx: &mut Context<VmMemory>,
    interp: &mut Interpreter<VmMemory, HostCalls>,
) -> Result<u64> {
    loop {
        pc = match interp.host.take_fuel_wanted(reason) {
            Some(slot) => call_with_fuel(slot, pc, code, ctx, interp)?,
            None => resume_at(reason, pc, code, interp)?,
        };
        let stop = interp.resume(ctx, code, pc);
        (reason, pc) = (stop.reason, stop.pc);
        if let Reason::Exit = reason {
            return Ok(ctx.regs[0]);
        }
    }
}

/// Call the host function in extern-table `slot`, which stopped the call at `pc` asking for the caller's fuel, again
/// with the fuel the caller has left, and return where the caller continues. The caller continues with the fuel the
/// function leaves.
#[cold]
#[inline(never)]
fn call_with_fuel(
    slot: u32,
    pc: u64,
    code: &Code,
    ctx: &mut Context<VmMemory>,
    interp: &mut Interpreter<VmMemory, HostCalls>,
) -> Result<u64> {
    let fuel = interp.fuel().expect("only a metered caller asks for its fuel");
    // the call passes the stack arguments again if it passed them the first time
    let stack = code.passes_stack_args(pc).then(|| *interp.stack_args());
    let host = &mut interp.host;
    host.state.fuel = CallerFuel::Left(fuel);
    let mut stop = None;
    let r0 = match &stack {
        Some(stack) => host
            .registry
            .call_slot_stack(slot, ctx, &mut host.state, &mut stop, stack),
        None => host.registry.call_slot(slot, ctx, &mut host.state, &mut stop),
    };
    let CallerFuel::Left(left) = std::mem::replace(&mut host.state.fuel, CallerFuel::Unknown) else {
        unreachable!("the fuel stays while the function runs")
    };
    interp.set_fuel(left);
    ctx.regs[0] = r0.ok_or_else(|| failure(stop.expect("stopped host call left no reason"), pc))?;
    Ok(pc + 1)
}

/// Where to continue after [`Interpreter::run`] stopped at `pc` with `reason`, which is not [`Reason::Exit`], or why
/// the call fails.
#[cold]
#[inline(never)]
fn resume_at(reason: Reason<u64>, pc: u64, code: &Code, interp: &mut Interpreter<VmMemory, HostCalls>) -> Result<u64> {
    match reason {
        Reason::StackOverflow => Err(ExecError::StackOverflow { pc }.into()),
        // a call the linker planted for an unresolved CO-RE relocation
        Reason::CallHelper(CORE_POISON_HELPER) => Err(ExecError::UnresolvedCoreRelo { pc }.into()),
        Reason::CallHelper(id) | Reason::CallKfunc(id) => match interp.host.stop.take() {
            Some(stop) => Err(failure(stop, pc)),
            // a native call past the table, which binding never writes
            None => Err(ExecError::UnknownExtern { pc, slot: id }.into()),
        },
        Reason::OutOfFuel => {
            let limit = interp.limit().expect("only a metered call runs out of fuel");
            Err(ExecError::InstructionLimit { limit }.into())
        }
        Reason::BadPc => Err(ExecError::InvalidPc { pc }.into()),
        Reason::InvalidInstruction => Err(ExecError::InvalidInstruction { pc }.into()),
        Reason::MemoryFault(addr) => Err(memory_fault(pc, addr, code)),
        Reason::Unsupported => Err(ExecError::Unimplemented { pc }.into()),
        // a host call `HostCalls::call_indirect` ran failed, or the target addresses neither a function nor a helper
        Reason::CallIndirect(target) => match interp.host.stop.take() {
            Some(stop) => Err(failure(stop, pc)),
            None => Err(ExecError::BadCodeAddress { pc, target }.into()),
        },
        Reason::JumpIndirect(target) => jump_indirect(target, pc, code),
        Reason::Exit => unreachable!("the executor returns at `exit`"),
    }
}

/// The error of the call at `pc` that `stop` stopped.
fn failure(stop: Stop, pc: u64) -> VmError {
    match stop {
        Stop::Failed(error) => error.into(),
        Stop::UnknownHelper(id) => ExecError::UnknownHelper { pc, id }.into(),
        Stop::UnknownSlot(slot) => ExecError::UnknownExtern { pc, slot }.into(),
        Stop::FuelWanted => unreachable!("`run_on` answers fuel requests"),
    }
}

/// The extern table and the state that helper, kfunc and `callx` calls reach from inside [`Interpreter::run`].
struct HostCalls {
    registry: HelperRegistry,
    state: HostState,
    /// Why the host call that stopped the run did, until the executor takes it.
    stop: Option<Stop>,
    /// Whether a `callx` through a raw address calls it: [`RawCalls::on`](crate::RawCalls::on).
    raw_calls: bool,
}

impl HostCalls {
    /// The extern-table slot of the host function that stopped the run with `reason` asking for the caller's fuel, if
    /// it did; takes the request.
    #[cold]
    fn take_fuel_wanted(&mut self, reason: Reason<u64>) -> Option<u32> {
        if !matches!(self.stop, Some(Stop::FuelWanted)) {
            return None;
        }
        let slot = match reason {
            Reason::CallKfunc(slot) => Some(slot),
            Reason::CallHelper(id) => self.registry.slot_of_id(id),
            Reason::CallIndirect(target) => u32::try_from(target).ok().and_then(|id| self.registry.slot_of_id(id)),
            _ => None,
        }?;
        self.stop = None;
        Some(slot)
    }
}

impl Host<VmMemory> for HostCalls {
    // Raw bytecode calls helpers by ID; linked programs call slots only, except for calls the linker planted for
    // unresolved CO-RE relocations, which the executor reports.
    #[inline]
    fn call_helper(&mut self, ctx: &mut Context<VmMemory>, id: u32) -> Option<u64> {
        if id == CORE_POISON_HELPER {
            return None;
        }
        let Some(slot) = self.registry.slot_of_id(id) else {
            self.stop = Some(Stop::UnknownHelper(id));
            return None;
        };
        self.call_kfunc(ctx, slot)
    }

    #[inline]
    fn call_kfunc(&mut self, ctx: &mut Context<VmMemory>, slot: u32) -> Option<u64> {
        self.registry.call_slot(slot, ctx, &mut self.state, &mut self.stop)
    }

    #[inline]
    fn call_kfunc_stack(&mut self, ctx: &mut Context<VmMemory>, slot: u32, stack: &StackArgs) -> Option<u64> {
        self.registry
            .call_slot_stack(slot, ctx, &mut self.state, &mut self.stop, stack)
    }

    // A code address names a guest function, which the interpreter checks against the code. With raw calls, an
    // address without a tag from 64 KiB up is a native function. A helper's address is its ID, as in libbpf's
    // `(void *)BPF_FUNC_*` helper declarations.
    //
    // Always inline: the interpreter has one `callx` handler for metered runs and one for the others, and LLVM leaves
    // a function with two callers out of line, which costs every `callx` a call.
    #[inline(always)]
    fn call_indirect(
        &mut self,
        ctx: &mut Context<VmMemory>,
        target: u64,
        native: NativeCall<'_, u64>,
    ) -> Option<Callee> {
        if let Some(pc) = code_index(target) {
            return Some(Callee::Local(pc));
        }
        // The helper IDs in use lie below 64 KiB, so this one test decides for them. Its other side is cold, so that
        // the register allocator serves the helper call first.
        if target >= RAW_START {
            core::hint::cold_path();
            if self.raw_calls && target < RAW_END {
                // SAFETY: `RawCalls::on` leaves every target and its arguments to the host
                return Some(Callee::Host(unsafe { native.call(target, &ctx.regs) }));
            }
            if target > u64::from(u32::MAX) {
                return None;
            }
        }
        let id = target as u32;
        let Some(slot) = self.registry.slot_of_id(id) else {
            self.stop = Some(Stop::UnknownHelper(id));
            return None;
        };
        self.call_kfunc(ctx, slot).map(Callee::Host)
    }

    #[inline(always)]
    fn natives(&self) -> &[Native] {
        self.registry.natives()
    }
}

/// The fault at `pc` of the load or store, or of the native call's pointer argument, that failed at `addr`.
fn memory_fault(pc: u64, addr: u64, code: &Code) -> VmError {
    // `VmMemory::native_ptr` fails with the first byte out of reach
    let size = code.access_size(pc).unwrap_or(1);
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
    let offset = addr.checked_sub(region_tag(CODE_REGION))?;
    (offset % INSN_SIZE == 0).then_some(offset / INSN_SIZE)
}

/// The fuel of a call limited to `limit` instructions, for [`Executor::call_fueled`]: 0 means no limit, which counts
/// as `i64::MAX`, the most a limit can be.
pub fn fuel_for(limit: u64) -> u64 {
    match limit {
        0 => i64::MAX as u64,
        limit => limit.min(i64::MAX as u64),
    }
}

#[cfg(test)]
mod tests {
    use ebpf_asm::{Assembler, R0, R1, R10, R2, R3, R6};
    use rvm_core::Instruction;

    use super::*;
    use crate::error::HostError;
    use crate::helper::{HelperContext, HostFn};
    use crate::layout::STACK_REGION;
    use crate::memory::{GuestMemory, Perms};

    /// Run `code` from its first instruction on `memory` plus a one-frame stack.
    fn run_with(code: &[u8], helpers: &HelperRegistry, mut memory: VmMemory, config: &VmConfig) -> Result<u64> {
        let code = Code::new(Instruction::decode(code));
        let len = config.frame_size as usize;
        let stack_top = memory.map_any(STACK_REGION, len, Perms::RW).unwrap() + config.frame_size;
        Executor::new(helpers.clone(), stack_top, config).call(&code, &mut memory, 0, &[])
    }

    fn run(asm: &Assembler) -> Result<u64> {
        run_with(&asm.assemble().unwrap(), &HelperRegistry::default(), VmMemory::new(), &VmConfig::default())
    }

    #[test]
    fn running_off_code_end_is_invalid_pc() {
        let mut asm = Assembler::new();
        asm.mov64_imm(R0, 1);
        assert!(matches!(run(&asm), Err(VmError::Exec(ExecError::InvalidPc { pc: 1 }))));
    }

    /// Load-acquire writes its `dst`, and r10 is read-only.
    #[test]
    fn load_acquire_into_r10_faults() {
        let mut asm = Assembler::new();
        asm.mov64(R1, R10).load_acquire64(R10, R1, -8).exit();
        assert!(matches!(run(&asm), Err(VmError::Exec(ExecError::InvalidInstruction { pc: 1 }))));
    }

    /// The access size comes from the faulting instruction, which may sit inside a superinstruction or be an r10
    /// access, whose first slots hold rewritten opcode bytes.
    #[test]
    fn memory_fault_reports_access_size() {
        let fault = |asm: &Assembler| match run(asm) {
            Err(VmError::Exec(ExecError::MemoryFault { pc, error })) => (pc, error.size),
            other => panic!("{other:?}"),
        };

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 0).ldxh(R0, R1, 0).exit();
        assert_eq!(fault(&asm), (1, 2));

        // mov, add, ldxw: one superinstruction
        let mut asm = Assembler::new();
        asm.mov64_imm(R2, 0)
            .mov64_imm(R3, 0)
            .mov64(R1, R2)
            .add64(R1, R3)
            .ldxw(R0, R1, 0)
            .exit();
        assert_eq!(fault(&asm), (4, 4));

        // above the stack top
        let mut asm = Assembler::new();
        asm.stxdw(R10, 8, R1).exit();
        assert_eq!(fault(&asm), (0, 8));
    }

    #[test]
    fn stack_overflow_deep_recursion() {
        let mut asm = Assembler::new();
        let func_start = asm.label();
        asm.bind(func_start);
        asm.call_local(func_start);
        asm.exit();
        assert!(matches!(run(&asm), Err(VmError::Exec(ExecError::StackOverflow { .. }))));
    }

    // helper calls run inside the handler chain; this is the lib test that takes Miri through that path
    #[test]
    fn helper_calls() {
        let mut helpers = HelperRegistry::default();
        let store_and_double = |ctx: &mut HelperContext| {
            ctx.memory.write(ctx.args.r2, 7u64).unwrap();
            Ok(ctx.args.r1 * 2)
        };
        helpers.put_id(1, HostFn::raw(store_and_double));
        let run = |asm: &Assembler| run_with(&asm.assemble().unwrap(), &helpers, VmMemory::new(), &VmConfig::default());

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
        assert_eq!(run(&asm).unwrap(), 49);

        let mut asm = Assembler::new();
        asm.mov64(R2, R10);
        asm.add64_imm(R2, -8);
        asm.call(1);
        asm.call(2);
        asm.exit();
        assert!(matches!(run(&asm), Err(VmError::Exec(ExecError::UnknownHelper { pc: 3, id: 2 }))));
    }

    // `callx` runs inside the handler chain too; this is the lib test that takes Miri through that path
    #[test]
    fn callx_calls() {
        let mut helpers = HelperRegistry::default();
        helpers.put_id(1, HostFn::typed(|x: u64| x * 2));
        let run = |asm: &Assembler| run_with(&asm.assemble().unwrap(), &helpers, VmMemory::new(), &VmConfig::default());
        let addr = |pc: u64| (region_tag(CODE_REGION) + pc * INSN_SIZE) as i64;

        // the function at pc 8 returns r1 + 1, then helper 1 doubles it
        let mut asm = Assembler::new();
        asm.lddw(R2, addr(8)).mov64_imm(R1, 20).callx(R2);
        asm.mov64(R1, R0).mov64_imm(R3, 1).callx(R3).exit();
        asm.mov64(R0, R1).add64_imm(R0, 1).exit();
        assert_eq!(run(&asm).unwrap(), 42);

        let mut asm = Assembler::new();
        asm.mov64_imm(R1, 2).callx(R1).exit();
        assert!(matches!(run(&asm), Err(VmError::Exec(ExecError::UnknownHelper { pc: 1, id: 2 }))));

        // the function at pc 0 calls itself until the frames run out
        let mut asm = Assembler::new();
        asm.lddw(R1, addr(0)).callx(R1).exit();
        assert!(matches!(run(&asm), Err(VmError::Exec(ExecError::StackOverflow { pc: 2 }))));
    }

    // a host function with memory access runs inside the handler chain too, and an `Err` from it fails the guest call
    #[test]
    fn memory_fn() {
        let mut helpers = HelperRegistry::default();
        let bump = |mem: &mut GuestMemory, addr: u64| {
            let old = mem.read::<u64>(addr)?;
            mem.write(addr, old + 1)?;
            Ok::<_, MemoryError>(old)
        };
        helpers.put_name("bump".into(), HostFn::with_memory(bump));
        let run = |addr: Option<u64>, memory: VmMemory| {
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

            run_with(&code, &helpers, memory, &VmConfig::default())
        };

        // r0 in the low half, the stack slot in the high half
        assert_eq!(run(None, VmMemory::new()).unwrap(), 42 << 32 | 41);
        // an unmapped address, and a read-only region that can be read but not written
        let mut read_only = VmMemory::new();
        let base = read_only.map_bytes_any(2, &[7; 8], 8, Perms::R).unwrap();
        for (addr, memory) in [(0, VmMemory::new()), (base, read_only)] {
            let err = run(Some(addr), memory).unwrap_err();
            let VmError::Host(HostError::Failed(e)) = &err else {
                panic!("{err:?}")
            };
            assert_eq!(e.downcast_ref::<MemoryError>(), Some(&MemoryError { addr, size: 8 }));
        }
    }
}
