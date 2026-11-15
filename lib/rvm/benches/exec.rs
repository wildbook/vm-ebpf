//! Interpreter throughput baselines. Each program runs `N` loop iterations;
//! criterion reports time per full call, so divide by `N` for per-iteration cost.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ebpf_asm::{Assembler, R0, R1, R10, R2, R6};
use rvm::{Executor, HelperRegistry, Instruction, Perms, VmMemory};

const N: i32 = 10_000;
const STACK: usize = 4096;

fn load(asm: &mut Assembler) -> (Box<[Instruction]>, VmMemory, u64) {
    let bytes = asm.assemble().unwrap();
    let code = rvm::instructions_from_bytes(&bytes);
    let mut mem = VmMemory::new();
    let stack_top = mem.map(rvm::STACK_REGION, STACK, Perms::RW) + STACK as u64;
    (code, mem, stack_top)
}

/// r0 += r1 * 3 ^ r1, N times: pure ALU + one conditional branch per iteration.
fn alu_loop() -> Assembler {
    let mut asm = Assembler::new();
    let mut top = asm.create_label();
    asm.mov64_imm(R0, 0).mov64_imm(R1, 0);
    asm.set_label(&mut top).unwrap();
    asm.mov64(R2, R1)
        .mul64_imm(R2, 3)
        .xor64(R2, R1)
        .add64(R0, R2)
        .add64_imm(R1, 1);
    asm.jlt_imm(R1, N, &top);
    asm.exit();
    asm
}

/// Store then load a stack slot each iteration: two memory accesses per iteration.
fn mem_loop() -> Assembler {
    let mut asm = Assembler::new();
    let mut top = asm.create_label();
    asm.mov64_imm(R0, 0).mov64_imm(R1, 0);
    asm.set_label(&mut top).unwrap();
    asm.stxdw(R10, -8, R1).ldxdw(R2, R10, -8).add64(R0, R2).add64_imm(R1, 1);
    asm.jlt_imm(R1, N, &top);
    asm.exit();
    asm
}

/// Call helper 1 (identity) each iteration; r6 is the callee-saved counter.
fn helper_loop() -> Assembler {
    let mut asm = Assembler::new();
    let mut top = asm.create_label();
    asm.mov64_imm(R0, 0).mov64_imm(R6, 0);
    asm.set_label(&mut top).unwrap();
    asm.mov64(R1, R6).call(1).add64_imm(R6, 1);
    asm.jlt_imm(R6, N, &top);
    asm.exit();
    asm
}

/// Rewrite `call <id>` into a slot call (`src_reg = 2`), as the linker does.
/// Patches the decoded instruction slice, since code is not in guest memory.
fn as_slot_calls(asm: &mut Assembler, helpers: &HelperRegistry) -> (Box<[Instruction]>, VmMemory, u64) {
    use rvm_core::opcode::OpCode;

    let (mut code, mem, stack_top) = load(asm);
    for insn in code.iter_mut() {
        if insn.opcode().0 == 0x85 && insn.src_reg() == 0 {
            let slot = helpers.slot_of_id(insn.imm() as u32).unwrap();
            *insn = Instruction::from_parts(OpCode(0x85), insn.dst_reg(), 2, insn.offset(), slot as i32);
        }
    }
    (code, mem, stack_top)
}

fn bench(c: &mut Criterion) {
    let mut helpers = HelperRegistry::new();
    helpers.register(1, |x: u64| x);

    let mut group = c.benchmark_group("exec");
    group.throughput(Throughput::Elements(N as u64));
    let programs = [
        ("alu_loop", load(&mut alu_loop())),
        ("mem_loop", load(&mut mem_loop())),
        ("helper_loop", load(&mut helper_loop())),
        ("slot_call_loop", as_slot_calls(&mut helper_loop(), &helpers)),
    ];
    for (name, (code, mut mem, stack_top)) in programs {
        group.bench_function(name, |b| {
            b.iter(|| {
                Executor::new(&code, &mut mem, &helpers, stack_top)
                    .call(0, black_box(&[]))
                    .unwrap()
            })
        });
    }
    group.finish();

    // Map helpers from a compiled object; each call runs N operations in a guest loop.
    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/map_bench.o")).unwrap();
    let mut program = rvm::Vm::new().load_elf(&elf).unwrap();
    program.call("hash_update", &[N as u64]).unwrap(); // fill all keys before timing lookups

    let mut group = c.benchmark_group("maps");
    group.throughput(Throughput::Elements(N as u64));
    for name in ["hash_update", "hash_lookup", "array_lookup"] {
        group.bench_function(name, |b| b.iter(|| program.call(name, black_box(&[N as u64])).unwrap()));
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
