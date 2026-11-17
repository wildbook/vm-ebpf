//! Interpreter throughput baselines. Each program runs `N` loop iterations; criterion reports time per full call, so
//! divide by `N` for per-iteration cost.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ebpf_asm::{Assembler, R0, R1, R10, R2, R6};
use rvm::{FunctionInfo, Image, Import, Program, Vm};

const N: i32 = 10_000;

/// Opcode byte of `call`.
const CALL: u8 = 0x85;

/// `asm` as the program's `main`; with `slot_calls`, its `call <id>` instructions bind to helper slots at load time,
/// as linked calls do.
fn load(vm: &Vm, asm: &mut Assembler, slot_calls: bool) -> Program {
    let code = asm.assemble().unwrap();
    let externs = if slot_calls {
        let (insns, _) = code.as_chunks::<8>();
        let calls = insns.iter().enumerate().filter(|(_, insn)| insn[0] == CALL);
        calls
            .map(|(at, insn)| (at as u32, Import::Helper(u32::from_le_bytes(insn[4..].try_into().unwrap()))))
            .collect()
    } else {
        Vec::new()
    };
    let main = FunctionInfo {
        pc: 0,
        size: code.len() as u64,
        borrows: Vec::new(),
    };
    let image = Image {
        code,
        functions: vec![("main".into(), main)],
        externs,
        ..Image::default()
    };
    vm.load(image).unwrap()
}

/// r0 += r1 * 3 ^ r1, N times: pure ALU + one conditional branch per iteration.
fn alu_loop() -> Assembler {
    let mut asm = Assembler::new();
    let top = asm.create_label();
    asm.mov64_imm(R0, 0).mov64_imm(R1, 0);
    asm.set_label(&top).unwrap();
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
    let top = asm.create_label();
    asm.mov64_imm(R0, 0).mov64_imm(R1, 0);
    asm.set_label(&top).unwrap();
    asm.stxdw(R10, -8, R1).ldxdw(R2, R10, -8).add64(R0, R2).add64_imm(R1, 1);
    asm.jlt_imm(R1, N, &top);
    asm.exit();
    asm
}

/// Call helper 1 (identity) each iteration; r6 is the callee-saved counter.
fn helper_loop() -> Assembler {
    let mut asm = Assembler::new();
    let top = asm.create_label();
    asm.mov64_imm(R0, 0).mov64_imm(R6, 0);
    asm.set_label(&top).unwrap();
    asm.mov64(R1, R6).call(1).add64_imm(R6, 1);
    asm.jlt_imm(R6, N, &top);
    asm.exit();
    asm
}

fn bench(c: &mut Criterion) {
    let vm = Vm::with_config(rvm::VmConfig {
        #[cfg(feature = "fuel")]
        instruction_limit: 0,
        ..rvm::VmConfig::default()
    });
    vm.register_helper(1, |x: u64| x);

    let mut group = c.benchmark_group("exec");
    group.throughput(Throughput::Elements(N as u64));
    let programs = [
        ("alu_loop", load(&vm, &mut alu_loop(), false)),
        ("mem_loop", load(&vm, &mut mem_loop(), false)),
        ("helper_loop", load(&vm, &mut helper_loop(), false)),
        ("slot_call_loop", load(&vm, &mut helper_loop(), true)),
    ];
    for (name, mut program) in programs {
        let main = program.func("main").unwrap();
        group.bench_function(name, |b| b.iter(|| program.call_func(main, black_box(&[])).unwrap()));
    }
    group.finish();

    // Map helpers from a compiled object; each call runs N operations in a guest loop.
    let elf = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/bench/map_bench.o")).unwrap();
    let mut program = rvm::Vm::new().load_elf(&elf).unwrap();
    program.call("hash_update", &[N as u64]).unwrap(); // fill all keys before timing lookups

    let mut group = c.benchmark_group("maps");
    group.throughput(Throughput::Elements(N as u64));
    for name in ["hash_update", "hash_lookup", "array_lookup"] {
        group.bench_function(name, |b| b.iter(|| program.call(name, black_box(&[N as u64])).unwrap()));
    }

    // Same guest loop with helper 1 replaced by a stub: the cost outside the map code.
    let vm = rvm::Vm::new();
    vm.register_helper(1, |_: ()| 0u64);
    let mut stub = vm.load_elf(&elf).unwrap();
    group.bench_function("lookup_stub", |b| b.iter(|| stub.call("array_lookup", black_box(&[N as u64])).unwrap()));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
