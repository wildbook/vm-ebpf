//! Costs a plugin host sees: entering a program, calling between plugins, and clang-compiled workloads
//! (bpf/bench/workloads.c). Compare against a saved baseline:
//!
//!   cargo bench -p rvm --bench workloads -- --save-baseline before
//!   cargo bench -p rvm --bench workloads -- --baseline before

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rvm::{Perms, Plugin, Vm};

fn object(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../bpf/prebuilt/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Calling into a program and plugin, with no guest work.
fn entry(c: &mut Criterion) {
    let vm = Vm::new();
    let mut program = vm.load_elf(&object("bench/workloads.o")).unwrap();
    let plugin = Plugin::new("w", vm.load_elf(&object("bench/workloads.o")).unwrap());

    let mut group = c.benchmark_group("entry");
    group.bench_function("program_call", |b| b.iter(|| program.call("noop", black_box(&[])).unwrap()));
    group.bench_function("plugin_call", |b| b.iter(|| plugin.call("noop", black_box(&[])).unwrap()));
    group.finish();
}

/// One plugin calling another's export, plain and with two borrowed buffers.
fn cross_plugin(c: &mut Criterion) {
    let vm = Vm::new();
    vm.register_extern("host_reenter", |x: u64| x);
    let a = Plugin::new("a", vm.load_elf(&object("tests/plugin_a_v1.o")).unwrap());
    vm.export(&a, "a_scale").unwrap();
    let b = Plugin::new("b", vm.load_elf(&object("tests/plugin_b.o")).unwrap());

    let callee = Plugin::new("callee", vm.load_elf(&object("tests/borrow_callee.o")).unwrap());
    for func in ["sum", "fill", "poke"] {
        vm.export(&callee, func).unwrap();
    }
    let caller = Plugin::new("caller", vm.load_elf(&object("tests/borrow_caller.o")).unwrap());

    let mut group = c.benchmark_group("cross_plugin");
    group.bench_function("export_call", |bench| bench.iter(|| b.call("b_run", black_box(&[5])).unwrap()));
    group.bench_function("two_borrowed_calls", |bench| bench.iter(|| caller.call("run", black_box(&[])).unwrap()));
    group.finish();
}

/// Guest-heavy workloads.
fn guest(c: &mut Criterion) {
    const BUF: usize = 64 * 1024;
    const N: u64 = 10_000;

    let vm = Vm::new();
    let mut program = vm.load_elf(&object("bench/workloads.o")).unwrap();

    // records of [kind][n][n bytes], n cycling 0..32
    let mut records = Vec::with_capacity(BUF);
    for i in 0.. {
        let n = (i % 32) as u8;
        if records.len() + 2 + n as usize > BUF {
            break;
        }
        records.extend([(i % 4) as u8, n]);
        records.extend((0..n).map(|j| j.wrapping_mul(31)));
    }
    let buf = program.memory_mut().map_bytes(&records, BUF, Perms::R).unwrap().base();

    let mut group = c.benchmark_group("guest");
    group.throughput(Throughput::Bytes(records.len() as u64));
    group.bench_function("parse_64k", |b| {
        b.iter(|| program.call("parse", black_box(&[buf, records.len() as u64])).unwrap())
    });
    group.throughput(Throughput::Elements(N));
    group.bench_function("aggregate_10k", |b| b.iter(|| program.call("aggregate", black_box(&[N])).unwrap()));
    group.throughput(Throughput::Elements(100));
    group.bench_function("fib7_x100", |b| b.iter(|| program.call("calls", black_box(&[100])).unwrap()));
    group.finish();
}

fn config() -> Criterion {
    Criterion::default()
        .measurement_time(Duration::from_secs(8))
        .sample_size(200)
        .noise_threshold(0.03)
}

criterion_group! {
    name = benches;
    config = config();
    targets = entry, cross_plugin, guest
}
criterion_main!(benches);
