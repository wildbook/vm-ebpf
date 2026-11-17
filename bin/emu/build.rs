//! Links `bpf.o` into an rvm image, so the binary loads it without the linker. `bpf.o` is built from `bpf/example.c`
//! with `clang -target bpf -O2 -g -c bpf/example.c -o bpf.o`.

use std::path::Path;

fn main() {
    let elf = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf.o");
    println!("cargo::rerun-if-changed={elf}");

    let bytes = std::fs::read(elf).unwrap_or_else(|e| panic!("reading {elf}: {e}"));
    let image = rvm::Vm::new()
        .prepare(&bytes)
        .unwrap_or_else(|e| panic!("linking {elf}: {e}"));

    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("bpf.rvmi");
    std::fs::write(&out, image.to_bytes()).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}
