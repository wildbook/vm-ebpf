//! Links `bpf/examples/example.o` into an rvm image, so the binary loads it without the linker.

use std::path::Path;

fn main() {
    let elf = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/examples/example.o");
    println!("cargo::rerun-if-changed={elf}");

    let bytes = std::fs::read(elf).unwrap_or_else(|e| panic!("reading {elf}: {e}"));
    let image = rvm::Vm::new()
        .prepare(&bytes)
        .unwrap_or_else(|e| panic!("linking {elf}: {e}"));

    let out = Path::new(&std::env::var("OUT_DIR").unwrap()).join("bpf.rvmi");
    std::fs::write(&out, image.to_bytes()).unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
}
