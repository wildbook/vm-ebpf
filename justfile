# vm-ebpf justfile
# Run `just --list` to see all available recipes

# Default recipe: build everything
default: build

# === Build Recipes ===

# Build all Rust components
build:
    cargo build

# Build in release mode
build-release:
    cargo build --release

# Build a specific package
build-pkg pkg:
    cargo build -p {{pkg}}

# === BPF Compilation ===

# Compiler settings
clang := "clang"
llvm_objdump := "llvm-objdump"
bpf_cflags := "-target bpf -O2 -g -Wall -Wno-unused-function"

# Build all BPF programs
bpf:
    @echo "Building BPF programs..."
    {{clang}} {{bpf_cflags}} -c bpf/example.c -o bpf/example.o
    @echo "Built: bpf/example.o"

# Build a specific BPF source file
bpf-file file:
    @echo "Compiling {{file}}..."
    {{clang}} {{bpf_cflags}} -c {{file}} -o {{without_extension(file)}}.o

# Build BPF and copy to root for emu (which uses bpf.o)
bpf-emu: bpf
    cp bpf/example.o bpf.o
    @echo "Copied to bpf.o for emu"

# Disassemble a BPF object file
bpf-dump file="bpf/example.o":
    @echo "=== Disassembly of {{file}} ==="
    {{llvm_objdump}} -d --no-show-raw-insn {{file}}

# Show sections in a BPF object file
bpf-sections file="bpf/example.o":
    @echo "=== Sections in {{file}} ==="
    {{llvm_objdump}} -h {{file}}

# Show symbols in a BPF object file
bpf-symbols file="bpf/example.o":
    @echo "=== Symbols in {{file}} ==="
    {{llvm_objdump}} -t {{file}}

# === Run Recipes ===

# Run the emu binary
run-emu: bpf-emu
    cargo run --bin emu

# Run the loader binary
run-loader: bpf
    cargo run --bin loader

# Run the demo binary
run-demo:
    cargo run --bin demo

# Run a specific binary
run bin:
    cargo run --bin {{bin}}

# Run in release mode
run-release bin:
    cargo run --release --bin {{bin}}

# === Test Recipes ===

# Run all tests
test:
    cargo test

# Run tests for a specific package
test-pkg pkg:
    cargo test -p {{pkg}}

# Run tests with output
test-verbose:
    cargo test -- --nocapture

# === Check & Lint ===

# Check all code compiles
check:
    cargo check

# Run clippy lints
clippy:
    cargo clippy

# Format code
fmt:
    cargo fmt

# Check formatting without changes
fmt-check:
    cargo fmt -- --check

# === Clean ===

# Clean Rust build artifacts
clean:
    cargo clean

# Clean BPF object files
clean-bpf:
    rm -f bpf/*.o bpf.o
    @echo "Cleaned BPF object files"

# Clean everything
clean-all: clean clean-bpf

# === Documentation ===

# Build documentation
doc:
    cargo doc

# Build and open documentation
doc-open:
    cargo doc --open

# === Utility ===

# Show workspace members
members:
    @echo "Workspace members:"
    @echo "  Libraries:"
    @echo "    - rvm-core (lib/rvm-core)"
    @echo "    - constelf (lib/constelf)"
    @echo "    - btf (lib/btf)"
    @echo "  Binaries:"
    @echo "    - emu (bin/emu)"
    @echo "    - loader (bin/loader)"
    @echo "    - demo (bin/demo)"

# Full rebuild: clean and build everything
rebuild: clean-all bpf build

# CI check: format, clippy, test
ci: fmt-check clippy test
