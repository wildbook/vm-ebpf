# vm-ebpf

A minimal eBPF virtual machine implementation in Rust with constant-time ELF loading.

## Components

### `rvm-core` (lib/rvm-core)
eBPF virtual machine core with instruction execution, register management, and memory abstraction. Implements the full eBPF instruction set including ALU operations, jumps, memory loads/stores, and function calls.

### `constelf` (lib/constelf)  
Constant-time ELF parser for loading eBPF bytecode. Handles ELF sections, symbol tables, and relocations at compile-time for zero-overhead loading.

### `emu` (bin/emu)
Main emulator binary that loads and executes eBPF programs. Demonstrates the complete workflow from ELF loading to program execution.

### `bpf` (bpf/)
Sample eBPF program source code (C++) that gets compiled to ELF and executed by the VM.

## Building

This project uses [just](https://github.com/casey/just) as a command runner. Run `just --list` to see all available recipes.

```bash
# Build all Rust components
just build

# Build in release mode
just build-release

# Build BPF programs
just bpf

# Full rebuild (clean + bpf + build)
just rebuild
```

### Manual Building

```bash
# Build the entire workspace
cargo build --release

# Build individual components
cargo build -p rvm-core
cargo build -p constelf  
cargo build -p emu

# Compile BPF program (requires clang/llvm)
clang -target bpf -O2 -g -c bpf/example.c -o bpf/example.o
```

## Usage

```bash
# Run the emulator (builds BPF first)
just run-emu

# Run the loader
just run-loader

# Run the demo
just run-demo
```

### Manual Usage

```bash
# Execute the compiled eBPF program
cargo run --bin emu --release
```

## Testing

```bash
# Run all tests
just test

# Run tests with output
just test-verbose

# CI checks (format, clippy, test)
just ci
```

## BPF Inspection

```bash
# Disassemble BPF object file
just bpf-dump

# Show sections
just bpf-sections

# Show symbols
just bpf-symbols
```

## Architecture

The VM loads eBPF ELF files at compile-time using `constelf`, maps executable sections into memory, and executes them using the `rvm-core` interpreter. The emulator demonstrates the complete pipeline from ELF loading to program execution with proper register state management and memory handling.