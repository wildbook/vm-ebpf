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

```bash
# Build the entire workspace
cargo build --release

# Build individual components
cargo build -p rvm-core
cargo build -p constelf  
cargo build -p emu
```

## Usage

### Compile eBPF program
```bash
# Compile the sample eBPF program (requires clang/llvm)
clang -target bpf -c bpf/bpf.cpp -o bpf.o
```

### Run the emulator
```bash
# Execute the compiled eBPF program
cargo run --bin emu --release
```

### Run examples
```bash
# ELF parsing demo
cargo run --example demo -p constelf

# VM execution demo  
cargo run --example demo -p rvm-core
```

## Architecture

The VM loads eBPF ELF files at compile-time using `constelf`, maps executable sections into memory, and executes them using the `rvm-core` interpreter. The emulator demonstrates the complete pipeline from ELF loading to program execution with proper register state management and memory handling.