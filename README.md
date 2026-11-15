# vm-ebpf

An embeddable eBPF virtual machine for Rust: parse eBPF ELF objects, link them
against host-registered helper functions, and run them in a bounds-checked
guest memory space.

## Building

```bash
cargo build --release
```

eBPF programs under `bpf/` are plain object files, built separately with
clang:

```bash
clang -target bpf -O2 -g -c bpf/example.c -o bpf/example.o
```

## Running

```bash
cargo run --bin loader   # loads and calls bpf/example.o
cargo run --bin demo     # CO-RE relocation walkthrough
cargo run --bin emu      # loads an ELF passed on the command line
```

## Crates

- `lib/rvm-core`: the instruction set and interpreter loop (`run`, `step`),
  independent of any host integration. Operates on a `Context<M>` over a
  `Memory` trait implementation and returns a `Flow` describing why execution
  stopped (exit, a call, a helper, a fault, or out of fuel).
- `lib/rvm`: the embeddable runtime built on `rvm-core`. Parses ELF objects,
  links them into executable programs, manages guest memory, and dispatches
  helper calls.
- `lib/constelf`: a `const fn` ELF reader used by `rvm` and by `bin/emu`'s
  compile-time address resolution.
- `lib/btf`: BTF (BPF Type Format) parsing and CO-RE (Compile Once, Run
  Everywhere) relocations. The host registers its actual struct layouts in a
  `TypeRegistry`; relocations patch field-access instructions compiled
  against a different layout to match.
- `lib/ebpf-asm`: an assembler and disassembler used by tests and benchmarks
  to build eBPF bytecode without a C toolchain.
- `bin/loader`, `bin/demo`, `bin/emu`: example programs. `loader` shows the
  parse and link API; `demo` shows a CO-RE relocation; `emu` loads an
  arbitrary ELF file.

## Using the runtime

```rust
use rvm::Vm;

let mut vm = Vm::new();

// Numeric helper, called from the guest via `call <id>` with src_reg 0.
vm.register_helper(1, |x: u64| x * 2);

// Named extern, called from the guest via a kfunc-style call.
vm.register_fn("host_add", |a: u64, b: u64| a + b);

let program = vm.load_elf(&elf_bytes)?;
let result = program.call("run", &[42])?;
```

`load_elf` parses and links a single module. For multi-module programs, call
`Vm::load_module` for each object and `Vm::link` with the set of modules.

## Linking

`Linker::link` places code and data sections, resolves relocations between
modules, binds the remaining calls to numeric helper IDs, and applies CO-RE
relocations. A call is bound to a slot in the program's extern table at link
time; linking fails if a named extern has no matching helper or module
export, if a numeric helper ID is never registered, or if a host extern's
declared argument count does not match the registered helper's arity
(checked against the module's BTF, when present). There is no late binding:
an unresolved call is a link error, not a runtime one.

## Guest memory

A guest address is `(region << 32) | offset`. `rvm::VmMemory` holds
`MAX_REGIONS` region slots, each with its own byte range and permissions:

| Region | Contents | Permissions |
|---|---|---|
| 0 | unmapped (always faults) | - |
| `STACK_REGION` (1) | stack, one frame per call level | RW |
| `RODATA_REGION` (2) | `.rodata*` | R |
| `DATA_REGION` (3) | `.data*`, `.bss*` | RW |
| `FIRST_FREE_REGION` (4) and up | free for the host | - |

Host code maps its own regions with `VmMemory::map` (zeroed) or
`VmMemory::map_bytes` (host-owned buffer), and can map existing host memory
directly with the unsafe `VmMemory::map_host`, which requires the pointed-to
memory to outlive the mapping.

## Tests and benchmarks

```bash
cargo test
cargo bench -p rvm --bench exec
```

`exec` benchmarks interpreter throughput on hand-assembled ALU, memory, and
call-heavy loops built with `ebpf-asm`.

## Scope

Loads and links are limited to what the interpreter actually implements:
there is no `BPF_XADD`/atomic support, no BPF map support, and no kfunc BTF
ID resolution. Only the plain and sign-extending memory addressing modes
(`BPF_MEM`, `BPF_MEMSX`) are implemented; `BPF_ABS`, `BPF_IND`, and
`BPF_ATOMIC` return `Flow::Missing`.
