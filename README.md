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

let vm = Vm::new();

// Numeric helper, called from the guest via `call <id>` with src_reg 0.
// IDs 1 to 3 are the built-in map helpers.
vm.register_helper(100, |x: u64| x * 2);

// Named extern, imported by the guest as `extern u64 host_add(u64, u64);`.
vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);

let mut program = vm.load_elf(&elf_bytes)?;
let result = program.call("run", &[42])?;
```

`load_elf` parses and links a single module. For multi-module programs, call
`Vm::parse_module` for each object and `Vm::link` with the set of modules.

Registering a helper again replaces it everywhere: programs linked earlier
pick up the change at their next call, and helper calls themselves take no
lock.

## Plugins

`Vm::load_plugin` links a program behind a lock, and `Vm::export(&plugin, "f")`
publishes its function `f` as a named extern that programs linked afterwards can
import. The call runs in the exporting plugin with its own memory and maps, so
plain pointers mean nothing on the other side. `Plugin::replace` swaps in a new
build, and importers use it from their next call. A call into a plugin that is
already running fails with `VmError::PluginBusy` instead of deadlocking.

An exported function can borrow a buffer from its caller for one call by
tagging the pointer parameter with the index of its length parameter:

```c
#define BORROW(len_arg) __attribute__((btf_decl_tag("borrow:" #len_arg)))
#define BORROW_RO(len_arg) __attribute__((btf_decl_tag("borrow_ro:" #len_arg)))

u64 sum(const u64 *buf BORROW_RO(1), u64 len);
```

The runtime maps the caller's bytes into the callee at a `BORROW_FIRST_REGION`
slot, passes that address instead, and unmaps it when the call returns. A
length that runs past the caller's memory fails the call before the callee
runs.

## Linking

`Vm::link` places code and data sections, resolves relocations between
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
| `MAPS_REGION` (4) | map values | RW |
| `FIRST_FREE_REGION` (5) to 26 | free for the host, `Vm::share_region` | - |
| `BORROW_FIRST_REGION` (27) to 31 | buffers borrowed during a plugin call | per tag |
| `SHARED_MAPS_FIRST_REGION` (32) to 63 | shared maps, one region each | RW |

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

Not implemented: kfunc BTF ID resolution, and the legacy packet access modes
`BPF_ABS` and `BPF_IND`, which return `Flow::Missing`.

Helpers that touch host state are off by default. `Vm::enable_time` adds
`ktime_get_ns` (5), `Vm::enable_random` adds `get_prandom_u32` (7), and
`Vm::enable_print(sink)` adds `trace_printk` (6), passing each line to `sink`.
A program that calls a helper the host didn't enable fails to link.

Maps: array and hash maps declared libbpf style in `.maps` (`__uint(type, ...)`,
`__type(key, ...)`, `__type(value, ...)`, `max_entries`). Helpers 1 to 3
(`map_lookup_elem`, `map_update_elem`, `map_delete_elem`) are built in unless the
host registers its own under those IDs. Values live in `MAPS_REGION`, so a looked
up pointer is an ordinary guest address. The host reads and writes maps through
`Program::map(name)`.

`Vm::share_map(name, pad_values)` makes maps of that name one instance across
every program the VM links afterwards, at the same guest address in each. The
first program to declare it creates it, and a later declaration with a
different layout fails the link. `pad_values` puts each value on its own cache
line. The call is `unsafe`: programs running on different threads at the same
time may only touch shared values with atomics.

`Vm::share_region(region, len, perms)` allocates a buffer and maps it at region
`region` (between `FIRST_FREE_REGION` and `BORROW_FIRST_REGION`) into every
program linked afterwards, so plugins can pass plain pointers into it. The host
reaches the same bytes through `SharedRegion::buffer`. It has the same `unsafe`
contract as `share_map`.

Atomics (`BPF_ATOMIC` add, or, and, xor with and without fetch, xchg and
cmpxchg, 32 and 64 bit) go through `Memory::atomic_u32` and
`Memory::atomic_u64`. `VmMemory` uses real host atomics and faults on
misaligned addresses; the trait's default is a plain load and store.
