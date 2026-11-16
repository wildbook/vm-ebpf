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

Each file's header has its exact build line. Benchmark programs (`workloads.c`,
`map_bench.c`) are built with `-mcpu=v4`, which needs LLVM 18 or newer, so the
numbers reflect clang's current ISA: sign-extending loads, `movsx`, `sdiv`/`smod`,
`bswap` and 32-bit jumps.

## Running

```bash
cargo run --bin loader   # loads and calls bpf/example.o
cargo run --bin demo     # CO-RE relocation walkthrough
cargo run --bin emu      # runs bpf.o, linked into an image at build time
```

## Crates

- `lib/rvm-core`: the instruction set and interpreter loop (`run`, `step`),
  independent of any host integration. Operates on a `Context<M>` over a
  `Memory` trait implementation and returns a `Flow` describing why execution
  stopped (exit, a call, a helper, a fault, or out of fuel).
- `lib/rvm`: the embeddable runtime built on `rvm-core`. Parses ELF objects,
  links them into executable programs, manages guest memory, and dispatches
  helper calls.
- `lib/constelf`: a `const fn` ELF reader used by `rvm`'s linker.
- `lib/btf`: BTF (BPF Type Format) parsing and CO-RE (Compile Once, Run
  Everywhere) relocations. The host describes its actual struct layouts as BTF,
  with `BtfBuilder`; relocations patch field-access instructions compiled
  against a different layout to match, exactly as kernel CO-RE matches a BPF
  program's BTF against the kernel's.
- `lib/ebpf-asm`: an assembler used by `bin/demo`, `lib/rvm`'s tests, benches and
  examples to build eBPF bytecode without a C toolchain. Also has a disassembler,
  used by its own examples and tests for debugging.
- `bin/loader`, `bin/demo`, `bin/emu`: example programs. `loader` shows the
  parse and link API; `demo` shows a CO-RE relocation; `emu` loads an image
  its build script prepares, with rvm built without the linker.

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
modules, records the remaining calls to numeric helper IDs and named externs,
and applies CO-RE relocations. Loading then binds each recorded call to a slot
in the program's extern table. Linking fails if a named extern has no matching
helper or module export, if a numeric helper ID is never registered, or if a
host extern's declared argument count does not match the registered helper's
arity (checked against the module's BTF, when present). There is no late
binding: an unresolved call is a link or load error, not a runtime one.

## Prepared images

`Vm::prepare(&elf)` (or `Vm::prepare_modules`) links ahead of time and returns
an `rvm::Image`: the final code with every relocation applied, the initial data,
map declarations, exported functions and the calls to bind on load.
`Image::to_bytes` serializes it, and `Vm::load_image(&bytes)` or
`Vm::load_plugin_image(name, &bytes)` turns it into a program in any VM that
registers the same externs and helper IDs. Loading binds each extern by name or
ID, allocates memory and maps, and maps the VM's shared maps and regions. An
image loads only into the rvm version that wrote it, and loading checks every
length, index and map definition, so images may come from untrusted files.

The linker sits behind rvm's default `link` feature, together with ELF parsing,
BTF and CO-RE (`Module`, `BtfBuilder`, `Vm::types`, `Vm::prepare`,
`Vm::load_elf`, `Vm::load_plugin`). A host that ships prepared images can depend
on rvm with `default-features = false` and prepare them in a build script or a
separate tool, as `bin/emu` does.

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
| `CODE_REGION` (64) | code addresses, never mapped | - |

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

`lib/rvm/tests/integration/conformance.rs` runs the
[bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) suite, vendored
under `lib/rvm/tests/conformance/`, against the interpreter.

Miri checks the `unsafe` memory code. The integration tests list fixture directories,
which Miri only supports on Unix targets, so they run as Linux (about 8 minutes):

```bash
cargo miri test -p rvm-core
cargo miri test -p rvm --lib
MIRIFLAGS=-Zmiri-disable-isolation cargo miri test -p rvm --test integration --target x86_64-unknown-linux-gnu
```

Without PGO, the interpreter loop's speed depends on where the compiler happens to
place it: one loop alignment flag moves the guest benchmarks by 12-20%. Compare
interpreter changes on PGO builds, where the layout follows the profile and the same
flag moves them by under 4%. Collect a profile for each version being compared, since
a profile only matches the code it was recorded on (needs `cargo install cargo-pgo`
and `rustup component add llvm-tools-preview`):

```bash
cargo pgo bench -- -p rvm --bench workloads --bench exec -- --profile-time 2
cargo pgo optimize bench -- -p rvm --bench workloads
```

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

Function pointers: a code address is `region_base(CODE_REGION)` plus a byte
offset into the linked program's code, so loads and stores through it fault.
The linker writes one wherever clang takes a function's address (`lddw` and
pointers in `.data` or `.rodata`). `callx` (`call` with the register bit set,
target in `dst_reg`) calls one with a new stack frame, and faults unless the
target is an instruction in the program. A target below 2^32 is a helper ID
instead, matching libbpf's `(void *)BPF_FUNC_*` helper declarations. Clang 22
at `-mcpu=v4` lowers a dense `switch` of 13 or more cases to `gotox` through a
`.jumptables` table; the linker copies each table into `.rodata` as code
addresses, and `gotox` checks its target the same way.
