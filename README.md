# vm-ebpf

rvm, an embeddable eBPF runtime for Rust. It links eBPF ELF objects against
host functions, runs them in bounds-checked guest memory, and runs them as
plugins that call each other and share maps. Needs nightly (pinned in
`rust-toolchain.toml`).

```bash
cargo build --release
cargo run --bin loader                         # loads and calls bpf/examples/example.o
cargo run --bin emu                            # runs the same object, prepared into an image at build time
cargo run -p rvm --example modding             # game mods as plugins: CO-RE, exports, borrows, shared maps, hot reload
cargo run -p rvm --example msgpack_logs        # streams MessagePack logs through a parser plugin into maps
cargo run -p rvm --example core_reloc          # one object against two struct layouts
cargo run -p rvm --example hello               # hand-assembled bytecode on a bare Executor
```

The eBPF objects under `bpf/` (`examples/`, `bench/`, `tests/`) are checked in.
`bpf/build.sh` rebuilds them with the clang line in each source file's header,
which needs LLVM 18 or newer for `-mcpu=v4`.

## Crates

- `lib/rvm-core`: the instruction set and interpreter (`run`) over a `Memory`
  and a `Host` trait. `run` returns a `Flow` saying why execution stopped: exit,
  an indirect call or jump, a declined host call, an invalid or unimplemented
  instruction, a memory fault, a `pc` outside the code, a call stack overflow, or
  out of fuel. `Code` fuses common instruction sequences into superinstructions.
- `lib/rvm`: the runtime: ELF loading, linking, guest memory, helpers, maps and
  plugins.
- `lib/btf`: BTF parsing, `BtfBuilder` and CO-RE relocations.
- `lib/constelf`: a `const fn` ELF reader for the linker.
- `lib/ebpf-asm`: an assembler and disassembler for writing bytecode in Rust,
  used by tests, benches and examples.
- `bin/loader`, `bin/emu`: the programs above.

## Features and profiles

rvm's features:

- `link` (default): ELF parsing, BTF, CO-RE and the linker (`Module`,
  `BtfBuilder`, `Vm::types`, `Vm::prepare`, `Vm::load_elf`, `Vm::load_plugin`).
  Without it, rvm loads prepared images only.
- `fuel` (default): enforces `VmConfig::instruction_limit`. Without it the field
  doesn't exist and the interpreter doesn't count instructions.
- `fixed-hash-seed`: guest hash maps use a fixed seed, for reproducible
  benchmarks.

The `release` profile optimizes for size but builds rvm at `opt-level = 3`,
because the interpreter inlines into rvm. The `embedded` profile
(`cargo build --profile embedded`) also strips symbols and panic locations and
shortens `Debug` output to type names, for the smallest host binary.

## Using the runtime

```rust
use rvm::Vm;

let vm = Vm::new();

// Numeric helper, called from the guest via `call <id>`. IDs 1 to 3 are the
// built-in map helpers.
vm.register_helper(100, |x: u64| x * 2);

// Named extern, imported by the guest as `extern u64 host_add(u64, u64);`.
vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);

// Named extern that reads guest memory: `extern void log(const char *, u64);`.
vm.register_fn_with_memory("log", |mem, (msg, len): (u64, u64)| {
    println!("{}", String::from_utf8_lossy(&mem.read_vec(msg, len as usize)?));
    Ok::<_, rvm::MemoryError>(())
});

let mut program = vm.load_elf(&elf_bytes)?;
let result = program.call("run", &[42])?;
```

A `register_fn_with_memory` function gets the calling program's memory as a
`GuestMemory`. Its reads and writes copy, need the same permissions as the
guest's own loads and stores, and return a `MemoryError` for a pointer the guest
couldn't use. A host function that returns `Err` gives the guest -1.

Registering a helper again replaces it everywhere: programs linked earlier use
the new one from their next call.

Helpers that touch host state are opt-in: `Vm::enable_time` adds `ktime_get_ns`
(5), `Vm::enable_random` adds `get_prandom_u32` (7), and `Vm::enable_print(sink)`
adds `trace_printk` (6), passing each line to `sink`.

## Linking

`load_elf` parses and links one object. For several, call `Vm::parse_module` for
each and `Vm::link` with the set. The linker places code and data sections,
resolves relocations between modules, and applies CO-RE relocations; loading
binds each call to a numeric helper or named extern. Linking fails if a named
extern has no matching helper or module export, or if a helper ID isn't
registered. It also fails if an extern's argument count in the module's BTF
differs from the arity of the host function registered under that name; exports
from plugins and variadic prototypes aren't checked. Calls with more than five
arguments fail with `VmError::InvalidArgument`. The only call resolved at run
time is `callx` to a helper ID, which fails with `UnknownHelper` if no helper
has that ID.

## CO-RE

Field accesses compiled with `preserve_access_index` carry CO-RE relocations,
which the linker patches to the host's struct layouts as kernel CO-RE does
against kernel BTF. The host describes its layouts with `Vm::types()`, a
`BtfBuilder`, or derives one from a `#[repr(C)]` struct:

```rust
rvm::host_struct!(vm.types(), Entity as "entity" { id, hp, pos as "position" });
```

## Prepared images

`Vm::prepare(&elf)` (or `Vm::prepare_modules`) links ahead of time and returns an
`rvm::Image`: the final code, initial data, map declarations, exports and the
calls to bind. `Image::to_bytes` serializes it, and `Vm::load_image(&bytes)` or
`Vm::load_plugin_image(name, &bytes)` loads it into any VM that registers the
same externs and helper IDs. An image loads only into the rvm version that wrote
it. Loading checks every length, index and map definition, so images may come
from untrusted files. A host that ships images can build rvm without `link`, as
`bin/emu` does.

## Plugins

`Vm::load_plugin` links a program behind a lock, and `Vm::export(&plugin, "f")`
publishes its function `f` as a named extern for programs linked afterwards. The
call runs in the exporting plugin with its own memory and maps, so plain
pointers mean nothing on the other side. `Plugin::replace` swaps in a new build,
which importers use from their next call. A `Func` from `Plugin::func` fails
after a replace; `Plugin::named_func` looks the function up again in the new
build. A plugin runs one call at a time: calling into it, or replacing it, while
a call runs fails with `VmError::PluginBusy` instead of blocking. When the call
comes through another plugin's import, the importer's caller gets
`HelperError::Plugin`, which names the export and wraps the inner `VmError`.

An export can borrow a buffer from its caller for one call by tagging the
pointer parameter with the index of its length parameter:

```c
#define BORROW(len_arg) __attribute__((btf_decl_tag("borrow:" #len_arg)))
#define BORROW_RO(len_arg) __attribute__((btf_decl_tag("borrow_ro:" #len_arg)))

u64 sum(const u64 *buf BORROW_RO(1), u64 len);
```

The runtime maps the caller's bytes into the callee at a `BORROW_FIRST_REGION`
slot for the duration of the call. A length that runs past the caller's memory
fails the call before the callee runs.

## Guest memory

A guest address is `(region << 32) | offset`. `rvm::VmMemory` has `MAX_REGIONS`
region slots, each with its own byte range and permissions:

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

The host maps its own regions with `VmMemory::map` (zeroed) or
`VmMemory::map_bytes` (initialized from a slice). The unsafe `VmMemory::map_host`
maps existing host memory, which must outlive the mapping.

`Vm::share_region(region, len, perms)` maps one buffer at the same region in
every program linked afterwards, so plugins can pass plain pointers into it.
The host accesses it through the returned `SharedRegion`: `read_bytes`,
`write_bytes`, `read` and `write` copy, and `atomic_u32`/`atomic_u64` are real
atomics. The call is unsafe: guests on different threads may only touch the
same values with atomics, and against them host copies count as plain loads
and stores.

## Maps

Array and hash maps are declared libbpf style in `.maps` (`__uint(type, ...)`,
`__type(key, ...)`, `__type(value, ...)`, `max_entries`). Helpers 1 to 3
(`map_lookup_elem`, `map_update_elem`, `map_delete_elem`) are built in unless the
host registers its own under those IDs. Values live in `MAPS_REGION`, or in
their own region for a shared map, so a looked up pointer is an ordinary guest
address.

The host reaches a map through `Program::map(name)`, as bytes (`get`, `update`,
`delete`) or as `Pod` types (`get_as`, `update_as`). `MapRef::entries` iterates
without allocating: every element of an array map, or the present keys of a
hash map. For a shared hash map it holds the key index read-locked until
dropped.

`Vm::share_map(name, pad_values)` makes maps of that name one instance across
every program linked afterwards, at the same guest address in each. The first
program to declare it creates it, and a later declaration with a different
layout fails the link. `pad_values` puts each value on its own cache line. It
has the same unsafe contract as `share_region`.

## Instruction set

The interpreter covers the ISA up to `-mcpu=v4`, with these details:

- Atomics (add, or, and, xor with and without fetch, xchg, cmpxchg; 32 and 64
  bit) through `Memory::atomic_u32`/`atomic_u64`. `VmMemory` uses host atomics
  and faults on misaligned addresses.
- Load-acquire and store-release (Linux 6.15; all sizes) through
  `Memory::load_acquire_*`/`store_release_*`, with the same rules in `VmMemory`.
- Function pointers. A code address is `region_base(CODE_REGION)` plus a byte
  offset into the program's code, so loads and stores through it fault. The
  linker writes one wherever clang takes a function's address. `callx` faults
  unless its target is an instruction in the program; a target below 2^32 is a
  helper ID, as in libbpf's `(void *)BPF_FUNC_*` declarations.
- Jump tables. Clang 22 lowers a dense `switch` of 13 or more cases to `gotox`
  through `.jumptables`; the linker copies each table into `.rodata` as code
  addresses, and `gotox` checks its target like `callx`.

Not implemented: kfunc BTF ID resolution, and the legacy packet access modes
`BPF_ABS` and `BPF_IND`, which return `Flow::Missing`.

## Tests and benchmarks

```bash
cargo test
cargo test -p rvm --no-default-features --features link
cargo bench -p rvm --bench exec        # interpreter loops from ebpf-asm, map helpers
cargo bench -p rvm --bench workloads   # program and plugin calls, bpf/bench/workloads.c
```

The `conformance` test target runs the vendored
[bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) suite
(`lib/rvm/tests/conformance/`).

Miri checks the unsafe memory code. The integration and conformance tests list
fixture directories, which Miri supports only on Unix targets, so they run as
Linux:

```bash
cargo miri test -p rvm-core
cargo miri test -p rvm --lib
MIRIFLAGS=-Zmiri-disable-isolation cargo miri test -p rvm --test integration --test conformance --target x86_64-unknown-linux-gnu
```

To compare interpreter changes, benchmark plain release builds with
`fixed-hash-seed`, and build both versions from the same checkout path: cargo's
package IDs include the source path, and builds from different directories lay
code out differently.
