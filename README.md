# vm-ebpf

rvm, an embeddable eBPF runtime for Rust. It links eBPF ELF objects against
host functions, runs them in bounds-checked guest memory, and runs them as
plugins that call each other and share maps. Needs nightly (pinned in
`rust-toolchain.toml`).

```bash
cargo build --release
cargo run --bin loader                         # loads and calls bpf/prebuilt/examples/example.o
cargo run --bin emu                            # runs the same object, prepared into an image at build time
cargo run -p rvm --example modding             # game mods as plugins: CO-RE, exports, borrows, shared maps, hot reload
cargo run -p rvm --example hot_reload          # replaces a running plugin and checks what the reload kept
cargo run -p rvm --example msgpack_logs        # streams MessagePack logs through a parser plugin into maps
cargo run -p rvm --example core_reloc          # one object against two struct layouts
cargo run -p rvm --example hello               # hand-assembled bytecode with host helpers, loaded as an Image, no ELF
```

The eBPF objects are built from the C sources under `bpf/` (`examples/`, `bench/`, `corpus/`, `tests/`) and checked in
under `bpf/prebuilt/`. Rebuilding them needs clang, Ninja and CMake 3.21 or later on `PATH`; `CMakeLists.txt` sets the
clang flags:

```bash
cmake --preset bpf && cmake --build --preset bpf
cmake --build --preset update-prebuilt         # copies the built objects into bpf/prebuilt/
```

`update-prebuilt` also records the hashes of the sources, headers and CMake files in `bpf/prebuilt/inputs.sha256`,
and `cargo test` fails when they change without a rebuild.

## Crates

- `lib/rvm-core`: the instruction set and an `Interpreter` for it over a
  `Memory` and a `Host` trait. `Code::new` prepares bytecode for it: it decodes
  each instruction once and fuses common sequences into superinstructions. A
  run returns a `Stop` whose `Reason` says why execution stopped: exit, an
  indirect call or jump, a declined host call, an invalid or unsupported
  instruction, a memory fault, a `pc` outside the code, a call stack overflow,
  or out of fuel.
- `lib/rvm`: the runtime: ELF loading, linking, guest memory, helpers, maps and
  plugins.
- `lib/btf`: BTF parsing, `BtfBuilder` and CO-RE relocations.
- `lib/constelf`: a `const fn` ELF reader for the linker.
- `lib/ebpf-asm`: an assembler and disassembler for writing bytecode in Rust,
  used by tests, benches and examples.
- `lib/rvmrt`: rvm as a C library that runs prepared images (see
  [C library](#c-library)).
- `bin/loader`, `bin/emu`: the programs above.

## Features and profiles

rvm's features are described in [`lib/rvm/Cargo.toml`](lib/rvm/Cargo.toml).

With the `fuel` feature (on by default), a call that runs more than
`VmConfig::instruction_limit` instructions fails with
`ExecError::InstructionLimit`. The default limit is 0, which means no limit;
`rvm::DEFAULT_INSTRUCTION_LIMIT` (1,000,000) is there for hosts that want one.
`Program::call_func_with_limit` gives one call a limit of its own and reports
how many instructions it ran. The count is exact: the interpreter charges a
basic block's instructions as it enters the block, and runs a block the fuel
can't pay for one instruction at a time. A call without a limit counts
nothing: it runs the same code as in a build without the feature, and its
program holds no data for the count. The first call with a limit computes the
block lengths of the program, 8 bytes per instruction. In the benchmarks, guest
code with a limit ran 1% to 12% more host instructions than without one and
took up to about 10% longer; a workload of indirect calls took 15% longer, and
a call of an empty function 15 instructions more.

Without the feature the interpreter doesn't count instructions. The API is the
same in both builds, but a non-zero limit in `Vm::with_config` or
`Program::call_func_with_limit` fails with `VmError::FuelNotEnabled`.

The `release` profile optimizes for size but builds rvm at `opt-level = 3`,
because the interpreter inlines into rvm. The `embedded` profile
(`cargo build --profile embedded`) also strips symbols and panic locations and
shortens `Debug` output to type names, for the smallest host binary.

## Using the runtime

```rust
use rvm::Vm;

let vm = Vm::new();

// Numeric helper, called from the guest via `call <id>`, under an ID that no
// standard helper (`rvm::BPF_FUNC_*`) uses.
vm.register_helper(100, |x: u64| x * 2);

// Named extern, imported by the guest as `extern u64 host_add(u64, u64);`.
vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);

// Named extern that reads guest memory: `extern void log(const char *, u64);`.
vm.register_extern_with_memory("log", |mem, (msg, len): (u64, u64)| {
    println!("{}", String::from_utf8_lossy(&mem.read_vec(msg, len as usize)?));
    Ok::<_, rvm::MemoryError>(())
});

let mut program = vm.load_elf(&elf_bytes)?;
let result = program.call("run", &[42])?;
```

Helpers and externs are the same host functions under two kinds of key, and
each kind registers in two shapes: `register_helper` and `register_extern` take
the arguments, `register_helper_with_memory` and `register_extern_with_memory`
also get the calling program's memory as a `GuestMemory`. Its reads and writes
copy, need the same permissions as the guest's own loads and stores, and return
a `MemoryError` for a pointer the guest couldn't use. A host function that
returns `Err` fails the guest call with `HostError::Failed`, which holds the
error; any error type that converts into `Box<dyn Error + Send + Sync>` works.
To give the guest an error code instead, return it as an `i64`.

Registering a host function again replaces it everywhere: programs linked
earlier use the new one from their next call.

Helpers that touch host state are opt-in: `Vm::enable_time` adds `ktime_get_ns`,
`Vm::enable_random` adds `get_prandom_u32`, and `Vm::enable_print(sink)` adds
`trace_printk`, passing each line to `sink`. `rvm::BPF_FUNC_*` holds their IDs,
and `bpf/rvm_bpf.h` declares them for C.

## Linking

`load_elf` parses and links one object. For several, call `Module::from_elf` for
each and `Vm::load_modules` with the set. The linker places code and data sections,
resolves relocations between modules, and applies CO-RE relocations; loading
binds each call to a numeric helper or named extern. Linking fails if a named
extern has no matching helper or module export, or if a helper ID isn't
registered. It also fails if an extern's argument count in the module's BTF
differs from the arity of the host function registered under that name; exports
from plugins and variadic prototypes aren't checked. Calls with more than five
arguments fail with `VmError::TooManyArgs`. The only call resolved at run
time is `callx` to a helper ID, which fails with `ExecError::UnknownHelper` if
no helper has that ID.

## CO-RE

Field accesses compiled with `preserve_access_index` carry CO-RE relocations,
which the linker patches to the host's struct layouts as kernel CO-RE does
against kernel BTF. The host describes its layouts in `Vm::with_types`, whose
`HostTypes` is a `BtfBuilder`, or derives one from a `#[repr(C)]` struct; a Rust
type is described once however often it is added:

```rust
vm.with_types(|types| rvm::host_struct!(types, Entity as "entity" { id, hp, pos as "position" }));
```

## Prepared images

`Vm::prepare_elf(&elf)` (or `Vm::prepare_modules`) links ahead of time and returns an
`rvm::Image`: the final code, initial data, map declarations, exports and the
calls to bind. `Image::to_bytes` serializes it, and
`Vm::load_image_bytes(&bytes)` loads it into any VM that registers the same
externs and helper IDs. An image loads only into the rvm version that wrote it.
Loading checks every length, index and map definition, so images may come from
untrusted files. `Vm::load_image` takes an `Image`, including one built by hand
around raw bytecode, whose `call <id>` instructions reach the helpers
registered under those IDs. A
host that ships images can build rvm without `link`, and without `maps` if its
images declare none, as `bin/emu` does (see
[`bin/emu/Cargo.toml`](bin/emu/Cargo.toml)).

## C library

`lib/rvmrt` builds rvm, with the features that
[`lib/rvmrt/Cargo.toml`](lib/rvmrt/Cargo.toml) selects, as `rvmrt.dll` and a
static `rvmrt.lib`. `lib/rvmrt/include/rvmrt.h` declares its
functions: `rvm_load` loads a prepared image, `rvm_map` maps zeroed guest
memory and returns its address, `rvm_unmap` unmaps the memory at such an
address, `rvm_write` and `rvm_read` copy bytes into
and out of guest memory where the guest itself may write or read them,
`rvm_call` calls a function by name, and `rvm_free` frees the program.
Functions also have indices, in name order: `rvm_function_count` and
`rvm_function_name` list them, `rvm_func` finds a name's index once, and
`rvm_call_func` calls by index without the name lookup, which saves about 15 ns
per call. Errors come back as `rvm_status` codes. The runtime has no helpers,
its instruction limit is `rvm::DEFAULT_INSTRUCTION_LIMIT` and its memory limit
`rvm::DEFAULT_MEMORY_LIMIT`; an image that declares maps fails with
`RVM_ERR_LINK`.

```bash
cd lib/rvmrt
cargo build --profile embedded    # target/x86_64-pc-windows-msvc/embedded/rvmrt.{dll,dll.lib,lib}
cargo rustc --profile embedded --crate-type staticlib -- --print native-static-libs   # system libraries for rvmrt.lib
```

`lib/rvmrt/.cargo/config.toml` applies only to builds started in `lib/rvmrt`. It
rebuilds std with `optimize_for_size`, which needs the `rust-src` component, and
makes panics trap: a panic inside the library ends the host process at once,
without a message. A build from the workspace root uses the prebuilt std and
prints the panic message before it aborts.

Sizes on x86_64 Windows with the embedded profile. The C host reads the image
file and calls `bpf_main`, built with clang-cl `-O1 -MD`. Without the calls into
rvmrt it is 9,216 bytes with 44 imports.

| build | `rvmrt.dll` | added to the C host by `rvmrt.lib` |
|---|---|---|
| in `lib/rvmrt` | 103,424 B, 31 imports from 3 DLLs | 96,256 B, 8 imports |
| at the root | 189,440 B, 58 imports from 6 DLLs | 182,272 B, 33 imports |
| in `lib/rvmrt`, without `fuel` | 84,480 B, 31 imports from 3 DLLs | 76,800 B, 8 imports |
| at the root, without `fuel` | 169,984 B, 58 imports from 6 DLLs | 162,816 B, 33 imports |

The rows without `fuel` drop the feature from `lib/rvmrt/Cargo.toml` and the
instruction limit from the runtime's configuration. The 8 imports are the
process heap (`GetProcessHeap`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`),
`memcmp`, `memmove`, and `GetCurrentProcess` with `TerminateProcess` for aborts.

## Plugins

`Plugin::new(name, program)` puts a loaded program behind a lock, and
`Vm::export(&plugin, "f")`
publishes its function `f` as a named extern for programs linked afterwards. The
call runs in the exporting plugin with its own memory and maps, so plain
pointers mean nothing on the other side. `Plugin::replace` swaps in a new build,
which importers use from their next call. `Plugin::func` returns a handle that
looks the function up again in the new build. A plugin runs one call at a time:
calling into it, or replacing it, while a call runs fails with
`VmError::PluginBusy` instead of blocking. When the call comes through another
plugin's import, the importer's caller gets `HostError::Plugin`, which names
the export and wraps the inner `VmError`.

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
| 5 to 26 | host regions: `VmMemory::map`, `Vm::share_region` | per mapping |
| `BORROW_FIRST_REGION` (27) to 31 | buffers borrowed during a plugin call | per tag |
| `SHARED_MAPS_FIRST_REGION` (32) to 63 | shared maps, one region each | RW |
| `CODE_REGION` (64) | code addresses, never mapped | - |

The host maps memory into a program with `VmMemory::map` (zeroed) or
`VmMemory::map_bytes` (initialized from a slice), through
`Program::memory_mut`. The unsafe `VmMemory::map_host` maps existing host
memory, which must outlive the mapping. Each returns a `Region` handle at a
free host region; `Region::base` is its guest address, and `VmMemory::unmap`
takes the handle back and frees the region. The other regions belong to the
program and the runtime, and no call maps over them. A mapping fails with
`VmError::NoFreeRegion` once every host region is taken, and an unmap with
`VmError::ForeignRegion` when the handle comes from another program, such as
the one a `Plugin::replace` swapped out.

`Vm::share_region(len, perms)` maps one buffer at a free host region, at the
same address in every program linked afterwards, so plugins can pass plain
pointers into it. Programs linked afterwards map their own memory around it.
The host accesses it through the returned `SharedRegion`: `read_bytes`,
`write_bytes`, `read` and `write` copy, and `atomic_u32`/`atomic_u64` are real
atomics. The call is unsafe: guests on different threads may only touch the
same values with atomics, and against them host copies count as plain loads
and stores. `VmMemory::bytes` and `bytes_mut` refuse shared regions, since other
programs may write them during the borrow; `VmMemory::read_bytes` copies instead.

## Maps

Array and hash maps are declared libbpf style in `.maps` (`__uint(type, ...)`,
`__type(key, ...)`, `__type(value, ...)`, `max_entries`). The map helpers
(`map_lookup_elem`, `map_update_elem`, `map_delete_elem`) are built in unless the
host registers its own under their IDs. Values live in `MAPS_REGION`, or in
their own region for a shared map, so a looked up pointer is an ordinary guest
address.

The host reaches a map through `Program::map(name)`, as bytes (`get`, `update`,
`delete`) or as `Pod` types (`get_as`, `update_as`). `get` borrows the value
and refuses shared maps; `get_as` copies. `MapRef::entries` iterates without
allocating: every element of an array map, or the present keys of a hash map.
For a shared hash map it holds the key index read-locked until dropped.
`rvm::Pod` is bytemuck's trait; a host struct gets it from
`#[derive(Clone, Copy, Pod, Zeroable)]` with bytemuck's `derive` feature, which
checks at compile time that the struct is `#[repr(C)]` plain data without
padding.

`Vm::share_map(name, spacing)` makes maps of that name one instance across
every program linked afterwards, at the same guest address in each. The first
program to declare it creates it, and a later declaration with a different
layout fails the link. `ValueSpacing::CacheLine` puts each value on its own
cache line, and `ValueSpacing::Packed` aligns each to 8 bytes. It has the same
unsafe contract as `share_region`.

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
- `may_goto` (libbpf's `can_loop`, Linux 6.9) never jumps. The kernel jumps
  once a loop's budget runs out; rvm bounds loops with the instruction limit
  instead.

Not implemented: kfunc BTF ID resolution, and the legacy packet access modes
`BPF_ABS` and `BPF_IND`, which stop with `Reason::Unsupported`.

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
