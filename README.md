# rvm

rvm is an eBPF runtime that a program embeds to run plugins. You write the plugins in C, or in anything else that
clang's BPF target compiles, and build them with a stock clang into ordinary eBPF object files. The host loads them,
gives them the host functions they may call, and calls their functions. rvm is for plugin layers and modding
frameworks inside a host process: small, fast to call in both directions, and isolated from the host's memory. It is a
Rust library, with a C library for hosts in other languages. It runs plugins in an interpreter and has no JIT.

## Example

A plugin that calls a host function:

```c
// plugin.c
typedef unsigned long long u64;

extern u64 host_add(u64 a, u64 b);

u64 run(u64 x) {
    return host_add(x, 1);
}
```

```bash
clang -target bpf -mcpu=v4 -O2 -g -c plugin.c -o plugin.o
```

A host that loads it:

```toml
[dependencies]
rvm = { git = "https://github.com/wildbook/vm-ebpf" }
```

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vm = rvm::Vm::new();
    vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);

    let mut plugin = vm.load_elf(&std::fs::read("plugin.o")?)?;
    println!("{}", plugin.call("run", &[41])?); // 42
    Ok(())
}
```

rvm needs nightly Rust; [`rust-toolchain.toml`](rust-toolchain.toml) pins the channel.

## Features

### Plugins are C compiled by clang

Plugins are relocatable eBPF ELF objects as `clang -target bpf -mcpu=v4 -O2 -g` writes them; the objects in this
repository are built with clang 22. No custom toolchain, SDK build or post-processing step is needed. A plugin can
have globals (`.data`, `.bss`, `.rodata`), static functions, function pointers, `switch` statements that clang turns
into jump tables, and libbpf style maps. Its non-static functions are the ones the host can call, by name. `-g` emits
the BTF that maps, CO-RE and borrowed buffers need, and lets the linker check the argument count of each host
function. [`bpf/rvm_bpf.h`](bpf/rvm_bpf.h) has the integer types, the map declaration macros, the borrow tags and the
built-in helpers; the plugins under [`bpf/examples/`](bpf/examples) use it.

### Host functions

A plugin calls host functions that the host registers, either by name or by numeric helper ID:

```rust
// C: extern u64 host_add(u64 a, u64 b);
vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);

// C: static u64 (*double_it)(u64) = (void *)100;
vm.register_helper(100, |x: u64| x * 2);

// C: extern void print(const char *msg, u64 len);
vm.register_extern_with_memory("print", |mem, (msg, len): (u64, u64)| {
    let msg = mem.read_vec(msg, len as usize)?;
    println!("{}", String::from_utf8_lossy(&msg));
    Ok::<_, rvm::MemoryError>(())
});
```

A host function takes `()`, one integer, or a tuple of up to five `u64`, and returns `()`, an integer, `bool` or a
`Result` of one. The `_with_memory` variants also get the calling plugin's memory. Every read and write through it
copies, needs the same permissions as the plugin's own loads and stores, and returns a `MemoryError` for a pointer the
plugin could not use itself. An `Err` from a host function fails the plugin call with `HostError::Failed`. To give the
plugin an error code instead, return it as an integer.

Loading fails when a plugin uses a name or helper ID that the host has not registered, or when the C declaration of
an extern passes a different number of registers than the host function takes: a struct of 9 to 16 bytes passes two,
and a struct return passes the result's address first. A missing host function is a load error, not a crash in the
middle of a call. Registering a function again replaces it, also for plugins loaded earlier, from their next call.

The host decides what a plugin can reach. The only built-in helpers are the map helpers. `Vm::enable_time`,
`Vm::enable_random` and `Vm::enable_print` add `bpf_ktime_get_ns`, `bpf_get_prandom_u32` and `bpf_trace_printk`.

### Passing data

Arguments and return values are up to five `u64` values. For more data, the host maps memory into the plugin and
passes its address:

```rust
use rvm::Perms;

let input = program.memory_mut().map_bytes(bytes, bytes.len(), Perms::R)?;
program.call("parse", &[input.base(), bytes.len() as u64])?;
program.memory_mut().unmap(input)?;
```

`map` maps zeroed memory, `map_bytes` copies a slice in, and the unsafe `map_host` maps host memory in place, which
must stay valid while it is mapped. The host reads and writes plugin memory with `read`, `write`, `read_bytes` and
`write_bytes`.

### Plugins calling plugins

A `Plugin` wraps a loaded program so that other plugins can call it. `Vm::export` publishes one of its functions under
its name, and plugins loaded afterwards declare it as an `extern` like a host function. The call runs in the exporting
plugin, with its own memory and maps. A pointer parameter tagged with `BORROW(n)` or `BORROW_RO(n)` lends the caller's
buffer to the callee for that one call, where argument `n` holds the length in bytes. The callee reads and writes the
caller's bytes in place, without a copy:

```c
// math.c
u64 sum(const u64 *values BORROW_RO(1), u64 len) {
    u64 total = 0;
    for (u64 i = 0; i < len / sizeof(u64); i++)
        total += values[i];
    return total;
}

// game.c
extern u64 sum(const u64 *values, u64 len);

u64 score(void) {
    u64 values[3] = {1, 2, 3};
    return sum(values, sizeof(values));
}
```

```rust
use rvm::Plugin;

let math = Plugin::new("math", vm.load_elf(&math_o)?);
vm.export(&math, "sum")?;

let game = Plugin::new("game", vm.load_elf(&game_o)?);
let score = game.func("score")?;
assert_eq!(score.call(&[])?, 6);
```

A plugin runs one call at a time. A call into a plugin that is already running, from another thread or from a chain of
calls that comes back to it, fails with `VmError::PluginBusy` instead of blocking. When the call came through another
plugin's import, the error reaches the host as `HostError::Plugin`, which names the export.

### Maps and shared memory

Plugins declare array and hash maps the way libbpf programs do, and use them through `bpf_map_lookup_elem`,
`bpf_map_update_elem` and `bpf_map_delete_elem`:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u64);
} hits SEC(".maps");
```

The host reads and writes the same map as bytes or as types that implement `rvm::Pod` (bytemuck's `Pod`):

```rust
let hits = program.map("hits")?;
let count: Option<u64> = hits.get_as(7u32)?;
for (id, count) in hits.entries().iter_as::<u32, u64>()? {
    println!("{id}: {count}");
}
```

`Vm::share_map(name, spacing)` makes every map of that name one instance for all plugins loaded afterwards, at the
same address in each. `Vm::share_region(len, perms)` does the same for a plain buffer, which the host reads and writes
through the returned `SharedRegion`, with atomic operations on `u32` and `u64` values. Both calls are unsafe: plugins
on different threads may only touch the same values with atomic instructions, and the host's copies count as plain
loads and stores.

### Hot reload

`Plugin::replace` swaps in a new build of a plugin while the host keeps using it. Function handles from
`Plugin::func` and exports to other plugins find their functions in the new build at their next call. Shared maps and
regions belong to the `Vm`, so they keep their contents. The plugin's own globals and unshared maps start over:

```rust
use rvm::{Plugin, ValueSpacing};

// SAFETY: the plugin runs on this thread only.
unsafe { vm.share_map("hits", ValueSpacing::Packed) };

let counter = Plugin::new("counter", vm.load_elf(&v1)?);
let hit = counter.func("hit")?;
hit.call(&[1])?;

counter.replace(vm.load_elf(&v2)?)?;
hit.call(&[1])?; // runs version 2, which sees the hit from version 1
```

[`lib/rvm/examples/hot_reload.rs`](lib/rvm/examples/hot_reload.rs) checks what a reload keeps and what it replaces.

### CO-RE: host struct layouts can change

A plugin compiled against one layout of a host struct keeps working when the host reorders, resizes or adds fields.
Field accesses in a struct declared with `preserve_access_index` carry CO-RE relocations, and the linker patches them
to the layout that the host describes, as the Linux kernel does with its own types:

```c
struct entity {
    u32 id;
    s32 hp;
} __attribute__((preserve_access_index));

s64 heal(struct entity *e, s64 amount) {
    e->hp += amount;
    return e->hp;
}
```

```rust
#[repr(C)]
struct Entity {
    name: [u8; 16],
    hp: i32,
    id: u32,
}

vm.with_types(|types| rvm::host_struct!(types, Entity as "entity" { id, hp }));
```

Here `heal` reads `hp` at offset 16, where the host has it. A plugin can test whether a field exists with
`__builtin_preserve_field_info` and get the host's struct size with `__builtin_preserve_type_info`. An access to a field
that the host does not describe fails when it runs. `HostTypes` (from `Vm::with_types`) also builds BTF by hand, for
layouts without a Rust struct.

### Raw host pointers

By default a plugin reaches only memory the host maps for it, and any other address faults. A host whose plugins
should follow its own pointers, for example the pointer fields of a struct the plugin reads through CO-RE, opts in
when it creates the `Vm`:

```rust
let vm = Vm::with_config(VmConfig {
    // SAFETY: the plugins may read and write any memory of this process
    passthrough: unsafe { Passthrough::on() },
    ..VmConfig::default()
})?;
plugin.call("walk", &[&raw const scene as u64])?;
```

`VmConfig::passthrough` has three modes:

| mode | plugin pointers into its own memory | other addresses |
|---|---|---|
| `Passthrough::OFF` (default) | checked against their region | fault |
| `Passthrough::on()` | checked against their region | from 64 KiB up, read and written directly |
| `Passthrough::untagged()` | plain host addresses, unchecked | from 64 KiB up, read and written directly |

With either of the unsafe modes, a plugin can read and write any memory of the process it can name, as native code
can; addresses below 64 KiB still fault, so a null pointer stops the call. Pass pointers as integers with `as`, which
keeps Rust's provenance rules satisfied. Host functions that take `GuestMemory` and the map helpers accept the same
pointers the plugin can use. [`lib/rvm/examples/passthrough.rs`](lib/rvm/examples/passthrough.rs) walks a host list
through pointer fields and shows the faults of each mode.

### Prepared images

A host does not need the ELF parser and linker at run time. `Vm::prepare_elf` links a plugin ahead of time, for
example in a build script, into an `Image`. `Image::to_bytes` serializes it, and `Vm::load_image_bytes` loads it into
any `Vm` that registers the same host functions:

```rust
// at build time
let image = linker_vm.prepare_elf(&elf)?.to_bytes();

// at run time, with rvm built without the `link` feature
let mut plugin = vm.load_image_bytes(&image)?;
```

An image loads only into the rvm version that wrote it. `Vm::load_image` also takes an `Image` built by hand around
raw bytecode. [`bin/emu`](bin/emu) ships its plugin this way.

### C library

[`lib/rvmrt`](lib/rvmrt) builds rvm as `rvmrt.dll` and a static `rvmrt.lib` that load prepared images.
[`rvmrt.h`](lib/rvmrt/include/rvmrt.h) declares the functions:

```c
rvm_program *program;
if (rvm_load(image, image_len, &program) != RVM_OK)
    return 1;

uint64_t values[3] = {1, 2, 3}, addr, total;
rvm_map(program, sizeof(values), &addr);
rvm_write(program, addr, (const uint8_t *)values, sizeof(values));

uint64_t args[2] = {addr, sizeof(values)};
rvm_status status = rvm_call(program, "sum", 3, args, 2, &total);
rvm_free(program);
```

`rvm_func` looks a function up once and `rvm_call_func` calls it by index; `rvm_function_count` and
`rvm_function_name` list the functions. The C library is smaller in scope than the Rust API. It has no host functions
and no maps, so images that import a host function or declare a map fail to load. Each call is limited to 1,000,000
instructions, unless the library is built without `fuel`. A panic inside the library ends the process.

Built with `cargo build --profile embedded` in `lib/rvmrt`, on x86-64 Windows:

| build | `rvmrt.dll` | added to a C host by `rvmrt.lib` |
|---|---|---|
| default | 103,424 bytes, 31 imports from 3 DLLs | 96,256 bytes, 8 imports |
| without `fuel` | 84,480 bytes, 31 imports from 3 DLLs | 76,800 bytes, 8 imports |

The 8 imports of the static library are the process heap functions, `memcmp`, `memmove`, `GetCurrentProcess` and
`TerminateProcess`. The build rebuilds the standard library for size, which needs the `rust-src` component.

### Instruction limits

By default a call runs until it returns. A host that runs plugins it does not trust to terminate sets a limit:

```rust
use rvm::{ExecError, Vm, VmConfig, VmError};

let vm = Vm::with_config(VmConfig {
    instruction_limit: 1_000_000,
    ..VmConfig::default()
})?;
// ...
match plugin.call("run", &[41]) {
    Err(VmError::Exec(ExecError::InstructionLimit { .. })) => println!("ran too long"),
    result => println!("{result:?}"),
}
```

The count is exact and covers the instructions that other plugins run for the call. `Program::call_func_with_limit` and
`PluginFunc::call_with_limit` give one call its own limit and return a `LimitedCall` with the number of instructions it
ran. A call with a limit took up to about 15% more time on the benchmarks below; a call without one costs the same as
in a build without the `fuel` feature. Without that feature, a non-zero limit fails with `VmError::FuelNotEnabled`.

## Isolation and threat model

Each program has its own guest memory: a 64-bit address is a host address with a region tag in its top bits. The
stack, the read-only data, the writable data, the maps and every buffer the host maps are separate regions, each with a
length and read and write permissions. The interpreter checks every load and store against the region its tag names
and stops the call with `ExecError::MemoryFault` when an access falls outside. Addresses without a tag are never mapped
unless the host turns on raw host pointers, so null pointers fault. The code itself is outside guest memory: a plugin
can't read or change it, and a jump, indirect call or jump table entry that leads outside the program's instructions
stops the call. Calls nest at most 8 deep, with a 512-byte stack frame each by default (`VmConfig::frame_size`).

A plugin can reach only what the host gives it: the host functions it registers, the memory it maps, and the maps and
regions it shares. Another plugin's memory is visible only through a borrowed buffer, for the duration of one call.
Memory a program allocates for its stack, data and maps is limited by `VmConfig::memory_limit` (256 MiB by default),
checked before allocation.

Untrusted input that rvm validates:

- Prepared images: loading checks every length, index and map definition, so images may come from untrusted files.
- Bytecode: an invalid or reserved instruction stops the call with an error when it runs.
- ELF objects: the ELF reader checks every offset and length against the file.

Limits of the model:

- There is no verifier. rvm doesn't reject programs ahead of time as the Linux kernel does; it checks each operation
  when it runs.
- Without an instruction limit, a plugin can loop forever. The limit counts guest instructions only, not time spent
  in host functions.
- Host functions run with the host's full privileges. Their checks are your responsibility; `GuestMemory` only checks
  that a pointer is valid for the plugin.
- rvm has no mitigations for side channels such as Spectre.
- `VmMemory::map_host`, `Vm::share_map`, `Vm::share_region` and the raw host pointer modes are unsafe and depend on
  their documented contracts.
- A plugin's pointers hold host addresses, so a plugin learns the layout that address randomization hides.

## What plugins can use

rvm implements the eBPF instruction set of [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html) up to clang's
`-mcpu=v4`: 32 and 64-bit arithmetic, signed division and modulo, sign extension, byte swaps, BPF-to-BPF calls and the
32 and 64-bit atomic operations. It also runs these Linux extensions:

- Load-acquire and store-release (Linux 6.15).
- Function pointers (`callx`). A pointer can also be a helper ID, as in libbpf's `(void *)BPF_FUNC_*` declarations.
- Jump tables (`gotox`), which clang 22 emits for dense `switch` statements.
- `may_goto` (libbpf's `can_loop`). It never jumps; use the instruction limit to bound loops.

Not supported: the legacy packet loads (`BPF_ABS`, `BPF_IND`), kfunc calls by BTF ID, and map types other than array
and hash.

The eBPF calling convention applies to plugins too: functions take at most five arguments, all integers or pointers,
and return one. eBPF has no floating point instructions. clang rejects code that breaks either rule.

## Performance

Measured on one machine: an AMD Ryzen 5 5625U (Zen 3) at about 4.15 GHz, on Windows 11, with rvm at commit e6cb1ca.
Each runtime ran the same C code, compiled with clang 22 to eBPF or wasm32, or an equivalent Lua script; the cycle
counts come from hardware performance counters. Sieve and Permute are from the Are We Fast Yet suite and Gimli is the
Gimli permutation from Sightglass. Differences below about 15% are within noise: two rvm builds that run the same
host instructions differed by up to 17% in cycles, from code placement alone.

| runtime | Sieve | Permute | Gimli | call into plugin | call to host |
|---|---:|---:|---:|---:|---:|
| native, clang -O2 | 1.0 | 1.0 | 1.0 | 6 | 3 |
| **rvm** | **16.6** | **16.9** | **28.4** | **24** | **7** |
| **rvm, with an instruction limit** | **18.5** | **14.9** | **27.8** | | |
| wasm3 (28ecb9a) | 18.2 | 14.7 | 23.1 | 95 | 6\* |
| wasmi 2.0.0 | 12.9 | 14.1 | 22.3 | 170 | 68 |
| uBPF interpreter (261fd2a0) | 122.0 | 77.9 | 174.0 | 70 | 46 |
| Lua 5.4.9 | 37.6 | 38.2 | 118.8 | 109 | 66 |
| LuaJIT 2.1, interpreter | 26.3 | 28.2 | 86.4 | 49 | 27 |
| Luau 0.747, interpreter | 41.7 | 24.3 | 79.5 | 116 | 68 |
| uBPF JIT | 2.2 | 1.4 | 2.7 | | |
| LuaJIT 2.1, JIT | 4.0 | 4.2 | 3.3 | 66 | 53 (FFI: 2) |
| Luau 0.747, native code | 28.9 | 12.3 | 8.5 | 130 | 67 |

The kernel columns are CPU cycles per run as a multiple of native. The call columns are CPU cycles per call with one
integer argument: from the host into an empty plugin function (`PluginFunc::call` costs 33), and from a plugin into an
empty host function. With five arguments a call into the plugin costs 27 cycles and a call to the host 29. \*wasm3's
call to the host overlaps with its loop in a way that makes its cycle count too low; it runs 96 host instructions per
call against rvm's 48. The benchmark harness is not part of this repository.

The interpreter is generic code that the compiler inlines into rvm. Build rvm at `opt-level = 3` even when the rest of
the host optimizes for size; at `opt-level = "s"` plugins run 17% to 24% slower:

```toml
[profile.release.package.rvm]
opt-level = 3
```

## Cargo features

`link`, `fuel` and `maps` are on by default.

| feature | what it adds | size |
|---|---|---:|
| (`default-features = false`) | loads prepared images and runs them | 75 KB |
| `link` | the ELF reader, BTF, CO-RE and the linker: `Vm::load_elf`, `Vm::prepare_elf`, `Vm::with_types` | 87 KB |
| `fuel` | instruction limits | 19 KB |
| `maps` | maps, the map helpers, `Vm::share_map` and `Pod` | 20 KB |

The size column is what rvm adds to a small Rust host on x86-64 Windows, built with the workspace's `embedded`
profile (`cargo build --profile embedded`), which also strips symbols and panic locations. Without `maps`, an image
that declares maps fails to load. `fixed-hash-seed` makes hash maps use a fixed seed, for benchmarks.

## Limitations

- rvm is an interpreter. Compute-bound plugins run about 15 to 30 times slower than native code; there is no JIT.
- rvm is developed and measured on x86-64 Windows only.
- It needs nightly Rust.
- Plugins are limited by eBPF: five integer arguments per function, no floating point, a 512-byte stack frame and 8
  nested calls.
- A plugin runs one call at a time. Calls from several threads into the same plugin fail with
  `VmError::PluginBusy`; load one program per thread to run them in parallel.
- Images are tied to the rvm version that wrote them. Relink them when you update rvm.
- The C library runs prepared images only, without host functions, maps or raw host pointers.
- rvm is not published on crates.io.

## Building and development

```bash
cargo build --release
cargo test
cargo run --bin loader                  # loads bpf/prebuilt/examples/example.o and calls its functions
cargo run --bin emu                     # the same plugin as an image prepared at build time
cargo run -p rvm --example hot_reload   # replaces a running plugin and checks what the reload kept
cargo run -p rvm --example modding      # a game with two mod plugins: CO-RE, exports, borrows, shared maps, reload
cargo run -p rvm --example msgpack_logs # a MessagePack parser plugin that fills maps
cargo run -p rvm --example core_reloc   # one plugin against two layouts of a host struct
cargo run -p rvm --example hello        # hand-assembled bytecode loaded as an Image, without ELF
cargo run -p rvm --example passthrough  # a plugin that follows pointers in host structs, and the faults around them
```

The plugins under [`bpf/`](bpf) are checked in compiled, under `bpf/prebuilt/`, so cargo doesn't need clang. After you
change a C source or header, rebuild them with clang, Ninja and CMake 3.21 or later:

```bash
cmake --preset bpf && cmake --build --preset bpf
cmake --build --preset update-prebuilt   # copies the objects into bpf/prebuilt/
```

`cargo test` fails when the sources changed and the objects were not rebuilt.

The crates:

- [`lib/rvm`](lib/rvm): the runtime.
- [`lib/rvm-core`](lib/rvm-core): the instruction set and the interpreter.
- [`lib/btf`](lib/btf): BTF parsing and building, and CO-RE relocation.
- [`lib/constelf`](lib/constelf): the ELF reader.
- [`lib/ebpf-asm`](lib/ebpf-asm): an eBPF assembler and disassembler, for tests and examples.
- [`lib/rvmrt`](lib/rvmrt): the C library.

The module documentation describes the internals: the guest memory layout in
[`lib/rvm/src/layout.rs`](lib/rvm/src/layout.rs), the image format in [`lib/rvm/src/image.rs`](lib/rvm/src/image.rs),
and how the interpreter prepares and runs code in [`lib/rvm-core/src/lib.rs`](lib/rvm-core/src/lib.rs). The
`conformance` test target runs the [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) suite. Miri
checks the unsafe memory code; the tests that list fixture directories run under Miri only as Linux:

```bash
cargo miri test -p rvm-core
cargo miri test -p rvm --lib
MIRIFLAGS=-Zmiri-disable-isolation cargo miri test -p rvm --test integration --test conformance --target x86_64-unknown-linux-gnu
```

`cargo bench -p rvm --bench exec` and `--bench workloads` run the benchmarks. To compare two versions, build both with
`fixed-hash-seed` from the same checkout path, since the path changes how the code is laid out.
