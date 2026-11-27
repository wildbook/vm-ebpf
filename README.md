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
clang -target bpf -mcpu=v4 -O2 -g -fno-slp-vectorize -c plugin.c -o plugin.o
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

Plugins are relocatable eBPF ELF objects as `clang -target bpf -mcpu=v4 -O2 -g -fno-slp-vectorize` writes them. rvm
needs clang 23.1.6 or newer and follows its calling convention; the objects in this repository are built with clang
23.1.6. No custom toolchain, SDK build or post-processing step is needed. A plugin can have globals (`.data`, `.bss`,
`.rodata`), static functions, function pointers, `switch` statements that clang turns into jump tables, and libbpf
style maps. Its non-static functions are the ones the host can call, by name. `-g` emits the BTF that maps, CO-RE
and borrowed buffers need, and lets the linker check the registers of each host function.
[`bpf/rvm_bpf.h`](bpf/rvm_bpf.h) has the integer types, the map declaration macros, the borrow tags and the built-in
helpers; the plugins under [`bpf/examples/`](bpf/examples) use it.

About the compiler:

- Clang 22 and older return small structs by another convention, so rvm fails the load of their objects with
  `LinkError::UnsupportedCompiler`. It reads the compiler from the debug strings that `-g` writes. An object stripped
  of them says nothing of its compiler and loads. `rvm_bpf.h` stops the compilation under an older clang.
- `-fno-slp-vectorize` avoids a crash of clang 23.1 in BPF instruction selection (`BPF DAG->DAG Pattern Instruction
  Selection`), on a signed vector division that its SLP vectorizer forms from scalar divisions. The BPF target has
  no vector instructions, so the flag loses nothing.
- For calls with more than five arguments, declare a plugin function's sixth and later integer parameters as `int` or
  wider, not `char` or `short`; see [What plugins can use](#what-plugins-can-use).

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

A host function takes `()`, one integer, or a tuple of up to twelve `u64` (calls by helper ID pass five), and returns
`()`, an integer, `bool`, a `(u64, u64)` or a `Result` of one of these. The `_with_memory` variants also get the calling
plugin's memory. Every read and write through it copies, needs the same permissions as the plugin's own loads and
stores, and returns a `MemoryError` for a pointer the plugin could not use itself. An `Err` from a host function fails
the plugin call with `HostError::Failed`. To give the plugin an error code instead, return it as an integer.

A struct or union that the C declaration passes or returns by value travels in registers, as clang 23 lays it out,
and the host function takes and returns those registers:

| C type | as a parameter | as the result |
|---|---|---|
| integer, enum, pointer, struct of up to 8 bytes | one argument, the first byte in the lowest bits | r0: the function returns an integer |
| struct of 9 to 16 bytes, `__int128` | two arguments, bytes 0 to 7 first | r0 and r2: the function returns `(u64, u64)`, bytes 0 to 7 first |
| struct of more than 16 bytes | clang rejects the call | memory: the plugin passes the address for the result as the first argument, ahead of the parameters |
| empty struct | no argument | nothing |

```rust
// C: struct size { u64 width, height; };  extern struct size window_size(u64 window);
vm.register_extern("window_size", |window: u64| (800u64, 600u64));
```

Loading fails when a plugin uses a name or helper ID that the host has not registered, when the C declaration of an
extern passes a different number of registers than the host function takes, and when one of the two returns in r0
and r2 and the other in r0 alone. A missing host function is a load error, not a crash in the middle of a call.
Registering a function again replaces it, also for plugins loaded earlier, from their next call.

The host decides what a plugin can reach. The only built-in helpers are the map helpers. `Vm::enable_time`,
`Vm::enable_random` and `Vm::enable_print` add `bpf_ktime_get_ns`, `bpf_get_prandom_u32` and `bpf_trace_printk`.

### Native functions

A native function is a plain function pointer that the interpreter calls directly, in the host C convention (Windows x64
on Windows, System V AMD64 on Unix). A call from a plugin loop costs 18 host instructions without arguments and 31 with
one, against 38 and 50 for a host function from `register_extern`; a pointer argument that rvm checks adds about 30. The
plugin declares a native as an `extern` like any host function, and the host registers it with its signature, which says
which arguments are pointers to plugin memory and how many bytes each covers:

```c
extern u64 checksum(const u8 *buf BORROW_RO(1), u64 len);
```

```rust
use rvm::{NativeArg, NativeSig};

unsafe extern "C" fn checksum(buf: *const u8, len: u64) -> u64 {
    // ...
}

const CHECKSUM: NativeSig = NativeSig::new(&[NativeArg::Read(Some(2)), NativeArg::Int]);
// SAFETY: checksum reads only the `len` bytes at `buf`, never unwinds, and runs on any thread
unsafe { vm.register_native("checksum", checksum as *const (), CHECKSUM)? };
// all integers: NativeSig::ints(3)
```

Loading checks the plugin's declaration against the signature: the same number of arguments, pointers in the same
places, and a `BORROW` tag, where there is one, on the same length argument. Structs and unions of 1, 2, 4 or 8 bytes
pass as integers. The declaration may return nothing, an integer, a pointer, or a struct of 1, 2, 4 or 8 bytes, which
returns in rax. Loading fails for a struct of another size. A prepared image records each import's BTF prototype (and
any `IMPORT_FROM` tag) without requiring externs to be registered during `prepare_elf`, and checks it at load time.
Before each call, rvm checks every pointer the signature declares against the plugin's memory, one byte or as many as
its length argument says, with the plugin's read or write permission, and the native gets the host address of the
bytes. A bad pointer stops the plugin call with `ExecError::MemoryFault`. With `Passthrough::untagged()` arguments
arrive unchanged and unchecked.

For externs not registered ahead of time, `Vm::set_native_resolver` (or `rvm_options.resolve` in `rvmrt`) asks a host
callback once per unresolved import name at load time and caches the result in the VM. A plugin can tag an extern with
`IMPORT_FROM("user32.dll")` or `IMPORT_FROM("ucrtbase.dll!strlen")` from `rvm_bpf.h` to pass a DLL name and optional
symbol override to the resolver. When the resolver returns a `NativeSig`, loading checks the plugin's prototype and
checks pointer bounds as for `register_native`. When it returns `sig: None`, the plugin's prototype decides which
arguments are pointers, and rvm strips their region tags in tagged programs without bounds checks. Without BTF,
arguments pass unchanged through the native trampoline.

Taking the address of a declared extern (`&host_fn`, in code or in `.rodata`/`.data` tables) produces a callable token
that dispatches through the import's bound target without requiring `RawCalls::on()`. With the `ffi` Cargo feature
enabled, resolver-bound natives (and variadic natives registered with `NativeSig::variadic`) also support structs of 3,
5, 6, 7 and 9 to 16 bytes by value, struct returns of any size, `float` and `double` arguments and returns, and
variadic calls.

Pointers stored inside plugin memory, such as the fields of a struct the plugin fills, keep the plugin's region tag,
and native code can't follow them. Either load the plugin with `Passthrough::untagged()`, where every pointer is a
plain host address and nothing is checked, or declare those pointers `__host` and convert with `HOST()` from
`rvm_bpf.h`:

```c
struct iovec { const u8 __host *base; u64 len; };
struct iovec part = { HOST(text), 5 };
```

The compiler rejects a plain pointer where a `__host` pointer is expected, so it finds every conversion site. A pointer
that a native returns is a host address; declare it `__host` to dereference it when it points into the plugin's own
memory in any mode, or into host memory with `Passthrough::on()`.

Registration is unsafe: the native must take exactly the signature's arguments (up to twelve), never unwind (no panic,
C++ exception or `longjmp`), stay loaded while plugins may call it, be safe on any thread, and treat its integer
arguments and the bytes behind its pointers as untrusted. Native time doesn't count against the instruction limit, a
native can't fail the plugin call, and one that calls back into the same plugin gets `VmError::PluginBusy`. Use
`register_extern` where you need any of those. `rvm_load_with` does the same for the C library.
[`lib/rvm/examples/natives.rs`](lib/rvm/examples/natives.rs) calls natives on integers and buffers (including a
seven-argument call with a checked buffer on the stack) and follows a returned pointer.

### Passing data

A call passes up to twelve `u64` arguments and returns a `u64`. For more data, the host maps memory into the plugin and
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
plugin, with its own memory and maps, and passes up to twelve arguments. A pointer parameter tagged with `BORROW(n)` or
`BORROW_RO(n)` lends the caller's buffer to the callee for that one call, where argument `n` holds the length in bytes,
whether in a register or on the stack. The callee reads and writes the caller's bytes in place, without a copy:

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

The caller of an exported function gets r0, which holds a result of up to 8 bytes, and so does the host from
`call`. A plugin that declares an import with a struct of 9 to 16 bytes as the result fails to load. A struct of
more than 16 bytes comes back through a pointer into the caller's memory, which the callee can follow only if both
plugins are loaded untagged.

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

A `Loader` picks the mode for one plugin, and the VM's mode stays the default:

```rust
// SAFETY: this plugin may read and write any memory of this process
let untagged = unsafe { Passthrough::untagged() };
let trusted = vm.loader().passthrough(untagged).load_elf(&object)?;
let checked = vm.load_elf(&other)?;
```

Plugins of different modes work in one VM. Calls between them, borrowed buffers and shared maps give each side
addresses of its own mode. A pointer that a plugin stores in shared memory is an address of its own mode, so only
plugins of the same mode can follow it, and `SharedRegion::base_for(mode)` is a shared region's address for a mode
other than the VM's.

### Function pointers to native code

A plugin can call native code that it only holds a pointer to: a table of functions in a host struct, a callback it
got as an argument, the result of a lookup. The host allows it with `RawCalls::on()`, for the VM in
`VmConfig::raw_calls` or for one plugin:

```c
struct host_api {
    u64 (*version)(void);
    void (*log)(const char *text, u64 len);
};

u64 run(const struct host_api *api) {
    api->log("hello", 5);
    return api->version();
}
```

```rust
// SAFETY: the plugin is as trusted as native code; it reads `API` and calls the functions in it
let (untagged, raw_calls) = unsafe { (Passthrough::untagged(), RawCalls::on()) };
let mut plugin = vm.loader().passthrough(untagged).raw_calls(raw_calls).load_elf(&object)?;
plugin.call("run", &[&raw const API as u64])?;
```

A call through a pointer that holds an address without a region tag, from 64 KiB up, then calls the function at that
address in the host C convention, with five arguments (or twelve in a program that stores a stack argument anywhere),
and the plugin gets what the function leaves in rax. Register arguments also go to xmm registers (xmm0 to xmm3 on
Windows x64, xmm0 to xmm4 or xmm5 on System V AMD64), where a function reads `float` and `double` parameters and a
variadic function reads its copies. Pointers to the plugin's own functions and helper IDs below 64 KiB work as before.
Without the switch, such a call fails with `ExecError::BadCodeAddress`, or with `ExecError::UnknownHelper` if the
address fits 32 bits.

Nothing declares what such a call passes, so each argument arrives as the register holds it, without a check or a
conversion. A pointer into plugin memory keeps its region tag, which native code can't follow: load the plugin with
`Passthrough::untagged()`, or declare the parameter `__host` and pass `HOST(p)` from `rvm_bpf.h`. For an address that
the plugin holds as a constant, use `NATIVE_AT(type, addr)` from the same header, because clang compiles a call through
a constant address as a helper call and keeps only the low 32 bits of the address.

The switch makes the plugin as trusted as native code, whatever its memory mode. It can call any address in the
process with any arguments, nothing validates the target, and a call through a pointer that is no function runs
whatever bytes are there. The function must not unwind, its time doesn't count against the instruction limit, and
one that calls back into the plugin that called it gets `VmError::PluginBusy`. A call through a pointer costs about
45 host instructions more than a call of a native function that the plugin declares as an `extern`, so declare the
functions it calls often. [`lib/rvm/examples/vtable.rs`](lib/rvm/examples/vtable.rs) runs a plugin against a table
of host functions.

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
`rvm_function_name` list the functions. The C library is smaller in scope than the Rust API. Its only host functions
are the native functions passed to `rvm_load_with`, and it has no maps, so images that import any other host
function or declare a map fail to load. Each call is limited to 1,000,000
instructions, unless the library is built with `--no-default-features`, which drops its `fuel` feature and the limit.
A panic inside the library ends the process.

`rvm_load_with` takes an `rvm_options`: the native functions, and the flags `RVM_RAW_POINTERS`, `RVM_UNTAGGED` and
`RVM_RAW_CALLS` for `Passthrough::on()`, `Passthrough::untagged()` and `RawCalls::on()`, under the same contracts. A
plugin loaded untagged and with raw calls takes a host struct as it is and calls the function pointers in it:

```c
static const struct host_api api = {version, log_line};

rvm_options options = {.size = sizeof options, .flags = RVM_UNTAGGED | RVM_RAW_CALLS};
if (rvm_load_with(image, image_len, &options, &program) != RVM_OK)
    return 1;

uint64_t args[1] = {(uint64_t)&api}, result;
rvm_status status = rvm_call(program, "run", 3, args, 1, &result);
```

Built with `cargo build --profile embedded` in `lib/rvmrt`, on x86-64 Windows:

| build | `rvmrt.dll` | added to a C host by `rvmrt.lib` |
|---|---|---|
| default | 115,200 bytes, 24 imports from 3 DLLs | 105,984 bytes, 7 imports |
| without `fuel` | 96,256 bytes, 24 imports from 3 DLLs | 87,040 bytes, 7 imports |

The 7 imports of the static library are the process heap functions, `memcmp`, `memmove` and `memset`. The build
rebuilds the standard library for size, which needs the `rust-src` component.

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
stops the call, unless the host turns on raw calls, which let an indirect call reach native code. Calls nest at most
8 deep, with a 512-byte stack frame each by default (`VmConfig::frame_size`).

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
- `VmMemory::map_host`, `Vm::share_map`, `Vm::share_region`, the raw host pointer modes and raw calls are unsafe and
  depend on their documented contracts. With raw host pointers or raw calls, a plugin is as trusted as native code.
- A plugin's pointers hold host addresses, so a plugin learns the layout that address randomization hides.

## What plugins can use

rvm implements the eBPF instruction set of [RFC 9669](https://www.rfc-editor.org/rfc/rfc9669.html) up to clang's
`-mcpu=v4`: 32 and 64-bit arithmetic, signed division and modulo, sign extension, byte swaps, BPF-to-BPF calls and the
32 and 64-bit atomic operations. It also runs these Linux extensions:

- Load-acquire and store-release (Linux 6.15).
- Function pointers (`callx`). A pointer can also be a helper ID, as in libbpf's `(void *)BPF_FUNC_*` declarations.
- Jump tables (`gotox`), which clang emits for dense `switch` statements.
- `may_goto` (libbpf's `can_loop`). It never jumps; use the instruction limit to bound loops.

Not supported: the legacy packet loads (`BPF_ABS`, `BPF_IND`), kfunc calls by BTF ID, and map types other than array
and hash.

A call passes up to twelve arguments: the first five in registers and up to seven more on the stack, as clang 23
compiles a call with more than five, and returns up to 16 bytes. Each argument is an integer, a pointer, or half of a 9
to 16-byte struct; a thirteenth argument fails the load with `LinkError::StackArguments`, or with
`LinkError::TooManyRegisters` on a host extern. A call through a helper ID passes five. eBPF has no floating point
instructions, and clang rejects code that needs them.

Clang 23.1 miscompiles `char` and `short` parameters past the fifth argument between a plugin's own functions: a caller
passing a negative constant or forwarding a narrow parameter stores it with only its low 32 bits extended, and the
callee reads all 64 bits. Declare a plugin function's sixth and later integer parameters as `int` or wider (`int` and
`u32` are extended by the callee). Host and native functions read narrow arguments from the low bits. The fix,
[llvm/llvm-project#238315](https://github.com/llvm/llvm-project/commit/0fdfbb6f05), is on LLVM's main branch and in no
23.x release.

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
| (`default-features = false`) | loads prepared images and runs them | 82 KiB |
| `link` | the ELF reader, BTF, CO-RE and the linker: `Vm::load_elf`, `Vm::prepare_elf`, `Vm::with_types` | 94 KiB |
| `fuel` | instruction limits | 18 KiB |
| `maps` | maps, the map helpers, `Vm::share_map` and `Pod` | 28 KiB |

The size column is what rvm adds to a small Rust host on x86-64 Windows, built with the workspace's `embedded`
profile (`cargo build --profile embedded`), which also strips symbols and panic locations. Without `maps`, an image
that declares maps fails to load. `fixed-hash-seed` makes hash maps use a fixed seed, for benchmarks.

## Limitations

- rvm is an interpreter. Compute-bound plugins run about 15 to 30 times slower than native code; there is no JIT.
- rvm is developed and measured on x86-64 Windows. System V AMD64 native calls and Linux LA57 raw addresses are
  implemented for x86-64 Unix, but not regularly tested on Unix hardware.
- It needs nightly Rust.
- Plugins are limited by eBPF: twelve arguments per call (five in registers and seven on the stack), no floating point,
  a 512-byte stack frame and 8 nested calls.
- A plugin runs one call at a time. Calls from several threads into the same plugin fail with
  `VmError::PluginBusy`; load one program per thread to run them in parallel.
- A struct of 9 to 16 bytes comes back in two registers, which only a host function from `register_extern` returns.
  Native functions, the functions that plugins export and calls from the host carry r0.
- Native functions use the host x86-64 C convention (Windows x64 on Windows, System V AMD64 on Unix). They take
  integers and pointers and return integers, pointers and structs of 1, 2, 4 or 8 bytes: no struct parameters, no floats
  and no variadic functions. They run unmetered.
- A call through a function pointer to native code has no signature. It passes five registers as they are, plus the
  seven stack slots in a program that stores any: pointers keep their region tags, a struct by value passes and comes
  back only if it is 1, 2, 4 or 8 bytes long, and a `float` or `double` result is lost. Nothing validates the target,
  and Control Flow Guard doesn't check the call.
- Images are tied to the rvm version that wrote them. Relink them when you update rvm.
- The C library runs prepared images only, without maps and without host functions other than natives.
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
cargo run -p rvm --example natives      # native functions on integers and buffers, and a returned host pointer
cargo run -p rvm --example vtable       # a plugin that calls the host through a table of function pointers
```

The plugins under [`bpf/`](bpf) are checked in compiled, under `bpf/prebuilt/`, so cargo doesn't need clang. After you
change a C source or header, rebuild them with clang 23.1.6 or newer, Ninja and CMake 3.21 or later. `BPF_CLANG`
names a clang other than the one on `PATH`:

```bash
cmake --preset bpf -DBPF_CLANG="C:/Program Files/LLVM/bin/clang.exe"
cmake --build --preset bpf
cmake --build --preset update-prebuilt   # copies the objects into bpf/prebuilt/
```

The configuration fails for an older clang. A build directory keeps the compiler of its first configuration, so
after you install or name another one, configure with `cmake --fresh --preset bpf`. `cargo test` fails when the
sources or the CMake files changed and the objects were not rebuilt.

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
MIRIFLAGS=-Zmiri-disable-isolation cargo miri test -p rvm --test integration --test conformance --target x86_64-unknown-linux-gnu -- --test-threads=1
```

`cargo bench -p rvm --bench exec` and `--bench workloads` run the benchmarks. To compare two versions, build both with
`fixed-hash-seed` from the same checkout path, since the path changes how the code is laid out.
