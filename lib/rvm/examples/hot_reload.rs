//! Hot reload: loads a plugin, runs it, replaces its program while the host keeps using it, and checks what the reload
//! kept and what it replaced.
//!
//! `bpf/examples/counter.c` counts hits per id in the map `totals`. The VM shares that map, so it belongs to the VM
//! and not to a program. Version 2 of the plugin counts in steps of 10.
//!
//! - Function handles follow the reload: the handles looked up before it call version 2 afterwards.
//! - The shared map keeps every total, and version 2 continues from them.
//! - A global of the program does not survive: version 2 starts with its own.
//!
//! Every check fails the example with its own message. Rebuild the plugin with the CMake project in the repo root.
//!
//! Run with: cargo run -p rvm --example hot_reload

use std::error::Error;

use rvm::{Plugin, PluginFunc, ValueSpacing, Vm};

const V1: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/counter.o"));
const V2: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/counter_v2.o"));

type Check = Result<(), Box<dyn Error>>;

fn main() -> Check {
    let vm = Vm::new();
    // SAFETY: the plugin only runs on this thread.
    unsafe { vm.share_map("totals", ValueSpacing::Packed) };

    let plugin = Plugin::new("counter", vm.load_elf(V1)?);
    // looked up once, used on both sides of the reload
    let counter = Counter {
        version: plugin.func("version")?,
        hit: plugin.func("hit")?,
        calls_seen: plugin.func("calls_seen")?,
    };

    version_1_counts(&plugin, &counter)?;

    plugin.replace(vm.load_elf(V2)?)?;
    println!("reloaded");

    handles_follow_the_reload(&counter)?;
    totals_survive_the_reload(&plugin)?;
    version_2_continues_the_totals(&plugin, &counter)?;
    globals_start_over(&counter)?;

    println!("hot reload kept the handles and the shared map");
    Ok(())
}

/// The plugin's functions, as handles that stay valid when the plugin's program is replaced.
struct Counter {
    version: PluginFunc,
    hit: PluginFunc,
    calls_seen: PluginFunc,
}

fn version_1_counts(plugin: &Plugin, counter: &Counter) -> Check {
    expect("version before the reload", counter.version.call(&[])?, 1)?;

    for id in [1, 2, 2] {
        counter.hit.call(&[id])?;
    }

    expect("calls version 1 has seen", counter.calls_seen.call(&[])?, 3)?;
    expect_totals("totals from version 1", plugin, &[(1, 1), (2, 2)])
}

fn handles_follow_the_reload(counter: &Counter) -> Check {
    expect("version through the old handle", counter.version.call(&[])?, 2)
}

fn totals_survive_the_reload(plugin: &Plugin) -> Check {
    expect_totals("totals right after the reload", plugin, &[(1, 1), (2, 2)])
}

fn version_2_continues_the_totals(plugin: &Plugin, counter: &Counter) -> Check {
    expect("id 1 after a hit from version 2", counter.hit.call(&[1])?, 11)?;
    expect("id 2 after a hit from version 2", counter.hit.call(&[2])?, 12)?;
    expect("a new id from version 2", counter.hit.call(&[3])?, 10)?;

    expect_totals("totals from both versions", plugin, &[(1, 11), (2, 12), (3, 10)])
}

fn globals_start_over(counter: &Counter) -> Check {
    // five hits ran in total, three of them in version 2
    expect("calls version 2 has seen", counter.calls_seen.call(&[])?, 3)
}

fn expect(what: &str, got: u64, want: u64) -> Check {
    if got != want {
        return Err(format!("{what}: got {got}, expected {want}").into());
    }
    println!("{what}: {got}");
    Ok(())
}

/// Compares the whole `totals` map, read from the host, with `want`.
fn expect_totals(what: &str, plugin: &Plugin, want: &[(u32, u64)]) -> Check {
    let mut program = plugin.lock()?;
    let totals = program.map("totals")?;
    let mut got: Vec<(u32, u64)> = totals.entries().iter_as()?.collect();
    got.sort_unstable();

    if got != want {
        return Err(format!("{what}: got {got:?}, expected {want:?}").into());
    }
    println!("{what}: {got:?}");
    Ok(())
}
