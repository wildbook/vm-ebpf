//! Hands a plugin real host pointers. The host owns a linked list of `#[repr(C)]` nodes whose `next` and `name` fields
//! are raw pointers to other host objects. In a VM with passthrough on, `bpf/examples/passthrough.c` walks the list
//! through those pointers: it reads the nodes and their names, counts a visit on each node, and adds to the scene's
//! walk counter with an atomic. The host describes both structs with `host_struct!`, and the plugin declares them with
//! another field order, so CO-RE patches each field access to the host's layout.
//!
//! Then the example checks that the addresses passthrough doesn't cover still fault: null, the first 64 KiB, an address
//! past the end of a mapped region, the host pointer under that region's tag, and the host pointer in a VM without
//! passthrough. Exits with an error when a check fails.
//!
//! Run with: cargo run -p rvm --example passthrough

use std::error::Error;
use std::ffi::CStr;
use std::fmt::Debug;
use std::mem::offset_of;
use std::{array, ptr};

use rvm::{ExecError, HostTypes, MemoryError, Passthrough, Perms, Program, Vm, VmConfig, VmError};

const OBJECT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/passthrough.o"));

/// The name and value of each node, in list order.
const NODES: [(&CStr, i64); 3] = [(c"ant", 10), (c"bee", -3), (c"cat", 25)];
const WALKS: u32 = 2;

/// `struct scene` in `bpf/examples/passthrough.c`, which declares `head` first.
#[repr(C)]
struct Scene {
    walks: u64,
    head: *mut Node,
}

/// `struct node` in `bpf/examples/passthrough.c`, which declares the fields in reverse order and has no `id`.
#[repr(C)]
struct Node {
    id: u32,
    visits: u32,
    value: i64,
    name: *const u8,
    next: *mut Node,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut nodes: [Node; NODES.len()] = array::from_fn(|i| {
        let (name, value) = NODES[i];
        Node {
            id: i as u32,
            visits: 0,
            value,
            name: name.as_ptr().cast(),
            next: ptr::null_mut(),
        }
    });
    let mut scene = Scene {
        walks: 0,
        head: link(&mut nodes),
    };
    // `as` exposes the provenance of the pointer the plugin gets as its argument
    let scene_addr = (&raw mut scene) as u64;

    // SAFETY: the plugin only reaches `scene`, `nodes` and the names, which outlive its calls, and the host holds no
    // references to them while it runs.
    let vm = Vm::with_config(VmConfig {
        passthrough: unsafe { Passthrough::on() },
        ..Default::default()
    })?;
    vm.with_types(describe);
    let mut program = vm.load_elf(OBJECT)?;

    println!("--- walking the host's list ---");
    walk(&mut program, scene_addr)?;
    check_writes(&scene, &nodes)?;

    println!("\n--- faults ---");
    check_raw_faults(&mut program)?;
    check_region_faults(&mut program, scene_addr)?;
    check_passthrough_off(scene_addr)?;
    Ok(())
}

/// Describes the host's structs to CO-RE. Pointer fields become `void *`, which CO-RE relocates `struct node *` and
/// `const char *` onto.
fn describe(types: &mut HostTypes) {
    rvm::host_struct!(types, Node as "node" { visits, value, name, next });
    rvm::host_struct!(types, Scene as "scene" { walks, head });
}

/// Links `nodes` into a list in slice order and returns its head.
fn link(nodes: &mut [Node]) -> *mut Node {
    let addrs = nodes.as_mut_ptr();
    let last = nodes.len() - 1;
    for (i, node) in nodes[..last].iter_mut().enumerate() {
        node.next = addrs.wrapping_add(i + 1);
    }

    // The plugin loads `head`, `next` and `name` as plain integers, and the interpreter turns an address back into a
    // pointer with the provenance exposed for it. So expose the names, and the nodes after the last write above.
    for node in nodes.iter() {
        node.name.expose_provenance();
    }
    let head = nodes.as_mut_ptr();
    head.expose_provenance();
    head
}

/// Walks the list `WALKS` times, summing the node values, and reads the first letter of each name.
fn walk(program: &mut Program, scene: u64) -> Result<(), Box<dyn Error>> {
    let sum: i64 = NODES.iter().map(|&(_, value)| value).sum();
    for _ in 0..WALKS {
        check("walk()", program.call("walk", &[scene])? as i64, sum)?;
    }

    let initials: String = NODES.iter().map(|&(name, _)| char::from(name.to_bytes()[0])).collect();
    let letters = program.call("initials", &[scene])?.to_le_bytes();
    let letters: String = letters
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| char::from(b))
        .collect();
    check("initials()", letters, initials)
}

/// Checks the plugin's writes into host memory: a visit on each node per walk, and the walk count.
fn check_writes(scene: &Scene, nodes: &[Node]) -> Result<(), Box<dyn Error>> {
    check("scene.walks", scene.walks, u64::from(WALKS))?;
    for node in nodes {
        let name = NODES[node.id as usize].0.to_str()?;
        check(&format!("node {} ({name}) visits", node.id), node.visits, WALKS)?;
    }
    Ok(())
}

/// Raw addresses below `RAW_START` fault even with passthrough on.
fn check_raw_faults(program: &mut Program) -> Result<(), Box<dyn Error>> {
    expect_fault(program, "null scene", 0)?;
    // `head` still lies below 64 KiB
    expect_fault(program, "scene just below 64 KiB", rvm::RAW_START - 16)
}

/// Tagged addresses keep their region's bounds with passthrough on, even when the low bits are a host address.
fn check_region_faults(program: &mut Program, scene: u64) -> Result<(), Box<dyn Error>> {
    // room for `walks` only, so the load of `head` runs past the region's end
    let short = program.memory_mut().map(size_of::<u64>(), Perms::RW)?;
    expect_fault(program, "scene in a region of 8 bytes", short.base())?;

    let tag = short.base() & (u64::MAX << rvm::REGION_SHIFT);
    expect_fault(program, "host scene under the region's tag", tag | scene)
}

/// Without passthrough, the host's own pointer is an unmapped guest address.
fn check_passthrough_off(scene: u64) -> Result<(), Box<dyn Error>> {
    let vm = Vm::new();
    vm.with_types(describe);
    let mut program = vm.load_elf(OBJECT)?;
    expect_fault(&mut program, "host scene without passthrough", scene)
}

/// Calls `walk` with `scene` and checks that its first load, of `head` at the host's offset, faults.
fn expect_fault(program: &mut Program, case: &str, scene: u64) -> Result<(), Box<dyn Error>> {
    let addr = scene + offset_of!(Scene, head) as u64;
    let expected = MemoryError {
        addr,
        size: size_of::<*mut Node>(),
    };
    match program.call("walk", &[scene]) {
        Err(VmError::Exec(ExecError::MemoryFault { error, .. })) if error == expected => {
            println!("  {case} ({scene:#x}): faults at {addr:#x}");
            Ok(())
        }
        other => Err(format!("{case}: walk({scene:#x}) returned {other:?}, expected a fault at {addr:#x}").into()),
    }
}

fn check<T: PartialEq + Debug>(what: &str, actual: T, expected: T) -> Result<(), Box<dyn Error>> {
    println!("  {what} = {actual:?}");
    if actual != expected {
        return Err(format!("{what} is {actual:?}, expected {expected:?}").into());
    }
    Ok(())
}
