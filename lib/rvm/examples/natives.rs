//! Gives a plugin native functions, which the interpreter calls directly in the Windows x64 convention:
//! `bpf/examples/natives.c` mixes integers, upper-cases a buffer on its stack in place and checksums it, and follows a
//! pointer to a host struct that a native returns. The VM checks each buffer against the guest's memory before the
//! native gets its host address, and runs with passthrough on so that the guest can read through the returned
//! pointer. Without passthrough that read faults, which the example checks too.
//!
//! Run with: cargo run -p rvm --example natives

use std::error::Error;

use rvm::{ExecError, NativeArg, NativeSig, Passthrough, Vm, VmConfig, VmError};

const OBJECT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/natives.o"));

/// `struct config` in `bpf/examples/natives.c`.
#[repr(C)]
struct Config {
    version: u32,
    scale: u32,
}

static CONFIG: Config = Config { version: 1, scale: 7 };

extern "win64" fn mix(a: u64, b: u64, c: u64) -> u64 {
    a.wrapping_mul(b) ^ c
}

/// # Safety
///
/// `buf` must point to `len` readable bytes, or `len` be 0.
unsafe extern "win64" fn checksum(buf: *const u8, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    bytes
        .iter()
        .fold(0, |sum: u64, &b| sum.wrapping_mul(31).wrapping_add(b.into()))
}

/// # Safety
///
/// `buf` must point to `len` writable bytes, or `len` be 0.
unsafe extern "win64" fn upper(buf: *mut u8, len: u64) -> u64 {
    if len == 0 {
        return 0;
    }
    unsafe { std::slice::from_raw_parts_mut(buf, len as usize) }.make_ascii_uppercase();
    0
}

extern "win64" fn host_config() -> u64 {
    // `as` exposes the provenance of the pointer the guest reads through
    (&raw const CONFIG) as u64
}

const NATIVES: [(&str, *const (), NativeSig); 4] = [
    ("mix", mix as *const (), NativeSig::ints(3)),
    ("checksum", checksum as *const (), NativeSig::new(&[NativeArg::Read(Some(2)), NativeArg::Int])),
    ("upper", upper as *const (), NativeSig::new(&[NativeArg::Write(Some(2)), NativeArg::Int])),
    ("host_config", host_config as *const (), NativeSig::ints(0)),
];

fn main() -> Result<(), Box<dyn Error>> {
    // SAFETY: the guest reads only `CONFIG` through a raw pointer
    let passthrough = unsafe { Passthrough::on() };
    let mut program = native_vm(passthrough)?.load_elf(OBJECT)?;

    let mixed = program.call("mixed", &[5])?;
    println!("mixed(5) = {mixed}");
    expect("mixed", mixed, mix(5, 6, 7))?;

    let shouted = program.call("shout", &[])?;
    println!("shout() = {shouted:#x}");
    // SAFETY: the bytes of a live string
    expect("shout", shouted, unsafe { checksum(b"HELLO, NATIVES".as_ptr(), 14) })?;

    let scaled = program.call("scaled", &[6])?;
    println!("scaled(6) = {scaled} (config version {})", CONFIG.version);
    expect("scaled", scaled, 42)?;

    let mut off = native_vm(Passthrough::OFF)?.load_elf(OBJECT)?;
    match off.call("scaled", &[6]) {
        Err(VmError::Exec(ExecError::MemoryFault { error, .. })) => {
            println!("without passthrough, the returned pointer faults: {error}");
            Ok(())
        }
        other => Err(format!("scaled without passthrough: expected a memory fault, got {other:?}").into()),
    }
}

/// A VM with the natives of `bpf/examples/natives.c`.
fn native_vm(passthrough: Passthrough) -> Result<Vm, VmError> {
    let config = VmConfig {
        passthrough,
        ..VmConfig::default()
    };
    // SAFETY: each native takes its signature's arguments in the Windows x64 convention, never unwinds, keeps to the
    // bytes the checks of its buffer cover, and is safe on any thread.
    unsafe { Vm::with_natives(config, &NATIVES) }
}

fn expect(func: &str, got: u64, want: u64) -> Result<(), String> {
    match got == want {
        true => Ok(()),
        false => Err(format!("{func}: got {got}, want {want}")),
    }
}
