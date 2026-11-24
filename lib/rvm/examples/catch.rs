//! Catches what a plugin's mistakes raise on Windows. `bpf/examples/catch.c` passes a native function a pointer the
//! function can't read, and reads through a raw host pointer that isn't mapped. With `VmConfig::catch`, each mistake
//! fails the plugin's call with an error and the host carries on; without it, each would end the process.
//!
//! The native function is the C runtime's `strlen`, in a system DLL. The catch covers a native function outside the
//! executable or DLL that holds rvm, which a function of this example would not be.
//!
//! Run with: cargo run -p rvm --features seh --example catch

use std::error::Error;
use std::ffi::{c_char, c_void};

use rvm::{Catch, ExecError, NativeSig, Passthrough, Program, Vm, VmConfig, VmError};

const OBJECT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/catch.o"));

/// `struct item` in `bpf/examples/catch.c`.
#[repr(C)]
struct Item {
    price: u64,
    label: *const c_char,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleA(name: *const c_char) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *const ();
    fn VirtualAlloc(addr: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut program = catching_vm()?.load_elf(OBJECT)?;

    let good = Item {
        price: 250,
        label: c"lantern".as_ptr(),
    };
    // a label that points nowhere, as a plugin gets from a stale or corrupt item
    let bad = Item {
        price: 100,
        label: 0x10 as *const c_char,
    };
    // `as` exposes the provenance of the pointers the guest reads through
    let (good, bad) = (&raw const good as u64, &raw const bad as u64);

    let len = program.call("label_len", &[good])?;
    println!("label_len(good item) = {len}");
    expect("label_len", len, 7)?;

    match program.call("label_len", &[bad]) {
        Err(VmError::Exec(ExecError::NativeException {
            native, code, address, ..
        })) => {
            println!("label_len(bad item): {native} raised exception {code:#x} at {address:#x}");
            expect("exception code", code.into(), 0xC000_0005)?;
        }
        other => return Err(format!("label_len of a bad label: expected an exception, got {other:?}").into()),
    }

    // an item that was never there: reserved address space without memory
    let missing = reserve()?;
    match program.call("price", &[missing]) {
        Err(VmError::Exec(ExecError::MemoryFault { pc, error })) => {
            println!("price(missing item): memory fault at instruction {pc}: {error}");
            expect("fault address", error.addr, missing)?;
        }
        other => return Err(format!("price of a missing item: expected a memory fault, got {other:?}").into()),
    }

    // the host and the plugin carry on
    call_again(&mut program, good)
}

/// A VM that catches both kinds of fault, with passthrough on, so that the guest follows host pointers.
fn catching_vm() -> Result<Vm, Box<dyn Error>> {
    let config = VmConfig {
        // SAFETY: the guest reads the items it is given, and `catch` covers the ones that aren't there
        passthrough: unsafe { Passthrough::on() },
        catch: Catch::ALL,
        ..VmConfig::default()
    };
    // SAFETY: the function takes one argument in the Windows x64 convention; what it does with a bad pointer is
    // what `catch` is for
    let strlen = unsafe { GetProcAddress(GetModuleHandleA(c"ucrtbase.dll".as_ptr()), c"strlen".as_ptr()) };
    if strlen.is_null() {
        return Err("ucrtbase.dll has no strlen".into());
    }
    // SAFETY: as above
    Ok(unsafe { Vm::with_natives(config, &[("text_len", strlen, NativeSig::ints(1))]) }?)
}

/// 64 KiB of address space that is reserved and never committed.
fn reserve() -> Result<u64, Box<dyn Error>> {
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_NOACCESS: u32 = 1;
    // SAFETY: reserves fresh address space
    let reserved = unsafe { VirtualAlloc(std::ptr::null_mut(), 1 << 16, MEM_RESERVE, PAGE_NOACCESS) };
    match reserved.is_null() {
        true => Err("can't reserve address space".into()),
        false => Ok(reserved as u64),
    }
}

fn call_again(program: &mut Program, item: u64) -> Result<(), Box<dyn Error>> {
    let price = program.call("price", &[item])?;
    let len = program.call("label_len", &[item])?;
    println!("afterwards: price(good item) = {price}, label_len(good item) = {len}");
    expect("price", price, 250)?;
    Ok(expect("label_len", len, 7)?)
}

fn expect(what: &str, got: u64, want: u64) -> Result<(), String> {
    match got == want {
        true => Ok(()),
        false => Err(format!("{what}: got {got:#x}, want {want:#x}")),
    }
}
