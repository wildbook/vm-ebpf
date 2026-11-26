//! Hands a plugin a table of function pointers, the way a C plugin API hands its functions out, and lets it call
//! them: `bpf/examples/vtable.c` asks for the API version, logs a line, has the host fill a struct on its stack and
//! calls a function with three integers. The plugin is loaded untagged and with raw calls, which makes it as trusted
//! as native code, while the VM's other programs keep their checks. Without raw calls the first call through the
//! table fails, which the example checks too.
//!
//! Run with: cargo run -p rvm --example vtable

use std::error::Error;
use std::sync::Mutex;

use rvm::{ExecError, Passthrough, RawCalls, Vm, VmError};

const OBJECT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/vtable.o"));

/// `struct host_api` in `bpf/examples/vtable.c`.
#[repr(C)]
struct HostApi {
    version: extern "win64" fn() -> u64,
    log: unsafe extern "win64" fn(*const u8, u64),
    window_size: unsafe extern "win64" fn(*mut Size),
    scale: extern "win64" fn(u64, u64, u64) -> u64,
}

/// `struct size` in the plugin.
#[repr(C)]
struct Size {
    width: u32,
    height: u32,
}

static API: HostApi = HostApi {
    version,
    log,
    window_size,
    scale,
};

/// The lines the plugin logged.
static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

extern "win64" fn version() -> u64 {
    2
}

/// # Safety
///
/// `text` must point to `len` readable bytes.
unsafe extern "win64" fn log(text: *const u8, len: u64) {
    let text = unsafe { std::slice::from_raw_parts(text, len as usize) };
    LOG.lock().unwrap().push(String::from_utf8_lossy(text).into_owned());
}

/// # Safety
///
/// `out` must be valid for a write.
unsafe extern "win64" fn window_size(out: *mut Size) {
    let size = Size {
        width: 640,
        height: 480,
    };
    unsafe { out.write(size) };
}

extern "win64" fn scale(value: u64, numerator: u64, denominator: u64) -> u64 {
    value * numerator / denominator.max(1)
}

fn main() -> Result<(), Box<dyn Error>> {
    let vm = Vm::new();
    // `as` exposes the provenance of the pointer the plugin reads through
    let api = &raw const API as u64;
    // SAFETY: the plugin reads `API` and passes pointers into its own stack and data
    let untagged = unsafe { Passthrough::untagged() };

    // SAFETY: the plugin calls only the functions of `API`, with the arguments they take, and none of them unwinds
    let raw_calls = unsafe { RawCalls::on() };
    let mut plugin = vm
        .loader()
        .passthrough(untagged)
        .raw_calls(raw_calls)
        .load_elf(OBJECT)?;
    let area = plugin.call("run", &[api])?;
    println!("run() = {area}, log: {:?}", LOG.lock().unwrap());
    if area != 640 * 480 / 10 || *LOG.lock().unwrap() != ["hello from the plugin"] {
        return Err("run: wrong result or log".into());
    }

    let mut plugin = vm.loader().passthrough(untagged).load_elf(OBJECT)?;
    match plugin.call("run", &[api]) {
        Err(VmError::Exec(ExecError::BadCodeAddress { target, .. })) if target == API.version as usize as u64 => {
            println!("without raw calls, the call through the table fails: no code at {target:#x}");
            Ok(())
        }
        other => Err(format!("run without raw calls: expected a bad code address, got {other:?}").into()),
    }
}
