//! Runs `bpf_main` from `bpf/prebuilt/examples/example.o`, linked into an rvm image at build time (see `build.rs`),
//! with zeroed input and output structs. Prints the result; exits with status 1 if loading or the call fails.

use std::process::ExitCode;

use rvm::{Perms, Vm, FIRST_FREE_REGION};

const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bpf.rvmi"));

fn main() -> ExitCode {
    match run() {
        Ok(res) => {
            println!("res: {res}");
            ExitCode::SUCCESS
        }
        // printing the error would link in the `Display` text of every rvm error
        Err(_) => {
            eprintln!("emu: bpf_main failed to load or run");
            ExitCode::FAILURE
        }
    }
}

/// Loads the image and returns what `bpf_main` returns.
fn run() -> rvm::Result<u64> {
    let mut program = Vm::new().load_image(IMAGE)?;
    let input = program.memory_mut().map(FIRST_FREE_REGION, 64, Perms::RW)?;
    program.call("bpf_main", &[input, input + 32])
}
