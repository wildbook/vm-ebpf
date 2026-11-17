//! Runs `bpf_main` from `bpf/prebuilt/examples/example.o`, linked into an rvm image at build time (see `build.rs`),
//! with zeroed input and output structs.

use rvm::{Perms, Vm, FIRST_FREE_REGION};

const IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bpf.rvmi"));

fn main() -> rvm::Result<()> {
    let mut program = Vm::new().load_image(IMAGE)?;
    let input = program.memory_mut().map(FIRST_FREE_REGION, 64, Perms::RW)?;
    let res = program.call("bpf_main", &[input, input + 32])?;
    println!("res: {res}");
    Ok(())
}
