//! Runs `bpf/examples/core_example.o` against two host layouts of `struct event`: the one it was compiled against, and
//! one with the fields reordered. The linker patches each field access through its CO-RE relocation, so the same object
//! reads the right bytes from both. Exits with an error when a read returns the wrong value.
//!
//! Run with: cargo run -p rvm --example core_reloc

use std::error::Error;

use rvm::{Perms, Vm};

const OBJECT: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/examples/core_example.o"));

/// A field of `struct event`: its name, byte size and the value the host writes into it.
type Field = (&'static str, u32, u64);

const TIMESTAMP: Field = ("timestamp", 8, 0x1122_3344_5566_7788);
const PID: Field = ("pid", 4, 1234);
const UID: Field = ("uid", 4, 5678);
const FLAGS: Field = ("flags", 4, 0xABCD);
const PAD: Field = ("_pad", 4, 0);
const DATA: Field = ("data", 8, 0xDEAD_BEEF);

/// Fields in the order `core_example.c` declares them.
const COMPILE_TIME: [Field; 6] = [TIMESTAMP, PID, UID, FLAGS, PAD, DATA];
/// The host's layout of the same struct, with timestamp moved from offset 0 to 16.
const RUNTIME: [Field; 6] = [FLAGS, PID, UID, PAD, TIMESTAMP, DATA];

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- compile-time layout ---");
    run_against(&COMPILE_TIME)?;

    println!("\n--- reordered layout ---");
    run_against(&RUNTIME)?;
    Ok(())
}

/// Describe `layout` as the host's `struct event`, write an event in that layout and check that each reader returns
/// its field.
fn run_against(layout: &[Field]) -> Result<(), Box<dyn Error>> {
    let vm = Vm::new();
    let size = layout.iter().map(|&(_, size, _)| size).sum();
    let mut fields = Vec::new();
    {
        let mut types = vm.types();
        let u32_t = types.int("__u32", 4, false);
        let u64_t = types.int("__u64", 8, false);
        let event = types.add_struct("event", size);
        let mut offset = 0;
        for &(name, size, value) in layout {
            let ty = if size == 8 { u64_t } else { u32_t };
            types.member(event, name, offset, ty);
            println!("  {name:9} @ offset {offset}");
            fields.push((offset, size, value));
            offset += size;
        }
    }

    let mut program = vm.load_elf(OBJECT)?;
    let mem = program.memory_mut();
    let event_ptr = mem.map(rvm::FIRST_FREE_REGION, size as usize, Perms::RW);
    for &(offset, size, value) in &fields {
        let addr = event_ptr + u64::from(offset);
        match size {
            8 => mem.write(addr, value)?,
            _ => mem.write(addr, value as u32)?,
        }
    }

    for (reader, field) in [("read_timestamp", TIMESTAMP), ("read_pid", PID), ("read_flags", FLAGS)] {
        let (name, _, expected) = field;
        let result = program.call(reader, &[event_ptr])?;
        println!("  {reader}() = 0x{result:X}");
        if result != expected {
            return Err(format!("{reader} returned 0x{result:X}, expected {name} = 0x{expected:X}").into());
        }
    }
    Ok(())
}
