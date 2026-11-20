//! Prints the sections and relocations of `bpf/prebuilt/examples/example.o`.

use constelf::{ElfFile, ElfResult};

fn main() -> ElfResult {
    let elf = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/example.o"));
    let elf = ElfFile::new(elf)?;
    println!("{elf:#?}");

    for sect in elf.sections()?.iter() {
        let name = sect.name()?;

        println!("{name:?} | {:#x?}", sect.raw());
        println!(" - {:02x?}", sect.bytes()?);
    }

    for sect in elf.relocs()? {
        let src = sect.source().name()?.to_string_lossy();
        let tgt = sect.target().name()?.to_string_lossy();
        let relocs = sect.relocs()?;

        println!("{src: ^15}->{tgt: ^11}| {relocs:?}");
    }

    Ok(())
}
