use constelf::file::ElfFile;
use constelf::ElfResult;

fn main() -> ElfResult {
    // built with `clang -target bpf -O2 -g -c bpf/example.c -o bpf.o`
    let elf = include_bytes!("../../../bpf.o");
    let elf = ElfFile::new(elf)?;
    println!("{elf:#?}");

    let sections = elf.sections()?;

    for sect in sections.iter() {
        let name = sect.name()?;

        println!("{name:?} | {:#x?}", sect.raw());
        println!(" - {:?}", hex::encode(sect.bytes()?));
    }

    for sect in elf.relocs().iter()? {
        let src = sect.source().name()?.to_string_lossy();
        let tgt = sect.target().name()?.to_string_lossy();
        let relocs = sect.relocs()?;

        println!("{src: ^15}->{tgt: ^11}| {relocs:?}");
    }

    Ok(())
}
