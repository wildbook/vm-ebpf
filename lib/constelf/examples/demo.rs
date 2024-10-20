use constelf::file::ElfFile;
use constelf::ElfResult;

fn main() -> ElfResult {
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

        println!("{: ^15}->{: ^11}| {:?}", src, tgt, sect.relocs()?);
    }

    Ok(())
}
