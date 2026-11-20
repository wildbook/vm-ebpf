//! Cross-module linking: externs, numeric helpers, and hot-reloading a helper.

use std::mem::{offset_of, size_of};

use constelf::raw::{shf, sht, Elf64Ehdr, Elf64Rel, Elf64Shdr, Elf64Sym};
use constelf::{ElfFile, ElfRelocs};
use rvm::{LinkError, Module, Vm, VmConfig, VmError, DEFAULT_MEMORY_LIMIT};

use crate::common::object;

/// Vm with everything link_main.o imports: helper 100 and `host_add`.
fn full_vm() -> Vm {
    let vm = Vm::new();
    vm.register_helper(100, |x: u64| x * 2);
    vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);
    vm
}

fn link(vm: &Vm) -> rvm::Result<rvm::Program> {
    let main = Module::from_elf(&object("tests/link_main.o"))?;
    let lib = Module::from_elf(&object("tests/link_lib.o"))?;
    vm.load_modules(&[&main, &lib])
}

#[test]
fn cross_module_call_helper_and_extern() {
    let mut program = link(&full_vm()).unwrap();
    // host_add(lib_scale(7), helper_double(7)) = 21 + 14
    assert_eq!(program.call("run", &[7]).unwrap(), 35);
    assert_eq!(program.call("lib_scale", &[5]).unwrap(), 15);
}

#[test]
fn link_failures() {
    fn missing_host_add(vm: &Vm) {
        vm.register_helper(100, |x: u64| x * 2);
    }
    fn missing_helper(vm: &Vm) {
        vm.register_extern("host_add", |(a, b): (u64, u64)| a + b);
    }
    fn arity_mismatch(vm: &Vm) {
        vm.register_helper(100, |x: u64| x * 2);
        vm.register_extern("host_add", |x: u64| x);
    }

    type Case = (fn(&Vm), fn(&VmError) -> bool);
    let cases: [Case; 3] = [
        (
            missing_host_add,
            |e| matches!(e, VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "host_add"),
        ),
        (missing_helper, |e| matches!(e, VmError::Link(LinkError::UnknownHelper(100)))),
        (arity_mismatch, |e| {
            matches!(
                e,
                VmError::Link(LinkError::SignatureMismatch {
                    declared: 2,
                    host: 1,
                    ..
                })
            )
        }),
    ];

    for (setup, check) in cases {
        let vm = Vm::new();
        setup(&vm);
        let err = link(&vm).unwrap_err();
        assert!(check(&err), "{err}");
    }
}

/// Linking inside `with_types` fails instead of deadlocking on the types the closure holds.
#[test]
fn link_inside_with_types_fails() {
    let vm = full_vm();
    let err = vm.with_types(|_| link(&vm)).unwrap_err();
    assert!(matches!(err, VmError::TypesBusy), "{err}");
    link(&vm).unwrap();
}

/// Re-registering a function reaches already linked programs at their next call.
#[test]
fn replacing_extern_rebinds_linked_calls() {
    let vm = full_vm();
    let mut program = link(&vm).unwrap();
    assert_eq!(program.call("run", &[7]).unwrap(), 21 + 14);
    vm.register_extern("host_add", |(a, b): (u64, u64)| a * b);
    assert_eq!(program.call("run", &[7]).unwrap(), 21 * 14);
}

/// A global in one module named like a map in another stays a global.
#[test]
fn global_named_like_a_map_is_data() {
    let vm = Vm::new();
    let counter = Module::from_elf(&object("tests/shared_counter.o")).unwrap();
    let global = Module::from_elf(&object("tests/global_hits.o")).unwrap();
    let mut program = vm.load_modules(&[&counter, &global]).unwrap();
    assert_eq!(program.call("get", &[]).unwrap(), 5);
    assert_eq!(program.call("bump", &[]).unwrap(), 1);
}

/// A relocation must patch a whole instruction inside its own section. One past the end of the section fails the
/// parse, which reads the addend there, and one at half an `imm` fails the link.
#[test]
fn relocation_outside_its_section_fails() {
    let elf = object("tests/link_main.o");
    let lib = Module::from_elf(&object("tests/link_lib.o")).unwrap();

    // the first relocation of a code section: the file offset of its `r_offset`, its value, and the section's size
    let (at, offset, size) = ElfFile::new(&elf)
        .unwrap()
        .relocs()
        .unwrap()
        .find_map(|chunk| {
            let (source, target) = (chunk.source(), chunk.target());
            let ElfRelocs::Rel([first, ..]) = chunk.relocs().unwrap() else {
                return None;
            };
            let is_code = target.sh_flags & u64::from(shf::EXECINSTR) != 0;
            is_code.then_some((source.sh_offset as usize, first.r_offset, target.sh_size))
        })
        .unwrap();
    let load = |offset: u64| {
        let mut elf = elf.clone();
        elf[at..][..8].copy_from_slice(&offset.to_le_bytes());
        let main = Module::from_elf(&elf)?;
        full_vm().load_modules(&[&main, &lib])
    };

    assert!(matches!(load(size).err(), Some(VmError::Elf(_))));
    let err = load(offset + 4).err().unwrap();
    assert!(matches!(err, VmError::Link(LinkError::InvalidReference(_))), "{err}");
}

/// An unreadable `.BTF` fails the parse instead of dropping CO-RE and BTF maps.
#[test]
fn unreadable_btf_fails() {
    let mut elf = object("examples/example.o");
    let btf = section_header(&elf, ".BTF");
    // sh_offset past the end of the file
    set(&mut elf, btf + offset_of!(Elf64Shdr, sh_offset), u64::MAX.to_le_bytes());
    assert!(Module::from_elf(&elf).is_err());
}

/// Linking counts code and data against the memory limit before it grows the image. A `.bss` stays a length, and
/// jump tables, copied once per code section and table, stop at the limit.
#[test]
fn layout_stays_within_memory_limit() {
    let limited = |memory_limit| {
        Vm::with_config(VmConfig {
            memory_limit,
            ..VmConfig::default()
        })
        .unwrap()
    };

    let mut elf = object("tests/link_lib.o");
    let bss_size = section_header(&elf, ".bss") + offset_of!(Elf64Shdr, sh_size);
    set(&mut elf, bss_size, (64u64 << 20).to_le_bytes());
    let image = Vm::new().prepare_elf(&elf).unwrap();
    assert!(image.data_len >= 64 << 20 && image.data.capacity() < 1 << 20, "{}", image.data.capacity());
    set(&mut elf, bss_size, (1u64 << 30).to_le_bytes());
    let err = Vm::new().prepare_elf(&elf).unwrap_err();
    assert!(matches!(err, VmError::MemoryLimit(DEFAULT_MEMORY_LIMIT)), "{err}");

    // 64 code sections that each load 64 tables: 4096 copies from 128 sections
    let elf = object("tests/func_ptr.o");
    let size = |elf: &[u8]| {
        let image = Vm::new().prepare_elf(elf).unwrap();
        image.code.len() + image.rodata_len + image.data_len
    };
    let base = size(&elf);
    let (elf, code_size, table_size) = repeat_jump_tables(&elf, 64);
    let copies = 64 * 64 * table_size;
    assert!(size(&elf) >= base + 64 * code_size + copies);
    let limit = base + 64 * code_size + copies / 2;
    let err = limited(limit).prepare_elf(&elf).unwrap_err();
    assert!(matches!(err, VmError::MemoryLimit(_)), "{err}");
}

/// `elf` with `n` more `.jumptables` sections and `n` more copies of the code section that loads a table, where every
/// code copy loads every new table, and the sizes of that code section and of the table. The new sections share the
/// file bytes of the originals.
fn repeat_jump_tables(elf: &[u8], n: usize) -> (Vec<u8>, usize, usize) {
    const SHDR: usize = size_of::<Elf64Shdr>();

    let file = ElfFile::new(elf).unwrap();
    let sections = file.sections().unwrap();
    let headers = sections.headers();
    let symbols = sections.symtab().unwrap().raw;
    let table_idx = section_index(elf, ".jumptables");
    let symtab_idx = headers.iter().position(|h| h.sh_type == sht::SYMTAB).unwrap();

    // a relocation that loads the table, and the code section it patches
    let (code_idx, rel) = file
        .relocs()
        .unwrap()
        .find_map(|chunk| {
            let ElfRelocs::Rel(relocs) = chunk.relocs().unwrap() else {
                return None;
            };
            let loads_table = |r: &&Elf64Rel| symbols[r.sym() as usize].st_shndx as usize == table_idx;
            Some((chunk.target_idx(), *relocs.iter().find(loads_table)?))
        })
        .unwrap();
    let first_table = headers.len();
    let first_code = first_table + n;
    let mut out = elf.to_vec();

    // the symbol table, with a symbol for each new table
    let symtab_at = out.len();
    out.extend_from_slice(sections.bytes(&headers[symtab_idx]).unwrap());
    for i in 0..n {
        let mut symbol = [0; size_of::<Elf64Sym>()];
        set(&mut symbol, offset_of!(Elf64Sym, st_shndx), ((first_table + i) as u16).to_le_bytes());
        out.extend_from_slice(&symbol);
    }
    let symtab_len = out.len() - symtab_at;

    // one relocation section for every code copy to share: `rel` against each new symbol
    let rels_at = out.len();
    for i in 0..n {
        let info = ((symbols.len() + i) as u64) << 32 | u64::from(rel.typ());
        out.extend_from_slice(&{ rel.r_offset }.to_le_bytes());
        out.extend_from_slice(&info.to_le_bytes());
    }
    let rels_len = out.len() - rels_at;

    let old_headers = file.header().e_shoff as usize;
    let header = |idx: usize| elf[old_headers..][idx * SHDR..][..SHDR].to_vec();
    let new_headers = out.len();
    out.extend_from_slice(&elf[old_headers..][..headers.len() * SHDR]);
    let symtab = new_headers + symtab_idx * SHDR;
    set(&mut out, symtab + offset_of!(Elf64Shdr, sh_offset), (symtab_at as u64).to_le_bytes());
    set(&mut out, symtab + offset_of!(Elf64Shdr, sh_size), (symtab_len as u64).to_le_bytes());
    out.extend_from_slice(&header(table_idx).repeat(n));
    out.extend_from_slice(&header(code_idx).repeat(n));
    for i in 0..n {
        let mut rels = [0; SHDR];
        set(&mut rels, offset_of!(Elf64Shdr, sh_type), sht::REL.to_le_bytes());
        set(&mut rels, offset_of!(Elf64Shdr, sh_offset), (rels_at as u64).to_le_bytes());
        set(&mut rels, offset_of!(Elf64Shdr, sh_size), (rels_len as u64).to_le_bytes());
        set(&mut rels, offset_of!(Elf64Shdr, sh_link), (symtab_idx as u32).to_le_bytes());
        set(&mut rels, offset_of!(Elf64Shdr, sh_info), ((first_code + i) as u32).to_le_bytes());
        out.extend_from_slice(&rels);
    }
    let count = (headers.len() + 3 * n) as u16;
    set(&mut out, offset_of!(Elf64Ehdr, e_shoff), (new_headers as u64).to_le_bytes());
    set(&mut out, offset_of!(Elf64Ehdr, e_shnum), count.to_le_bytes());

    (out, headers[code_idx].sh_size as usize, headers[table_idx].sh_size as usize)
}

/// Index of the section called `name`.
fn section_index(elf: &[u8], name: &str) -> usize {
    let sections = ElfFile::new(elf).unwrap().sections().unwrap();
    sections
        .iter()
        .position(|s| s.name().unwrap().to_bytes() == name.as_bytes())
        .unwrap()
}

/// File offset of the header of the section called `name`.
fn section_header(elf: &[u8], name: &str) -> usize {
    let headers = ElfFile::new(elf).unwrap().header().e_shoff as usize;
    headers + section_index(elf, name) * size_of::<Elf64Shdr>()
}

fn set<const N: usize>(bytes: &mut [u8], at: usize, value: [u8; N]) {
    bytes[at..][..N].copy_from_slice(&value);
}
