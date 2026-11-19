//! Cross-module linking: externs, numeric helpers, and hot-reloading a helper.

use rvm::{LinkError, Module, Relocation, Section, SectionKind, Symbol, Vm, VmConfig, VmError, DEFAULT_MEMORY_LIMIT};

use crate::common::object;

/// Vm with everything link_main.o imports: helper 100 and `host_add`.
fn full_vm() -> Vm {
    let vm = Vm::new();
    vm.register_helper(100, |x: u64| x * 2);
    vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);
    vm
}

fn link(vm: &Vm) -> rvm::Result<rvm::Program> {
    let main = Module::from_elf("main", &object("tests/link_main.o"))?;
    let lib = Module::from_elf("lib", &object("tests/link_lib.o"))?;
    vm.link(&[&main, &lib])
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
        vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);
    }
    fn arity_mismatch(vm: &Vm) {
        vm.register_helper(100, |x: u64| x * 2);
        vm.register_fn("host_add", |x: u64| x);
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
    vm.register_fn("host_add", |(a, b): (u64, u64)| a * b);
    assert_eq!(program.call("run", &[7]).unwrap(), 21 * 14);
}

/// A global in one module named like a map in another stays a global.
#[test]
fn global_named_like_a_map_is_data() {
    let vm = Vm::new();
    let counter = Module::from_elf("counter", &object("tests/shared_counter.o")).unwrap();
    let global = Module::from_elf("global", &object("tests/global_hits.o")).unwrap();
    let mut program = vm.link(&[&counter, &global]).unwrap();
    assert_eq!(program.call("get", &[]).unwrap(), 5);
    assert_eq!(program.call("bump", &[]).unwrap(), 1);
}

/// A relocation must patch whole instructions inside its own section, not the next section or half an `imm`.
#[test]
fn relocation_outside_its_section_fails() {
    let parse = || Module::from_elf("main", &object("tests/link_main.o")).unwrap();
    let lib = Module::from_elf("lib", &object("tests/link_lib.o")).unwrap();
    let main = parse();
    let at = main
        .relocations
        .iter()
        .position(|r| main.sections[r.section_idx].kind == SectionKind::Code)
        .unwrap();
    let size = main.sections[main.relocations[at].section_idx].size;
    for offset in [size, main.relocations[at].offset + 4] {
        let mut main = parse();
        main.relocations[at].offset = offset;
        let err = full_vm().link(&[&main, &lib]).unwrap_err();
        assert!(matches!(err, VmError::Link(LinkError::InvalidReference(_))), "offset {offset}: {err}");
    }
}

/// An unreadable `.BTF` fails the parse instead of dropping CO-RE and BTF maps.
#[test]
fn unreadable_btf_fails() {
    let mut elf = object("examples/example.o");
    let u16_at = |elf: &[u8], at: usize| u16::from_le_bytes(elf[at..][..2].try_into().unwrap()) as usize;
    let u64_at = |elf: &[u8], at: usize| u64::from_le_bytes(elf[at..][..8].try_into().unwrap()) as usize;
    let (shoff, shentsize, shnum, shstrndx) =
        (u64_at(&elf, 0x28), u16_at(&elf, 0x3A), u16_at(&elf, 0x3C), u16_at(&elf, 0x3E));
    let header = |idx: usize| shoff + idx * shentsize;
    let names = u64_at(&elf, header(shstrndx) + 0x18);
    let btf = (0..shnum)
        .find(|&idx| {
            let name = names + u32::from_le_bytes(elf[header(idx)..][..4].try_into().unwrap()) as usize;
            elf[name..].starts_with(b".BTF\0")
        })
        .unwrap();
    // sh_offset past the end of the file
    elf[header(btf) + 0x18..][..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Module::from_elf("main", &elf).is_err());
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
    };

    let mut module = Module::from_elf("main", &object("examples/example.o")).unwrap();
    module.sections.push(Section {
        name: ".bss.big".into(),
        kind: SectionKind::Bss,
        data: Vec::new(),
        size: 64 << 20,
        align: 8,
        elf_index: usize::MAX,
    });
    let image = Vm::new().prepare_modules(&[&module]).unwrap();
    assert!(image.data_len >= 64 << 20 && image.data.capacity() < 1 << 20, "{}", image.data.capacity());
    module.sections.last_mut().unwrap().size = 1 << 30;
    let err = Vm::new().prepare_modules(&[&module]).unwrap_err();
    assert!(matches!(err, VmError::MemoryLimit(DEFAULT_MEMORY_LIMIT)), "{err}");

    // 64 code sections that each load 64 tables: 4096 copies from 128 sections
    let mut module = Module::from_elf("main", &object("tests/func_ptr.o")).unwrap();
    let base = Vm::new().prepare_modules(&[&module]).unwrap();
    let base = base.code.len() + base.rodata_len + base.data_len;
    let (reloc, table) = module
        .relocations
        .iter()
        .find_map(|r| {
            let table = module.symbol_by_idx(r.symbol_idx)?.section_idx?;
            (module.sections[table].kind == SectionKind::JumpTable).then(|| (r.clone(), table))
        })
        .unwrap();
    let (code, table) = (module.sections[reloc.section_idx].clone(), module.sections[table].clone());
    let symbols: Vec<usize> = (0..64)
        .map(|_| {
            module.sections.push(table.clone());
            let section_idx = Some(module.sections.len() - 1);
            module.symbols.push(Symbol {
                name: String::new(),
                section_idx,
                value: 0,
            });
            module.symbols.len() - 1
        })
        .collect();
    for _ in 0..64 {
        module.sections.push(code.clone());
        let section_idx = module.sections.len() - 1;
        for &symbol_idx in &symbols {
            module.relocations.push(Relocation {
                section_idx,
                symbol_idx,
                ..reloc.clone()
            });
        }
    }
    let copies = 64 * 64 * table.size as usize;
    let err = limited(base + 64 * code.size as usize + copies / 2)
        .prepare_modules(&[&module])
        .unwrap_err();
    assert!(matches!(err, VmError::MemoryLimit(_)), "{err}");
}
