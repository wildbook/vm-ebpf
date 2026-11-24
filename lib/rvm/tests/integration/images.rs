//! Prepared images: they run like programs linked from ELF, plugins load from them, and malformed ones fail to load.

use rvm::{
    Borrow, FunctionInfo, Image, Import, LinkError, MapDef, MapKind, Module, Perms, Plugin, Program, Vm, VmConfig,
    VmError, DEFAULT_MEMORY_LIMIT, MAX_REGION_LEN,
};
use rvm_core::opcode::CALL;

use crate::common::{host_vm, object};

/// Every program from an image calls exactly like the same program linked from ELF.
#[test]
fn images_run_like_elf() {
    type Case<'a> = (&'a [&'a str], &'a [(&'a str, &'a [u64])]);
    let vm = host_vm();
    // SAFETY: the programs run on this thread only.
    let shared = unsafe { vm.share_region(64, Perms::RW) }.unwrap();
    let slot = shared.base() + 8;
    let cases: &[Case] = &[
        (&["tests/atomics.o"], &[("run", &[5])]),
        (&["tests/data_ptrs.o"], &[("deref", &[])]),
        (
            &["tests/func_ptr.o"],
            &[
                ("call_ro", &[2, 10, 3]),
                ("call_rw", &[1, 10, 3]),
                ("pass_callback", &[10, 3]),
                ("dense_switch", &[3, 10]),
                ("dense_switch", &[16, 10]),
                ("addr_of_add", &[]),
            ],
        ),
        (&["tests/core_guard.o"], &[("read_flags", &[0]), ("read_flags_unguarded", &[0])]),
        (&["tests/core_bitfield.o"], &[("read_b", &[0])]),
        (
            &["tests/maps.o"],
            &[
                ("count", &[1]),
                ("count", &[1]),
                ("remember", &[7]),
                ("remember", &[7]),
                ("recall", &[7]),
            ],
        ),
        (&["examples/example.o"], &[("simple_add", &[2, 3]), ("return_magic", &[])]),
        (&["tests/std_helpers.o"], &[("draws_differ", &[])]),
        (&["tests/shared_counter.o"], &[("bump", &[]), ("bump", &[])]),
        (&["tests/shared_region.o"], &[("put", &[slot, 42]), ("get", &[slot])]),
        (&["tests/plugin_a_v1.o"], &[("a_scale", &[5])]),
        (&["tests/plugin_b.o"], &[("b_run", &[5])]),
        (&["tests/borrow_caller.o"], &[("run", &[]), ("run_keyed", &[])]),
        (&["tests/link_main.o", "tests/link_lib.o"], &[("run", &[7]), ("lib_scale", &[5])]),
    ];

    for &(objects, calls) in cases {
        let elfs: Vec<_> = objects.iter().map(|name| object(name)).collect();
        let modules: Vec<Module> = elfs.iter().map(|elf| Module::from_elf(elf).unwrap()).collect();
        let modules: Vec<&Module> = modules.iter().collect();

        let mut linked = vm.load_modules(&modules).unwrap();
        let image = vm.prepare_modules(&modules).unwrap().to_bytes();
        let mut loaded = vm.load_image_bytes(&image).unwrap();

        assert_eq!(functions(&linked), functions(&loaded), "{objects:?}");
        for (func, args) in calls {
            let want = format!("{:?}", linked.call(func, args));
            assert_eq!(format!("{:?}", loaded.call(func, args)), want, "{objects:?} {func}");
        }
    }
}

fn functions(program: &Program) -> Vec<(&str, &FunctionInfo)> {
    program
        .functions()
        .iter()
        .map(|(name, info)| (name.as_str(), info))
        .collect()
}

/// Plugins loaded from images bind exports by name and hot reload from images.
#[test]
fn plugins_from_images() {
    let vm = Vm::new();
    vm.register_extern("host_reenter", |x: u64| x);
    let image = |name: &str| vm.prepare_elf(&object(name)).unwrap().to_bytes();

    let a = Plugin::new("a", vm.load_image_bytes(&image("tests/plugin_a_v1.o")).unwrap());
    vm.export(&a, "a_scale").unwrap();
    let b_image = image("tests/plugin_b.o");
    let b = Plugin::new("b", vm.load_image_bytes(&b_image).unwrap());
    assert_eq!(b.call("b_run", &[5]).unwrap(), 11);

    a.replace(vm.load_image_bytes(&image("tests/plugin_a_v2.o")).unwrap())
        .unwrap();
    assert_eq!(b.call("b_run", &[5]).unwrap(), 16);

    // a VM without the export can't bind b's import
    let other = Vm::new();
    other.register_extern("host_reenter", |x: u64| x);
    assert!(matches!(
        other.load_image_bytes(&b_image).unwrap_err(),
        VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "a_scale"
    ));
}

#[test]
fn malformed_images_fail_to_load() {
    let vm = Vm::new();
    let good = vm.prepare_elf(&object("tests/maps.o")).unwrap();
    let bytes = good.to_bytes();
    let load = |image: &Image| vm.load_image_bytes(&image.to_bytes());
    let is_invalid = |r: rvm::Result<rvm::Program>| matches!(r, Err(VmError::InvalidImage(_)));

    for len in 0..bytes.len() {
        assert!(is_invalid(vm.load_image_bytes(&bytes[..len])), "truncated to {len} bytes");
    }

    let mut other_magic = bytes.clone();
    other_magic[0] = b'X';
    assert!(is_invalid(vm.load_image_bytes(&other_magic)));

    // the version string follows the magic, the format version and its length
    let ours = env!("CARGO_PKG_VERSION");
    let mut other_version = bytes.clone();
    other_version[12] ^= 1;
    let theirs = std::str::from_utf8(&other_version[12..][..ours.len()]).unwrap();
    let err = vm.load_image_bytes(&other_version).unwrap_err().to_string();
    assert!(err.contains(&format!("rvm {theirs} ")) && err.contains(&format!("rvm {ours} ")), "{err}");

    let insns = (good.code.len() / 8) as u32;
    let not_a_call = good.code.chunks(8).position(|insn| insn[0] != CALL).unwrap() as u32;
    for at in [insns, not_a_call] {
        let mut image = good.clone();
        image.externs.push((at, Import::Helper(1)));
        assert!(is_invalid(load(&image)), "extern at {at}");
    }

    let mut image = good.clone();
    image.externs[0].1 = Import::Helper(999);
    assert!(matches!(load(&image), Err(VmError::Link(LinkError::UnknownHelper(999)))));

    let mut image = good.clone();
    image.functions[0].1.pc = insns.into();
    assert!(is_invalid(load(&image)));

    // a borrow's length can't be another borrow's pointer, which the call rewrites first
    let mut image = good.clone();
    let borrow = |arg, len_arg| Borrow {
        arg,
        len_arg,
        writable: true,
    };
    image.functions[0].1.borrows = vec![borrow(0, 1), borrow(1, 0)];
    assert!(is_invalid(load(&image)));

    let mut image = good.clone();
    image.maps[0].max_entries = u32::MAX;
    let err = load(&image).unwrap_err();
    assert!(matches!(&err, VmError::Link(LinkError::InvalidMap(msg)) if msg.contains("too large")), "{err}");

    let mut image = good.clone();
    image.data_len = MAX_REGION_LEN + 1;
    assert!(matches!(load(&image), Err(VmError::ProgramTooLarge("data"))));
}

/// Images that ask for more memory than the limit fail before allocating it, whether one region or map asks or
/// several add up.
#[test]
fn oversized_images_fail_to_load() {
    let vm = Vm::new();
    let good = vm.prepare_elf(&object("tests/maps.o")).unwrap();
    let over_limit = |vm: &Vm, image: &Image| match vm.load_image_bytes(&image.to_bytes()) {
        Err(VmError::MemoryLimit(limit)) => limit,
        other => panic!("{other:?}"),
    };

    let mut image = good.clone();
    image.rodata_len = MAX_REGION_LEN;
    assert_eq!(over_limit(&vm, &image), DEFAULT_MEMORY_LIMIT);

    // one 4 GiB key in 64 bytes of values
    let mut image = good.clone();
    let map = |name: &str, key_size, max_entries| MapDef {
        name: name.into(),
        kind: MapKind::Hash,
        key_size,
        value_size: 8,
        max_entries,
    };
    image.maps = vec![map("big_key", u32::MAX, 1)];
    assert_eq!(over_limit(&vm, &image), DEFAULT_MEMORY_LIMIT);

    // each map fits the limit, together they don't
    let small = Vm::with_config(VmConfig {
        memory_limit: 1 << 20,
        ..VmConfig::default()
    })
    .unwrap();
    image.maps = (0..3).map(|i| map(&format!("m{i}"), 1024, 400)).collect();
    assert_eq!(over_limit(&small, &image), 1 << 20);
    image.maps.pop();
    small.load_image_bytes(&image.to_bytes()).unwrap();
}
