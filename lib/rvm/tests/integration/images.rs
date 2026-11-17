//! Prepared images: they run like programs linked from ELF, plugins load from them, and malformed ones fail to load.

use rvm::{region_base, Image, Import, LinkError, Module, Vm, VmError, FIRST_FREE_REGION, MAX_REGION_LEN};

use crate::common::object;

/// Every program from an image calls exactly like the same program linked from ELF.
#[test]
fn images_run_like_elf() {
    type Case = (&'static [&'static str], &'static [(&'static str, &'static [u64])]);
    const SLOT: u64 = region_base(FIRST_FREE_REGION) + 8;
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
        (&["tests/shared_region.o"], &[("put", &[SLOT, 42]), ("get", &[SLOT])]),
        (&["tests/plugin_a.o"], &[("a_scale", &[5])]),
        (&["tests/plugin_b.o"], &[("b_run", &[5])]),
        (&["tests/borrow_caller.o"], &[("run", &[])]),
        (&["tests/link_main.o", "tests/link_lib.o"], &[("run", &[7]), ("lib_scale", &[5])]),
    ];

    let vm = Vm::new();
    vm.register_helper(100, |x: u64| x * 2);
    vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);
    vm.register_fn("host_reenter", |x: u64| x);
    vm.enable_time();
    vm.enable_random();
    vm.enable_print(|_| {});
    // SAFETY: the programs run on this thread only.
    unsafe { vm.share_region(FIRST_FREE_REGION, 64, rvm::Perms::RW) }.unwrap();
    let a = vm.load_plugin("a", &object("tests/plugin_a.o")).unwrap();
    vm.export(&a, "a_scale").unwrap();
    let callee = vm.load_plugin("callee", &object("tests/borrow_callee.o")).unwrap();
    for func in ["sum", "fill", "poke"] {
        vm.export(&callee, func).unwrap();
    }

    for &(objects, calls) in cases {
        let elfs: Vec<_> = objects.iter().map(|name| object(name)).collect();
        let modules: Vec<Module> = elfs.iter().map(|elf| vm.parse_module("main", elf).unwrap()).collect();
        let modules: Vec<&Module> = modules.iter().collect();

        let mut linked = vm.link(&modules).unwrap();
        let image = vm.prepare_modules(&modules).unwrap().to_bytes();
        let mut loaded = vm.load_image(&image).unwrap();

        assert_eq!(linked.functions(), loaded.functions(), "{objects:?}");
        for (func, args) in calls {
            let want = format!("{:?}", linked.call(func, args));
            assert_eq!(format!("{:?}", loaded.call(func, args)), want, "{objects:?} {func}");
        }
    }
}

/// Plugins loaded from images bind exports by name and hot reload from images.
#[test]
fn plugins_from_images() {
    let vm = Vm::new();
    vm.register_fn("host_reenter", |x: u64| x);
    let image = |name: &str| vm.prepare(&object(name)).unwrap().to_bytes();

    let a = vm.load_plugin_image("a", &image("tests/plugin_a.o")).unwrap();
    vm.export(&a, "a_scale").unwrap();
    let b_image = image("tests/plugin_b.o");
    let b = vm.load_plugin_image("b", &b_image).unwrap();
    assert_eq!(b.call("b_run", &[5]).unwrap(), 11);

    a.replace(vm.load_image(&image("tests/plugin_a3.o")).unwrap()).unwrap();
    assert_eq!(b.call("b_run", &[5]).unwrap(), 16);

    // a VM without the export can't bind b's import
    let other = Vm::new();
    other.register_fn("host_reenter", |x: u64| x);
    assert!(matches!(
        other.load_image(&b_image).unwrap_err(),
        VmError::Link(LinkError::UnresolvedSymbol(name)) if name == "a_scale"
    ));
}

#[test]
fn malformed_images_fail_to_load() {
    let vm = Vm::new();
    let good = vm.prepare(&object("tests/maps.o")).unwrap();
    let bytes = good.to_bytes();
    let load = |image: &Image| vm.load_image(&image.to_bytes());
    let is_invalid = |r: rvm::Result<rvm::Program>| matches!(r, Err(VmError::InvalidImage(_)));

    for len in 0..bytes.len() {
        assert!(is_invalid(vm.load_image(&bytes[..len])), "truncated to {len} bytes");
    }

    let mut other_magic = bytes.clone();
    other_magic[0] = b'X';
    assert!(is_invalid(vm.load_image(&other_magic)));

    // the version string follows the magic, the format version and its length
    let ours = env!("CARGO_PKG_VERSION");
    let mut other_version = bytes.clone();
    other_version[12] ^= 1;
    let theirs = std::str::from_utf8(&other_version[12..][..ours.len()]).unwrap();
    let err = vm.load_image(&other_version).unwrap_err().to_string();
    assert!(err.contains(&format!("rvm {theirs} ")) && err.contains(&format!("rvm {ours} ")), "{err}");

    let insns = (good.code.len() / 8) as u32;
    let not_a_call = good.code.chunks(8).position(|insn| insn[0] != 0x85).unwrap() as u32;
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

    let mut image = good.clone();
    image.maps[0].max_entries = u32::MAX;
    let err = load(&image).unwrap_err();
    assert!(matches!(&err, VmError::InvalidImage(msg) if msg.contains("too large")), "{err}");

    let mut image = good.clone();
    image.data_len = MAX_REGION_LEN + 1;
    assert!(matches!(load(&image), Err(VmError::ProgramTooLarge("data"))));
}
