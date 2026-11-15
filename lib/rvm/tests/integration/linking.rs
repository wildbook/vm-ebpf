//! Cross-module linking: externs, numeric helpers, and hot-reloading a helper.

use rvm::{LinkError, Vm, VmError};

use crate::common::object;

/// Vm with everything link_main.o imports: helper 100 and `host_add`.
fn full_vm() -> Vm {
    let vm = Vm::new();
    vm.register_helper(100, |x: u64| x * 2);
    vm.register_fn("host_add", |(a, b): (u64, u64)| a + b);
    vm
}

fn link(vm: &Vm) -> rvm::Result<rvm::Program> {
    let main = vm.parse_module("main", &object("link_main.o"))?;
    let lib = vm.parse_module("lib", &object("link_lib.o"))?;
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

/// Re-registering a function reaches already linked programs at their next call.
#[test]
fn replacing_extern_rebinds_linked_calls() {
    let vm = full_vm();
    let mut program = link(&vm).unwrap();
    assert_eq!(program.call("run", &[7]).unwrap(), 21 + 14);
    vm.register_fn("host_add", |(a, b): (u64, u64)| a * b);
    assert_eq!(program.call("run", &[7]).unwrap(), 21 * 14);
}
