//! Calls with more than five arguments, over the guest in `bpf/tests/stack_args.c`: clang passes arguments 6 to 12
//! on the stack, to the guest's own functions, host functions, native functions, raw function pointers and the
//! exports of another plugin.

use rvm::{
    ExecError, Image, Import, LinkError, MemoryError, NativeArg, NativeSig, Passthrough, Plugin, Program, RawCalls, Vm,
    VmConfig, VmError, STACK_REGION,
};

use crate::common::object;

/// What every callee of the fixture returns: argument `n` times `n`.
fn weigh(args: &[u64]) -> u64 {
    let weighted = args.iter().zip(1..).map(|(&arg, n)| arg.wrapping_mul(n));
    weighted.fold(0, u64::wrapping_add)
}

/// `x, x + 1, ...`, the `n` arguments the fixture's callers pass.
fn from(x: u64, n: u64) -> Vec<u64> {
    (x..x + n).collect()
}

extern "C" fn n6(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u64 {
    weigh(&[a, b, c, d, e, f])
}

extern "C" fn n8(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64 {
    weigh(&[a, b, c, d, e, f, g, h])
}

#[rustfmt::skip]
extern "C" fn n12(
    a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64,
) -> u64 {
    weigh(&[a, b, c, d, e, f, g, h, i, j, k, l])
}

/// # Safety
///
/// `buf` must point to `len` readable bytes.
unsafe extern "C" fn n_buf(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, buf: *const u8, len: u64) -> u64 {
    let bytes = unsafe { std::slice::from_raw_parts(buf, len as usize) };
    weigh(&[a, b, c, d, e, f]) + bytes.iter().map(|&b| u64::from(b)).sum::<u64>()
}

/// `n_buf`: a pointer in argument 7 to as many bytes as argument 8 holds, both on the stack.
const BUF: NativeSig = {
    let int = NativeArg::Int;
    NativeSig::new(&[int, int, int, int, int, int, NativeArg::Read(Some(8)), int])
};

/// A VM with the host and native functions the fixture imports.
fn vm_with(config: VmConfig) -> Vm {
    let natives = [
        ("n6", n6 as *const (), NativeSig::ints(6)),
        ("n8", n8 as *const (), NativeSig::ints(8)),
        ("n12", n12 as *const (), NativeSig::ints(12)),
        ("n_buf", n_buf as *const (), BUF),
    ];
    // SAFETY: each function takes its signature's arguments and never unwinds, and `n_buf` reads only the bytes its
    // pointer argument's check covers; the untagged test passes it a buffer of the guest's stack.
    let vm = unsafe { Vm::with_natives(config, &natives) }.unwrap();
    type Six = (u64, u64, u64, u64, u64, u64);
    type Eight = (u64, u64, u64, u64, u64, u64, u64, u64);
    type Twelve = (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);
    vm.register_extern("h6", |(a, b, c, d, e, f): Six| weigh(&[a, b, c, d, e, f]));
    vm.register_extern("h8", |(a, b, c, d, e, f, g, h): Eight| weigh(&[a, b, c, d, e, f, g, h]));
    vm.register_extern("h12", |(a, b, c, d, e, f, g, h, i, j, k, l): Twelve| {
        weigh(&[a, b, c, d, e, f, g, h, i, j, k, l])
    });
    // the struct's first half arrives as the fifth argument and its second half as the sixth
    vm.register_extern("h_split", |(a, b, c, d, s_a, s_b): Six| weigh(&[a, b, c, d, s_a, s_b]));
    vm
}

fn vm() -> Vm {
    vm_with(VmConfig::default())
}

fn load(vm: &Vm) -> Program {
    vm.load_elf(&object("tests/stack_args.o")).unwrap()
}

/// The calls of the fixture that reach each kind of callee with 6 and 12 arguments, each with its result for `x`.
fn calls(x: u64) -> Vec<(&'static str, u64)> {
    let split = weigh(&from(x, 6));
    let mut calls = vec![("call_g_split", split), ("call_h_split", split)];
    for (n, names) in [
        (6, &["call_g6", "callx_g6", "call_h6", "call_n6"][..]),
        (12, &["call_g12", "callx_g12", "call_h12", "call_n12"]),
    ] {
        calls.extend(names.iter().map(|&name| (name, weigh(&from(x, n)))));
    }
    calls
}

/// Each kind of callee gets every argument, in registers and on the stack, from a direct call and through a pointer.
#[test]
fn every_callee_gets_its_arguments() {
    let mut program = load(&vm());
    for x in [1, u64::MAX - 20] {
        for (name, expected) in calls(x) {
            assert_eq!(program.call(name, &[x]).unwrap(), expected, "{name}({x})");
        }
    }
}

/// The host passes more than five arguments as a guest caller does, and a struct of 16 bytes in two of them.
#[test]
fn host_calls_with_stack_arguments() {
    let mut program = load(&vm());
    for (name, n) in [("g12", 12), ("g_split", 6)] {
        let args = from(7, n);
        assert_eq!(program.call(name, &args).unwrap(), weigh(&args), "{name}");
    }

    // an argument the host leaves out is 0, also after a call that passed it
    assert_eq!(program.call("g12", &from(7, 5)).unwrap(), weigh(&from(7, 5)));
    assert_eq!(program.call("g12", &from(7, 9)).unwrap(), weigh(&from(7, 9)));
    assert!(matches!(program.call("g12", &from(7, 13)), Err(VmError::TooManyArgs(13))));

    let plugin = Plugin::new("stack", program);
    assert_eq!(plugin.func("g12").unwrap().call(&from(3, 12)).unwrap(), weigh(&from(3, 12)));
}

/// `nest` in the fixture.
fn nest(depth: u64, f: u64, g: u64) -> u64 {
    match depth {
        0 => f + g,
        _ => (nest(depth - 1, f * 3, g + 1) ^ f) + g,
    }
}

/// Each call depth has stack arguments of its own: a function finds its own again after the calls it makes, to
/// itself, to a host function and to another function.
#[test]
fn nested_calls_keep_their_arguments() {
    let mut program = load(&vm());
    // `call_nest` runs in the entry frame, and `nest` in up to the eight frames below it
    for depth in 0..rvm::MAX_CALL_DEPTH as u64 {
        assert_eq!(program.call("call_nest", &[depth, 5, 100]).unwrap(), nest(depth, 5, 100), "depth {depth}");
    }

    // through_host(a, .., g) = h6(g, f, e, d, c, b) + g8(a, .., g, 1) + f + g
    let x = 10;
    let a = from(x, 7);
    let reversed: Vec<u64> = a[1..].iter().rev().copied().collect();
    let expected = weigh(&reversed) + weigh(&[a[0], a[1], a[2], a[3], a[4], a[5], a[6], 1]) + a[5] + a[6];
    assert_eq!(program.call("call_through_host", &[x]).unwrap(), expected);
}

/// A callee that loads a stack argument its caller didn't store reads what the last call from that depth stored
/// there, and 0 before any. The entry function reads 0 for what the host doesn't pass.
#[test]
fn an_argument_the_caller_did_not_store() {
    let mut program = load(&vm());
    // g6 with five arguments
    assert_eq!(program.call("call_g6_short", &[9]).unwrap(), 9);
    // the entry frame stores x + 5 as the sixth argument of `g6`
    program.call("call_g6", &[100]).unwrap();
    assert_eq!(program.call("call_g6_short", &[9]).unwrap(), 9 + 6 * 105);

    program.call("g6", &from(50, 6)).unwrap();
    assert_eq!(program.call("g6", &from(50, 5)).unwrap(), weigh(&from(50, 5)));
}

fn fault(result: rvm::Result<u64>) -> MemoryError {
    match result {
        Err(VmError::Exec(ExecError::MemoryFault { error, .. })) => error,
        other => panic!("expected a memory fault, got {other:?}"),
    }
}

/// A pointer among the stack arguments of a native function resolves to the host address of its bytes, with a length
/// from another stack argument, and faults where the guest may not read them.
#[test]
fn native_pointer_on_the_stack() {
    let mut program = load(&vm());
    let x = 9;
    let sum = |len: u64| [1, 2, 3, x][..len as usize].iter().sum::<u64>();
    for len in [0, 1, 4] {
        assert_eq!(program.call("call_n_buf", &[x, len]).unwrap(), weigh(&from(x, 6)) + sum(len), "{len} bytes");
    }
    // the first byte past the stack, where a 1 MiB buffer leaves it
    let stack_end = program.memory().region_base(STACK_REGION) + program.memory().region_len(STACK_REGION) as u64;
    assert_eq!(
        fault(program.call("call_n_buf", &[x, 1 << 20])),
        MemoryError {
            addr: stack_end,
            size: 1
        }
    );

    // SAFETY: the guest passes `n_buf` four bytes of its stack
    let config = VmConfig {
        passthrough: unsafe { Passthrough::untagged() },
        ..VmConfig::default()
    };
    let mut untagged = load(&vm_with(config));
    assert_eq!(untagged.call("call_n_buf", &[x, 4]).unwrap(), weigh(&from(x, 6)) + sum(4));
    assert_eq!(untagged.call("call_n12", &[x]).unwrap(), weigh(&from(x, 12)));
}

/// A raw function pointer has no signature: in a program that passes stack arguments, the native function behind it
/// gets all seven, and takes those it has parameters for.
#[test]
fn raw_calls_pass_the_stack_arguments() {
    // SAFETY: the test passes the guest only the functions above, which take the arguments the guest passes them
    let raw = unsafe { RawCalls::on() };
    let mut program = vm()
        .loader()
        .raw_calls(raw)
        .load_elf(&object("tests/stack_args.o"))
        .unwrap();
    let x = 21;
    assert_eq!(program.call("raw12", &[n12 as *const () as u64, x]).unwrap(), weigh(&from(x, 12)));
    // a function of fewer parameters ignores the rest
    assert_eq!(program.call("raw12", &[n6 as *const () as u64, x]).unwrap(), weigh(&from(x, 6)));
}

/// Functions of another plugin take stack arguments too: integers, a struct that starts in r5, and a borrowed buffer
/// whose pointer and length are both on the stack.
#[test]
fn exports_take_stack_arguments() {
    for limit in [0, rvm::DEFAULT_INSTRUCTION_LIMIT] {
        if limit != 0 && !cfg!(feature = "fuel") {
            continue;
        }
        // a caller with a limit runs the export a second time, with what it has left
        let vm = vm_with(VmConfig {
            instruction_limit: limit,
            ..VmConfig::default()
        });
        let callee = Plugin::new("callee", load(&vm));
        for func in ["g8", "g12", "g_split", "g_sum"] {
            vm.export(&callee, func).unwrap();
        }
        let mut caller = vm.load_elf(&object("tests/stack_args_caller.o")).unwrap();

        let x = 40;
        for (name, n) in [("export_g8", 8), ("export_g12", 12), ("export_g_split", 6)] {
            assert_eq!(caller.call(name, &[x]).unwrap(), weigh(&from(x, n)), "{name}, limit {limit}");
        }
        // the callee sums `len / 8` of the caller's values x, 10, 20, 30
        let rest = weigh(&[1, 2, 3, 4, 5]);
        assert_eq!(caller.call("export_g_sum", &[x, 32]).unwrap(), rest + x + 60);
        assert_eq!(caller.call("export_g_sum", &[x, 16]).unwrap(), rest + x + 10);
        // a length past the caller's stack fails before the callee runs
        let err = caller.call("export_g_sum", &[x, 1 << 20]).unwrap_err().to_string();
        assert!(err.contains("callee::g_sum") && err.contains("no access"), "{err}");
        assert_eq!(callee.lock().unwrap().memory().region_len(rvm::BORROW_FIRST_REGION), 0);
    }
}

/// An instruction limit counts the loads and stores of stack arguments and the calls that take them as one
/// instruction each, and stops a call between any two of them.
#[cfg(feature = "fuel")]
#[test]
fn instruction_limit_at_every_instruction() {
    let mut program = load(&vm());
    for (name, args, expected) in [
        ("call_g12", vec![3], weigh(&from(3, 12))),
        ("call_n12", vec![3], weigh(&from(3, 12))),
    ] {
        let func = program.func(name).unwrap();
        let whole = program.call_func_with_limit(func, &args, 0);
        assert_eq!(whole.result.unwrap(), expected, "{name}");

        for limit in 1..=whole.instructions {
            let call = program.call_func_with_limit(func, &args, limit);
            match (limit == whole.instructions, call.result) {
                (true, Ok(result)) => assert_eq!(result, expected, "{name} under {limit}"),
                (false, Err(VmError::Exec(ExecError::InstructionLimit { .. }))) => {
                    assert!(
                        (limit - 1..=limit).contains(&call.instructions),
                        "{name} under {limit}: {}",
                        call.instructions
                    );
                }
                (_, result) => panic!("{name} under {limit}: {result:?}"),
            }
        }
    }
}

/// A prepared image records `stack` flags and 12-argument native signatures, and runs as the object does.
#[test]
fn prepared_image() {
    let image = vm().prepare_elf(&object("tests/stack_args.o")).unwrap();
    assert!(image
        .imports()
        .iter()
        .any(|i| matches!(i, Import::Name { name, stack: true, .. } if name == "h12")));
    let bytes = image.to_bytes();
    assert_eq!(Image::from_bytes(&bytes).unwrap(), image);
    let mut program = vm().load_image_bytes(&bytes).unwrap();
    assert_eq!(program.call("call_h12", &[5]).unwrap(), weigh(&from(5, 12)));
    assert_eq!(program.call("call_n_buf", &[5, 4]).unwrap(), weigh(&from(5, 6)) + 11);
}

/// A thirteenth argument has no place: the load fails for a function that takes one and names the function, and for
/// an 8-byte load or store through r11 at any offset that is no argument slot.
#[test]
fn what_no_call_passes_fails_the_load() {
    let err = vm().load_elf(&object("tests/stack_args_13.o")).unwrap_err();
    let in_g13 = |e: &LinkError| matches!(e, LinkError::StackArguments { function: Some(f), .. } if f == "g13");
    assert!(matches!(&err, VmError::Link(e) if in_g13(e)), "{err}");

    const LDX_DW: u8 = 0x79;
    const STX_DW: u8 = 0x7b;
    const ST_DW: u8 = 0x7a;
    let load = |opcode: u8, regs: u8, offset: i16| {
        let [lo, hi] = offset.to_le_bytes();
        let exit = [0x95, 0, 0, 0, 0, 0, 0, 0];
        let code = [[opcode, regs, lo, hi, 0, 0, 0, 0], exit].concat();
        Vm::new().load_image(Image::from_code(code))
    };
    // `r1 = *(u64 *)(r11 + offset)`, `*(u64 *)(r11 + offset) = r1` and `*(u64 *)(r11 + offset) = 0`
    let forms = [(LDX_DW, 0xb1, 1), (STX_DW, 0x1b, -1), (ST_DW, 0x0b, -1)];
    for (opcode, regs, sign) in forms {
        for slot in 1..=7 {
            load(opcode, regs, sign * 8 * slot).unwrap();
        }
        for offset in [0, 4, 12, 64, -8, -64, i16::MAX, i16::MIN] {
            let offset = sign * offset.max(-i16::MAX);
            let err = load(opcode, regs, offset).unwrap_err();
            let expected = LinkError::StackArguments {
                pc: 0,
                function: Some("main".into()),
            };
            assert!(matches!(&err, VmError::Link(e) if *e == expected), "{opcode:#x} at {offset}: {err}");
        }
    }
    // r11 stays a register to every other instruction: `r11 = 7; r0 = r11`
    let code = [
        0xb7, 0x0b, 0, 0, 7, 0, 0, 0, 0xbf, 0xb0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut program = Vm::new().load_image(Image::from_code(code.to_vec())).unwrap();
    assert_eq!(program.call("main", &[]).unwrap(), 7);
}
