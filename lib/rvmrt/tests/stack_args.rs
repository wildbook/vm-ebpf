//! A C host that loads `rvmrt.dll` and exercises stack arguments (6 to 12 arguments) through `rvm_call`,
//! `rvm_call_func`, `rvm_native` and `RVM_RAW_CALLS`: `stack_args_host.c`.
//!
//! The test compiles the host with clang-cl and needs the DLL built first, as `cargo test` builds no DLL, so it is
//! ignored by default:
//!
//!   cargo build -p rvmrt
//!   cargo test -p rvmrt -- --ignored
//!
//! It takes `rvmrt.dll` and its import library from the directory in `RVMRT_DLL_DIR`, or from the profile's
//! directory of this build. The first is for the build of `lib/rvmrt` itself, with its own standard library:
//!
//!   (cd lib/rvmrt && cargo build --profile embedded)
//!   RVMRT_DLL_DIR=target/x86_64-pc-windows-msvc/embedded cargo test -p rvmrt -- --ignored

use std::path::PathBuf;
use std::process::Command;

use rvm::{NativeArg, NativeSig, Vm, VmConfig};

/// The image of `bpf/tests/rvmrt_stack_args.c`, linked against natives with the signatures the C host registers.
fn image() -> Vec<u8> {
    extern "win64" fn unused() -> u64 {
        0
    }
    let int = NativeArg::Int;
    let buf_sig = NativeSig::new(&[int, int, int, int, int, int, NativeArg::Read(Some(8)), int]);
    let natives = [
        ("n6", unused as *const (), NativeSig::ints(6)),
        ("n12", unused as *const (), NativeSig::ints(12)),
        ("n_buf", unused as *const (), buf_sig),
    ];
    // SAFETY: the VM only links; it calls none of them
    let vm = unsafe { Vm::with_natives(VmConfig::default(), &natives) }.unwrap();
    let object = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/tests/rvmrt_stack_args.o");
    vm.prepare_elf(&std::fs::read(object).unwrap()).unwrap().to_bytes()
}

#[test]
#[ignore = "needs clang-cl and rvmrt.dll"]
fn c_host_calls_with_stack_arguments() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    // the profile's directory: the one below the target directory that this test's executable lies under
    let target = tmp.parent().unwrap();
    let exe = std::env::current_exe().unwrap();
    let built = exe.ancestors().find(|dir| dir.parent() == Some(target)).unwrap();
    let dll_dir = std::env::var_os("RVMRT_DLL_DIR").map_or(built.to_owned(), PathBuf::from);
    let dll_dir = std::path::absolute(dll_dir).unwrap();

    let image = tmp.join("stack_args.image");
    std::fs::write(&image, self::image()).unwrap();
    let host = tmp.join("stack_args_host.exe");

    let compiled = Command::new("clang-cl")
        .args(["/nologo", "/O2", "/W4", "/MD"])
        .arg(format!("/I{}", manifest.join("include").display()))
        .arg(manifest.join("tests/stack_args_host.c"))
        .arg(format!("/Fe{}", host.display()))
        .arg(format!("/Fo{}", tmp.join("stack_args_host.obj").display()))
        .arg("/link")
        .arg(dll_dir.join("rvmrt.dll.lib"))
        .output()
        .expect("clang-cl");
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));

    let mut path = vec![dll_dir];
    path.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let ran = Command::new(&host)
        .arg(&image)
        .env("PATH", std::env::join_paths(path).unwrap())
        .output()
        .unwrap();
    let output = String::from_utf8_lossy(&ran.stdout);
    assert!(ran.status.success(), "{:?}\n{output}", ran.status);
    assert!(!output.contains("FAILED"), "{output}");
}
