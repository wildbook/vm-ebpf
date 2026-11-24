//! A C++ host that loads `rvmrt.dll` and makes native functions and raw accesses fault: `seh_host.cpp`.
//!
//! The test compiles the host with clang-cl and needs the DLL built first, as `cargo test` builds no DLL, so it is
//! ignored by default:
//!
//!   cargo build -p rvmrt --features seh
//!   cargo test -p rvmrt --features seh -- --ignored
//!
//! It takes `rvmrt.dll` and its import library from the directory in `RVMRT_DLL_DIR`, or from the profile's
//! directory of this build. The first is for the build of `lib/rvmrt` itself, with its own standard library:
//!
//!   (cd lib/rvmrt && cargo build --profile embedded --features seh)
//!   RVMRT_DLL_DIR=target/x86_64-pc-windows-msvc/embedded cargo test -p rvmrt --features seh -- --ignored

#![cfg(feature = "seh")]

use std::path::PathBuf;
use std::process::Command;

use rvm::{NativeSig, Vm, VmConfig};

/// The image of `bpf/tests/seh.c`, linked against natives with the signatures the host registers.
fn image() -> Vec<u8> {
    extern "win64" fn unused() -> u64 {
        0
    }
    let natives = [
        ("nat_strlen", 1),
        ("nat_raise", 4),
        ("nat_break", 0),
        ("nat_sort", 4),
        ("nat_throw", 1),
        ("nat_recurse", 1),
    ]
    .map(|(name, args)| (name, unused as *const (), NativeSig::ints(args)));
    // SAFETY: the VM only links; it calls none of them
    let vm = unsafe { Vm::with_natives(VmConfig::default(), &natives) }.unwrap();
    let object = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/tests/seh.o");
    vm.prepare_elf(&std::fs::read(object).unwrap()).unwrap().to_bytes()
}

#[test]
#[ignore = "needs clang-cl"]
fn cpp_host_catches_native_and_raw_faults() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    // the profile's directory: the one below the target directory that this test's executable lies under
    let target = tmp.parent().unwrap();
    let exe = std::env::current_exe().unwrap();
    let built = exe.ancestors().find(|dir| dir.parent() == Some(target)).unwrap();
    let dll_dir = std::env::var_os("RVMRT_DLL_DIR").map_or(built.to_owned(), PathBuf::from);
    let dll_dir = std::path::absolute(dll_dir).unwrap();

    let image = tmp.join("seh.image");
    std::fs::write(&image, self::image()).unwrap();
    let host = tmp.join("seh_host.exe");

    // /EHa: the destructor below the throw is in a function that also faults
    let compiled = Command::new("clang-cl")
        .args(["/nologo", "/O2", "/EHa", "/MD"])
        .arg(format!("/I{}", manifest.join("include").display()))
        .arg(manifest.join("tests/seh_host.cpp"))
        .arg(format!("/Fe{}", host.display()))
        .arg(format!("/Fo{}", tmp.join("seh_host.obj").display()))
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
