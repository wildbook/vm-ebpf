//! Runs the [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) suite against the rvm interpreter. The
//! `.data` files under `tests/conformance/data/` are vendored verbatim from commit
//! `698e379525f44cf422bc1dbd43efe8495a76ab87` (MIT or Apache-2.0 per file, see the SPDX header in each and
//! `tests/conformance/LICENSE`); `asm` assembles their ubpf-style syntax and `data` parses the file format itself.
//!
//! A test file's `r1`/`r2` on entry are a pointer to its `-- mem` bytes and their length, the calling convention every
//! reference plugin in the suite uses.

mod asm;
mod data;

use rvm::{Image, Perms, Vm};

#[test]
fn bpf_conformance_suite() {
    let dir = format!("{}/tests/conformance/data", env!("CARGO_MANIFEST_DIR"));
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("reading {dir}: {e}"))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "no test files found under {dir}");

    let mut passed = 0;
    let mut failures = Vec::new();

    for path in &entries {
        let name = path.file_name().unwrap().to_str().unwrap();
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {name}: {e}"));
        match run_one(&text) {
            Ok(()) => passed += 1,
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }

    eprintln!("bpf_conformance: {passed} passed, {} failed", failures.len());
    assert!(failures.is_empty(), "bpf_conformance failures:\n{}", failures.join("\n"));
}

/// Assembles and runs one parsed `.data` file, and checks its outcome.
fn run_one(text: &str) -> Result<(), String> {
    let case = data::parse(text)?;

    let vm = Vm::new();
    // helper 5 is `unwind` in the classic interpreter test ABI; call_unwind_fail.data and callx.data only check that
    // calling it doesn't abort the program
    vm.register_helper(5, |_: ()| 0u64);
    let mut program = vm.load_image(Image::from_code(case.code)).map_err(|e| e.to_string())?;
    let mem = program
        .memory_mut()
        .map_bytes(&case.mem, case.mem.len(), Perms::RW)
        .map_err(|e| e.to_string())?;
    let outcome = program.call("main", &[mem.base(), case.mem.len() as u64]);

    match (outcome, case.result, case.error) {
        (Ok(r0), Some(expected), _) if r0 == expected => Ok(()),
        (Ok(r0), Some(expected), _) => Err(format!("expected r0 = {expected:#x}, got {r0:#x}")),
        (Ok(r0), None, Some(expected)) => Err(format!("expected error {expected:?}, got r0 = {r0:#x}")),
        (Ok(_), None, None) => unreachable!("parsed test case has neither a result nor an error"),
        // No vendored file sets `-- error`; a real one would need to compare `e`'s text.
        (Err(_), _, Some(_)) => Ok(()),
        (Err(e), _, None) => Err(e.to_string()),
    }
}
