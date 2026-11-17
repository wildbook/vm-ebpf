//! Runs the [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) suite against the rvm interpreter. The
//! `.data` files under `tests/conformance/data/` are vendored verbatim from commit
//! `698e379525f44cf422bc1dbd43efe8495a76ab87` (MIT or Apache-2.0 per file, see the SPDX header in each and
//! `tests/conformance/LICENSE`); `asm` assembles their ubpf-style syntax and `data` parses the file format itself.
//!
//! A test file's `r1`/`r2` on entry are a pointer to its `-- mem` bytes and their length, the calling convention every
//! reference plugin in the suite uses.

mod asm;
mod data;

use rvm::{Executor, HelperRegistry, Perms, VmMemory, FIRST_FREE_REGION, STACK_REGION};

/// Comfortably covers the suite's deepest call nesting (`DEFAULT_FRAME_SIZE` per level).
const STACK_SIZE: usize = 8192;

/// Files that exercise something rvm deliberately does not implement, with why.
const SKIP: &[(&str, &str)] = &[];

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
        if let Some((_, reason)) = SKIP.iter().find(|(skipped, _)| *skipped == name) {
            eprintln!("SKIP {name}: {reason}");
            continue;
        }

        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {name}: {e}"));
        match run_one(&text) {
            Ok(()) => passed += 1,
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }

    eprintln!("bpf_conformance: {passed} passed, {} skipped, {} failed", SKIP.len(), failures.len());
    assert!(failures.is_empty(), "bpf_conformance failures:\n{}", failures.join("\n"));
}

/// Assembles and runs one parsed `.data` file, and checks its outcome.
fn run_one(text: &str) -> Result<(), String> {
    let case = data::parse(text)?;
    let code = rvm::instructions_from_bytes(&case.code);

    let mut memory = VmMemory::new();
    let stack_top = memory.map(STACK_REGION, STACK_SIZE, Perms::RW) + STACK_SIZE as u64;
    let mem_ptr = memory.map_bytes(FIRST_FREE_REGION, &case.mem, case.mem.len(), Perms::RW);

    let mut helpers = HelperRegistry::new();
    // helper 5 is `unwind` in the classic interpreter test ABI; call_unwind_fail.data and callx.data only check that
    // calling it doesn't abort the program
    helpers.register(5, |_: ()| 0u64);

    let mut exec = Executor::new(&code, &mut memory, &helpers, stack_top);
    #[cfg(feature = "fuel")]
    exec.set_instruction_limit(1_000_000);
    let outcome = exec.call(0, &[mem_ptr, case.mem.len() as u64]);

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
