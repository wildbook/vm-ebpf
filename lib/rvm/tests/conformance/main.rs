//! Runs the [bpf_conformance](https://github.com/Alan-Jowett/bpf_conformance) suite against the rvm interpreter. The
//! `.data` files under `tests/conformance/data/` are vendored verbatim from commit
//! `698e379525f44cf422bc1dbd43efe8495a76ab87` (MIT or Apache-2.0 per file, see the SPDX header in each and
//! `tests/conformance/LICENSE`); `asm` assembles their ubpf-style syntax and `data` parses the file format itself.
//!
//! A test file's `r1`/`r2` on entry are a pointer to its `-- mem` bytes and their length, the calling convention every
//! reference plugin in the suite uses.

mod asm;
mod data;

#[cfg(feature = "fuel")]
use rvm::{ExecError, LimitedCall, VmError};
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

/// Assembles and runs one parsed `.data` file unmetered and (with the `fuel` feature) metered, including exact
/// fuel boundary checks, and verifies every outcome.
fn run_one(text: &str) -> Result<(), String> {
    let case = data::parse(text)?;
    let vm = Vm::new();
    // helper 5 is `unwind` in the classic interpreter test ABI; call_unwind_fail.data and callx.data only check that
    // calling it doesn't abort the program
    vm.register_helper(5, |_: ()| 0u64);

    let load = || -> Result<(rvm::Program, u64), String> {
        let mut program = vm
            .load_image(Image::from_code(case.code.clone()))
            .map_err(|e| e.to_string())?;
        let mem = program
            .memory_mut()
            .map_bytes(&case.mem, case.mem.len(), Perms::RW)
            .map_err(|e| e.to_string())?;
        Ok((program, mem.base()))
    };

    let check_outcome = |label: &str, outcome: rvm::Result<u64>| -> Result<(), String> {
        match (outcome, case.result, case.error.as_deref()) {
            (Ok(r0), Some(expected), _) if r0 == expected => Ok(()),
            (Ok(r0), Some(expected), _) => Err(format!("{label}: expected r0 = {expected:#x}, got {r0:#x}")),
            (Ok(r0), None, Some(expected)) => Err(format!("{label}: expected error {expected:?}, got r0 = {r0:#x}")),
            (Ok(_), None, None) => unreachable!("parsed test case has neither a result nor an error"),
            // No vendored file sets `-- error`; a real one would need to compare `e`'s text.
            (Err(_), _, Some(_)) => Ok(()),
            (Err(e), _, None) => Err(format!("{label}: {e}")),
        }
    };

    // 1. Unmetered run (`Tables::PLAIN`).
    let (mut program, base) = load()?;
    let args = [base, case.mem.len() as u64];
    check_outcome("unmetered", program.call("main", &args))?;

    // 2. Metered run (`Tables::METERED`) and exact fuel boundary check (`Metered::step`).
    #[cfg(feature = "fuel")]
    {
        let (mut program, base) = load()?;
        let args = [base, case.mem.len() as u64];
        let main = program.func("main").map_err(|e| e.to_string())?;
        let LimitedCall { result, instructions } = program.call_func_with_limit(main, &args, 0);
        check_outcome("metered", result)?;

        if let Some(expected) = case.result {
            if instructions > 0 {
                // Exact limit must succeed and consume every unit.
                let (mut program, base) = load()?;
                let args = [base, case.mem.len() as u64];
                let main = program.func("main").map_err(|e| e.to_string())?;
                let exact = program.call_func_with_limit(main, &args, instructions);
                match exact.result {
                    Ok(r0) if r0 == expected && exact.instructions == instructions => {}
                    other => {
                        return Err(format!(
                            "exact fuel ({instructions}): got ({other:?}, used={}), expected Ok({expected:#x})",
                            exact.instructions
                        ));
                    }
                }

                // One unit short must stop with `InstructionLimit`.
                let short_limit = instructions - 1;
                let (mut program, base) = load()?;
                let args = [base, case.mem.len() as u64];
                let main = program.func("main").map_err(|e| e.to_string())?;
                let short = program.call_func_with_limit(main, &args, short_limit);
                if !matches!(
                    short.result,
                    Err(VmError::Exec(ExecError::InstructionLimit { limit })) if limit == short_limit
                ) {
                    return Err(format!(
                        "short fuel ({short_limit}): expected InstructionLimit, got {:?}",
                        short.result
                    ));
                }
            }
        }
    }

    Ok(())
}
