//! Parser for the bpf_conformance suite's `.data` test file format: a sequence of
//! `-- <section>` headers followed by their content, as documented in the
//! project's README. `# ...` comments are stripped from every line first, exactly
//! as the reference parser does, so they can trail any section's content.

/// One parsed `.data` file.
pub struct TestCase {
    /// Raw eBPF bytecode, from assembling `-- asm` or decoding `-- raw` words.
    pub code: Vec<u8>,
    /// The `-- mem` section, decoded from whitespace-separated hex bytes.
    pub mem: Vec<u8>,
    /// Expected `r0` on exit, from `-- result` (hex with a `0x` prefix, or decimal).
    pub result: Option<u64>,
    /// Expected error text from `-- error`.
    pub error: Option<String>,
}

enum Section {
    Ignore,
    Asm,
    Raw,
    Mem,
    Result,
    Error,
}

/// Parses one `.data` file's text. Returns `Err` for a file with neither a `-- raw`
/// nor an `-- asm` section, or neither a result nor an error, matching the
/// reference parser's "nothing to run" skip.
pub fn parse(text: &str) -> Result<TestCase, String> {
    let mut section = Section::Ignore;
    let mut asm_source = String::new();
    let mut raw = String::new();
    let mut mem_hex = String::new();
    let mut result_text = String::new();
    let mut error = String::new();

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        if let Some(header) = line.trim().strip_prefix("--") {
            let header = header.trim();
            section = match header {
                "asm" => Section::Asm,
                "raw" => Section::Raw,
                "mem" => Section::Mem,
                "result" => Section::Result,
                "error" => Section::Error,
                // "c" (reference source) and "no register offset" are documentation only.
                _ => Section::Ignore,
            };
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        match section {
            Section::Asm => {
                asm_source.push_str(line);
                asm_source.push('\n');
            }
            Section::Raw => {
                raw.push(' ');
                raw.push_str(line.trim());
            }
            Section::Mem => {
                mem_hex.push(' ');
                mem_hex.push_str(line.trim());
            }
            Section::Result => result_text = line.trim().to_string(),
            Section::Error => error = line.trim().to_string(),
            Section::Ignore => {}
        }
    }

    if result_text.is_empty() && error.is_empty() {
        return Err("no result or error section".to_string());
    }

    let code = if !raw.is_empty() {
        parse_raw_words(&raw)?
    } else {
        super::asm::assemble(&asm_source)?
    };
    if code.is_empty() {
        return Err("no instructions".to_string());
    }

    Ok(TestCase {
        code,
        mem: parse_mem_bytes(&mem_hex)?,
        result: (!result_text.is_empty())
            .then(|| parse_result(&result_text))
            .transpose()?,
        error: (!error.is_empty()).then_some(error),
    })
}

/// `-- raw` holds whole little-endian instruction words (`0x...` hex or decimal),
/// one or two per logical instruction (LDDW spans two).
fn parse_raw_words(words: &str) -> Result<Vec<u8>, String> {
    let mut code = Vec::new();
    for word in words.split_whitespace() {
        let value: u64 = match word.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| format!("bad raw word {word:?}: {e}"))?,
            None => word.parse().map_err(|e| format!("bad raw word {word:?}: {e}"))?,
        };
        code.extend_from_slice(&value.to_le_bytes());
    }
    Ok(code)
}

fn parse_mem_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex.split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).map_err(|e| format!("bad mem byte {byte:?}: {e}")))
        .collect()
}

fn parse_result(text: &str) -> Result<u64, String> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| format!("bad result {text:?}: {e}")),
        None => text.parse().map_err(|e| format!("bad result {text:?}: {e}")),
    }
}
