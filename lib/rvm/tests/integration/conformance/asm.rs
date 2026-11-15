//! Minimal text assembler for the ubpf-style syntax the bpf_conformance suite's
//! `.data` files use (`mov32 %r0, 0`, `ldxb %r0, [%r1+0x2]`, `jgt %r1, 0x2, L3`, ...).
//!
//! Every instruction goes through [`ebpf_asm::Assembler`], so this module only
//! tokenizes lines and resolves jump targets; it never builds raw opcode bytes
//! itself. A jump target is either a label name or a `+N`/`-N` literal relative
//! offset (both forms appear in the suite); both resolve to a code slot index
//! up front, so a single `Label` per target slot covers either form. `exit` is
//! additionally bound to the slot of the first `exit` instruction, matching the
//! reference parser's implicit "default exit label" so branches to a bare
//! `exit` resolve without a `label:` line.

use std::collections::HashMap;

use ebpf_asm::{Assembler, Label, Register};

/// One parsed instruction line, in source order.
struct Insn {
    mnemonic: String,
    operands: Vec<String>,
    /// Code slot index (LDDW occupies two slots; every other instruction, one).
    slot: usize,
}

/// Assembles a `-- asm` section into eBPF bytecode.
pub fn assemble(source: &str) -> Result<Vec<u8>, String> {
    let (insns, label_slot) = parse_lines(source)?;
    let mut asm = Assembler::new();

    // Every slot a jump or local call targets needs one `Label`, created up front so
    // backward and forward references resolve the same way.
    let mut label_by_slot: HashMap<usize, Label> = HashMap::new();
    for insn in &insns {
        if let Some(target) = label_operand(insn, &label_slot)? {
            label_by_slot.entry(target).or_insert_with(|| asm.create_label());
        }
    }

    for insn in &insns {
        if let Some(label) = label_by_slot.get_mut(&insn.slot) {
            asm.set_label(label).map_err(|e| e.to_string())?;
        }
        emit(&mut asm, insn, &label_slot, &label_by_slot)?;
    }

    asm.assemble().map_err(|e| e.to_string())
}

/// Tokenizes `source` into instructions and resolves every label (including the
/// implicit `exit` one) to the slot of the instruction it precedes.
fn parse_lines(source: &str) -> Result<(Vec<Insn>, HashMap<String, usize>), String> {
    let mut insns = Vec::new();
    let mut pending_labels: Vec<String> = Vec::new();
    let mut label_slot = HashMap::new();
    let mut slot = 0;

    for line in source.lines() {
        // `bpf_conformance` strips `#` comments from every line before tokenizing.
        let line = line.split('#').next().unwrap_or("");
        let tokens: Vec<&str> = line.split_whitespace().map(|t| t.trim_end_matches(',')).collect();
        let Some((&head, rest)) = tokens.split_first() else {
            continue;
        };

        if let Some(name) = head.strip_suffix(':') {
            pending_labels.push(name.to_string());
            continue;
        }

        let mut operands: Vec<String> = rest.iter().map(|&s| s.to_string()).collect();
        // `call <id>` and `call local <label>` both parse to two operands; a bare
        // numeric or register target means the mode defaults to `helper`.
        if head == "call" && operands.len() == 1 {
            operands.insert(0, "helper".to_string());
        }

        for name in pending_labels.drain(..) {
            label_slot.insert(name, slot);
        }
        if head == "exit" {
            label_slot.entry("exit".to_string()).or_insert(slot);
        }

        insns.push(Insn {
            mnemonic: head.to_string(),
            operands,
            slot,
        });
        slot += if head == "lddw" { 2 } else { 1 };
    }

    Ok((insns, label_slot))
}

/// The target slot of `insn`'s jump/local-call operand, if it has one.
fn label_operand(insn: &Insn, label_slot: &HashMap<String, usize>) -> Result<Option<usize>, String> {
    let token = match insn.mnemonic.as_str() {
        "ja" | "ja32" => &insn.operands[0],
        "call" if insn.operands[0] == "local" => &insn.operands[1],
        m if is_jmp_base(strip32(m).0) => &insn.operands[2],
        _ => return Ok(None),
    };
    resolve_target(token, insn.slot, label_slot).map(Some)
}

/// A `+N`/`-N` literal resolves relative to the next slot, like a label would after
/// going through [`ebpf_asm::Assembler`]'s own offset math; a bare name looks up
/// `label_slot`.
fn resolve_target(token: &str, slot: usize, label_slot: &HashMap<String, usize>) -> Result<usize, String> {
    if token.starts_with(['+', '-']) {
        let offset = parse_number(token)?;
        usize::try_from(slot as i64 + 1 + offset).map_err(|_| format!("jump target before start of program: {token}"))
    } else {
        label_slot
            .get(token)
            .copied()
            .ok_or_else(|| format!("undefined label: {token}"))
    }
}

fn is_jmp_base(base: &str) -> bool {
    matches!(base, "jeq" | "jne" | "jgt" | "jge" | "jlt" | "jle" | "jset" | "jsgt" | "jsge" | "jslt" | "jsle")
}

/// Splits a trailing `32` width suffix off a mnemonic, e.g. `"jeq32"` -> `("jeq", true)`.
fn strip32(mnemonic: &str) -> (&str, bool) {
    match mnemonic.strip_suffix("32") {
        Some(base) => (base, true),
        None => (mnemonic, false),
    }
}

fn reg(token: &str) -> Result<Register, String> {
    let n: u8 = token
        .strip_prefix("%r")
        .ok_or_else(|| format!("expected a register, got {token:?}"))?
        .parse()
        .map_err(|_| format!("bad register {token:?}"))?;
    Register::from_u8(n).ok_or_else(|| format!("register out of range: {token:?}"))
}

/// Parses `[%rN+off]`, `[%rN-off]` or `[%rN]`.
fn mem(token: &str) -> Result<(Register, i16), String> {
    let inner = token
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected [reg+off], got {token:?}"))?;
    match inner.find(['+', '-']) {
        Some(at) => Ok((reg(&inner[..at])?, off16(&inner[at..])?)),
        None => Ok((reg(inner)?, 0)),
    }
}

/// Hex (`0x...`) is an unsigned bit pattern; decimal is signed. Both match the
/// reference assembler's `_decode_imm32`/`_decode_imm64`.
fn parse_number(token: &str) -> Result<i64, String> {
    let (negative, rest) = match token.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, token.strip_prefix('+').unwrap_or(token)),
    };
    let value: u64 = match rest.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex {token:?}: {e}"))?,
        None => rest.parse().map_err(|e| format!("bad number {token:?}: {e}"))?,
    };
    Ok(if negative {
        value.wrapping_neg() as i64
    } else {
        value as i64
    })
}

fn imm32(token: &str) -> Result<i32, String> {
    Ok(parse_number(token)? as i32)
}

fn imm64(token: &str) -> Result<i64, String> {
    parse_number(token)
}

fn off16(token: &str) -> Result<i16, String> {
    Ok(parse_number(token)? as i16)
}

/// Emits one register/immediate ALU method pair per base name, keyed by `(base, is32)`.
macro_rules! alu_dispatch {
    ($base:expr, $is32:expr, $asm:expr, $dst:expr, $src:expr;
     $( $name:literal: $m64:ident, $m64i:ident, $m32:ident, $m32i:ident );+ $(;)?) => {
        match ($base, $is32, $src) {
            $(
                ($name, false, Operand::Reg(r)) => { $asm.$m64($dst, r); }
                ($name, false, Operand::Imm(i)) => { $asm.$m64i($dst, i); }
                ($name, true, Operand::Reg(r)) => { $asm.$m32($dst, r); }
                ($name, true, Operand::Imm(i)) => { $asm.$m32i($dst, i); }
            )+
            _ => return Err(format!("unknown alu mnemonic: {}{}", $base, if $is32 { "32" } else { "" })),
        }
    };
}

/// Emits one register/immediate conditional jump method pair per base name.
macro_rules! jmp_dispatch {
    ($base:expr, $is32:expr, $asm:expr, $dst:expr, $src:expr, $label:expr;
     $( $name:literal: $m64:ident, $m64i:ident, $m32:ident, $m32i:ident );+ $(;)?) => {
        match ($base, $is32, $src) {
            $(
                ($name, false, Operand::Reg(r)) => { $asm.$m64($dst, r, $label); }
                ($name, false, Operand::Imm(i)) => { $asm.$m64i($dst, i, $label); }
                ($name, true, Operand::Reg(r)) => { $asm.$m32($dst, r, $label); }
                ($name, true, Operand::Imm(i)) => { $asm.$m32i($dst, i, $label); }
            )+
            _ => return Err(format!("unknown jump mnemonic: {}{}", $base, if $is32 { "32" } else { "" })),
        }
    };
}

/// Emits the non-fetch/fetch method pair per atomic op name, keyed by `(base, is32, fetch)`.
macro_rules! atomic_dispatch {
    ($base:expr, $is32:expr, $fetch:expr, $asm:expr, $dst:expr, $off:expr, $src:expr;
     $( $name:literal: $m64:ident, $m64f:ident, $m32:ident, $m32f:ident );+ $(;)?) => {
        match ($base, $is32, $fetch) {
            $(
                ($name, false, false) => { $asm.$m64($dst, $off, $src); }
                ($name, false, true) => { $asm.$m64f($dst, $off, $src); }
                ($name, true, false) => { $asm.$m32($dst, $off, $src); }
                ($name, true, true) => { $asm.$m32f($dst, $off, $src); }
            )+
            ("xchg", false, _) => { $asm.atomic_xchg64($dst, $off, $src); }
            ("xchg", true, _) => { $asm.atomic_xchg32($dst, $off, $src); }
            ("cmpxchg", false, _) => { $asm.atomic_cmpxchg64($dst, $off, $src); }
            ("cmpxchg", true, _) => { $asm.atomic_cmpxchg32($dst, $off, $src); }
            _ => return Err(format!("unknown atomic op: {}{}", $base, if $is32 { "32" } else { "" })),
        }
    };
}

/// A resolved ALU/jump source operand: a register or a sign-extended 32-bit immediate.
enum Operand {
    Reg(Register),
    Imm(i32),
}

fn operand(token: &str) -> Result<Operand, String> {
    if token.starts_with('%') {
        Ok(Operand::Reg(reg(token)?))
    } else {
        Ok(Operand::Imm(imm32(token)?))
    }
}

fn emit(
    asm: &mut Assembler,
    insn: &Insn,
    label_slot: &HashMap<String, usize>,
    label_by_slot: &HashMap<usize, Label>,
) -> Result<(), String> {
    let ops = &insn.operands;
    let label_operand = |token: &str| -> Result<&Label, String> {
        let target = resolve_target(token, insn.slot, label_slot)?;
        label_by_slot
            .get(&target)
            .ok_or_else(|| format!("no label created for slot {target}"))
    };

    match insn.mnemonic.as_str() {
        "exit" => {
            asm.exit();
        }
        "lddw" => {
            asm.lddw(reg(&ops[0])?, imm64(&ops[1])?);
        }
        "neg" => {
            asm.neg64(reg(&ops[0])?);
        }
        "neg32" => {
            asm.neg32(reg(&ops[0])?);
        }
        "le16" => {
            asm.le16(reg(&ops[0])?);
        }
        "le32" => {
            asm.le32(reg(&ops[0])?);
        }
        "le64" => {
            asm.le64(reg(&ops[0])?);
        }
        "be16" => {
            asm.be16(reg(&ops[0])?);
        }
        "be32" => {
            asm.be32(reg(&ops[0])?);
        }
        "be64" => {
            asm.be64(reg(&ops[0])?);
        }
        "swap16" | "bswap16" => {
            asm.bswap16(reg(&ops[0])?);
        }
        "swap32" | "bswap32" => {
            asm.bswap32(reg(&ops[0])?);
        }
        "swap64" | "bswap64" => {
            asm.bswap64(reg(&ops[0])?);
        }
        "movsx832" => {
            asm.movsx832(reg(&ops[0])?, reg(&ops[1])?);
        }
        "movsx1632" => {
            asm.movsx1632(reg(&ops[0])?, reg(&ops[1])?);
        }
        "movsx864" => {
            asm.movsx864(reg(&ops[0])?, reg(&ops[1])?);
        }
        "movsx1664" => {
            asm.movsx1664(reg(&ops[0])?, reg(&ops[1])?);
        }
        "movsx3264" => {
            asm.movsx3264(reg(&ops[0])?, reg(&ops[1])?);
        }
        "ldxdw" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxdw(reg(&ops[0])?, src, off);
        }
        "ldxw" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxw(reg(&ops[0])?, src, off);
        }
        "ldxh" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxh(reg(&ops[0])?, src, off);
        }
        "ldxb" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxb(reg(&ops[0])?, src, off);
        }
        "ldxsw" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxsw(reg(&ops[0])?, src, off);
        }
        "ldxsh" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxsh(reg(&ops[0])?, src, off);
        }
        "ldxsb" => {
            let (src, off) = mem(&ops[1])?;
            asm.ldxsb(reg(&ops[0])?, src, off);
        }
        "stdw" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stdw(dst, off, imm32(&ops[1])?);
        }
        "stw" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stw(dst, off, imm32(&ops[1])?);
        }
        "sth" => {
            let (dst, off) = mem(&ops[0])?;
            asm.sth(dst, off, imm32(&ops[1])?);
        }
        "stb" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stb(dst, off, imm32(&ops[1])?);
        }
        "stxdw" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stxdw(dst, off, reg(&ops[1])?);
        }
        "stxw" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stxw(dst, off, reg(&ops[1])?);
        }
        "stxh" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stxh(dst, off, reg(&ops[1])?);
        }
        "stxb" => {
            let (dst, off) = mem(&ops[0])?;
            asm.stxb(dst, off, reg(&ops[1])?);
        }
        "ja" => {
            asm.ja(label_operand(&ops[0])?);
        }
        "ja32" => {
            asm.ja32(label_operand(&ops[0])?);
        }
        "call" if ops[0] == "local" => {
            asm.call_local(label_operand(&ops[1])?);
        }
        "call" if ops[0] == "helper" => {
            if ops[1].starts_with('%') {
                return Err("register-indirect helper call is not supported".to_string());
            }
            asm.call(imm32(&ops[1])?);
        }
        "lock" => {
            let mut ops = ops.clone();
            if ops[0] != "fetch" {
                ops.insert(0, "no_fetch".to_string());
            }
            ops.swap(0, 1);
            let op_name = ops.remove(0);
            let fetch = ops.remove(0) == "fetch";
            let (dst, off) = mem(&ops[0])?;
            let src = reg(&ops[1])?;
            let (base, is32) = strip32(&op_name);
            atomic_dispatch!(base, is32, fetch, asm, dst, off, src;
                "add": atomic_add64, atomic_fetch_add64, atomic_add32, atomic_fetch_add32;
                "or": atomic_or64, atomic_fetch_or64, atomic_or32, atomic_fetch_or32;
                "and": atomic_and64, atomic_fetch_and64, atomic_and32, atomic_fetch_and32;
                "xor": atomic_xor64, atomic_fetch_xor64, atomic_xor32, atomic_fetch_xor32;
            );
        }
        mnemonic => {
            let (base, is32) = strip32(mnemonic);
            if is_jmp_base(base) {
                let dst = reg(&ops[0])?;
                let src = operand(&ops[1])?;
                let label = label_operand(&ops[2])?;
                jmp_dispatch!(base, is32, asm, dst, src, label;
                    "jeq": jeq, jeq_imm, jeq32, jeq32_imm;
                    "jne": jne, jne_imm, jne32, jne32_imm;
                    "jgt": jgt, jgt_imm, jgt32, jgt32_imm;
                    "jge": jge, jge_imm, jge32, jge32_imm;
                    "jlt": jlt, jlt_imm, jlt32, jlt32_imm;
                    "jle": jle, jle_imm, jle32, jle32_imm;
                    "jset": jset, jset_imm, jset32, jset32_imm;
                    "jsgt": jsgt, jsgt_imm, jsgt32, jsgt32_imm;
                    "jsge": jsge, jsge_imm, jsge32, jsge32_imm;
                    "jslt": jslt, jslt_imm, jslt32, jslt32_imm;
                    "jsle": jsle, jsle_imm, jsle32, jsle32_imm;
                );
                return Ok(());
            }
            let dst = reg(&ops[0])?;
            let src = operand(&ops[1])?;
            alu_dispatch!(base, is32, asm, dst, src;
                "add": add64, add64_imm, add32, add32_imm;
                "sub": sub64, sub64_imm, sub32, sub32_imm;
                "mul": mul64, mul64_imm, mul32, mul32_imm;
                "div": div64, div64_imm, div32, div32_imm;
                "sdiv": sdiv64, sdiv64_imm, sdiv32, sdiv32_imm;
                "or": or64, or64_imm, or32, or32_imm;
                "and": and64, and64_imm, and32, and32_imm;
                "lsh": lsh64, lsh64_imm, lsh32, lsh32_imm;
                "rsh": rsh64, rsh64_imm, rsh32, rsh32_imm;
                "mod": mod64, mod64_imm, mod32, mod32_imm;
                "smod": smod64, smod64_imm, smod32, smod32_imm;
                "xor": xor64, xor64_imm, xor32, xor32_imm;
                "mov": mov64, mov64_imm, mov32, mov32_imm;
                "arsh": arsh64, arsh64_imm, arsh32, arsh32_imm;
            );
        }
    }
    Ok(())
}
