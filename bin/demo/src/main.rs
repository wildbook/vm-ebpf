//! Demo: Embeddable eBPF VM with BTF/CO-RE and Structured Logging
//!
//! This demo shows the correct CO-RE (Compile Once - Run Everywhere) workflow:
//!
//! 1. eBPF program is compiled with BTF describing types it *expects*
//! 2. Host application registers its *actual* struct layouts in TypeRegistry
//! 3. At load time, CO-RE relocations patch eBPF instructions to use host's offsets
//! 4. The patched program runs correctly against host's memory layout
//!
//! # The Problem CO-RE Solves
//!
//! ```text
//! eBPF program compiled expecting:     Host application actually has:
//!   struct event {                       struct event {
//!     u64 timestamp;  // offset 0          u64 timestamp;  // offset 0
//!     u32 pid;        // offset 8          u32 flags;      // offset 8  (new!)
//!   }                                      u32 pid;        // offset 12 (moved!)
//!                                        }
//!
//! Without CO-RE: Program reads offset 8, gets flags instead of pid - BUG!
//! With CO-RE:    Program's "read pid" patched to offset 12 - CORRECT!
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         LOAD TIME                                   │
//! │  ┌──────────────────┐          ┌──────────────────┐                │
//! │  │ eBPF Program     │          │ Host TypeRegistry │                │
//! │  │ + BTF (expected) │──────────│ (actual layout)   │                │
//! │  └────────┬─────────┘          └─────────┬────────┘                │
//! │           │                              │                          │
//! │           └──────────┬───────────────────┘                          │
//! │                      ▼                                              │
//! │           ┌──────────────────────┐                                  │
//! │           │ apply_core_relocations│                                  │
//! │           │ (patches instructions)│                                  │
//! │           └──────────┬───────────┘                                  │
//! │                      ▼                                              │
//! │           ┌──────────────────────┐                                  │
//! │           │ Patched eBPF Program │                                  │
//! │           └──────────────────────┘                                  │
//! └─────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         RUN TIME                                    │
//! │  ┌──────────────────┐     ┌─────────────────────────────────────┐  │
//! │  │ Patched Program  │────▶│ Correctly accesses host's structs   │  │
//! │  │ (offset=12)      │     │ even though compiled with offset=8  │  │
//! │  └──────────────────┘     └─────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```

use btf::{apply_core_relocations, Btf, CoreRelo, CoreReloKind};
use ebpf_asm::{Assembler, CoreReloKind as AsmReloKind, R0, R1, R2, R3, R6};
use rvm::{Executor, HelperRegistry, TypeRegistry, VmMemory};

// ============================================================================
// Host Helper Function IDs
// ============================================================================

mod helper_id {
    pub const PRINT_U64: u32 = 1;
}

// ============================================================================
// Helper Registration
// ============================================================================

/// Build the registry of host helper functions exposed to eBPF programs.
fn build_helpers() -> HelperRegistry {
    let mut helpers = HelperRegistry::new();
    helpers.register(helper_id::PRINT_U64, |val: u64| {
        println!("  [eBPF] print_u64: {val}");
        0u64
    });
    helpers
}

// ============================================================================
// eBPF Program + BTF Builder (using ebpf-asm)
// ============================================================================

/// Represents an eBPF program with its BTF metadata and CO-RE relocations.
struct EbpfProgram {
    /// The assembler used to build the program
    assembler: Assembler,
    /// Raw instructions as u64 values (populated after assemble)
    instructions: Vec<u64>,
    /// BTF data describing types the program expects
    btf_data: Vec<u8>,
    /// CO-RE relocations to apply (converted from assembler output)
    relocations: Vec<CoreRelo>,
}

impl EbpfProgram {
    fn new() -> Self {
        Self {
            assembler: Assembler::new(),
            instructions: Vec::new(),
            btf_data: Vec::new(),
            relocations: Vec::new(),
        }
    }

    /// Get the assembler for building the program.
    fn asm(&mut self) -> &mut Assembler {
        &mut self.assembler
    }

    /// Finalize assembly and store instructions + relocations.
    ///
    /// This assembles the program and converts the assembler's CO-RE
    /// relocations to btf::CoreRelo format.
    fn finalize(&mut self) -> Result<(), ebpf_asm::AsmError> {
        let result = self.assembler.assemble_with_core()?;
        self.instructions = result.instructions();

        // Convert ebpf_asm::CoreRelo -> btf::CoreRelo
        self.relocations = result
            .relocations
            .into_iter()
            .map(|r| CoreRelo {
                insn_off: r.insn_off,
                type_id: r.type_id,
                access_str_off: r.access_str_off,
                kind: match r.kind {
                    AsmReloKind::FieldByteOffset => CoreReloKind::FieldByteOffset,
                    AsmReloKind::FieldByteSize => CoreReloKind::FieldByteSize,
                    AsmReloKind::FieldExists => CoreReloKind::FieldExists,
                    AsmReloKind::FieldSigned => CoreReloKind::FieldSigned,
                    AsmReloKind::FieldLShiftU64 => CoreReloKind::FieldLShiftU64,
                    AsmReloKind::FieldRShiftU64 => CoreReloKind::FieldRShiftU64,
                    AsmReloKind::TypeIdLocal => CoreReloKind::TypeIdLocal,
                    AsmReloKind::TypeIdTarget => CoreReloKind::TypeIdTarget,
                    AsmReloKind::TypeExists => CoreReloKind::TypeExists,
                    AsmReloKind::TypeSize => CoreReloKind::TypeSize,
                    AsmReloKind::EnumvalExists => CoreReloKind::EnumvalExists,
                    AsmReloKind::EnumvalValue => CoreReloKind::EnumvalValue,
                    AsmReloKind::TypeMatches => CoreReloKind::TypeMatches,
                },
            })
            .collect();

        Ok(())
    }

    /// Build minimal BTF for a struct type.
    fn build_btf(&mut self, struct_name: &str, fields: &[(&str, u32)]) {
        // String table: "\0<struct>\0<field1>\0<field2>\0..."
        let mut strings = vec![0u8];
        let struct_name_off = strings.len() as u32;
        strings.extend_from_slice(struct_name.as_bytes());
        strings.push(0);

        let mut field_offs = Vec::new();
        for (name, _) in fields {
            field_offs.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }

        // Type section: struct type + members
        let mut types = Vec::new();
        let vlen = fields.len() as u32;
        let info = (4 << 24) | vlen; // kind=4 (struct)
        let struct_size: u32 = fields.iter().map(|(_, sz)| sz).sum();

        types.extend_from_slice(&struct_name_off.to_le_bytes());
        types.extend_from_slice(&info.to_le_bytes());
        types.extend_from_slice(&struct_size.to_le_bytes());

        let mut bit_offset = 0u32;
        for (i, (_, size)) in fields.iter().enumerate() {
            types.extend_from_slice(&field_offs[i].to_le_bytes());
            types.extend_from_slice(&1u32.to_le_bytes()); // type_id (dummy)
            types.extend_from_slice(&bit_offset.to_le_bytes());
            bit_offset += size * 8;
        }

        // Header
        let hdr_len = 24u32;
        let type_len = types.len() as u32;
        let str_len = strings.len() as u32;

        let mut btf = Vec::new();
        btf.extend_from_slice(&0xEB9F_u16.to_le_bytes()); // magic
        btf.push(1); // version
        btf.push(0); // flags
        btf.extend_from_slice(&hdr_len.to_le_bytes());
        btf.extend_from_slice(&0u32.to_le_bytes()); // type_off
        btf.extend_from_slice(&type_len.to_le_bytes());
        btf.extend_from_slice(&type_len.to_le_bytes()); // str_off = type_len
        btf.extend_from_slice(&str_len.to_le_bytes());
        btf.extend_from_slice(&types);
        btf.extend_from_slice(&strings);

        self.btf_data = btf;
    }

    /// Convert the raw u64 instructions to rvm's `Instruction` code slice.
    fn code(&self) -> Vec<rvm::Instruction> {
        self.instructions.iter().map(|&i| rvm::Instruction(i)).collect()
    }

    /// Get mutable access to instructions for relocation patching.
    fn instructions_mut(&mut self) -> &mut [u64] {
        &mut self.instructions
    }
}

// ============================================================================
// Demo: CO-RE Field Offset Relocation
// ============================================================================

/// Build a program that reads `event.pid` using CO-RE.
///
/// The program expects this struct layout (from BTF):
/// ```c
/// struct event {
///     u64 timestamp;  // offset 0, size 8
///     u32 pid;        // offset 8, size 4  <-- BPF expects pid here!
/// };
/// ```
///
/// The instruction that reads `pid` will be patched by CO-RE to use
/// whatever offset the host's TypeRegistry says.
fn build_core_demo_program() -> EbpfProgram {
    let mut prog = EbpfProgram::new();

    // Build BTF: program expects struct event { timestamp(8), pid(4) }
    // This means BPF code expects pid at offset 8
    prog.build_btf("event", &[("timestamp", 8), ("pid", 4)]);

    // BTF string table after building:
    // offset 0: ""
    // offset 1: "event"
    // offset 7: "timestamp"
    // offset 17: "pid"
    let pid_str_off = 17u32;

    // === Program ===
    // r1 = pointer to event struct (passed as input)
    // This simulates: u32 pid = event->pid;

    // Instruction 0: r2 = *(u32*)(r1 + OFFSET)
    // The offset here (8) is what BPF *expects*, but CO-RE will patch it
    prog.asm().ldxw(R2, R1, 8); // <-- This offset gets patched!
    prog.asm().mark_field_offset(1, pid_str_off);

    // Save pid in a callee-saved register because the helper call clobbers r1-r5.
    prog.asm().mov64(R6, R2);

    // Call print_u64(pid)
    prog.asm().mov64(R1, R6);
    prog.asm().call(helper_id::PRINT_U64 as i32);

    // r0 = pid (read back from the callee-saved register)
    prog.asm().mov64(R0, R6);

    // exit
    prog.asm().exit();

    prog.finalize().unwrap();
    prog
}

/// Demonstrates CO-RE patching when host has different struct layout.
fn demo_core_relocation() {
    println!("=== Demo: CO-RE Field Offset Relocation ===\n");

    // Build the eBPF program (expects pid at offset 8)
    let prog = build_core_demo_program();

    // Parse the program's BTF
    let btf = Btf::parse(&prog.btf_data).expect("BTF parse failed");

    println!("eBPF program expects (from BTF):");
    println!("  struct event {{ timestamp: 0, pid: 8 }}\n");

    // Show original instruction
    let orig_insn = prog.instructions[0];
    let orig_offset = ((orig_insn >> 16) & 0xFFFF) as i16;
    println!("Before CO-RE relocation:");
    println!("  LDX instruction offset = {orig_offset} (expects pid at 8)\n");

    // === Scenario 1: Host has SAME layout ===
    println!("--- Scenario 1: Host has same layout ---");
    {
        let mut registry = TypeRegistry::new();
        registry
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("pid", 8, 4) // Same offset as BPF expects
            .size(12);

        let mut prog_copy = prog.instructions.clone();
        let applied =
            apply_core_relocations(&mut prog_copy, &btf, &registry, &prog.relocations).expect("relocation failed");

        // LDX/STX relocations patch the instruction's `off` field, not `imm`.
        let patched_off = ((prog_copy[0] >> 16) & 0xFFFF) as i16;
        println!("  Host layout: event {{ timestamp: 0, pid: 8 }}");
        println!("  Applied {applied} relocation(s)");
        println!("  Patched off = {patched_off} (should be 8)");
    }

    // === Scenario 2: Host has DIFFERENT layout ===
    println!("\n--- Scenario 2: Host added a field, pid moved! ---");
    {
        let mut registry = TypeRegistry::new();
        registry
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("flags", 8, 4) // New field inserted!
            .field("pid", 12, 4) // pid moved to offset 12
            .size(16);

        let mut prog_copy = prog.instructions.clone();
        let applied =
            apply_core_relocations(&mut prog_copy, &btf, &registry, &prog.relocations).expect("relocation failed");

        let patched_off = ((prog_copy[0] >> 16) & 0xFFFF) as i16;
        println!("  Host layout: event {{ timestamp: 0, flags: 8, pid: 12 }}");
        println!("  Applied {applied} relocation(s)");
        println!("  Patched off = {patched_off} (should be 12!)");

        println!("\n  Running patched program...");
    }

    println!();
}

/// Build a program that correctly uses CO-RE with imm-based addressing.
///
/// Instead of: LDX r2, [r1 + offset]    (offset in instruction)
/// We do:      r3 = CO-RE_OFFSET; LDX r2, [r1 + r3]  (offset from imm)
fn build_correct_core_program() -> EbpfProgram {
    let mut prog = EbpfProgram::new();

    // BTF: program expects pid at offset 8
    prog.build_btf("event", &[("timestamp", 8), ("pid", 4)]);
    let pid_str_off = 17u32;

    // === Program ===
    // Input: r1 = pointer to event struct

    // Instruction 0: r3 = OFFSET (will be patched by CO-RE)
    prog.asm().mov64_imm(R3, 8); // r3 = 8 (placeholder)
    prog.asm().mark_field_offset(1, pid_str_off);

    // Instruction 1: r2 = r1 (copy base pointer)
    prog.asm().mov64(R2, R1);

    // Instruction 2: r2 += r3 (add offset)
    prog.asm().add64(R2, R3);

    // Instruction 3: r2 = *(u32*)(r2 + 0)
    prog.asm().ldxw(R2, R2, 0);

    // Save pid in a callee-saved register before the helper call clobbers r2.
    prog.asm().mov64(R6, R2);

    // Call print_u64(pid)
    prog.asm().mov64(R1, R6);
    prog.asm().call(helper_id::PRINT_U64 as i32);

    // r0 = pid (read back from the callee-saved register)
    prog.asm().mov64(R0, R6);

    // exit
    prog.asm().exit();

    prog.finalize().unwrap();
    prog
}

fn demo_full_core_execution() {
    println!("=== Demo: Full CO-RE Execution ===\n");

    let mut prog = build_correct_core_program();
    let btf_data = prog.btf_data.clone();
    let relocations = prog.relocations.clone();
    let btf = Btf::parse(&btf_data).expect("BTF parse failed");

    println!("eBPF program structure:");
    println!("  r3 = CO-RE_OFFSET  // patched at load time");
    println!("  r2 = r1 + r3       // compute field address");
    println!("  r2 = *(u32*)r2     // load field value");
    println!("  print_u64(r2)");
    println!("  return r2\n");

    // === Test with host layout where pid is at offset 12 ===
    println!("--- Host has: struct event {{ timestamp(0), flags(8), pid(12) }} ---\n");

    let mut registry = TypeRegistry::new();
    registry
        .register_struct("event")
        .field("timestamp", 0, 8)
        .field("flags", 8, 4)
        .field("pid", 12, 4)
        .size(16);

    // Apply CO-RE relocations
    let applied =
        apply_core_relocations(prog.instructions_mut(), &btf, &registry, &relocations).expect("relocation failed");

    println!("Applied {applied} CO-RE relocation(s)");

    // Check what got patched
    let patched_insn = prog.instructions[0];
    let patched_imm = (patched_insn >> 32) as i32;
    println!("Instruction 0 (MOV r3, imm): imm = {patched_imm} (pid offset)");

    // Build memory with event struct at a known location
    let stack_size = 512;
    let code = prog.code();

    // Write event struct with HOST's layout:
    // offset 0: timestamp = 0x1234567890ABCDEF
    // offset 8: flags = 0xDEAD
    // offset 12: pid = 42
    let timestamp: u64 = 0x1234567890ABCDEF;
    let flags: u32 = 0xDEAD;
    let pid: u32 = 42;

    let mut mem = VmMemory::new();
    let stack_top = mem.map(rvm::STACK_REGION, stack_size, rvm::Perms::RW) + stack_size as u64;
    let event_ptr = mem.map(rvm::FIRST_FREE_REGION, 16, rvm::Perms::RW);
    mem.write(event_ptr, timestamp).unwrap();
    mem.write(event_ptr + 8, flags).unwrap();
    mem.write(event_ptr + 12, pid).unwrap();

    println!("\nMemory layout at 0x{event_ptr:x}:");
    println!("  [0x{event_ptr:x}] timestamp = 0x{timestamp:016x}");
    let flags_addr = event_ptr + 8;
    let pid_addr = event_ptr + 12;
    println!("  [0x{flags_addr:x}] flags     = 0x{flags:08x}");
    println!("  [0x{pid_addr:x}] pid       = {pid}");

    // Run the program
    let helpers = build_helpers();
    let mut executor = Executor::new(&code, &mut mem, &helpers, stack_top);

    println!("\nExecuting eBPF program...");
    let result = executor.call(0, &[event_ptr]);

    match result {
        Ok(ret) => {
            println!("\nProgram returned: {ret}");
            let pid_u64 = pid as u64;
            if ret == pid_u64 {
                println!("SUCCESS: CO-RE correctly relocated pid offset from 8 to 12!");
            } else {
                println!("UNEXPECTED: Got {ret} but expected {pid}");
            }
        }
        Err(e) => println!("Error: {e}"),
    }

    println!();
}

/// Demo: Field existence check
fn demo_field_exists() {
    println!("=== Demo: CO-RE Field Existence Check ===\n");

    let mut prog = EbpfProgram::new();

    // BTF: program checks for optional "debug_flags" field
    prog.build_btf("event", &[("timestamp", 8), ("pid", 4), ("debug_flags", 4)]);
    // String offsets: "" (0), "event" (1), "timestamp" (7), "pid" (17), "debug_flags" (21)
    let debug_flags_off = 21u32;

    // Instruction 0: r1 = FIELD_EXISTS (1 or 0)
    prog.asm().mov64_imm(R1, 1); // placeholder: assume exists
    prog.asm().mark_field_exists(1, debug_flags_off);

    // Instruction 1: if r1 == 0 goto +2 (skip to return 0)
    prog.asm().raw(0x15, 1, 0, 2, 0); // jeq_imm r1, 0, +2

    // Instruction 2: r0 = 1 (field exists path)
    prog.asm().mov64_imm(R0, 1);

    // Instruction 3: exit
    prog.asm().exit();

    // Instruction 4: r0 = 0 (field missing path)
    prog.asm().mov64_imm(R0, 0);

    // Instruction 5: exit
    prog.asm().exit();

    prog.finalize().unwrap();

    let btf = Btf::parse(&prog.btf_data).expect("BTF parse failed");

    // Test 1: Host HAS the field
    println!("--- Scenario: Host HAS debug_flags ---");
    {
        let mut registry = TypeRegistry::new();
        registry
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("pid", 8, 4)
            .field("debug_flags", 12, 4)
            .size(16);

        let mut instrs = prog.instructions.clone();
        apply_core_relocations(&mut instrs, &btf, &registry, &prog.relocations).expect("relo failed");

        let exists_val = (instrs[0] >> 32) as i32;
        println!("  CO-RE patched FIELD_EXISTS = {exists_val}");
        println!("  Program would take 'field exists' path\n");
    }

    // Test 2: Host does NOT have the field
    println!("--- Scenario: Host does NOT have debug_flags ---");
    {
        let mut registry = TypeRegistry::new();
        registry
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("pid", 8, 4)
            // No debug_flags!
            .size(12);

        let mut instrs = prog.instructions.clone();
        apply_core_relocations(&mut instrs, &btf, &registry, &prog.relocations).expect("relo failed");

        let exists_val = (instrs[0] >> 32) as i32;
        println!("  CO-RE patched FIELD_EXISTS = {exists_val}");
        println!("  Program would take 'field missing' path\n");
    }
}

/// Demo: Type size query
fn demo_type_size() {
    println!("=== Demo: CO-RE Type Size Query ===\n");

    let mut prog = EbpfProgram::new();
    prog.build_btf("event", &[("timestamp", 8), ("pid", 4)]);

    // Instruction 0: r0 = sizeof(event) -- will be patched
    prog.asm().mov64_imm(R0, 12); // BPF expects 12
    prog.asm().mark_type_size(1);

    prog.asm().exit();
    prog.finalize().unwrap();

    let btf = Btf::parse(&prog.btf_data).expect("BTF parse failed");

    // Host has larger struct
    let mut registry = TypeRegistry::new();
    registry
        .register_struct("event")
        .field("timestamp", 0, 8)
        .field("flags", 8, 4)
        .field("pid", 12, 4)
        .field("extra", 16, 8)
        .size(24);

    let mut instrs = prog.instructions.clone();
    apply_core_relocations(&mut instrs, &btf, &registry, &prog.relocations).expect("relo failed");

    let size_val = (instrs[0] >> 32) as i32;
    println!("BPF program expected: sizeof(event) = 12");
    println!("Host actually has:    sizeof(event) = 24");
    println!("CO-RE patched:        r0 = {size_val}\n");
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    println!("########################################################");
    println!("#  eBPF VM Demo: BTF/CO-RE Compile Once - Run Everywhere");
    println!("########################################################\n");

    demo_core_relocation();
    demo_full_core_execution();
    demo_field_exists();
    demo_type_size();

    println!("=== All demos complete ===");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_relocation_patches_offset() {
        let mut prog = build_correct_core_program();
        let btf_data = prog.btf_data.clone();
        let relocations = prog.relocations.clone();
        let btf = Btf::parse(&btf_data).unwrap();

        let mut registry = TypeRegistry::new();
        registry
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("flags", 8, 4)
            .field("pid", 12, 4) // Moved from offset 8 to 12
            .size(16);

        apply_core_relocations(prog.instructions_mut(), &btf, &registry, &relocations).unwrap();

        // The MOV instruction's imm should be patched to 12
        let patched_imm = (prog.instructions[0] >> 32) as i32;
        assert_eq!(patched_imm, 12);
    }

    #[test]
    fn test_full_execution_with_core() {
        let mut prog = build_correct_core_program();
        let btf_data = prog.btf_data.clone();
        let relocations = prog.relocations.clone();
        let btf = Btf::parse(&btf_data).unwrap();

        let mut registry = TypeRegistry::new();
        registry
            .register_struct("event")
            .field("timestamp", 0, 8)
            .field("pid", 12, 4) // At offset 12
            .size(16);

        apply_core_relocations(prog.instructions_mut(), &btf, &registry, &relocations).unwrap();

        // Build memory
        let stack_size = 512;
        let code = prog.code();
        let pid: u32 = 999;

        let mut mem = VmMemory::new();
        let stack_top = mem.map(rvm::STACK_REGION, stack_size, rvm::Perms::RW) + stack_size as u64;
        let event_ptr = mem.map(rvm::FIRST_FREE_REGION, 16, rvm::Perms::RW);
        mem.write(event_ptr + 12, pid).unwrap();

        let helpers = build_helpers();
        let mut executor = Executor::new(&code, &mut mem, &helpers, stack_top);

        let result = executor.call(0, &[event_ptr]).unwrap();
        assert_eq!(result, 999);
    }
}
