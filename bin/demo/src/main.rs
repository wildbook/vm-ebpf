//! Demo: Embeddable eBPF VM with BTF/CO-RE and Structured Logging
//!
//! This demo shows the correct CO-RE (Compile Once - Run Everywhere) workflow:
//!
//! 1. eBPF program is compiled with BTF describing types it *expects*
//! 2. Host application describes its *actual* struct layouts as BTF, with `BtfBuilder`
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
//! │  │ eBPF Program     │          │ Host BTF          │                │
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

use btf::{apply_core_relocations, Btf, BtfBuilder, CoreRelo, CoreReloKind};
use ebpf_asm::{Assembler, R0, R1, R2, R6};
use rvm::{Executor, HelperRegistry, VmMemory};

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

/// Build the target BTF for the host's actual `struct event` layout.
///
/// `fields` is `(name, byte offset, byte size)`; `size` is the struct's total size.
fn host_event(fields: &[(&str, u32, u32)], size: u32) -> Vec<u8> {
    let mut b = BtfBuilder::new();
    let s = b.add_struct("event", size);
    for &(name, offset, field_size) in fields {
        let int_ty = b.int(name, field_size, false);
        b.member(s, name, offset, int_ty);
    }
    b.encode()
}

/// Build minimal local BTF for a struct type: a single `BTF_KIND_STRUCT` with one
/// member per field, named so libbpf-style access strings resolve against it.
///
/// `fields` is `(name, byte size)`, laid out contiguously from offset 0. Returns the
/// encoded BTF, each field's libbpf access string offset ("0:<index>"), and the
/// access string offset for type-kind relocations (the literal `"0"`).
fn local_event_btf(struct_name: &str, fields: &[(&str, u32)]) -> (Vec<u8>, Vec<u32>, u32) {
    let mut b = BtfBuilder::new();
    let size: u32 = fields.iter().map(|(_, sz)| sz).sum();
    let s = b.add_struct(struct_name, size);

    let mut access_offs = Vec::with_capacity(fields.len());
    let mut offset = 0u32;
    for (i, &(name, field_size)) in fields.iter().enumerate() {
        let int_ty = b.int(name, field_size, false);
        b.member(s, name, offset, int_ty);
        // Libbpf access strings are always numeric index paths ("0:1" = member 1 of
        // the root), never bare field names.
        access_offs.push(b.string(&format!("0:{i}")));
        offset += field_size;
    }
    // Type-kind relocations (e.g. TYPE_SIZE) always use "0": the root type itself.
    let type_root_access = b.string("0");

    (b.encode(), access_offs, type_root_access)
}

// ============================================================================
// eBPF Program + BTF (using ebpf-asm and btf)
// ============================================================================

/// An eBPF program together with its local BTF and CO-RE relocations.
struct EbpfProgram {
    assembler: Assembler,
    /// Raw instructions as u64 values (populated by `finalize`).
    instructions: Vec<u64>,
    /// BTF data describing types the program expects.
    btf_data: Vec<u8>,
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

    /// Finalize assembly and store instructions and relocations.
    fn finalize(&mut self) -> Result<(), ebpf_asm::AsmError> {
        let result = self.assembler.assemble_with_core()?;
        self.instructions = result.instructions();
        self.relocations = result.relocations;
        Ok(())
    }
}

/// Apply `relos`, failing if any target is missing from the host. Returns the count.
fn relocate(insns: &mut [u64], local: &Btf, target: &Btf, relos: &[CoreRelo]) -> Result<usize, String> {
    match apply_core_relocations(insns, local, target, relos)
        .map_err(|e| e.to_string())?
        .first()
    {
        Some(u) => Err(format!("unresolved CO-RE relocation at {:#x}: {}", u.insn_off, u.error)),
        None => Ok(relos.len()),
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
/// whatever offset the host's BTF says.
fn build_core_demo_program() -> EbpfProgram {
    let mut prog = EbpfProgram::new();

    // Program expects struct event { timestamp(8), pid(4) }, i.e. pid at offset 8.
    let (btf_data, access_offs, _) = local_event_btf("event", &[("timestamp", 8), ("pid", 4)]);
    prog.btf_data = btf_data;
    let pid_access = access_offs[1];

    // === Program ===
    // r1 = pointer to event struct (passed as input)
    // This simulates: u32 pid = event->pid;

    // Instruction 0: r2 = *(u32*)(r1 + OFFSET)
    // The offset here (8) is what BPF *expects*, but CO-RE will patch it
    prog.assembler.ldxw(R2, R1, 8); // <-- This offset gets patched!
    prog.assembler
        .mark_core_relo(CoreReloKind::FieldByteOffset, 1, pid_access);

    // Save pid in a callee-saved register because the helper call clobbers r1-r5.
    prog.assembler.mov64(R6, R2);

    // Call print_u64(pid)
    prog.assembler.mov64(R1, R6);
    prog.assembler.call(helper_id::PRINT_U64 as i32);

    // r0 = pid (read back from the callee-saved register)
    prog.assembler.mov64(R0, R6);

    // exit
    prog.assembler.exit();

    prog.finalize().unwrap();
    prog
}

/// Patches the CO-RE program against two host layouts (one matching the program's
/// expectation, one where a field was inserted and `pid` moved) and runs the
/// patched program against the second layout's actual memory.
fn demo_core_relocation() -> Result<(), String> {
    println!("=== Demo: CO-RE Field Offset Relocation ===\n");

    let prog = build_core_demo_program();
    let btf = Btf::parse(&prog.btf_data).expect("BTF parse failed");

    println!("eBPF program expects (from BTF):");
    println!("  struct event {{ timestamp: 0, pid: 8 }}\n");

    let orig_offset = ((prog.instructions[0] >> 16) & 0xFFFF) as i16;
    println!("Before CO-RE relocation:");
    println!("  LDX instruction offset = {orig_offset} (expects pid at 8)\n");

    println!("--- Scenario 1: Host has same layout ---");
    {
        let host_bytes = host_event(&[("timestamp", 0, 8), ("pid", 8, 4)], 12);
        let target = Btf::parse(&host_bytes).unwrap();

        let mut insns = prog.instructions.clone();
        let applied = relocate(&mut insns, &btf, &target, &prog.relocations)?;

        let patched_off = ((insns[0] >> 16) & 0xFFFF) as i16;
        println!("  Host layout: event {{ timestamp: 0, pid: 8 }}");
        println!("  Applied {applied} relocation(s)");
        println!("  Patched off = {patched_off} (should be 8)");
        if patched_off != 8 {
            return Err(format!("scenario 1: expected patched offset 8, got {patched_off}"));
        }
    }

    println!("\n--- Scenario 2: Host added a field, pid moved! ---");
    let mut insns = prog.instructions.clone();
    let timestamp: u64 = 0x1234567890ABCDEF;
    let flags: u32 = 0xDEAD;
    let pid: u32 = 42;
    let host_bytes = host_event(&[("timestamp", 0, 8), ("flags", 8, 4), ("pid", 12, 4)], 16);
    let target = Btf::parse(&host_bytes).unwrap();

    let applied = relocate(&mut insns, &btf, &target, &prog.relocations)?;
    let patched_off = ((insns[0] >> 16) & 0xFFFF) as i16;
    println!("  Host layout: event {{ timestamp: 0, flags: 8, pid: 12 }}");
    println!("  Applied {applied} relocation(s)");
    println!("  Patched off = {patched_off} (should be 12!)");
    if patched_off != 12 {
        return Err(format!("scenario 2: expected patched offset 12, got {patched_off}"));
    }

    println!("\nRunning patched program against the host's actual memory layout...");
    let code = rvm::Code::new(insns.iter().map(|&i| rvm::Instruction(i)).collect::<Vec<_>>());

    let stack_size = 512;
    let mut mem = VmMemory::new();
    let stack_top = mem.map(rvm::STACK_REGION, stack_size, rvm::Perms::RW) + stack_size as u64;
    let event_ptr = mem.map(rvm::FIRST_FREE_REGION, 16, rvm::Perms::RW);
    mem.write(event_ptr, timestamp).unwrap();
    mem.write(event_ptr + 8, flags).unwrap();
    mem.write(event_ptr + 12, pid).unwrap();

    let helpers = build_helpers();
    let mut executor = Executor::new(&code, &mut mem, &helpers, stack_top);
    let result = executor
        .call(0, &[event_ptr])
        .map_err(|e| format!("execution failed: {e}"))?;

    println!("Program returned: {result}");
    if result != pid as u64 {
        return Err(format!("expected pid {pid}, got {result}"));
    }
    println!("SUCCESS: CO-RE correctly relocated pid offset from 8 to 12!\n");

    Ok(())
}

/// Demo: Field existence check
fn demo_field_exists() -> Result<(), String> {
    println!("=== Demo: CO-RE Field Existence Check ===\n");

    let mut prog = EbpfProgram::new();

    // Program checks for optional "debug_flags" field.
    let (btf_data, access_offs, _) = local_event_btf("event", &[("timestamp", 8), ("pid", 4), ("debug_flags", 4)]);
    prog.btf_data = btf_data;
    let debug_flags_access = access_offs[2];

    let mut missing = prog.assembler.create_label();

    // Instruction 0: r1 = FIELD_EXISTS (1 or 0)
    prog.assembler.mov64_imm(R1, 1); // placeholder: assume exists
    prog.assembler
        .mark_core_relo(CoreReloKind::FieldExists, 1, debug_flags_access);

    // if r1 == 0 goto missing
    prog.assembler.jeq_imm(R1, 0, &missing);

    // field exists path
    prog.assembler.mov64_imm(R0, 1);
    prog.assembler.exit();

    // field missing path
    prog.assembler.set_label(&mut missing).unwrap();
    prog.assembler.mov64_imm(R0, 0);
    prog.assembler.exit();

    prog.finalize().unwrap();

    let btf = Btf::parse(&prog.btf_data).expect("BTF parse failed");

    // Test 1: Host HAS the field
    println!("--- Scenario: Host HAS debug_flags ---");
    {
        let host_bytes = host_event(&[("timestamp", 0, 8), ("pid", 8, 4), ("debug_flags", 12, 4)], 16);
        let target = Btf::parse(&host_bytes).unwrap();

        let mut instrs = prog.instructions.clone();
        relocate(&mut instrs, &btf, &target, &prog.relocations)?;

        let exists_val = (instrs[0] >> 32) as i32;
        println!("  CO-RE patched FIELD_EXISTS = {exists_val}");
        println!("  Program would take 'field exists' path\n");
        if exists_val != 1 {
            return Err(format!("expected FIELD_EXISTS = 1 when the field is present, got {exists_val}"));
        }
    }

    // Test 2: Host does NOT have the field
    println!("--- Scenario: Host does NOT have debug_flags ---");
    {
        // No debug_flags!
        let host_bytes = host_event(&[("timestamp", 0, 8), ("pid", 8, 4)], 12);
        let target = Btf::parse(&host_bytes).unwrap();

        let mut instrs = prog.instructions.clone();
        relocate(&mut instrs, &btf, &target, &prog.relocations)?;

        let exists_val = (instrs[0] >> 32) as i32;
        println!("  CO-RE patched FIELD_EXISTS = {exists_val}");
        println!("  Program would take 'field missing' path\n");
        if exists_val != 0 {
            return Err(format!("expected FIELD_EXISTS = 0 when the field is missing, got {exists_val}"));
        }
    }

    Ok(())
}

/// Demo: Type size query
fn demo_type_size() -> Result<(), String> {
    println!("=== Demo: CO-RE Type Size Query ===\n");

    let mut prog = EbpfProgram::new();
    let (btf_data, _, type_access) = local_event_btf("event", &[("timestamp", 8), ("pid", 4)]);
    prog.btf_data = btf_data;

    // Instruction 0: r0 = sizeof(event) -- will be patched
    prog.assembler.mov64_imm(R0, 12); // BPF expects 12
    prog.assembler.mark_core_relo(CoreReloKind::TypeSize, 1, type_access);

    prog.assembler.exit();
    prog.finalize().unwrap();

    let btf = Btf::parse(&prog.btf_data).expect("BTF parse failed");

    // Host has larger struct
    let host_bytes = host_event(&[("timestamp", 0, 8), ("flags", 8, 4), ("pid", 12, 4), ("extra", 16, 8)], 24);
    let target = Btf::parse(&host_bytes).unwrap();

    let mut instrs = prog.instructions.clone();
    relocate(&mut instrs, &btf, &target, &prog.relocations)?;

    let size_val = (instrs[0] >> 32) as i32;
    println!("BPF program expected: sizeof(event) = 12");
    println!("Host actually has:    sizeof(event) = 24");
    println!("CO-RE patched:        r0 = {size_val}\n");
    if size_val != 24 {
        return Err(format!("expected CO-RE to patch sizeof(event) to 24, got {size_val}"));
    }
    Ok(())
}

// ============================================================================
// Main
// ============================================================================

fn main() -> Result<(), String> {
    println!("########################################################");
    println!("#  eBPF VM Demo: BTF/CO-RE Compile Once - Run Everywhere");
    println!("########################################################\n");

    demo_core_relocation()?;
    demo_field_exists()?;
    demo_type_size()?;

    println!("=== All demos complete ===");
    Ok(())
}
