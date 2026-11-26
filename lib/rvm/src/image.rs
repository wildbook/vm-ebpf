//! Prepared programs.
//!
//! An [`Image`] is everything linking produces except runtime binding and allocation: the final code with every
//! relocation, CO-RE adjustment and jump table applied, the initial data, map declarations, exported functions, and the
//! call sites that bind to host and native functions, natives with the signature they were linked against.
//! [`crate::Vm::load_image`] binds those call sites in the loading VM, allocates memory and maps, maps the VM's shared
//! maps and regions, and returns a [`Program`].
//!
//! # Format
//!
//! Little endian. A header: `RVMI`, the format version as `u32`, and the version of rvm that wrote the image as a
//! string. Then seven sections, each a `u64` byte length and its contents: code, rodata, data, maps, functions,
//! externs, addresses.
//! A string is a `u32` length and UTF-8 bytes. An image loads only into the rvm version that wrote it. The code and
//! data hold link addresses (see [`crate::memory`]), which loading moves to guest addresses.

use std::sync::Arc;

use rvm_core::opcode::{call, MemMode, MemSize, OpCode, CALL, LD_IMM64};
use rvm_core::{Code, Instruction, NativeArg, NativeSig, MAX_CALL_DEPTH, MAX_NATIVE_ARGS};

use crate::error::{LinkError, Result, VmError};
use crate::helper::{HelperRegistry, SharedHelpers};
#[cfg(feature = "maps")]
use crate::layout::MAPS_REGION;
use crate::layout::{DATA_REGION, RODATA_REGION, STACK_REGION};
use crate::map_def::{MapDef, MapKind};
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{region_tag, MemoryBudget, Perms, VmMemory, MAX_REGION_LEN};
use crate::program::{Borrow, FunctionInfo, Functions, Program};
use crate::vm::{Shared, VmConfig};

const MAGIC: &[u8; 4] = b"RVMI";
const FORMAT_VERSION: u32 = 3;
const RVM_VERSION: &str = env!("CARGO_PKG_VERSION");

// tag bytes of the `MapKind`, `Import` and `Site` variants
const MAP_ARRAY: u8 = 0;
const MAP_HASH: u8 = 1;
const IMPORT_NAME: u8 = 0;
const IMPORT_HELPER: u8 = 1;
const IMPORT_NATIVE: u8 = 2;
const ARG_INT: u8 = 0;
const ARG_READ: u8 = 1;
const ARG_WRITE: u8 = 2;
const SITE_CODE: u8 = 0;
const SITE_RODATA: u8 = 1;
const SITE_DATA: u8 = 2;

/// Size of an instruction in bytes.
pub const INSN_SIZE: u64 = size_of::<Instruction>() as u64;

/// A linked program, ready to load into a [`crate::Vm`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    /// Instructions, [`INSN_SIZE`] bytes each.
    pub code: Vec<u8>,
    /// Initial bytes of the `.rodata` region; the rest of its `rodata_len` bytes are zero.
    pub rodata: Vec<u8>,
    /// Size of the `.rodata` region in bytes.
    pub rodata_len: usize,
    /// Initial bytes of the `.data` and `.bss` region; the rest of its `data_len` bytes are zero.
    pub data: Vec<u8>,
    /// Size of the `.data` and `.bss` region in bytes.
    pub data_len: usize,
    /// Maps in handle order: the `lddw` that loads a map holds its index here.
    pub maps: Vec<MapDef>,
    /// Exported functions, sorted by name.
    pub functions: Vec<(String, FunctionInfo)>,
    /// Call instructions, by index, that bind to a host function at load time.
    pub externs: Vec<(u32, Import)>,
    /// The link addresses of `.rodata` and `.data` bytes in the code and data, which loading moves to the guest
    /// addresses of those bytes.
    pub addresses: Vec<Address>,
}

/// The host function an extern call binds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    /// A function registered by name, such as a plugin export.
    Name(String),
    /// A helper registered by ID.
    Helper(u32),
    /// A native function registered by name, with the signature it had where the image was linked.
    Native { name: String, sig: NativeSig },
}

/// A link address in an image: `region_tag(region)` plus an offset that an addend may take past the region's ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    /// Where the address is.
    pub at: Site,
    /// The region it points into, [`RODATA_REGION`] or [`DATA_REGION`].
    pub region: usize,
}

/// Where an image holds an [`Address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// The immediate of the `lddw` at this instruction index.
    Code(u32),
    /// The 8 bytes at this offset into `.rodata`.
    RoData(u32),
    /// The 8 bytes at this offset into `.data`.
    Data(u32),
}

impl Image {
    /// An image of raw bytecode whose only function, `main`, spans all of `code` from its first instruction.
    pub fn from_code(code: Vec<u8>) -> Image {
        let main = FunctionInfo {
            pc: 0,
            size: code.len() as u64,
            borrows: Vec::new(),
        };
        Image {
            code,
            functions: vec![("main".into(), main)],
            ..Image::default()
        }
    }

    /// Each `call <helper id>` in the code, as its instruction index and the helper ID. Linking records these as
    /// [`Import::Helper`] externs.
    pub fn helper_calls(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        helper_calls(&self.code)
    }

    /// Serialize the image for [`crate::Vm::load_image`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer(Vec::new());
        w.0.extend_from_slice(MAGIC);
        w.u32(FORMAT_VERSION);
        w.str(RVM_VERSION);

        w.section(|w| w.0.extend_from_slice(&self.code));
        w.section(|w| {
            w.u64(self.rodata_len as u64);
            w.0.extend_from_slice(&self.rodata);
        });
        w.section(|w| {
            w.u64(self.data_len as u64);
            w.0.extend_from_slice(&self.data);
        });
        w.section(|w| {
            w.u32(self.maps.len() as u32);
            for def in &self.maps {
                w.str(&def.name);
                w.0.push(match def.kind {
                    MapKind::Array => MAP_ARRAY,
                    MapKind::Hash => MAP_HASH,
                });
                w.u32(def.key_size);
                w.u32(def.value_size);
                w.u32(def.max_entries);
            }
        });
        w.section(|w| {
            w.u32(self.functions.len() as u32);
            for (name, info) in &self.functions {
                w.str(name);
                w.u64(info.pc);
                w.u64(info.size);
                w.0.push(info.borrows.len() as u8);
                for borrow in &info.borrows {
                    w.0.extend_from_slice(&[borrow.arg, borrow.len_arg, borrow.writable.into()]);
                }
            }
        });
        w.section(|w| {
            w.u32(self.externs.len() as u32);
            for (at, import) in &self.externs {
                w.u32(*at);
                match import {
                    Import::Name(name) => {
                        w.0.push(IMPORT_NAME);
                        w.str(name);
                    }
                    Import::Helper(id) => {
                        w.0.push(IMPORT_HELPER);
                        w.u32(*id);
                    }
                    Import::Native { name, sig } => {
                        w.0.push(IMPORT_NATIVE);
                        w.str(name);
                        w.0.push(sig.args());
                        for n in 1..=sig.args() {
                            let (kind, len) = match sig.arg(n) {
                                Some(NativeArg::Read(len)) => (ARG_READ, len),
                                Some(NativeArg::Write(len)) => (ARG_WRITE, len),
                                _ => (ARG_INT, None),
                            };
                            w.0.extend_from_slice(&[kind, len.unwrap_or(0)]);
                        }
                    }
                }
            }
        });
        w.section(|w| {
            w.u32(self.addresses.len() as u32);
            for address in &self.addresses {
                let (kind, at) = match address.at {
                    Site::Code(at) => (SITE_CODE, at),
                    Site::RoData(at) => (SITE_RODATA, at),
                    Site::Data(at) => (SITE_DATA, at),
                };
                w.0.push(kind);
                w.u32(at);
                w.0.push(address.region as u8);
            }
        });
        w.0
    }

    /// Parse an image written by [`Image::to_bytes`]. Contents are checked when the image is loaded.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = Sections::parse(bytes)?;
        Ok(Self {
            code: s.code.to_vec(),
            rodata: s.rodata.to_vec(),
            rodata_len: s.rodata_len,
            data: s.data.to_vec(),
            data_len: s.data_len,
            maps: s.maps,
            functions: s.functions,
            externs: s.externs,
            addresses: s.addresses,
        })
    }
}

/// An [`Image`] whose code and initial data borrow from the image or from its serialized bytes, so loading copies them
/// once, into the program.
struct Sections<'a> {
    code: &'a [u8],
    rodata: &'a [u8],
    rodata_len: usize,
    data: &'a [u8],
    data_len: usize,
    maps: Vec<MapDef>,
    functions: Vec<(String, FunctionInfo)>,
    externs: Vec<(u32, Import)>,
    addresses: Vec<Address>,
}

impl<'a> Sections<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(invalid("not an rvm image"));
        }
        let format = r.u32()?;
        let version = r.str()?;
        if format != FORMAT_VERSION || version != RVM_VERSION {
            return Err(invalid(format!(
                "written by rvm {version} (format {format}), this is rvm {RVM_VERSION} (format {FORMAT_VERSION})"
            )));
        }

        let code = r.section()?.0;
        let (rodata, rodata_len) = r.section()?.segment()?;
        let (data, data_len) = r.section()?.segment()?;

        let mut s = r.section()?;
        let mut maps = Vec::new();
        for _ in 0..s.u32()? {
            let name = s.str()?;
            let kind = match s.u8()? {
                MAP_ARRAY => MapKind::Array,
                MAP_HASH => MapKind::Hash,
                kind => return Err(invalid(format!("map {name}: unknown kind {kind}"))),
            };
            maps.push(MapDef {
                name,
                kind,
                key_size: s.u32()?,
                value_size: s.u32()?,
                max_entries: s.u32()?,
            });
        }
        s.end()?;

        let mut s = r.section()?;
        let mut functions = Vec::new();
        for _ in 0..s.u32()? {
            let name = s.str()?;
            let (pc, size) = (s.u64()?, s.u64()?);
            let mut borrows = Vec::new();
            for _ in 0..s.u8()? {
                let [arg, len_arg, writable] = s.array()?;
                let writable = writable != 0;
                borrows.push(Borrow { arg, len_arg, writable });
            }
            functions.push((name, FunctionInfo { pc, size, borrows }));
        }
        s.end()?;

        let mut s = r.section()?;
        let mut externs = Vec::new();
        for _ in 0..s.u32()? {
            let at = s.u32()?;
            let import = match s.u8()? {
                IMPORT_NAME => Import::Name(s.str()?),
                IMPORT_HELPER => Import::Helper(s.u32()?),
                IMPORT_NATIVE => {
                    let name = s.str()?;
                    let sig = s.native_sig(&name)?;
                    Import::Native { name, sig }
                }
                kind => return Err(invalid(format!("extern at instruction {at}: unknown kind {kind}"))),
            };
            externs.push((at, import));
        }
        s.end()?;

        let mut s = r.section()?;
        let mut addresses = Vec::new();
        for _ in 0..s.u32()? {
            let (kind, at) = (s.u8()?, s.u32()?);
            let at = match kind {
                SITE_CODE => Site::Code(at),
                SITE_RODATA => Site::RoData(at),
                SITE_DATA => Site::Data(at),
                kind => return Err(invalid(format!("address site of unknown kind {kind}"))),
            };
            addresses.push(Address {
                at,
                region: s.u8()?.into(),
            });
        }
        s.end()?;
        r.end()?;

        Ok(Self {
            code,
            rodata,
            rodata_len,
            data,
            data_len,
            maps,
            functions,
            externs,
            addresses,
        })
    }
}

/// Check `image`, bind its extern calls to `helpers`, and allocate its memory and maps.
pub fn load(image: Image, helpers: &Arc<SharedHelpers>, shared: &Shared, config: &VmConfig) -> Result<Program> {
    let Image {
        code,
        rodata,
        rodata_len,
        data,
        data_len,
        maps,
        functions,
        externs,
        addresses,
    } = image;
    let sections = Sections {
        code: &code,
        rodata: &rodata,
        rodata_len,
        data: &data,
        data_len,
        maps,
        functions,
        externs,
        addresses,
    };
    load_sections(sections, helpers, shared, config)
}

/// [`load`] the image that [`Image::to_bytes`] wrote to `bytes`.
pub fn load_bytes(bytes: &[u8], helpers: &Arc<SharedHelpers>, shared: &Shared, config: &VmConfig) -> Result<Program> {
    load_sections(Sections::parse(bytes)?, helpers, shared, config)
}

fn load_sections(s: Sections<'_>, helpers: &Arc<SharedHelpers>, shared: &Shared, config: &VmConfig) -> Result<Program> {
    #[cfg(not(feature = "maps"))]
    if let Some(def) = s.maps.first() {
        let msg = format!("map {}: rvm is built without the `maps` feature", def.name);
        return Err(LinkError::InvalidMap(msg).into());
    }

    check_lengths(&s)?;
    let stack_len = stack_len(config)?;
    let mut budget = MemoryBudget::new(config.memory_limit);
    for len in [s.code.len() as u64, stack_len, s.rodata_len as u64, s.data_len as u64] {
        budget.take(len)?;
    }
    #[cfg(feature = "maps")]
    let (mut maps, maps_len) = Maps::new(s.maps, &shared.maps, &mut budget)?;

    let mut insns = Instruction::decode(s.code);
    check_stack_arguments(&insns, &s.functions)?;
    // Bind against one version of the table; the program refreshes from there.
    let snapshot = helpers.snapshot();
    bind_helper_calls(&mut insns, s.code, &snapshot.table);
    let natives = bind_externs(&mut insns, &s.externs, &snapshot.table)?;
    let functions = check_functions(s.functions, insns.len() as u64)?;

    let mut memory = VmMemory::with_passthrough(config.passthrough);
    let stack_top = memory.map_any(STACK_REGION, stack_len as usize, Perms::RW)? + stack_len;
    memory.map_bytes_any(RODATA_REGION, s.rodata, s.rodata_len, Perms::R)?;
    memory.map_bytes_any(DATA_REGION, s.data, s.data_len, Perms::RW)?;
    #[cfg(feature = "maps")]
    if maps_len != 0 {
        memory.map_any(MAPS_REGION, maps_len, Perms::RW)?;
    }
    // SAFETY: the callers of `Vm::share_map`/`Vm::share_region` accepted the `Vm::share_region` contract.
    unsafe {
        #[cfg(feature = "maps")]
        for map in maps.shared() {
            memory.map_shared(map.region, map.storage.clone(), Perms::RW);
        }
        shared.regions.map_into(&mut memory);
    }
    #[cfg(feature = "maps")]
    maps.locate(&memory);
    relocate(&s.addresses, &mut insns, &mut memory)?;

    let mut code = Code::new(insns);
    // tagged pointers resolve to host addresses before the call; untagged ones are host addresses already
    let tagged = !config.passthrough.is_untagged();
    for (at, index, sig) in natives {
        let checked = tagged && sig.has_pointers();
        // SAFETY: `bind_externs` checked that the native at `index` has the signature `sig`, which a native keeps in
        // every later table the program refreshes to. `Vm::register_native` vouches for the function.
        if !unsafe { code.bind_native(at as usize, index, sig.args(), checked) } {
            return Err(invalid(format!("native call at instruction {at} is not a valid call")));
        }
    }
    let program = Program::new(code, memory, stack_top, functions, helpers.clone(), snapshot, config);
    #[cfg(feature = "maps")]
    let program = program.with_maps(maps);
    Ok(program)
}

/// Move each of `addresses` from its link address to the guest address of the same byte in `memory`, where the
/// regions they point into are mapped.
fn relocate(addresses: &[Address], insns: &mut [Instruction], memory: &mut VmMemory) -> Result<()> {
    // the immediate of an instruction
    const IMM: u64 = 0xFFFF_FFFF << 32;

    for &Address { at, region } in addresses {
        let bad = || invalid(format!("address at {at:?} into region {region}"));
        if region != RODATA_REGION && region != DATA_REGION {
            return Err(bad());
        }
        let base = memory.region_base(region);
        let guest = |link: u64| base.wrapping_add(link.wrapping_sub(region_tag(region)));
        match at {
            Site::Code(at) => {
                let at = at as usize;
                let [lo, hi] = insns.get_mut(at..at + 2).ok_or_else(bad)? else {
                    unreachable!("two instructions")
                };
                if lo.byte() != LD_IMM64 {
                    return Err(bad());
                }
                let addr = guest((lo.0 >> 32) | (hi.0 & IMM));
                lo.0 = lo.0 & !IMM | addr << 32;
                hi.0 = hi.0 & !IMM | addr & IMM;
            }
            Site::RoData(offset) | Site::Data(offset) => {
                let in_region = match at {
                    Site::RoData(_) => RODATA_REGION,
                    _ => DATA_REGION,
                };
                let site = memory.region_base(in_region) + u64::from(offset);
                let addr = guest(memory.read(site).map_err(|_| bad())?);
                memory.write(site, addr).map_err(|_| bad())?;
            }
        }
    }
    Ok(())
}

/// Fails unless the code is whole instructions and the code and the initial data fit their regions.
fn check_lengths(s: &Sections<'_>) -> Result<()> {
    if !s.code.len().is_multiple_of(8) {
        return Err(invalid(format!("code is {} bytes", s.code.len())));
    }
    for (region, init, len) in [
        ("code", s.code, s.code.len()),
        ("rodata", s.rodata, s.rodata_len),
        ("data", s.data, s.data_len),
    ] {
        if len > MAX_REGION_LEN {
            return Err(VmError::ProgramTooLarge(region));
        }
        if init.len() > len {
            return Err(invalid(format!("{} initial bytes in a {len} byte {region} region", init.len())));
        }
    }
    Ok(())
}

/// Fails if `insns` pass or take an argument on the stack as clang does from the sixth argument register on: with an
/// 8-byte store to `r11 - 8k` or an 8-byte load from `r11 + 8k`. rvm has no stack arguments. To the interpreter r11
/// is a register like r12 to r15, 0 unless the program sets it, and such an access would fault only when it runs.
fn check_stack_arguments(insns: &[Instruction], functions: &[(String, FunctionInfo)]) -> Result<()> {
    const R11: u8 = 11;
    const LDX_DW: u8 = OpCode::ldx(MemSize::DWord, MemMode::Mem).0;
    const ST_DW: u8 = OpCode::st(MemSize::DWord, MemMode::Mem).0;
    const STX_DW: u8 = OpCode::stx(MemSize::DWord, MemMode::Mem).0;

    let slot = |offset: i16| offset % 8 == 0;
    let stack_argument = |insn: &Instruction| match insn.byte() {
        LDX_DW => insn.src_reg() == R11 && insn.offset() > 0 && slot(insn.offset()),
        ST_DW | STX_DW => insn.dst_reg() == R11 && insn.offset() < 0 && slot(insn.offset()),
        _ => false,
    };
    let Some(pc) = insns.iter().position(stack_argument) else {
        return Ok(());
    };

    let pc = pc as u64;
    let function = functions
        .iter()
        .find(|(_, info)| pc >= info.pc && pc - info.pc < info.size / INSN_SIZE)
        .map(|(name, _)| name.clone());
    Err(LinkError::StackArguments { pc, function }.into())
}

/// Turn each `call <helper id>` in `code` whose helper `table` has into a call to its slot, as linking does, so the
/// call skips the lookup by ID. Calls to IDs the table lacks keep looking the helper up when they run.
fn bind_helper_calls(insns: &mut [Instruction], code: &[u8], table: &HelperRegistry) {
    for (at, id) in helper_calls(code) {
        if let Some(slot) = table.slot_of_id(id) {
            bind_call(&mut insns[at as usize], slot);
        }
    }
}

/// Turn each extern call in `insns` into a call to the slot of its import in `table`, but for native imports, which
/// it checks against `table` and returns as their instruction index, native index and signature.
fn bind_externs(
    insns: &mut [Instruction],
    externs: &[(u32, Import)],
    table: &HelperRegistry,
) -> Result<Vec<(u32, u32, NativeSig)>> {
    let mut natives = Vec::new();
    for (at, import) in externs {
        let insn = insns
            .get_mut(*at as usize)
            .filter(|insn| insn.byte() == CALL)
            .ok_or_else(|| invalid(format!("extern at instruction {at} is not a call")))?;
        let slot = match import {
            Import::Name(name) => table
                .slot_of_name(name)
                .ok_or_else(|| LinkError::UnresolvedSymbol(name.clone()))?,
            Import::Helper(id) => table.slot_of_id(*id).ok_or(LinkError::UnknownHelper(*id))?,
            Import::Native { name, sig } => {
                let (index, host) = table
                    .native(name)
                    .ok_or_else(|| LinkError::UnresolvedSymbol(name.clone()))?;
                check_native(name, *sig, host)?;
                natives.push((*at, index, *sig));
                continue;
            }
        };
        bind_call(insn, slot);
    }
    Ok(natives)
}

/// Fails unless `linked`, the signature an image recorded for the native `name`, is `host`, the loading VM's.
fn check_native(name: &str, linked: NativeSig, host: NativeSig) -> Result<()> {
    if linked.args() != host.args() {
        let (name, declared, host) = (name.to_string(), usize::from(linked.args()), host.args());
        return Err(LinkError::SignatureMismatch { name, declared, host }.into());
    }
    if linked != host {
        let reason = "the image was linked against other pointer arguments".to_string();
        return Err(LinkError::NativeMismatch {
            name: name.to_string(),
            reason,
        }
        .into());
    }
    Ok(())
}

/// The function table of `functions`, in code of `insn_count` instructions.
fn check_functions(functions: Vec<(String, FunctionInfo)>, insn_count: u64) -> Result<Functions> {
    for (name, info) in &functions {
        // Each borrow maps its own region, so the pointer parameters must differ. A call rewrites each pointer
        // parameter as it maps it, so none may also hold a length.
        let borrows = &info.borrows;
        let distinct = borrows
            .iter()
            .enumerate()
            .all(|(i, b)| borrows[..i].iter().all(|o| o.arg != b.arg));
        let lengths_apart = borrows.iter().all(|b| borrows.iter().all(|o| o.arg != b.len_arg));
        if info.pc >= insn_count || !borrows.iter().all(Borrow::in_range) || !distinct || !lengths_apart {
            return Err(invalid(format!("function {name}: entry or borrows out of range")));
        }
    }
    Functions::new(functions).ok_or_else(|| invalid("functions are not sorted by unique name"))
}

/// Length of the stack region: one frame per call level.
fn stack_len(config: &VmConfig) -> Result<u64> {
    config
        .frame_size
        .checked_mul(MAX_CALL_DEPTH as u64 + 1)
        .filter(|&len| len <= MAX_REGION_LEN as u64)
        .ok_or_else(|| {
            let frame_size = config.frame_size;
            let msg = format!("frame size {frame_size} makes the stack larger than {MAX_REGION_LEN} bytes");
            VmError::InvalidArgument(msg)
        })
}

/// Each `call <helper id>` in `code`, as its instruction index and the helper ID.
fn helper_calls(code: &[u8]) -> impl Iterator<Item = (u32, u32)> + '_ {
    let insns = code.as_chunks::<8>().0;
    let mut i = 0;
    std::iter::from_fn(move || {
        while let Some(insn) = insns.get(i) {
            let at = i as u32;
            // the second slot of an `lddw` holds immediate bits, not an instruction
            i += if insn[0] == LD_IMM64 { 2 } else { 1 };
            if insn[0] == CALL && Instruction(u64::from_le_bytes(*insn)).src_reg() == 0 {
                return Some((at, imm(insn)));
            }
        }
        None
    })
}

/// Turn the call `insn` into a call to extern-table `slot`.
fn bind_call(insn: &mut Instruction, slot: u32) {
    let mut bytes = insn.0.to_le_bytes();
    set_slot_call(&mut bytes, slot);
    insn.0 = u64::from_le_bytes(bytes);
}

/// Turn a call instruction into a call to extern-table `slot`.
pub fn set_slot_call(insn: &mut [u8; 8], slot: u32) {
    insn[1] = (insn[1] & 0x0F) | (call::KFUNC << 4);
    set_imm(insn, slot);
}

/// The `imm` field of `insn`.
pub fn imm(insn: &[u8; 8]) -> u32 {
    let [.., a, b, c, d] = *insn;
    u32::from_le_bytes([a, b, c, d])
}

pub fn set_imm(insn: &mut [u8; 8], imm: u32) {
    insn[4..].copy_from_slice(&imm.to_le_bytes());
}

fn invalid(msg: impl Into<String>) -> VmError {
    VmError::InvalidImage(msg.into())
}

struct Writer(Vec<u8>);

impl Writer {
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }

    /// Write what `f` writes, prefixed with its length.
    fn section(&mut self, f: impl FnOnce(&mut Self)) {
        let at = self.0.len();
        self.u64(0);
        f(self);
        let len = (self.0.len() - at - 8) as u64;
        self.0[at..][..8].copy_from_slice(&len.to_le_bytes());
    }
}

/// Bounds-checked reads from untrusted bytes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n).ok_or_else(|| invalid("truncated"))?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("took N bytes"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_le_bytes)
    }

    fn len(&mut self) -> Result<usize> {
        usize::try_from(self.u64()?).map_err(|_| invalid("length out of range"))
    }

    fn str(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| invalid("string is not UTF-8"))
    }

    fn section(&mut self) -> Result<Self> {
        let len = self.len()?;
        Ok(Self(self.take(len)?))
    }

    /// A region's length followed by its initial bytes, filling the section.
    fn segment(mut self) -> Result<(&'a [u8], usize)> {
        let len = self.len()?;
        Ok((self.0, len))
    }

    fn end(&self) -> Result<()> {
        if !self.0.is_empty() {
            return Err(invalid(format!("{} unexpected bytes", self.0.len())));
        }
        Ok(())
    }

    /// The [`NativeSig`] of the native `name`, as [`Image::to_bytes`] writes it.
    fn native_sig(&mut self, name: &str) -> Result<NativeSig> {
        let args = self.u8()?;
        if usize::from(args) > MAX_NATIVE_ARGS {
            return Err(invalid(format!("native {name}: {args} arguments")));
        }
        let mut list = [NativeArg::Int; MAX_NATIVE_ARGS];
        for arg in &mut list[..usize::from(args)] {
            let [kind, len] = self.array()?;
            let len = (len != 0).then_some(len);
            *arg = match kind {
                ARG_INT => NativeArg::Int,
                ARG_READ => NativeArg::Read(len),
                ARG_WRITE => NativeArg::Write(len),
                kind => return Err(invalid(format!("native {name}: argument of unknown kind {kind}"))),
            };
        }
        let sig = NativeSig::try_new(&list[..usize::from(args)]);
        sig.ok_or_else(|| invalid(format!("native {name}: a length that isn't an integer argument")))
    }
}
