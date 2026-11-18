//! Prepared programs.
//!
//! An [`Image`] is everything linking produces except runtime binding and allocation: the final code with every
//! relocation, CO-RE adjustment and jump table applied, the initial data, map declarations, exported functions, and the
//! call sites that bind to host functions. [`crate::Vm::load_image`] binds those call sites in the loading VM,
//! allocates memory and maps, maps the VM's shared maps and regions, and returns a [`Program`].
//!
//! # Format
//!
//! Little endian. A header: `RVMI`, the format version as `u32`, and the version of rvm that wrote the image as a
//! string. Then six sections, each a `u64` byte length and its contents: code, rodata, data, maps, functions, externs.
//! A string is a `u32` length and UTF-8 bytes. An image loads only into the rvm version that wrote it.

use std::sync::Arc;

use rvm_core::opcode::{JmpOpc, OpCode, Source};
use rvm_core::{Code, Instruction, BPF_PSEUDO_KFUNC_CALL, MAX_CALL_DEPTH};

use crate::error::{LinkError, Result, VmError};
use crate::helper::SharedHelpers;
#[cfg(feature = "maps")]
use crate::layout::MAPS_REGION;
use crate::layout::{DATA_REGION, RODATA_REGION, STACK_REGION};
use crate::map_def::{MapDef, MapKind};
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{Perms, VmMemory, MAX_REGION_LEN};
use crate::program::{Borrow, FunctionInfo, Functions, Program};
use crate::vm::{Shared, VmConfig};

const MAGIC: &[u8; 4] = b"RVMI";
const FORMAT_VERSION: u32 = 1;
const RVM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Opcode byte of `call`.
pub const CALL: u8 = OpCode::jmp64_from_parts(JmpOpc::Call, Source::Imm).0;

/// A linked program, ready to load into a [`crate::Vm`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    /// Instructions, 8 bytes each.
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
}

/// The host function an extern call binds to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    /// A function registered by name, such as a plugin export.
    Name(String),
    /// A helper registered by ID.
    Helper(u32),
}

impl Image {
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
                    MapKind::Array => 0,
                    MapKind::Hash => 1,
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
                        w.0.push(0);
                        w.str(name);
                    }
                    Import::Helper(id) => {
                        w.0.push(1);
                        w.u32(*id);
                    }
                }
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
                0 => MapKind::Array,
                1 => MapKind::Hash,
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
                0 => Import::Name(s.str()?),
                1 => Import::Helper(s.u32()?),
                kind => return Err(invalid(format!("extern at instruction {at}: unknown kind {kind}"))),
            };
            externs.push((at, import));
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

    let (words, rest) = s.code.as_chunks::<8>();
    if !rest.is_empty() {
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

    // room for the guard slot that `Code::new` appends
    let mut insns = Vec::with_capacity(words.len() + 1);
    insns.extend(words.iter().map(|w| Instruction(u64::from_le_bytes(*w))));
    // Bind against one version of the table; the program refreshes from there.
    let (table, version) = helpers.snapshot();
    for (at, import) in &s.externs {
        let insn = insns
            .get_mut(*at as usize)
            .filter(|insn| insn.opcode().0 == CALL)
            .ok_or_else(|| invalid(format!("extern at instruction {at} is not a call")))?;
        let slot = match import {
            Import::Name(name) => table
                .slot_of_name(name)
                .ok_or_else(|| LinkError::UnresolvedSymbol(name.clone()))?,
            Import::Helper(id) => table.slot_of_id(*id).ok_or(LinkError::UnknownHelper(*id))?,
        };
        let mut bytes = insn.0.to_le_bytes();
        set_slot_call(&mut bytes, slot);
        insn.0 = u64::from_le_bytes(bytes);
    }

    let insn_count = insns.len() as u64;
    for (name, info) in &s.functions {
        // each borrow maps its own region, so the pointer parameters must differ
        let borrows = &info.borrows;
        let distinct = borrows
            .iter()
            .enumerate()
            .all(|(i, b)| borrows[..i].iter().all(|o| o.arg != b.arg));
        if info.pc >= insn_count || !borrows.iter().all(Borrow::in_range) || !distinct {
            return Err(invalid(format!("function {name}: entry or borrows out of range")));
        }
    }
    let functions = Functions::new(s.functions).ok_or_else(|| invalid("functions are not sorted by unique name"))?;

    let stack_len = config
        .frame_size
        .checked_mul(MAX_CALL_DEPTH as u64 + 1)
        .filter(|&len| len <= MAX_REGION_LEN as u64)
        .ok_or_else(|| {
            let frame_size = config.frame_size;
            let msg = format!("frame size {frame_size} makes the stack larger than {MAX_REGION_LEN} bytes");
            VmError::InvalidArgument(msg)
        })?;

    #[cfg(feature = "maps")]
    let (maps, maps_len) = Maps::new(s.maps, &shared.maps)?;

    let mut memory = VmMemory::new();
    let stack_top = memory.map_any(STACK_REGION, stack_len as usize, Perms::RW) + stack_len;
    memory.map_bytes_any(RODATA_REGION, s.rodata, s.rodata_len, Perms::R);
    memory.map_bytes_any(DATA_REGION, s.data, s.data_len, Perms::RW);
    #[cfg(feature = "maps")]
    if maps_len != 0 {
        memory.map_any(MAPS_REGION, maps_len, Perms::RW);
    }
    // SAFETY: the callers of `Vm::share_map`/`Vm::share_region` accepted the `Vm::share_region` contract.
    unsafe {
        #[cfg(feature = "maps")]
        for map in maps.shared() {
            memory.map_shared(map.region, map.storage.clone(), Perms::RW);
        }
        shared.regions.map_into(&mut memory);
    }

    let helpers = (helpers.clone(), table, version);
    let program = Program::new(Code::new(insns), memory, stack_top, functions, helpers, config);
    #[cfg(feature = "maps")]
    let program = program.with_maps(maps);
    Ok(program)
}

/// Turn a call instruction into a call to extern-table `slot`.
pub fn set_slot_call(insn: &mut [u8; 8], slot: u32) {
    insn[1] = (insn[1] & 0x0F) | (BPF_PSEUDO_KFUNC_CALL << 4);
    set_imm(insn, slot);
}

/// The `imm` field of `insn`.
#[cfg(feature = "link")]
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
}
