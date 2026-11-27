//! Prepared programs.
//!
//! An [`Image`] is everything linking produces except runtime binding and allocation: the final code with every
//! relocation, CO-RE adjustment and jump table applied, the initial data, map declarations, exported functions,
//! deduplicated imports with their BTF prototypes, and the call sites that refer to them. [`crate::Vm::load_image`]
//! resolves and binds those imports in the loading VM, allocates memory and maps, maps the VM's shared maps and
//! regions, and returns a [`Program`].
//!
//! # Format
//!
//! Little endian. A header: `RVMI`, the format version as `u32`, and the version of rvm that wrote the image as a
//! string. Then eight sections, each a `u64` byte length and its contents: code, rodata, data, maps, functions,
//! imports, calls, addresses.
//! A string is a `u32` length and UTF-8 bytes. An image loads only into the rvm version that wrote it. The code and
//! data hold link addresses (see [`crate::memory`]), which loading moves to guest addresses.

use std::sync::Arc;

use rvm_core::opcode::{call, MemMode, MemSize, OpCode, CALL, LD_IMM64};
use rvm_core::{
    Code, Instruction, Native, NativeBind, NativeMode, NativeSig, MAX_CALL_DEPTH, MAX_NATIVE_ARGS, MAX_STACK_ARGS,
};

use crate::error::{LinkError, Result, VmError};
use crate::executor::{Token, MAX_ARGS, REG_ARGS};
use crate::helper::{HelperRegistry, NativeKind, SharedHelpers};
#[cfg(feature = "maps")]
use crate::layout::MAPS_REGION;
use crate::layout::{BORROW_REGIONS, CODE_REGION, DATA_REGION, RODATA_REGION, STACK_REGION};
use crate::map_def::{MapDef, MapKind};
#[cfg(feature = "maps")]
use crate::maps::Maps;
use crate::memory::{region_tag, MemoryBudget, Perms, VmMemory, MAX_REGION_LEN};
use crate::program::{Borrow, FunctionInfo, Functions, Program};
use crate::proto::{ArgKind, Proto, ReturnKind};
use crate::vm::{NativeImport, NativeResolver, OnceResolver, Resolved, Shared, VmConfig};

const MAGIC: &[u8; 4] = b"RVMI";
const FORMAT_VERSION: u32 = 5;
const RVM_VERSION: &str = env!("CARGO_PKG_VERSION");

// tag bytes of the serialized variants
const MAP_ARRAY: u8 = 0;
const MAP_HASH: u8 = 1;
const IMPORT_NAME: u8 = 0;
const IMPORT_HELPER: u8 = 1;
const FLAG_STACK: u8 = 1;
const FLAG_PROTO: u8 = 2;
const PROTO_VARIADIC: u8 = 1;
const PROTO_CALLS_BACK: u8 = 2;
const RET_VOID: u8 = 0;
const RET_INT: u8 = 1;
const RET_PTR: u8 = 2;
const RET_F32: u8 = 3;
const RET_F64: u8 = 4;
const RET_AGG: u8 = 5;
const ARG_INT: u8 = 0;
const ARG_PTR: u8 = 1;
const ARG_CALLBACK: u8 = 2;
const ARG_F32: u8 = 3;
const ARG_F64: u8 = 4;
const ARG_COPY: u8 = 5;
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
    /// Deduplicated imports referenced by [`calls`](Self::calls).
    pub imports: Vec<Import>,
    /// Call instructions, as `(instruction index, import index into imports)`.
    pub calls: Vec<(u32, u32)>,
    /// The link addresses of `.rodata` and `.data` bytes in the code and data, which loading moves to the guest
    /// addresses of those bytes.
    pub addresses: Vec<Address>,
    /// `&extern` references in code and data, as `(site, import index into imports)`.
    pub tokens: Vec<(Site, u32)>,
    /// Address-taken plugin functions and their BTF prototypes, for callback thunk unmarshalling.
    pub callbacks: Vec<CallbackInfo>,
}

/// A plugin function whose address is taken, recorded so callback thunks know its ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackInfo {
    /// Instruction index where the function starts.
    pub pc: u64,
    /// Export name if globally exported (so retained callbacks follow [`Plugin::replace`](crate::Plugin::replace)).
    pub name: Option<String>,
    /// Prototype of the function from BTF.
    pub proto: Proto,
}

/// A host, native, or plugin function that an [`Image`] imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    /// A named function: native, host closure, plugin export, or resolved at load time.
    Name {
        name: String,
        /// DLL name from `IMPORT_FROM("dll")` or `IMPORT_FROM("dll!symbol")`.
        dll: Option<String>,
        /// Symbol name override from `IMPORT_FROM("dll!symbol")`.
        symbol: Option<String>,
        /// Prototype from BTF, if the module carried BTF for this extern.
        proto: Option<Proto>,
        /// Whether calls pass arguments on the stack (more than five argument registers).
        stack: bool,
    },
    /// A helper registered by ID.
    Helper(u32),
}

impl Import {
    /// A named import without a DLL tag, prototype, or stack arguments.
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name {
            name: name.into(),
            dll: None,
            symbol: None,
            proto: None,
            stack: false,
        }
    }
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

    /// The imports this image requires when loaded.
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// Add `import` to [`Image::imports`], returning its deduplicated index.
    pub fn add_import(&mut self, import: Import) -> u32 {
        match self.imports.iter().position(|existing| existing == &import) {
            Some(idx) => idx as u32,
            None => {
                let idx = self.imports.len() as u32;
                self.imports.push(import);
                idx
            }
        }
    }

    /// Record a call at instruction index `at` to `import`, deduplicating `import` in [`Image::imports`].
    pub fn add_call(&mut self, at: u32, import: Import) {
        let idx = self.add_import(import);
        self.calls.push((at, idx));
    }

    /// Each `call <helper id>` in the code, as its instruction index and the helper ID. Linking records these as
    /// [`Import::Helper`] imports.
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
                w.borrows(&info.borrows);
            }
        });
        w.section(|w| {
            w.u32(self.imports.len() as u32);
            for import in &self.imports {
                match import {
                    Import::Name {
                        name,
                        dll,
                        symbol,
                        proto,
                        stack,
                    } => {
                        w.0.push(IMPORT_NAME);
                        w.str(name);
                        w.str(dll.as_deref().unwrap_or(""));
                        w.str(symbol.as_deref().unwrap_or(""));
                        let flags = (u8::from(*stack) * FLAG_STACK) | (u8::from(proto.is_some()) * FLAG_PROTO);
                        w.0.push(flags);
                        if let Some(proto) = proto {
                            w.proto(proto);
                        }
                    }
                    Import::Helper(id) => {
                        w.0.push(IMPORT_HELPER);
                        w.u32(*id);
                    }
                }
            }
        });
        w.section(|w| {
            w.u32(self.calls.len() as u32);
            for &(at, idx) in &self.calls {
                w.u32(at);
                w.u32(idx);
            }
        });
        w.section(|w| {
            w.u32(self.addresses.len() as u32);
            for address in &self.addresses {
                let (kind, at) = site_bytes(address.at);
                w.0.push(kind);
                w.u32(at);
                w.0.push(address.region as u8);
            }
        });
        w.section(|w| {
            w.u32(self.tokens.len() as u32);
            for &(site, idx) in &self.tokens {
                let (kind, at) = site_bytes(site);
                w.0.push(kind);
                w.u32(at);
                w.u32(idx);
            }
        });
        w.section(|w| {
            w.u32(self.callbacks.len() as u32);
            for cb in &self.callbacks {
                w.u64(cb.pc);
                w.str(cb.name.as_deref().unwrap_or(""));
                w.proto(&cb.proto);
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
            imports: s.imports,
            calls: s.calls,
            addresses: s.addresses,
            tokens: s.tokens,
            callbacks: s.callbacks,
        })
    }
}

fn site_bytes(site: Site) -> (u8, u32) {
    match site {
        Site::Code(at) => (SITE_CODE, at),
        Site::RoData(at) => (SITE_RODATA, at),
        Site::Data(at) => (SITE_DATA, at),
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
    imports: Vec<Import>,
    calls: Vec<(u32, u32)>,
    addresses: Vec<Address>,
    tokens: Vec<(Site, u32)>,
    callbacks: Vec<CallbackInfo>,
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
            let borrows = s.borrows()?;
            functions.push((name, FunctionInfo { pc, size, borrows }));
        }
        s.end()?;

        let mut s = r.section()?;
        let mut imports = Vec::new();
        for _ in 0..s.u32()? {
            let import = match s.u8()? {
                IMPORT_NAME => {
                    let name = s.str()?;
                    let dll = s.opt_str()?;
                    let symbol = s.opt_str()?;
                    let flags = s.u8()?;
                    if flags & !(FLAG_STACK | FLAG_PROTO) != 0 {
                        return Err(invalid(format!("import {name}: unknown flags {flags:#x}")));
                    }
                    let proto = match flags & FLAG_PROTO != 0 {
                        true => Some(s.proto(&name)?),
                        false => None,
                    };
                    Import::Name {
                        name,
                        dll,
                        symbol,
                        proto,
                        stack: flags & FLAG_STACK != 0,
                    }
                }
                IMPORT_HELPER => Import::Helper(s.u32()?),
                kind => return Err(invalid(format!("import of unknown kind {kind}"))),
            };
            imports.push(import);
        }
        s.end()?;

        let mut s = r.section()?;
        let mut calls = Vec::new();
        for _ in 0..s.u32()? {
            calls.push((s.u32()?, s.u32()?));
        }
        s.end()?;

        let mut s = r.section()?;
        let mut addresses = Vec::new();
        for _ in 0..s.u32()? {
            let at = parse_site(s.u8()?, s.u32()?)?;
            addresses.push(Address {
                at,
                region: s.u8()?.into(),
            });
        }
        s.end()?;

        let mut s = r.section()?;
        let mut tokens = Vec::new();
        for _ in 0..s.u32()? {
            let site = parse_site(s.u8()?, s.u32()?)?;
            tokens.push((site, s.u32()?));
        }
        s.end()?;

        let mut s = r.section()?;
        let mut callbacks = Vec::new();
        for _ in 0..s.u32()? {
            let pc = s.u64()?;
            let name = s.opt_str()?;
            let label = name.as_deref().unwrap_or("<callback>");
            let proto = s.proto(label)?;
            callbacks.push(CallbackInfo { pc, name, proto });
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
            imports,
            calls,
            addresses,
            tokens,
            callbacks,
        })
    }
}

fn parse_site(kind: u8, at: u32) -> Result<Site> {
    match kind {
        SITE_CODE => Ok(Site::Code(at)),
        SITE_RODATA => Ok(Site::RoData(at)),
        SITE_DATA => Ok(Site::Data(at)),
        kind => Err(invalid(format!("site of unknown kind {kind}"))),
    }
}

/// Check `image`, resolve missing imports through `resolver`, bind calls to `helpers`, and allocate memory and maps.
pub fn load(
    image: Image,
    helpers: &Arc<SharedHelpers>,
    resolver: Option<&NativeResolver>,
    shared: &Shared,
    config: &VmConfig,
) -> Result<Program> {
    let Image {
        code,
        rodata,
        rodata_len,
        data,
        data_len,
        maps,
        functions,
        imports,
        calls,
        addresses,
        tokens,
        callbacks,
    } = image;
    let sections = Sections {
        code: &code,
        rodata: &rodata,
        rodata_len,
        data: &data,
        data_len,
        maps,
        functions,
        imports,
        calls,
        addresses,
        tokens,
        callbacks,
    };
    load_with_shared_resolver(sections, helpers, resolver, shared, config)
}

/// [`load`] the image that [`Image::to_bytes`] wrote to `bytes`.
pub fn load_bytes(
    bytes: &[u8],
    helpers: &Arc<SharedHelpers>,
    resolver: Option<&NativeResolver>,
    shared: &Shared,
    config: &VmConfig,
) -> Result<Program> {
    if bytes.len() > config.memory_limit {
        return Err(VmError::MemoryLimit(config.memory_limit));
    }
    load_with_shared_resolver(Sections::parse(bytes)?, helpers, resolver, shared, config)
}

/// Load a serialized image into a fresh `registry` with an optional one-shot resolver, without taking any mutex.
pub fn load_bytes_once(
    bytes: &[u8],
    mut registry: HelperRegistry,
    resolver: Option<&mut OnceResolver<'_>>,
    config: &VmConfig,
) -> Result<Program> {
    if bytes.len() > config.memory_limit {
        return Err(VmError::MemoryLimit(config.memory_limit));
    }
    let sections = Sections::parse(bytes)?;
    if let Some(resolve) = resolver {
        let resolved = resolve_imports(&sections.imports, &registry, resolve)?;
        for (name, nat, kind) in resolved {
            registry.put_native_if_absent(name, nat, kind);
        }
    }
    let helpers = Arc::new(SharedHelpers::new(registry));
    load_sections(sections, &helpers, &Shared::default(), config)
}

fn load_with_shared_resolver(
    s: Sections<'_>,
    helpers: &Arc<SharedHelpers>,
    resolver: Option<&NativeResolver>,
    shared: &Shared,
    config: &VmConfig,
) -> Result<Program> {
    if let Some(resolve) = resolver {
        let table = helpers.read();
        let resolved = resolve_imports(&s.imports, &table, &mut |import| resolve(import))?;
        if !resolved.is_empty() {
            helpers.update(|h| {
                for (name, nat, kind) in resolved {
                    h.put_native_if_absent(name, nat, kind);
                }
            });
        }
    }
    load_sections(s, helpers, shared, config)
}

/// Ask `resolve` for every `Import::Name` not already present in `table`, checking the returned signature or deriving
/// one from the plugin's prototype.
fn resolve_imports(
    imports: &[Import],
    table: &HelperRegistry,
    resolve: &mut dyn FnMut(&NativeImport<'_>) -> Option<Resolved>,
) -> Result<Vec<(String, Native, NativeKind)>> {
    let mut resolved = Vec::new();
    for import in imports {
        let Import::Name {
            name,
            dll,
            symbol,
            proto,
            ..
        } = import
        else {
            continue;
        };
        if table.native(name).is_some()
            || table.slot_of_name(name).is_some()
            || resolved.iter().any(|(n, _, _)| n == name)
        {
            continue;
        }
        let query = NativeImport {
            name: symbol.as_deref().unwrap_or(name),
            dll: dll.as_deref(),
            proto: proto.as_ref(),
        };
        let Some(Resolved { func, sig }) = resolve(&query) else {
            continue;
        };
        let (native_sig, kind) = match (sig, proto) {
            (Some(host_sig), Some(p)) => {
                p.check_native_sig(name, host_sig)?;
                (host_sig, NativeKind::Checked)
            }
            (Some(_), None) => {
                let reason = "the module has no BTF for the extern to check its signature against".into();
                return Err(LinkError::NativeMismatch {
                    name: name.clone(),
                    reason,
                }
                .into());
            }
            (None, Some(p)) if p.needs_general() => {
                general_mode(name, p, None, true)?;
                #[cfg(feature = "ffi")]
                {
                    (NativeSig::ints(0), NativeKind::General)
                }
                #[cfg(not(feature = "ffi"))]
                {
                    unreachable!("general_mode returns Err without `ffi`")
                }
            }
            (None, Some(p)) => (p.native_sig(name)?, NativeKind::Strip),
            (None, None) => (NativeSig::ints(0), NativeKind::Raw),
        };
        let nat = crate::vm::native(name, func, native_sig)?;
        resolved.push((name.clone(), nat, kind));
    }
    Ok(resolved)
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

    let mut insns = Instruction::decode(s.code);
    check_stack_arguments(&insns, &s.functions)?;
    // Bind against one version of the table; the program refreshes from there.
    let snapshot = helpers.snapshot();
    bind_helper_calls(&mut insns, s.code, &snapshot.table);
    let tagged = !config.passthrough.is_untagged();
    let Bound {
        natives,
        stack_calls,
        resolved,
    } = bind_externs(&mut insns, &s.imports, &s.calls, &snapshot.table, tagged)?;
    let functions = check_functions(s.functions, insns.len() as u64)?;
    for cb in &s.callbacks {
        if cb.pc >= insns.len() as u64 {
            return Err(invalid(format!("callback at pc {} out of range", cb.pc)));
        }
    }

    let mut memory = VmMemory::with_passthrough(config.passthrough);
    let stack_top = memory.map_any(STACK_REGION, stack_len as usize, Perms::RW)? + stack_len;
    memory.map_bytes_any(RODATA_REGION, s.rodata, s.rodata_len, Perms::R)?;
    memory.map_bytes_any(DATA_REGION, s.data, s.data_len, Perms::RW)?;
    relocate(&s.addresses, &mut insns, &mut memory)?;
    let tokens = patch_tokens(&s.tokens, &resolved, &mut insns, &mut memory)?;

    // SAFETY: `bind_externs` checked each native's prototype against `snapshot.table`'s signature, which a native
    // keeps in every later table the program refreshes to. `register_native` and `set_native_resolver` vouch for the
    // function pointers.
    let mut code = unsafe { Code::with_natives(insns, &natives) }
        .map_err(|at| invalid(format!("native call at instruction {at} is not a valid call")))?;
    for at in stack_calls {
        if !code.pass_stack_args(at as usize) {
            return Err(invalid(format!("extern call at instruction {at} is not a valid call")));
        }
    }

    // Bind maps only after every other check and allocation has succeeded so a failed load never leaks or poisons
    // shared maps.
    #[cfg(feature = "maps")]
    let (mut maps, maps_len) = Maps::new(s.maps, &shared.maps, &mut budget)?;
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

    let program =
        Program::new(code, memory, stack_top, functions, helpers.clone(), snapshot, config).with_tokens(tokens);
    #[cfg(feature = "callbacks")]
    let program = program.with_callbacks(&s.callbacks);
    #[cfg(feature = "maps")]
    let program = program.with_maps(maps);
    Ok(program)
}

/// Rewrite the 64-bit address stored at `site` (`LD_IMM64` immediate in `insns`, or 8 bytes in `.rodata`/`.data`).
fn patch_site(
    site: Site,
    insns: &mut [Instruction],
    memory: &mut VmMemory,
    update: impl FnOnce(u64) -> u64,
    bad: impl Fn() -> VmError,
) -> Result<()> {
    // the immediate of an instruction
    const IMM: u64 = 0xFFFF_FFFF << 32;

    match site {
        Site::Code(at) => {
            let at = at as usize;
            let [lo, hi] = insns.get_mut(at..at + 2).ok_or_else(&bad)? else {
                unreachable!("two instructions")
            };
            if lo.byte() != LD_IMM64 {
                return Err(bad());
            }
            let addr = update((lo.0 >> 32) | (hi.0 & IMM));
            lo.0 = lo.0 & !IMM | addr << 32;
            hi.0 = hi.0 & !IMM | addr & IMM;
        }
        Site::RoData(offset) | Site::Data(offset) => {
            let in_region = match site {
                Site::RoData(_) => RODATA_REGION,
                _ => DATA_REGION,
            };
            let at = memory.region_base(in_region) + u64::from(offset);
            let old = memory.read(at).map_err(|_| bad())?;
            memory.write(at, update(old)).map_err(|_| bad())?;
        }
    }
    Ok(())
}

/// Move each of `addresses` from its link address to the guest address of the same byte in `memory`, where the
/// regions they point into are mapped.
fn relocate(addresses: &[Address], insns: &mut [Instruction], memory: &mut VmMemory) -> Result<()> {
    for &Address { at, region } in addresses {
        let bad = || invalid(format!("address at {at:?} into region {region}"));
        if region != RODATA_REGION && region != DATA_REGION {
            return Err(bad());
        }
        let base = memory.region_base(region);
        patch_site(at, insns, memory, |link| base.wrapping_add(link.wrapping_sub(region_tag(region))), bad)?;
    }
    Ok(())
}

/// Patch each `&extern` token site in `code`, `.rodata` or `.data` with its token address in `CODE_REGION`
/// (`region_tag(CODE_REGION) | (token_idx * 8 + 1)`).
fn patch_tokens(
    token_sites: &[(Site, u32)],
    resolved: &[BoundImport],
    insns: &mut [Instruction],
    memory: &mut VmMemory,
) -> Result<Box<[Token]>> {
    let mut table: Vec<Token> = Vec::new();
    for &(site, import_idx) in token_sites {
        let bad = || invalid(format!("token at {site:?} for import {import_idx}"));
        let bound = resolved.get(import_idx as usize).ok_or_else(bad)?;
        let token = match *bound {
            BoundImport::Slot { slot, stack } => Token::Slot { slot, stack },
            BoundImport::Native { index, mode, .. } => Token::Native { index, mode },
        };
        let token_idx = match table.iter().position(|existing| existing == &token) {
            Some(idx) => idx as u64,
            None => {
                let idx = table.len() as u64;
                table.push(token);
                idx
            }
        };
        let addr = region_tag(CODE_REGION) | (token_idx * INSN_SIZE + 1);
        patch_site(site, insns, memory, |_| addr, bad)?;
    }
    Ok(table.into_boxed_slice())
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

/// Fails if an 8-byte load or store through r11 in `insns` names none of the stack arguments 6 to 12 with its offset,
/// as the store of a thirteenth argument does. The interpreter fails such an instruction only when it runs. Every
/// other instruction may name r11, which is a register like r12 to r15 to it.
fn check_stack_arguments(insns: &[Instruction], functions: &[(String, FunctionInfo)]) -> Result<()> {
    const R11: u8 = 11;
    const LDX_DW: u8 = OpCode::ldx(MemSize::DWord, MemMode::Mem).0;
    const ST_DW: u8 = OpCode::st(MemSize::DWord, MemMode::Mem).0;
    const STX_DW: u8 = OpCode::stx(MemSize::DWord, MemMode::Mem).0;

    // the callee loads argument `5 + k` from `r11 + 8k`, and the caller stores it to `r11 - 8k`
    let slot = |offset: i16| (1..=MAX_STACK_ARGS as i16).any(|k| offset == 8 * k);
    let no_argument = |insn: &Instruction| match insn.byte() {
        LDX_DW => insn.src_reg() == R11 && !slot(insn.offset()),
        ST_DW | STX_DW => insn.dst_reg() == R11 && !slot(insn.offset().wrapping_neg()),
        _ => false,
    };
    let Some(pc) = insns.iter().position(no_argument) else {
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

/// The extern calls of an image that [`bind_externs`] leaves to the prepared code.
struct Bound {
    natives: Vec<NativeBind>,
    stack_calls: Vec<u32>,
    resolved: Vec<BoundImport>,
}

enum BoundImport {
    Slot { slot: u32, stack: bool },
    Native { index: u32, args: u8, mode: NativeMode },
}

/// Validate each entry of `imports` against `table`, then bind every call in `calls`.
fn bind_externs(
    insns: &mut [Instruction],
    imports: &[Import],
    calls: &[(u32, u32)],
    table: &HelperRegistry,
    tagged: bool,
) -> Result<Bound> {
    let mut resolved = Vec::with_capacity(imports.len());
    for import in imports {
        resolved.push(bind_import(import, table, tagged)?);
    }

    let mut bound = Bound {
        natives: Vec::new(),
        stack_calls: Vec::new(),
        resolved,
    };
    for &(at, import_idx) in calls {
        let target = bound
            .resolved
            .get(import_idx as usize)
            .ok_or_else(|| invalid(format!("call at instruction {at}: import index {import_idx} out of range")))?;
        let insn = insns
            .get_mut(at as usize)
            .filter(|insn| insn.byte() == CALL)
            .ok_or_else(|| invalid(format!("extern at instruction {at} is not a call")))?;
        match *target {
            BoundImport::Slot { slot, stack } => {
                bind_call(insn, slot);
                if stack {
                    bound.stack_calls.push(at);
                }
            }
            BoundImport::Native { index, args, mode } => {
                bound.natives.push(NativeBind {
                    pc: at as usize,
                    index,
                    args,
                    mode,
                });
            }
        }
    }
    Ok(bound)
}

fn general_mode(name: &str, proto: &Proto, host_sig: Option<NativeSig>, tagged: bool) -> Result<NativeMode> {
    #[cfg(feature = "ffi")]
    {
        Ok(NativeMode::General(proto.general_proto(name, host_sig, tagged)?))
    }
    #[cfg(not(feature = "ffi"))]
    {
        let _ = (proto, host_sig, tagged);
        Err(LinkError::NativeMismatch {
            name: name.to_string(),
            reason: "this extern needs the `ffi` feature".into(),
        }
        .into())
    }
}

fn bind_import(import: &Import, table: &HelperRegistry, tagged: bool) -> Result<BoundImport> {
    match import {
        Import::Helper(id) => {
            let slot = table.slot_of_id(*id).ok_or(LinkError::UnknownHelper(*id))?;
            Ok(BoundImport::Slot { slot, stack: false })
        }
        Import::Name { name, proto, stack, .. } => {
            if let Some((index, host_sig, kind)) = table.native(name) {
                let mode = match kind {
                    NativeKind::Checked => {
                        let Some(p) = proto else {
                            let reason = "the module has no BTF for the extern to check its signature against".into();
                            return Err(LinkError::NativeMismatch {
                                name: name.clone(),
                                reason,
                            }
                            .into());
                        };
                        p.check_native_sig(name, host_sig)?;
                        if p.needs_general() || host_sig.is_aware() {
                            general_mode(name, p, Some(host_sig), tagged)?
                        } else if tagged && host_sig.has_pointers() {
                            NativeMode::Checked
                        } else {
                            NativeMode::Plain
                        }
                    }
                    NativeKind::Strip => match proto {
                        Some(p) if p.needs_general() => general_mode(name, p, None, tagged)?,
                        Some(p) => {
                            let declared = p.native_sig(name)?;
                            check_strip_sig(name, declared, host_sig)?;
                            if tagged && host_sig.has_pointers() {
                                NativeMode::Strip
                            } else {
                                NativeMode::Plain
                            }
                        }
                        None => match tagged && host_sig.has_pointers() {
                            true => NativeMode::Strip,
                            false => NativeMode::Plain,
                        },
                    },
                    #[cfg(feature = "ffi")]
                    NativeKind::General => {
                        let Some(p) = proto else {
                            let reason = "the module has no BTF for this extern".into();
                            return Err(LinkError::NativeMismatch {
                                name: name.clone(),
                                reason,
                            }
                            .into());
                        };
                        NativeMode::General(p.general_proto(name, None, tagged)?)
                    }
                    NativeKind::Raw => NativeMode::Raw,
                };
                return Ok(BoundImport::Native {
                    index,
                    args: host_sig.args(),
                    mode,
                });
            }
            if let Some(slot) = table.slot_of_name(name) {
                if let Some(p) = proto.as_ref().filter(|p| !p.variadic) {
                    let args = p.reg_count();
                    if args > MAX_ARGS {
                        return Err(LinkError::TooManyRegisters {
                            name: name.clone(),
                            registers: args,
                        }
                        .into());
                    }
                    if let Some(host) = table.arity(slot).filter(|&host| usize::from(host) != args) {
                        return Err(LinkError::SignatureMismatch {
                            name: name.clone(),
                            declared: args,
                            host,
                        }
                        .into());
                    }
                    let wide = p.wide_return();
                    if wide != table.wide(slot) {
                        return Err(LinkError::ReturnMismatch {
                            name: name.clone(),
                            wide,
                        }
                        .into());
                    }
                }
                let needs_stack = *stack
                    || table.arity(slot).is_some_and(|a| usize::from(a) > REG_ARGS)
                    || proto.as_ref().is_some_and(|p| p.reg_count() > REG_ARGS);
                return Ok(BoundImport::Slot {
                    slot,
                    stack: needs_stack,
                });
            }
            Err(LinkError::UnresolvedSymbol(name.clone()).into())
        }
    }
}

/// Fails unless a resolver-bound native's prototype matches the signature cached in the VM's native table.
fn check_strip_sig(name: &str, declared: NativeSig, cached: NativeSig) -> Result<()> {
    if declared.args() != cached.args() {
        return Err(LinkError::SignatureMismatch {
            name: name.to_string(),
            declared: usize::from(declared.args()),
            host: cached.args(),
        }
        .into());
    }
    if declared != cached {
        return Err(LinkError::NativeMismatch {
            name: name.to_string(),
            reason: "the extern disagrees with the prototype this VM resolved the native under".into(),
        }
        .into());
    }
    Ok(())
}

/// The function table of `functions`, in code of `insn_count` instructions.
fn check_functions(functions: Vec<(String, FunctionInfo)>, insn_count: u64) -> Result<Functions> {
    for (name, info) in &functions {
        // Each borrow maps its own region, of which a program has `BORROW_REGIONS`, so the pointer parameters must
        // differ. A call rewrites each pointer parameter as it maps it, so none may also hold a length.
        let borrows = &info.borrows;
        let distinct = borrows
            .iter()
            .enumerate()
            .all(|(i, b)| borrows[..i].iter().all(|o| o.arg != b.arg));
        let lengths_apart = borrows.iter().all(|b| borrows.iter().all(|o| o.arg != b.len_arg));
        let in_range = borrows.len() <= BORROW_REGIONS && borrows.iter().all(Borrow::in_range);
        if info.pc >= insn_count || !in_range || !distinct || !lengths_apart {
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

    fn borrows(&mut self, borrows: &[Borrow]) {
        self.0.push(borrows.len() as u8);
        for borrow in borrows {
            self.0
                .extend_from_slice(&[borrow.arg, borrow.len_arg, borrow.writable.into()]);
        }
    }

    fn proto(&mut self, proto: &Proto) {
        match proto.ret {
            ReturnKind::Void => self.0.push(RET_VOID),
            ReturnKind::Int => self.0.push(RET_INT),
            ReturnKind::Ptr => self.0.push(RET_PTR),
            ReturnKind::Float(4) => self.0.push(RET_F32),
            ReturnKind::Float(_) => self.0.push(RET_F64),
            ReturnKind::Agg(size) => {
                self.0.push(RET_AGG);
                self.u32(size);
            }
        }
        let flags = (u8::from(proto.variadic) * PROTO_VARIADIC) | (u8::from(proto.calls_back) * PROTO_CALLS_BACK);
        self.0.push(flags);
        self.0.push(proto.args.len() as u8);
        for &arg in &proto.args {
            match arg {
                ArgKind::Int => self.0.push(ARG_INT),
                ArgKind::Ptr => self.0.push(ARG_PTR),
                ArgKind::Callback => self.0.push(ARG_CALLBACK),
                ArgKind::Float(4) => self.0.push(ARG_F32),
                ArgKind::Float(_) => self.0.push(ARG_F64),
                ArgKind::Copy(size) => {
                    self.0.push(ARG_COPY);
                    self.0.push(size);
                }
            }
        }
        self.borrows(&proto.borrows);
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

    fn opt_str(&mut self) -> Result<Option<String>> {
        let s = self.str()?;
        Ok((!s.is_empty()).then_some(s))
    }

    fn borrows(&mut self) -> Result<Vec<Borrow>> {
        let count = self.u8()?;
        let mut borrows = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let [arg, len_arg, writable] = self.array()?;
            let writable = writable != 0;
            borrows.push(Borrow { arg, len_arg, writable });
        }
        Ok(borrows)
    }

    fn proto(&mut self, name: &str) -> Result<Proto> {
        let ret = match self.u8()? {
            RET_VOID => ReturnKind::Void,
            RET_INT => ReturnKind::Int,
            RET_PTR => ReturnKind::Ptr,
            RET_F32 => ReturnKind::Float(4),
            RET_F64 => ReturnKind::Float(8),
            RET_AGG => ReturnKind::Agg(self.u32()?),
            kind => return Err(invalid(format!("import {name}: unknown return kind {kind}"))),
        };
        let flags = self.u8()?;
        if flags & !(PROTO_VARIADIC | PROTO_CALLS_BACK) != 0 {
            return Err(invalid(format!("import {name}: unknown proto flags {flags:#x}")));
        }
        let variadic = flags & PROTO_VARIADIC != 0;
        let calls_back = flags & PROTO_CALLS_BACK != 0;
        let count = self.u8()?;
        if usize::from(count) > MAX_NATIVE_ARGS {
            return Err(invalid(format!("import {name}: {count} parameters")));
        }
        let mut args = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let kind = match self.u8()? {
                ARG_INT => ArgKind::Int,
                ARG_PTR => ArgKind::Ptr,
                ARG_CALLBACK => ArgKind::Callback,
                ARG_F32 => ArgKind::Float(4),
                ARG_F64 => ArgKind::Float(8),
                ARG_COPY => {
                    let size = self.u8()?;
                    if !matches!(size, 3 | 5 | 6 | 7 | 9..=16) {
                        return Err(invalid(format!("import {name}: bad copy size {size}")));
                    }
                    ArgKind::Copy(size)
                }
                kind => return Err(invalid(format!("import {name}: unknown argument kind {kind}"))),
            };
            args.push(kind);
        }
        let borrows = self.borrows()?;
        if borrows.len() > BORROW_REGIONS || !borrows.iter().all(Borrow::in_range) {
            return Err(invalid(format!("import {name}: borrow tag out of range")));
        }
        Ok(Proto {
            args,
            ret,
            variadic,
            calls_back,
            borrows,
        })
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
