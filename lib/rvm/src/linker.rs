//! Linker for combining multiple eBPF modules.
//!
//! The linker resolves symbol references between modules, applies relocations, and produces an [`Image`] for
//! [`crate::image::load`] to bind and allocate.
//!
//! Code and data live in separate address spaces. Code sections are concatenated into one instruction array (addressed
//! by byte offset during linking, by instruction index at runtime) that the guest cannot read or write. A function
//! pointer or jump table entry is a byte offset into that array in [`CODE_REGION`], which `callx` and `gotox` accept
//! and loads and stores reject. Data sections go into guest memory regions; see [`crate::layout`] for the complete
//! table.

use std::ops::Range;

use btf::{apply_core_relocations, Btf, BtfBuilder, BtfType, BTF_FUNC_EXTERN};
use constelf::raw::reloc;
use hashbrown::{HashMap, HashSet};
use rvm_core::{NativeArg, NativeSig};

use crate::error::{LinkError, Result, VmError};
use crate::executor::{CORE_POISON_HELPER, MAX_ARGS};
use crate::helper::HelperRegistry;
use crate::image::{set_imm, set_slot_call, Address, Image, Import, Site, INSN_SIZE};
use crate::layout::{CODE_REGION, DATA_REGION, RODATA_REGION};
use crate::map_def::map_defs;
use crate::memory::{region_tag, split_addr, MemoryBudget, MAX_REGION_LEN};
use crate::module::{Module, Relocation};
use crate::program::{Borrow, FunctionInfo};
use crate::section::SectionKind;

const _: () = assert!(CORE_POISON_HELPER == btf::CORE_POISON_HELPER);

/// Where a section or symbol lives after linking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addr {
    /// Byte offset into the program's code.
    Code(u64),
    /// Link address of guest data (see [`crate::memory`]).
    Data(u64),
}

impl Addr {
    /// The address `by` bytes on. Nothing checks `by` against the section's size: a symbol value past the end names an
    /// address in a later section, or one the guest faults on.
    fn offset(self, by: u64) -> Self {
        match self {
            Self::Code(a) => Self::Code(a.wrapping_add(by)),
            Self::Data(a) => Self::Data(a.wrapping_add(by)),
        }
    }

    /// The address the guest sees.
    fn guest(self) -> u64 {
        match self {
            Self::Code(a) => region_tag(CODE_REGION).wrapping_add(a),
            Self::Data(a) => a,
        }
    }
}

/// Memory layout information for a module: original section index -> address.
#[derive(Debug, Clone, Default)]
struct ModuleLayout {
    sections: HashMap<usize, Addr>,
    /// (code section, `.jumptables` section) -> copy of the tables in `.rodata` with each entry turned into a guest
    /// code address.
    jump_tables: HashMap<(usize, usize), Addr>,
}

impl Image {
    /// The 8-byte instruction at code offset `at`.
    fn insn_mut(&mut self, at: u64) -> Result<&mut [u8; 8]> {
        let at = at as usize;
        self.code
            .get_mut(at..)
            .and_then(|s| s.first_chunk_mut())
            .ok_or_else(|| LinkError::InvalidReference(format!("code offset {at:#x}")).into())
    }

    /// `len` bytes of the data image at guest address `addr`.
    fn data_mut(&mut self, addr: u64, len: usize) -> Result<&mut [u8]> {
        let (region, at) = split_addr(addr);
        let buf = match region {
            RODATA_REGION => &mut self.rodata,
            DATA_REGION => &mut self.data,
            _ => return Err(LinkError::InvalidReference(format!("data address {addr:#x}")).into()),
        };
        buf.get_mut(at..)
            .and_then(|b| b.get_mut(..len))
            .ok_or_else(|| LinkError::InvalidReference(format!("data address {addr:#x}")).into())
    }

    /// Split `value` across the `imm` fields of the `lddw` at code offset `at` and its second slot.
    fn set_ld_imm64(&mut self, at: u64, value: u64) -> Result<()> {
        set_imm(self.insn_mut(at)?, value as u32);
        set_imm(self.insn_mut(at + INSN_SIZE)?, (value >> 32) as u32);
        Ok(())
    }
}

/// Link modules into an image, binding extern calls against `helpers` and CO-RE relocations against `types`. Fails
/// with [`VmError::MemoryLimit`] before the image's code and data grow past `memory_limit` bytes.
pub fn link<'m>(
    helpers: &HelperRegistry,
    types: &BtfBuilder,
    modules: &[&'m Module],
    memory_limit: usize,
) -> Result<Image> {
    if modules.is_empty() {
        return Err(VmError::InvalidArgument("no modules to link".to_string()));
    }

    // Each module's BTF, parsed once and shared by every pass below.
    let btfs = modules
        .iter()
        .map(|m| m.btf_data.as_deref().map(Btf::parse).transpose())
        .collect::<std::result::Result<Vec<Option<Btf<'m>>>, _>>()?;

    // The host's types, encoded once as standard BTF and shared by every CO-RE relocation below, the same way a second
    // translation unit would be.
    let target_bytes = types.encode();
    let target = Btf::parse(&target_bytes)?;

    let (mut image, layouts) = lay_out(modules, &mut MemoryBudget::new(memory_limit))?;
    let global_symbols = build_symbol_table(modules, &layouts)?;
    check_extern_signatures(helpers, &btfs)?;
    let natives = btfs
        .iter()
        .map(|btf| check_native_externs(helpers, btf.as_ref()))
        .collect::<Result<Vec<_>>>()?;

    for (module, btf) in modules.iter().zip(&btfs) {
        for def in map_defs(module, btf.as_ref())? {
            if image.maps.iter().any(|d| d.name == def.name) {
                return Err(LinkError::DuplicateSymbol(def.name).into());
            }
            image.maps.push(def);
        }
    }

    // Relocations bind maps and named externs; then numeric helper calls.
    for ((module, layout), natives) in modules.iter().zip(&layouts).zip(&natives) {
        for reloc in &module.relocations {
            apply_relocation(helpers, natives, module, layout, &global_symbols, reloc, &mut image)?;
        }
    }
    mark_helper_calls(helpers, &mut image)?;
    apply_core_relocations_pass(modules, &layouts, &btfs, &target, &mut image)?;

    image.functions = build_function_table(modules, &layouts, &btfs)?.into_iter().collect();
    image.functions.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    trim_zeros(&mut image.rodata);
    trim_zeros(&mut image.data);
    Ok(image)
}

/// Drop trailing zero bytes, which loading restores.
fn trim_zeros(bytes: &mut Vec<u8>) {
    bytes.truncate(bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1));
}

/// Place every allocatable section and copy its contents into the image. Rodata and data keep their zero tails
/// unmaterialised: `Image::rodata_len` and `Image::data_len` count them, the byte vectors don't.
fn lay_out(modules: &[&Module], budget: &mut MemoryBudget) -> Result<(Image, Vec<ModuleLayout>)> {
    let mut image = Image::default();
    let mut code_len = 0;
    let layouts = modules
        .iter()
        .map(|module| {
            let mut layout = ModuleLayout::default();
            for (idx, section) in module.sections.iter().enumerate() {
                let (region, bytes, len, align) = match section.kind {
                    SectionKind::Code => ("code", &mut image.code, &mut code_len, INSN_SIZE),
                    SectionKind::RoData => ("rodata", &mut image.rodata, &mut image.rodata_len, 1),
                    SectionKind::Data | SectionKind::Bss => ("data", &mut image.data, &mut image.data_len, 1),
                    _ => continue,
                };
                let at = grow(len, region, section.align.max(align), section.size, budget)?;
                let init = &section.data[..section.data.len().min(section.size as usize)];
                if !init.is_empty() {
                    bytes.resize(at, 0);
                    bytes.extend_from_slice(init);
                }
                let addr = match section.kind {
                    SectionKind::Code => Addr::Code(at as u64),
                    SectionKind::RoData => Addr::Data(region_tag(RODATA_REGION) + at as u64),
                    _ => Addr::Data(region_tag(DATA_REGION) + at as u64),
                };
                layout.sections.insert(idx, addr);
            }
            lay_out_jump_tables(module, &mut layout, &mut image, budget)?;
            Ok(layout)
        })
        .collect::<Result<_>>()?;
    // relocations patch code anywhere in a section, so code is materialised whole
    image.code.resize(code_len, 0);
    Ok((image, layouts))
}

/// Reserve `size` bytes at the next multiple of `align` in the region of length `*len`, and return their offset.
/// Fails before anything grows if the region would exceed [`MAX_REGION_LEN`] or the program its memory budget.
fn grow(len: &mut usize, region: &'static str, align: u64, size: u64, budget: &mut MemoryBudget) -> Result<usize> {
    let range = (*len as u64)
        .checked_next_multiple_of(align)
        .and_then(|at| Some((at, at.checked_add(size)?)))
        .filter(|&(_, end)| end <= MAX_REGION_LEN as u64);
    let Some((at, end)) = range else {
        return Err(VmError::ProgramTooLarge(region));
    };
    budget.take(end - *len as u64)?;
    *len = end as usize;
    Ok(at as usize)
}

/// Copy each jump table section that `module`'s code loads into rodata, once per code section that loads it. Entries
/// are byte offsets into that code section; the copy holds guest code addresses, which `gotox` takes.
fn lay_out_jump_tables(
    module: &Module,
    layout: &mut ModuleLayout,
    image: &mut Image,
    budget: &mut MemoryBudget,
) -> Result<()> {
    for reloc in &module.relocations {
        let Some(&Addr::Code(code)) = layout.sections.get(&reloc.section_idx) else {
            continue;
        };
        let Some(table_idx) = module.symbol_by_idx(reloc.symbol_idx).and_then(|s| s.section_idx) else {
            continue;
        };
        let table = &module.sections[table_idx];
        let key = (reloc.section_idx, table_idx);
        if reloc.rel_type != reloc::bpf::BPF_64_64
            || table.kind != SectionKind::JumpTable
            || layout.jump_tables.contains_key(&key)
        {
            continue;
        }

        let entries = table.data.as_chunks::<8>().0;
        let size = entries.len() as u64 * 8;
        let at = grow(&mut image.rodata_len, "rodata", 8, size, budget)?;
        image.rodata.resize(at, 0);
        for entry in entries {
            let target = Addr::Code(code.wrapping_add(u64::from_le_bytes(*entry)));
            image.rodata.extend_from_slice(&target.guest().to_le_bytes());
        }
        layout
            .jump_tables
            .insert(key, Addr::Data(region_tag(RODATA_REGION) + at as u64));
    }
    Ok(())
}

/// Compare each host-bound extern's BTF prototype with the registered function, counting argument registers as clang
/// passes them (see [`arg_registers`]). Fails for an extern that needs more than [`MAX_ARGS`] registers, and for a
/// host function with a known arity that differs. Modules without BTF and variadic prototypes are not checked.
fn check_extern_signatures(helpers: &HelperRegistry, btfs: &[Option<Btf<'_>>]) -> Result<()> {
    for btf in btfs.iter().flatten() {
        for (_, ty) in btf.types() {
            let BtfType::Func {
                name,
                proto_type,
                linkage: BTF_FUNC_EXTERN,
            } = ty
            else {
                continue;
            };
            // a native has a check of its own
            let Some(slot) = helpers.slot_of_name(name).filter(|_| helpers.native(name).is_none()) else {
                continue;
            };
            // a trailing unnamed void parameter marks a variadic prototype
            let variadic = |proto: &BtfType| match proto {
                BtfType::FuncProto { params, .. } => params.last().is_some_and(|p| p.type_id == 0),
                _ => false,
            };
            if btf.type_by_id(*proto_type).is_some_and(variadic) {
                continue;
            }

            let name = name.to_string();
            let Some((_, registers)) = arg_registers(btf, *proto_type) else {
                let msg = format!("extern {name}: a parameter or return type no register holds");
                return Err(LinkError::InvalidReference(msg).into());
            };
            if registers > MAX_ARGS {
                return Err(LinkError::TooManyRegisters { name, registers }.into());
            }
            if let Some(host) = helpers.arity(slot).filter(|&host| usize::from(host) != registers) {
                let declared = registers;
                return Err(LinkError::SignatureMismatch { name, declared, host }.into());
            }
        }
    }
    Ok(())
}

/// Compare each extern in `btf` that names a native function with the native's signature: the same number of argument
/// registers, an integer or enum where it takes an integer and a pointer where it takes a pointer, and a `borrow` or
/// `borrow_ro` tag only on a pointer with the same length argument and access. Returns the names it checked, which are
/// the only natives the module may call.
fn check_native_externs(helpers: &HelperRegistry, btf: Option<&Btf<'_>>) -> Result<HashSet<String>> {
    let mut checked = HashSet::new();
    let Some(btf) = btf else {
        return Ok(checked);
    };
    let borrows = function_borrows(Some(btf))?;
    for (_, ty) in btf.types() {
        let BtfType::Func {
            name,
            proto_type,
            linkage: BTF_FUNC_EXTERN,
        } = ty
        else {
            continue;
        };
        let Some((_, sig)) = helpers.native(name) else {
            continue;
        };
        let mismatch = |reason: String| LinkError::NativeMismatch {
            name: name.to_string(),
            reason,
        };

        let Some(BtfType::FuncProto { return_type, params }) = btf.type_by_id(*proto_type) else {
            return Err(mismatch("the extern has no prototype".into()).into());
        };
        if params.last().is_some_and(|p| p.type_id == 0) {
            return Err(mismatch("the extern is variadic".into()).into());
        }
        if params.len() != usize::from(sig.args()) {
            let (name, declared, host) = (name.to_string(), params.len(), sig.args());
            return Err(LinkError::SignatureMismatch { name, declared, host }.into());
        }
        let returns = btf.resolve_type(*return_type).map(|(_, ty)| ty);
        if !matches!(returns, Some(BtfType::Void | BtfType::Int { .. } | BtfType::Enum { .. } | BtfType::Ptr { .. })) {
            return Err(mismatch("the extern returns something other than an integer or pointer".into()).into());
        }
        for (n, param) in (1..).zip(params) {
            let pointer = match btf.resolve_type(param.type_id).map(|(_, ty)| ty) {
                Some(BtfType::Int { .. } | BtfType::Enum { .. }) => false,
                Some(BtfType::Ptr { .. }) => true,
                _ => return Err(mismatch(format!("parameter {n} is neither an integer nor a pointer")).into()),
            };
            if pointer != !matches!(sig.arg(n), Some(NativeArg::Int)) {
                let host = if pointer { "an integer" } else { "a pointer" };
                return Err(mismatch(format!("parameter {n} is {host} in the host's signature")).into());
            }
        }
        for borrow in borrows.get(*name).into_iter().flatten() {
            if !borrow_matches(borrow, sig) {
                let n = borrow.arg + 1;
                return Err(
                    mismatch(format!("parameter {n} has a borrow tag the host's signature doesn't match")).into()
                );
            }
        }
        checked.insert(name.to_string());
    }
    Ok(checked)
}

/// Whether the native signature `sig` declares the pointer that `borrow` tags, with its length argument and access.
fn borrow_matches(borrow: &Borrow, sig: NativeSig) -> bool {
    let len = Some(borrow.len_arg + 1);
    match sig.arg(borrow.arg + 1) {
        Some(NativeArg::Read(l)) => !borrow.writable && l == len,
        Some(NativeArg::Write(l)) => borrow.writable && l == len,
        _ => false,
    }
}

/// The argument registers clang uses for each parameter of the function prototype `proto_type`, numbered from 0 for
/// r1, and their total. A struct or union return passes a hidden result pointer in r1 ahead of the parameters. `None`
/// for a missing prototype or a parameter or return type no register holds.
fn arg_registers(btf: &Btf<'_>, proto_type: u32) -> Option<(Vec<Range<usize>>, usize)> {
    let Some(BtfType::FuncProto { return_type, params }) = btf.type_by_id(proto_type) else {
        return None;
    };
    let mut next = match btf.resolve_type(*return_type)?.1 {
        BtfType::Struct { .. } | BtfType::Union { .. } => 1,
        _ => 0,
    };
    let mut ranges = Vec::with_capacity(params.len());
    for param in params {
        let width = match btf.resolve_type(param.type_id)?.1 {
            BtfType::Int { .. } | BtfType::Enum { .. } | BtfType::Ptr { .. } | BtfType::Float { .. } => 1,
            // Clang packs a struct of up to 16 bytes into registers and passes nothing for an empty one. A function
            // gets a larger one by pointer, though calls to it fail to compile.
            BtfType::Struct { size, .. } | BtfType::Union { size, .. } => match size {
                0 => 0,
                9..=16 => 2,
                _ => 1,
            },
            _ => return None,
        };
        ranges.push(next..next + width);
        next += width;
    }
    Some((ranges, next))
}

/// Every module's exported symbols by name; two different definitions of one name fail.
fn build_symbol_table(modules: &[&Module], layouts: &[ModuleLayout]) -> Result<HashMap<String, Addr>> {
    let mut symbols = HashMap::new();

    for (module, layout) in modules.iter().zip(layouts) {
        for (name, export) in &module.exports {
            let Some(&section_addr) = layout.sections.get(&export.section_idx) else {
                continue;
            };
            let addr = section_addr.offset(export.offset);

            if symbols.insert(name.clone(), addr).is_some_and(|prev| prev != addr) {
                return Err(LinkError::DuplicateSymbol(name.clone()).into());
            }
        }
    }

    Ok(symbols)
}

/// Patch the instruction or data that `reloc` points at.
fn apply_relocation(
    helpers: &HelperRegistry,
    natives: &HashSet<String>,
    module: &Module,
    layout: &ModuleLayout,
    global_symbols: &HashMap<String, Addr>,
    reloc: &Relocation,
    image: &mut Image,
) -> Result<()> {
    // relocations in sections that aren't loaded (debug info, BTF) don't matter here
    let Some(&patch) = layout.sections.get(&reloc.section_idx) else {
        return Ok(());
    };
    // an `lddw` spans two instruction slots; every other patch is at most 8 bytes
    let width = match (reloc.rel_type, patch) {
        (reloc::bpf::BPF_64_64, Addr::Code(_)) => 2 * INSN_SIZE,
        _ => 8,
    };
    let size = module.sections[reloc.section_idx].size;
    let inside = reloc.offset.checked_add(width).is_some_and(|end| end <= size);
    let aligned = matches!(patch, Addr::Data(_)) || reloc.offset.is_multiple_of(INSN_SIZE);
    if !inside || !aligned {
        let msg = format!("relocation at {:#x} in a {size} byte section", reloc.offset);
        return Err(LinkError::InvalidReference(msg).into());
    }
    let patch = patch.offset(reloc.offset);

    let symbol = module.symbol_by_idx(reloc.symbol_idx).ok_or_else(|| {
        let idx = reloc.symbol_idx;
        LinkError::InvalidReference(format!("symbol index {idx}"))
    })?;

    // `lddw rX, map`: the guest gets the map's handle, its index in the image. Only a symbol in `.maps`, or an
    // undefined one, names a map; a global of the same name in another module is plain data.
    let in_maps = symbol
        .section_idx
        .is_none_or(|i| module.sections[i].kind == SectionKind::Maps);
    let map = image.maps.iter().position(|d| in_maps && d.name == symbol.name);
    if let (reloc::bpf::BPF_64_64, Addr::Code(at), Some(handle)) = (reloc.rel_type, patch, map) {
        image.set_ld_imm64(at, handle as u64)?;
        return Ok(());
    }

    let sym_addr = if let Some(sym_section_idx) = symbol.section_idx {
        let section_addr = layout
            .jump_tables
            .get(&(reloc.section_idx, sym_section_idx))
            .or_else(|| layout.sections.get(&sym_section_idx))
            .ok_or_else(|| LinkError::InvalidReference(format!("symbol section {sym_section_idx}")))?;
        section_addr.offset(symbol.value)
    } else if let Some(&addr) = global_symbols.get(&symbol.name) {
        addr
    } else if let (reloc::bpf::BPF_64_32, Addr::Code(at)) = (reloc.rel_type, patch) {
        // Call to an extern function, bound to its slot in the extern table on load, or to a native function.
        let name = symbol.name.clone();
        let import = match helpers.native(&name) {
            Some((_, sig)) if natives.contains(&name) => Import::Native { name, sig },
            Some(_) => {
                let reason = "the module has no BTF for the extern to check its signature against".into();
                return Err(LinkError::NativeMismatch { name, reason }.into());
            }
            None if helpers.slot_of_name(&name).is_some() => Import::Name(name),
            None => return Err(LinkError::UnresolvedSymbol(name).into()),
        };
        mark_extern(image, at, import)?;
        return Ok(());
    } else {
        return Err(LinkError::UnresolvedSymbol(symbol.name.clone()).into());
    };

    let bad_target = || LinkError::InvalidReference(format!("relocation type {} -> {}", reloc.rel_type, symbol.name));

    match (reloc.rel_type, patch, sym_addr) {
        (reloc::bpf::BPF_64_64, Addr::Code(at), target) => {
            image.set_ld_imm64(at, target.guest().wrapping_add_signed(reloc.addend))?;
            if let Addr::Data(target) = target {
                let at = Site::Code((at / INSN_SIZE) as u32);
                image.addresses.push(Address {
                    at,
                    region: split_addr(target).0,
                });
            }
        }
        (reloc::bpf::BPF_64_32, Addr::Code(at), Addr::Code(target)) => {
            // BPF-to-BPF call: imm becomes the instruction offset from the next instruction.
            let target = target.wrapping_add_signed(reloc.addend);
            let rel = (target.wrapping_sub(at.wrapping_add(INSN_SIZE)) as i64 / INSN_SIZE as i64) as i32;
            set_imm(image.insn_mut(at)?, rel as u32);
        }
        (reloc::bpf::BPF_64_ABS64, Addr::Data(at), target) => {
            // a data or function pointer stored in global data
            let addr = target.guest().wrapping_add_signed(reloc.addend);
            image.data_mut(at, 8)?.copy_from_slice(&addr.to_le_bytes());
            if let Addr::Data(target) = target {
                let at = match split_addr(at) {
                    (RODATA_REGION, offset) => Site::RoData(offset as u32),
                    (_, offset) => Site::Data(offset as u32),
                };
                image.addresses.push(Address {
                    at,
                    region: split_addr(target).0,
                });
            }
        }
        // calls into data, and relocation types a loaded section shouldn't carry
        _ => return Err(bad_target().into()),
    }

    Ok(())
}

/// Record every `call <helper id>` as an extern, so loaded programs never look helpers up at runtime. Unregistered IDs
/// fail the link.
fn mark_helper_calls(helpers: &HelperRegistry, image: &mut Image) -> Result<()> {
    let calls: Vec<(u32, u32)> = image.helper_calls().collect();
    for (at, id) in calls {
        if helpers.slot_of_id(id).is_none() {
            return Err(LinkError::UnknownHelper(id).into());
        }
        mark_extern(image, at as u64 * INSN_SIZE, Import::Helper(id))?;
    }
    Ok(())
}

/// Record the call at code offset `at` as an extern. Until loading binds it, it calls a slot no table has.
fn mark_extern(image: &mut Image, at: u64, import: Import) -> Result<()> {
    set_slot_call(image.insn_mut(at)?, u32::MAX);
    image.externs.push(((at / INSN_SIZE) as u32, import));
    Ok(())
}

/// Apply CO-RE relocations. Instructions whose target the host lacks become calls that fail when run; malformed or
/// unsupported relocations fail the link.
fn apply_core_relocations_pass(
    modules: &[&Module],
    layouts: &[ModuleLayout],
    btfs: &[Option<Btf<'_>>],
    target: &Btf<'_>,
    image: &mut Image,
) -> Result<()> {
    for ((module, layout), btf) in modules.iter().zip(layouts).zip(btfs) {
        let (Some(btf), Some(btf_ext_data)) = (btf, &module.btf_ext_data) else {
            continue;
        };
        let btf_ext = btf::BtfExt::parse(btf_ext_data, btf.strings())?;

        for (section_idx, section) in module.sections.iter().enumerate() {
            let Some(&Addr::Code(at)) = layout.sections.get(&section_idx) else {
                continue;
            };

            // BTF.ext uses section names like "prog" (from SEC("prog"))
            let relos = btf_ext
                .relos_for_section(&section.name)
                .or_else(|| btf_ext.relos_for_section(section.name.strip_prefix('.').unwrap_or(&section.name)));
            let Some(relos) = relos else {
                continue;
            };

            let (insns, _) = image.code[at as usize..][..section.size as usize].as_chunks_mut::<8>();
            apply_core_relocations(insns, btf, target, relos).map_err(LinkError::CoreRelo)?;
        }
    }
    Ok(())
}

/// Exported functions by name, or each code section by name if no module exports a function.
fn build_function_table(
    modules: &[&Module],
    layouts: &[ModuleLayout],
    btfs: &[Option<Btf<'_>>],
) -> Result<HashMap<String, FunctionInfo>> {
    let mut functions = HashMap::new();
    for ((module, layout), btf) in modules.iter().zip(layouts).zip(btfs) {
        let borrows = function_borrows(btf.as_ref())?;
        for (name, export) in module.exports.iter().filter(|(_, e)| e.is_function) {
            let Some(Addr::Code(at)) = layout
                .sections
                .get(&export.section_idx)
                .map(|a| a.offset(export.offset))
            else {
                continue;
            };
            let info = FunctionInfo {
                pc: at / INSN_SIZE,
                size: export.size,
                borrows: borrows.get(name.as_str()).cloned().unwrap_or_default(),
            };
            functions.insert(name.clone(), info);
        }
    }

    if functions.is_empty() {
        for (module, layout) in modules.iter().zip(layouts) {
            for (idx, section) in module.sections.iter().enumerate() {
                if let Some(&Addr::Code(at)) = layout.sections.get(&idx) {
                    let info = FunctionInfo {
                        pc: at / INSN_SIZE,
                        size: section.size,
                        borrows: Vec::new(),
                    };
                    functions.insert(section.name.clone(), info);
                }
            }
        }
    }

    Ok(functions)
}

/// `borrow:N` / `borrow_ro:N` decl tags on function parameters, by function name, with each parameter mapped to its
/// argument register (see [`arg_registers`]). Both parameters must take one register each.
fn function_borrows(btf: Option<&Btf<'_>>) -> Result<HashMap<String, Vec<Borrow>>> {
    let mut borrows: HashMap<String, Vec<Borrow>> = HashMap::new();
    let Some(btf) = btf else {
        return Ok(borrows);
    };
    for (_, ty) in btf.types() {
        let BtfType::DeclTag {
            name: tag,
            type_id,
            component_idx,
        } = ty
        else {
            continue;
        };
        let (writable, len_arg) = match tag.split_once(':') {
            Some(("borrow", n)) => (true, n),
            Some(("borrow_ro", n)) => (false, n),
            _ => continue,
        };
        let Some(BtfType::Func { name, proto_type, .. }) = btf.type_by_id(*type_id) else {
            continue;
        };
        let params = arg_registers(btf, *proto_type).map(|(params, _)| params);
        let register = |param: usize| {
            let range = params.as_ref()?.get(param)?;
            u8::try_from(range.start).ok().filter(|_| range.len() == 1)
        };
        let borrow = usize::try_from(*component_idx)
            .ok()
            .and_then(register)
            .zip(len_arg.parse().ok().and_then(register))
            .map(|(arg, len_arg)| Borrow { arg, len_arg, writable })
            .filter(Borrow::in_range)
            .ok_or_else(|| {
                LinkError::InvalidReference(format!("{name}: bad tag {tag} on parameter {component_idx}"))
            })?;
        borrows.entry(name.to_string()).or_default().push(borrow);
    }
    Ok(borrows)
}
