//! Linker for combining multiple eBPF modules.
//!
//! The linker resolves symbol references between modules, applies relocations,
//! and produces an [`Image`] for [`crate::image::load`] to bind and allocate.
//!
//! Code and data live in separate address spaces. Code sections are concatenated
//! into one instruction array (addressed by byte offset during linking, by
//! instruction index at runtime) that the guest cannot read or write. A function
//! pointer or jump table entry is a byte offset into that array in
//! [`CODE_REGION`], which `callx` and `gotox` accept and loads and stores reject.
//! Data sections go into guest memory regions; see [`crate::layout`] for the
//! complete table.

use btf::{apply_core_relocations, Btf, BtfBuilder, BtfTypeInfo};
use constelf::raw::reloc;
use hashbrown::HashMap;

use crate::error::{LinkError, Result, VmError};
use crate::executor::CORE_POISON_HELPER;
use crate::helper::HelperRegistry;
use crate::image::{set_slot_call, Image, Import, BPF_CALL};
use crate::layout::{CODE_REGION, DATA_REGION, RODATA_REGION};
use crate::maps::map_defs;
use crate::memory::{region_base, MAX_REGION_LEN, REGION_SHIFT};
use crate::module::{Module, Relocation};
use crate::program::{Borrow, FunctionInfo};
use crate::section::{Section, SectionKind};

const _: () = assert!(CORE_POISON_HELPER == btf::CORE_POISON_HELPER);

/// Where a section or symbol lives after linking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addr {
    /// Byte offset into the program's code.
    Code(u64),
    /// Guest data address.
    Data(u64),
}

impl Addr {
    /// The address `by` bytes on. A symbol value or relocation offset past the end
    /// of its section wraps here and fails where the address is used.
    fn offset(self, by: u64) -> Self {
        match self {
            Self::Code(a) => Self::Code(a.wrapping_add(by)),
            Self::Data(a) => Self::Data(a.wrapping_add(by)),
        }
    }

    /// The address the guest sees.
    fn guest(self) -> u64 {
        match self {
            Self::Code(a) => region_base(CODE_REGION).wrapping_add(a),
            Self::Data(a) => a,
        }
    }
}

/// Memory layout information for a module: original section index -> address.
#[derive(Debug, Clone, Default)]
struct ModuleLayout {
    sections: HashMap<usize, Addr>,
    /// (code section, `.jumptables` section) -> copy of the tables in `.rodata` with
    /// each entry turned into a guest code address.
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
        let buf = match (addr >> REGION_SHIFT) as usize {
            RODATA_REGION => &mut self.rodata,
            DATA_REGION => &mut self.data,
            _ => return Err(LinkError::InvalidReference(format!("data address {addr:#x}")).into()),
        };
        let at = addr as u32 as usize;
        buf.get_mut(at..)
            .and_then(|b| b.get_mut(..len))
            .ok_or_else(|| LinkError::InvalidReference(format!("data address {addr:#x}")).into())
    }
}

/// Link modules into an image, binding extern calls against `helpers` and CO-RE
/// relocations against `types`.
pub fn link<'m>(helpers: &HelperRegistry, types: &BtfBuilder, modules: &[&'m Module]) -> Result<Image> {
    if modules.is_empty() {
        return Err(VmError::InvalidArgument("no modules to link".to_string()));
    }

    // Each module's BTF, parsed once and shared by every pass below.
    let btfs = modules
        .iter()
        .map(|m| m.btf_data.as_deref().map(Btf::parse).transpose())
        .collect::<std::result::Result<Vec<Option<Btf<'m>>>, _>>()?;

    // The host's types, encoded once as standard BTF and shared by every
    // CO-RE relocation below, the same way a second translation unit would be.
    let target_bytes = types.encode();
    let target = Btf::parse(&target_bytes)?;

    let (mut image, layouts) = lay_out(modules)?;
    let regions = [("code", &image.code), ("rodata", &image.rodata), ("data", &image.data)];
    if let Some((region, _)) = regions.iter().find(|(_, b)| b.len() > MAX_REGION_LEN) {
        return Err(VmError::ProgramTooLarge(region));
    }
    let global_symbols = build_symbol_table(modules, &layouts)?;
    check_extern_signatures(helpers, &btfs)?;

    for (module, btf) in modules.iter().zip(&btfs) {
        for def in map_defs(module, btf.as_ref())? {
            if image.maps.iter().any(|d| d.name == def.name) {
                return Err(LinkError::DuplicateSymbol(def.name).into());
            }
            image.maps.push(def);
        }
    }

    // Relocations bind maps and named externs; then numeric helper calls.
    for (module, layout) in modules.iter().zip(&layouts) {
        for reloc in &module.relocations {
            apply_relocation(helpers, module, layout, &global_symbols, reloc, &mut image)?;
        }
    }
    mark_helper_calls(helpers, &mut image)?;
    apply_core_relocations_pass(modules, &layouts, &btfs, &target, &mut image)?;

    image.functions = build_function_table(modules, &layouts, &btfs)?.into_iter().collect();
    image.functions.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    image.rodata_len = trim_zeros(&mut image.rodata);
    image.data_len = trim_zeros(&mut image.data);
    Ok(image)
}

/// Drop trailing zero bytes, which loading restores, and return the original length.
fn trim_zeros(bytes: &mut Vec<u8>) -> usize {
    let len = bytes.len();
    bytes.truncate(bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1));
    len
}

/// Place every allocatable section and copy its contents into the image.
fn lay_out(modules: &[&Module]) -> Result<(Image, Vec<ModuleLayout>)> {
    // Checks the size before growing `buf`, so a section header can't ask for more
    // than a region holds.
    fn place(buf: &mut Vec<u8>, region: &'static str, section: &Section, align: usize) -> Result<u64> {
        let align = section.align.max(align as u64);
        let end = (buf.len() as u64)
            .checked_next_multiple_of(align)
            .and_then(|at| Some((at, at.checked_add(section.size)?)))
            .filter(|&(_, end)| end <= MAX_REGION_LEN as u64);
        let Some((at, end)) = end else {
            return Err(VmError::ProgramTooLarge(region));
        };
        buf.resize(at as usize, 0);
        buf.extend_from_slice(&section.data);
        buf.resize(end as usize, 0); // .bss has size but no data
        Ok(at)
    }

    let mut image = Image::default();
    let layouts = modules
        .iter()
        .map(|module| {
            let mut layout = ModuleLayout::default();
            for (idx, section) in module.sections.iter().enumerate() {
                let addr = match section.kind {
                    SectionKind::Code => Addr::Code(place(&mut image.code, "code", section, 8)?),
                    SectionKind::RoData => {
                        Addr::Data(region_base(RODATA_REGION) + place(&mut image.rodata, "rodata", section, 1)?)
                    }
                    SectionKind::Data | SectionKind::Bss => {
                        Addr::Data(region_base(DATA_REGION) + place(&mut image.data, "data", section, 1)?)
                    }
                    _ => continue,
                };
                layout.sections.insert(idx, addr);
            }
            lay_out_jump_tables(module, &mut layout, &mut image.rodata);
            Ok(layout)
        })
        .collect::<Result<_>>()?;
    Ok((image, layouts))
}

/// Copy each jump table section that `module`'s code loads into `rodata`, once per
/// code section that loads it. Entries are byte offsets into that code section; the
/// copy holds guest code addresses, which `gotox` takes.
fn lay_out_jump_tables(module: &Module, layout: &mut ModuleLayout, rodata: &mut Vec<u8>) {
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

        let at = rodata.len().next_multiple_of(8);
        rodata.resize(at, 0);
        for entry in table.data.as_chunks::<8>().0 {
            let target = Addr::Code(code.wrapping_add(u64::from_le_bytes(*entry)));
            rodata.extend_from_slice(&target.guest().to_le_bytes());
        }
        layout
            .jump_tables
            .insert(key, Addr::Data(region_base(RODATA_REGION) + at as u64));
    }
}

/// Compare each host-bound extern's BTF prototype with the registered function's
/// argument count. Modules without BTF and host functions without a known arity
/// (raw and context helpers) are not checked.
fn check_extern_signatures(helpers: &HelperRegistry, btfs: &[Option<Btf<'_>>]) -> Result<()> {
    const BTF_FUNC_EXTERN: u16 = 2;

    for btf in btfs.iter().flatten() {
        for (_, ty) in btf.types() {
            let BtfTypeInfo::Func {
                name,
                proto_type,
                linkage: BTF_FUNC_EXTERN,
            } = ty
            else {
                continue;
            };
            let Some(host) = helpers.slot_of_name(name).and_then(|slot| helpers.arity(slot)) else {
                continue;
            };
            let Some(BtfTypeInfo::FuncProto { params, .. }) = btf.type_by_id(*proto_type) else {
                continue;
            };
            // a trailing unnamed void parameter marks a variadic prototype
            if params.last().is_some_and(|p| p.type_id == 0) {
                continue;
            }
            if params.len() != usize::from(host) {
                let name = name.to_string();
                return Err(LinkError::SignatureMismatch {
                    name,
                    declared: params.len(),
                    host,
                }
                .into());
            }
        }
    }
    Ok(())
}

/// Every module's exported symbols by name; two different definitions of one name
/// fail.
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
    let patch = patch.offset(reloc.offset);

    let symbol = module.symbol_by_idx(reloc.symbol_idx).ok_or_else(|| {
        let idx = reloc.symbol_idx;
        LinkError::InvalidReference(format!("symbol index {idx}"))
    })?;

    // `lddw rX, map`: the guest gets the map's handle, its index in the image.
    let map = image.maps.iter().position(|d| d.name == symbol.name);
    if let (reloc::bpf::BPF_64_64, Addr::Code(at), Some(handle)) = (reloc.rel_type, patch, map) {
        image.insn_mut(at)?[4..].copy_from_slice(&(handle as u32).to_le_bytes());
        image.insn_mut(at + 8)?[4..].copy_from_slice(&0u32.to_le_bytes());
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
        // Call to an extern function, bound to its slot in the extern table on load.
        if helpers.slot_of_name(&symbol.name).is_none() {
            return Err(LinkError::UnresolvedSymbol(symbol.name.clone()).into());
        }
        mark_extern(image, at, Import::Name(symbol.name.clone()))?;
        return Ok(());
    } else {
        return Err(LinkError::UnresolvedSymbol(symbol.name.clone()).into());
    };

    let bad_target = || LinkError::InvalidReference(format!("relocation type {} -> {}", reloc.rel_type, symbol.name));

    match (reloc.rel_type, patch, sym_addr) {
        (reloc::bpf::BPF_64_64, Addr::Code(at), target) => {
            // LD_IMM64: split the address across the imm fields of both slots.
            let addr = target.guest().wrapping_add_signed(reloc.addend);
            image.insn_mut(at)?[4..8].copy_from_slice(&(addr as u32).to_le_bytes());
            image.insn_mut(at + 8)?[4..8].copy_from_slice(&((addr >> 32) as u32).to_le_bytes());
        }
        (reloc::bpf::BPF_64_32, Addr::Code(at), Addr::Code(target)) => {
            // BPF-to-BPF call: imm becomes the instruction offset from the next instruction.
            let target = target.wrapping_add_signed(reloc.addend);
            let rel = (target.wrapping_sub(at.wrapping_add(8)) as i64 / 8) as i32;
            image.insn_mut(at)?[4..8].copy_from_slice(&rel.to_le_bytes());
        }
        (reloc::bpf::BPF_64_ABS64, Addr::Data(at), target) => {
            // a data or function pointer stored in global data
            let addr = target.guest().wrapping_add_signed(reloc.addend);
            image.data_mut(at, 8)?.copy_from_slice(&addr.to_le_bytes());
        }
        // calls into data, and relocation types a loaded section shouldn't carry
        _ => return Err(bad_target().into()),
    }

    Ok(())
}

/// Record every `call <helper id>` as an extern, so loaded programs never look
/// helpers up at runtime. Unregistered IDs fail the link.
fn mark_helper_calls(helpers: &HelperRegistry, image: &mut Image) -> Result<()> {
    const BPF_LD_IMM64: u8 = 0x18;

    let mut i = 0;
    while let Some(insn) = image.code.as_chunks::<8>().0.get(i) {
        if insn[0] == BPF_LD_IMM64 {
            i += 2;
            continue;
        }
        if insn[0] == BPF_CALL && insn[1] >> 4 == 0 {
            let id = u32::from_le_bytes(insn[4..].try_into().unwrap());
            if helpers.slot_of_id(id).is_none() {
                return Err(LinkError::UnknownHelper(id).into());
            }
            mark_extern(image, i as u64 * 8, Import::Helper(id))?;
        }
        i += 1;
    }
    Ok(())
}

/// Record the call at code offset `at` as an extern. Until loading binds it, it
/// calls a slot no table has.
fn mark_extern(image: &mut Image, at: u64, import: Import) -> Result<()> {
    set_slot_call(image.insn_mut(at)?, u32::MAX);
    image.externs.push(((at / 8) as u32, import));
    Ok(())
}

/// Apply CO-RE relocations. Instructions whose target the host lacks become calls
/// that fail when run; malformed or unsupported relocations fail the link.
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

            let bytes = &mut image.code[at as usize..(at + section.size) as usize];
            let mut insns: Vec<u64> = bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|w| u64::from_le_bytes(*w))
                .collect();
            apply_core_relocations(&mut insns, btf, target, relos).map_err(LinkError::CoreRelo)?;
            for (dst, insn) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(&insns) {
                *dst = insn.to_le_bytes();
            }
        }
    }
    Ok(())
}

/// Exported functions by name, or each code section by name if no module exports a
/// function.
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
                pc: at / 8,
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
                        pc: at / 8,
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

/// `borrow:N` / `borrow_ro:N` decl tags on function parameters, by function name.
fn function_borrows(btf: Option<&Btf<'_>>) -> Result<HashMap<String, Vec<Borrow>>> {
    let mut borrows: HashMap<String, Vec<Borrow>> = HashMap::new();
    let Some(btf) = btf else {
        return Ok(borrows);
    };
    for (_, ty) in btf.types() {
        let BtfTypeInfo::DeclTag {
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
        let Some(BtfTypeInfo::Func { name, .. }) = btf.type_by_id(*type_id) else {
            continue;
        };
        let borrow = u8::try_from(*component_idx)
            .ok()
            .zip(len_arg.parse::<u8>().ok())
            .map(|(arg, len_arg)| Borrow { arg, len_arg, writable })
            .filter(Borrow::in_range)
            .ok_or_else(|| {
                LinkError::InvalidReference(format!("{name}: bad tag {tag} on parameter {component_idx}"))
            })?;
        borrows.entry(name.to_string()).or_default().push(borrow);
    }
    Ok(borrows)
}
