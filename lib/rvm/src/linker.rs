//! Linker for combining multiple eBPF modules.
//!
//! The linker resolves symbol references between modules, applies relocations,
//! and produces a linked program ready for execution.
//!
//! Code and data live in separate address spaces. Code sections are concatenated
//! into one instruction array (addressed by byte offset during linking, by
//! instruction index at runtime) that the guest cannot read or write. Data
//! sections go into guest memory regions; see [`crate::layout`] for the complete
//! table.

use std::sync::Arc;

use btf::{apply_core_relocations, Btf, BtfTypeInfo, TypeRegistry};
use constelf::raw::reloc;
use hashbrown::HashMap;
use rvm_core::instructions_from_bytes;

use crate::error::{LinkError, Result, VmError};
use crate::executor::MAX_CALL_DEPTH;
use crate::helper::{HelperRegistry, SharedHelpers};
use crate::layout::{DATA_REGION, MAPS_REGION, RODATA_REGION, STACK_REGION};
use crate::maps::{map_defs, MapDef, Maps, SharedMaps};
use crate::memory::{region_base, Perms, SharedRegion, VmMemory, REGION_SHIFT};
use crate::module::{Module, Relocation};
use crate::program::{Borrow, FunctionInfo, Program};
use crate::section::{Section, SectionKind};
use crate::vm::VmConfig;

/// `src_reg` of a call into the extern table (`imm` = slot).
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;

/// Turn a call instruction into a call to extern-table `slot`.
fn set_slot_call(insn: &mut [u8; 8], slot: u32) {
    insn[1] = (insn[1] & 0x0F) | (BPF_PSEUDO_KFUNC_CALL << 4);
    insn[4..8].copy_from_slice(&slot.to_le_bytes());
}

/// Where a section or symbol lives after linking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Addr {
    /// Byte offset into the program's code.
    Code(u64),
    /// Guest data address.
    Data(u64),
}

impl Addr {
    fn offset(self, by: u64) -> Self {
        match self {
            Self::Code(a) => Self::Code(a + by),
            Self::Data(a) => Self::Data(a + by),
        }
    }
}

/// Memory layout information for a module: original section index -> address.
#[derive(Debug, Clone, Default)]
struct ModuleLayout {
    sections: HashMap<usize, Addr>,
}

/// Linked image before it becomes a [`Program`].
struct Image {
    code: Vec<u8>,
    rodata: Vec<u8>,
    data: Vec<u8>,
}

impl Image {
    /// The 8-byte instruction at code offset `at`.
    fn insn_mut(&mut self, at: u64) -> Result<&mut [u8; 8]> {
        let at = at as usize;
        self.code
            .get_mut(at..at + 8)
            .map(|s| s.try_into().unwrap())
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

/// Linker for eBPF modules.
pub struct Linker<'a> {
    helpers: &'a Arc<SharedHelpers>,
    shared_maps: &'a SharedMaps,
    shared_regions: &'a [SharedRegion],
    types: &'a TypeRegistry,
    config: &'a VmConfig,
}

impl<'a> Linker<'a> {
    /// Create a new linker.
    pub fn new(
        helpers: &'a Arc<SharedHelpers>,
        shared_maps: &'a SharedMaps,
        shared_regions: &'a [SharedRegion],
        types: &'a TypeRegistry,
        config: &'a VmConfig,
    ) -> Self {
        Self {
            helpers,
            shared_maps,
            shared_regions,
            types,
            config,
        }
    }

    /// Link multiple modules into a single program.
    pub fn link<'m>(&self, modules: &[&'m Module]) -> Result<Program> {
        if modules.is_empty() {
            return Err(VmError::InvalidArgument("no modules to link".to_string()));
        }

        // Bind against one version of the table; the program refreshes from there.
        let (helpers, version) = self.helpers.snapshot();

        // Each module's BTF, parsed once and shared by every pass below.
        let btfs = modules
            .iter()
            .map(|m| m.btf_data.as_deref().map(Btf::parse).transpose())
            .collect::<std::result::Result<Vec<Option<Btf<'m>>>, _>>()?;

        let (mut image, layouts) = Self::lay_out(modules);
        let global_symbols = Self::build_symbol_table(modules, &layouts)?;
        Self::check_extern_signatures(&helpers, &btfs)?;

        let mut defs = Vec::new();
        for (module, btf) in modules.iter().zip(&btfs) {
            for def in map_defs(module, btf.as_ref())? {
                if defs.iter().any(|d: &MapDef| d.name == def.name) {
                    return Err(LinkError::DuplicateSymbol(def.name).into());
                }
                defs.push(def);
            }
        }
        let (maps, maps_len) = Maps::new(defs, self.shared_maps)?;

        // Relocations bind maps and named externs; then numeric helper calls.
        for (module, layout) in modules.iter().zip(&layouts) {
            for reloc in &module.relocations {
                Self::apply_relocation(&helpers, &maps, module, layout, &global_symbols, reloc, &mut image)?;
            }
        }
        Self::bind_helper_calls(&helpers, &mut image)?;
        self.apply_core_relocations(modules, &layouts, &btfs, &mut image);

        let functions = Self::build_function_table(modules, &layouts, &btfs)?;

        let mut memory = VmMemory::new();
        let stack_len = self.config.frame_size * (MAX_CALL_DEPTH + 1);
        memory.map(STACK_REGION, stack_len, Perms::RW);
        memory.map_bytes(RODATA_REGION, &image.rodata, image.rodata.len(), Perms::R);
        memory.map_bytes(DATA_REGION, &image.data, image.data.len(), Perms::RW);
        if maps_len != 0 {
            memory.map(MAPS_REGION, maps_len, Perms::RW);
        }
        // SAFETY: the callers of `Vm::share_map`/`Vm::share_region` accepted the
        // `map_shared` contract.
        unsafe {
            for shared in maps.shared() {
                memory.map_shared(shared.region(), shared.storage().clone(), Perms::RW);
            }
            for shared in self.shared_regions {
                memory.map_shared(shared.region(), shared.buffer().clone(), shared.perms());
            }
        }

        let code = instructions_from_bytes(&image.code);

        Ok(Program::new(code, memory, maps, functions, self.helpers.clone(), (helpers, version), self.config))
    }

    /// Place every allocatable section and copy its contents into the image.
    fn lay_out(modules: &[&Module]) -> (Image, Vec<ModuleLayout>) {
        fn place(buf: &mut Vec<u8>, section: &Section, align: usize) -> u64 {
            let at = buf.len().next_multiple_of(section.align.max(align as u64) as usize);
            buf.resize(at, 0);
            buf.extend_from_slice(&section.data);
            buf.resize(at + section.size as usize, 0); // .bss has size but no data
            at as u64
        }

        let mut image = Image {
            code: Vec::new(),
            rodata: Vec::new(),
            data: Vec::new(),
        };
        let layouts = modules
            .iter()
            .map(|module| {
                let mut layout = ModuleLayout::default();
                for (idx, section) in module.sections.iter().enumerate() {
                    let addr = match section.kind {
                        SectionKind::Code => Addr::Code(place(&mut image.code, section, 8)),
                        SectionKind::RoData => {
                            Addr::Data(region_base(RODATA_REGION) + place(&mut image.rodata, section, 1))
                        }
                        SectionKind::Data | SectionKind::Bss => {
                            Addr::Data(region_base(DATA_REGION) + place(&mut image.data, section, 1))
                        }
                        _ => continue,
                    };
                    layout.sections.insert(idx, addr);
                }
                layout
            })
            .collect();
        (image, layouts)
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

    /// Build a global symbol table from all modules.
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

    /// Apply a single relocation.
    fn apply_relocation(
        helpers: &HelperRegistry,
        maps: &Maps,
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

        // `lddw rX, map`: the guest gets the map's handle.
        if let (reloc::bpf::BPF_64_64, Addr::Code(at), Some(handle)) =
            (reloc.rel_type, patch, maps.handle(&symbol.name))
        {
            image.insn_mut(at)?[4..8].copy_from_slice(&handle.to_le_bytes());
            image.insn_mut(at + 8)?[4..8].copy_from_slice(&0u32.to_le_bytes());
            return Ok(());
        }

        let sym_addr = if symbol.is_defined() {
            let sym_section_idx = symbol.section_idx.unwrap();
            let section_addr = layout
                .sections
                .get(&sym_section_idx)
                .ok_or_else(|| LinkError::InvalidReference(format!("symbol section {sym_section_idx}")))?;
            section_addr.offset(symbol.value)
        } else if let Some(&addr) = global_symbols.get(&symbol.name) {
            addr
        } else if let (reloc::bpf::BPF_64_32, Addr::Code(at)) = (reloc.rel_type, patch) {
            // Call to an extern function: bind it to its slot in the extern table.
            let slot = helpers
                .slot_of_name(&symbol.name)
                .ok_or_else(|| LinkError::UnresolvedSymbol(symbol.name.clone()))?;
            set_slot_call(image.insn_mut(at)?, slot);
            return Ok(());
        } else {
            return Err(LinkError::UnresolvedSymbol(symbol.name.clone()).into());
        };

        let bad_target =
            || LinkError::InvalidReference(format!("relocation type {} -> {}", reloc.rel_type, symbol.name));

        match (reloc.rel_type, patch, sym_addr) {
            (reloc::bpf::BPF_64_64, Addr::Code(at), Addr::Data(addr)) => {
                // LD_IMM64: split the address across the imm fields of both slots.
                let addr = addr.wrapping_add_signed(reloc.addend);
                image.insn_mut(at)?[4..8].copy_from_slice(&(addr as u32).to_le_bytes());
                image.insn_mut(at + 8)?[4..8].copy_from_slice(&((addr >> 32) as u32).to_le_bytes());
            }
            (reloc::bpf::BPF_64_32, Addr::Code(at), Addr::Code(target)) => {
                // BPF-to-BPF call: imm becomes the instruction offset from the next instruction.
                let target = target.wrapping_add_signed(reloc.addend);
                let rel = ((target as i64 - (at + 8) as i64) / 8) as i32;
                image.insn_mut(at)?[4..8].copy_from_slice(&rel.to_le_bytes());
            }
            (reloc::bpf::BPF_64_ABS64, Addr::Data(at), Addr::Data(addr)) => {
                // a pointer stored in global data
                let addr = addr.wrapping_add_signed(reloc.addend);
                image.data_mut(at, 8)?.copy_from_slice(&addr.to_le_bytes());
            }
            // Code addresses aren't guest-visible, so function pointers and calls into data
            // can't be resolved; nor can relocation types a loaded section shouldn't carry.
            _ => return Err(bad_target().into()),
        }

        Ok(())
    }

    /// Rewrite every `call <helper id>` into a slot call, so linked programs never
    /// look helpers up at runtime. Unregistered IDs fail the link.
    fn bind_helper_calls(helpers: &HelperRegistry, image: &mut Image) -> Result<()> {
        const BPF_CALL: u8 = 0x85;
        const BPF_LD_IMM64: u8 = 0x18;

        let (insns, _) = image.code.as_chunks_mut::<8>();
        let mut i = 0;
        while i < insns.len() {
            let insn = &mut insns[i];
            if insn[0] == BPF_LD_IMM64 {
                i += 2;
                continue;
            }
            if insn[0] == BPF_CALL && insn[1] >> 4 == 0 {
                let id = u32::from_le_bytes(insn[4..8].try_into().unwrap());
                let slot = helpers.slot_of_id(id).ok_or(LinkError::UnknownHelper(id))?;
                set_slot_call(insn, slot);
            }
            i += 1;
        }
        Ok(())
    }

    /// Apply CO-RE relocations. Failures leave the compile-time values in place.
    fn apply_core_relocations(
        &self,
        modules: &[&Module],
        layouts: &[ModuleLayout],
        btfs: &[Option<Btf<'_>>],
        image: &mut Image,
    ) {
        for ((module, layout), btf) in modules.iter().zip(layouts).zip(btfs) {
            let (Some(btf), Some(btf_ext_data)) = (btf, &module.btf_ext_data) else {
                continue;
            };
            let Ok(btf_ext) = btf::BtfExt::parse(btf_ext_data, btf.strings()) else {
                continue;
            };

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
                let _ = apply_core_relocations(&mut insns, btf, self.types, relos);
                for (dst, insn) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(&insns) {
                    *dst = insn.to_le_bytes();
                }
            }
        }
    }

    /// Build the function table.
    fn build_function_table(
        modules: &[&Module],
        layouts: &[ModuleLayout],
        btfs: &[Option<Btf<'_>>],
    ) -> Result<HashMap<String, FunctionInfo>> {
        let mut functions = HashMap::new();
        for ((module, layout), btf) in modules.iter().zip(layouts).zip(btfs) {
            let borrows = Self::borrows(btf.as_ref())?;
            for (name, export) in module.exports.iter().filter(|(_, e)| e.is_function) {
                let Some(Addr::Code(at)) = layout
                    .sections
                    .get(&export.section_idx)
                    .map(|a| a.offset(export.offset))
                else {
                    continue;
                };
                let info = FunctionInfo {
                    name: name.clone(),
                    pc: at / 8,
                    size: export.size,
                    borrows: borrows.get(name.as_str()).cloned().unwrap_or_default(),
                };
                functions.insert(name.clone(), info);
            }
        }

        // If no named functions, use code sections as entry points.
        if functions.is_empty() {
            for (module, layout) in modules.iter().zip(layouts) {
                for (idx, section) in module.sections.iter().enumerate() {
                    if let Some(&Addr::Code(at)) = layout.sections.get(&idx) {
                        let info = FunctionInfo {
                            name: section.name.clone(),
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
    fn borrows(btf: Option<&Btf<'_>>) -> Result<HashMap<String, Vec<Borrow>>> {
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
            let bad = || LinkError::InvalidReference(format!("{name}: bad tag {tag} on parameter {component_idx}"));
            let arg = u8::try_from(*component_idx).ok().filter(|&a| a < 5).ok_or_else(bad)?;
            let len_arg = len_arg
                .parse::<u8>()
                .ok()
                .filter(|&a| a < 5 && a != arg)
                .ok_or_else(bad)?;
            borrows
                .entry(name.to_string())
                .or_default()
                .push(Borrow { arg, len_arg, writable });
        }
        Ok(borrows)
    }
}
