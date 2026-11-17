//! Reading map definitions from a module's BTF.

use btf::{Btf, BtfTypeInfo};

use super::{check_def, invalid, MapDef, MapKind};
use crate::error::Result;
use crate::module::Module;
use crate::section::SectionKind;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;

/// Map definitions declared in `module`'s `.maps` section.
pub fn map_defs(module: &Module, btf: Option<&Btf<'_>>) -> Result<Vec<MapDef>> {
    let has_maps = module.sections.iter().any(|s| s.kind == SectionKind::Maps);
    let (true, Some(btf)) = (has_maps, btf) else {
        return Ok(Vec::new());
    };

    let mut defs = Vec::new();
    for (_, ty) in btf.types() {
        let BtfTypeInfo::DataSec {
            name: ".maps", vars, ..
        } = ty
        else {
            continue;
        };
        for var in vars {
            let Some(BtfTypeInfo::Var { name, type_id, .. }) = btf.type_by_id(var.type_id) else {
                continue;
            };
            defs.push(parse_def(btf, name, *type_id)?);
        }
    }
    Ok(defs)
}

/// Parse one libbpf map definition: `__uint(field, n)` is `int (*field)[n]`, and
/// `__type(field, T)` is `T *field`.
fn parse_def(btf: &Btf<'_>, name: &str, type_id: u32) -> Result<MapDef> {
    let bad = |what: &str| invalid(format!("map {name}: {what}"));

    let Some(BtfTypeInfo::Struct { members, .. }) = resolve(btf, type_id) else {
        return Err(bad("definition is not a struct"));
    };

    let (mut kind, mut max_entries, mut key_size, mut value_size) = (None, None, None, None);
    for member in members {
        let Some(BtfTypeInfo::Ptr { pointee_type }) = resolve(btf, member.type_id) else {
            return Err(bad("field is not a pointer"));
        };
        let pointee = resolve(btf, *pointee_type);
        let uint = || match pointee {
            Some(BtfTypeInfo::Array { nelems, .. }) => Ok(*nelems),
            _ => Err(bad("expected __uint")),
        };
        match member.name {
            "type" => kind = Some(uint()?),
            "max_entries" => max_entries = Some(uint()?),
            "key_size" => key_size = Some(uint()?),
            "value_size" => value_size = Some(uint()?),
            "key" => key_size = Some(resolve_size(btf, *pointee_type).ok_or_else(|| bad("unsized key"))?),
            "value" => value_size = Some(resolve_size(btf, *pointee_type).ok_or_else(|| bad("unsized value"))?),
            _ => {}
        }
    }

    let kind = match kind.ok_or_else(|| bad("missing type"))? {
        BPF_MAP_TYPE_HASH => MapKind::Hash,
        BPF_MAP_TYPE_ARRAY => MapKind::Array,
        other => return Err(bad(&format!("unsupported map type {other}"))),
    };
    let key_size = key_size.ok_or_else(|| bad("missing key"))?;
    let value_size = value_size.ok_or_else(|| bad("missing value"))?;
    let max_entries = max_entries.ok_or_else(|| bad("missing max_entries"))?;

    let def = MapDef {
        name: name.to_string(),
        kind,
        key_size,
        value_size,
        max_entries,
    };
    check_def(&def)?;
    Ok(def)
}

fn resolve<'a, 'b>(btf: &'b Btf<'a>, id: u32) -> Option<&'b BtfTypeInfo<'a>> {
    btf.resolve_type(id).map(|(_, ty)| ty)
}

fn resolve_size(btf: &Btf<'_>, id: u32) -> Option<u32> {
    btf.resolve_size(id).and_then(|s| u32::try_from(s).ok())
}
