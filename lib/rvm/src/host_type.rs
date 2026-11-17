//! Host types described as BTF for CO-RE, from their Rust definitions.

use std::any::TypeId;
use std::ops::{Deref, DerefMut};

use btf::BtfBuilder;
use hashbrown::HashMap;

/// The host's types, as BTF, for CO-RE; see [`crate::Vm::with_types`]. Dereferences to its [`BtfBuilder`].
///
/// Each Rust type is described once: [`HostTypes::add`] and [`crate::host_struct!`] return the type ID from the first
/// time, so struct fields of the same type and repeated descriptions share one BTF type and CO-RE never sees two
/// candidates for one name.
#[derive(Default)]
pub struct HostTypes {
    btf: BtfBuilder,
    ids: HashMap<TypeId, u32>,
}

impl HostTypes {
    /// The BTF type ID of `T`, adding `T` the first time.
    pub fn add<T: HostType + 'static>(&mut self) -> u32 {
        self.__memo::<T>(T::btf_type)
    }

    /// The BTF type ID of `T`, adding it with `describe` the first time.
    #[doc(hidden)]
    pub fn __memo<T: 'static>(&mut self, describe: impl FnOnce(&mut Self) -> u32) -> u32 {
        if let Some(&id) = self.ids.get(&TypeId::of::<T>()) {
            return id;
        }
        let id = describe(self);
        self.ids.insert(TypeId::of::<T>(), id);
        id
    }
}

impl Deref for HostTypes {
    type Target = BtfBuilder;

    fn deref(&self) -> &BtfBuilder {
        &self.btf
    }
}

impl DerefMut for HostTypes {
    fn deref_mut(&mut self) -> &mut BtfBuilder {
        &mut self.btf
    }
}

/// A Rust type that adds its C equivalent to [`HostTypes`]. [`crate::host_struct!`] needs it for every field it lists.
///
/// Implement it for a nested struct with [`crate::host_struct!`]:
///
/// ```
/// use rvm::{HostType, HostTypes};
///
/// #[repr(C)]
/// struct Pos {
///     x: i32,
///     y: i32,
/// }
///
/// impl HostType for Pos {
///     fn btf_type(types: &mut HostTypes) -> u32 {
///         rvm::host_struct!(types, Pos as "pos" { x, y })
///     }
/// }
/// ```
pub trait HostType {
    /// Add the type to `types` and return its BTF type ID. [`HostTypes::add`] calls it once per type.
    fn btf_type(types: &mut HostTypes) -> u32;
}

macro_rules! host_int {
    ($($ty:ty => $name:literal),* $(,)?) => {$(
        impl HostType for $ty {
            fn btf_type(types: &mut HostTypes) -> u32 {
                types.int($name, size_of::<$ty>() as u32, <$ty>::MIN != 0)
            }
        }
    )*};
}

host_int!(
    u8 => "unsigned char",
    i8 => "signed char",
    u16 => "unsigned short",
    i16 => "short",
    u32 => "unsigned int",
    i32 => "int",
    u64 => "unsigned long long",
    i64 => "long long",
);

impl HostType for bool {
    fn btf_type(types: &mut HostTypes) -> u32 {
        types.int("_Bool", 1, false)
    }
}

impl HostType for f32 {
    fn btf_type(types: &mut HostTypes) -> u32 {
        types.float("float", 4)
    }
}

impl HostType for f64 {
    fn btf_type(types: &mut HostTypes) -> u32 {
        types.float("double", 8)
    }
}

impl<T: HostType + 'static, const N: usize> HostType for [T; N] {
    fn btf_type(types: &mut HostTypes) -> u32 {
        let elem = types.add::<T>();
        types.array(elem, N as u32)
    }
}

/// Describe a `#[repr(C)]` host struct to CO-RE, as `struct name` in C.
///
/// Adds the struct to [`HostTypes`] with its size and the listed fields at their offsets, each typed by its
/// [`HostType`], and evaluates to the struct's BTF type ID. `field as "c_name"` gives a field another name in C.
/// Plugins can't relocate accesses to fields left out. A struct already described keeps its first description.
///
/// ```
/// #[repr(C)]
/// struct Entity {
///     id: u32,
///     hp: i32,
///     pos: [i32; 2],
///     secret: u64,
/// }
///
/// let vm = rvm::Vm::new();
/// vm.with_types(|types| rvm::host_struct!(types, Entity as "entity" { id, hp, pos as "position" }));
/// ```
#[macro_export]
macro_rules! host_struct {
    (@name $field:ident) => {
        ::core::stringify!($field)
    };
    (@name $field:ident $c_name:literal) => {
        $c_name
    };
    ($types:expr, $ty:ty as $name:literal { $($field:ident $(as $c_name:literal)?),* $(,)? }) => {{
        let types: &mut $crate::HostTypes = &mut *$types;
        types.__memo::<$ty>(|types| {
            let id = types.add_struct($name, ::core::mem::size_of::<$ty>() as u32);
            $(
                let field = $crate::__host_field_type(types, |s: &$ty| &s.$field);
                let offset = ::core::mem::offset_of!($ty, $field) as u32;
                types.member(id, $crate::host_struct!(@name $field $($c_name)?), offset, field);
            )*
            id
        })
    }};
}

/// The BTF type of the field that `field` projects to; lets [`host_struct!`] infer it.
#[doc(hidden)]
pub fn __host_field_type<S, T: HostType + 'static>(types: &mut HostTypes, _field: fn(&S) -> &T) -> u32 {
    types.add::<T>()
}

#[cfg(test)]
mod tests {
    use btf::{Btf, BtfTypeInfo};

    use super::*;

    #[allow(dead_code)]
    #[repr(C)]
    struct Entity {
        id: u32,
        pos: [i32; 2],
        hidden: u64,
        hp: i16,
        target: u32,
    }

    #[test]
    fn host_struct_lists_fields_at_their_offsets() {
        let mut types = HostTypes::default();
        let id = crate::host_struct!(&mut types, Entity as "entity" { id, pos as "position", hp, target });
        // a second description adds nothing
        assert_eq!(crate::host_struct!(&mut types, Entity as "entity" { id }), id);
        let bytes = types.encode();
        let btf = Btf::parse(&bytes).unwrap();

        let Some(BtfTypeInfo::Struct { name, size, members }) = btf.type_by_id(id) else {
            panic!("not a struct");
        };
        assert_eq!((*name, *size), ("entity", 32));
        let fields: Vec<_> = members.iter().map(|m| (m.name, m.bit_offset / 8)).collect();
        assert_eq!(fields, [("id", 0), ("position", 4), ("hp", 24), ("target", 28)]);
        // `u32` fields share one type
        assert_eq!(members[0].type_id, members[3].type_id);
        let Some(BtfTypeInfo::Array { elem_type, nelems, .. }) = btf.type_by_id(members[1].type_id) else {
            panic!("position is not an array");
        };
        assert_eq!(*nelems, 2);
        assert!(matches!(btf.type_by_id(*elem_type), Some(BtfTypeInfo::Int { size: 4, .. })));
        assert_eq!(btf.types().count(), 6); // void, entity, u32, int[2], int, short
    }
}
