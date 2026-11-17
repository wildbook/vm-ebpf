//! Host types described as BTF for CO-RE, from their Rust definitions.

use btf::BtfBuilder;

/// A Rust type that adds its C equivalent to a [`BtfBuilder`]. [`crate::host_struct!`]
/// needs it for every field it lists.
///
/// Implement it for a nested struct with [`crate::host_struct!`]:
///
/// ```
/// use rvm::{BtfBuilder, HostType};
///
/// #[repr(C)]
/// struct Pos {
///     x: i32,
///     y: i32,
/// }
///
/// impl HostType for Pos {
///     fn btf_type(types: &mut BtfBuilder) -> u32 {
///         rvm::host_struct!(types, Pos as "pos" { x, y })
///     }
/// }
/// ```
pub trait HostType {
    /// Add the type to `types` and return its BTF type ID.
    fn btf_type(types: &mut BtfBuilder) -> u32;
}

macro_rules! host_int {
    ($($ty:ty => $name:literal),* $(,)?) => {$(
        impl HostType for $ty {
            fn btf_type(types: &mut BtfBuilder) -> u32 {
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
    fn btf_type(types: &mut BtfBuilder) -> u32 {
        types.int("_Bool", 1, false)
    }
}

impl HostType for f32 {
    fn btf_type(types: &mut BtfBuilder) -> u32 {
        types.float("float", 4)
    }
}

impl HostType for f64 {
    fn btf_type(types: &mut BtfBuilder) -> u32 {
        types.float("double", 8)
    }
}

impl<T: HostType, const N: usize> HostType for [T; N] {
    fn btf_type(types: &mut BtfBuilder) -> u32 {
        let elem = T::btf_type(types);
        types.array(elem, N as u32)
    }
}

/// Describe a `#[repr(C)]` host struct to CO-RE, as `struct name` in C.
///
/// Adds the struct to a [`BtfBuilder`] with its size and the listed fields at their
/// offsets, each typed by its [`HostType`], and evaluates to the struct's BTF type ID.
/// `field as "c_name"` gives a field another name in C. Plugins can't relocate
/// accesses to fields left out. `types` is a `&mut BtfBuilder` or the guard from
/// [`crate::Vm::types`].
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
/// rvm::host_struct!(vm.types(), Entity as "entity" { id, hp, pos as "position" });
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
        let types: &mut $crate::BtfBuilder = &mut *$types;
        let id = types.add_struct($name, ::core::mem::size_of::<$ty>() as u32);
        $(
            let field = $crate::__host_field_type(types, |s: &$ty| &s.$field);
            let offset = ::core::mem::offset_of!($ty, $field) as u32;
            types.member(id, $crate::host_struct!(@name $field $($c_name)?), offset, field);
        )*
        id
    }};
}

/// The BTF type of the field that `field` projects to; lets [`host_struct!`] infer it.
#[doc(hidden)]
pub fn __host_field_type<S, T: HostType>(types: &mut BtfBuilder, _field: fn(&S) -> &T) -> u32 {
    T::btf_type(types)
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
    }

    #[test]
    fn host_struct_lists_fields_at_their_offsets() {
        let mut types = BtfBuilder::new();
        let id = crate::host_struct!(&mut types, Entity as "entity" { id, pos as "position", hp });
        let bytes = types.encode();
        let btf = Btf::parse(&bytes).unwrap();

        let Some(BtfTypeInfo::Struct { name, size, members }) = btf.type_by_id(id) else {
            panic!("not a struct");
        };
        assert_eq!((*name, *size), ("entity", 32));
        let fields: Vec<_> = members.iter().map(|m| (m.name, m.bit_offset / 8)).collect();
        assert_eq!(fields, [("id", 0), ("position", 4), ("hp", 24)]);
        let Some(BtfTypeInfo::Array { elem_type, nelems, .. }) = btf.type_by_id(members[1].type_id) else {
            panic!("position is not an array");
        };
        assert_eq!(*nelems, 2);
        assert!(matches!(btf.type_by_id(*elem_type), Some(BtfTypeInfo::Int { size: 4, .. })));
    }
}
