//! Type registry for host application struct layouts.
//!
//! This module provides a way for the host application to register its own
//! struct layouts that eBPF programs can link against. This is the key
//! component for non-kernel CO-RE support.
//!
//! # Example
//!
//! ```
//! use btf::{TypeRegistry, StructField};
//!
//! let mut registry = TypeRegistry::new();
//!
//! // Register a struct layout
//! registry.register_struct("my_event")
//!     .field("timestamp", 0, 8)
//!     .field("pid", 8, 4)
//!     .field("comm", 12, 16)
//!     .size(32);
//!
//! // Query field offsets
//! let offset = registry.field_offset("my_event", "pid");
//! assert_eq!(offset, Some(8));
//! ```

use hashbrown::HashMap;

/// A field within a struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Byte offset from struct start.
    pub offset: u32,
    /// Size in bytes.
    pub size: u32,
    /// Bitfield offset within the byte (0 for non-bitfields).
    pub bit_offset: u8,
    /// Bitfield size in bits (0 for non-bitfields).
    pub bit_size: u8,
}

impl StructField {
    /// Create a new non-bitfield field.
    pub fn new(name: impl Into<String>, offset: u32, size: u32) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            bit_offset: 0,
            bit_size: 0,
        }
    }

    /// Create a bitfield.
    pub fn bitfield(name: impl Into<String>, offset: u32, bit_offset: u8, bit_size: u8) -> Self {
        Self {
            name: name.into(),
            offset,
            size: (bit_offset as u32 + bit_size as u32).div_ceil(8),
            bit_offset,
            bit_size,
        }
    }

    /// Check if this is a bitfield.
    pub fn is_bitfield(&self) -> bool {
        self.bit_size > 0
    }
}

/// A struct definition with its layout.
#[derive(Debug, Clone)]
pub struct StructDef {
    /// Struct name.
    pub name: String,
    /// Total size in bytes.
    pub size: u32,
    /// Fields in order.
    pub fields: Vec<StructField>,
    /// Field lookup by name.
    field_map: HashMap<String, usize>,
}

impl StructDef {
    /// Create a new struct definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            size: 0,
            fields: Vec::new(),
            field_map: HashMap::new(),
        }
    }

    /// Add a field to the struct.
    pub fn field(mut self, name: impl Into<String>, offset: u32, size: u32) -> Self {
        let name = name.into();
        let idx = self.fields.len();
        self.field_map.insert(name.clone(), idx);
        self.fields.push(StructField::new(name, offset, size));
        self
    }

    /// Add a bitfield to the struct.
    pub fn bitfield(mut self, name: impl Into<String>, offset: u32, bit_offset: u8, bit_size: u8) -> Self {
        let name = name.into();
        let idx = self.fields.len();
        self.field_map.insert(name.clone(), idx);
        self.fields
            .push(StructField::bitfield(name, offset, bit_offset, bit_size));
        self
    }

    /// Set the total struct size.
    pub fn size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    /// Get a field by name.
    pub fn get_field(&self, name: &str) -> Option<&StructField> {
        self.field_map.get(name).map(|&idx| &self.fields[idx])
    }

    /// Check if a field exists.
    pub fn has_field(&self, name: &str) -> bool {
        self.field_map.contains_key(name)
    }
}

/// An enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumVariant {
    /// Variant name.
    pub name: String,
    /// Variant value.
    pub value: i64,
}

impl EnumVariant {
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// An enum definition.
#[derive(Debug, Clone)]
pub struct EnumDef {
    /// Enum name.
    pub name: String,
    /// Size in bytes (1, 2, 4, or 8).
    pub size: u32,
    /// Whether values are signed.
    pub is_signed: bool,
    /// Variants.
    pub variants: Vec<EnumVariant>,
    /// Variant lookup by name.
    variant_map: HashMap<String, usize>,
}

impl EnumDef {
    /// Create a new enum definition.
    pub fn new(name: impl Into<String>, size: u32, is_signed: bool) -> Self {
        Self {
            name: name.into(),
            size,
            is_signed,
            variants: Vec::new(),
            variant_map: HashMap::new(),
        }
    }

    /// Add a variant.
    pub fn variant(mut self, name: impl Into<String>, value: i64) -> Self {
        let name = name.into();
        let idx = self.variants.len();
        self.variant_map.insert(name.clone(), idx);
        self.variants.push(EnumVariant::new(name, value));
        self
    }

    /// Get a variant by name.
    pub fn get_variant(&self, name: &str) -> Option<&EnumVariant> {
        self.variant_map.get(name).map(|&idx| &self.variants[idx])
    }

    /// Check if a variant exists.
    pub fn has_variant(&self, name: &str) -> bool {
        self.variant_map.contains_key(name)
    }
}

/// Registry of host application types.
///
/// This is how the host application tells the eBPF loader about its
/// struct layouts, so CO-RE relocations can adjust field accesses.
#[derive(Debug, Clone, Default)]
pub struct TypeRegistry {
    structs: HashMap<String, StructDef>,
    enums: HashMap<String, EnumDef>,
}

impl TypeRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a struct definition.
    ///
    /// Returns the builder for method chaining.
    pub fn register_struct(&mut self, name: impl Into<String>) -> StructDefBuilder<'_> {
        let name = name.into();
        StructDefBuilder {
            registry: self,
            def: StructDef::new(name),
            registered: false,
        }
    }

    /// Register a struct definition directly.
    pub fn add_struct(&mut self, def: StructDef) {
        self.structs.insert(def.name.clone(), def);
    }

    /// Register an enum definition.
    pub fn register_enum(&mut self, name: impl Into<String>, size: u32, is_signed: bool) -> EnumDefBuilder<'_> {
        let name = name.into();
        EnumDefBuilder {
            registry: self,
            def: EnumDef::new(name, size, is_signed),
            registered: false,
        }
    }

    /// Register an enum definition directly.
    pub fn add_enum(&mut self, def: EnumDef) {
        self.enums.insert(def.name.clone(), def);
    }

    /// Get a struct by name.
    pub fn get_struct(&self, name: &str) -> Option<&StructDef> {
        // Handle CO-RE naming convention: strip ___suffix
        let base_name = strip_core_suffix(name);
        self.structs.get(base_name)
    }

    /// Get an enum by name.
    pub fn get_enum(&self, name: &str) -> Option<&EnumDef> {
        let base_name = strip_core_suffix(name);
        self.enums.get(base_name)
    }

    /// Check if a struct exists.
    pub fn has_struct(&self, name: &str) -> bool {
        self.get_struct(name).is_some()
    }

    /// Check if an enum exists.
    pub fn has_enum(&self, name: &str) -> bool {
        self.get_enum(name).is_some()
    }

    /// Get a field's byte offset.
    pub fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<u32> {
        let field_name = strip_core_suffix(field_name);
        self.get_struct(struct_name)?.get_field(field_name).map(|f| f.offset)
    }

    /// Get a field's size.
    pub fn field_size(&self, struct_name: &str, field_name: &str) -> Option<u32> {
        let field_name = strip_core_suffix(field_name);
        self.get_struct(struct_name)?.get_field(field_name).map(|f| f.size)
    }

    /// Check if a field exists.
    pub fn field_exists(&self, struct_name: &str, field_name: &str) -> bool {
        let field_name = strip_core_suffix(field_name);
        self.get_struct(struct_name).is_some_and(|s| s.has_field(field_name))
    }

    /// Get a struct's size.
    pub fn struct_size(&self, name: &str) -> Option<u32> {
        self.get_struct(name).map(|s| s.size)
    }

    /// Get an enum variant's value.
    pub fn enum_value(&self, enum_name: &str, variant_name: &str) -> Option<i64> {
        let variant_name = strip_core_suffix(variant_name);
        self.get_enum(enum_name)?.get_variant(variant_name).map(|v| v.value)
    }

    /// Check if an enum variant exists.
    pub fn enum_variant_exists(&self, enum_name: &str, variant_name: &str) -> bool {
        let variant_name = strip_core_suffix(variant_name);
        self.get_enum(enum_name).is_some_and(|e| e.has_variant(variant_name))
    }
}

/// Builder for struct definitions.
pub struct StructDefBuilder<'a> {
    registry: &'a mut TypeRegistry,
    def: StructDef,
    registered: bool,
}

impl<'a> StructDefBuilder<'a> {
    /// Add a field.
    pub fn field(&mut self, name: impl Into<String>, offset: u32, size: u32) -> &mut Self {
        let name = name.into();
        let idx = self.def.fields.len();
        self.def.field_map.insert(name.clone(), idx);
        self.def.fields.push(StructField::new(name, offset, size));
        self
    }

    /// Add a bitfield.
    pub fn bitfield(&mut self, name: impl Into<String>, offset: u32, bit_offset: u8, bit_size: u8) -> &mut Self {
        let name = name.into();
        let idx = self.def.fields.len();
        self.def.field_map.insert(name.clone(), idx);
        self.def
            .fields
            .push(StructField::bitfield(name, offset, bit_offset, bit_size));
        self
    }

    /// Set the struct size.
    pub fn size(&mut self, size: u32) -> &mut Self {
        self.def.size = size;
        self
    }

    /// Finish building and register the struct.
    pub fn build(&mut self) {
        if !self.registered {
            let def = std::mem::replace(&mut self.def, StructDef::new(""));
            self.registry.structs.insert(def.name.clone(), def);
            self.registered = true;
        }
    }
}

impl Drop for StructDefBuilder<'_> {
    fn drop(&mut self) {
        // Auto-register on drop if not already registered
        if !self.registered && !self.def.name.is_empty() {
            let def = std::mem::replace(&mut self.def, StructDef::new(""));
            self.registry.structs.insert(def.name.clone(), def);
        }
    }
}

/// Builder for enum definitions.
pub struct EnumDefBuilder<'a> {
    registry: &'a mut TypeRegistry,
    def: EnumDef,
    registered: bool,
}

impl<'a> EnumDefBuilder<'a> {
    /// Add a variant.
    pub fn variant(&mut self, name: impl Into<String>, value: i64) -> &mut Self {
        let name = name.into();
        let idx = self.def.variants.len();
        self.def.variant_map.insert(name.clone(), idx);
        self.def.variants.push(EnumVariant::new(name, value));
        self
    }

    /// Finish building and register the enum.
    pub fn build(&mut self) {
        if !self.registered {
            let def = std::mem::replace(&mut self.def, EnumDef::new("", 4, false));
            self.registry.enums.insert(def.name.clone(), def);
            self.registered = true;
        }
    }
}

impl Drop for EnumDefBuilder<'_> {
    fn drop(&mut self) {
        if !self.registered && !self.def.name.is_empty() {
            let def = std::mem::replace(&mut self.def, EnumDef::new("", 4, false));
            self.registry.enums.insert(def.name.clone(), def);
        }
    }
}

/// Strip the CO-RE `___suffix` from a name.
///
/// CO-RE allows defining multiple versions of a type with different suffixes
/// (e.g., `task_struct___old`). The suffix is stripped for matching.
fn strip_core_suffix(name: &str) -> &str {
    name.split_once("___").map_or(name, |(prefix, _)| prefix)
}
