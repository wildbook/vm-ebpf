//! Guest memory region layout.
//!
//! | Region | Contents | Guest perms |
//! |---|---|---|
//! | 0 | unmapped (null) | - |
//! | [`STACK_REGION`] | stack, one frame per call level | RW |
//! | [`RODATA_REGION`] | `.rodata*` | R |
//! | [`DATA_REGION`] | `.data*`, `.bss*` | RW |
//! | [`MAPS_REGION`] | map values | RW |
//! | [`FIRST_FREE_REGION`]..[`BORROW_FIRST_REGION`] | free for the host, `Vm::share_region` | - |
//! | [`BORROW_FIRST_REGION`]..[`SHARED_MAPS_FIRST_REGION`] | buffers borrowed during a plugin call | per tag |
//! | [`SHARED_MAPS_FIRST_REGION`]..[`MAX_REGIONS`] | shared maps, one region each | RW |
//! | [`CODE_REGION`] | code addresses for `callx` and `gotox`, never mapped | - |

use crate::memory::MAX_REGIONS;

/// Guest region holding the stack.
pub const STACK_REGION: usize = 1;
/// Guest region holding read-only data.
pub const RODATA_REGION: usize = 2;
/// Guest region holding writable data and bss.
pub const DATA_REGION: usize = 3;
/// Guest region holding all map values.
pub const MAPS_REGION: usize = 4;
/// First region index the linker leaves free for the host.
pub const FIRST_FREE_REGION: usize = MAPS_REGION + 1;
/// First of the [`BORROW_REGIONS`] regions in each program reserved for borrowed
/// buffers.
pub const BORROW_FIRST_REGION: usize = SHARED_MAPS_FIRST_REGION - BORROW_REGIONS;
/// Number of borrow regions, one per argument register.
pub const BORROW_REGIONS: usize = 5;
/// First guest region used for shared maps; each shared map has its own region at
/// the same address in every program.
pub const SHARED_MAPS_FIRST_REGION: usize = MAX_REGIONS / 2;
/// Region index of guest code addresses: `region_base(CODE_REGION)` plus a byte offset
/// into the program's code. It lies past the last mappable region, so loads and
/// stores through a code address fault and no data pointer is a valid call target.
pub const CODE_REGION: usize = MAX_REGIONS;
