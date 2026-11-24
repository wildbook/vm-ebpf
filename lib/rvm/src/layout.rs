//! Guest memory region layout.
//!
//! | Region | Contents | Guest perms |
//! |---|---|---|
//! | 0 | unmapped (null) | - |
//! | [`STACK_REGION`] | stack, one frame per call level | RW |
//! | [`RODATA_REGION`] | `.rodata*` | R |
//! | [`DATA_REGION`] | `.data*`, `.bss*` | RW |
//! | [`MAPS_REGION`] | map values | RW |
//! | [`FIRST_HOST_REGION`]..[`BORROW_FIRST_REGION`] | host regions: `VmMemory::map`, `Vm::share_region` | per mapping |
//! | [`BORROW_FIRST_REGION`]..[`SHARED_MAPS_FIRST_REGION`] | buffers borrowed during a plugin call | per tag |
//! | [`SHARED_MAPS_FIRST_REGION`]..[`MAX_REGIONS`] | shared maps, one region each | RW |
//! | [`CODE_REGION`] | code addresses for `callx` and `gotox`, never mapped | - |

use crate::error::{Result, VmError};
use crate::executor::MAX_ARGS;
use crate::memory::MAX_REGIONS;

/// Guest region holding the stack.
pub const STACK_REGION: usize = 1;
/// Guest region holding read-only data.
pub const RODATA_REGION: usize = STACK_REGION + 1;
/// Guest region holding writable data and bss.
pub const DATA_REGION: usize = RODATA_REGION + 1;
/// Guest region holding all map values.
pub const MAPS_REGION: usize = DATA_REGION + 1;
/// First host region: the ones that `VmMemory::map` and `Vm::share_region` hand out.
pub const FIRST_HOST_REGION: usize = MAPS_REGION + 1;
/// First of the [`BORROW_REGIONS`] regions in each program reserved for borrowed buffers.
pub const BORROW_FIRST_REGION: usize = SHARED_MAPS_FIRST_REGION - BORROW_REGIONS;
/// Number of borrow regions, one per argument register.
pub const BORROW_REGIONS: usize = MAX_ARGS;
/// First guest region used for shared maps; each shared map has its own region at the same address in every program.
pub const SHARED_MAPS_FIRST_REGION: usize = MAX_REGIONS / 2;
/// Region index of guest code addresses: `region_base(CODE_REGION)` plus a byte offset into the program's code. It lies
/// past the last mappable region, so loads and stores through a code address fault and no data pointer is a valid call
/// target.
pub const CODE_REGION: usize = MAX_REGIONS;

// Each region range in the table above holds at least one region.
const _: () = assert!(FIRST_HOST_REGION < BORROW_FIRST_REGION && SHARED_MAPS_FIRST_REGION < MAX_REGIONS);

/// The host regions, one bit per region.
const HOST_REGIONS: u64 = (1 << BORROW_FIRST_REGION) - (1 << FIRST_HOST_REGION);

/// The lowest host region whose bit in `taken` is clear. Fails with [`VmError::NoFreeRegion`] if there is none.
pub fn free_host_region(taken: u64) -> Result<usize> {
    match HOST_REGIONS & !taken {
        0 => Err(VmError::NoFreeRegion),
        free => Ok(free.trailing_zeros() as usize),
    }
}
