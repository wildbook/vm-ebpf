//! Function prototypes extracted from BTF and carried in prepared [`Image`](crate::Image)s.

#[cfg(feature = "link")]
use std::ops::Range;

#[cfg(feature = "link")]
use btf::{Btf, BtfType};
#[cfg(feature = "ffi")]
use rvm_core::{GeneralArg, GeneralProto, GeneralRet};
use rvm_core::{NativeArg, NativeSig, MAX_NATIVE_ARGS};

use crate::error::{LinkError, Result};
use crate::program::Borrow;

/// One parameter of a plugin's C declaration, as BTF describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    /// Integer, enum, or struct/union of 1, 2, 4 or 8 bytes (one register slot).
    Int,
    /// Pointer to data (one register slot).
    Ptr,
    /// Function pointer (pointer to `FUNC_PROTO`, one register slot).
    Callback,
    /// `float` (4) or `double` (8) (one register slot).
    Float(u8),
    /// Struct/union of 3, 5, 6 or 7 bytes (one register slot) or 9 to 16 bytes (two register slots).
    Copy(u8),
}

impl ArgKind {
    /// Guest register slots this parameter occupies (r1 to r5, then stack slots).
    pub const fn regs(self) -> usize {
        match self {
            Self::Copy(9..=16) => 2,
            _ => 1,
        }
    }
}

/// The return type of a plugin's C declaration, as BTF describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnKind {
    Void,
    /// Integer, enum, or struct/union of 1, 2, 4 or 8 bytes (returned in r0).
    Int,
    /// Pointer (returned in r0).
    Ptr,
    /// `float` (4) or `double` (8).
    Float(u8),
    /// Struct, union, or integer of another size (3, 5, 6, 7, 9 to 16, or over 16 bytes).
    Agg(u32),
}

/// Prototype of an extern function as the plugin declared it in C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proto {
    /// Parameters in C order (zero-sized structs omitted, matching clang's register assignment).
    pub args: Vec<ArgKind>,
    pub ret: ReturnKind,
    pub variadic: bool,
    /// `borrow` / `borrow_ro` tags on pointer parameters, indexed by argument register.
    pub borrows: Vec<Borrow>,
}

impl Proto {
    /// Number of guest argument registers (r1 to r5, then stack slots), including the hidden result pointer for
    /// returns larger than 16 bytes.
    pub fn reg_count(&self) -> usize {
        let sret = usize::from(matches!(self.ret, ReturnKind::Agg(n) if n > 16));
        sret + self.args.iter().map(|a| a.regs()).sum::<usize>()
    }

    /// Whether the guest expects a two-register return in r0 and r2 (9 to 16 bytes).
    pub fn wide_return(&self) -> bool {
        matches!(self.ret, ReturnKind::Agg(9..=16))
    }

    /// Whether a native call with this prototype needs the `GENERAL` marshalling handler instead of the fast
    /// integer/pointer handlers.
    pub fn needs_general(&self) -> bool {
        self.variadic
            || matches!(self.ret, ReturnKind::Float(_) | ReturnKind::Agg(_))
            || self
                .args
                .iter()
                .any(|a| matches!(a, ArgKind::Float(_) | ArgKind::Copy(_)))
    }

    /// Check that this prototype matches a host-registered native signature `sig`.
    pub fn check_native_sig(&self, name: &str, sig: NativeSig) -> Result<()> {
        let mismatch = |reason: String| LinkError::NativeMismatch {
            name: name.to_string(),
            reason,
        };
        if self.variadic != sig.is_variadic() {
            let reason = match self.variadic {
                true => "the extern is variadic",
                false => "the host's signature is variadic",
            };
            return Err(mismatch(reason.into()).into());
        }
        #[cfg(not(feature = "ffi"))]
        if self.variadic {
            return Err(mismatch("the extern is variadic (enable the `ffi` feature)".into()).into());
        }
        if self.args.len() != usize::from(sig.args()) {
            let (name, declared, host) = (name.to_string(), self.args.len(), sig.args());
            return Err(LinkError::SignatureMismatch { name, declared, host }.into());
        }
        check_fast_return(name, self.ret)?;

        for (n, &arg) in (1u8..).zip(&self.args) {
            let pointer = match arg {
                ArgKind::Int => false,
                ArgKind::Ptr | ArgKind::Callback => true,
                _ => return Err(mismatch(format!("parameter {n} is neither an integer nor a pointer")).into()),
            };
            if pointer != !matches!(sig.arg(n), Some(NativeArg::Int)) {
                let host = if pointer { "an integer" } else { "a pointer" };
                return Err(mismatch(format!("parameter {n} is {host} in the host's signature")).into());
            }
        }
        for borrow in &self.borrows {
            if !borrow_matches(borrow, sig) {
                let n = borrow.arg + 1;
                let reason = format!("parameter {n} has a borrow tag the host's signature doesn't match");
                return Err(mismatch(reason).into());
            }
        }
        Ok(())
    }

    /// Build a [`GeneralProto`] for `GENERAL` marshalling. When `host_sig` is `Some`, pointer parameters are checked
    /// against it in tagged programs; when `None`, pointer parameters lose their tags unchecked.
    #[cfg(feature = "ffi")]
    pub fn general_proto(&self, name: &str, host_sig: Option<NativeSig>, tagged: bool) -> Result<GeneralProto> {
        let mismatch = |reason: String| LinkError::NativeMismatch {
            name: name.to_string(),
            reason,
        };
        let ret = match self.ret {
            ReturnKind::Void | ReturnKind::Int | ReturnKind::Ptr => GeneralRet::Int,
            ReturnKind::Float(4) => GeneralRet::F32,
            ReturnKind::Float(8) => GeneralRet::F64,
            ReturnKind::Agg(3 | 5 | 6 | 7) => GeneralRet::SmallAgg,
            ReturnKind::Agg(9..=16) => GeneralRet::WideAgg,
            ReturnKind::Agg(size) if size > 16 => GeneralRet::Sret(size),
            ReturnKind::Agg(size) => return Err(mismatch(format!("unsupported return struct size {size}")).into()),
            ReturnKind::Float(size) => return Err(mismatch(format!("unsupported float return size {size}")).into()),
        };

        let guest_regs = self.reg_count();
        if guest_regs > MAX_NATIVE_ARGS {
            return Err(LinkError::TooManyRegisters {
                name: name.to_string(),
                registers: guest_regs,
            }
            .into());
        }
        let native_slots = usize::from(matches!(ret, GeneralRet::SmallAgg | GeneralRet::WideAgg | GeneralRet::Sret(_)))
            + self.args.len();
        if native_slots > MAX_NATIVE_ARGS {
            return Err(LinkError::TooManyRegisters {
                name: name.to_string(),
                registers: native_slots,
            }
            .into());
        }

        let mut args = [GeneralArg::Value; MAX_NATIVE_ARGS];
        for (i, &arg) in self.args.iter().enumerate() {
            args[i] = match arg {
                ArgKind::Int | ArgKind::Float(4 | 8) => GeneralArg::Value,
                ArgKind::Ptr | ArgKind::Callback => {
                    if !tagged {
                        GeneralArg::Value
                    } else if let Some(sig) = host_sig {
                        match sig.arg((i + 1) as u8) {
                            Some(NativeArg::Read(len)) => GeneralArg::Checked {
                                write: false,
                                len_arg: len.unwrap_or(0),
                            },
                            Some(NativeArg::Write(len)) => GeneralArg::Checked {
                                write: true,
                                len_arg: len.unwrap_or(0),
                            },
                            _ => GeneralArg::Value,
                        }
                    } else {
                        GeneralArg::Strip
                    }
                }
                ArgKind::Copy(3 | 5 | 6 | 7) => GeneralArg::Copy1,
                ArgKind::Copy(9..=16) => GeneralArg::Copy2,
                ArgKind::Copy(size) => {
                    let n = i + 1;
                    return Err(mismatch(format!("parameter {n}: unsupported struct size {size}")).into());
                }
                ArgKind::Float(size) => {
                    let n = i + 1;
                    return Err(mismatch(format!("parameter {n}: unsupported float size {size}")).into());
                }
            };
        }

        Ok(GeneralProto {
            args,
            nargs: self.args.len() as u8,
            ret,
            variadic: self.variadic,
            aware: host_sig.is_some_and(NativeSig::is_aware),
        })
    }

    /// Build a [`NativeSig`] from this prototype when the resolver trusts the plugin's BTF (`Resolved::sig` is
    /// `None`). Pointer parameters are marked so `STRIP` handlers strip their tags in tagged programs.
    pub fn native_sig(&self, name: &str) -> Result<NativeSig> {
        let mismatch = |reason: String| LinkError::NativeMismatch {
            name: name.to_string(),
            reason,
        };
        if self.variadic {
            return Err(mismatch("the extern is variadic".into()).into());
        }
        if self.args.len() > MAX_NATIVE_ARGS {
            return Err(LinkError::TooManyRegisters {
                name: name.to_string(),
                registers: self.args.len(),
            }
            .into());
        }
        check_fast_return(name, self.ret)?;

        let mut list = [NativeArg::Int; MAX_NATIVE_ARGS];
        for (i, &arg) in self.args.iter().enumerate() {
            list[i] = match arg {
                ArgKind::Int => NativeArg::Int,
                ArgKind::Ptr | ArgKind::Callback => NativeArg::Read(None),
                _ => {
                    let n = i + 1;
                    return Err(mismatch(format!("parameter {n} is neither an integer nor a pointer")).into());
                }
            };
        }
        NativeSig::try_new(&list[..self.args.len()]).ok_or_else(|| mismatch("invalid native signature".into()).into())
    }
}

/// Check that `ret` fits the fast native handlers (returned in `rax` or void).
fn check_fast_return(name: &str, ret: ReturnKind) -> Result<()> {
    let mismatch = |reason: String| LinkError::NativeMismatch {
        name: name.to_string(),
        reason,
    };
    match ret {
        ReturnKind::Void | ReturnKind::Int | ReturnKind::Ptr => Ok(()),
        ReturnKind::Agg(size) => {
            let reason = format!("the extern returns a struct of {size} bytes, not of 1, 2, 4 or 8");
            Err(mismatch(reason).into())
        }
        ReturnKind::Float(_) => {
            let reason = "the extern returns something other than an integer, a pointer or a struct".into();
            Err(mismatch(reason).into())
        }
    }
}

/// Whether `sig` declares the pointer that `borrow` tags, with its length argument and access.
fn borrow_matches(borrow: &Borrow, sig: NativeSig) -> bool {
    let len = Some(borrow.len_arg + 1);
    match sig.arg(borrow.arg + 1) {
        Some(NativeArg::Read(l)) => !borrow.writable && l == len,
        Some(NativeArg::Write(l)) => borrow.writable && l == len,
        _ => false,
    }
}

/// Extract a [`Proto`] from BTF `FUNC_PROTO` `proto_type`. Returns `None` if the prototype is missing or contains a
/// parameter or return type no register holds.
#[cfg(feature = "link")]
pub fn from_btf(btf: &Btf<'_>, proto_type: u32, borrows: Vec<Borrow>) -> Option<Proto> {
    let Some(BtfType::FuncProto { return_type, params }) = btf.type_by_id(proto_type) else {
        return None;
    };
    let ret = return_kind(btf, *return_type)?;
    let (variadic, params) = match params.last() {
        Some(last) if last.type_id == 0 => (true, &params[..params.len() - 1]),
        _ => (false, params.as_slice()),
    };

    let mut args = Vec::with_capacity(params.len());
    for param in params {
        if let Some(kind) = arg_kind(btf, param.type_id)? {
            args.push(kind);
        }
    }
    Some(Proto {
        args,
        ret,
        variadic,
        borrows,
    })
}

/// Register-position range of each C parameter of `proto_type` (0 to 4 for r1 to r5, 5 on for stack slots), accounting
/// for a hidden result pointer when the return type exceeds 16 bytes.
#[cfg(feature = "link")]
pub fn param_ranges(btf: &Btf<'_>, proto_type: u32) -> Option<Vec<Range<usize>>> {
    let Some(BtfType::FuncProto { return_type, params }) = btf.type_by_id(proto_type) else {
        return None;
    };
    let ret = return_kind(btf, *return_type)?;
    let params = match params.last() {
        Some(last) if last.type_id == 0 => &params[..params.len() - 1],
        _ => params.as_slice(),
    };
    let mut next = usize::from(matches!(ret, ReturnKind::Agg(n) if n > 16));
    let mut ranges = Vec::with_capacity(params.len());
    for param in params {
        let width = match arg_kind(btf, param.type_id)? {
            None => 0,
            Some(kind) => kind.regs(),
        };
        ranges.push(next..next + width);
        next += width;
    }
    Some(ranges)
}

#[cfg(feature = "link")]
fn return_kind(btf: &Btf<'_>, type_id: u32) -> Option<ReturnKind> {
    Some(match btf.resolve_type(type_id)?.1 {
        BtfType::Void => ReturnKind::Void,
        BtfType::Int { size: ..=8, .. } | BtfType::Enum { .. } => ReturnKind::Int,
        BtfType::Int { size, .. } => ReturnKind::Agg(*size),
        BtfType::Ptr { .. } => ReturnKind::Ptr,
        BtfType::Float {
            size: size @ (4 | 8), ..
        } => ReturnKind::Float(*size as u8),
        BtfType::Struct { size, .. } | BtfType::Union { size, .. } => match *size {
            0 => ReturnKind::Void,
            1 | 2 | 4 | 8 => ReturnKind::Int,
            other => ReturnKind::Agg(other),
        },
        _ => return None,
    })
}

/// Returns `Ok` (`Some(None)`) for a zero-sized struct (0 registers), `Some(Some(kind))` for a supported parameter,
/// and `None` for an unsupported type.
#[cfg(feature = "link")]
fn arg_kind(btf: &Btf<'_>, type_id: u32) -> Option<Option<ArgKind>> {
    Some(match btf.resolve_type(type_id)?.1 {
        BtfType::Int { size: ..=8, .. } | BtfType::Enum { .. } => Some(ArgKind::Int),
        BtfType::Int {
            size: size @ 9..=16, ..
        } => Some(ArgKind::Copy(*size as u8)),
        BtfType::Ptr { pointee_type } => {
            let is_fn = btf
                .resolve_type(*pointee_type)
                .is_some_and(|(_, ty)| matches!(ty, BtfType::FuncProto { .. }));
            Some(if is_fn { ArgKind::Callback } else { ArgKind::Ptr })
        }
        BtfType::Float {
            size: size @ (4 | 8), ..
        } => Some(ArgKind::Float(*size as u8)),
        BtfType::Struct { size, .. } | BtfType::Union { size, .. } => match *size {
            0 => None,
            1 | 2 | 4 | 8 => Some(ArgKind::Int),
            3 | 5 | 6 | 7 | 9..=16 => Some(ArgKind::Copy(*size as u8)),
            _ => return None,
        },
        _ => return None,
    })
}
