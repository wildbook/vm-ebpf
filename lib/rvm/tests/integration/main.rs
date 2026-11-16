//! Integration tests against the compiled fixtures under `bpf/`.

#[cfg(feature = "link")]
mod common;
mod conformance;
#[cfg(feature = "link")]
mod images;
#[cfg(feature = "link")]
mod linking;
#[cfg(feature = "link")]
mod plugins;
#[cfg(feature = "link")]
mod programs;
#[cfg(feature = "link")]
mod regions;
