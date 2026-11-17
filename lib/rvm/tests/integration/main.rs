//! Integration tests against the compiled fixtures under `bpf/prebuilt/`.

#![feature(alloc_error_hook)]

mod common;
mod images;
mod linking;
// thousands of loads per fixture, far too slow under Miri
#[cfg(not(miri))]
mod mutations;
mod plugins;
mod programs;
mod regions;
