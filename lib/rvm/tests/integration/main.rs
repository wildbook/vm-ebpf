//! Integration tests against the compiled fixtures under `bpf/prebuilt/`.

#![cfg_attr(not(miri), feature(alloc_error_hook))]

mod common;
mod corpus;
mod images;
mod linking;
// thousands of loads per fixture, far too slow under Miri
#[cfg(not(miri))]
mod mutations;
mod plugins;
mod programs;
mod regions;
