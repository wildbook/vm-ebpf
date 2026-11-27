//! Integration tests against the compiled fixtures under `bpf/prebuilt/`.

#![cfg_attr(not(miri), feature(alloc_error_hook))]

mod common;
mod corpus;
mod images;
mod linking;
// thousands of loads per fixture, far too slow under Miri
#[cfg(not(miri))]
mod mutations;
// Miri can't call the `extern "win64"` natives through their pointers
#[cfg(not(miri))]
mod natives;
mod plugins;
mod programs;
// nor the natives a raw call reaches
#[cfg(not(miri))]
mod raw_calls;
mod regions;
// natives again
#[cfg(not(miri))]
mod stack_args;
