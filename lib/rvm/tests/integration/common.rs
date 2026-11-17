//! Shared fixture loading for the integration tests.

/// Read a compiled fixture by its path under `bpf/`.
pub fn object(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../bpf/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}
