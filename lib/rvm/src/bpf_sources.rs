//! Checks that the C side under `bpf/` agrees with rvm: `rvm_bpf.h` declares the same helper IDs and map constants,
//! and `bpf/prebuilt/inputs.sha256` matches the sources, so the committed objects were built from them.

use std::fs;
use std::path::Path;

use crate::std_helpers::STD_HELPERS;

const RVM_BPF_H: &str = include_str!("../../../bpf/rvm_bpf.h");

/// The value of `#define <name> <number>` in `rvm_bpf.h`.
#[cfg(any(feature = "maps", feature = "link"))]
pub fn define(name: &str) -> u64 {
    let value = |line: &str| match line.split_whitespace().collect::<Vec<_>>()[..] {
        ["#define", n, value] if n == name => value.parse().ok(),
        _ => None,
    };
    RVM_BPF_H
        .lines()
        .find_map(value)
        .unwrap_or_else(|| panic!("rvm_bpf.h has no `#define {name} <number>`"))
}

#[test]
fn helpers_match_rvm_bpf_h() {
    let mut declared: Vec<(u32, String)> = RVM_BPF_H.lines().filter_map(helper_decl).collect();
    declared.sort();
    let mut expected: Vec<(u32, String)> = STD_HELPERS
        .iter()
        .map(|&(id, name)| (id, format!("bpf_{name}")))
        .collect();
    expected.sort();

    assert_eq!(declared, expected);
}

/// The ID and name of a helper declaration such as `static u64 (*bpf_ktime_get_ns)(void) = (void *)5;`.
fn helper_decl(line: &str) -> Option<(u32, String)> {
    let (decl, id) = line.split_once("= (void *)")?;
    let name = decl.split_once("(*")?.1.split_once(')')?.0;
    Some((id.trim_end_matches(';').parse().ok()?, name.to_owned()))
}

#[cfg(feature = "maps")]
#[test]
fn map_flags_match_rvm_bpf_h() {
    assert_eq!(define("BPF_ANY"), crate::BPF_ANY);
    assert_eq!(define("BPF_NOEXIST"), crate::BPF_NOEXIST);
    assert_eq!(define("BPF_EXIST"), crate::BPF_EXIST);
}

#[test]
#[cfg_attr(miri, ignore = "reads files")]
fn prebuilt_objects_match_sources() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let recorded = fs::read_to_string(root.join("bpf/prebuilt/inputs.sha256"))
        .unwrap()
        .replace("\r\n", "\n");
    let current = input_hashes(&root);

    let missing_from = |text: &str, line: &str| !text.lines().any(|l| l == line);
    let mut changed: Vec<&str> = recorded
        .lines()
        .filter(|line| missing_from(&current, line))
        .chain(current.lines().filter(|line| missing_from(&recorded, line)))
        .map(|line| line.split_once("  ").map_or(line, |(_, path)| path))
        .collect();
    changed.sort();
    changed.dedup();
    assert!(
        changed.is_empty(),
        "bpf/prebuilt/ was built from other sources ({}); rebuild it with `cmake --preset bpf` and `cmake --build \
         --preset update-prebuilt`",
        changed.join(", ")
    );
}

/// `inputs.sha256` as `cmake/hash-inputs.cmake` writes it: a `<sha256>  <path>` line per input of the BPF objects,
/// sorted by path, hashing CRLF line ends as LF.
fn input_hashes(root: &Path) -> String {
    let mut paths = vec!["CMakeLists.txt".to_owned()];
    for entry in fs::read_dir(root.join("cmake")).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".cmake") {
            paths.push(format!("cmake/{name}"));
        }
    }
    bpf_inputs(root, "bpf", &mut paths);
    paths.sort();

    let mut out = String::new();
    for path in paths {
        let text = fs::read(root.join(&path)).unwrap();
        let text = String::from_utf8(text).unwrap().replace("\r\n", "\n");
        out += &format!("{}  {path}\n", sha256(text.as_bytes()));
    }
    out
}

/// Adds the C sources, headers and CMake lists under `dir` to `paths`.
fn bpf_inputs(root: &Path, dir: &str, paths: &mut Vec<String>) {
    for entry in fs::read_dir(root.join(dir)).unwrap() {
        let entry = entry.unwrap();
        let path = format!("{dir}/{}", entry.file_name().into_string().unwrap());
        if entry.file_type().unwrap().is_dir() {
            bpf_inputs(root, &path, paths);
        } else if path.ends_with(".c") || path.ends_with(".h") || path.ends_with("/CMakeLists.txt") {
            paths.push(path);
        }
    }
}

/// SHA-256 of `data` as lowercase hex.
fn sha256(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    msg.push(0x80);
    msg.resize((msg.len() + 8).next_multiple_of(64) - 8, 0);
    msg.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());

    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for (k, w) in K.into_iter().zip(w) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k).wrapping_add(w);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            (hh, g, f, e, d, c, b) = (g, f, e, d.wrapping_add(t1), c, b, a);
            a = t1.wrapping_add(s0).wrapping_add(maj);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}
