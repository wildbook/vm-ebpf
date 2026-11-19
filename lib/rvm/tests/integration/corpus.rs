//! The programs under `bpf/corpus/` return the same checksums under rvm as compiled natively for the host.
//!
//! [`EXPECTED`] comes from building each `bpf/corpus/*.c` with `clang -O2` for the host, with a host `rvm_bpf.h` that
//! keeps the types and map definitions and implements the map helpers on plain arrays (hash maps fail an update when
//! full, as rvm's do), and a `main` that prints `run(seed)` for each of [`SEEDS`] in order on one instance. Run the
//! same steps after changing a program and paste the output into the table.

use rvm::Vm;

use crate::common::object;

/// The seeds each program runs with, in order on one loaded program, so state kept in maps and globals carries over.
const SEEDS: [u64; 3] = [1, 2, 0xdead_beef];

const EXPECTED: &[(&str, [u64; 3])] = &[
    ("base64", [0x697c52b5decf5da1, 0x414db014fc6b3ee6, 0x7a7c347b1787b779]),
    ("binary_search", [0x0000006900030121, 0x0000005b00032ffc, 0x0000005c0003000a]),
    ("bitset", [0x62b4fb9e633715eb, 0xd453743002d05b0e, 0x36bb586b85af26fc]),
    ("case_trim", [0xc769aad0bf7ba783, 0x10dafd917afa941d, 0x9331c019658fcbe2]),
    ("crc32_bitwise", [0x49761e737c07aa3a, 0x094eb023f5dab278, 0xc7b2c44dbe73e283]),
    ("crc32_table", [0x3e3679b58501dac1, 0x2e3f67c8a5adc510, 0xc6b7370d61644b5a]),
    ("csv_fields", [0xabd027deb5ca03f3, 0x71116cef5186d62a, 0x23a9ee12797f4b9f]),
    ("fixed_point", [0x59b06e14f46e0157, 0x156232e483b5e986, 0xf296777b482c3ec8]),
    ("fnv1a", [0xbf5a1abeeff0cb80, 0x333b0050e91036c0, 0x7fdd81ea8a419ee0]),
    ("fsm_http", [0x1527d06a648ea846, 0x6cfa8067d14eb613, 0x3f8a42b049111ad3]),
    ("fsm_ini", [0x9a92f61846606bd6, 0x6ab9028801183db7, 0xeb0643f55a3dab8c]),
    ("gcd", [0x5c3858c15b48a5a4, 0x578102654fdc8545, 0xe9493bcfbaabbaf4]),
    ("hash_table", [0x008f0000aa000188, 0x00910000b500010e, 0x008d0000b30000c3]),
    ("insertion_sort", [0x7d62b748a76b08a5, 0x6fe9d793dff201c6, 0xca99dbdcd57a8138]),
    ("isqrt", [0xfcc5e2abcf919102, 0x1d58f73e044d17e6, 0xf055a0087dfb9ae6]),
    ("json_tokens", [0x728b4edf549bfb00, 0x57ee1a141a53c6a8, 0x683ec40f43853be9]),
    ("leb128", [0x0a6853c2ca7f0acb, 0xa950172567ed2201, 0x94642567e8128470]),
    ("map_counters", [0x33720bef4d1214da, 0x2a756eabe207e614, 0xbb30a2af7c83e69c]),
    ("offset_list", [0xb82cf6dc86458117, 0x5db203f4925e4d2f, 0x230e842526638cac]),
    ("parse_int", [0x35d1b5e944df1164, 0xcba59612403b2cb3, 0x0ab72ac86ed9ea48]),
    ("popcount", [0x0000107c00760000, 0x00000ff200880000, 0x00001081007d0000]),
    ("rate_limit", [0x00021c00008000a6, 0x00021c00008000c1, 0x00020900007000b0]),
    ("ring_buffer", [0x5aa489c332eea8d0, 0x98ef70965a5b7c19, 0x212b0ad5d4238dce]),
    ("strsearch", [0x7d4438be2c4ae6d0, 0x76b8cca987dfd372, 0xeb4d0a27aa7c54ae]),
    ("struct_array", [0xb1a4f180f8c418dc, 0x90f5c6d0c1247d40, 0x6fb3a40cac0fd760]),
    ("utf8_validate", [0x901ea1581a991466, 0x6f9fb11f0a28ec10, 0x443d0270925e96fa]),
    ("wide_mul", [0xda8a4f76ed87c320, 0x1e1988429da2580f, 0xf84072309518c73c]),
    ("xxhash32", [0x632bc273a62afea8, 0x7abe220168d58ce6, 0xf1581c5c5ba24a4e]),
];

#[test]
fn corpus_matches_native() {
    let dir = format!("{}/../../bpf/prebuilt/corpus", env!("CARGO_MANIFEST_DIR"));
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let file = entry.unwrap().file_name().into_string().unwrap();
        if let Some(name) = file.strip_suffix(".o") {
            names.push(name.to_owned());
        }
    }
    names.sort();
    let expected_names: Vec<&str> = EXPECTED.iter().map(|(name, _)| *name).collect();
    assert_eq!(names, expected_names, "bpf/prebuilt/corpus/ and EXPECTED list different programs");

    for (name, expected) in EXPECTED {
        let mut program = Vm::new().load_elf(&object(&format!("corpus/{name}.o"))).unwrap();
        for (seed, want) in SEEDS.into_iter().zip(expected) {
            let got = match program.call("run", &[seed]) {
                Ok(got) => got,
                Err(e) => panic!("{name}({seed:#x}): {e}"),
            };
            assert_eq!(got, *want, "{name}({seed:#x}): {got:#018x}, native {want:#018x}");
        }
    }
}
