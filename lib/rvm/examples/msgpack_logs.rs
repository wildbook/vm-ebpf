//! Streams MessagePack log events through a parser plugin in fixed-size chunks.
//!
//! `bpf/examples/msgpack_logs.c` decodes records with a `switch` over the MessagePack tag bytes, which clang compiles
//! to a jump table (`gotox`), hands known keys to handlers through a table of function pointers (`callx`), and adds
//! each event to per-service stats in a hash map and two array maps. The decoder is split into BPF-to-BPF calls.
//!
//! The host maps a read-only input region into the program, copies each chunk in and calls `parse` through a function
//! handle. `parse` returns how many bytes of complete records it consumed. The host keeps the rest and passes it again
//! in front of the next chunk, so a record split across chunks is parsed once. At the end, the host reads the stats
//! from the maps and checks them against its own tally of the events it generated.
//!
//! Rebuild the plugin with the CMake project in the repo root.
//!
//! Run with: cargo run -p rvm --example msgpack_logs

use std::error::Error;

use rvm::{Perms, Pod, Program, Vm};

const PARSER: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf/prebuilt/examples/msgpack_logs.o"));

const RECORDS: usize = 400;
const CHUNK: usize = 96;
/// Room for a chunk and the start of a record carried over from the one before.
const INPUT_LEN: usize = 4096;

const SERVICES: [&str; 5] = ["api", "auth", "billing", "search", "web"];
const LEVELS: [&str; 4] = ["debug", "info", "warn", "error"];
const NAME_LEN: usize = 16;

fn main() -> Result<(), Box<dyn Error>> {
    let (stream, expected) = generate(RECORDS);

    let vm = Vm::new();
    let mut parser = vm.load_elf(PARSER)?;
    let input = parser.memory_mut().map(rvm::FIRST_FREE_REGION, INPUT_LEN, Perms::R)?;
    let parse = parser.func("parse")?;

    let mut pending = Vec::new();
    for chunk in stream.chunks(CHUNK) {
        pending.extend_from_slice(chunk);
        parser.memory_mut().write_bytes(input, &pending)?;
        let consumed = parser.call_func(parse, &[input, pending.len() as u64])?;
        let consumed = usize::try_from(consumed)
            .ok()
            .filter(|&n| n <= pending.len())
            .ok_or_else(|| format!("the plugin claims to have parsed {consumed} of {} bytes", pending.len()))?;
        pending.drain(..consumed);
    }
    if !pending.is_empty() {
        return Err(format!("the stream ends inside a record, {} bytes in", pending.len()).into());
    }

    let stats = read_stats(&mut parser)?;
    print_stats(&stats, stream.len());
    if stats != expected {
        return Err(format!("the plugin's stats differ from the host's tally: {expected:?}").into());
    }
    println!("matches the host's tally");
    Ok(())
}

fn read_stats(parser: &mut Program) -> Result<Stats, Box<dyn Error>> {
    let totals = parser.map("totals")?;
    let [events, services, skipped_fields, other_records]: [u64; 4] = totals.get_as(0u32)?.ok_or("no totals")?;

    let map = parser.map("services")?;
    let entries = map.entries();
    let services = entries.iter_as::<u32, SvcStats>()?.take(services as usize);
    let services = services.map(|(_, s)| s.into()).collect();

    Ok(Stats {
        events,
        skipped_fields,
        other_records,
        services,
    })
}

fn print_stats(stats: &Stats, bytes: usize) {
    let chunks = bytes.div_ceil(CHUNK);
    let records = stats.events + stats.other_records;
    println!("{bytes} bytes in {chunks} chunks of {CHUNK}: {records} records");
    println!(
        "{} events, {} other records, {} unknown fields skipped",
        stats.events, stats.other_records, stats.skipped_fields
    );

    println!("service   events  debug  info  warn  error  avg ms  max ms  MiB out");
    for s in &stats.services {
        let [debug, info, warn, error] = s.by_level;
        let avg = s.ms_total / s.events;
        let mib = s.bytes as f64 / (1 << 20) as f64;
        println!(
            "{:<8}  {:>6}  {debug:>5}  {info:>4}  {warn:>4}  {error:>5}  {avg:>6}  {:>6}  {mib:>7.1}",
            s.name, s.events, s.ms_max
        );
    }
}

/// The stats as the plugin keeps them in its `totals` and `services` maps.
#[derive(Debug, Default, PartialEq)]
struct Stats {
    events: u64,
    skipped_fields: u64,
    other_records: u64,
    services: Vec<Service>,
}

/// One service's stats.
#[derive(Debug, Default, PartialEq)]
struct Service {
    name: String,
    events: u64,
    by_level: [u64; 4],
    ms_total: u64,
    ms_max: u64,
    bytes: u64,
}

impl From<SvcStats> for Service {
    fn from(s: SvcStats) -> Self {
        let name = &s.name[..s.name.iter().position(|&b| b == 0).unwrap_or(NAME_LEN)];
        Self {
            name: String::from_utf8_lossy(name).into_owned(),
            events: s.events,
            by_level: s.by_level,
            ms_total: s.ms_total,
            ms_max: s.ms_max,
            bytes: s.bytes,
        }
    }
}

impl Stats {
    fn service(&mut self, name: &str) -> &mut Service {
        match self.services.iter().position(|s| s.name == name) {
            Some(i) => &mut self.services[i],
            None => {
                let name = name.to_string();
                self.services.push(Service {
                    name,
                    ..Service::default()
                });
                self.services.last_mut().unwrap()
            }
        }
    }
}

/// `struct svc_stats`, a value of the `services` map.
#[repr(C)]
#[derive(Clone, Copy)]
struct SvcStats {
    name: [u8; NAME_LEN],
    events: u64,
    by_level: [u64; 4],
    ms_total: u64,
    ms_max: u64,
    bytes: u64,
}

// SAFETY: integer fields only, and the `u64`s start at an 8 byte offset, so there is no padding.
unsafe impl Pod for SvcStats {}

/// Encodes `records` log records and tallies what the parser should make of them. Every 40th record is a heartbeat and
/// every 57th a map without a service name; the rest are events, some with fields the parser doesn't know.
fn generate(records: usize) -> (Vec<u8>, Stats) {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let mut stream = Vec::new();
    let mut stats = Stats::default();

    for i in 1..=records {
        let record = if i % 40 == 0 {
            stats.other_records += 1;
            Value::Ext(1, (i as u64 * 1000).to_be_bytes().to_vec())
        } else if i % 57 == 0 {
            stats.other_records += 1;
            stats.skipped_fields += 1;
            Value::Map(vec![field("lvl", "warn".into()), field("msg", "config reloaded".into())])
        } else {
            event(&mut rng, &mut stats)
        };
        record.encode(&mut stream);
    }
    (stream, stats)
}

fn event(rng: &mut Rng, stats: &mut Stats) -> Value {
    let svc = SERVICES[rng.below(5) as usize];
    let level = match rng.below(20) {
        0..4 => 0,
        4..15 => 1,
        15..18 => 2,
        _ => 3,
    };
    let ms = match rng.below(10) {
        0 => rng.below(100_000),
        1..3 => rng.below(2_000),
        _ => rng.below(120),
    };
    let bytes = if level == 3 { 0 } else { rng.below(1 << 20) };

    let mut fields = vec![
        field("svc", svc.into()),
        field("lvl", LEVELS[level].into()),
        field("ms", Value::Int(ms as i64)),
        field("bytes", Value::Int(bytes as i64)),
    ];
    let extras = [
        field("trace", Value::Bin(rng.next().to_le_bytes().to_vec())),
        field("user", if rng.below(2) == 0 { Value::Nil } else { "u-8812".into() }),
        field("retry", Value::Bool(rng.below(2) == 0)),
        field("ratio", Value::F64(rng.below(1000) as f64 / 1000.0)),
        field("delta", Value::Int(-(rng.below(40_000) as i64))),
        field("msg", "upstream answered after the deadline; retrying once".into()),
        field("tags", Value::Array(vec!["beta".into(), "eu".into()])),
        field("ctx", Value::Map(vec![field("region", "eu-west".into()), field("shard", Value::Int(7))])),
    ];
    for extra in extras {
        if rng.below(4) == 0 {
            fields.insert(rng.below(fields.len() as u64 + 1) as usize, extra);
            stats.skipped_fields += 1;
        }
    }

    stats.events += 1;
    let s = stats.service(svc);
    s.events += 1;
    s.by_level[level] += 1;
    s.ms_total += ms;
    s.ms_max = s.ms_max.max(ms);
    s.bytes += bytes;
    Value::Map(fields)
}

fn field(key: &str, value: Value) -> (Value, Value) {
    (key.into(), value)
}

/// A MessagePack value, encoded in its shortest form.
enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    F64(f64),
    Str(String),
    Bin(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Ext(i8, Vec<u8>),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::Str(s.to_string())
    }
}

impl Value {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Nil => out.push(0xc0),
            Self::Bool(b) => out.push(0xc2 | *b as u8),
            Self::Int(n) => encode_int(*n, out),
            Self::F64(x) => {
                out.push(0xcb);
                out.extend(x.to_be_bytes());
            }
            Self::Str(s) => {
                match s.len() {
                    len @ 0..32 => out.push(0xa0 | len as u8),
                    len @ 32..256 => out.extend([0xd9, len as u8]),
                    len => panic!("string of {len} bytes"),
                }
                out.extend(s.as_bytes());
            }
            Self::Bin(b) => {
                out.extend([0xc4, b.len().try_into().expect("short binary")]);
                out.extend(b);
            }
            Self::Array(items) => {
                out.push(0x90 | u8::try_from(items.len()).ok().filter(|&n| n < 16).expect("short array"));
                items.iter().for_each(|v| v.encode(out));
            }
            Self::Map(entries) => {
                out.push(0x80 | u8::try_from(entries.len()).ok().filter(|&n| n < 16).expect("short map"));
                for (k, v) in entries {
                    k.encode(out);
                    v.encode(out);
                }
            }
            Self::Ext(ty, data) => {
                let tag = match data.len() {
                    1 => 0xd4,
                    2 => 0xd5,
                    4 => 0xd6,
                    8 => 0xd7,
                    16 => 0xd8,
                    len => panic!("extension of {len} bytes"),
                };
                out.extend([tag, *ty as u8]);
                out.extend(data);
            }
        }
    }
}

fn encode_int(n: i64, out: &mut Vec<u8>) {
    match n {
        0..=0x7f => out.push(n as u8),
        0x80..=0xff => out.extend([0xcc, n as u8]),
        0x100..=0xffff => {
            out.push(0xcd);
            out.extend((n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xce);
            out.extend((n as u32).to_be_bytes());
        }
        -32..=-1 => out.push(n as u8),
        -0x80..=-33 => out.extend([0xd0, n as u8]),
        -0x8000..=-0x81 => {
            out.push(0xd1);
            out.extend((n as i16).to_be_bytes());
        }
        -0x8000_0000..=-0x8001 => {
            out.push(0xd2);
            out.extend((n as i32).to_be_bytes());
        }
        _ => {
            out.push(0xd3);
            out.extend(n.to_be_bytes());
        }
    }
}

/// xorshift64, so the stream is the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}
