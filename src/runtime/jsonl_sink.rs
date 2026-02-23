// src/runtime/jsonl_sink.rs
//
// Step 3: Deterministic JSONL sink fed from canonical binary events.
// - No serde_json, no HashMap => stable byte output
// - Strict key order
// - Fail-fast on IO errors (returns Result)

use std::{
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::Path,
};

use super::event::{CapabilityKind, EventHeader, EventKind};

pub struct JsonlSink {
    w: BufWriter<std::fs::File>,
}

impl JsonlSink {
    pub fn new(path: &Path) -> io::Result<Self> {
        // Append-only semantics. Do not truncate.
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            w: BufWriter::new(f),
        })
    }

    #[inline]
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.w.write_all(line.as_bytes())?;
        self.w.write_all(b"\n")?;
        // For governance/audit integrity, flush per line.
        self.w.flush()?;
        Ok(())
    }
}

// ---------- Deterministic JSON helpers (manual formatting) ----------

#[inline]
fn esc_json_str(s: &str) -> String {
    // Deterministic JSON string escape:
    // - backslash, quote, newline, carriage return, tab
    // - Also escape control chars < 0x20 as \u00XX
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // \u00XX
                let v = c as u32;
                out.push_str("\\u00");
                out.push(hex_nibble(((v >> 4) & 0xF) as u8));
                out.push(hex_nibble((v & 0xF) as u8));
            }
            c => out.push(c),
        }
    }
    out
}

#[inline]
fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}

#[inline]
fn json_str(s: &str) -> String {
    format!("\"{}\"", esc_json_str(s))
}

#[inline]
fn json_u64(v: u64) -> String {
    v.to_string()
}

#[inline]
fn json_u32(v: u32) -> String {
    v.to_string()
}

#[inline]
fn json_i32(v: i32) -> String {
    v.to_string()
}

#[inline]
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        s.push(hex_nibble(hi));
        s.push(hex_nibble(lo));
    }
    s
}

#[inline]
fn kind_str(kind: EventKind) -> &'static str {
    match kind {
        EventKind::TaskSpawned => "TaskSpawned",
        EventKind::CapabilityInvoked => "CapabilityInvoked",
        EventKind::FuelExhausted => "FuelExhausted",
        EventKind::ResourceViolation => "ResourceViolation",
        EventKind::RunFinished => "RunFinished",
    }
}

#[inline]
fn cap_kind_str(k: CapabilityKind) -> &'static str {
    match k {
        CapabilityKind::FsRead => "fs.read",
        CapabilityKind::NetListen => "net.listen",
    }
}

// ---------- Deterministic LE decode helpers (no panic, fail-fast) ----------

#[inline]
fn take<const N: usize>(buf: &mut &[u8]) -> io::Result<[u8; N]> {
    if buf.len() < N {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "payload truncated",
        ));
    }
    let (a, rest) = buf.split_at(N);
    *buf = rest;
    let mut out = [0u8; N];
    out.copy_from_slice(a);
    Ok(out)
}

#[inline]
fn read_u16_le(buf: &mut &[u8]) -> io::Result<u16> {
    Ok(u16::from_le_bytes(take::<2>(buf)?))
}

#[inline]
fn read_u32_le(buf: &mut &[u8]) -> io::Result<u32> {
    Ok(u32::from_le_bytes(take::<4>(buf)?))
}

#[inline]
fn read_u64_le(buf: &mut &[u8]) -> io::Result<u64> {
    Ok(u64::from_le_bytes(take::<8>(buf)?))
}

#[inline]
fn read_i32_le(buf: &mut &[u8]) -> io::Result<i32> {
    Ok(i32::from_le_bytes(take::<4>(buf)?))
}

#[inline]
fn read_32(buf: &mut &[u8]) -> io::Result<[u8; 32]> {
    take::<32>(buf)
}

#[inline]
fn decode_cap_kind(tag: u16) -> io::Result<CapabilityKind> {
    match tag {
        1 => Ok(CapabilityKind::FsRead),
        2 => Ok(CapabilityKind::NetListen),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown capability kind tag",
        )),
    }
}

// ---------- Event -> JSONL formatting (stable key order) ----------

fn json_for_task_spawned(h: &EventHeader, payload: &[u8]) -> io::Result<String> {
    let mut p = payload;
    let parent = read_u64_le(&mut p)?;
    let child = read_u64_le(&mut p)?;

    // Key order MUST be stable and identical across runs.
    // {"seq":...,"task":...,"kind":"TaskSpawned","parent":...,"child":...}
    Ok(format!(
        "{{\"seq\":{},\"task\":{},\"kind\":{},\"parent\":{},\"child\":{}}}",
        json_u64(h.seq),
        json_u64(h.task_id),
        json_str(kind_str(h.kind)),
        json_u64(parent),
        json_u64(child),
    ))
}

fn json_for_capability_invoked(h: &EventHeader, payload: &[u8]) -> io::Result<String> {
    let mut p = payload;
    let cap_kind_tag = read_u16_le(&mut p)?;
    let cap_kind = decode_cap_kind(cap_kind_tag)?;
    let cap_id = read_u32_le(&mut p)?;
    let args_digest = read_32(&mut p)?;

    Ok(format!(
        "{{\"seq\":{},\"task\":{},\"kind\":{},\"cap_kind\":{},\"cap_id\":{},\"args_digest\":{}}}",
        json_u64(h.seq),
        json_u64(h.task_id),
        json_str(kind_str(h.kind)),
        json_str(cap_kind_str(cap_kind)),
        json_u32(cap_id),
        json_str(&hex_lower(&args_digest)),
    ))
}

fn json_for_fuel_exhausted(h: &EventHeader, payload: &[u8]) -> io::Result<String> {
    let mut p = payload;
    let budget_before = read_u64_le(&mut p)?;
    let cost = read_u64_le(&mut p)?;

    Ok(format!(
        "{{\"seq\":{},\"task\":{},\"kind\":{},\"budget_before\":{},\"cost\":{}}}",
        json_u64(h.seq),
        json_u64(h.task_id),
        json_str(kind_str(h.kind)),
        json_u64(budget_before),
        json_u64(cost),
    ))
}

fn json_for_resource_violation(h: &EventHeader, payload: &[u8]) -> io::Result<String> {
    let mut p = payload;
    let violation_code = read_u32_le(&mut p)?;
    let detail_digest = read_32(&mut p)?;

    Ok(format!(
        "{{\"seq\":{},\"task\":{},\"kind\":{},\"violation_code\":{},\"detail_digest\":{}}}",
        json_u64(h.seq),
        json_u64(h.task_id),
        json_str(kind_str(h.kind)),
        json_u32(violation_code),
        json_str(&hex_lower(&detail_digest)),
    ))
}

fn json_for_run_finished(h: &EventHeader, payload: &[u8]) -> io::Result<String> {
    let mut p = payload;
    let exit_code = read_i32_le(&mut p)?;
    let run_hash = read_32(&mut p)?;

    Ok(format!(
        "{{\"seq\":{},\"task\":{},\"kind\":{},\"exit_code\":{},\"run_hash\":{}}}",
        json_u64(h.seq),
        json_u64(h.task_id),
        json_str(kind_str(h.kind)),
        json_i32(exit_code),
        json_str(&hex_lower(&run_hash)),
    ))
}

// ---------- Sink implementation ----------

use super::event_sink::EventSink;

impl EventSink for JsonlSink {
    fn on_event(&mut self, header: &EventHeader, payload: &[u8]) -> io::Result<()> {
        let line = match header.kind {
            EventKind::TaskSpawned => json_for_task_spawned(header, payload)?,
            EventKind::CapabilityInvoked => json_for_capability_invoked(header, payload)?,
            EventKind::FuelExhausted => json_for_fuel_exhausted(header, payload)?,
            EventKind::ResourceViolation => json_for_resource_violation(header, payload)?,
            EventKind::RunFinished => json_for_run_finished(header, payload)?,
        };

        self.write_line(&line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}