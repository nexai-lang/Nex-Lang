// src/codegen.rs
#![allow(dead_code, unused_mut, unused_variables)]

use crate::ast::Program;
use anyhow::Result;
use std::path::Path;

pub fn build_project(
    _program: &Program,
    build_dir: &Path,
    runtime_out_dir: &Path,
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
) -> Result<()> {
    if build_dir.exists() {
        std::fs::remove_dir_all(build_dir)?;
    }

    std::fs::create_dir_all(build_dir.join("src"))?;
    std::fs::create_dir_all(runtime_out_dir)?;

    let cargo_toml = r#"[package]
name = "nex_out"
version = "0.1.0"
edition = "2021"

[dependencies]
sha2 = "0.10"
"#;

    std::fs::write(build_dir.join("Cargo.toml"), cargo_toml)?;
    let runner = generate_rust(codegen_hash, source_hash);
    std::fs::write(build_dir.join("src").join("main.rs"), runner)?;

    let status = std::process::Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .current_dir(build_dir)
        .status()?;

    if !status.success() {
        anyhow::bail!("cargo build failed");
    }

    Ok(())
}

fn generate_rust(codegen_hash: [u8; 32], source_hash: [u8; 32]) -> String {
    format!(
        r#"
use std::fs;
use std::io::{{Write, BufWriter}};
use std::sync::{{OnceLock, Mutex, atomic::{{AtomicU64, Ordering}}}};
use sha2::{{Digest, Sha256}};

const LOG_MAGIC: [u8;4] = *b"NEXL";
const LOG_VERSION: u16 = 1;
const LOG_FLAGS: u16 = 0;

const KIND_TASK_STARTED: u16 = 5;
const KIND_TASK_FINISHED: u16 = 6;
const KIND_RUN_STARTED: u16 = 0xFFFE;
const KIND_RUN_FINISHED: u16 = 0xFFFF;

static SEQ: AtomicU64 = AtomicU64::new(0);
static HASHER: OnceLock<Mutex<Sha256>> = OnceLock::new();

fn hasher() -> &'static Mutex<Sha256> {{
    HASHER.get_or_init(|| Mutex::new(Sha256::new()))
}}

fn compute_crc32(bytes: &[u8]) -> u32 {{
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {{
        crc ^= b as u32;
        for _ in 0..8 {{
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }}
    }}
    !crc
}}

fn append_record(task_id: u64, kind: u16, payload: &[u8]) {{
    let mut f = fs::OpenOptions::new()
        .append(true)
        .open("./nex_out/events.bin")
        .unwrap();

    let seq = SEQ.fetch_add(1, Ordering::SeqCst);

    let mut rec = Vec::new();
    rec.extend_from_slice(&seq.to_le_bytes());
    rec.extend_from_slice(&task_id.to_le_bytes());
    rec.extend_from_slice(&kind.to_le_bytes());
    rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    rec.extend_from_slice(payload);

    if kind != KIND_RUN_FINISHED {{
        hasher().lock().unwrap().update(&rec);
    }}

    f.write_all(&rec).unwrap();
}}

fn write_header() {{
    fs::create_dir_all("./nex_out").unwrap();
    let f = fs::File::create("./nex_out/events.bin").unwrap();
    let mut bw = BufWriter::new(f);

    let mut raw = Vec::new();
    raw.extend_from_slice(&LOG_MAGIC);
    raw.extend_from_slice(&LOG_VERSION.to_le_bytes());
    raw.extend_from_slice(&{codegen_hash:?});
    raw.extend_from_slice(&{source_hash:?});
    raw.extend_from_slice(&LOG_FLAGS.to_le_bytes());

    let crc = compute_crc32(&raw);
    raw.extend_from_slice(&crc.to_le_bytes());

    bw.write_all(&raw).unwrap();
    bw.flush().unwrap();

    hasher().lock().unwrap().update(&raw);
}}

fn run_finished(exit_code: i32) {{
    let h = hasher().lock().unwrap().clone().finalize();
    let mut arr = [0u8;32];
    arr.copy_from_slice(&h[..]);

    let mut payload = Vec::new();
    payload.extend_from_slice(&exit_code.to_le_bytes());
    payload.extend_from_slice(&arr);

    append_record(0, KIND_RUN_FINISHED, &payload);
}}

fn main() {{
    write_header();
    append_record(0, KIND_RUN_STARTED, &[]);

    append_record(0, KIND_TASK_STARTED, &[]);

    let mut exit_code: i32 = 0;

    let r = std::panic::catch_unwind(|| {{
    }});

    if r.is_err() {{
        exit_code = 1;
    }}

    append_record(0, KIND_TASK_FINISHED, &exit_code.to_le_bytes());

    run_finished(exit_code);
}}
"#
    )
}
