#![cfg(not(feature = "coop_scheduler"))]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BUNDLE_MAGIC: &[u8; 4] = b"NEXB";

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct BundleSections {
    bytes: Vec<u8>,
    events_offset: usize,
    events_len: usize,
    evidence_bytes: Vec<u8>,
}

#[test]
fn bundle_roundtrip_ok() {
    let (out_dir, build_dir) = unique_dirs("bundle_roundtrip_ok");
    let src_file = out_dir.join("bundle_roundtrip_source.nex");
    let bundle_path = out_dir.join("events.nexbundle");

    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run bundle fixture", &run);

    let bundle = run_nex(
        &[
            "bundle",
            out_dir.join("events.bin").to_str().unwrap(),
            "--out",
            bundle_path.to_str().unwrap(),
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex bundle valid fixture", &bundle);

    let replay = run_nex(
        &["replay", "--bundle", bundle_path.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay --bundle valid fixture", &replay);

    let all = all_output(&replay);
    assert!(all.contains("✅ REPLAY OK"), "expected REPLAY OK\n{}", all);
}

#[test]
fn bundle_tamper_fails() {
    let (out_dir, build_dir) = unique_dirs("bundle_tamper_fails");
    let src_file = out_dir.join("bundle_tamper_source.nex");
    let bundle_path = out_dir.join("events.nexbundle");

    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run bundle tamper fixture", &run);

    let bundle = run_nex(
        &[
            "bundle",
            out_dir.join("events.bin").to_str().unwrap(),
            "--out",
            bundle_path.to_str().unwrap(),
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex bundle tamper fixture", &bundle);

    let mut parsed = parse_bundle(&bundle_path);
    assert!(parsed.events_len > 0, "events section must be non-empty");

    let tamper_off = parsed.events_offset;
    parsed.bytes[tamper_off] ^= 0x01;

    let tampered_path = out_dir.join("events.tampered.nexbundle");
    fs::write(&tampered_path, &parsed.bytes).expect("write tampered bundle");

    let replay = run_nex(
        &["replay", "--bundle", tampered_path.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert!(
        !replay.status.success(),
        "tampered bundle replay must fail deterministically"
    );

    let all = all_output(&replay);
    assert!(
        !all.contains("✅ REPLAY OK"),
        "tampered bundle must not report REPLAY OK"
    );
}

#[test]
fn bundle_zero_trust_unknown_fails() {
    let (out_dir, build_dir) = unique_dirs("bundle_zero_trust_unknown_fails");
    let src_file = out_dir.join("bundle_zero_trust_unknown_source.nex");
    let bundle_path = out_dir.join("events.nexbundle");

    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run bundle zero-trust unknown fixture", &run);

    let bundle = run_nex(
        &[
            "bundle",
            out_dir.join("events.bin").to_str().unwrap(),
            "--out",
            bundle_path.to_str().unwrap(),
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex bundle zero-trust unknown fixture", &bundle);

    write_trust_registry(&out_dir.join("nex_home"), &[]);

    let replay = run_nex(
        &[
            "replay",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--zero-trust",
        ],
        &out_dir,
        &build_dir,
    );

    assert!(
        !replay.status.success(),
        "zero-trust unknown key must fail for bundle replay"
    );

    let all = all_output(&replay);
    assert!(
        all.contains("zero-trust replay rejected untrusted public key"),
        "expected zero-trust rejection\n{}",
        all
    );
    assert!(
        !all.contains("✅ REPLAY OK"),
        "zero-trust unknown key must not report REPLAY OK"
    );
}

#[test]
fn bundle_zero_trust_registered_ok() {
    let (out_dir, build_dir) = unique_dirs("bundle_zero_trust_registered_ok");
    let src_file = out_dir.join("bundle_zero_trust_registered_source.nex");
    let bundle_path = out_dir.join("events.nexbundle");

    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run bundle zero-trust registered fixture", &run);

    let bundle = run_nex(
        &[
            "bundle",
            out_dir.join("events.bin").to_str().unwrap(),
            "--out",
            bundle_path.to_str().unwrap(),
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex bundle zero-trust registered fixture", &bundle);

    let parsed = parse_bundle(&bundle_path);
    let public_key_b64 = decode_evidence_public_key_b64(&parsed.evidence_bytes);
    write_trust_registry(&out_dir.join("nex_home"), &[public_key_b64]);

    let replay = run_nex(
        &[
            "replay",
            "--bundle",
            bundle_path.to_str().unwrap(),
            "--zero-trust",
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay bundle zero-trust registered fixture", &replay);

    let all = all_output(&replay);
    assert!(all.contains("✅ REPLAY OK"), "expected REPLAY OK\n{}", all);
}

#[test]
fn bundle_format_canonicality() {
    let (out_dir, build_dir) = unique_dirs("bundle_format_canonicality");
    let src_file = out_dir.join("bundle_canonicality_source.nex");
    let bundle_a = out_dir.join("events_a.nexbundle");
    let bundle_b = out_dir.join("events_b.nexbundle");

    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run bundle canonicality fixture", &run);

    let make_a = run_nex(
        &[
            "bundle",
            out_dir.join("events.bin").to_str().unwrap(),
            "--out",
            bundle_a.to_str().unwrap(),
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex bundle canonicality A", &make_a);

    let make_b = run_nex(
        &[
            "bundle",
            out_dir.join("events.bin").to_str().unwrap(),
            "--out",
            bundle_b.to_str().unwrap(),
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex bundle canonicality B", &make_b);

    let a = fs::read(&bundle_a).expect("read bundle A");
    let b = fs::read(&bundle_b).expect("read bundle B");
    assert_eq!(a, b, "bundle bytes must be exactly canonical");
}

fn parse_bundle(path: &Path) -> BundleSections {
    let bytes = fs::read(path).expect("read bundle bytes");
    let mut offset = 0usize;

    assert!(bytes.len() >= 4 + 2 + 1 + 1 + 1 + 4, "bundle too short");

    let magic = &bytes[offset..offset + 4];
    assert_eq!(magic, BUNDLE_MAGIC, "invalid bundle magic");
    offset += 4;

    let _format_version = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;

    let _hash_alg = bytes[offset];
    offset += 1;

    let _sig_alg = bytes[offset];
    offset += 1;

    let _flags = bytes[offset];
    offset += 1;

    let header_len = u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]) as usize;
    offset += 4;

    assert!(offset + header_len <= bytes.len(), "header out of bounds");
    offset += header_len;

    let events_len = read_u64_at(&bytes, &mut offset, "events_len") as usize;
    let events_offset = offset;
    assert!(
        events_offset + events_len <= bytes.len(),
        "events section out of bounds"
    );
    offset += events_len;

    let evidence_len = read_u64_at(&bytes, &mut offset, "evidence_len") as usize;
    let evidence_offset = offset;
    assert!(
        evidence_offset + evidence_len <= bytes.len(),
        "evidence section out of bounds"
    );
    let evidence_bytes = bytes[evidence_offset..evidence_offset + evidence_len].to_vec();
    offset += evidence_len;

    let policy_len = read_u64_at(&bytes, &mut offset, "policy_len") as usize;
    assert!(
        offset + policy_len <= bytes.len(),
        "policy section out of bounds"
    );
    offset += policy_len;

    let source_len = read_u64_at(&bytes, &mut offset, "source_len") as usize;
    assert!(
        offset + source_len <= bytes.len(),
        "source section out of bounds"
    );
    offset += source_len;

    let codegen_len = read_u64_at(&bytes, &mut offset, "codegen_len") as usize;
    assert!(
        offset + codegen_len <= bytes.len(),
        "codegen section out of bounds"
    );
    offset += codegen_len;

    assert_eq!(offset, bytes.len(), "bundle trailing bytes");

    BundleSections {
        bytes,
        events_offset,
        events_len,
        evidence_bytes,
    }
}

fn decode_evidence_public_key_b64(payload: &[u8]) -> String {
    const LEGACY_FIXED: usize = 4 + 32 * 4;
    const V081_FIXED: usize = 4 + 4 + 4 + 4 + 32 * 4;

    fn parse_tail(payload: &[u8], prefix_len: usize) -> Option<(String, String, String)> {
        let pk_len_end = prefix_len.checked_add(2)?;
        let pk_len_bytes = payload.get(prefix_len..pk_len_end)?;
        let pk_len = u16::from_le_bytes([pk_len_bytes[0], pk_len_bytes[1]]) as usize;

        let pk_start = pk_len_end;
        let pk_end = pk_start.checked_add(pk_len)?;
        if pk_end + 2 > payload.len() {
            return None;
        }

        let sig_len_bytes = &payload[pk_end..pk_end + 2];
        let sig_len = u16::from_le_bytes([sig_len_bytes[0], sig_len_bytes[1]]) as usize;
        let sig_start = pk_end + 2;
        let sig_end = sig_start.checked_add(sig_len)?;
        if sig_end > payload.len() {
            return None;
        }

        let public_key_b64 = std::str::from_utf8(&payload[pk_start..pk_end])
            .ok()?
            .to_string();
        let signature_b64 = std::str::from_utf8(&payload[sig_start..sig_end])
            .ok()?
            .to_string();

        let provider_id = if sig_end == payload.len() {
            "file-v1".to_string()
        } else {
            if sig_end + 2 > payload.len() {
                return None;
            }
            let provider_len =
                u16::from_le_bytes([payload[sig_end], payload[sig_end + 1]]) as usize;
            let provider_start = sig_end + 2;
            let provider_end = provider_start.checked_add(provider_len)?;
            if provider_end != payload.len() {
                return None;
            }
            std::str::from_utf8(&payload[provider_start..provider_end])
                .ok()?
                .to_string()
        };

        Some((public_key_b64, signature_b64, provider_id))
    }

    if payload.len() >= V081_FIXED + 2 + 2 {
        let format = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if format == 1 {
            if let Some((public_key_b64, _, _)) = parse_tail(payload, V081_FIXED) {
                let decoded = STANDARD
                    .decode(public_key_b64.as_bytes())
                    .expect("decode v0.8.1 public_key_b64");
                assert_eq!(decoded.len(), 32, "public key length mismatch");
                return public_key_b64;
            }
        }
    }

    let (public_key_b64, _, _) =
        parse_tail(payload, LEGACY_FIXED).expect("decode legacy EvidenceFinal payload tail");
    let decoded = STANDARD
        .decode(public_key_b64.as_bytes())
        .expect("decode legacy public_key_b64");
    assert_eq!(decoded.len(), 32, "public key length mismatch");
    public_key_b64
}

fn read_u64_at(bytes: &[u8], offset: &mut usize, field: &str) -> u64 {
    assert!(
        *offset + 8 <= bytes.len(),
        "{} out of bounds at offset {}",
        field,
        offset
    );
    let v = u64::from_le_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
        bytes[*offset + 4],
        bytes[*offset + 5],
        bytes[*offset + 6],
        bytes[*offset + 7],
    ]);
    *offset += 8;
    v
}

fn run_nex(args: &[&str], out_dir: &Path, build_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nex"))
        .args(args)
        .env("NEX_OUT_DIR", out_dir)
        .env("NEX_BUILD_DIR", build_dir)
        .env("NEX_HOME", out_dir.join("nex_home"))
        .env("NEX_AGENT_ID", "0")
        .output()
        .expect("failed to execute nex binary")
}

fn write_trust_registry(home: &Path, trusted_public_keys: &[String]) {
    let trust_dir = home.join("trust");
    fs::create_dir_all(&trust_dir).expect("create trust dir");

    let mut keys = trusted_public_keys.to_vec();
    keys.sort();
    keys.dedup();

    let mut json = String::from("{\"format_version\":1,\"trusted_public_keys\":[");
    for (idx, key) in keys.iter().enumerate() {
        if idx > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(&escape_json(key));
        json.push('"');
    }
    json.push_str("]}\n");

    fs::write(trust_dir.join("registry.json"), json).expect("write trust registry");
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

fn all_output(out: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_status_ok(label: &str, out: &std::process::Output) {
    assert!(
        out.status.success(),
        "{} failed\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn unique_dirs(label: &str) -> (PathBuf, PathBuf) {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base =
        std::env::temp_dir().join(format!("nex_test_{}_{}_{}", label, std::process::id(), id));
    let out_dir = base.join("out");
    let build_dir = base.join("build");

    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&out_dir).expect("create out dir");
    fs::create_dir_all(&build_dir).expect("create build dir");

    (out_dir, build_dir)
}
