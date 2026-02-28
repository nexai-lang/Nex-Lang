#![cfg(not(feature = "coop_scheduler"))]

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LOG_HEADER_LEN: usize = 76;
const RECORD_HEADER_LEN: usize = 22;
const KIND_TASK_FINISHED_U16: u16 = 7;
const KIND_EVIDENCE_FINAL_U16: u16 = 34;
const KIND_RUN_FINISHED_U16: u16 = 0xFFFF;

const EVIDENCE_DOMAIN_LEGACY: &[u8] = b"NEX-EVIDENCE-V1";

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct RecordRef {
    kind: u16,
    record_offset: usize,
    record_len: usize,
    payload_offset: usize,
    payload_len: usize,
}

#[derive(Debug, Clone)]
struct LogRecord {
    seq: u64,
    task_id: u64,
    kind: u16,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceMode {
    LegacyV080,
    V081,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceVersion {
    format: u32,
    hash_alg: u32,
    sig_alg: u32,
}

#[derive(Debug, Clone)]
struct EvidencePayload {
    mode: EvidenceMode,
    version: EvidenceVersion,
    agent_id: u32,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
    public_key_b64: String,
    signature_b64: String,
    provider_id: String,
    signature_range: (usize, usize),
    version_range: Option<(usize, usize)>,
}

#[test]
fn streaming_run_hash_matches_replay() {
    let (out_dir, build_dir) = unique_dirs("streaming_run_hash_matches_replay");
    let src_file = out_dir.join("streaming_hash_source.nex");
    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run streaming hash fixture", &run);

    let bytes = fs::read(out_dir.join("events.bin")).expect("read events.bin");
    let records = parse_records(&bytes);

    let evidence_idx = records
        .iter()
        .position(|r| r.kind == KIND_EVIDENCE_FINAL_U16)
        .expect("missing EvidenceFinal");
    let run_finished_idx = records
        .iter()
        .position(|r| r.kind == KIND_RUN_FINISHED_U16)
        .expect("missing RunFinished");
    assert_eq!(
        evidence_idx + 1,
        run_finished_idx,
        "EvidenceFinal must precede RunFinished"
    );

    let evidence_ref = &records[evidence_idx];
    let evidence = decode_evidence_payload(
        &bytes[evidence_ref.payload_offset..evidence_ref.payload_offset + evidence_ref.payload_len],
    );
    assert_eq!(
        evidence.mode,
        EvidenceMode::V081,
        "expected v0.8.1 evidence"
    );

    let computed = compute_pre_evidence_hash(&bytes, &records, evidence_idx);
    assert_eq!(
        evidence.run_hash, computed,
        "EvidenceFinal run_hash must equal streaming pre-evidence digest"
    );

    let replay = run_nex(
        &["replay", out_dir.join("events.bin").to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay streaming hash fixture", &replay);
    let all = all_output(&replay);
    assert!(all.contains("✅ REPLAY OK"), "expected REPLAY OK\n{}", all);
}

#[test]
fn evidence_version_in_signature() {
    let (out_dir, build_dir) = unique_dirs("evidence_version_in_signature");
    let src_file = out_dir.join("version_signature_source.nex");
    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run version tamper fixture", &run);

    let base = out_dir.join("events.bin");
    let mut bytes = fs::read(&base).expect("read base log");
    let records = parse_records(&bytes);

    let evidence_ref = records
        .iter()
        .find(|r| r.kind == KIND_EVIDENCE_FINAL_U16)
        .expect("missing EvidenceFinal");
    let evidence = decode_evidence_payload(
        &bytes[evidence_ref.payload_offset..evidence_ref.payload_offset + evidence_ref.payload_len],
    );
    let (version_start, _) = evidence
        .version_range
        .expect("expected v0.8.1 version fields");

    let abs = evidence_ref.payload_offset + version_start;
    bytes[abs] ^= 0x01;

    let tampered = out_dir.join("events.version_tampered.bin");
    fs::write(&tampered, &bytes).expect("write version-tampered log");

    let replay = run_nex(
        &["replay", tampered.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert!(!replay.status.success(), "version tamper must fail replay");

    let all = all_output(&replay);
    assert!(
        all.contains("EvidenceFinal signature verification failed")
            || all.contains("unsupported evidence format")
            || all.contains("unsupported evidence"),
        "expected deterministic version/signature failure, got:\n{}",
        all
    );
    assert!(
        !all.contains("✅ REPLAY OK"),
        "version tamper must not report REPLAY OK"
    );
}

#[test]
fn legacy_log_still_verifies() {
    let (out_dir, build_dir) = unique_dirs("legacy_log_still_verifies");
    let src_file = out_dir.join("legacy_compat_source.nex");
    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run legacy fixture", &run);

    let base = fs::read(out_dir.join("events.bin")).expect("read base log");
    let mut records = parse_log_records(&base);

    let evidence_idx = records
        .iter()
        .position(|r| r.kind == KIND_EVIDENCE_FINAL_U16)
        .expect("missing EvidenceFinal");
    let run_finished_idx = records
        .iter()
        .position(|r| r.kind == KIND_RUN_FINISHED_U16)
        .expect("missing RunFinished");
    assert_eq!(
        evidence_idx + 1,
        run_finished_idx,
        "EvidenceFinal must precede RunFinished"
    );

    let evidence = decode_evidence_payload(&records[evidence_idx].payload);
    assert_eq!(
        evidence.mode,
        EvidenceMode::V081,
        "expected v0.8.1 source log"
    );

    let secret_key = load_secret_key(&out_dir.join("nex_home"), evidence.agent_id);
    let signing_key = SigningKey::from_bytes(&secret_key);
    let legacy_sig = signing_key
        .sign(&legacy_evidence_message(
            evidence.agent_id,
            evidence.source_hash,
            evidence.codegen_hash,
            evidence.policy_hash,
            evidence.run_hash,
        ))
        .to_bytes();

    let legacy_payload = build_legacy_evidence_payload(&evidence, &legacy_sig);
    records[evidence_idx].payload = legacy_payload;

    refresh_run_finished_hash(&mut records, &base[..LOG_HEADER_LEN]);

    let legacy_bytes = serialize_log_records(&base[..LOG_HEADER_LEN], &records);
    let legacy_path = out_dir.join("events.legacy_v080.bin");
    fs::write(&legacy_path, &legacy_bytes).expect("write legacy log");

    let replay = run_nex(
        &["replay", legacy_path.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay legacy_v080 log", &replay);

    let all = all_output(&replay);
    assert!(all.contains("✅ REPLAY OK"), "expected REPLAY OK\n{}", all);
}

#[test]
fn event_byte_tamper_changes_run_hash() {
    let (out_dir, build_dir) = unique_dirs("event_byte_tamper_changes_run_hash");
    let src_file = out_dir.join("event_tamper_source.nex");
    fs::write(&src_file, "fn main() { 1 + 2; }\n").expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run event tamper fixture", &run);

    let base = out_dir.join("events.bin");
    let mut bytes = fs::read(&base).expect("read base log");
    let records = parse_records(&bytes);

    let task_finished = records
        .iter()
        .find(|r| r.kind == KIND_TASK_FINISHED_U16)
        .expect("missing TaskFinished event");
    assert!(
        task_finished.payload_len >= 4,
        "TaskFinished payload too short"
    );

    bytes[task_finished.payload_offset] ^= 0x01;

    let tampered = out_dir.join("events.event_byte_tampered.bin");
    fs::write(&tampered, &bytes).expect("write event-tampered log");

    let replay = run_nex(
        &["replay", tampered.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert!(!replay.status.success(), "event tamper must fail replay");

    let all = all_output(&replay);
    assert!(
        all.contains("evidence run hash mismatch") || all.contains("run hash mismatch"),
        "expected run hash mismatch failure, got:\n{}",
        all
    );
    assert!(
        !all.contains("✅ REPLAY OK"),
        "event tamper must not report REPLAY OK"
    );
}

#[test]
fn replay_permissive_ok() {
    let (out_dir, build_dir) = unique_dirs("replay_permissive_ok");
    let src_file = out_dir.join("permissive_ok_source.nex");
    fs::write(
        &src_file,
        "fn main() { 1 + 2; }
",
    )
    .expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run permissive fixture", &run);

    let replay = run_nex(
        &["replay", out_dir.join("events.bin").to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay permissive fixture", &replay);
    assert!(all_output(&replay).contains("✅ REPLAY OK"));
}

#[test]
fn replay_zero_trust_unknown_key_fails() {
    let (out_dir, build_dir) = unique_dirs("replay_zero_trust_unknown_key_fails");
    let src_file = out_dir.join("zero_trust_unknown_source.nex");
    fs::write(
        &src_file,
        "fn main() { 1 + 2; }
",
    )
    .expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run zero-trust unknown fixture", &run);

    write_trust_registry(&out_dir.join("nex_home"), &[]);

    let replay = run_nex(
        &[
            "replay",
            out_dir.join("events.bin").to_str().unwrap(),
            "--zero-trust",
        ],
        &out_dir,
        &build_dir,
    );
    assert!(
        !replay.status.success(),
        "zero-trust unknown key must fail replay"
    );

    let all = all_output(&replay);
    assert!(
        all.contains("zero-trust replay rejected untrusted public key"),
        "expected zero-trust unknown key failure, got:
{}",
        all
    );
    assert!(
        !all.contains("✅ REPLAY OK"),
        "zero-trust unknown key must not report REPLAY OK"
    );
}

#[test]
fn replay_zero_trust_registered_key_ok() {
    let (out_dir, build_dir) = unique_dirs("replay_zero_trust_registered_key_ok");
    let src_file = out_dir.join("zero_trust_registered_source.nex");
    fs::write(
        &src_file,
        "fn main() { 1 + 2; }
",
    )
    .expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run zero-trust registered fixture", &run);

    let bytes = fs::read(out_dir.join("events.bin")).expect("read events.bin");
    let records = parse_records(&bytes);
    let evidence_ref = records
        .iter()
        .find(|r| r.kind == KIND_EVIDENCE_FINAL_U16)
        .expect("missing EvidenceFinal");
    let evidence = decode_evidence_payload(
        &bytes[evidence_ref.payload_offset..evidence_ref.payload_offset + evidence_ref.payload_len],
    );

    write_trust_registry(
        &out_dir.join("nex_home"),
        &[evidence.public_key_b64.clone()],
    );

    let replay = run_nex(
        &[
            "replay",
            out_dir.join("events.bin").to_str().unwrap(),
            "--zero-trust",
        ],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay zero-trust registered fixture", &replay);
    assert!(all_output(&replay).contains("✅ REPLAY OK"));
}

#[test]
fn replay_zero_trust_tamper_fails() {
    let (out_dir, build_dir) = unique_dirs("replay_zero_trust_tamper_fails");
    let src_file = out_dir.join("zero_trust_tamper_source.nex");
    fs::write(
        &src_file,
        "fn main() { 1 + 2; }
",
    )
    .expect("write source");

    let run = run_nex(&["run", src_file.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run zero-trust tamper fixture", &run);

    let base = out_dir.join("events.bin");
    let mut bytes = fs::read(&base).expect("read base log");
    let records = parse_records(&bytes);
    let evidence_ref = records
        .iter()
        .find(|r| r.kind == KIND_EVIDENCE_FINAL_U16)
        .expect("missing EvidenceFinal");
    let evidence = decode_evidence_payload(
        &bytes[evidence_ref.payload_offset..evidence_ref.payload_offset + evidence_ref.payload_len],
    );

    write_trust_registry(
        &out_dir.join("nex_home"),
        &[evidence.public_key_b64.clone()],
    );

    let sig_abs_start = evidence_ref.payload_offset + evidence.signature_range.0;
    let sig_abs_end = evidence_ref.payload_offset + evidence.signature_range.1;
    assert!(sig_abs_end > sig_abs_start, "empty signature range");
    bytes[sig_abs_start] = if bytes[sig_abs_start] == b'A' {
        b'B'
    } else {
        b'A'
    };

    let tampered = out_dir.join("events.zero_trust_signature_tampered.bin");
    fs::write(&tampered, &bytes).expect("write tampered log");

    let replay = run_nex(
        &["replay", tampered.to_str().unwrap(), "--zero-trust"],
        &out_dir,
        &build_dir,
    );
    assert!(
        !replay.status.success(),
        "zero-trust tampered log must fail replay"
    );

    let all = all_output(&replay);
    assert!(
        all.contains("EvidenceFinal signature verification failed")
            || all.contains("evidence run hash mismatch")
            || all.contains("run hash mismatch"),
        "expected deterministic corruption failure, got:
{}",
        all
    );
    assert!(
        !all.contains("✅ REPLAY OK"),
        "zero-trust tampered replay must not report REPLAY OK"
    );
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

fn assert_status_ok(label: &str, out: &std::process::Output) {
    assert!(
        out.status.success(),
        "{} failed\nstdout:\n{}\nstderr:\n{}",
        label,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn all_output(out: &std::process::Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn unique_dirs(label: &str) -> (PathBuf, PathBuf) {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base =
        std::env::temp_dir().join(format!("nex_test_{}_{}_{}", label, std::process::id(), id));
    let out_dir = base.join("out");
    let build_dir = base.join("build");

    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&out_dir).unwrap();
    fs::create_dir_all(&build_dir).unwrap();

    (out_dir, build_dir)
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
        json.push_str(key);
        json.push('"');
    }
    json.push_str("]}\n");

    fs::write(trust_dir.join("registry.json"), json).expect("write trust registry");
}

fn parse_records(bytes: &[u8]) -> Vec<RecordRef> {
    assert!(bytes.len() >= LOG_HEADER_LEN, "log too short for header");

    let mut pos = LOG_HEADER_LEN;
    let mut out = Vec::new();

    while pos < bytes.len() {
        assert!(
            pos + RECORD_HEADER_LEN <= bytes.len(),
            "truncated record header at offset {}",
            pos
        );

        let kind = read_u16_le(bytes, pos + 16);
        let payload_len = read_u32_le(bytes, pos + 18) as usize;
        let payload_offset = pos + RECORD_HEADER_LEN;
        let record_len = RECORD_HEADER_LEN + payload_len;

        assert!(
            payload_offset + payload_len <= bytes.len(),
            "truncated payload at offset {}",
            payload_offset
        );

        out.push(RecordRef {
            kind,
            record_offset: pos,
            record_len,
            payload_offset,
            payload_len,
        });

        pos += record_len;
    }

    out
}

fn parse_log_records(bytes: &[u8]) -> Vec<LogRecord> {
    parse_records(bytes)
        .into_iter()
        .map(|r| LogRecord {
            seq: read_u64_le(bytes, r.record_offset),
            task_id: read_u64_le(bytes, r.record_offset + 8),
            kind: r.kind,
            payload: bytes[r.payload_offset..r.payload_offset + r.payload_len].to_vec(),
        })
        .collect()
}

fn serialize_log_records(header: &[u8], records: &[LogRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + records.iter().map(record_len).sum::<usize>());
    out.extend_from_slice(header);
    for r in records {
        out.extend_from_slice(&encode_record(r));
    }
    out
}

fn record_len(rec: &LogRecord) -> usize {
    RECORD_HEADER_LEN + rec.payload.len()
}

fn encode_record(rec: &LogRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(record_len(rec));
    out.extend_from_slice(&rec.seq.to_le_bytes());
    out.extend_from_slice(&rec.task_id.to_le_bytes());
    out.extend_from_slice(&rec.kind.to_le_bytes());
    out.extend_from_slice(&(rec.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&rec.payload);
    out
}

fn refresh_run_finished_hash(records: &mut [LogRecord], header: &[u8]) {
    let run_idx = records
        .iter()
        .position(|r| r.kind == KIND_RUN_FINISHED_U16)
        .expect("missing RunFinished");

    let mut hasher = Sha256::new();
    hasher.update(header);
    for rec in &records[..run_idx] {
        hasher.update(encode_record(rec));
    }
    let digest = hasher.finalize();

    assert!(
        records[run_idx].payload.len() >= 36,
        "RunFinished payload too short"
    );
    records[run_idx].payload[4..36].copy_from_slice(&digest[..]);
}

fn compute_pre_evidence_hash(bytes: &[u8], records: &[RecordRef], evidence_idx: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&bytes[..LOG_HEADER_LEN]);
    for rec in &records[..evidence_idx] {
        hasher.update(&bytes[rec.record_offset..rec.record_offset + rec.record_len]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

fn decode_evidence_payload(payload: &[u8]) -> EvidencePayload {
    const LEGACY_FIXED: usize = 4 + 32 * 4;
    const V081_FIXED: usize = 4 + 4 + 4 + 4 + 32 * 4;

    assert!(
        payload.len() >= LEGACY_FIXED + 2 + 2,
        "EvidenceFinal payload too short: {}",
        payload.len()
    );

    let read_u32 = |off: usize, field: &str| -> u32 {
        let bytes = payload
            .get(off..off + 4)
            .unwrap_or_else(|| panic!("EvidenceFinal {} out of bounds", field));
        u32::from_le_bytes(bytes.try_into().unwrap())
    };

    let read_hash = |off: usize, field: &str| -> [u8; 32] {
        payload
            .get(off..off + 32)
            .unwrap_or_else(|| panic!("EvidenceFinal {} out of bounds", field))
            .try_into()
            .unwrap()
    };

    let parse_tail = |prefix_len: usize| -> Option<(String, String, String, (usize, usize))> {
        let pk_len_bytes = payload.get(prefix_len..prefix_len + 2)?;
        let pk_len = u16::from_le_bytes([pk_len_bytes[0], pk_len_bytes[1]]) as usize;
        let pk_start = prefix_len + 2;
        let pk_end = pk_start.checked_add(pk_len)?;
        if pk_end + 2 > payload.len() {
            return None;
        }

        let sig_len_bytes = payload.get(pk_end..pk_end + 2)?;
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

        Some((
            public_key_b64,
            signature_b64,
            provider_id,
            (sig_start, sig_end),
        ))
    };

    if payload.len() >= V081_FIXED + 2 + 2 {
        let format = read_u32(0, "format");
        let hash_alg = read_u32(4, "hash_alg");
        let sig_alg = read_u32(8, "sig_alg");
        if format == 1 && hash_alg == 1 && sig_alg == 1 {
            if let Some((public_key_b64, signature_b64, provider_id, signature_range)) =
                parse_tail(V081_FIXED)
            {
                return EvidencePayload {
                    mode: EvidenceMode::V081,
                    version: EvidenceVersion {
                        format,
                        hash_alg,
                        sig_alg,
                    },
                    agent_id: read_u32(12, "agent_id"),
                    source_hash: read_hash(16, "source_hash"),
                    codegen_hash: read_hash(48, "codegen_hash"),
                    policy_hash: read_hash(80, "policy_hash"),
                    run_hash: read_hash(112, "run_hash"),
                    public_key_b64,
                    signature_b64,
                    provider_id,
                    signature_range,
                    version_range: Some((0, 12)),
                };
            }
        }
    }

    let (public_key_b64, signature_b64, provider_id, signature_range) =
        parse_tail(LEGACY_FIXED).expect("EvidenceFinal legacy bounds mismatch");
    EvidencePayload {
        mode: EvidenceMode::LegacyV080,
        version: EvidenceVersion {
            format: 0,
            hash_alg: 1,
            sig_alg: 1,
        },
        agent_id: read_u32(0, "agent_id"),
        source_hash: read_hash(4, "source_hash"),
        codegen_hash: read_hash(36, "codegen_hash"),
        policy_hash: read_hash(68, "policy_hash"),
        run_hash: read_hash(100, "run_hash"),
        public_key_b64,
        signature_b64,
        provider_id,
        signature_range,
        version_range: None,
    }
}

fn parse_json_string_field(doc: &str, key: &str) -> String {
    let needle = format!("\"{}\":\"", key);
    let start = doc.find(&needle).expect("field key") + needle.len();
    let tail = &doc[start..];
    let end = tail.find('"').expect("field end");
    tail[..end].to_string()
}

fn load_secret_key(home: &Path, agent_id: u32) -> [u8; 32] {
    let key_path = home.join("keys").join(format!("agent_{}.json", agent_id));
    let doc = fs::read_to_string(&key_path).expect("read key file");
    let secret_key_b64 = parse_json_string_field(&doc, "secret_key_b64");
    let raw = STANDARD
        .decode(secret_key_b64)
        .expect("decode secret key b64");
    assert_eq!(raw.len(), 32, "secret key length mismatch");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn legacy_evidence_message(
    agent_id: u32,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(EVIDENCE_DOMAIN_LEGACY.len() + 4 + 32 * 4);
    msg.extend_from_slice(EVIDENCE_DOMAIN_LEGACY);
    msg.extend_from_slice(&agent_id.to_le_bytes());
    msg.extend_from_slice(&source_hash);
    msg.extend_from_slice(&codegen_hash);
    msg.extend_from_slice(&policy_hash);
    msg.extend_from_slice(&run_hash);
    msg
}

fn build_legacy_evidence_payload(evidence: &EvidencePayload, signature: &[u8; 64]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&evidence.agent_id.to_le_bytes());
    payload.extend_from_slice(&evidence.source_hash);
    payload.extend_from_slice(&evidence.codegen_hash);
    payload.extend_from_slice(&evidence.policy_hash);
    payload.extend_from_slice(&evidence.run_hash);

    let pk = evidence.public_key_b64.as_bytes();
    let sig_b64 = STANDARD.encode(signature);
    let sig = sig_b64.as_bytes();

    payload.extend_from_slice(&(pk.len() as u16).to_le_bytes());
    payload.extend_from_slice(pk);
    payload.extend_from_slice(&(sig.len() as u16).to_le_bytes());
    payload.extend_from_slice(sig);
    payload
}

fn read_u64_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap())
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}
