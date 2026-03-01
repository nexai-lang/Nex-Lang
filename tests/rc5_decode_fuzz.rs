use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const BUNDLE_MAGIC: [u8; 4] = *b"NEXB";
const BUNDLE_FORMAT_VERSION: u16 = 1;
const BUNDLE_HASH_ALG_SHA256: u8 = 1;
const BUNDLE_SIG_ALG_ED25519: u8 = 1;
const BUNDLE_FLAG_NONE: u8 = 0;

const LOG_MAGIC: [u8; 4] = *b"NEXL";
const LOG_VERSION: u16 = 1;
const LOG_HEADER_LEN: usize = 76;

const KIND_TASK_STARTED: u16 = 6;
const KIND_EVIDENCE_FINAL: u16 = 34;
const KIND_RUN_FINISHED: u16 = 0xFFFF;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn hir_decoder_hostile_inputs_no_panic() {
    let base = unique_dir("hir_decoder_fuzz");
    let mut seed = 0xA1B2_C3D4_E5F6_0001u64;

    for i in 0..24usize {
        let mut bytes = hostile_bytes(&mut seed, (i * 31) % 511);
        if i % 2 == 0 {
            // Force HIR decoder path by setting HIR magic + version prefix.
            let mut prefixed = b"NEXHIR\0\0".to_vec();
            prefixed.extend_from_slice(&1u32.to_le_bytes());
            prefixed.extend_from_slice(&bytes);
            bytes = prefixed;
        }

        let in_path = base.join(format!("hir_case_{i}.bin"));
        let out_path = base.join(format!("hir_case_{i}.out"));
        fs::write(&in_path, &bytes).expect("write hir fuzz case");

        let output = run_nex(
            &[
                "ir-upgrade",
                in_path.to_str().expect("hir input utf8"),
                "--out",
                out_path.to_str().expect("hir output utf8"),
                "--kind",
                "hir",
            ],
            &[],
        );

        assert_no_panic(&format!("hir case {i}"), &output);
    }
}

#[test]
fn mir_decoder_hostile_inputs_no_panic() {
    let base = unique_dir("mir_decoder_fuzz");
    let mut seed = 0x1122_3344_5566_7788u64;

    for i in 0..24usize {
        let mut bytes = hostile_bytes(&mut seed, (i * 29) % 509);
        if i % 2 == 0 {
            // Force MIR decoder path by setting MIR magic + version prefix.
            let mut prefixed = b"NEXM".to_vec();
            prefixed.extend_from_slice(&1u16.to_le_bytes());
            prefixed.extend_from_slice(&bytes);
            bytes = prefixed;
        }

        let in_path = base.join(format!("mir_case_{i}.bin"));
        let out_path = base.join(format!("mir_case_{i}.out"));
        fs::write(&in_path, &bytes).expect("write mir fuzz case");

        let output = run_nex(
            &[
                "ir-upgrade",
                in_path.to_str().expect("mir input utf8"),
                "--out",
                out_path.to_str().expect("mir output utf8"),
                "--kind",
                "mir",
            ],
            &[],
        );

        assert_no_panic(&format!("mir case {i}"), &output);
    }
}

#[test]
fn log_decoder_truncation_dup_reorder_and_no_panic() {
    let base = unique_dir("log_decoder_hardening");

    // Truncation: header + partial record header.
    let mut truncated = build_log_header([0u8; 32], [0u8; 32], 0).to_vec();
    truncated.extend_from_slice(&[1, 2, 3, 4, 5]);
    let truncated_path = base.join("truncated.events.bin");
    fs::write(&truncated_path, &truncated).expect("write truncated log");
    let truncated_out = run_nex(&["replay", path_arg(&truncated_path)], &[]);
    assert_no_panic("truncated log", &truncated_out);
    assert!(
        !truncated_out.status.success(),
        "truncated log must fail closed"
    );

    // Reordering: non-monotonic seq.
    let reordered_path = base.join("reordered.events.bin");
    let reordered = build_log(
        [0u8; 32],
        [0u8; 32],
        0,
        &[
            (2, 0, KIND_TASK_STARTED, vec![]),
            (1, 0, KIND_TASK_STARTED, vec![]),
            (3, 0, KIND_RUN_FINISHED, 0i32.to_le_bytes().to_vec()),
        ],
    );
    fs::write(&reordered_path, reordered).expect("write reordered log");
    let reordered_out = run_nex(&["replay", path_arg(&reordered_path)], &[]);
    assert_no_panic("reordered log", &reordered_out);
    assert!(
        !reordered_out.status.success(),
        "reordered log must fail closed"
    );

    // Duplication: duplicate sequence number.
    let dup_seq_path = base.join("dup_seq.events.bin");
    let dup_seq = build_log(
        [0u8; 32],
        [0u8; 32],
        0,
        &[
            (1, 0, KIND_TASK_STARTED, vec![]),
            (1, 0, KIND_TASK_STARTED, vec![]),
            (2, 0, KIND_RUN_FINISHED, 0i32.to_le_bytes().to_vec()),
        ],
    );
    fs::write(&dup_seq_path, dup_seq).expect("write duplicate-seq log");
    let dup_seq_out = run_nex(&["replay", path_arg(&dup_seq_path)], &[]);
    assert_no_panic("duplicate seq log", &dup_seq_out);
    assert!(
        !dup_seq_out.status.success(),
        "duplicate sequence numbers must fail closed"
    );

    // Oversize section: declared event payload length beyond cap.
    let oversize_path = base.join("oversize.events.bin");
    let mut oversize = build_log_header([0u8; 32], [0u8; 32], 0).to_vec();
    oversize.extend_from_slice(&0u64.to_le_bytes()); // seq
    oversize.extend_from_slice(&0u64.to_le_bytes()); // task_id
    oversize.extend_from_slice(&KIND_TASK_STARTED.to_le_bytes()); // kind
    oversize.extend_from_slice(&((16 * 1024 * 1024 + 1) as u32).to_le_bytes()); // payload len
    fs::write(&oversize_path, oversize).expect("write oversize log");
    let oversize_out = run_nex(&["replay", path_arg(&oversize_path)], &[]);
    assert_no_panic("oversize payload log", &oversize_out);
    assert!(
        !oversize_out.status.success(),
        "oversize payload_len must fail closed"
    );

    // Property-style hostile corpus.
    let mut seed = 0xFACE_FEED_0BAD_C0DEu64;
    for i in 0..20usize {
        let path = base.join(format!("hostile_log_{i}.bin"));
        fs::write(&path, hostile_bytes(&mut seed, (i * 37) % 701)).expect("write hostile log");
        let out = run_nex(&["replay", path_arg(&path)], &[]);
        assert_no_panic(&format!("hostile log {i}"), &out);
    }
}

#[test]
fn evidence_and_bundle_decoder_hostile_inputs_no_panic_and_caps() {
    let base = unique_dir("bundle_decoder_hardening");

    // Truncation: malformed bundle body.
    let trunc_bundle = base.join("truncated.bundle");
    fs::write(&trunc_bundle, b"NEXB\x01").expect("write truncated bundle");
    let trunc_out = run_nex(&["replay", "--bundle", path_arg(&trunc_bundle)], &[]);
    assert_no_panic("truncated bundle", &trunc_out);
    assert!(
        !trunc_out.status.success(),
        "truncated bundle must fail closed"
    );

    // Oversize section cap enforcement via env.
    let cap_bundle = base.join("cap.bundle");
    let cap_evidence = vec![1, 2, 3];
    let cap_events = build_log(
        [0u8; 32],
        [0u8; 32],
        0,
        &[
            (0, 0, KIND_EVIDENCE_FINAL, cap_evidence.clone()),
            (1, 0, KIND_RUN_FINISHED, 0i32.to_le_bytes().to_vec()),
        ],
    );
    fs::write(
        &cap_bundle,
        build_bundle_bytes(&cap_events, &cap_evidence, "x".repeat(96)),
    )
    .expect("write cap bundle");

    let cap_out = run_nex(
        &["replay", "--bundle", path_arg(&cap_bundle)],
        &[("NEX_BUNDLE_MAX_HEADER_BYTES", "8")],
    );
    assert_no_panic("bundle cap", &cap_out);
    assert!(
        !cap_out.status.success(),
        "oversize bundle header must fail closed"
    );

    // Duplication: duplicate EvidenceFinal in events stream inside bundle.
    let dup_bundle = base.join("duplicate_evidence.bundle");
    let dup_evidence = vec![9, 9, 9, 9, 9];
    let dup_events = build_log(
        [0u8; 32],
        [0u8; 32],
        0,
        &[
            (0, 0, KIND_EVIDENCE_FINAL, dup_evidence.clone()),
            (1, 0, KIND_EVIDENCE_FINAL, dup_evidence.clone()),
        ],
    );
    fs::write(
        &dup_bundle,
        build_bundle_bytes(&dup_events, &dup_evidence, "dup-evidence".to_string()),
    )
    .expect("write duplicate-evidence bundle");

    let dup_out = run_nex(&["replay", "--bundle", path_arg(&dup_bundle)], &[]);
    assert_no_panic("duplicate evidence bundle", &dup_out);
    assert!(
        !dup_out.status.success(),
        "duplicate EvidenceFinal must fail closed"
    );

    // Property-style hostile evidence payload corpus in syntactically valid bundle container.
    let mut seed = 0x1234_5678_9ABC_DEF0u64;
    for i in 0..20usize {
        let evidence = hostile_bytes(&mut seed, (i * 41) % 389);
        let events = build_log(
            [0u8; 32],
            [0u8; 32],
            0,
            &[(0, 0, KIND_EVIDENCE_FINAL, evidence.clone())],
        );

        let bundle_path = base.join(format!("hostile_bundle_{i}.nexbundle"));
        let bytes = build_bundle_bytes(&events, &evidence, format!("hostile-{i}"));
        fs::write(&bundle_path, bytes).expect("write hostile bundle");

        let out = run_nex(&["replay", "--bundle", path_arg(&bundle_path)], &[]);
        assert_no_panic(&format!("hostile bundle {i}"), &out);
    }
}

#[test]
fn decode_paths_deny_unwrap_expect() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let targets = [
        root.join("src/hir/codec.rs"),
        root.join("src/mir/codec.rs"),
        root.join("src/runtime/event_reader.rs"),
        root.join("src/replay.rs"),
        root.join("src/bundle.rs"),
    ];

    for path in &targets {
        assert_decode_module_no_unwrap_expect(path);
    }
}

fn assert_decode_module_no_unwrap_expect(path: &Path) {
    let text = fs::read_to_string(path).expect("read decode module");
    let mut in_target_fn = false;
    let mut active_fn = String::new();
    let mut brace_depth: isize = 0;

    for line in text.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with("#[cfg(test)]") {
            break;
        }

        if !in_target_fn {
            if let Some(name) = fn_name_from_line(trimmed) {
                if should_gate_fn(path, &name) {
                    in_target_fn = true;
                    active_fn = name;
                    brace_depth = brace_delta(line);
                    if line.contains(".unwrap(") || line.contains(".expect(") {
                        panic!(
                            "decode gate violation in {}::{}: {}",
                            path.display(),
                            active_fn,
                            line.trim()
                        );
                    }
                    if brace_depth <= 0 {
                        in_target_fn = false;
                        active_fn.clear();
                        brace_depth = 0;
                    }
                    continue;
                }
            }
            continue;
        }

        if line.contains(".unwrap(") || line.contains(".expect(") {
            panic!(
                "decode gate violation in {}::{}: {}",
                path.display(),
                active_fn,
                line.trim()
            );
        }

        brace_depth += brace_delta(line);
        if brace_depth <= 0 {
            in_target_fn = false;
            active_fn.clear();
            brace_depth = 0;
        }
    }
}

fn should_gate_fn(path: &Path, name: &str) -> bool {
    let p = path.to_string_lossy();
    if p.ends_with("src/hir/codec.rs") || p.ends_with("src/mir/codec.rs") {
        return name.contains("decode") || name.starts_with("read_");
    }

    if p.ends_with("src/runtime/event_reader.rs") {
        return matches!(name, "read_log_header" | "read_next");
    }

    if p.ends_with("src/replay.rs") {
        return name.starts_with("decode_");
    }

    if p.ends_with("src/bundle.rs") {
        return name.contains("decode")
            || name.starts_with("parse_")
            || name.starts_with("read_")
            || name == "extract_events_evidence";
    }

    false
}

fn fn_name_from_line(trimmed: &str) -> Option<String> {
    if !(trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ")) {
        return None;
    }

    let after_fn = trimmed.split_once("fn ")?.1;
    let name: String = after_fn
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn brace_delta(line: &str) -> isize {
    let opens = line.chars().filter(|c| *c == '{').count() as isize;
    let closes = line.chars().filter(|c| *c == '}').count() as isize;
    opens - closes
}

fn path_arg(path: &Path) -> &str {
    path.to_str().expect("path must be utf8 for test")
}

fn run_nex(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nex"));
    cmd.args(args);

    for (k, v) in envs {
        cmd.env(k, v);
    }

    cmd.output().expect("run nex command")
}

fn assert_no_panic(case: &str, output: &Output) {
    let all = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !all.contains("panicked at"),
        "{} triggered panic output:\n{}",
        case,
        all
    );

    assert_ne!(
        output.status.code(),
        Some(101),
        "{} exited with panic code 101:\n{}",
        case,
        all
    );
}

fn hostile_bytes(seed: &mut u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        out.push((*seed & 0xFF) as u8);
    }
    out
}

fn unique_dir(label: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base =
        std::env::temp_dir().join(format!("nex_rc5_{}_{}_{}", label, std::process::id(), id));
    fs::create_dir_all(&base).expect("create unique test dir");
    base
}

fn build_log(
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
    flags: u16,
    records: &[(u64, u64, u16, Vec<u8>)],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&build_log_header(codegen_hash, source_hash, flags));

    for (seq, task_id, kind, payload) in records {
        out.extend_from_slice(&encode_record(*seq, *task_id, *kind, payload));
    }

    out
}

fn build_log_header(
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
    flags: u16,
) -> [u8; LOG_HEADER_LEN] {
    let mut header = [0u8; LOG_HEADER_LEN];
    header[0..4].copy_from_slice(&LOG_MAGIC);
    header[4..6].copy_from_slice(&LOG_VERSION.to_le_bytes());
    header[6..38].copy_from_slice(&codegen_hash);
    header[38..70].copy_from_slice(&source_hash);
    header[70..72].copy_from_slice(&flags.to_le_bytes());
    let crc = crc32_ieee(&header[0..72]);
    header[72..76].copy_from_slice(&crc.to_le_bytes());
    header
}

fn encode_record(seq: u64, task_id: u64, kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + payload.len());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&task_id.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn build_bundle_bytes(events_bytes: &[u8], evidence_bytes: &[u8], tag: String) -> Vec<u8> {
    let events_sha = sha256_hex(events_bytes);
    let evidence_sha = sha256_hex(evidence_bytes);

    let header_json = format!(
        "{{\"bundle_format\":\"nexbundle-v1\",\"codegen_hash_hex\":\"{}\",\"compression\":\"none\",\"evidence_sha256_hex\":\"{}\",\"events_sha256_hex\":\"{}\",\"policy_hash_hex\":\"{}\",\"provider_id\":\"{}\",\"public_key_b64\":\"{}\",\"sig_mode\":\"{}\",\"source_hash_hex\":\"{}\"}}",
        "00".repeat(32),
        evidence_sha,
        events_sha,
        "00".repeat(32),
        format!("file-v1-{tag}"),
        "",
        "v0.8.1",
        "00".repeat(32),
    );

    let mut out = Vec::new();
    out.extend_from_slice(&BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_FORMAT_VERSION.to_le_bytes());
    out.push(BUNDLE_HASH_ALG_SHA256);
    out.push(BUNDLE_SIG_ALG_ED25519);
    out.push(BUNDLE_FLAG_NONE);

    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(header_json.as_bytes());

    append_section(&mut out, events_bytes);
    append_section(&mut out, evidence_bytes);
    append_section(&mut out, &[]);
    append_section(&mut out, &[]);
    append_section(&mut out, &[]);

    out
}

fn append_section(dst: &mut Vec<u8>, section: &[u8]) {
    dst.extend_from_slice(&(section.len() as u64).to_le_bytes());
    dst.extend_from_slice(section);
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
