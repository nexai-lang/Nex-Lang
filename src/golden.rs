use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const LOG_HEADER_LEN: usize = 76;
const RECORD_HEADER_LEN: usize = 22;

const KIND_TASK_STARTED_U64: u64 = 6;
const KIND_TASK_FINISHED_U64: u64 = 7;
const KIND_TASK_CANCELLED_U64: u64 = 8;
const KIND_TASK_JOINED_U64: u64 = 9;
const KIND_TASK_SPAWNED_U64: u64 = 1;
const KIND_SCHED_INIT_U64: u64 = 10;
const KIND_SCHED_STATE_U64: u64 = 11;
const KIND_TICK_START_U64: u64 = 12;
const KIND_TICK_END_U64: u64 = 13;
const KIND_PICK_TASK_U64: u64 = 14;
const KIND_YIELD_U64: u64 = 15;
const KIND_FUEL_DEBIT_U64: u64 = 16;
const KIND_RUN_FINISHED_U64: u64 = 0xFFFF;

const KIND_TASK_CANCELLED_U16: u16 = 8;
const KIND_TASK_JOINED_U16: u16 = 9;
const KIND_RUN_FINISHED_U16: u16 = 0xFFFF;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct JsonEvent {
    seq: u64,
    task: u64,
    kind: u64,
    parent: Option<u64>,
    child: Option<u64>,
    joined_task: Option<u64>,
}

#[derive(Debug, Clone)]
struct RecordRef {
    kind: u16,
    record_offset: usize,
    record_len: usize,
    payload_offset: usize,
    payload_len: usize,
}

#[test]
fn cancel_bfs_replay_and_phase1_invariants() {
    let (out_dir, build_dir) = unique_dirs("cancel_bfs_phase1");
    let src = manifest_root().join("examples/cancel_bfs.nex");

    let run = run_nex(&["run", src.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run cancel_bfs", &run);

    let events_bin = out_dir.join("events.bin");
    assert!(events_bin.exists(), "missing events.bin at {}", events_bin.display());

    let replay = run_nex(
        &["replay", events_bin.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay cancel_bfs", &replay);
    assert!(
        String::from_utf8_lossy(&replay.stdout).contains("REPLAY OK"),
        "expected REPLAY OK\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );

    let events = parse_json_events(&out_dir.join("events.jsonl"));

    let root_started_idx = events
        .iter()
        .position(|e| e.task == 0 && e.kind == KIND_TASK_STARTED_U64)
        .expect("missing TaskStarted(0)");

    for (idx, ev) in events.iter().enumerate() {
        if ev.task != 0 && !is_scheduler_kind(ev.kind) {
            assert!(
                idx > root_started_idx,
                "non-root event before TaskStarted(0): {:?}",
                ev
            );
        }
    }

    let root_finished_idx = events
        .iter()
        .position(|e| e.task == 0 && e.kind == KIND_TASK_FINISHED_U64)
        .expect("missing TaskFinished(0)");

    let run_finished_idx = events
        .iter()
        .position(|e| e.kind == KIND_RUN_FINISHED_U64)
        .expect("missing RunFinished");

    assert_eq!(run_finished_idx, events.len() - 1, "RunFinished must be last");
    assert!(
        root_finished_idx < run_finished_idx,
        "TaskFinished(0) must occur before RunFinished"
    );

    let mut started = BTreeSet::new();
    let mut finished = BTreeSet::new();
    let mut finished_so_far = HashSet::new();
    let mut joined_once = HashSet::new();

    for ev in &events {
        if ev.kind == KIND_TASK_STARTED_U64 {
            started.insert(ev.task);
        }
        if ev.kind == KIND_TASK_FINISHED_U64 {
            finished.insert(ev.task);
            finished_so_far.insert(ev.task);
        }
        if ev.kind == KIND_TASK_JOINED_U64 {
            let joined = ev.joined_task.expect("TaskJoined missing joined_task");
            assert!(started.contains(&joined), "joined unknown task id {}", joined);
            assert!(
                finished_so_far.contains(&joined),
                "joined task {} before finish",
                joined
            );
            assert!(joined_once.insert(joined), "task {} joined twice", joined);
        }
    }

    for tid in started {
        assert!(finished.contains(&tid), "started task {} did not finish", tid);
    }

    let cancel_order: Vec<u64> = events
        .iter()
        .filter(|e| e.kind == KIND_TASK_CANCELLED_U64)
        .map(|e| e.task)
        .collect();
    assert!(!cancel_order.is_empty(), "expected at least one TaskCancelled");
    assert_eq!(cancel_order[0], 0, "BFS cancel traversal must begin at root 0");

    let mut sorted = cancel_order.clone();
    sorted.sort_unstable();
    assert_eq!(
        cancel_order, sorted,
        "cancelled task IDs must appear in deterministic BFS order"
    );
}

#[test]
fn negative_join_unknown_task_rejected() {
    let (out_dir, build_dir) = unique_dirs("neg_join_unknown");
    let src = manifest_root().join("examples/cancel_bfs.nex");

    let run = run_nex(&["run", src.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run base for join unknown", &run);

    let base = out_dir.join("events.bin");
    let bad = out_dir.join("events.join_unknown.bin");
    let mut bytes = fs::read(&base).expect("read base events.bin");
    let records = parse_records(&bytes);

    let rec = records
        .iter()
        .find(|r| r.kind == KIND_TASK_JOINED_U16)
        .expect("expected at least one TaskJoined in base fixture");
    write_u64_le(&mut bytes, rec.payload_offset, 999_999);
    refresh_run_hash(&mut bytes);
    fs::write(&bad, &bytes).expect("write tampered join_unknown log");

    let replay = run_nex(&["replay", bad.to_str().unwrap()], &out_dir, &build_dir);
    assert!(!replay.status.success(), "expected replay failure for unknown join");

    let all = format!(
        "{}\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        all.contains("joined unknown task"),
        "expected unknown join error, got:\n{}",
        all
    );
}

#[test]
fn negative_double_join_rejected() {
    let (out_dir, build_dir) = unique_dirs("neg_double_join");
    let src = manifest_root().join("examples/cancel_bfs.nex");

    let run = run_nex(&["run", src.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run base for double join", &run);

    let base = out_dir.join("events.bin");
    let bad = out_dir.join("events.double_join.bin");
    let mut bytes = fs::read(&base).expect("read base events.bin");
    let records = parse_records(&bytes);

    let joins: Vec<&RecordRef> = records
        .iter()
        .filter(|r| r.kind == KIND_TASK_JOINED_U16)
        .collect();
    assert!(joins.len() >= 2, "expected two joins in base fixture");

    let first_joined = read_u64_le(&bytes, joins[0].payload_offset);
    write_u64_le(&mut bytes, joins[1].payload_offset, first_joined);
    refresh_run_hash(&mut bytes);
    fs::write(&bad, &bytes).expect("write tampered double_join log");

    let replay = run_nex(&["replay", bad.to_str().unwrap()], &out_dir, &build_dir);
    assert!(!replay.status.success(), "expected replay failure for double join");

    let all = format!(
        "{}\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        all.contains("joined more than once"),
        "expected double join error, got:\n{}",
        all
    );
}

#[test]
fn negative_cancel_unknown_root_rejected() {
    let (out_dir, build_dir) = unique_dirs("neg_cancel_unknown_root");
    let src = manifest_root().join("examples/cancel_bfs.nex");

    let run = run_nex(&["run", src.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("nex run base for cancel unknown root", &run);

    let base = out_dir.join("events.bin");
    let bad = out_dir.join("events.cancel_unknown_root.bin");
    let mut bytes = fs::read(&base).expect("read base events.bin");
    let records = parse_records(&bytes);

    let cancel = records
        .iter()
        .find(|r| r.kind == KIND_TASK_CANCELLED_U16)
        .expect("expected at least one TaskCancelled in base fixture");

    // Rewrite event header task_id to unknown root id.
    write_u64_le(&mut bytes, cancel.record_offset + 8, 999_999);
    refresh_run_hash(&mut bytes);
    fs::write(&bad, &bytes).expect("write tampered cancel_unknown_root log");

    let replay = run_nex(&["replay", bad.to_str().unwrap()], &out_dir, &build_dir);
    assert!(!replay.status.success(), "expected replay failure for unknown cancel root");

    let all = format!(
        "{}\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        all.contains("cancelled without start"),
        "expected cancelled-without-start error, got:\n{}",
        all
    );
}

#[test]
fn nested_spawn_tree_three_levels_replay_ok() {
    let (out_dir, build_dir) = unique_dirs("nested_spawn_tree");
    let src_file = out_dir.join("nested_spawn_3_levels.nex");

    let src = r#"
fn level3() {
  1 + 2;
}

fn level2() {
  let t3 = spawn { level3(); };
  join(t3);
}

fn level1() {
  let t2 = spawn { level2(); };
  join(t2);
}

fn main() {
  let t1 = spawn { level1(); };
  join(t1);
}
"#;
    fs::write(&src_file, src).expect("write nested spawn source");

    let run = run_nex(
        &["run", src_file.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex run nested spawn", &run);

    let replay = run_nex(
        &["replay", out_dir.join("events.bin").to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay nested spawn", &replay);

    let events = parse_json_events(&out_dir.join("events.jsonl"));
    let spawned: Vec<(u64, u64)> = events
        .iter()
        .filter(|e| e.kind == KIND_TASK_SPAWNED_U64)
        .map(|e| (e.parent.expect("spawn parent"), e.child.expect("spawn child")))
        .collect();

    assert_eq!(
        spawned,
        vec![(0, 1), (1, 2), (2, 3)],
        "nested spawn tree must be deterministic and 3 levels deep"
    );
}

#[test]
fn child_finishes_before_cancel_replay_ok() {
    let (out_dir, build_dir) = unique_dirs("child_finish_before_cancel");
    let src_file = out_dir.join("child_finishes_before_cancel.nex");

    let src = r#"
fn main() {
  let t = spawn {
    1 + 2;
  };
  join(t);
  cancel(0);
}
"#;
    fs::write(&src_file, src).expect("write child-before-cancel source");

    let run = run_nex(
        &["run", src_file.to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex run child before cancel", &run);

    let replay = run_nex(
        &["replay", out_dir.join("events.bin").to_str().unwrap()],
        &out_dir,
        &build_dir,
    );
    assert_status_ok("nex replay child before cancel", &replay);

    let events = parse_json_events(&out_dir.join("events.jsonl"));
    let child_finished_idx = events
        .iter()
        .position(|e| e.task == 1 && e.kind == KIND_TASK_FINISHED_U64)
        .expect("missing TaskFinished for child 1");

    if let Some(first_cancel_idx) = events.iter().position(|e| e.kind == KIND_TASK_CANCELLED_U64) {
        assert!(
            child_finished_idx < first_cancel_idx,
            "child should finish before cancellation phase"
        );
    }

    let cancel_order: Vec<u64> = events
        .iter()
        .filter(|e| e.kind == KIND_TASK_CANCELLED_U64)
        .map(|e| e.task)
        .collect();
    if !cancel_order.is_empty() {
        let mut sorted = cancel_order.clone();
        sorted.sort_unstable();
        assert_eq!(cancel_order, sorted, "cancel order must remain deterministic");
    }
}

#[test]
fn jsonl_is_overwritten_each_run_not_appended() {
    let (out_dir, build_dir) = unique_dirs("jsonl_overwrite");
    let src = manifest_root().join("examples/cancel_bfs.nex");

    let first = run_nex(&["run", src.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("first run for overwrite test", &first);

    let second = run_nex(&["run", src.to_str().unwrap()], &out_dir, &build_dir);
    assert_status_ok("second run for overwrite test", &second);

    let lines = read_jsonl_lines(&out_dir.join("events.jsonl"));
    assert!(!lines.is_empty(), "events.jsonl is empty");

    let events: Vec<JsonEvent> = lines.iter().map(|l| parse_event(l)).collect();
    let run_finished_count = events
        .iter()
        .filter(|e| e.kind == KIND_RUN_FINISHED_U64)
        .count();

    assert_eq!(
        run_finished_count, 1,
        "events.jsonl appears appended across runs (multiple RunFinished records)"
    );
    assert_eq!(events[0].seq, 0, "first event seq should reset to 0 per run");
}

fn run_nex(args: &[&str], out_dir: &Path, build_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_nex"))
        .args(args)
        .env("NEX_OUT_DIR", out_dir)
        .env("NEX_BUILD_DIR", build_dir)
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

fn manifest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn unique_dirs(label: &str) -> (PathBuf, PathBuf) {
    let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!(
        "nex_test_{}_{}_{}",
        label,
        std::process::id(),
        id
    ));
    let out_dir = base.join("out");
    let build_dir = base.join("build");

    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&out_dir).unwrap();
    fs::create_dir_all(&build_dir).unwrap();

    (out_dir, build_dir)
}

fn read_jsonl_lines(path: &Path) -> Vec<String> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed reading {}: {}", path.display(), e));
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

fn parse_json_events(path: &Path) -> Vec<JsonEvent> {
    let lines = read_jsonl_lines(path);
    let mut events = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        assert!(
            is_valid_json_object_line(line),
            "invalid JSON at line {}: {}",
            idx + 1,
            line
        );
        assert!(
            !line.contains(",}"),
            "trailing comma in line {}: {}",
            idx + 1,
            line
        );
        events.push(parse_event(line));
    }
    events
}

fn is_scheduler_kind(kind: u64) -> bool {
    matches!(
        kind,
        KIND_SCHED_INIT_U64
            | KIND_SCHED_STATE_U64
            | KIND_TICK_START_U64
            | KIND_TICK_END_U64
            | KIND_PICK_TASK_U64
            | KIND_YIELD_U64
            | KIND_FUEL_DEBIT_U64
    )
}

fn parse_event(line: &str) -> JsonEvent {
    JsonEvent {
        seq: parse_u64_field(line, "seq").expect("missing seq"),
        task: parse_u64_field(line, "task").expect("missing task"),
        kind: parse_u64_field(line, "kind").expect("missing kind"),
        parent: parse_u64_field(line, "parent"),
        child: parse_u64_field(line, "child"),
        joined_task: parse_u64_field(line, "joined_task"),
    }
}

fn parse_u64_field(line: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = line.find(&needle)? + needle.len();
    let tail = &line[start..];

    let mut end = tail.len();
    for (idx, ch) in tail.char_indices() {
        if ch == ',' || ch == '}' {
            end = idx;
            break;
        }
    }

    let raw = tail[..end].trim();
    if raw.is_empty() || raw.starts_with('"') {
        return None;
    }

    raw.parse::<u64>().ok()
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

fn refresh_run_hash(bytes: &mut [u8]) {
    let records = parse_records(bytes);
    let run_idx = records
        .iter()
        .position(|r| r.kind == KIND_RUN_FINISHED_U16)
        .expect("missing RunFinished for hash refresh");

    let run_ref = &records[run_idx];
    assert_eq!(
        run_idx,
        records.len() - 1,
        "RunFinished must be last record"
    );
    assert!(
        run_ref.payload_len >= 36,
        "RunFinished payload must contain exit_code + hash"
    );

    let mut hasher = Sha256::new();
    hasher.update(&bytes[..LOG_HEADER_LEN]);

    for rec in &records[..run_idx] {
        hasher.update(&bytes[rec.record_offset..rec.record_offset + rec.record_len]);
    }

    let digest = hasher.finalize();
    let start = run_ref.payload_offset + 4;
    let end = start + 32;
    bytes[start..end].copy_from_slice(&digest[..]);
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

fn write_u64_le(bytes: &mut [u8], off: usize, value: u64) {
    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn is_valid_json_object_line(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'{' || *bytes.last().unwrap() != b'}' {
        return false;
    }

    let mut i = 1usize;
    let end = bytes.len() - 1;

    while i < end {
        skip_ws(bytes, &mut i);
        if i >= end {
            return false;
        }

        if !parse_json_string(bytes, &mut i, end) {
            return false;
        }

        skip_ws(bytes, &mut i);
        if i >= end || bytes[i] != b':' {
            return false;
        }
        i += 1;

        skip_ws(bytes, &mut i);
        if !parse_json_value(bytes, &mut i, end) {
            return false;
        }

        skip_ws(bytes, &mut i);
        if i == end {
            break;
        }

        if bytes[i] != b',' {
            return false;
        }
        i += 1;
    }

    i == end
}

fn skip_ws(bytes: &[u8], i: &mut usize) {
    while *i < bytes.len() && matches!(bytes[*i], b' ' | b'\n' | b'\r' | b'\t') {
        *i += 1;
    }
}

fn parse_json_string(bytes: &[u8], i: &mut usize, end: usize) -> bool {
    if *i >= end || bytes[*i] != b'"' {
        return false;
    }
    *i += 1;

    while *i < end {
        let ch = bytes[*i];
        if ch == b'"' {
            *i += 1;
            return true;
        }
        if ch == b'\\' {
            *i += 1;
            if *i >= end {
                return false;
            }
        }
        *i += 1;
    }

    false
}

fn parse_json_number(bytes: &[u8], i: &mut usize, end: usize) -> bool {
    if *i >= end {
        return false;
    }

    if bytes[*i] == b'-' {
        *i += 1;
        if *i >= end {
            return false;
        }
    }

    let start_digits = *i;
    while *i < end && bytes[*i].is_ascii_digit() {
        *i += 1;
    }

    *i > start_digits
}

fn parse_json_value(bytes: &[u8], i: &mut usize, end: usize) -> bool {
    if *i >= end {
        return false;
    }

    match bytes[*i] {
        b'"' => parse_json_string(bytes, i, end),
        b'-' | b'0'..=b'9' => parse_json_number(bytes, i, end),
        b't' => consume_literal(bytes, i, end, b"true"),
        b'f' => consume_literal(bytes, i, end, b"false"),
        b'n' => consume_literal(bytes, i, end, b"null"),
        _ => false,
    }
}

fn consume_literal(bytes: &[u8], i: &mut usize, end: usize, lit: &[u8]) -> bool {
    if *i + lit.len() > end {
        return false;
    }
    if &bytes[*i..*i + lit.len()] == lit {
        *i += lit.len();
        true
    } else {
        false
    }
}
