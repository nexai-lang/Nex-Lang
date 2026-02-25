// src/replay.rs
//
// v0.6-pre — ReplayHarness
//  - Canonical hash verification
//  - Capability governance counters
//  - Structural lifecycle validation
//
// Invariants enforced:
//  - Streaming SHA-256 correctness
//  - Exactly one terminal event per started task
//  - No orphan tasks at RunFinished
//  - Root task lifecycle correctness

use crate::runtime::event_reader::{
    EventReader, KIND_CAPABILITY_INVOKED, KIND_RESOURCE_VIOLATION, KIND_RUN_FINISHED,
    RECORD_HEADER_LEN,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

/// Must match runtime violation code
pub const VIOL_CAPABILITY_DENIED: u32 = 3;

// Lifecycle event kinds (must match runtime)
const KIND_TASK_STARTED: u16 = 5;
const KIND_TASK_FINISHED: u16 = 6;
const KIND_TASK_CANCELLED: u16 = 7;

#[derive(Debug)]
pub struct ReplayResult {
    pub events_seen: u64,
    pub run_finished_seq: u64,
    pub exit_code: i32,
    pub run_hash_hex: String,
    pub codegen_hash_hex: String,
    pub source_hash_hex: String,
    pub cap_allowed_total: u64,
    pub cap_denied_total: u64,
}

#[derive(Clone, Copy, Debug)]
enum TaskState {
    Started,
    Finished,
    Cancelled,
}

pub fn verify_log<P: AsRef<Path>>(path: P) -> io::Result<ReplayResult> {
    let path = path.as_ref();
    let f = File::open(path)?;
    let mut reader = EventReader::new(BufReader::new(f));

    let header = reader.read_log_header()?;

    let mut hasher = Sha256::new();
    hasher.update(&header.raw);

    let mut expected_run_hash: Option<[u8; 32]> = None;
    let mut exit_code: Option<i32> = None;
    let mut run_finished_seq: Option<u64> = None;

    let mut events_seen: u64 = 0;
    let mut cap_allowed_total: u64 = 0;
    let mut cap_denied_total: u64 = 0;

    // Structural lifecycle tracking
    let mut tasks: HashMap<u64, TaskState> = HashMap::new();

    while let Some(ev) = reader.read_next()? {
        events_seen = events_seen.saturating_add(1);

        // Governance counters
        if ev.kind == KIND_CAPABILITY_INVOKED {
            cap_allowed_total = cap_allowed_total.saturating_add(1);
        } else if ev.kind == KIND_RESOURCE_VIOLATION {
            if ev.payload.len() >= 4 {
                let code = u32::from_le_bytes([
                    ev.payload[0],
                    ev.payload[1],
                    ev.payload[2],
                    ev.payload[3],
                ]);
                if code == VIOL_CAPABILITY_DENIED {
                    cap_denied_total = cap_denied_total.saturating_add(1);
                }
            }
        }

        // Lifecycle tracking
        match ev.kind {
            KIND_TASK_STARTED => {
                if tasks.contains_key(&ev.task_id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Task {} started multiple times", ev.task_id),
                    ));
                }
                tasks.insert(ev.task_id, TaskState::Started);
            }
            KIND_TASK_FINISHED => {
                match tasks.get(&ev.task_id) {
                    Some(TaskState::Started) => {
                        tasks.insert(ev.task_id, TaskState::Finished);
                    }
                    Some(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Task {} has multiple terminal events", ev.task_id),
                        ));
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Task {} finished without being started", ev.task_id),
                        ));
                    }
                }
            }
            KIND_TASK_CANCELLED => {
                match tasks.get(&ev.task_id) {
                    Some(TaskState::Started) => {
                        tasks.insert(ev.task_id, TaskState::Cancelled);
                    }
                    Some(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Task {} has multiple terminal events", ev.task_id),
                        ));
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Task {} cancelled without being started", ev.task_id),
                        ));
                    }
                }
            }
            _ => {}
        }

        // Deterministic record reconstruction for hash
        let payload_len_u32: u32 = ev.payload.len() as u32;

        let mut record_bytes = Vec::with_capacity(RECORD_HEADER_LEN + ev.payload.len());
        record_bytes.extend_from_slice(&ev.seq.to_le_bytes());
        record_bytes.extend_from_slice(&ev.task_id.to_le_bytes());
        record_bytes.extend_from_slice(&ev.kind.to_le_bytes());
        record_bytes.extend_from_slice(&payload_len_u32.to_le_bytes());
        record_bytes.extend_from_slice(&ev.payload);

        if ev.kind != KIND_RUN_FINISHED {
            hasher.update(&record_bytes);
        } else {
            if ev.payload.len() < 4 + 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RunFinished payload too short",
                ));
            }

            let ec = i32::from_le_bytes([
                ev.payload[0],
                ev.payload[1],
                ev.payload[2],
                ev.payload[3],
            ]);

            let mut rh = [0u8; 32];
            rh.copy_from_slice(&ev.payload[4..4 + 32]);

            expected_run_hash = Some(rh);
            exit_code = Some(ec);
            run_finished_seq = Some(ev.seq);
        }
    }

    // Verify RunFinished exists
    let expected = expected_run_hash.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing RunFinished event")
    })?;

    let computed: [u8; 32] = hasher.finalize().into();

    if computed != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "run_hash mismatch (tamper detected)",
        ));
    }

    // Structural closure validation
    for (task_id, state) in &tasks {
        match state {
            TaskState::Started => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Task {} never terminated", task_id),
                ));
            }
            _ => {}
        }
    }

    // Root task must exist and terminate
    match tasks.get(&0) {
        Some(TaskState::Finished) | Some(TaskState::Cancelled) => {}
        Some(TaskState::Started) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Root task did not terminate",
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Root task never started",
            ));
        }
    }

    Ok(ReplayResult {
        events_seen,
        run_finished_seq: run_finished_seq.unwrap_or(0),
        exit_code: exit_code.unwrap_or(1),
        run_hash_hex: hex32(computed),
        codegen_hash_hex: hex32(header.codegen_hash),
        source_hash_hex: hex32(header.source_hash),
        cap_allowed_total,
        cap_denied_total,
    })
}

fn hex32(b: [u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for x in b {
        s.push(hex_nibble(x >> 4));
        s.push(hex_nibble(x & 0x0f));
    }
    s
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '?',
    }
}