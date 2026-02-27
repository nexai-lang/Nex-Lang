// src/replay.rs
//
// ReplayHarness (binary-only canonical) + capability audit counters
// + structural verifier lifecycle checks.

use crate::runtime::event_reader::{
    EventReader, KIND_CAPABILITY_INVOKED, KIND_FUEL_DEBIT, KIND_PICK_TASK, KIND_RESOURCE_VIOLATION,
    KIND_RUN_FINISHED, KIND_SCHED_INIT, KIND_SCHED_STATE, KIND_TASK_CANCELLED, KIND_TASK_FINISHED,
    KIND_TASK_JOINED, KIND_TASK_SPAWNED, KIND_TASK_STARTED, KIND_TICK_END, KIND_TICK_START,
    KIND_YIELD, RECORD_HEADER_LEN,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

pub const VIOL_CAPABILITY_DENIED: u32 = 3;

#[derive(Debug, Default)]
struct TaskState {
    parent: Option<u64>,
    started: bool,
    finished: bool,
    cancelled: bool,
}

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

fn err_invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn is_scheduler_kind(kind: u16) -> bool {
    matches!(
        kind,
        KIND_SCHED_INIT
            | KIND_SCHED_STATE
            | KIND_TICK_START
            | KIND_TICK_END
            | KIND_PICK_TASK
            | KIND_YIELD
            | KIND_FUEL_DEBIT
    )
}

fn scheduler_tick(kind: u16, payload: &[u8]) -> io::Result<Option<u64>> {
    match kind {
        KIND_SCHED_INIT => {
            if payload.len() != 8 {
                return Err(err_invalid(format!(
                    "Bad SchedInit payload len {}",
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[0..8].try_into().unwrap())))
        }
        KIND_SCHED_STATE => {
            if payload.len() != 10 {
                return Err(err_invalid(format!(
                    "Bad SchedState payload len {}",
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[2..10].try_into().unwrap())))
        }
        KIND_TICK_START => {
            if payload.len() != 8 {
                return Err(err_invalid(format!(
                    "Bad TickStart payload len {}",
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[0..8].try_into().unwrap())))
        }
        KIND_TICK_END => {
            if payload.len() != 16 {
                return Err(err_invalid(format!(
                    "Bad TickEnd payload len {}",
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[0..8].try_into().unwrap())))
        }
        KIND_PICK_TASK => {
            if payload.len() < 14 {
                return Err(err_invalid(format!(
                    "Bad PickTask payload len {}",
                    payload.len()
                )));
            }
            let reason_len = u16::from_le_bytes(payload[12..14].try_into().unwrap()) as usize;
            if payload.len() != 14 + reason_len {
                return Err(err_invalid(format!(
                    "Bad PickTask payload length mismatch: expected {}, got {}",
                    14 + reason_len,
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[0..8].try_into().unwrap())))
        }
        KIND_YIELD => {
            if payload.len() != 13 {
                return Err(err_invalid(format!(
                    "Bad Yield payload len {}",
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[0..8].try_into().unwrap())))
        }
        KIND_FUEL_DEBIT => {
            if payload.len() != 17 {
                return Err(err_invalid(format!(
                    "Bad FuelDebit payload len {}",
                    payload.len()
                )));
            }
            Ok(Some(u64::from_le_bytes(payload[0..8].try_into().unwrap())))
        }
        _ => Ok(None),
    }
}

pub fn verify_log<P: AsRef<Path>>(path: P) -> io::Result<ReplayResult> {
    let path = path.as_ref();
    let f = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {:?}: {}", path, e)))?;
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

    let mut tasks: BTreeMap<u64, TaskState> = BTreeMap::new();
    let mut joined_once: BTreeSet<u64> = BTreeSet::new();
    let mut seen_run_finished = false;
    let mut root_started = false;
    let mut last_scheduler_tick: Option<u64> = None;

    while let Some(ev) = reader.read_next()? {
        if seen_run_finished {
            return Err(err_invalid(format!(
                "Event after RunFinished: seq={} task={} kind={}",
                ev.seq, ev.task_id, ev.kind
            )));
        }

        events_seen = events_seen.saturating_add(1);

        if ev.kind == KIND_CAPABILITY_INVOKED {
            cap_allowed_total = cap_allowed_total.saturating_add(1);
        } else if ev.kind == KIND_RESOURCE_VIOLATION && ev.payload.len() >= 4 {
            let code =
                u32::from_le_bytes([ev.payload[0], ev.payload[1], ev.payload[2], ev.payload[3]]);
            if code == VIOL_CAPABILITY_DENIED {
                cap_denied_total = cap_denied_total.saturating_add(1);
            }
        }

        if ev.task_id != 0 && !root_started && !is_scheduler_kind(ev.kind) {
            return Err(err_invalid(format!(
                "Non-root event before root TaskStarted: seq={} task={} kind={}",
                ev.seq, ev.task_id, ev.kind
            )));
        }

        if let Some(tick) = scheduler_tick(ev.kind, &ev.payload)? {
            if let Some(prev) = last_scheduler_tick {
                if tick < prev {
                    return Err(err_invalid(format!(
                        "scheduler tick regressed: prev={} current={} at seq={}",
                        prev, tick, ev.seq
                    )));
                }
            }
            last_scheduler_tick = Some(tick);
        }

        match ev.kind {
            KIND_TASK_SPAWNED => {
                if ev.payload.len() != 16 {
                    return Err(err_invalid(format!(
                        "Bad TaskSpawned payload len {} at seq={} task={}",
                        ev.payload.len(),
                        ev.seq,
                        ev.task_id
                    )));
                }

                let parent = u64::from_le_bytes(ev.payload[0..8].try_into().unwrap());
                let child = u64::from_le_bytes(ev.payload[8..16].try_into().unwrap());

                if parent == child {
                    return Err(err_invalid(format!(
                        "TaskSpawned parent==child ({}) at seq={}",
                        parent, ev.seq
                    )));
                }

                tasks.entry(parent).or_default();

                let child_state = tasks.entry(child).or_default();
                if let Some(existing_parent) = child_state.parent {
                    if existing_parent != parent {
                        return Err(err_invalid(format!(
                            "Task {} has two parents: {} and {} (seq={})",
                            child, existing_parent, parent, ev.seq
                        )));
                    }
                } else {
                    child_state.parent = Some(parent);
                }
            }

            KIND_TASK_STARTED => {
                if !ev.payload.is_empty() {
                    return Err(err_invalid(format!(
                        "Bad TaskStarted payload len {} at seq={} task={}",
                        ev.payload.len(),
                        ev.seq,
                        ev.task_id
                    )));
                }

                let state = tasks.entry(ev.task_id).or_default();
                if state.started {
                    return Err(err_invalid(format!(
                        "Task {} started twice (seq={})",
                        ev.task_id, ev.seq
                    )));
                }
                state.started = true;

                if ev.task_id == 0 {
                    root_started = true;
                }
            }

            KIND_TASK_FINISHED => {
                if ev.payload.len() != 4 {
                    return Err(err_invalid(format!(
                        "Bad TaskFinished payload len {} at seq={} task={}",
                        ev.payload.len(),
                        ev.seq,
                        ev.task_id
                    )));
                }

                let state = tasks.entry(ev.task_id).or_default();
                if !state.started {
                    return Err(err_invalid(format!(
                        "Task {} finished without start (seq={})",
                        ev.task_id, ev.seq
                    )));
                }
                if state.finished {
                    return Err(err_invalid(format!(
                        "Task {} finished twice (seq={})",
                        ev.task_id, ev.seq
                    )));
                }
                state.finished = true;
            }

            KIND_TASK_CANCELLED => {
                if ev.payload.len() != 4 {
                    return Err(err_invalid(format!(
                        "Bad TaskCancelled payload len {} at seq={} task={}",
                        ev.payload.len(),
                        ev.seq,
                        ev.task_id
                    )));
                }

                let state = tasks.entry(ev.task_id).or_default();
                if !state.started {
                    return Err(err_invalid(format!(
                        "Task {} cancelled without start (seq={})",
                        ev.task_id, ev.seq
                    )));
                }
                state.cancelled = true;
            }

            KIND_TASK_JOINED => {
                if ev.payload.len() != 8 {
                    return Err(err_invalid(format!(
                        "Bad TaskJoined payload len {} at seq={} joiner_task={}",
                        ev.payload.len(),
                        ev.seq,
                        ev.task_id
                    )));
                }

                let joined = u64::from_le_bytes(ev.payload[0..8].try_into().unwrap());

                let joiner = tasks.get(&ev.task_id).ok_or_else(|| {
                    err_invalid(format!(
                        "Unknown joiner task {} at seq={}",
                        ev.task_id, ev.seq
                    ))
                })?;
                if !joiner.started {
                    return Err(err_invalid(format!(
                        "Task {} joined before start (seq={})",
                        ev.task_id, ev.seq
                    )));
                }

                let joined_state = tasks.get(&joined).ok_or_else(|| {
                    err_invalid(format!(
                        "Task {} joined unknown task {} (seq={})",
                        ev.task_id, joined, ev.seq
                    ))
                })?;
                if !joined_state.finished {
                    return Err(err_invalid(format!(
                        "Task {} joined task {} before finish (seq={})",
                        ev.task_id, joined, ev.seq
                    )));
                }

                if let Some(parent) = joined_state.parent {
                    if parent != ev.task_id {
                        return Err(err_invalid(format!(
                            "Task {} joined task {} but is not its parent (parent={}) (seq={})",
                            ev.task_id, joined, parent, ev.seq
                        )));
                    }
                }

                if !joined_once.insert(joined) {
                    return Err(err_invalid(format!(
                        "Task {} joined more than once (seq={})",
                        joined, ev.seq
                    )));
                }
            }

            _ => {}
        }

        let payload_len = ev.payload.len() as u32;
        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + ev.payload.len());
        rec.extend_from_slice(&ev.seq.to_le_bytes());
        rec.extend_from_slice(&ev.task_id.to_le_bytes());
        rec.extend_from_slice(&ev.kind.to_le_bytes());
        rec.extend_from_slice(&payload_len.to_le_bytes());
        rec.extend_from_slice(&ev.payload);

        if ev.kind == KIND_RUN_FINISHED {
            if seen_run_finished {
                return Err(err_invalid(format!(
                    "Duplicate RunFinished at seq={}",
                    ev.seq
                )));
            }
            seen_run_finished = true;

            if ev.payload.len() < 4 + 32 {
                return Err(err_invalid("RunFinished payload too short"));
            }

            let ec =
                i32::from_le_bytes([ev.payload[0], ev.payload[1], ev.payload[2], ev.payload[3]]);
            let mut rh = [0u8; 32];
            rh.copy_from_slice(&ev.payload[4..36]);

            exit_code = Some(ec);
            expected_run_hash = Some(rh);
            run_finished_seq = Some(ev.seq);

            continue;
        }

        hasher.update(&rec);
    }

    if !seen_run_finished {
        return Err(err_invalid("missing RunFinished record"));
    }

    match tasks.get(&0) {
        Some(root) => {
            if !root.started {
                return Err(err_invalid("Root task (0) never started"));
            }
            if !root.finished {
                return Err(err_invalid("Root task (0) not finished at RunFinished"));
            }
        }
        None => return Err(err_invalid("No task table entry for root (0)")),
    }

    for (tid, st) in &tasks {
        if st.started && !st.finished {
            return Err(err_invalid(format!(
                "Orphan task at RunFinished: task {} started but not finished",
                tid
            )));
        }
        if st.finished && !st.started {
            return Err(err_invalid(format!("Task {} finished without start", tid)));
        }
    }

    let computed = hasher.finalize();
    let mut computed_arr = [0u8; 32];
    computed_arr.copy_from_slice(&computed[..]);

    let expected = expected_run_hash.ok_or_else(|| err_invalid("missing RunFinished record"))?;
    if computed_arr != expected {
        return Err(err_invalid(format!(
            "run hash mismatch: expected {}, computed {}",
            hex::encode(expected),
            hex::encode(computed_arr)
        )));
    }

    Ok(ReplayResult {
        events_seen,
        run_finished_seq: run_finished_seq.unwrap_or(0),
        exit_code: exit_code.unwrap_or(1),
        run_hash_hex: hex::encode(computed_arr),
        codegen_hash_hex: hex::encode(header.codegen_hash),
        source_hash_hex: hex::encode(header.source_hash),
        cap_allowed_total,
        cap_denied_total,
    })
}
