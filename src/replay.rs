// src/replay.rs
//
// ReplayHarness (binary-only canonical) + capability audit counters
// + structural verifier lifecycle checks + scheduler Phase 2 checks.

use crate::runtime::event::{SchedState, YieldKind};
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

fn decode_sched_init_tick(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 8 {
        return Err(err_invalid(format!(
            "Bad SchedInit payload len {}",
            payload.len()
        )));
    }
    Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
}

fn decode_sched_state(payload: &[u8]) -> io::Result<(SchedState, SchedState, u64)> {
    if payload.len() != 10 {
        return Err(err_invalid(format!(
            "Bad SchedState payload len {}",
            payload.len()
        )));
    }

    let from = SchedState::from_u8(payload[0])
        .ok_or_else(|| err_invalid(format!("invalid SchedState.from {}", payload[0])))?;
    let to = SchedState::from_u8(payload[1])
        .ok_or_else(|| err_invalid(format!("invalid SchedState.to {}", payload[1])))?;
    let tick = u64::from_le_bytes(payload[2..10].try_into().unwrap());

    Ok((from, to, tick))
}

fn decode_tick_start(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 8 {
        return Err(err_invalid(format!(
            "Bad TickStart payload len {}",
            payload.len()
        )));
    }
    Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
}

fn decode_tick_end(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 16 {
        return Err(err_invalid(format!(
            "Bad TickEnd payload len {}",
            payload.len()
        )));
    }
    Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
}

fn decode_pick_task(payload: &[u8]) -> io::Result<(u64, u64)> {
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

    let tick = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let task_id_u32 = u32::from_le_bytes(payload[8..12].try_into().unwrap());

    Ok((tick, u64::from(task_id_u32)))
}

fn decode_yield(payload: &[u8]) -> io::Result<(u64, u64, YieldKind)> {
    if payload.len() != 13 {
        return Err(err_invalid(format!(
            "Bad Yield payload len {}",
            payload.len()
        )));
    }

    let tick = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let task_id_u32 = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let kind = YieldKind::from_u8(payload[12])
        .ok_or_else(|| err_invalid(format!("invalid Yield.kind {}", payload[12])))?;

    Ok((tick, u64::from(task_id_u32), kind))
}

fn decode_fuel_debit_tick(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 17 {
        return Err(err_invalid(format!(
            "Bad FuelDebit payload len {}",
            payload.len()
        )));
    }
    Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
}

fn is_allowed_sched_transition(from: SchedState, to: SchedState) -> bool {
    matches!(
        (from, to),
        (SchedState::Init, SchedState::Running)
            | (SchedState::Running, SchedState::Draining)
            | (SchedState::Draining, SchedState::Finished)
    )
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

    // Scheduler-aware structural verifier state (Phase 2).
    let mut scheduler_events_seen = false;
    let mut scheduler_state: Option<SchedState> = None;
    let mut last_tick: Option<u64> = None;
    let mut open_tick: Option<u64> = None;
    let mut finished_tasks: BTreeSet<u64> = BTreeSet::new();
    let mut blocked_join: BTreeMap<u64, u64> = BTreeMap::new();
    let mut blocked_join_min_finished: BTreeMap<u64, usize> = BTreeMap::new();
    let mut fuel_exhausted_seen = false;
    let mut saw_draining_state = false;
    let mut saw_finished_state = false;

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

        // Phase 2 scheduler invariants (only when scheduler events are present).
        if is_scheduler_kind(ev.kind) {
            if !scheduler_events_seen {
                scheduler_events_seen = true;
                if ev.kind != KIND_SCHED_INIT {
                    return Err(err_invalid(format!(
                        "scheduler stream must begin with SchedInit, got kind {} at seq={}",
                        ev.kind, ev.seq
                    )));
                }
            }

            match ev.kind {
                KIND_SCHED_INIT => {
                    let tick0 = decode_sched_init_tick(&ev.payload)?;

                    if scheduler_state.is_some() {
                        return Err(err_invalid(format!(
                            "duplicate SchedInit at seq={}",
                            ev.seq
                        )));
                    }

                    scheduler_state = Some(SchedState::Init);
                    last_tick = Some(tick0);
                }

                KIND_SCHED_STATE => {
                    let (from, to, _tick) = decode_sched_state(&ev.payload)?;

                    let current = scheduler_state.ok_or_else(|| {
                        err_invalid(format!("SchedState before SchedInit at seq={}", ev.seq))
                    })?;

                    if current != from {
                        return Err(err_invalid(format!(
                            "SchedState 'from' mismatch at seq={}: expected {:?}, got {:?}",
                            ev.seq, current, from
                        )));
                    }

                    if !is_allowed_sched_transition(from, to) {
                        return Err(err_invalid(format!(
                            "illegal scheduler transition {:?}->{:?} at seq={}",
                            from, to, ev.seq
                        )));
                    }

                    scheduler_state = Some(to);
                    if to == SchedState::Draining {
                        saw_draining_state = true;
                    }
                    if to == SchedState::Finished {
                        saw_finished_state = true;
                    }
                }

                KIND_TICK_START => {
                    let tick = decode_tick_start(&ev.payload)?;

                    if let Some(open) = open_tick {
                        return Err(err_invalid(format!(
                            "TickStart at seq={} while tick {} is still open",
                            ev.seq, open
                        )));
                    }

                    if let Some(prev) = last_tick {
                        if tick < prev {
                            return Err(err_invalid(format!(
                                "TickStart regressed: prev={} current={} at seq={}",
                                prev, tick, ev.seq
                            )));
                        }
                    }

                    last_tick = Some(tick);
                    open_tick = Some(tick);
                }

                KIND_TICK_END => {
                    let tick = decode_tick_end(&ev.payload)?;

                    match open_tick {
                        None => {
                            return Err(err_invalid(format!(
                                "TickEnd at seq={} without matching TickStart",
                                ev.seq
                            )));
                        }
                        Some(open) => {
                            if open != tick {
                                return Err(err_invalid(format!(
                                    "TickEnd mismatch at seq={}: open_tick={} end_tick={}",
                                    ev.seq, open, tick
                                )));
                            }
                            open_tick = None;
                        }
                    }
                }

                KIND_PICK_TASK => {
                    let (_tick, picked_task) = decode_pick_task(&ev.payload)?;

                    if finished_tasks.contains(&picked_task) {
                        return Err(err_invalid(format!(
                            "PickTask selected finished task {} at seq={}",
                            picked_task, ev.seq
                        )));
                    }

                    if blocked_join.contains_key(&picked_task) {
                        let target = blocked_join.get(&picked_task).copied().unwrap_or(0);
                        if target != 0 {
                            if !finished_tasks.contains(&target) {
                                return Err(err_invalid(format!(
                                    "PickTask selected join-blocked waiter {} before target {} finished (seq={})",
                                    picked_task, target, ev.seq
                                )));
                            }
                        } else {
                            let min_finished = blocked_join_min_finished
                                .get(&picked_task)
                                .copied()
                                .unwrap_or(0);
                            if finished_tasks.len() < min_finished {
                                return Err(err_invalid(format!(
                                    "PickTask selected join-blocked waiter {} before any task finished after block (seq={})",
                                    picked_task, ev.seq
                                )));
                            }
                        }

                        blocked_join.remove(&picked_task);
                        blocked_join_min_finished.remove(&picked_task);
                    }
                }

                KIND_YIELD => {
                    let (_tick, waiter, kind) = decode_yield(&ev.payload)?;

                    if kind == YieldKind::JoinBlocked {
                        blocked_join.insert(waiter, 0);
                        blocked_join_min_finished
                            .insert(waiter, finished_tasks.len().saturating_add(1));
                    } else if kind == YieldKind::FuelExhausted {
                        fuel_exhausted_seen = true;
                    }
                }

                KIND_FUEL_DEBIT => {
                    let _ = decode_fuel_debit_tick(&ev.payload)?;
                }

                _ => {}
            }
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
                finished_tasks.insert(ev.task_id);

                let to_unblock: Vec<u64> = blocked_join
                    .iter()
                    .filter_map(|(waiter, target)| {
                        if *target == ev.task_id {
                            Some(*waiter)
                        } else {
                            None
                        }
                    })
                    .collect();
                for waiter in to_unblock {
                    blocked_join.remove(&waiter);
                    blocked_join_min_finished.remove(&waiter);
                }
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

                if blocked_join.contains_key(&ev.task_id) {
                    blocked_join.insert(ev.task_id, joined);
                    if finished_tasks.contains(&joined) {
                        blocked_join.remove(&ev.task_id);
                        blocked_join_min_finished.remove(&ev.task_id);
                    }
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

    if scheduler_events_seen {
        if open_tick.is_some() {
            return Err(err_invalid(format!(
                "TickStart at tick {} not closed by TickEnd",
                open_tick.unwrap_or(0)
            )));
        }

        if scheduler_state.is_none() {
            return Err(err_invalid("scheduler events present without SchedInit"));
        }
    }

    if fuel_exhausted_seen {
        if !saw_draining_state {
            return Err(err_invalid(
                "FuelExhausted observed but scheduler never transitioned to Draining",
            ));
        }
        if !saw_finished_state || scheduler_state != Some(SchedState::Finished) {
            return Err(err_invalid(
                "FuelExhausted observed but scheduler did not end in Finished",
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::crc32::crc32_ieee;
    use crate::runtime::event_reader::{
        KIND_RUN_FINISHED, KIND_SCHED_INIT, KIND_SCHED_STATE, KIND_TASK_FINISHED,
        KIND_TASK_STARTED, KIND_TICK_END, KIND_TICK_START, LOG_HEADER_LEN, LOG_MAGIC, LOG_VERSION,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn negative_sched_tick_backwards_rejected() {
        let mut records = base_records();
        records.extend_from_slice(&[
            record(2, 0, KIND_SCHED_INIT, &sched_init_payload(0)),
            record(
                3,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Init, SchedState::Running, 0),
            ),
            record(4, 0, KIND_TICK_START, &tick_start_payload(2)),
            record(5, 0, KIND_TICK_END, &tick_end_payload(2, 0, 0)),
            record(6, 0, KIND_TICK_START, &tick_start_payload(1)),
            record(7, 0, KIND_TICK_END, &tick_end_payload(1, 0, 0)),
            record(
                8,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Running, SchedState::Draining, 1),
            ),
            record(
                9,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Draining, SchedState::Finished, 1),
            ),
        ]);

        let bytes = finalize_log(records, 0, 10);
        let path = write_temp_log("neg_tick_backwards", &bytes);

        let err = verify_log(&path).expect_err("expected tick regression failure");
        let msg = err.to_string();
        assert!(
            msg.contains("TickStart regressed"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_sched_illegal_transition_rejected() {
        let mut records = base_records();
        records.extend_from_slice(&[
            record(2, 0, KIND_SCHED_INIT, &sched_init_payload(0)),
            record(
                3,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Init, SchedState::Running, 0),
            ),
            record(
                4,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Running, SchedState::Init, 0),
            ),
        ]);

        let bytes = finalize_log(records, 0, 5);
        let path = write_temp_log("neg_illegal_transition", &bytes);

        let err = verify_log(&path).expect_err("expected illegal transition failure");
        let msg = err.to_string();
        assert!(
            msg.contains("illegal scheduler transition"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_sched_tickstart_without_tickend_rejected() {
        let mut records = base_records();
        records.extend_from_slice(&[
            record(2, 0, KIND_SCHED_INIT, &sched_init_payload(0)),
            record(
                3,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Init, SchedState::Running, 0),
            ),
            record(4, 0, KIND_TICK_START, &tick_start_payload(0)),
            record(
                5,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Running, SchedState::Draining, 0),
            ),
            record(
                6,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Draining, SchedState::Finished, 0),
            ),
        ]);

        let bytes = finalize_log(records, 0, 7);
        let path = write_temp_log("neg_tickstart_without_end", &bytes);

        let err = verify_log(&path).expect_err("expected unmatched TickStart failure");
        let msg = err.to_string();
        assert!(
            msg.contains("not closed by TickEnd"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_sched_pick_finished_task_rejected() {
        let mut records = base_records();
        records.extend_from_slice(&[
            record(2, 0, KIND_SCHED_INIT, &sched_init_payload(0)),
            record(
                3,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Init, SchedState::Running, 0),
            ),
            record(4, 0, KIND_TICK_START, &tick_start_payload(0)),
            record(5, 0, KIND_PICK_TASK, &pick_task_payload(0, 0, "finished")),
            record(6, 0, KIND_TICK_END, &tick_end_payload(0, 0, 0)),
            record(
                7,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Running, SchedState::Draining, 0),
            ),
            record(
                8,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Draining, SchedState::Finished, 0),
            ),
        ]);

        let bytes = finalize_log(records, 0, 9);
        let path = write_temp_log("neg_pick_finished", &bytes);

        let err = verify_log(&path).expect_err("expected PickTask finished-task failure");
        let msg = err.to_string();
        assert!(
            msg.contains("PickTask selected finished task"),
            "unexpected verifier error: {}",
            msg
        );
    }

    fn base_records() -> Vec<Vec<u8>> {
        vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ]
    }

    fn build_header() -> [u8; LOG_HEADER_LEN] {
        let mut h = [0u8; LOG_HEADER_LEN];
        h[0..4].copy_from_slice(&LOG_MAGIC);
        h[4..6].copy_from_slice(&LOG_VERSION.to_le_bytes());
        h[6..38].copy_from_slice(&[0x11u8; 32]);
        h[38..70].copy_from_slice(&[0x22u8; 32]);
        h[70..72].copy_from_slice(&0u16.to_le_bytes());
        let crc = crc32_ieee(&h[0..72]);
        h[72..76].copy_from_slice(&crc.to_le_bytes());
        h
    }

    fn finalize_log(mut records: Vec<Vec<u8>>, exit_code: i32, run_finished_seq: u64) -> Vec<u8> {
        let header = build_header();

        let mut hasher = Sha256::new();
        hasher.update(header);
        for rec in &records {
            hasher.update(rec);
        }
        let digest = hasher.finalize();

        let mut run_payload = Vec::with_capacity(36);
        run_payload.extend_from_slice(&exit_code.to_le_bytes());
        run_payload.extend_from_slice(&digest);
        records.push(record(run_finished_seq, 0, KIND_RUN_FINISHED, &run_payload));

        let mut out = Vec::new();
        out.extend_from_slice(&header);
        for rec in records {
            out.extend_from_slice(&rec);
        }
        out
    }

    fn record(seq: u64, task_id: u64, kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
        rec.extend_from_slice(&seq.to_le_bytes());
        rec.extend_from_slice(&task_id.to_le_bytes());
        rec.extend_from_slice(&kind.to_le_bytes());
        rec.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        rec.extend_from_slice(payload);
        rec
    }

    fn sched_init_payload(tick0: u64) -> Vec<u8> {
        tick0.to_le_bytes().to_vec()
    }

    fn sched_state_payload(from: SchedState, to: SchedState, tick: u64) -> Vec<u8> {
        let mut p = Vec::with_capacity(10);
        p.push(from.as_u8());
        p.push(to.as_u8());
        p.extend_from_slice(&tick.to_le_bytes());
        p
    }

    fn tick_start_payload(tick: u64) -> Vec<u8> {
        tick.to_le_bytes().to_vec()
    }

    fn tick_end_payload(tick: u64, runnable: u32, blocked: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(16);
        p.extend_from_slice(&tick.to_le_bytes());
        p.extend_from_slice(&runnable.to_le_bytes());
        p.extend_from_slice(&blocked.to_le_bytes());
        p
    }

    fn pick_task_payload(tick: u64, task_id: u32, reason: &str) -> Vec<u8> {
        let rb = reason.as_bytes();
        let mut p = Vec::with_capacity(14 + rb.len());
        p.extend_from_slice(&tick.to_le_bytes());
        p.extend_from_slice(&task_id.to_le_bytes());
        p.extend_from_slice(&(rb.len() as u16).to_le_bytes());
        p.extend_from_slice(rb);
        p
    }

    fn write_temp_log(label: &str, bytes: &[u8]) -> PathBuf {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "nex_replay_{}_{}_{}.bin",
            label,
            std::process::id(),
            id
        ));
        fs::write(&path, bytes).expect("write temp log fixture");
        path
    }
}
