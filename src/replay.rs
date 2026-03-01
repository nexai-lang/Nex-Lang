// src/replay.rs
//
// ReplayHarness (binary-only canonical) + capability audit counters
// + structural verifier lifecycle checks + scheduler Phase 2 checks.

use crate::runtime::event::{SchedState, YieldKind};
use crate::runtime::event_reader::{
    EventReader, KIND_BUS_DECISION, KIND_BUS_RECV, KIND_BUS_SEND, KIND_BUS_SEND_REQUEST,
    KIND_BUS_SEND_RESULT, KIND_CAPABILITY_INVOKED, KIND_CHANNEL_CLOSED, KIND_CHANNEL_CREATED,
    KIND_DEADLOCK_DETECTED, KIND_DEADLOCK_EDGE, KIND_EVIDENCE_FINAL, KIND_FUEL_DEBIT,
    KIND_IO_BEGIN, KIND_IO_DECISION, KIND_IO_PAYLOAD, KIND_IO_REQUEST, KIND_IO_RESULT,
    KIND_MESSAGE_BLOCKED, KIND_MESSAGE_DELIVERED, KIND_MESSAGE_SENT, KIND_PICK_TASK,
    KIND_RESOURCE_VIOLATION, KIND_RUN_FINISHED, KIND_SCHED_INIT, KIND_SCHED_STATE,
    KIND_TASK_CANCELLED, KIND_TASK_FINISHED, KIND_TASK_JOINED, KIND_TASK_SPAWNED,
    KIND_TASK_STARTED, KIND_TICK_END, KIND_TICK_START, KIND_YIELD, RECORD_HEADER_LEN,
};
use crate::runtime::identity;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

pub const VIOL_CAPABILITY_DENIED: u32 = 3;
const LOG_FLAG_REPLAY_MODE: u16 = 0x0001;
const IO_KIND_FS_READ: u8 = 1;
const IO_KIND_FS_WRITE: u8 = 2;
const IO_KIND_NET_CONNECT: u8 = 3;
const IO_KIND_NET_SEND: u8 = 4;
const IO_KIND_NET_RECV: u8 = 5;
const IO_REASON_ALLOWED: u32 = 0;
const IO_REASON_DENIED_MISSING_CAPABILITY: u32 = 1;
const IO_REASON_DENIED_FUEL: u32 = 2;
const IO_REASON_DENIED_POLICY: u32 = 3;
const IO_REASON_DENIED_BACKPRESSURE: u32 = 4;
const COOP_EXIT_DEADLOCK: i32 = 75;

#[derive(Debug, Default)]
struct TaskState {
    parent: Option<u64>,
    started: bool,
    finished: bool,
    cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BusSendReqState {
    sender: u32,
    receiver: u32,
    decided: bool,
    decision_allowed: bool,
    result_seen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingIoState {
    AwaitDecision {
        request_seq: u64,
        kind: u8,
        req_id: u64,
    },
    AwaitPayload {
        request_seq: u64,
        kind: u8,
        req_id: u64,
        allowed: bool,
    },
    AwaitResult {
        request_seq: u64,
        kind: u8,
        req_id: u64,
        allowed: bool,
        payload_size: Option<u64>,
    },
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ReplayOptions {
    pub zero_trust: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvidenceSigMode {
    LegacyV080,
    V081(identity::EvidenceVersion),
}

#[derive(Debug, Clone)]
struct EvidenceFinalParsed {
    sig_mode: EvidenceSigMode,
    agent_id: u32,
    source_hash: [u8; 32],
    codegen_hash: [u8; 32],
    policy_hash: [u8; 32],
    run_hash: [u8; 32],
    public_key_b64: String,
    signature_b64: String,
    provider_id: String,
}

fn err_invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn read_u16_le_at(payload: &[u8], off: usize, field: &str) -> io::Result<u16> {
    let end = off
        .checked_add(2)
        .ok_or_else(|| err_invalid(format!("{} offset overflow", field)))?;
    let bytes = payload
        .get(off..end)
        .ok_or_else(|| err_invalid(format!("{} out of bounds", field)))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32_le_at(payload: &[u8], off: usize, field: &str) -> io::Result<u32> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| err_invalid(format!("{} offset overflow", field)))?;
    let bytes = payload
        .get(off..end)
        .ok_or_else(|| err_invalid(format!("{} out of bounds", field)))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le_at(payload: &[u8], off: usize, field: &str) -> io::Result<u64> {
    let end = off
        .checked_add(8)
        .ok_or_else(|| err_invalid(format!("{} offset overflow", field)))?;
    let bytes = payload
        .get(off..end)
        .ok_or_else(|| err_invalid(format!("{} out of bounds", field)))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
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
            | KIND_DEADLOCK_DETECTED
            | KIND_DEADLOCK_EDGE
    )
}

fn decode_sched_init_tick(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 8 {
        return Err(err_invalid(format!(
            "Bad SchedInit payload len {}",
            payload.len()
        )));
    }
    read_u64_le_at(payload, 0, "SchedInit.tick")
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
    let tick = read_u64_le_at(payload, 2, "SchedState.tick")?;

    Ok((from, to, tick))
}

fn decode_tick_start(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 8 {
        return Err(err_invalid(format!(
            "Bad TickStart payload len {}",
            payload.len()
        )));
    }
    read_u64_le_at(payload, 0, "TickStart.tick")
}

fn decode_tick_end(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 16 {
        return Err(err_invalid(format!(
            "Bad TickEnd payload len {}",
            payload.len()
        )));
    }
    read_u64_le_at(payload, 0, "TickEnd.tick")
}

fn decode_pick_task(payload: &[u8]) -> io::Result<(u64, u64)> {
    if payload.len() < 14 {
        return Err(err_invalid(format!(
            "Bad PickTask payload len {}",
            payload.len()
        )));
    }

    let reason_len = read_u16_le_at(payload, 12, "PickTask.reason_len")? as usize;
    if payload.len() != 14 + reason_len {
        return Err(err_invalid(format!(
            "Bad PickTask payload length mismatch: expected {}, got {}",
            14 + reason_len,
            payload.len()
        )));
    }

    let tick = read_u64_le_at(payload, 0, "PickTask.tick")?;
    let task_id_u32 = read_u32_le_at(payload, 8, "PickTask.task_id")?;

    Ok((tick, u64::from(task_id_u32)))
}

fn decode_yield(payload: &[u8]) -> io::Result<(u64, u64, YieldKind)> {
    if payload.len() != 13 {
        return Err(err_invalid(format!(
            "Bad Yield payload len {}",
            payload.len()
        )));
    }

    let tick = read_u64_le_at(payload, 0, "Yield.tick")?;
    let task_id_u32 = read_u32_le_at(payload, 8, "Yield.task_id")?;
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
    read_u64_le_at(payload, 0, "FuelDebit.tick")
}

fn decode_io_request(payload: &[u8]) -> io::Result<(u64, u8)> {
    if payload.len() >= 11 {
        let req_id = read_u64_le_at(payload, 0, "IoRequest.req_id")?;
        let maybe_kind = payload[8];
        let path_len = read_u16_le_at(payload, 9, "IoRequest.path_len")? as usize;
        if payload.len() == 11 + path_len
            && matches!(
                maybe_kind,
                IO_KIND_FS_READ
                    | IO_KIND_FS_WRITE
                    | IO_KIND_NET_CONNECT
                    | IO_KIND_NET_SEND
                    | IO_KIND_NET_RECV
            )
        {
            return Ok((req_id, maybe_kind));
        }
    }

    if payload.len() < 3 {
        return Err(err_invalid(format!(
            "Bad IoRequest payload len {}",
            payload.len()
        )));
    }
    let path_len = read_u16_le_at(payload, 1, "IoRequest.path_len_legacy")? as usize;
    if payload.len() != 3 + path_len {
        return Err(err_invalid(format!(
            "Bad IoRequest payload length mismatch: expected {}, got {}",
            3 + path_len,
            payload.len()
        )));
    }
    match payload[0] {
        IO_KIND_FS_READ | IO_KIND_FS_WRITE | IO_KIND_NET_CONNECT | IO_KIND_NET_SEND
        | IO_KIND_NET_RECV => Ok((0, payload[0])),
        v => Err(err_invalid(format!("invalid IoRequest kind {}", v))),
    }
}

fn decode_io_begin(payload: &[u8]) -> io::Result<u64> {
    if payload.len() != 8 {
        return Err(err_invalid(format!(
            "Bad IoBegin payload len {}",
            payload.len()
        )));
    }
    read_u64_le_at(payload, 0, "IoBegin.req_id")
}

fn decode_io_decision(payload: &[u8]) -> io::Result<(u64, bool, u32)> {
    if payload.len() == 13 {
        let req_id = read_u64_le_at(payload, 0, "IoDecision.req_id")?;
        let allowed = match payload[8] {
            0 => false,
            1 => true,
            v => return Err(err_invalid(format!("invalid IoDecision.allowed {}", v))),
        };
        let reason_code = read_u32_le_at(payload, 9, "IoDecision.reason")?;
        match reason_code {
            IO_REASON_ALLOWED
            | IO_REASON_DENIED_MISSING_CAPABILITY
            | IO_REASON_DENIED_FUEL
            | IO_REASON_DENIED_POLICY
            | IO_REASON_DENIED_BACKPRESSURE => {}
            other => {
                return Err(err_invalid(format!("invalid IoDecision.reason {}", other)));
            }
        }
        return Ok((req_id, allowed, reason_code));
    }

    if payload.len() != 1 {
        return Err(err_invalid(format!(
            "Bad IoDecision payload len {}",
            payload.len()
        )));
    }
    match payload[0] {
        0 => Ok((0, false, IO_REASON_DENIED_POLICY)),
        1 => Ok((0, true, IO_REASON_ALLOWED)),
        v => Err(err_invalid(format!("invalid IoDecision.allowed {}", v))),
    }
}

fn decode_io_result(payload: &[u8]) -> io::Result<(u64, bool, u64, Option<u8>)> {
    if payload.len() == 18 {
        let req_id = read_u64_le_at(payload, 0, "IoResult.req_id")?;
        let success = match payload[8] {
            0 => false,
            1 => true,
            v => return Err(err_invalid(format!("invalid IoResult.success {}", v))),
        };
        let size = read_u64_le_at(payload, 9, "IoResult.size")?;
        let code = payload[17];
        let code_opt = if code == u8::MAX {
            None
        } else if (1..=15).contains(&code) {
            Some(code)
        } else {
            return Err(err_invalid(format!("invalid IoResult.code {}", code)));
        };
        return Ok((req_id, success, size, code_opt));
    }

    if payload.len() == 17 {
        let req_id = read_u64_le_at(payload, 0, "IoResult.req_id")?;
        let success = match payload[8] {
            0 => false,
            1 => true,
            v => return Err(err_invalid(format!("invalid IoResult.success {}", v))),
        };
        let size = read_u64_le_at(payload, 9, "IoResult.size")?;
        return Ok((req_id, success, size, None));
    }

    if payload.len() != 9 {
        return Err(err_invalid(format!(
            "Bad IoResult payload len {}",
            payload.len()
        )));
    }
    let success = match payload[0] {
        0 => false,
        1 => true,
        v => return Err(err_invalid(format!("invalid IoResult.success {}", v))),
    };
    let size = read_u64_le_at(payload, 1, "IoResult.size_legacy")?;
    match payload[0] {
        0 | 1 => Ok((0, success, size, None)),
        v => Err(err_invalid(format!("invalid IoResult.success {}", v))),
    }
}

fn decode_io_payload(payload: &[u8]) -> io::Result<(u64, u64, u64, Option<&[u8]>)> {
    if payload.len() >= 25 {
        let req_id = read_u64_le_at(payload, 0, "IoPayload.req_id")?;
        let hash64 = read_u64_le_at(payload, 8, "IoPayload.hash64")?;
        let size = read_u64_le_at(payload, 16, "IoPayload.size")?;
        let has_bytes = payload[24];
        if has_bytes == 0 && payload.len() == 25 {
            return Ok((req_id, hash64, size, None));
        }
        if has_bytes == 1 && payload.len() >= 29 {
            let len = read_u32_le_at(payload, 25, "IoPayload.bytes_len")? as usize;
            if payload.len() == 29 + len {
                return Ok((req_id, hash64, size, Some(&payload[29..])));
            }
        }
    }

    if payload.len() < 17 {
        return Err(err_invalid(format!(
            "Bad IoPayload payload len {}",
            payload.len()
        )));
    }

    let hash64 = read_u64_le_at(payload, 0, "IoPayload.hash64_legacy")?;
    let size = read_u64_le_at(payload, 8, "IoPayload.size_legacy")?;
    let has_bytes = payload[16];
    match has_bytes {
        0 => {
            if payload.len() != 17 {
                return Err(err_invalid(format!(
                    "Bad IoPayload payload length mismatch: expected 17, got {}",
                    payload.len()
                )));
            }
            Ok((0, hash64, size, None))
        }
        1 => {
            if payload.len() < 21 {
                return Err(err_invalid(format!(
                    "Bad IoPayload payload too short for bytes len: {}",
                    payload.len()
                )));
            }
            let len = read_u32_le_at(payload, 17, "IoPayload.bytes_len_legacy")? as usize;
            if payload.len() != 21 + len {
                return Err(err_invalid(format!(
                    "Bad IoPayload payload length mismatch: expected {}, got {}",
                    21 + len,
                    payload.len()
                )));
            }
            Ok((0, hash64, size, Some(&payload[21..])))
        }
        v => Err(err_invalid(format!("invalid IoPayload.has_bytes {}", v))),
    }
}

fn decode_bus_send(payload: &[u8]) -> io::Result<(u64, u32, u32)> {
    if payload.len() != 30 {
        return Err(err_invalid(format!(
            "Bad BusSend payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "BusSend.req_id")?;
    let sender = read_u32_le_at(payload, 8, "BusSend.sender")?;
    let receiver = read_u32_le_at(payload, 12, "BusSend.receiver")?;
    Ok((req_id, sender, receiver))
}

fn decode_bus_recv(payload: &[u8]) -> io::Result<(u64, u32)> {
    if payload.len() != 12 {
        return Err(err_invalid(format!(
            "Bad BusRecv payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "BusRecv.req_id")?;
    let receiver = read_u32_le_at(payload, 8, "BusRecv.receiver")?;
    Ok((req_id, receiver))
}

fn decode_bus_send_request(payload: &[u8]) -> io::Result<(u64, u32, u32)> {
    if payload.len() != 24 {
        return Err(err_invalid(format!(
            "Bad BusSendRequest payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "BusSendRequest.req_id")?;
    let sender = read_u32_le_at(payload, 8, "BusSendRequest.sender")?;
    let receiver = read_u32_le_at(payload, 12, "BusSendRequest.receiver")?;
    Ok((req_id, sender, receiver))
}

fn decode_bus_decision(payload: &[u8]) -> io::Result<(u64, bool)> {
    if payload.len() != 13 {
        return Err(err_invalid(format!(
            "Bad BusDecision payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "BusDecision.req_id")?;
    let allowed = match payload[8] {
        0 => false,
        1 => true,
        v => return Err(err_invalid(format!("invalid BusDecision.allowed {}", v))),
    };
    Ok((req_id, allowed))
}

fn decode_bus_send_result(payload: &[u8]) -> io::Result<(u64, bool)> {
    if payload.len() != 9 {
        return Err(err_invalid(format!(
            "Bad BusSendResult payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "BusSendResult.req_id")?;
    let ok = match payload[8] {
        0 => false,
        1 => true,
        v => return Err(err_invalid(format!("invalid BusSendResult.ok {}", v))),
    };
    Ok((req_id, ok))
}

fn decode_channel_created(payload: &[u8]) -> io::Result<(u64, u64, u64, u64)> {
    if payload.len() != 32 {
        return Err(err_invalid(format!(
            "Bad ChannelCreated payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "ChannelCreated.req_id")?;
    let channel_id = read_u64_le_at(payload, 8, "ChannelCreated.channel_id")?;
    let schema_id = read_u64_le_at(payload, 16, "ChannelCreated.schema_id")?;
    let limits_digest = read_u64_le_at(payload, 24, "ChannelCreated.limits_digest")?;
    Ok((req_id, channel_id, schema_id, limits_digest))
}

fn decode_channel_closed(payload: &[u8]) -> io::Result<(u64, u64)> {
    if payload.len() != 16 {
        return Err(err_invalid(format!(
            "Bad ChannelClosed payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "ChannelClosed.req_id")?;
    let channel_id = read_u64_le_at(payload, 8, "ChannelClosed.channel_id")?;
    Ok((req_id, channel_id))
}

fn decode_message_sent(payload: &[u8]) -> io::Result<(u64, u64, u32, u64, u64, u64, u32)> {
    if payload.len() != 48 {
        return Err(err_invalid(format!(
            "Bad MessageSent payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "MessageSent.req_id")?;
    let channel_id = read_u64_le_at(payload, 8, "MessageSent.channel_id")?;
    let sender_id = read_u32_le_at(payload, 16, "MessageSent.sender_id")?;
    let sender_seq = read_u64_le_at(payload, 20, "MessageSent.sender_seq")?;
    let schema_id = read_u64_le_at(payload, 28, "MessageSent.schema_id")?;
    let hash64 = read_u64_le_at(payload, 36, "MessageSent.hash64")?;
    let size = read_u32_le_at(payload, 44, "MessageSent.size")?;
    Ok((
        req_id, channel_id, sender_id, sender_seq, schema_id, hash64, size,
    ))
}

fn decode_message_delivered(payload: &[u8]) -> io::Result<(u64, u64, u32, u32, u64, u64, u32)> {
    if payload.len() != 44 {
        return Err(err_invalid(format!(
            "Bad MessageDelivered payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "MessageDelivered.req_id")?;
    let channel_id = read_u64_le_at(payload, 8, "MessageDelivered.channel_id")?;
    let receiver_id = read_u32_le_at(payload, 16, "MessageDelivered.receiver_id")?;
    let sender_id = read_u32_le_at(payload, 20, "MessageDelivered.sender_id")?;
    let sender_seq = read_u64_le_at(payload, 24, "MessageDelivered.sender_seq")?;
    let hash64 = read_u64_le_at(payload, 32, "MessageDelivered.hash64")?;
    let size = read_u32_le_at(payload, 40, "MessageDelivered.size")?;
    Ok((
        req_id,
        channel_id,
        receiver_id,
        sender_id,
        sender_seq,
        hash64,
        size,
    ))
}

fn decode_message_blocked(payload: &[u8]) -> io::Result<(u64, u64, u32)> {
    if payload.len() != 20 {
        return Err(err_invalid(format!(
            "Bad MessageBlocked payload len {}",
            payload.len()
        )));
    }
    let req_id = read_u64_le_at(payload, 0, "MessageBlocked.req_id")?;
    let channel_id = read_u64_le_at(payload, 8, "MessageBlocked.channel_id")?;
    let receiver_id = read_u32_le_at(payload, 16, "MessageBlocked.receiver_id")?;
    Ok((req_id, channel_id, receiver_id))
}

fn decode_deadlock_detected(payload: &[u8]) -> io::Result<(u64, u32, u8)> {
    if payload.len() != 13 {
        return Err(err_invalid(format!(
            "Bad DeadlockDetected payload len {}",
            payload.len()
        )));
    }
    let tick = read_u64_le_at(payload, 0, "DeadlockDetected.tick")?;
    let blocked = read_u32_le_at(payload, 8, "DeadlockDetected.blocked")?;
    let kind = payload[12];
    if kind == 0 {
        return Err(err_invalid("invalid DeadlockDetected.kind 0"));
    }
    Ok((tick, blocked, kind))
}

fn decode_deadlock_edge(payload: &[u8]) -> io::Result<(u32, u32, u8)> {
    if payload.len() != 9 {
        return Err(err_invalid(format!(
            "Bad DeadlockEdge payload len {}",
            payload.len()
        )));
    }
    let from = read_u32_le_at(payload, 0, "DeadlockEdge.from")?;
    let to = read_u32_le_at(payload, 4, "DeadlockEdge.to")?;
    let reason = payload[8];
    match reason {
        1 | 2 | 3 => Ok((from, to, reason)),
        v => Err(err_invalid(format!("invalid DeadlockEdge.reason {}", v))),
    }
}

fn decode_evidence_final(payload: &[u8]) -> io::Result<EvidenceFinalParsed> {
    const LEGACY_FIXED: usize = 4 + 32 * 4;
    const V081_FIXED: usize = 4 + 4 + 4 + 4 + 32 * 4;

    if payload.len() < LEGACY_FIXED + 2 + 2 {
        return Err(err_invalid(format!(
            "EvidenceFinal payload too short: {}",
            payload.len()
        )));
    }

    fn read_u32_at(payload: &[u8], off: usize, field: &str) -> io::Result<u32> {
        let end = off.saturating_add(4);
        let bytes = payload
            .get(off..end)
            .ok_or_else(|| err_invalid(format!("EvidenceFinal {} out of bounds", field)))?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(arr))
    }

    fn read_arr32_at(payload: &[u8], off: usize, field: &str) -> io::Result<[u8; 32]> {
        let end = off.saturating_add(32);
        let bytes = payload
            .get(off..end)
            .ok_or_else(|| err_invalid(format!("EvidenceFinal {} out of bounds", field)))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn parse_tail(payload: &[u8], prefix_len: usize) -> io::Result<(String, String, String)> {
        let pk_len_end = prefix_len.saturating_add(2);
        let pk_len_bytes = payload
            .get(prefix_len..pk_len_end)
            .ok_or_else(|| err_invalid("EvidenceFinal public key length out of bounds"))?;
        let pk_len = u16::from_le_bytes([pk_len_bytes[0], pk_len_bytes[1]]) as usize;

        let pk_start = pk_len_end;
        let pk_end = pk_start.saturating_add(pk_len);
        if pk_end + 2 > payload.len() {
            return Err(err_invalid("EvidenceFinal public key length out of bounds"));
        }

        let sig_len_bytes = &payload[pk_end..pk_end + 2];
        let sig_len = u16::from_le_bytes([sig_len_bytes[0], sig_len_bytes[1]]) as usize;
        let sig_start = pk_end + 2;
        let sig_end = sig_start.saturating_add(sig_len);
        if sig_end > payload.len() {
            return Err(err_invalid("EvidenceFinal signature length mismatch"));
        }

        let public_key_b64 = std::str::from_utf8(&payload[pk_start..pk_end])
            .map_err(|e| err_invalid(format!("EvidenceFinal public key utf8: {}", e)))?
            .to_string();

        let signature_b64 = std::str::from_utf8(&payload[sig_start..sig_end])
            .map_err(|e| err_invalid(format!("EvidenceFinal signature utf8: {}", e)))?
            .to_string();

        let provider_id = if sig_end == payload.len() {
            identity::FILE_IDENTITY_PROVIDER_ID.to_string()
        } else {
            if sig_end + 2 > payload.len() {
                return Err(err_invalid(
                    "EvidenceFinal provider_id length out of bounds",
                ));
            }
            let provider_len =
                u16::from_le_bytes([payload[sig_end], payload[sig_end + 1]]) as usize;
            let provider_start = sig_end + 2;
            let provider_end = provider_start.saturating_add(provider_len);
            if provider_end != payload.len() {
                return Err(err_invalid("EvidenceFinal provider_id length mismatch"));
            }
            std::str::from_utf8(&payload[provider_start..provider_end])
                .map_err(|e| err_invalid(format!("EvidenceFinal provider_id utf8: {}", e)))?
                .to_string()
        };

        Ok((public_key_b64, signature_b64, provider_id))
    }

    if payload.len() >= V081_FIXED + 2 + 2 {
        let format = read_u32_at(payload, 0, "format")?;
        let hash_alg_raw = read_u32_at(payload, 4, "hash_alg")?;
        let sig_alg_raw = read_u32_at(payload, 8, "sig_alg")?;

        if let Ok((public_key_b64, signature_b64, provider_id)) = parse_tail(payload, V081_FIXED) {
            let hash_alg = identity::HashAlg::from_u32(hash_alg_raw).ok_or_else(|| {
                err_invalid(format!("unsupported evidence hash_alg: {}", hash_alg_raw))
            })?;
            let sig_alg = identity::SigAlg::from_u32(sig_alg_raw).ok_or_else(|| {
                err_invalid(format!("unsupported evidence sig_alg: {}", sig_alg_raw))
            })?;
            if format != identity::EvidenceVersion::FORMAT_V0_8_1 {
                return Err(err_invalid(format!(
                    "unsupported evidence format: {}",
                    format
                )));
            }

            let version = identity::EvidenceVersion {
                format,
                hash_alg,
                sig_alg,
            };

            return Ok(EvidenceFinalParsed {
                sig_mode: EvidenceSigMode::V081(version),
                agent_id: read_u32_at(payload, 12, "agent_id")?,
                source_hash: read_arr32_at(payload, 16, "source_hash")?,
                codegen_hash: read_arr32_at(payload, 48, "codegen_hash")?,
                policy_hash: read_arr32_at(payload, 80, "policy_hash")?,
                run_hash: read_arr32_at(payload, 112, "run_hash")?,
                public_key_b64,
                signature_b64,
                provider_id,
            });
        }
    }

    let (public_key_b64, signature_b64, provider_id) = parse_tail(payload, LEGACY_FIXED)?;
    Ok(EvidenceFinalParsed {
        sig_mode: EvidenceSigMode::LegacyV080,
        agent_id: read_u32_at(payload, 0, "agent_id")?,
        source_hash: read_arr32_at(payload, 4, "source_hash")?,
        codegen_hash: read_arr32_at(payload, 36, "codegen_hash")?,
        policy_hash: read_arr32_at(payload, 68, "policy_hash")?,
        run_hash: read_arr32_at(payload, 100, "run_hash")?,
        public_key_b64,
        signature_b64,
        provider_id,
    })
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn io_kind_name(kind: u8) -> &'static str {
    match kind {
        IO_KIND_FS_READ => "fs.read",
        IO_KIND_FS_WRITE => "fs.write",
        IO_KIND_NET_CONNECT => "net.connect",
        IO_KIND_NET_SEND => "net.send",
        IO_KIND_NET_RECV => "net.recv",
        _ => "io.unknown",
    }
}

#[inline]
fn is_io_event_kind(kind: u16) -> bool {
    matches!(
        kind,
        KIND_IO_BEGIN | KIND_IO_REQUEST | KIND_IO_DECISION | KIND_IO_PAYLOAD | KIND_IO_RESULT
    )
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
    verify_log_with_options(path, ReplayOptions::default())
}

pub fn verify_log_with_options<P: AsRef<Path>>(
    path: P,
    options: ReplayOptions,
) -> io::Result<ReplayResult> {
    let path = path.as_ref();
    let f = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("open {:?}: {}", path, e)))?;
    let mut reader = EventReader::new(BufReader::new(f));

    let header = reader.read_log_header()?;

    let mut run_hash_hasher = Sha256::new();
    run_hash_hasher.update(&header.raw);
    let mut evidence_run_hasher = Sha256::new();
    evidence_run_hasher.update(&header.raw);

    let mut expected_run_hash: Option<[u8; 32]> = None;
    let mut evidence_final: Option<EvidenceFinalParsed> = None;
    let mut saw_evidence_final = false;
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
    let replay_mode = (header.flags & LOG_FLAG_REPLAY_MODE) != 0;
    let mut pending_io: Vec<(u64, u8, u64)> = Vec::new();
    let mut pending_io_state: Option<PendingIoState> = None;
    let mut pending_io_begin_req: Option<u64> = None;
    let mut io_begin_seen = false;
    let mut last_io_req_id: Option<u64> = None;
    let mut bus_send_req: BTreeMap<u64, BusSendReqState> = BTreeMap::new();
    let mut bus_sent: BTreeMap<u64, (u32, u32, bool)> = BTreeMap::new();
    let mut bus_pending_by_receiver: BTreeMap<u32, BTreeSet<(u64, u32)>> = BTreeMap::new();
    let mut channels_open: BTreeSet<u64> = BTreeSet::new();
    let mut message_sent: BTreeMap<u64, (u64, u32, u64, u64, u32, bool)> = BTreeMap::new();
    let mut message_pending_by_channel: BTreeMap<u64, BTreeSet<(u32, u64, u64)>> = BTreeMap::new();
    let mut last_io_seq: Option<u64> = None;
    let mut deadlock_seen: Option<(u64, u32, u8)> = None;
    let mut deadlock_blocked_edges_seen: u32 = 0;
    let mut deadlock_last_from: Option<u32> = None;

    while let Some(ev) = reader.read_next()? {
        if seen_run_finished {
            return Err(err_invalid(format!(
                "Event after RunFinished: seq={} task={} kind={}",
                ev.seq, ev.task_id, ev.kind
            )));
        }

        if saw_evidence_final && ev.kind != KIND_RUN_FINISHED {
            return Err(err_invalid(format!(
                "Event after EvidenceFinal before RunFinished: seq={} task={} kind={}",
                ev.seq, ev.task_id, ev.kind
            )));
        }

        events_seen = events_seen.saturating_add(1);

        if is_io_event_kind(ev.kind) {
            if let Some(last) = last_io_seq {
                if ev.seq <= last {
                    return Err(err_invalid(format!(
                        "I/O event sequence is not strictly increasing: prev={} current={} kind={}",
                        last, ev.seq, ev.kind
                    )));
                }
            }
            last_io_seq = Some(ev.seq);
        }

        if let Some(pending) = pending_io_state {
            match pending {
                PendingIoState::AwaitDecision { .. } => {
                    if ev.kind != KIND_IO_DECISION {
                        return Err(err_invalid(format!(
                            "IoDecision expected after IoRequest but found kind {} at seq={}",
                            ev.kind, ev.seq
                        )));
                    }
                }
                PendingIoState::AwaitPayload { .. } => {
                    if ev.kind != KIND_IO_PAYLOAD {
                        return Err(err_invalid(format!(
                            "IoPayload expected after allowed IoDecision but found kind {} at seq={}",
                            ev.kind, ev.seq
                        )));
                    }
                }
                PendingIoState::AwaitResult { .. } => {
                    if ev.kind != KIND_IO_RESULT {
                        return Err(err_invalid(format!(
                            "IoResult expected after IoDecision/IoPayload but found kind {} at seq={}",
                            ev.kind, ev.seq
                        )));
                    }
                }
            }
        }

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

                KIND_DEADLOCK_DETECTED => {
                    if open_tick.is_some() {
                        return Err(err_invalid(format!(
                            "DeadlockDetected emitted with open tick at seq={}",
                            ev.seq
                        )));
                    }
                    if deadlock_seen.is_some() {
                        return Err(err_invalid(format!(
                            "duplicate DeadlockDetected at seq={}",
                            ev.seq
                        )));
                    }
                    let (tick, blocked, kind) = decode_deadlock_detected(&ev.payload)?;
                    deadlock_seen = Some((tick, blocked, kind));
                    deadlock_blocked_edges_seen = 0;
                    deadlock_last_from = None;
                }

                KIND_DEADLOCK_EDGE => {
                    let (from, _to, reason) = decode_deadlock_edge(&ev.payload)?;
                    let (_tick, blocked, _kind) = deadlock_seen.ok_or_else(|| {
                        err_invalid(format!(
                            "DeadlockEdge without DeadlockDetected at seq={}",
                            ev.seq
                        ))
                    })?;

                    if reason == 1 || reason == 2 {
                        if deadlock_blocked_edges_seen >= blocked {
                            return Err(err_invalid(format!(
                                "extra blocked DeadlockEdge beyond blocked_count at seq={}",
                                ev.seq
                            )));
                        }
                        if let Some(prev_from) = deadlock_last_from {
                            if from < prev_from {
                                return Err(err_invalid(format!(
                                    "DeadlockEdge blocked graph order regressed at seq={}: prev_from={} from={}",
                                    ev.seq, prev_from, from
                                )));
                            }
                        }
                        deadlock_last_from = Some(from);
                        deadlock_blocked_edges_seen = deadlock_blocked_edges_seen.saturating_add(1);
                    } else if deadlock_blocked_edges_seen < blocked {
                        return Err(err_invalid(format!(
                            "Deadlock cycle edges emitted before blocked graph completed at seq={}",
                            ev.seq
                        )));
                    }
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

                let parent = read_u64_le_at(&ev.payload, 0, "TaskSpawned.parent")?;
                let child = read_u64_le_at(&ev.payload, 8, "TaskSpawned.child")?;

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

                let joined = read_u64_le_at(&ev.payload, 0, "TaskJoined.joined")?;

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

            KIND_IO_BEGIN => {
                if replay_mode {
                    return Err(err_invalid(format!(
                        "IoBegin not allowed in replay mode at seq={}",
                        ev.seq
                    )));
                }
                if pending_io_state.is_some()
                    || !pending_io.is_empty()
                    || pending_io_begin_req.is_some()
                {
                    return Err(err_invalid(format!(
                        "IoBegin started before previous IO operation completed at seq={}",
                        ev.seq
                    )));
                }
                let req_id = decode_io_begin(&ev.payload)?;
                if req_id == 0 {
                    return Err(err_invalid(format!(
                        "IoBegin req_id must be > 0 at seq={}",
                        ev.seq
                    )));
                }
                match last_io_req_id {
                    Some(prev) if req_id != prev.saturating_add(1) => {
                        return Err(err_invalid(format!(
                            "IoBegin req_id must increase by 1: prev={} current={} at seq={}",
                            prev, req_id, ev.seq
                        )));
                    }
                    None if req_id != 1 => {
                        return Err(err_invalid(format!(
                            "first IoBegin req_id must be 1, got {} at seq={}",
                            req_id, ev.seq
                        )));
                    }
                    _ => {}
                }
                last_io_req_id = Some(req_id);
                pending_io_begin_req = Some(req_id);
                io_begin_seen = true;
            }

            KIND_IO_REQUEST => {
                let (request_req_id, kind) = decode_io_request(&ev.payload)?;
                if replay_mode {
                    return Err(err_invalid(format!(
                        "IoRequest not allowed in replay mode at seq={}",
                        ev.seq
                    )));
                }
                if !pending_io.is_empty() || pending_io_state.is_some() {
                    return Err(err_invalid(format!(
                        "IoRequest started before previous IO operation completed at seq={}",
                        ev.seq
                    )));
                }
                let begin_req_id = pending_io_begin_req.take().unwrap_or(0);
                if io_begin_seen && begin_req_id == 0 {
                    return Err(err_invalid(format!(
                        "IoRequest missing preceding IoBegin at seq={}",
                        ev.seq
                    )));
                }
                let req_id = if begin_req_id != 0 {
                    if request_req_id != 0 && request_req_id != begin_req_id {
                        return Err(err_invalid(format!(
                            "IoRequest req_id mismatch at seq={}: begin={} request={}",
                            ev.seq, begin_req_id, request_req_id
                        )));
                    }
                    begin_req_id
                } else {
                    request_req_id
                };
                pending_io.push((ev.seq, kind, req_id));
                pending_io_state = Some(PendingIoState::AwaitDecision {
                    request_seq: ev.seq,
                    kind,
                    req_id,
                });
            }

            KIND_IO_DECISION => {
                let (decision_req_id, allowed, reason_code) = decode_io_decision(&ev.payload)?;
                match pending_io_state {
                    Some(PendingIoState::AwaitDecision {
                        request_seq,
                        kind,
                        req_id,
                    }) => {
                        if req_id != 0 && decision_req_id != 0 && decision_req_id != req_id {
                            return Err(err_invalid(format!(
                                "IoDecision req_id mismatch at seq={}: expected {} got {}",
                                ev.seq, req_id, decision_req_id
                            )));
                        }
                        if allowed && reason_code != IO_REASON_ALLOWED {
                            return Err(err_invalid(format!(
                                "IoDecision.allowed=true must use reason Allowed at seq={}",
                                ev.seq
                            )));
                        }
                        if !allowed && reason_code == IO_REASON_ALLOWED {
                            return Err(err_invalid(format!(
                                "IoDecision.allowed=false cannot use reason Allowed at seq={}",
                                ev.seq
                            )));
                        }
                        if allowed {
                            pending_io_state = Some(PendingIoState::AwaitPayload {
                                request_seq,
                                kind,
                                req_id,
                                allowed,
                            });
                        } else {
                            pending_io_state = Some(PendingIoState::AwaitResult {
                                request_seq,
                                kind,
                                req_id,
                                allowed,
                                payload_size: None,
                            });
                        }
                    }
                    Some(PendingIoState::AwaitPayload { .. }) => {
                        return Err(err_invalid(format!(
                            "duplicate IoDecision before IoPayload at seq={}",
                            ev.seq
                        )));
                    }
                    Some(PendingIoState::AwaitResult { .. }) => {
                        return Err(err_invalid(format!(
                            "duplicate IoDecision before IoResult at seq={}",
                            ev.seq
                        )));
                    }
                    None => {
                        return Err(err_invalid(format!(
                            "IoDecision without preceding IoRequest at seq={}",
                            ev.seq
                        )));
                    }
                }
            }

            KIND_IO_PAYLOAD => {
                let (payload_req_id, hash64, size, bytes) = decode_io_payload(&ev.payload)?;
                match pending_io_state {
                    Some(PendingIoState::AwaitPayload {
                        request_seq,
                        kind,
                        req_id,
                        allowed,
                    }) => {
                        if !allowed {
                            return Err(err_invalid(format!(
                                "IoPayload after denied IoDecision at seq={}",
                                ev.seq
                            )));
                        }
                        if req_id != 0 && payload_req_id != 0 && payload_req_id != req_id {
                            return Err(err_invalid(format!(
                                "IoPayload req_id mismatch at seq={}: expected {} got {}",
                                ev.seq, req_id, payload_req_id
                            )));
                        }
                        match kind {
                            IO_KIND_FS_READ | IO_KIND_NET_RECV => {
                                if let Some(inline) = bytes {
                                    if (inline.len() as u64) != size {
                                        return Err(err_invalid(format!(
                                            "IoPayload size mismatch for {} at seq={}: payload.size={} inline_len={}",
                                            io_kind_name(kind),
                                            ev.seq,
                                            size,
                                            inline.len()
                                        )));
                                    }
                                    let computed = fnv1a64(inline);
                                    if computed != hash64 {
                                        return Err(err_invalid(format!(
                                            "IoPayload hash mismatch for {} at seq={}: expected={} computed={}",
                                            io_kind_name(kind),
                                            ev.seq,
                                            hash64,
                                            computed
                                        )));
                                    }
                                } else if size <= 64 * 1024 {
                                    return Err(err_invalid(format!(
                                        "IoPayload missing inline bytes for {} size {} at seq={}",
                                        io_kind_name(kind),
                                        size,
                                        ev.seq
                                    )));
                                }
                            }
                            IO_KIND_FS_WRITE => {
                                if bytes.is_some() {
                                    return Err(err_invalid(format!(
                                        "IoPayload.bytes must be absent for {} at seq={}",
                                        io_kind_name(kind),
                                        ev.seq
                                    )));
                                }
                            }
                            IO_KIND_NET_SEND => {
                                if let Some(inline) = bytes {
                                    if (inline.len() as u64) != size {
                                        return Err(err_invalid(format!(
                                            "IoPayload size mismatch for net.send at seq={}: payload.size={} inline_len={}",
                                            ev.seq, size, inline.len()
                                        )));
                                    }
                                    let computed = fnv1a64(inline);
                                    if computed != hash64 {
                                        return Err(err_invalid(format!(
                                            "IoPayload hash mismatch for net.send at seq={}: expected={} computed={}",
                                            ev.seq, hash64, computed
                                        )));
                                    }
                                }
                            }
                            IO_KIND_NET_CONNECT => {
                                let inline = bytes.ok_or_else(|| {
                                    err_invalid(format!(
                                        "IoPayload missing inline bytes for net.connect at seq={}",
                                        ev.seq
                                    ))
                                })?;
                                if size != 8 {
                                    return Err(err_invalid(format!(
                                        "IoPayload size mismatch for net.connect at seq={}: expected 8, got {}",
                                        ev.seq, size
                                    )));
                                }
                                if inline.len() != 8 {
                                    return Err(err_invalid(format!(
                                        "IoPayload inline bytes length mismatch for net.connect at seq={}: expected 8, got {}",
                                        ev.seq,
                                        inline.len()
                                    )));
                                }
                                let computed = fnv1a64(inline);
                                if computed != hash64 {
                                    return Err(err_invalid(format!(
                                        "IoPayload hash mismatch for net.connect at seq={}: expected={} computed={}",
                                        ev.seq, hash64, computed
                                    )));
                                }
                            }
                            _ => {
                                return Err(err_invalid(format!(
                                    "invalid pending IoRequest kind {} at seq={}",
                                    kind, ev.seq
                                )));
                            }
                        }
                        pending_io_state = Some(PendingIoState::AwaitResult {
                            request_seq,
                            kind,
                            req_id,
                            allowed,
                            payload_size: Some(size),
                        });
                    }
                    Some(PendingIoState::AwaitDecision { .. }) => {
                        return Err(err_invalid(format!(
                            "IoPayload before IoDecision at seq={}",
                            ev.seq
                        )));
                    }
                    Some(PendingIoState::AwaitResult { .. }) => {
                        return Err(err_invalid(format!(
                            "duplicate IoPayload before IoResult at seq={}",
                            ev.seq
                        )));
                    }
                    None => {
                        return Err(err_invalid(format!(
                            "IoPayload without preceding IoRequest at seq={}",
                            ev.seq
                        )));
                    }
                }
            }

            KIND_IO_RESULT => {
                let (result_req_id, success, size, code) = decode_io_result(&ev.payload)?;
                match pending_io_state {
                    Some(PendingIoState::AwaitResult {
                        request_seq,
                        kind,
                        req_id,
                        allowed,
                        payload_size,
                    }) => {
                        if req_id != 0 && result_req_id != 0 && result_req_id != req_id {
                            return Err(err_invalid(format!(
                                "IoResult req_id mismatch at seq={}: expected {} got {}",
                                ev.seq, req_id, result_req_id
                            )));
                        }
                        if allowed && payload_size.is_none() {
                            return Err(err_invalid(format!(
                                "IoResult without IoPayload after allowed IoDecision at seq={}",
                                ev.seq
                            )));
                        }
                        if !allowed && success {
                            return Err(err_invalid(format!(
                                "IoResult.success=true after denied IoDecision at seq={}",
                                ev.seq
                            )));
                        }
                        if success && code.is_some() {
                            return Err(err_invalid(format!(
                                "IoResult.success=true must not carry IoResult.code at seq={}",
                                ev.seq
                            )));
                        }
                        if !success && code.is_none() {
                            if req_id != 0 || result_req_id != 0 {
                                return Err(err_invalid(format!(
                                    "IoResult.success=false must carry IoResult.code at seq={}",
                                    ev.seq
                                )));
                            }
                        }
                        if let Some(ps) = payload_size {
                            if size != ps {
                                return Err(err_invalid(format!(
                                    "IoResult.size mismatch with IoPayload at seq={}: payload_size={} result_size={}",
                                    ev.seq, ps, size
                                )));
                            }
                        }
                        if allowed
                            && (kind == IO_KIND_FS_READ || kind == IO_KIND_NET_RECV)
                            && !success
                        {
                            if size != 0 {
                                return Err(err_invalid(format!(
                                    "failed {} IoResult must have size=0 at seq={}: got {}",
                                    io_kind_name(kind),
                                    ev.seq,
                                    size
                                )));
                            }
                        }
                        let (req_seq, req_kind, req_id_from_req) =
                            pending_io.pop().ok_or_else(|| {
                                err_invalid(format!(
                                    "IoResult without matching IoRequest at seq={}",
                                    ev.seq
                                ))
                            })?;
                        if req_seq != request_seq || req_kind != kind || req_id_from_req != req_id {
                            return Err(err_invalid(format!(
                                "IoResult matched wrong IoRequest at seq={}: request_seq={} result_request_seq={} request_kind={} result_kind={} request_req_id={} result_req_id={}",
                                ev.seq, req_seq, request_seq, req_kind, kind, req_id_from_req, req_id
                            )));
                        }
                        pending_io_state = None;
                    }
                    Some(PendingIoState::AwaitDecision { .. }) => {
                        return Err(err_invalid(format!(
                            "IoResult before IoDecision at seq={}",
                            ev.seq
                        )));
                    }
                    Some(PendingIoState::AwaitPayload { .. }) => {
                        return Err(err_invalid(format!(
                            "IoResult before IoPayload at seq={}",
                            ev.seq
                        )));
                    }
                    None => {
                        return Err(err_invalid(format!(
                            "IoResult without matching IoRequest at seq={}",
                            ev.seq
                        )));
                    }
                }
            }

            KIND_BUS_SEND_REQUEST => {
                if replay_mode {
                    return Err(err_invalid(format!(
                        "BusSendRequest not allowed in replay mode at seq={}",
                        ev.seq
                    )));
                }

                let (req_id, sender, receiver) = decode_bus_send_request(&ev.payload)?;
                if bus_send_req
                    .insert(
                        req_id,
                        BusSendReqState {
                            sender,
                            receiver,
                            decided: false,
                            decision_allowed: false,
                            result_seen: false,
                        },
                    )
                    .is_some()
                {
                    return Err(err_invalid(format!(
                        "duplicate BusSendRequest req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }
            }

            KIND_BUS_DECISION => {
                let (req_id, allowed) = decode_bus_decision(&ev.payload)?;
                if req_id == 0 {
                    continue;
                }

                let Some(state) = bus_send_req.get_mut(&req_id) else {
                    return Err(err_invalid(format!(
                        "BusDecision without matching BusSendRequest: req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                };
                if state.decided {
                    return Err(err_invalid(format!(
                        "duplicate BusDecision for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }

                state.decided = true;
                state.decision_allowed = allowed;
            }

            KIND_BUS_SEND_RESULT => {
                let (req_id, ok) = decode_bus_send_result(&ev.payload)?;
                let Some(state) = bus_send_req.get_mut(&req_id) else {
                    return Err(err_invalid(format!(
                        "BusSendResult without matching BusSendRequest: req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                };

                if !state.decided {
                    return Err(err_invalid(format!(
                        "BusSendResult before BusDecision for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }
                if state.result_seen {
                    return Err(err_invalid(format!(
                        "duplicate BusSendResult for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }
                if ok && !state.decision_allowed {
                    return Err(err_invalid(format!(
                        "BusSendResult.ok=true after denied BusDecision for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }

                state.result_seen = true;
                if ok {
                    if bus_sent
                        .insert(req_id, (state.sender, state.receiver, false))
                        .is_some()
                    {
                        return Err(err_invalid(format!(
                            "duplicate delivered req_id {} at seq={}",
                            req_id, ev.seq
                        )));
                    }
                    bus_pending_by_receiver
                        .entry(state.receiver)
                        .or_default()
                        .insert((req_id, state.sender));
                }
            }

            KIND_CHANNEL_CREATED => {
                let (_req_id, channel_id, _schema_id, _limits_digest) =
                    decode_channel_created(&ev.payload)?;
                if !channels_open.insert(channel_id) {
                    return Err(err_invalid(format!(
                        "duplicate ChannelCreated for channel_id {} at seq={}",
                        channel_id, ev.seq
                    )));
                }
            }

            KIND_CHANNEL_CLOSED => {
                let (_req_id, channel_id) = decode_channel_closed(&ev.payload)?;
                if !channels_open.remove(&channel_id) {
                    return Err(err_invalid(format!(
                        "ChannelClosed without open channel_id {} at seq={}",
                        channel_id, ev.seq
                    )));
                }
            }

            KIND_MESSAGE_SENT => {
                if replay_mode {
                    return Err(err_invalid(format!(
                        "MessageSent not allowed in replay mode at seq={}",
                        ev.seq
                    )));
                }
                let (req_id, channel_id, sender_id, sender_seq, _schema_id, hash64, size) =
                    decode_message_sent(&ev.payload)?;
                if !channels_open.contains(&channel_id) {
                    return Err(err_invalid(format!(
                        "MessageSent references non-open channel_id {} at seq={}",
                        channel_id, ev.seq
                    )));
                }
                if message_sent
                    .insert(
                        req_id,
                        (channel_id, sender_id, sender_seq, hash64, size, false),
                    )
                    .is_some()
                {
                    return Err(err_invalid(format!(
                        "duplicate MessageSent req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }
                message_pending_by_channel
                    .entry(channel_id)
                    .or_default()
                    .insert((sender_id, sender_seq, req_id));
            }

            KIND_MESSAGE_DELIVERED => {
                let (req_id, channel_id, _receiver_id, sender_id, sender_seq, hash64, size) =
                    decode_message_delivered(&ev.payload)?;
                let Some((
                    sent_channel,
                    sent_sender,
                    sent_sender_seq,
                    sent_hash,
                    sent_size,
                    delivered,
                )) = message_sent.get_mut(&req_id)
                else {
                    return Err(err_invalid(format!(
                        "MessageDelivered without MessageSent for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                };
                if *delivered {
                    return Err(err_invalid(format!(
                        "duplicate MessageDelivered for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }
                if *sent_channel != channel_id
                    || *sent_sender != sender_id
                    || *sent_sender_seq != sender_seq
                    || *sent_hash != hash64
                    || *sent_size != size
                {
                    return Err(err_invalid(format!(
                        "MessageDelivered mismatch for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }

                let Some(pending_for_channel) = message_pending_by_channel.get(&channel_id) else {
                    return Err(err_invalid(format!(
                        "MessageDelivered channel {} has no pending messages at seq={}",
                        channel_id, ev.seq
                    )));
                };
                let expected = pending_for_channel.iter().next().copied().ok_or_else(|| {
                    err_invalid(format!(
                        "MessageDelivered channel {} pending set is empty at seq={}",
                        channel_id, ev.seq
                    ))
                })?;
                if expected != (sender_id, sender_seq, req_id) {
                    return Err(err_invalid(format!(
                        "MessageDelivered ordering mismatch at seq={}: expected sender {} seq {} req_id {}, got sender {} seq {} req_id {}",
                        ev.seq, expected.0, expected.1, expected.2, sender_id, sender_seq, req_id
                    )));
                }

                let remove_channel_key =
                    if let Some(pending_mut) = message_pending_by_channel.get_mut(&channel_id) {
                        pending_mut.remove(&(sender_id, sender_seq, req_id));
                        pending_mut.is_empty()
                    } else {
                        false
                    };
                if remove_channel_key {
                    message_pending_by_channel.remove(&channel_id);
                }

                *delivered = true;
            }

            KIND_MESSAGE_BLOCKED => {
                let (_req_id, channel_id, _receiver_id) = decode_message_blocked(&ev.payload)?;
                if !channels_open.contains(&channel_id) {
                    return Err(err_invalid(format!(
                        "MessageBlocked references non-open channel_id {} at seq={}",
                        channel_id, ev.seq
                    )));
                }
            }

            KIND_BUS_SEND => {
                if replay_mode {
                    return Err(err_invalid(format!(
                        "BusSend not allowed in replay mode at seq={}",
                        ev.seq
                    )));
                }

                let (req_id, sender, receiver) = decode_bus_send(&ev.payload)?;
                if bus_sent.insert(req_id, (sender, receiver, false)).is_some() {
                    return Err(err_invalid(format!(
                        "duplicate BusSend req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }

                bus_pending_by_receiver
                    .entry(receiver)
                    .or_default()
                    .insert((req_id, sender));
            }

            KIND_BUS_RECV => {
                let (req_id, receiver) = decode_bus_recv(&ev.payload)?;
                let Some((sender, expected_receiver, delivered)) = bus_sent.get_mut(&req_id) else {
                    return Err(err_invalid(format!(
                        "BusRecv delivery mismatch: no matching successful send for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                };

                if *expected_receiver != receiver {
                    return Err(err_invalid(format!(
                        "BusRecv receiver mismatch for req_id {} at seq={}: expected {}, got {}",
                        req_id, ev.seq, *expected_receiver, receiver
                    )));
                }
                if *delivered {
                    return Err(err_invalid(format!(
                        "duplicate BusRecv for req_id {} at seq={}",
                        req_id, ev.seq
                    )));
                }

                let Some(pending_for_receiver) = bus_pending_by_receiver.get(&receiver) else {
                    return Err(err_invalid(format!(
                        "BusRecv delivery mismatch: receiver {} has no pending sends at seq={}",
                        receiver, ev.seq
                    )));
                };
                let expected = pending_for_receiver.iter().next().copied().ok_or_else(|| {
                    err_invalid(format!(
                        "BusRecv delivery mismatch: receiver {} has empty pending set at seq={}",
                        receiver, ev.seq
                    ))
                })?;

                if expected != (req_id, *sender) {
                    return Err(err_invalid(format!(
                        "BusRecv delivery mismatch at seq={}: expected req_id {} sender {} for receiver {}, got req_id {} sender {}",
                        ev.seq, expected.0, expected.1, receiver, req_id, *sender
                    )));
                }

                let remove_receiver_key =
                    if let Some(pending_mut) = bus_pending_by_receiver.get_mut(&receiver) {
                        pending_mut.remove(&(req_id, *sender));
                        pending_mut.is_empty()
                    } else {
                        false
                    };
                if remove_receiver_key {
                    bus_pending_by_receiver.remove(&receiver);
                }

                *delivered = true;
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

        if ev.kind == KIND_EVIDENCE_FINAL {
            if saw_evidence_final {
                return Err(err_invalid(format!(
                    "duplicate EvidenceFinal at seq={}",
                    ev.seq
                )));
            }
            saw_evidence_final = true;
            evidence_final = Some(decode_evidence_final(&ev.payload)?);

            run_hash_hasher.update(&rec);
            continue;
        }

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

        run_hash_hasher.update(&rec);
        if !saw_evidence_final {
            evidence_run_hasher.update(&rec);
        }
    }

    if !seen_run_finished {
        return Err(err_invalid("missing RunFinished record"));
    }

    if pending_io_state.is_some() || !pending_io.is_empty() || pending_io_begin_req.is_some() {
        return Err(err_invalid(
            "log ended with incomplete IO operation (missing IoDecision, IoPayload, or IoResult)",
        ));
    }

    for (req_id, st) in &bus_send_req {
        if !st.decided {
            return Err(err_invalid(format!(
                "log ended with incomplete BusSendRequest {} (missing BusDecision)",
                req_id
            )));
        }
        if !st.result_seen {
            return Err(err_invalid(format!(
                "log ended with incomplete BusSendRequest {} (missing BusSendResult)",
                req_id
            )));
        }
    }

    if let Some((_tick, blocked, _kind)) = deadlock_seen {
        if deadlock_blocked_edges_seen != blocked {
            return Err(err_invalid(format!(
                "DeadlockDetected blocked_count mismatch: expected {} blocked edges, saw {}",
                blocked, deadlock_blocked_edges_seen
            )));
        }
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

    if exit_code == Some(COOP_EXIT_DEADLOCK) && deadlock_seen.is_none() {
        return Err(err_invalid(
            "RunFinished exit_code=75 but DeadlockDetected was not emitted",
        ));
    }
    if exit_code != Some(COOP_EXIT_DEADLOCK) && deadlock_seen.is_some() {
        return Err(err_invalid(format!(
            "DeadlockDetected present but RunFinished exit_code={} (expected 75)",
            exit_code.unwrap_or(1)
        )));
    }

    if !saw_evidence_final {
        return Err(err_invalid("missing EvidenceFinal record"));
    }

    let evidence = evidence_final.ok_or_else(|| err_invalid("missing EvidenceFinal record"))?;

    if evidence.source_hash != header.source_hash {
        return Err(err_invalid(format!(
            "EvidenceFinal source_hash mismatch: header={} evidence={}",
            hex::encode(header.source_hash),
            hex::encode(evidence.source_hash)
        )));
    }

    if evidence.codegen_hash != header.codegen_hash {
        return Err(err_invalid(format!(
            "EvidenceFinal codegen_hash mismatch: header={} evidence={}",
            hex::encode(header.codegen_hash),
            hex::encode(evidence.codegen_hash)
        )));
    }

    let evidence_digest = evidence_run_hasher.finalize();
    let mut evidence_digest_arr = [0u8; 32];
    evidence_digest_arr.copy_from_slice(&evidence_digest[..]);

    if evidence.run_hash != evidence_digest_arr {
        return Err(err_invalid(format!(
            "evidence run hash mismatch: expected {}, computed {}",
            hex::encode(evidence.run_hash),
            hex::encode(evidence_digest_arr)
        )));
    }

    if evidence.provider_id != identity::FILE_IDENTITY_PROVIDER_ID {
        return Err(err_invalid(format!(
            "unsupported identity provider: {}",
            evidence.provider_id
        )));
    }

    if options.zero_trust {
        let trusted = identity::is_public_key_trusted_at(
            &identity::resolve_home_root(),
            &evidence.public_key_b64,
        )?;
        if !trusted {
            return Err(err_invalid(
                "zero-trust replay rejected untrusted public key",
            ));
        }
    }

    let public_key = identity::decode_b64_fixed::<32>(&evidence.public_key_b64, "public_key_b64")?;
    let signature = identity::decode_b64_fixed::<64>(&evidence.signature_b64, "signature_b64")?;

    let sig_ok = match evidence.sig_mode {
        EvidenceSigMode::LegacyV080 => identity::verify_evidence_signature_legacy(
            &public_key,
            &signature,
            evidence.agent_id,
            evidence.source_hash,
            evidence.codegen_hash,
            evidence.policy_hash,
            evidence.run_hash,
        ),
        EvidenceSigMode::V081(version) => identity::verify_evidence_signature_v0_8_1(
            &public_key,
            &signature,
            version,
            evidence.agent_id,
            evidence.source_hash,
            evidence.codegen_hash,
            evidence.policy_hash,
            evidence.run_hash,
        ),
    };
    if !sig_ok {
        return Err(err_invalid("EvidenceFinal signature verification failed"));
    }

    let computed = run_hash_hasher.finalize();
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
        KIND_BUS_DECISION, KIND_BUS_RECV, KIND_BUS_SEND, KIND_BUS_SEND_REQUEST,
        KIND_BUS_SEND_RESULT, KIND_DEADLOCK_DETECTED, KIND_DEADLOCK_EDGE, KIND_EVIDENCE_FINAL,
        KIND_IO_BEGIN, KIND_IO_DECISION, KIND_IO_PAYLOAD, KIND_IO_REQUEST, KIND_IO_RESULT,
        KIND_RUN_FINISHED, KIND_SCHED_INIT, KIND_SCHED_STATE, KIND_TASK_FINISHED,
        KIND_TASK_STARTED, KIND_TICK_END, KIND_TICK_START, LOG_HEADER_LEN, LOG_MAGIC, LOG_VERSION,
    };
    use crate::runtime::identity;
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

    #[test]
    fn negative_io_missing_decision_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(2, 0, KIND_IO_RESULT, &io_result_payload(true, 12)),
            record(3, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 4);
        let path = write_temp_log("neg_io_missing_decision", &bytes);

        let err = verify_log(&path).expect_err("expected missing IoDecision failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoDecision expected after IoRequest"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_io_begin_req_id_non_monotonic_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_IO_BEGIN, &io_begin_payload(1)),
            record(
                2,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(3, 0, KIND_IO_DECISION, &io_decision_payload(true)),
            record(
                4,
                0,
                KIND_IO_PAYLOAD,
                &io_payload_payload(fnv1a64(b"abc"), 3, Some(b"abc")),
            ),
            record(5, 0, KIND_IO_RESULT, &io_result_payload(true, 3)),
            record(6, 0, KIND_IO_BEGIN, &io_begin_payload(3)),
            record(
                7,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(8, 0, KIND_IO_DECISION, &io_decision_payload(false)),
            record(9, 0, KIND_IO_RESULT, &io_result_payload(false, 0)),
            record(10, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 11);
        let path = write_temp_log("neg_io_begin_req_id_non_monotonic", &bytes);

        let err = verify_log(&path).expect_err("expected IoBegin req_id monotonicity failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoBegin req_id must increase by 1"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_io_result_without_request_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_IO_RESULT, &io_result_payload(true, 12)),
            record(2, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 3);
        let path = write_temp_log("neg_io_result_without_request", &bytes);

        let err = verify_log(&path).expect_err("expected IoResult-without-IoRequest failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoResult without matching IoRequest"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_io_decision_without_request_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_IO_DECISION, &io_decision_payload(true)),
            record(2, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 3);
        let path = write_temp_log("neg_io_decision_without_request", &bytes);

        let err = verify_log(&path).expect_err("expected IoDecision-without-IoRequest failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoDecision without preceding IoRequest"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_io_denied_but_success_result_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(2, 0, KIND_IO_DECISION, &io_decision_payload(false)),
            record(3, 0, KIND_IO_RESULT, &io_result_payload(true, 12)),
            record(4, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 5);
        let path = write_temp_log("neg_io_denied_success", &bytes);

        let err = verify_log(&path).expect_err("expected denied/success mismatch failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoResult.success=true after denied IoDecision"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_io_two_results_for_one_request_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(2, 0, KIND_IO_DECISION, &io_decision_payload(false)),
            record(3, 0, KIND_IO_RESULT, &io_result_payload(false, 0)),
            record(4, 0, KIND_IO_RESULT, &io_result_payload(false, 0)),
            record(5, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 6);
        let path = write_temp_log("neg_io_two_results", &bytes);

        let err = verify_log(&path).expect_err("expected duplicate IoResult failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoResult without matching IoRequest"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_replay_mode_io_request_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(2, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log_with_flags(records, 0, 3, super::LOG_FLAG_REPLAY_MODE);
        let path = write_temp_log("neg_replay_mode_io_request", &bytes);

        let err = verify_log(&path).expect_err("expected replay-mode IoRequest rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("IoRequest not allowed in replay mode"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn v06_logs_without_io_events_still_pass() {
        let records = base_records();
        let bytes = finalize_log(records, 0, 2);
        let path = write_temp_log("v06_no_io_ok", &bytes);
        verify_log(&path).expect("v0.6 style logs without I/O should remain valid");
    }

    #[test]
    fn negative_io_allowed_missing_payload_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(2, 0, KIND_IO_DECISION, &io_decision_payload(true)),
            record(3, 0, KIND_IO_RESULT, &io_result_payload(true, 12)),
            record(4, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 5);
        let path = write_temp_log("neg_io_missing_payload", &bytes);

        let err = verify_log(&path).expect_err("expected missing IoPayload failure");
        let msg = err.to_string();
        assert!(
            msg.contains("IoPayload expected after allowed IoDecision"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn negative_io_payload_hash_mismatch_rejected() {
        let inline = b"hello-payload".to_vec();
        let bad_hash = super::fnv1a64(&inline).wrapping_add(1);
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_IO_REQUEST,
                &io_request_payload(1, "/tmp/fixture.txt"),
            ),
            record(2, 0, KIND_IO_DECISION, &io_decision_payload(true)),
            record(
                3,
                0,
                KIND_IO_PAYLOAD,
                &io_payload_payload(bad_hash, inline.len() as u64, Some(&inline)),
            ),
            record(
                4,
                0,
                KIND_IO_RESULT,
                &io_result_payload(true, inline.len() as u64),
            ),
            record(5, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 6);
        let path = write_temp_log("neg_io_payload_hash", &bytes);

        let err = verify_log(&path).expect_err("expected payload hash mismatch");
        let msg = err.to_string();
        assert!(
            msg.contains("IoPayload hash mismatch"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn replay_mode_rejects_new_send() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_BUS_SEND_REQUEST,
                &bus_send_request_payload(77, 1, 42, 0, 0),
            ),
            record(2, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log_with_flags(records, 0, 3, super::LOG_FLAG_REPLAY_MODE);
        let path = write_temp_log("replay_mode_rejects_new_send", &bytes);

        let err = verify_log(&path).expect_err("expected replay-mode bus send rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("BusSendRequest not allowed in replay mode"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn replay_mode_recv_mismatch_fails() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_BUS_RECV, &bus_recv_payload(77, 42)),
            record(2, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log_with_flags(records, 0, 3, super::LOG_FLAG_REPLAY_MODE);
        let path = write_temp_log("replay_mode_recv_mismatch_fails", &bytes);

        let err = verify_log(&path).expect_err("expected replay-mode bus recv rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("BusRecv delivery mismatch"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn bus_recv_non_canonical_order_rejected() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(
                1,
                0,
                KIND_BUS_SEND_REQUEST,
                &bus_send_request_payload(1, 2, 42, 0, 0),
            ),
            record(2, 0, KIND_BUS_DECISION, &bus_decision_payload(1, true, 0)),
            record(
                3,
                0,
                KIND_BUS_SEND_RESULT,
                &bus_send_result_payload(1, true),
            ),
            record(
                4,
                0,
                KIND_BUS_SEND_REQUEST,
                &bus_send_request_payload(2, 1, 42, 0, 0),
            ),
            record(5, 0, KIND_BUS_DECISION, &bus_decision_payload(2, true, 0)),
            record(
                6,
                0,
                KIND_BUS_SEND_RESULT,
                &bus_send_result_payload(2, true),
            ),
            record(7, 0, KIND_BUS_RECV, &bus_recv_payload(2, 42)),
            record(8, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 0, 9);
        let path = write_temp_log("bus_recv_non_canonical_order_rejected", &bytes);

        let err = verify_log(&path).expect_err("expected canonical bus order rejection");
        let msg = err.to_string();
        assert!(
            msg.contains("BusRecv delivery mismatch"),
            "unexpected verifier error: {}",
            msg
        );
    }

    #[test]
    fn deadlock_log_includes_deadlock_detected_before_run_finished() {
        let records = vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_SCHED_INIT, &sched_init_payload(0)),
            record(
                2,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Init, SchedState::Running, 0),
            ),
            record(
                3,
                0,
                KIND_DEADLOCK_DETECTED,
                &deadlock_detected_payload(7, 2, 1),
            ),
            record(4, 0, KIND_DEADLOCK_EDGE, &deadlock_edge_payload(0, 1, 1)),
            record(5, 0, KIND_DEADLOCK_EDGE, &deadlock_edge_payload(1, 9, 2)),
            record(
                6,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Running, SchedState::Draining, 7),
            ),
            record(
                7,
                0,
                KIND_SCHED_STATE,
                &sched_state_payload(SchedState::Draining, SchedState::Finished, 7),
            ),
            record(8, 0, KIND_TASK_FINISHED, &75i32.to_le_bytes()),
        ];

        let bytes = finalize_log(records, 75, 9);
        let path = write_temp_log("deadlock_event_before_run_finished", &bytes);

        let result = verify_log(&path).expect("deadlock log should verify");
        assert_eq!(result.exit_code, 75);
    }

    fn base_records() -> Vec<Vec<u8>> {
        vec![
            record(0, 0, KIND_TASK_STARTED, &[]),
            record(1, 0, KIND_TASK_FINISHED, &0i32.to_le_bytes()),
        ]
    }

    fn build_header_with_flags(flags: u16) -> [u8; LOG_HEADER_LEN] {
        let mut h = [0u8; LOG_HEADER_LEN];
        h[0..4].copy_from_slice(&LOG_MAGIC);
        h[4..6].copy_from_slice(&LOG_VERSION.to_le_bytes());
        h[6..38].copy_from_slice(&[0x11u8; 32]);
        h[38..70].copy_from_slice(&[0x22u8; 32]);
        h[70..72].copy_from_slice(&flags.to_le_bytes());
        let crc = crc32_ieee(&h[0..72]);
        h[72..76].copy_from_slice(&crc.to_le_bytes());
        h
    }

    fn build_header() -> [u8; LOG_HEADER_LEN] {
        build_header_with_flags(0)
    }

    fn finalize_log_with_flags(
        mut records: Vec<Vec<u8>>,
        exit_code: i32,
        run_finished_seq: u64,
        flags: u16,
    ) -> Vec<u8> {
        let header = build_header_with_flags(flags);

        let mut evidence_hasher = Sha256::new();
        evidence_hasher.update(header);
        for rec in &records {
            evidence_hasher.update(rec);
        }
        let evidence_digest = evidence_hasher.finalize();

        let mut evidence_run_hash = [0u8; 32];
        evidence_run_hash.copy_from_slice(&evidence_digest[..]);

        let secret_key = [7u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key);
        let keypair = identity::IdentityKeypair {
            public_key: signing_key.verifying_key().to_bytes(),
            secret_key,
        };

        let source_hash = [0x22u8; 32];
        let codegen_hash = [0x11u8; 32];
        let policy_hash = [0x33u8; 32];
        let signature = identity::sign_evidence(
            &keypair,
            0,
            source_hash,
            codegen_hash,
            policy_hash,
            evidence_run_hash,
        );

        let mut evidence_payload = Vec::new();
        evidence_payload.extend_from_slice(&0u32.to_le_bytes());
        evidence_payload.extend_from_slice(&source_hash);
        evidence_payload.extend_from_slice(&codegen_hash);
        evidence_payload.extend_from_slice(&policy_hash);
        evidence_payload.extend_from_slice(&evidence_run_hash);

        let public_key_b64 = identity::encode_b64(&keypair.public_key);
        let signature_b64 = identity::encode_b64(&signature);

        evidence_payload.extend_from_slice(&(public_key_b64.len() as u16).to_le_bytes());
        evidence_payload.extend_from_slice(public_key_b64.as_bytes());
        evidence_payload.extend_from_slice(&(signature_b64.len() as u16).to_le_bytes());
        evidence_payload.extend_from_slice(signature_b64.as_bytes());

        records.push(record(
            run_finished_seq,
            0,
            KIND_EVIDENCE_FINAL,
            &evidence_payload,
        ));

        let mut run_hash_hasher = Sha256::new();
        run_hash_hasher.update(header);
        for rec in &records {
            run_hash_hasher.update(rec);
        }
        let run_digest = run_hash_hasher.finalize();

        let mut run_payload = Vec::with_capacity(36);
        run_payload.extend_from_slice(&exit_code.to_le_bytes());
        run_payload.extend_from_slice(&run_digest);
        records.push(record(
            run_finished_seq.saturating_add(1),
            0,
            KIND_RUN_FINISHED,
            &run_payload,
        ));

        let mut out = Vec::new();
        out.extend_from_slice(&header);
        for rec in records {
            out.extend_from_slice(&rec);
        }
        out
    }

    fn finalize_log(records: Vec<Vec<u8>>, exit_code: i32, run_finished_seq: u64) -> Vec<u8> {
        finalize_log_with_flags(records, exit_code, run_finished_seq, 0)
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

    fn io_request_payload(kind: u8, path: &str) -> Vec<u8> {
        let path_bytes = path.as_bytes();
        let mut p = Vec::with_capacity(3 + path_bytes.len());
        p.push(kind);
        p.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
        p.extend_from_slice(path_bytes);
        p
    }

    fn io_begin_payload(req_id: u64) -> Vec<u8> {
        req_id.to_le_bytes().to_vec()
    }

    fn io_decision_payload(allowed: bool) -> Vec<u8> {
        vec![if allowed { 1 } else { 0 }]
    }

    fn io_result_payload(success: bool, size: u64) -> Vec<u8> {
        let mut p = Vec::with_capacity(9);
        p.push(if success { 1 } else { 0 });
        p.extend_from_slice(&size.to_le_bytes());
        p
    }

    fn io_payload_payload(hash64: u64, size: u64, bytes: Option<&[u8]>) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&hash64.to_le_bytes());
        p.extend_from_slice(&size.to_le_bytes());
        match bytes {
            Some(b) => {
                p.push(1);
                p.extend_from_slice(&(b.len() as u32).to_le_bytes());
                p.extend_from_slice(b);
            }
            None => p.push(0),
        }
        p
    }

    fn bus_send_request_payload(
        req_id: u64,
        sender: u32,
        receiver: u32,
        schema_id: u32,
        bytes: u32,
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(24);
        p.extend_from_slice(&req_id.to_le_bytes());
        p.extend_from_slice(&sender.to_le_bytes());
        p.extend_from_slice(&receiver.to_le_bytes());
        p.extend_from_slice(&schema_id.to_le_bytes());
        p.extend_from_slice(&bytes.to_le_bytes());
        p
    }

    fn bus_decision_payload(req_id: u64, allowed: bool, reason_code: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(13);
        p.extend_from_slice(&req_id.to_le_bytes());
        p.push(if allowed { 1 } else { 0 });
        p.extend_from_slice(&reason_code.to_le_bytes());
        p
    }

    fn bus_send_result_payload(req_id: u64, ok: bool) -> Vec<u8> {
        let mut p = Vec::with_capacity(9);
        p.extend_from_slice(&req_id.to_le_bytes());
        p.push(if ok { 1 } else { 0 });
        p
    }

    fn bus_recv_payload(req_id: u64, receiver: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(&req_id.to_le_bytes());
        p.extend_from_slice(&receiver.to_le_bytes());
        p
    }

    fn deadlock_detected_payload(tick: u64, blocked: u32, kind: u8) -> Vec<u8> {
        let mut p = Vec::with_capacity(13);
        p.extend_from_slice(&tick.to_le_bytes());
        p.extend_from_slice(&blocked.to_le_bytes());
        p.push(kind);
        p
    }

    fn deadlock_edge_payload(from: u32, to: u32, reason: u8) -> Vec<u8> {
        let mut p = Vec::with_capacity(9);
        p.extend_from_slice(&from.to_le_bytes());
        p.extend_from_slice(&to.to_le_bytes());
        p.push(reason);
        p
    }

    fn bus_send_payload(req_id: u64, sender: u32, receiver: u32, kind: u16) -> Vec<u8> {
        let mut p = Vec::with_capacity(30);
        p.extend_from_slice(&req_id.to_le_bytes());
        p.extend_from_slice(&sender.to_le_bytes());
        p.extend_from_slice(&receiver.to_le_bytes());
        p.extend_from_slice(&kind.to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes());
        p.extend_from_slice(&0u64.to_le_bytes());
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
