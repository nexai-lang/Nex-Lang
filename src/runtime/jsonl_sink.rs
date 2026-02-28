// src/runtime/jsonl_sink.rs
//
// Deterministic JSONL sink for canonical binary events.
// View-layer only. Does NOT affect hashing.

use crate::runtime::event::*;
use crate::runtime::event_sink::EventSink;
use crate::runtime::identity;
use crate::runtime::io_proxy::IoKind;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::Path;

pub struct JsonlSink {
    writer: BufWriter<std::fs::File>,
}

impl JsonlSink {
    pub fn new(path: &Path) -> io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            writer: BufWriter::new(f),
        })
    }
}

impl EventSink for JsonlSink {
    fn on_event(&mut self, header: &EventHeader, payload: &[u8]) -> io::Result<()> {
        let line = json_line_for_record(header, payload)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn json_line_for_record(header: &EventHeader, payload: &[u8]) -> io::Result<String> {
    let mut fields = vec![
        format!(r#""seq":{}"#, header.seq),
        format!(r#""task":{}"#, header.task_id),
        format!(r#""kind":{}"#, header.kind.as_u16()),
    ];

    match header.kind {
        EventKind::RunStarted => {
            fields.push(r#""event":"RunStarted""#.to_string());
        }

        EventKind::TaskSpawned => {
            let p = decode_task_spawned(payload)?;
            fields.push(format!(r#""parent":{}"#, p.parent));
            fields.push(format!(r#""child":{}"#, p.child));
        }

        EventKind::CapabilityInvoked => {
            let p = decode_capability_invoked(payload)?;
            fields.push(format!(r#""cap_kind":{}"#, p.cap_kind.as_u16()));
            fields.push(format!(r#""cap_id":{}"#, p.cap_id));
            fields.push(format!(r#""args_digest":"{}""#, hex::encode(p.args_digest)));
        }

        EventKind::FuelExhausted => {
            let p = decode_fuel_exhausted(payload)?;
            fields.push(format!(r#""budget_before":{}"#, p.budget_before));
            fields.push(format!(r#""cost":{}"#, p.cost));
        }

        EventKind::ResourceViolation => {
            let p = decode_resource_violation(payload)?;
            fields.push(format!(r#""violation_code":{}"#, p.violation_code));
            fields.push(format!(
                r#""detail_digest":"{}""#,
                hex::encode(p.detail_digest)
            ));
        }

        EventKind::RunFinished => {
            let p = decode_run_finished(payload)?;
            fields.push(format!(r#""exit_code":{}"#, p.exit_code));
            fields.push(format!(
                r#""run_hash":"{}""#,
                hex::encode(p.run_hash_excluding_finish)
            ));
        }

        EventKind::EvidenceFinal => {
            let p = decode_evidence_final(payload)?;
            fields.push(r#""event":"EvidenceFinal""#.to_string());
            fields.push(format!(r#""evidence_format":{}"#, p.version.format));
            fields.push(format!(r#""hash_alg":{}"#, p.version.hash_alg));
            fields.push(format!(r#""sig_alg":{}"#, p.version.sig_alg));
            fields.push(format!(r#""agent_id":{}"#, p.agent_id));
            fields.push(format!(r#""source_hash":"{}""#, hex::encode(p.source_hash)));
            fields.push(format!(
                r#""codegen_hash":"{}""#,
                hex::encode(p.codegen_hash)
            ));
            fields.push(format!(r#""policy_hash":"{}""#, hex::encode(p.policy_hash)));
            fields.push(format!(r#""run_hash":"{}""#, hex::encode(p.run_hash)));
            fields.push(format!(
                r#""public_key_b64":"{}""#,
                escape_json(&p.public_key_b64)
            ));
            fields.push(format!(
                r#""signature_b64":"{}""#,
                escape_json(&p.signature_b64)
            ));
            fields.push(format!(
                r#""provider_id":"{}""#,
                escape_json(&p.provider_id)
            ));
        }

        EventKind::TaskStarted => {
            fields.push(r#""event":"TaskStarted""#.to_string());
        }

        EventKind::TaskFinished => {
            let p = decode_task_finished(payload)?;
            fields.push(format!(r#""exit_code":{}"#, p.exit_code));
        }

        EventKind::TaskCancelled => {
            let p = decode_task_cancelled(payload)?;
            fields.push(format!(r#""reason_code":{}"#, p.reason_code));
        }

        EventKind::TaskJoined => {
            let p = decode_task_joined(payload)?;
            fields.push(format!(r#""joined_task":{}"#, p.joined_task));
        }

        EventKind::SchedInit => {
            let p = decode_sched_init(payload)?;
            fields.push(r#""event":"SchedInit""#.to_string());
            fields.push(format!(r#""tick0":{}"#, p.tick0));
        }

        EventKind::SchedState => {
            let p = decode_sched_state(payload)?;
            fields.push(r#""event":"SchedState""#.to_string());
            fields.push(format!(r#""from":{}"#, p.from.as_u8()));
            fields.push(format!(r#""to":{}"#, p.to.as_u8()));
            fields.push(format!(r#""tick":{}"#, p.tick));
        }

        EventKind::TickStart => {
            let p = decode_tick_start(payload)?;
            fields.push(r#""event":"TickStart""#.to_string());
            fields.push(format!(r#""tick":{}"#, p.tick));
        }

        EventKind::TickEnd => {
            let p = decode_tick_end(payload)?;
            fields.push(r#""event":"TickEnd""#.to_string());
            fields.push(format!(r#""tick":{}"#, p.tick));
            fields.push(format!(r#""runnable":{}"#, p.runnable));
            fields.push(format!(r#""blocked":{}"#, p.blocked));
        }

        EventKind::PickTask => {
            let p = decode_pick_task(payload)?;
            fields.push(r#""event":"PickTask""#.to_string());
            fields.push(format!(r#""tick":{}"#, p.tick));
            fields.push(format!(r#""task_id":{}"#, p.task_id));
            fields.push(format!(r#""reason":"{}""#, escape_json(&p.reason)));
        }

        EventKind::r#Yield => {
            let p = decode_yield(payload)?;
            fields.push(r#""event":"Yield""#.to_string());
            fields.push(format!(r#""tick":{}"#, p.tick));
            fields.push(format!(r#""task_id":{}"#, p.task_id));
            fields.push(format!(r#""kind_code":{}"#, p.kind.as_u8()));
        }

        EventKind::FuelDebit => {
            let p = decode_fuel_debit(payload)?;
            fields.push(r#""event":"FuelDebit""#.to_string());
            fields.push(format!(r#""tick":{}"#, p.tick));
            fields.push(format!(r#""task_id":{}"#, p.task_id));
            fields.push(format!(r#""amount":{}"#, p.amount));
            fields.push(format!(r#""reason_code":{}"#, p.reason.as_u8()));
        }

        EventKind::IoBegin => {
            let req_id = decode_io_begin(payload)?;
            fields.push(r#""event":"IoBegin""#.to_string());
            fields.push(format!(r#""req_id":{}"#, req_id));
        }

        EventKind::IoRequest => {
            let p = decode_io_request(payload)?;
            fields.push(r#""event":"IoRequest""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""io_kind":{}"#, p.kind.as_u8()));
            fields.push(format!(r#""path":"{}""#, escape_json(&p.path)));
        }

        EventKind::IoDecision => {
            let p = decode_io_decision(payload)?;
            fields.push(r#""event":"IoDecision""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(
                r#""allowed":{}"#,
                if p.allowed { "true" } else { "false" }
            ));
            fields.push(format!(r#""reason_code":{}"#, p.reason_code));
        }

        EventKind::IoResult => {
            let p = decode_io_result(payload)?;
            fields.push(r#""event":"IoResult""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(
                r#""success":{}"#,
                if p.success { "true" } else { "false" }
            ));
            fields.push(format!(r#""size":{}"#, p.size));
            match p.code {
                Some(code) => fields.push(format!(r#""code":{}"#, code)),
                None => fields.push(r#""code":null"#.to_string()),
            }
        }

        EventKind::IoPayload => {
            let p = decode_io_payload(payload)?;
            fields.push(r#""event":"IoPayload""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""hash64":{}"#, p.hash64));
            fields.push(format!(r#""size":{}"#, p.size));
            match p.bytes {
                Some(bytes) => {
                    fields.push(format!(r#""bytes_hex":"{}""#, hex::encode(bytes)));
                }
                None => fields.push(r#""bytes_hex":null"#.to_string()),
            }
        }

        EventKind::BusSend => {
            let p = decode_bus_send(payload)?;
            fields.push(r#""event":"BusSend""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""sender":{}"#, p.sender));
            fields.push(format!(r#""receiver":{}"#, p.receiver));
            fields.push(format!(r#""msg_kind":{}"#, p.kind));
            fields.push(format!(r#""payload_len":{}"#, p.payload_len));
            fields.push(format!(r#""payload_hash64":{}"#, p.payload_hash64));
        }

        EventKind::BusRecv => {
            let p = decode_bus_recv(payload)?;
            fields.push(r#""event":"BusRecv""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""receiver":{}"#, p.receiver));
        }

        EventKind::BusSendRequest => {
            let p = decode_bus_send_request(payload)?;
            fields.push(r#""event":"BusSendRequest""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""sender":{}"#, p.sender));
            fields.push(format!(r#""receiver":{}"#, p.receiver));
            fields.push(format!(r#""schema_id":{}"#, p.schema_id));
            fields.push(format!(r#""bytes":{}"#, p.bytes));
        }

        EventKind::BusDecision => {
            let p = decode_bus_decision(payload)?;
            fields.push(r#""event":"BusDecision""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(
                r#""allowed":{}"#,
                if p.allowed { "true" } else { "false" }
            ));
            fields.push(format!(r#""reason_code":{}"#, p.reason_code));
        }

        EventKind::BusSendResult => {
            let p = decode_bus_send_result(payload)?;
            fields.push(r#""event":"BusSendResult""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""ok":{}"#, if p.ok { "true" } else { "false" }));
        }

        EventKind::MessageSent => {
            let p = decode_message_sent(payload)?;
            fields.push(r#""event":"MessageSent""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""channel_id":{}"#, p.channel_id));
            fields.push(format!(r#""sender_id":{}"#, p.sender_id));
            fields.push(format!(r#""sender_seq":{}"#, p.sender_seq));
            fields.push(format!(r#""schema_id":{}"#, p.schema_id));
            fields.push(format!(r#""hash64":{}"#, p.hash64));
            fields.push(format!(r#""size":{}"#, p.size));
        }

        EventKind::MessageDelivered => {
            let p = decode_message_delivered(payload)?;
            fields.push(r#""event":"MessageDelivered""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""channel_id":{}"#, p.channel_id));
            fields.push(format!(r#""receiver_id":{}"#, p.receiver_id));
            fields.push(format!(r#""sender_id":{}"#, p.sender_id));
            fields.push(format!(r#""sender_seq":{}"#, p.sender_seq));
            fields.push(format!(r#""hash64":{}"#, p.hash64));
            fields.push(format!(r#""size":{}"#, p.size));
        }

        EventKind::MessageBlocked => {
            let p = decode_message_blocked(payload)?;
            fields.push(r#""event":"MessageBlocked""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""channel_id":{}"#, p.channel_id));
            fields.push(format!(r#""receiver_id":{}"#, p.receiver_id));
        }

        EventKind::ChannelCreated => {
            let p = decode_channel_created(payload)?;
            fields.push(r#""event":"ChannelCreated""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""channel_id":{}"#, p.channel_id));
            fields.push(format!(r#""schema_id":{}"#, p.schema_id));
            fields.push(format!(r#""limits_digest":{}"#, p.limits_digest));
        }

        EventKind::ChannelClosed => {
            let p = decode_channel_closed(payload)?;
            fields.push(r#""event":"ChannelClosed""#.to_string());
            fields.push(format!(r#""req_id":{}"#, p.req_id));
            fields.push(format!(r#""channel_id":{}"#, p.channel_id));
        }

        EventKind::DeadlockDetected => {
            let p = decode_deadlock_detected(payload)?;
            fields.push(r#""event":"DeadlockDetected""#.to_string());
            fields.push(format!(r#""tick":{}"#, p.tick));
            fields.push(format!(r#""blocked":{}"#, p.blocked));
            fields.push(format!(r#""kind_code":{}"#, p.kind));
        }

        EventKind::DeadlockEdge => {
            let p = decode_deadlock_edge(payload)?;
            fields.push(r#""event":"DeadlockEdge""#.to_string());
            fields.push(format!(r#""from":{}"#, p.from));
            fields.push(format!(r#""to":{}"#, p.to));
            fields.push(format!(r#""reason_code":{}"#, p.reason));
        }
    }

    Ok(format!("{{{}}}", fields.join(",")))
}

fn require_len(payload: &[u8], expected: usize, kind: &str) -> io::Result<()> {
    if payload.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} payload length mismatch: expected {}, got {}",
                kind,
                expected,
                payload.len()
            ),
        ));
    }
    Ok(())
}

fn decode_task_spawned(payload: &[u8]) -> io::Result<TaskSpawned> {
    require_len(payload, 16, "TaskSpawned")?;
    Ok(TaskSpawned {
        parent: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        child: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    })
}

fn decode_capability_invoked(payload: &[u8]) -> io::Result<CapabilityInvoked> {
    require_len(payload, 38, "CapabilityInvoked")?;
    Ok(CapabilityInvoked {
        cap_kind: match u16::from_le_bytes(payload[0..2].try_into().unwrap()) {
            1 => CapabilityKind::FsRead,
            2 => CapabilityKind::NetListen,
            3 => CapabilityKind::BusSend,
            4 => CapabilityKind::BusRecv,
            _ => CapabilityKind::FsRead,
        },
        cap_id: u32::from_le_bytes(payload[2..6].try_into().unwrap()),
        args_digest: payload[6..38].try_into().unwrap(),
    })
}

fn decode_fuel_exhausted(payload: &[u8]) -> io::Result<FuelExhausted> {
    require_len(payload, 16, "FuelExhausted")?;
    Ok(FuelExhausted {
        budget_before: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        cost: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    })
}

fn decode_resource_violation(payload: &[u8]) -> io::Result<ResourceViolation> {
    require_len(payload, 36, "ResourceViolation")?;
    Ok(ResourceViolation {
        violation_code: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
        detail_digest: payload[4..36].try_into().unwrap(),
    })
}

fn decode_run_finished(payload: &[u8]) -> io::Result<RunFinished> {
    require_len(payload, 36, "RunFinished")?;
    Ok(RunFinished {
        exit_code: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
        run_hash_excluding_finish: payload[4..36].try_into().unwrap(),
    })
}

fn decode_evidence_final(payload: &[u8]) -> io::Result<EvidenceFinal> {
    const LEGACY_FIXED: usize = 4 + 32 * 4;
    const V081_FIXED: usize = 4 + 4 + 4 + 4 + 32 * 4;

    if payload.len() < LEGACY_FIXED + 2 + 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("EvidenceFinal payload too short: {}", payload.len()),
        ));
    }

    let read_u32 = |off: usize, field: &str| -> io::Result<u32> {
        let end = off.saturating_add(4);
        let bytes = payload.get(off..end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("EvidenceFinal {} out of bounds", field),
            )
        })?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        Ok(u32::from_le_bytes(arr))
    };

    let parse_tail = |prefix_len: usize,
                      version: EvidenceVersion,
                      agent_id: u32,
                      source_hash: [u8; 32],
                      codegen_hash: [u8; 32],
                      policy_hash: [u8; 32],
                      run_hash: [u8; 32]|
     -> io::Result<EvidenceFinal> {
        let pk_len_off = prefix_len;
        let pk_len_end = pk_len_off.saturating_add(2);
        let pk_len_bytes = payload.get(pk_len_off..pk_len_end).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "EvidenceFinal public key length out of bounds",
            )
        })?;
        let pk_len = u16::from_le_bytes([pk_len_bytes[0], pk_len_bytes[1]]) as usize;

        let pk_start = pk_len_end;
        let pk_end = pk_start.saturating_add(pk_len);
        if pk_end + 2 > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "EvidenceFinal public key length out of bounds",
            ));
        }

        let sig_len_bytes = &payload[pk_end..pk_end + 2];
        let sig_len = u16::from_le_bytes([sig_len_bytes[0], sig_len_bytes[1]]) as usize;
        let sig_start = pk_end + 2;
        let sig_end = sig_start.saturating_add(sig_len);
        if sig_end > payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "EvidenceFinal signature length mismatch",
            ));
        }

        let public_key_b64 = std::str::from_utf8(&payload[pk_start..pk_end])
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("EvidenceFinal public key utf8: {}", e),
                )
            })?
            .to_string();

        let signature_b64 = std::str::from_utf8(&payload[sig_start..sig_end])
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("EvidenceFinal signature utf8: {}", e),
                )
            })?
            .to_string();

        let provider_id = if sig_end == payload.len() {
            identity::FILE_IDENTITY_PROVIDER_ID.to_string()
        } else {
            if sig_end + 2 > payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EvidenceFinal provider_id length out of bounds",
                ));
            }
            let provider_len =
                u16::from_le_bytes([payload[sig_end], payload[sig_end + 1]]) as usize;
            let provider_start = sig_end + 2;
            let provider_end = provider_start.saturating_add(provider_len);
            if provider_end != payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EvidenceFinal provider_id length mismatch",
                ));
            }
            std::str::from_utf8(&payload[provider_start..provider_end])
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("EvidenceFinal provider_id utf8: {}", e),
                    )
                })?
                .to_string()
        };

        Ok(EvidenceFinal {
            version,
            agent_id,
            source_hash,
            codegen_hash,
            policy_hash,
            run_hash,
            public_key_b64,
            signature_b64,
            provider_id,
        })
    };

    if payload.len() >= V081_FIXED + 2 + 2 {
        let format = read_u32(0, "format")?;
        let hash_alg = read_u32(4, "hash_alg")?;
        let sig_alg = read_u32(8, "sig_alg")?;
        if hash_alg == 1 && sig_alg == 1 {
            if format != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported evidence format: {}", format),
                ));
            }

            let agent_id = read_u32(12, "agent_id")?;

            let mut source_hash = [0u8; 32];
            source_hash.copy_from_slice(payload.get(16..48).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EvidenceFinal source_hash out of bounds",
                )
            })?);

            let mut codegen_hash = [0u8; 32];
            codegen_hash.copy_from_slice(payload.get(48..80).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EvidenceFinal codegen_hash out of bounds",
                )
            })?);

            let mut policy_hash = [0u8; 32];
            policy_hash.copy_from_slice(payload.get(80..112).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EvidenceFinal policy_hash out of bounds",
                )
            })?);

            let mut run_hash = [0u8; 32];
            run_hash.copy_from_slice(payload.get(112..144).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "EvidenceFinal run_hash out of bounds",
                )
            })?);

            return parse_tail(
                V081_FIXED,
                EvidenceVersion {
                    format,
                    hash_alg,
                    sig_alg,
                },
                agent_id,
                source_hash,
                codegen_hash,
                policy_hash,
                run_hash,
            );
        }
    }

    let mut source_hash = [0u8; 32];
    source_hash.copy_from_slice(payload.get(4..36).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "EvidenceFinal source_hash out of bounds",
        )
    })?);

    let mut codegen_hash = [0u8; 32];
    codegen_hash.copy_from_slice(payload.get(36..68).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "EvidenceFinal codegen_hash out of bounds",
        )
    })?);

    let mut policy_hash = [0u8; 32];
    policy_hash.copy_from_slice(payload.get(68..100).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "EvidenceFinal policy_hash out of bounds",
        )
    })?);

    let mut run_hash = [0u8; 32];
    run_hash.copy_from_slice(payload.get(100..132).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "EvidenceFinal run_hash out of bounds",
        )
    })?);

    parse_tail(
        LEGACY_FIXED,
        EvidenceVersion {
            format: 0,
            hash_alg: 1,
            sig_alg: 1,
        },
        read_u32(0, "agent_id")?,
        source_hash,
        codegen_hash,
        policy_hash,
        run_hash,
    )
}

fn decode_task_finished(payload: &[u8]) -> io::Result<TaskFinished> {
    require_len(payload, 4, "TaskFinished")?;
    Ok(TaskFinished {
        exit_code: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
    })
}

fn decode_task_cancelled(payload: &[u8]) -> io::Result<TaskCancelled> {
    require_len(payload, 4, "TaskCancelled")?;
    Ok(TaskCancelled {
        reason_code: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
    })
}

fn decode_task_joined(payload: &[u8]) -> io::Result<TaskJoined> {
    require_len(payload, 8, "TaskJoined")?;
    Ok(TaskJoined {
        joined_task: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
    })
}

fn decode_sched_init(payload: &[u8]) -> io::Result<SchedInit> {
    require_len(payload, 8, "SchedInit")?;
    Ok(SchedInit {
        tick0: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
    })
}

fn decode_sched_state(payload: &[u8]) -> io::Result<SchedStatePayload> {
    require_len(payload, 10, "SchedState")?;
    let from = SchedState::from_u8(payload[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid SchedState.from {}", payload[0]),
        )
    })?;
    let to = SchedState::from_u8(payload[1]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid SchedState.to {}", payload[1]),
        )
    })?;
    Ok(SchedStatePayload {
        from,
        to,
        tick: u64::from_le_bytes(payload[2..10].try_into().unwrap()),
    })
}

fn decode_tick_start(payload: &[u8]) -> io::Result<TickStart> {
    require_len(payload, 8, "TickStart")?;
    Ok(TickStart {
        tick: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
    })
}

fn decode_tick_end(payload: &[u8]) -> io::Result<TickEnd> {
    require_len(payload, 16, "TickEnd")?;
    Ok(TickEnd {
        tick: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        runnable: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        blocked: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
    })
}

fn decode_pick_task(payload: &[u8]) -> io::Result<PickTask> {
    if payload.len() < 14 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("PickTask payload too short: {}", payload.len()),
        ));
    }

    let tick = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let task_id = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let reason_len = u16::from_le_bytes(payload[12..14].try_into().unwrap()) as usize;
    if payload.len() != 14 + reason_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "PickTask payload length mismatch: expected {}, got {}",
                14 + reason_len,
                payload.len()
            ),
        ));
    }

    let reason = std::str::from_utf8(&payload[14..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("PickTask utf8: {}", e)))?
        .to_string();

    Ok(PickTask {
        tick,
        task_id,
        reason,
    })
}

fn decode_yield(payload: &[u8]) -> io::Result<YieldPayload> {
    require_len(payload, 13, "Yield")?;
    let kind = YieldKind::from_u8(payload[12]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid YieldKind {}", payload[12]),
        )
    })?;
    Ok(YieldPayload {
        tick: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        task_id: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        kind,
    })
}

fn decode_fuel_debit(payload: &[u8]) -> io::Result<FuelDebit> {
    require_len(payload, 17, "FuelDebit")?;
    let reason = FuelReason::from_u8(payload[16]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid FuelReason {}", payload[16]),
        )
    })?;
    Ok(FuelDebit {
        tick: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        task_id: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        amount: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
        reason,
    })
}

fn decode_io_begin(payload: &[u8]) -> io::Result<u64> {
    require_len(payload, 8, "IoBegin")?;
    Ok(u64::from_le_bytes(payload[0..8].try_into().unwrap()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JsonIoRequest {
    req_id: u64,
    kind: IoKind,
    path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct JsonIoDecision {
    req_id: u64,
    allowed: bool,
    reason_code: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct JsonIoResult {
    req_id: u64,
    success: bool,
    size: u64,
    code: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JsonIoPayload {
    req_id: u64,
    hash64: u64,
    size: u64,
    bytes: Option<Vec<u8>>,
}

fn decode_io_request(payload: &[u8]) -> io::Result<JsonIoRequest> {
    if payload.len() >= 11 {
        let req_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let maybe_kind = IoKind::from_u8(payload[8]);
        if let Some(kind) = maybe_kind {
            let path_len = u16::from_le_bytes(payload[9..11].try_into().unwrap()) as usize;
            if payload.len() == 11 + path_len {
                let path = std::str::from_utf8(&payload[11..])
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("IoRequest.path: {}", e))
                    })?
                    .to_string();
                return Ok(JsonIoRequest { req_id, kind, path });
            }
        }
    }

    if payload.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IoRequest payload too short: {}", payload.len()),
        ));
    }

    let kind = IoKind::from_u8(payload[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid IoRequest.kind {}", payload[0]),
        )
    })?;
    let path_len = u16::from_le_bytes(payload[1..3].try_into().unwrap()) as usize;
    if payload.len() != 3 + path_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "IoRequest payload length mismatch: expected {}, got {}",
                3 + path_len,
                payload.len()
            ),
        ));
    }

    let path = std::str::from_utf8(&payload[3..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("IoRequest.path: {}", e)))?
        .to_string();

    Ok(JsonIoRequest {
        req_id: 0,
        kind,
        path,
    })
}

fn decode_io_decision(payload: &[u8]) -> io::Result<JsonIoDecision> {
    if payload.len() == 13 {
        let req_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let allowed = match payload[8] {
            0 => false,
            1 => true,
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid IoDecision.allowed {}", v),
                ));
            }
        };
        let reason_code = u32::from_le_bytes(payload[9..13].try_into().unwrap());
        return Ok(JsonIoDecision {
            req_id,
            allowed,
            reason_code,
        });
    }

    require_len(payload, 1, "IoDecision")?;
    match payload[0] {
        0 => Ok(JsonIoDecision {
            req_id: 0,
            allowed: false,
            reason_code: 0,
        }),
        1 => Ok(JsonIoDecision {
            req_id: 0,
            allowed: true,
            reason_code: 0,
        }),
        v => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid IoDecision.allowed {}", v),
        )),
    }
}

fn decode_io_result(payload: &[u8]) -> io::Result<JsonIoResult> {
    if payload.len() == 18 {
        let req_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let success = match payload[8] {
            0 => false,
            1 => true,
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid IoResult.success {}", v),
                ));
            }
        };
        let size = u64::from_le_bytes(payload[9..17].try_into().unwrap());
        let code = if payload[17] == u8::MAX {
            None
        } else {
            Some(payload[17])
        };
        return Ok(JsonIoResult {
            req_id,
            success,
            size,
            code,
        });
    }

    if payload.len() == 17 {
        let req_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let success = match payload[8] {
            0 => false,
            1 => true,
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid IoResult.success {}", v),
                ));
            }
        };
        let size = u64::from_le_bytes(payload[9..17].try_into().unwrap());
        return Ok(JsonIoResult {
            req_id,
            success,
            size,
            code: None,
        });
    }

    require_len(payload, 9, "IoResult")?;
    let success = match payload[0] {
        0 => false,
        1 => true,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid IoResult.success {}", v),
            ));
        }
    };
    Ok(JsonIoResult {
        req_id: 0,
        success,
        size: u64::from_le_bytes(payload[1..9].try_into().unwrap()),
        code: None,
    })
}

fn decode_io_payload(payload: &[u8]) -> io::Result<JsonIoPayload> {
    if payload.len() >= 25 {
        let req_id = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let hash64 = u64::from_le_bytes(payload[8..16].try_into().unwrap());
        let size = u64::from_le_bytes(payload[16..24].try_into().unwrap());
        let has_bytes = payload[24];
        if has_bytes == 0 && payload.len() == 25 {
            return Ok(JsonIoPayload {
                req_id,
                hash64,
                size,
                bytes: None,
            });
        }
        if has_bytes == 1 && payload.len() >= 29 {
            let len = u32::from_le_bytes(payload[25..29].try_into().unwrap()) as usize;
            if payload.len() == 29 + len {
                return Ok(JsonIoPayload {
                    req_id,
                    hash64,
                    size,
                    bytes: Some(payload[29..].to_vec()),
                });
            }
        }
    }

    if payload.len() < 17 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("IoPayload payload too short: {}", payload.len()),
        ));
    }
    let hash64 = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let size = u64::from_le_bytes(payload[8..16].try_into().unwrap());
    let has_bytes = payload[16];
    match has_bytes {
        0 => {
            if payload.len() != 17 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "IoPayload payload length mismatch: expected 17, got {}",
                        payload.len()
                    ),
                ));
            }
            Ok(JsonIoPayload {
                req_id: 0,
                hash64,
                size,
                bytes: None,
            })
        }
        1 => {
            if payload.len() < 21 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("IoPayload bytes payload too short: {}", payload.len()),
                ));
            }
            let len = u32::from_le_bytes(payload[17..21].try_into().unwrap()) as usize;
            if payload.len() != 21 + len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "IoPayload bytes length mismatch: expected {}, got {}",
                        21 + len,
                        payload.len()
                    ),
                ));
            }
            Ok(JsonIoPayload {
                req_id: 0,
                hash64,
                size,
                bytes: Some(payload[21..].to_vec()),
            })
        }
        v => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid IoPayload.has_bytes {}", v),
        )),
    }
}

fn decode_bus_send(payload: &[u8]) -> io::Result<BusSend> {
    require_len(payload, 30, "BusSend")?;
    Ok(BusSend {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        sender: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        receiver: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
        kind: u16::from_le_bytes(payload[16..18].try_into().unwrap()),
        payload_len: u32::from_le_bytes(payload[18..22].try_into().unwrap()),
        payload_hash64: u64::from_le_bytes(payload[22..30].try_into().unwrap()),
    })
}

fn decode_bus_recv(payload: &[u8]) -> io::Result<BusRecv> {
    require_len(payload, 12, "BusRecv")?;
    Ok(BusRecv {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        receiver: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
    })
}

fn decode_bus_send_request(payload: &[u8]) -> io::Result<BusSendRequest> {
    require_len(payload, 24, "BusSendRequest")?;
    Ok(BusSendRequest {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        sender: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        receiver: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
        schema_id: u32::from_le_bytes(payload[16..20].try_into().unwrap()),
        bytes: u32::from_le_bytes(payload[20..24].try_into().unwrap()),
    })
}

fn decode_bus_decision(payload: &[u8]) -> io::Result<BusDecision> {
    require_len(payload, 13, "BusDecision")?;
    let allowed = match payload[8] {
        0 => false,
        1 => true,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid BusDecision.allowed {}", v),
            ));
        }
    };
    Ok(BusDecision {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        allowed,
        reason_code: u32::from_le_bytes(payload[9..13].try_into().unwrap()),
    })
}

fn decode_bus_send_result(payload: &[u8]) -> io::Result<BusSendResult> {
    require_len(payload, 9, "BusSendResult")?;
    let ok = match payload[8] {
        0 => false,
        1 => true,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid BusSendResult.ok {}", v),
            ));
        }
    };
    Ok(BusSendResult {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        ok,
    })
}

fn decode_channel_created(payload: &[u8]) -> io::Result<ChannelCreated> {
    require_len(payload, 32, "ChannelCreated")?;
    Ok(ChannelCreated {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        channel_id: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
        schema_id: u64::from_le_bytes(payload[16..24].try_into().unwrap()),
        limits_digest: u64::from_le_bytes(payload[24..32].try_into().unwrap()),
    })
}

fn decode_channel_closed(payload: &[u8]) -> io::Result<ChannelClosed> {
    require_len(payload, 16, "ChannelClosed")?;
    Ok(ChannelClosed {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        channel_id: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    })
}

fn decode_message_sent(payload: &[u8]) -> io::Result<MessageSent> {
    require_len(payload, 48, "MessageSent")?;
    Ok(MessageSent {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        channel_id: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
        sender_id: u32::from_le_bytes(payload[16..20].try_into().unwrap()),
        sender_seq: u64::from_le_bytes(payload[20..28].try_into().unwrap()),
        schema_id: u64::from_le_bytes(payload[28..36].try_into().unwrap()),
        hash64: u64::from_le_bytes(payload[36..44].try_into().unwrap()),
        size: u32::from_le_bytes(payload[44..48].try_into().unwrap()),
    })
}

fn decode_message_delivered(payload: &[u8]) -> io::Result<MessageDelivered> {
    require_len(payload, 44, "MessageDelivered")?;
    Ok(MessageDelivered {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        channel_id: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
        receiver_id: u32::from_le_bytes(payload[16..20].try_into().unwrap()),
        sender_id: u32::from_le_bytes(payload[20..24].try_into().unwrap()),
        sender_seq: u64::from_le_bytes(payload[24..32].try_into().unwrap()),
        hash64: u64::from_le_bytes(payload[32..40].try_into().unwrap()),
        size: u32::from_le_bytes(payload[40..44].try_into().unwrap()),
    })
}

fn decode_message_blocked(payload: &[u8]) -> io::Result<MessageBlocked> {
    require_len(payload, 20, "MessageBlocked")?;
    Ok(MessageBlocked {
        req_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        channel_id: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
        receiver_id: u32::from_le_bytes(payload[16..20].try_into().unwrap()),
    })
}

fn decode_deadlock_detected(payload: &[u8]) -> io::Result<DeadlockDetected> {
    require_len(payload, 13, "DeadlockDetected")?;
    Ok(DeadlockDetected {
        tick: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        blocked: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        kind: payload[12],
    })
}

fn decode_deadlock_edge(payload: &[u8]) -> io::Result<DeadlockEdge> {
    require_len(payload, 9, "DeadlockEdge")?;
    Ok(DeadlockEdge {
        from: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
        to: u32::from_le_bytes(payload[4..8].try_into().unwrap()),
        reason: payload[8],
    })
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1F}' => {
                let _ = std::fmt::Write::write_fmt(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}
