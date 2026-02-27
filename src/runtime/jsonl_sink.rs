// src/runtime/jsonl_sink.rs
//
// Deterministic JSONL sink for canonical binary events.
// View-layer only. Does NOT affect hashing.

use crate::runtime::event::*;
use crate::runtime::event_sink::EventSink;
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
