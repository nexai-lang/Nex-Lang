// src/runtime/jsonl_sink.rs
//
// Deterministic JSONL sink for canonical binary events.
// View-layer only. Does NOT affect hashing.
//
// Compatible with EventSink trait:
//   fn on_event(&mut self, header: &EventHeader, payload: &[u8]) -> io::Result<()>
//   fn flush(&mut self) -> io::Result<()>

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
        let f = OpenOptions::new().create(true).append(true).open(path)?;
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
    let base = format!(
        r#"{{"seq":{},"task":{},"kind":{},"#,
        header.seq,
        header.task_id,
        header.kind.as_u16()
    );

    let tail = match header.kind {
        EventKind::TaskSpawned => {
            let p = decode_task_spawned(payload)?;
            format!(r#""parent":{},"child":{}}}"#, p.parent, p.child)
        }

        EventKind::CapabilityInvoked => {
            let p = decode_capability_invoked(payload)?;
            format!(
                r#""cap_kind":{},"cap_id":{},"args_digest":"{}"}}"#,
                p.cap_kind.as_u16(),
                p.cap_id,
                hex::encode(p.args_digest)
            )
        }

        EventKind::FuelExhausted => {
            let p = decode_fuel_exhausted(payload)?;
            format!(r#""budget_before":{},"cost":{}}}"#, p.budget_before, p.cost)
        }

        EventKind::ResourceViolation => {
            let p = decode_resource_violation(payload)?;
            format!(
                r#""violation_code":{},"detail_digest":"{}"}}"#,
                p.violation_code,
                hex::encode(p.detail_digest)
            )
        }

        EventKind::RunFinished => {
            let p = decode_run_finished(payload)?;
            format!(
                r#""exit_code":{},"run_hash":"{}"}}"#,
                p.exit_code,
                hex::encode(p.run_hash_excluding_finish)
            )
        }

        // -------- Path B lifecycle --------
        EventKind::TaskStarted => "}".to_string(),

        EventKind::TaskFinished => {
            let p = decode_task_finished(payload)?;
            format!(r#""exit_code":{}}}"#, p.exit_code)
        }

        EventKind::TaskCancelled => {
            let p = decode_task_cancelled(payload)?;
            format!(r#""reason_code":{}}}"#, p.reason_code)
        }

        EventKind::TaskJoined => {
            let p = decode_task_joined(payload)?;
            format!(r#""joined_task":{}}}"#, p.joined_task)
        }
    };

    Ok(format!("{}{}", base, tail))
}

// ----------------- Decoders -----------------

fn decode_task_spawned(payload: &[u8]) -> io::Result<TaskSpawned> {
    Ok(TaskSpawned {
        parent: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        child: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    })
}

fn decode_capability_invoked(payload: &[u8]) -> io::Result<CapabilityInvoked> {
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
    Ok(FuelExhausted {
        budget_before: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        cost: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    })
}

fn decode_resource_violation(payload: &[u8]) -> io::Result<ResourceViolation> {
    Ok(ResourceViolation {
        violation_code: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
        detail_digest: payload[4..36].try_into().unwrap(),
    })
}

fn decode_run_finished(payload: &[u8]) -> io::Result<RunFinished> {
    Ok(RunFinished {
        exit_code: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
        run_hash_excluding_finish: payload[4..36].try_into().unwrap(),
    })
}

fn decode_task_finished(payload: &[u8]) -> io::Result<TaskFinished> {
    Ok(TaskFinished {
        exit_code: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
    })
}

fn decode_task_cancelled(payload: &[u8]) -> io::Result<TaskCancelled> {
    Ok(TaskCancelled {
        reason_code: u32::from_le_bytes(payload[0..4].try_into().unwrap()),
    })
}

fn decode_task_joined(payload: &[u8]) -> io::Result<TaskJoined> {
    Ok(TaskJoined {
        joined_task: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
    })
}
