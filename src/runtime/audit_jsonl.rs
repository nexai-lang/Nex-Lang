use crate::runtime::task_context::{AuditEvent, AuditSink, ResourceViolationKind, TaskId};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::Mutex;

/// Minimal JSONL writer.
/// Thread-safe via Mutex; later we can switch to a channel-based logger if needed.
pub struct JsonlAudit {
    writer: Mutex<BufWriter<std::fs::File>>,
}

impl JsonlAudit {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(f)),
        })
    }

    fn write_line(&self, line: &str) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
            let _ = w.flush();
        }
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn kind_str(k: &ResourceViolationKind) -> &'static str {
    match k {
        ResourceViolationKind::FuelExhausted => "FuelExhausted",
        ResourceViolationKind::MemoryExceeded => "MemoryExceeded",
    }
}

fn json_u64(v: u64) -> String {
    v.to_string()
}

fn json_str(v: &str) -> String {
    format!("\"{}\"", esc(v))
}

fn emit_spawned(parent: TaskId, child: TaskId) -> String {
    format!(
        "{{\"type\":\"TaskSpawned\",\"parent\":{},\"child\":{}}}",
        json_u64(parent),
        json_u64(child)
    )
}

fn emit_cap(task: TaskId, capability: &str, target: &str) -> String {
    format!(
        "{{\"type\":\"CapabilityInvoked\",\"task\":{},\"capability\":{},\"target\":{}}}",
        json_u64(task),
        json_str(capability),
        json_str(target)
    )
}

fn emit_violation(task: TaskId, kind: &ResourceViolationKind, detail: &str) -> String {
    format!(
        "{{\"type\":\"ResourceViolation\",\"task\":{},\"kind\":{},\"detail\":{}}}",
        json_u64(task),
        json_str(kind_str(kind)),
        json_str(detail)
    )
}

impl AuditSink for JsonlAudit {
    fn emit(&self, event: AuditEvent) {
        let line = match event {
            AuditEvent::TaskSpawned { parent, child } => emit_spawned(parent, child),
            AuditEvent::CapabilityInvoked {
                task,
                capability,
                target,
            } => emit_cap(task, &capability, &target),
            AuditEvent::ResourceViolation { task, kind, detail } => {
                emit_violation(task, &kind, &detail)
            }
        };

        self.write_line(&line);
    }
}
