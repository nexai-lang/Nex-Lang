// src/runtime/audit_jsonl.rs
//
// v0.5.7.1 — AuditSink routing to canonical binary event log.
// Deterministic: no timestamps, no RNG, no serde.

use crate::runtime::event::{CapabilityInvoked, CapabilityKind};
use crate::runtime::event_recorder::recorder;
use crate::runtime::task_context::{AuditEvent, AuditSink, ResourceViolationKind};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::sync::Mutex;

/// Stable violation code assignments (must match src/replay.rs).
pub const VIOL_FUEL_EXHAUSTED: u32 = 1;
pub const VIOL_MEMORY_EXCEEDED: u32 = 2;
pub const VIOL_CAPABILITY_DENIED: u32 = 3;

/// Back-compat type: historically wrote JSONL; kept to preserve codegen API.
/// We still open/touch the file path so the artifact exists inside NEX_OUT_DIR (I6).
pub struct JsonlAudit {
    _writer: Mutex<BufWriter<std::fs::File>>,
}

impl JsonlAudit {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            _writer: Mutex::new(BufWriter::new(f)),
        })
    }

    #[allow(dead_code)]
    fn touch_line(&self, line: &str) {
        if let Ok(mut w) = self._writer.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
            let _ = w.flush();
        }
    }
}

impl AuditSink for JsonlAudit {
    fn emit(&self, event: AuditEvent) {
        let rec = recorder();
        let mut rec = rec.lock().expect("EventRecorder lock poisoned");

        match event {
            AuditEvent::TaskSpawned { parent, child } => {
                rec.record_task_spawned(parent as u64, child as u64)
                    .unwrap_or_else(|e| panic!("audit binary write failed (TaskSpawned): {e}"));
            }

            AuditEvent::CapabilityInvoked {
                task,
                capability,
                target,
            } => {
                let (cap_kind, cap_id, args_digest) = digest_capability(&capability, &target);
                let payload = CapabilityInvoked {
                    cap_kind,
                    cap_id,
                    args_digest,
                };

                rec.record_capability_invoked(task as u64, payload)
                    .unwrap_or_else(|e| {
                        panic!("audit binary write failed (CapabilityInvoked): {e}")
                    });
            }

            AuditEvent::ResourceViolation { task, kind, detail } => {
                let violation_code = violation_code(&kind);
                let detail_digest = digest_detail(&detail);

                rec.record_resource_violation(task as u64, violation_code, detail_digest)
                    .unwrap_or_else(|e| {
                        panic!("audit binary write failed (ResourceViolation): {e}")
                    });
            }
        }
    }
}

#[inline]
fn violation_code(kind: &ResourceViolationKind) -> u32 {
    match kind {
        ResourceViolationKind::FuelExhausted => VIOL_FUEL_EXHAUSTED,
        ResourceViolationKind::MemoryExceeded => VIOL_MEMORY_EXCEEDED,
        ResourceViolationKind::CapabilityDenied => VIOL_CAPABILITY_DENIED,
    }
}

#[inline]
fn digest_detail(detail: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(detail.as_bytes());
    h.finalize().into()
}

/// Deterministically derive (cap_kind, cap_id, args_digest) from (capability, target).
///
/// - cap_kind: stable enum (FsRead / NetListen).
/// - cap_id: derived from args_digest low 4 bytes (LE).
/// - args_digest: SHA-256 over: b"cap\0" + capability + b"\0" + target
#[inline]
fn digest_capability(capability: &str, target: &str) -> (CapabilityKind, u32, [u8; 32]) {
    let cap_kind = if capability.starts_with("fs.read") {
        CapabilityKind::FsRead
    } else if capability.starts_with("net.listen") {
        CapabilityKind::NetListen
    } else {
        // Deterministic fallback: pick FsRead (do NOT invent new enum variants).
        CapabilityKind::FsRead
    };

    let mut h = Sha256::new();
    h.update(b"cap\0");
    h.update(capability.as_bytes());
    h.update(b"\0");
    h.update(target.as_bytes());
    let digest: [u8; 32] = h.finalize().into();

    let cap_id = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (cap_kind, cap_id, digest)
}
