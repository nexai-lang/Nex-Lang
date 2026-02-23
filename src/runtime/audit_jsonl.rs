// src/runtime/audit_jsonl.rs
//
// v0.5 Step 2 wiring:
// This module is intentionally kept (API compatibility), but all audit emission
// is routed to the canonical binary EventRecorder (NO JSONL writing).
//
// Hard invariants:
// - I9 append-only is enforced by EventRecorder (binary log)
// - determinism: all digests are SHA-256 over UTF-8 bytes with fixed separators
// - no timestamps, no usize, no floats
//
// NOTE: Step 3 will reintroduce JSONL as a fan-out sink *from* the recorder.
// For now: binary-only.

use crate::runtime::event::{CapabilityInvoked, CapabilityKind};
use crate::runtime::event_recorder::recorder;
use crate::runtime::task_context::{AuditEvent, AuditSink, ResourceViolationKind};

use sha2::{Digest, Sha256};

/// Backwards-compatible sink type.
///
/// `new(path)` is retained so existing code compiles unchanged, but `path` is
/// currently ignored because binary logging is canonical in v0.5.
pub struct JsonlAudit;

impl JsonlAudit {
    #[allow(unused_variables)]
    pub fn new(path: &str) -> std::io::Result<Self> {
        // Intentionally do NOT create/write the JSONL file in v0.5 Step 2.
        // JSONL returns later as a sink adapter in Step 3.
        Ok(Self)
    }
}

/// Stable mapping from ResourceViolationKind to a numeric violation code.
/// These codes become part of the binary log contract; only append new codes.
fn violation_code(kind: &ResourceViolationKind) -> u32 {
    match kind {
        ResourceViolationKind::FuelExhausted => 1,
        ResourceViolationKind::MemoryExceeded => 2,
    }
}

/// Deterministically infer capability kind from the capability string.
/// This is a temporary bridge while older AuditEvent carries strings.
///
/// If unknown, we default to FsRead (safe, non-escalating) but keep determinism.
/// In Step 3+ we’ll prefer structured capability IDs from the runtime policy layer.
fn infer_cap_kind(capability: &str) -> CapabilityKind {
    // Keep this logic strict and deterministic (no locale, no regex).
    // Use exact substring checks to avoid surprises.
    if capability.contains("net.listen") {
        CapabilityKind::NetListen
    } else {
        CapabilityKind::FsRead
    }
}

/// Deterministically derive a u32 capability ID from the capability string.
/// This is stable across runs and machines.
fn cap_id_from_str(capability: &str) -> u32 {
    let mut h = Sha256::new();
    h.update(capability.as_bytes());
    let digest = h.finalize();
    // First 4 bytes interpreted as LE u32 (explicit, deterministic).
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Deterministically hash (capability, target) for args digest.
/// Separator 0x00 ensures unambiguous concatenation.
fn args_digest_for_cap(capability: &str, target: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(capability.as_bytes());
    h.update([0u8]);
    h.update(target.as_bytes());
    let digest = h.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

/// Deterministically hash a detail string into a fixed digest.
fn detail_digest(detail: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(detail.as_bytes());
    let digest = h.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..]);
    out
}

impl AuditSink for JsonlAudit {
    fn emit(&self, event: AuditEvent) {
        // IMPORTANT: do not panic on lock poisoning; audit must be best-effort
        // only if the recorder itself is healthy. If the mutex is poisoned,
        // continuing may violate append-only expectations, so we conservatively drop.
        let Ok(mut rec) = recorder().lock() else {
            return;
        };

        // Best-effort logging: swallow IO errors here to avoid cascading failures
        // from audit paths. Policy enforcement should still panic/terminate where required.
        // (If you want “audit failure is fatal”, we can flip this later.)
        let _ = match event {
            AuditEvent::TaskSpawned { parent, child } => rec.record_task_spawned(parent as u64, child as u64),

            AuditEvent::CapabilityInvoked {
                task,
                capability,
                target,
            } => {
                let cap_kind = infer_cap_kind(&capability);
                let cap_id = cap_id_from_str(&capability);
                let args_digest = args_digest_for_cap(&capability, &target);

                let payload = CapabilityInvoked {
                    cap_kind,
                    cap_id,
                    args_digest,
                };

                rec.record_capability_invoked(task as u64, payload)
            }

            AuditEvent::ResourceViolation { task, kind, detail } => {
                let code = violation_code(&kind);
                let digest = detail_digest(&detail);
                rec.record_resource_violation(task as u64, code, digest)
            }
        };
    }
}