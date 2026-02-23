// src/runtime/event.rs
//
// Deterministic, stable event format for NEX v0.5.x.
//
// Hard invariants supported here:
// - I5 Deterministic codegen/runtime: explicit little-endian encoding.
// - I9 Append-only logs: format is strictly sequential.
// - No timestamps, no RNG, no usize/isize, no floats.
//
// NOTE: This module defines the *binary canonical* representation. JSONL is a view-layer sink later.

#![allow(dead_code)]

use core::fmt;

/// Binary log file magic (4 bytes).
pub const EVENT_MAGIC: [u8; 4] = *b"NEXE";

/// Binary log format version.
/// Bump only with a migration plan; treat as stable wire format.
pub const EVENT_VERSION: u16 = 1;

/// Event kind tags are stable numeric values.
/// Do not reorder; only append new variants with new numeric tags.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    TaskSpawned = 1,
    CapabilityInvoked = 2,
    FuelExhausted = 3,
    ResourceViolation = 4,
    RunFinished = 5,
}

impl EventKind {
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EventKind::TaskSpawned => "TaskSpawned",
            EventKind::CapabilityInvoked => "CapabilityInvoked",
            EventKind::FuelExhausted => "FuelExhausted",
            EventKind::ResourceViolation => "ResourceViolation",
            EventKind::RunFinished => "RunFinished",
        };
        f.write_str(s)
    }
}

/// Fixed-size, deterministic header.
/// All fields are little-endian on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventHeader {
    pub seq: u64,
    pub task_id: u64,
    pub kind: EventKind,
    pub payload_len: u32,
}

impl EventHeader {
    /// Size of the encoded header in bytes.
    pub const ENCODED_LEN: usize = 8 + 8 + 2 + 4;

    #[inline]
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        let mut i = 0;

        out[i..i + 8].copy_from_slice(&self.seq.to_le_bytes());
        i += 8;

        out[i..i + 8].copy_from_slice(&self.task_id.to_le_bytes());
        i += 8;

        out[i..i + 2].copy_from_slice(&self.kind.as_u16().to_le_bytes());
        i += 2;

        out[i..i + 4].copy_from_slice(&self.payload_len.to_le_bytes());
        // i += 4;

        out
    }
}

/// A small helper trait for deterministic binary encoding.
/// We deliberately avoid serde here to prevent accidental nondeterminism (maps, key order, etc.).
pub trait EncodeLE {
    /// Encoded payload length in bytes.
    fn encoded_len(&self) -> usize;

    /// Encode into `dst`. Must write exactly `encoded_len()` bytes.
    fn encode_le(&self, dst: &mut Vec<u8>);

    #[inline]
    fn to_bytes_le(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.encoded_len());
        self.encode_le(&mut v);
        debug_assert_eq!(v.len(), self.encoded_len());
        v
    }
}

/// Payload: TaskSpawned
/// Deterministic fields only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskSpawned {
    pub parent: u64,
    pub child: u64,
}

impl EncodeLE for TaskSpawned {
    #[inline]
    fn encoded_len(&self) -> usize {
        8 + 8
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.parent.to_le_bytes());
        dst.extend_from_slice(&self.child.to_le_bytes());
    }
}

/// Capability type tags (stable).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityKind {
    FsRead = 1,
    NetListen = 2,
}

impl CapabilityKind {
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Payload: CapabilityInvoked
///
/// `args_digest` is a fixed 32-byte digest of deterministic inputs (e.g., normalized path bytes).
/// This avoids embedding variable-length strings in the binary log (good for speed + stability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityInvoked {
    pub cap_kind: CapabilityKind,
    pub cap_id: u32,
    pub args_digest: [u8; 32],
}

impl EncodeLE for CapabilityInvoked {
    #[inline]
    fn encoded_len(&self) -> usize {
        2 + 4 + 32
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.cap_kind.as_u16().to_le_bytes());
        dst.extend_from_slice(&self.cap_id.to_le_bytes());
        dst.extend_from_slice(&self.args_digest);
    }
}

/// Payload: FuelExhausted
///
/// `budget_before` and `cost` are included so we can reconstruct policy behavior during replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuelExhausted {
    pub budget_before: u64,
    pub cost: u64,
}

impl EncodeLE for FuelExhausted {
    #[inline]
    fn encoded_len(&self) -> usize {
        8 + 8
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.budget_before.to_le_bytes());
        dst.extend_from_slice(&self.cost.to_le_bytes());
    }
}

/// Payload: ResourceViolation
///
/// Keep this compact. `violation_code` is a stable numeric policy ID.
/// Optional detail is a fixed digest (e.g., capability/path digest, rule digest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceViolation {
    pub violation_code: u32,
    pub detail_digest: [u8; 32],
}

impl EncodeLE for ResourceViolation {
    #[inline]
    fn encoded_len(&self) -> usize {
        4 + 32
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.violation_code.to_le_bytes());
        dst.extend_from_slice(&self.detail_digest);
    }
}

/// Payload: RunFinished
///
/// IMPORTANT: In v0.5, we define `run_hash` as the SHA-256 over the event byte stream
/// *up to but excluding* the RunFinished event. This allows stable comparison:
/// `replay_hash == original_hash`.
///
/// The RunFinished event itself is still appended (I9), but it is not part of the hash it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunFinished {
    pub exit_code: i32,
    pub run_hash_excluding_finish: [u8; 32],
}

impl EncodeLE for RunFinished {
    #[inline]
    fn encoded_len(&self) -> usize {
        4 + 32
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.exit_code.to_le_bytes());
        dst.extend_from_slice(&self.run_hash_excluding_finish);
    }
}