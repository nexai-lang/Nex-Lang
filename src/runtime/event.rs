// src/runtime/event.rs
//
// Deterministic, stable event format for NEX.
//
// Hard invariants supported here:
// - I5 Deterministic runtime: explicit little-endian encoding.
// - I9 Append-only logs: strictly sequential.
// - No timestamps, no RNG, no usize/isize, no floats.
//
// Canonical wire format. JSONL is a view-layer sink later.

#![allow(dead_code)]

use crate::runtime::io_proxy::IoKind;
use core::fmt;

/// Binary log file magic (4 bytes).
pub const EVENT_MAGIC: [u8; 4] = *b"NEXL";

/// Binary log format version.
pub const EVENT_VERSION: u16 = 1;

/// Event kind tags are stable numeric values.
/// Never reorder; only append new variants with new numeric tags.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    // ---- existing core kinds ----
    TaskSpawned = 1,
    CapabilityInvoked = 2,
    FuelExhausted = 3,
    ResourceViolation = 4,

    // ---- lifecycle extensions ----
    TaskStarted = 6,
    TaskFinished = 7,
    TaskCancelled = 8,
    TaskJoined = 9,

    // ---- scheduler extensions (append-only) ----
    SchedInit = 10,
    SchedState = 11,
    TickStart = 12,
    TickEnd = 13,
    PickTask = 14,
    r#Yield = 15,
    FuelDebit = 16,
    IoRequest = 17,
    IoDecision = 18,
    IoResult = 19,
    IoPayload = 20,

    // ---- run framing ----
    RunStarted = 0xFFFE,
    RunFinished = 0xFFFF,
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
            EventKind::RunStarted => "RunStarted",
            EventKind::TaskSpawned => "TaskSpawned",
            EventKind::CapabilityInvoked => "CapabilityInvoked",
            EventKind::FuelExhausted => "FuelExhausted",
            EventKind::ResourceViolation => "ResourceViolation",
            EventKind::RunFinished => "RunFinished",
            EventKind::TaskStarted => "TaskStarted",
            EventKind::TaskFinished => "TaskFinished",
            EventKind::TaskCancelled => "TaskCancelled",
            EventKind::TaskJoined => "TaskJoined",
            EventKind::SchedInit => "SchedInit",
            EventKind::SchedState => "SchedState",
            EventKind::TickStart => "TickStart",
            EventKind::TickEnd => "TickEnd",
            EventKind::PickTask => "PickTask",
            EventKind::r#Yield => "Yield",
            EventKind::FuelDebit => "FuelDebit",
            EventKind::IoRequest => "IoRequest",
            EventKind::IoDecision => "IoDecision",
            EventKind::IoResult => "IoResult",
            EventKind::IoPayload => "IoPayload",
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
        out
    }
}

/// Deterministic binary encoding helper.
/// We avoid serde to prevent accidental nondeterminism.
pub trait EncodeLE {
    fn encoded_len(&self) -> usize;
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

/// Payload: TaskStarted (empty payload; presence is the signal).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskStarted;

impl EncodeLE for TaskStarted {
    #[inline]
    fn encoded_len(&self) -> usize {
        0
    }
    #[inline]
    fn encode_le(&self, _dst: &mut Vec<u8>) {}
}

/// Payload: TaskFinished
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskFinished {
    pub exit_code: i32,
}

impl EncodeLE for TaskFinished {
    #[inline]
    fn encoded_len(&self) -> usize {
        4
    }
    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.exit_code.to_le_bytes());
    }
}

/// Payload: TaskCancelled
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskCancelled {
    pub reason_code: u32,
}

impl EncodeLE for TaskCancelled {
    #[inline]
    fn encoded_len(&self) -> usize {
        4
    }
    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.reason_code.to_le_bytes());
    }
}

/// Payload: TaskJoined
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskJoined {
    pub joined_task: u64,
}

impl EncodeLE for TaskJoined {
    #[inline]
    fn encoded_len(&self) -> usize {
        8
    }
    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.joined_task.to_le_bytes());
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedState {
    Init = 0,
    Running = 1,
    Draining = 2,
    Finished = 3,
}

impl SchedState {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Init),
            1 => Some(Self::Running),
            2 => Some(Self::Draining),
            3 => Some(Self::Finished),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YieldKind {
    Voluntary = 0,
    JoinBlocked = 1,
    CancelBlocked = 2,
    FuelExhausted = 3,
}

impl YieldKind {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Voluntary),
            1 => Some(Self::JoinBlocked),
            2 => Some(Self::CancelBlocked),
            3 => Some(Self::FuelExhausted),
            _ => None,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuelReason {
    Tick = 0,
    Step = 1,
    Checkpoint = 2,
    ProxyCall = 3,
}

impl FuelReason {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Tick),
            1 => Some(Self::Step),
            2 => Some(Self::Checkpoint),
            3 => Some(Self::ProxyCall),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedInit {
    pub tick0: u64,
}

impl EncodeLE for SchedInit {
    #[inline]
    fn encoded_len(&self) -> usize {
        8
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.tick0.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedStatePayload {
    pub from: SchedState,
    pub to: SchedState,
    pub tick: u64,
}

impl EncodeLE for SchedStatePayload {
    #[inline]
    fn encoded_len(&self) -> usize {
        1 + 1 + 8
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.push(self.from.as_u8());
        dst.push(self.to.as_u8());
        dst.extend_from_slice(&self.tick.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickStart {
    pub tick: u64,
}

impl EncodeLE for TickStart {
    #[inline]
    fn encoded_len(&self) -> usize {
        8
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.tick.to_le_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickEnd {
    pub tick: u64,
    pub runnable: u32,
    pub blocked: u32,
}

impl EncodeLE for TickEnd {
    #[inline]
    fn encoded_len(&self) -> usize {
        8 + 4 + 4
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.tick.to_le_bytes());
        dst.extend_from_slice(&self.runnable.to_le_bytes());
        dst.extend_from_slice(&self.blocked.to_le_bytes());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickTask {
    pub tick: u64,
    pub task_id: u32,
    pub reason: String,
}

impl EncodeLE for PickTask {
    #[inline]
    fn encoded_len(&self) -> usize {
        let reason_bytes = self.reason.as_bytes();
        8 + 4 + 2 + reason_bytes.len()
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        let reason_bytes = self.reason.as_bytes();
        let reason_len = reason_bytes.len().min(u16::MAX as usize) as u16;

        dst.extend_from_slice(&self.tick.to_le_bytes());
        dst.extend_from_slice(&self.task_id.to_le_bytes());
        dst.extend_from_slice(&reason_len.to_le_bytes());
        dst.extend_from_slice(&reason_bytes[..reason_len as usize]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YieldPayload {
    pub tick: u64,
    pub task_id: u32,
    pub kind: YieldKind,
}

impl EncodeLE for YieldPayload {
    #[inline]
    fn encoded_len(&self) -> usize {
        8 + 4 + 1
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.tick.to_le_bytes());
        dst.extend_from_slice(&self.task_id.to_le_bytes());
        dst.push(self.kind.as_u8());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuelDebit {
    pub tick: u64,
    pub task_id: u32,
    pub amount: u32,
    pub reason: FuelReason,
}

impl EncodeLE for FuelDebit {
    #[inline]
    fn encoded_len(&self) -> usize {
        8 + 4 + 4 + 1
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.tick.to_le_bytes());
        dst.extend_from_slice(&self.task_id.to_le_bytes());
        dst.extend_from_slice(&self.amount.to_le_bytes());
        dst.push(self.reason.as_u8());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoRequest {
    pub kind: IoKind,
    pub path: String,
}

impl EncodeLE for IoRequest {
    #[inline]
    fn encoded_len(&self) -> usize {
        let bytes = self.path.as_bytes();
        1 + 2 + bytes.len().min(u16::MAX as usize)
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        let path_bytes = self.path.as_bytes();
        let path_len = path_bytes.len().min(u16::MAX as usize) as u16;
        dst.push(self.kind.as_u8());
        dst.extend_from_slice(&path_len.to_le_bytes());
        dst.extend_from_slice(&path_bytes[..path_len as usize]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoDecision {
    pub allowed: bool,
}

impl EncodeLE for IoDecision {
    #[inline]
    fn encoded_len(&self) -> usize {
        1
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.push(if self.allowed { 1 } else { 0 });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoResult {
    pub success: bool,
    pub size: u64,
}

impl EncodeLE for IoResult {
    #[inline]
    fn encoded_len(&self) -> usize {
        1 + 8
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.push(if self.success { 1 } else { 0 });
        dst.extend_from_slice(&self.size.to_le_bytes());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoPayload {
    pub hash64: u64,
    pub size: u64,
    pub bytes: Option<Vec<u8>>,
}

impl EncodeLE for IoPayload {
    #[inline]
    fn encoded_len(&self) -> usize {
        let bytes_len = self.bytes.as_ref().map(|v| v.len()).unwrap_or(0);
        8 + 8
            + 1
            + if self.bytes.is_some() {
                4 + bytes_len
            } else {
                0
            }
    }

    #[inline]
    fn encode_le(&self, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.hash64.to_le_bytes());
        dst.extend_from_slice(&self.size.to_le_bytes());
        match &self.bytes {
            Some(bytes) => {
                let len_u32 = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
                dst.push(1);
                dst.extend_from_slice(&len_u32.to_le_bytes());
                dst.extend_from_slice(&bytes[..len_u32 as usize]);
            }
            None => dst.push(0),
        }
    }
}
