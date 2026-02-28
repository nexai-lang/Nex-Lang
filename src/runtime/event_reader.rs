// src/runtime/event_reader.rs
//
// Deterministic Log Reader (canonical).
//
// Header:
//   magic: [u8;4] = b"NEXL"
//   version: u16  = 1
//   codegen_hash: [u8;32]
//   source_hash:  [u8;32]
//   flags: u16
//   header_crc: u32  (CRC32 over bytes [0..72])
//
// Record:
//   seq: u64
//   task_id: u64
//   kind: u16
//   payload_len: u32
//   payload: [u8; payload_len]
//
// Design goals:
// - Fail-fast, deterministic parsing
// - Strong validation (magic/version/crc/size caps)
// - Provide a stable API used by replay + tamper tests

#![allow(dead_code)]

use crate::runtime::crc32::crc32_ieee;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

pub const LOG_MAGIC: [u8; 4] = *b"NEXL";
pub const LOG_VERSION: u16 = 1;

// === KIND VALUES MUST MATCH runtime/event.rs ===
pub const KIND_TASK_SPAWNED: u16 = 1;
pub const KIND_CAPABILITY_INVOKED: u16 = 2;
pub const KIND_FUEL_EXHAUSTED: u16 = 3;
pub const KIND_RESOURCE_VIOLATION: u16 = 4;

pub const KIND_TASK_STARTED: u16 = 6;
pub const KIND_TASK_FINISHED: u16 = 7;
pub const KIND_TASK_CANCELLED: u16 = 8;
pub const KIND_TASK_JOINED: u16 = 9;

// Scheduler extensions (append-only tags)
pub const KIND_SCHED_INIT: u16 = 10;
pub const KIND_SCHED_STATE: u16 = 11;
pub const KIND_TICK_START: u16 = 12;
pub const KIND_TICK_END: u16 = 13;
pub const KIND_PICK_TASK: u16 = 14;
pub const KIND_YIELD: u16 = 15;
pub const KIND_FUEL_DEBIT: u16 = 16;
pub const KIND_IO_REQUEST: u16 = 17;
pub const KIND_IO_DECISION: u16 = 18;
pub const KIND_IO_RESULT: u16 = 19;
pub const KIND_IO_PAYLOAD: u16 = 20;
pub const KIND_BUS_SEND: u16 = 21;
pub const KIND_BUS_RECV: u16 = 22;
pub const KIND_BUS_SEND_REQUEST: u16 = 23;
pub const KIND_BUS_DECISION: u16 = 24;
pub const KIND_BUS_SEND_RESULT: u16 = 25;
pub const KIND_DEADLOCK_DETECTED: u16 = 26;
pub const KIND_DEADLOCK_EDGE: u16 = 27;
pub const KIND_IO_BEGIN: u16 = 28;
pub const KIND_MESSAGE_SENT: u16 = 29;
pub const KIND_MESSAGE_DELIVERED: u16 = 30;
pub const KIND_MESSAGE_BLOCKED: u16 = 31;
pub const KIND_CHANNEL_CREATED: u16 = 32;
pub const KIND_CHANNEL_CLOSED: u16 = 33;

// Reserved high kinds
pub const KIND_RUN_STARTED: u16 = 0xFFFE;
pub const KIND_RUN_FINISHED: u16 = 0xFFFF;

pub const LOG_HEADER_LEN: usize = 76;
pub const RECORD_HEADER_LEN: usize = 8 + 8 + 2 + 4;

// Parsed header plus raw bytes for hashing.
#[derive(Clone, Debug)]
pub struct LogHeader {
    pub raw: [u8; LOG_HEADER_LEN],
    pub version: u16,
    pub codegen_hash: [u8; 32],
    pub source_hash: [u8; 32],
    pub flags: u16,
    pub header_crc: u32,
}

#[derive(Clone, Debug)]
pub struct EventRecord {
    pub seq: u64,
    pub task_id: u64,
    pub kind: u16,
    pub payload: Vec<u8>,
}

pub struct EventReader<R: Read> {
    r: R,
    header_read: bool,
}

impl<R: Read> EventReader<R> {
    pub fn new(r: R) -> Self {
        Self {
            r,
            header_read: false,
        }
    }

    pub fn read_log_header(&mut self) -> io::Result<LogHeader> {
        let mut raw = [0u8; LOG_HEADER_LEN];
        self.r.read_exact(&mut raw)?;

        if raw[0..4] != LOG_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "bad log magic: expected {:?}, got {:?}",
                    LOG_MAGIC,
                    &raw[0..4]
                ),
            ));
        }

        let version = u16::from_le_bytes([raw[4], raw[5]]);
        if version != LOG_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad log version: expected {}, got {}", LOG_VERSION, version),
            ));
        }

        let mut codegen_hash = [0u8; 32];
        codegen_hash.copy_from_slice(&raw[6..38]);

        let mut source_hash = [0u8; 32];
        source_hash.copy_from_slice(&raw[38..70]);

        let flags = u16::from_le_bytes([raw[70], raw[71]]);
        let header_crc = u32::from_le_bytes([raw[72], raw[73], raw[74], raw[75]]);

        let computed = crc32_ieee(&raw[0..72]);
        if computed != header_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "header CRC mismatch: expected {:08x}, computed {:08x}",
                    header_crc, computed
                ),
            ));
        }

        self.header_read = true;

        Ok(LogHeader {
            raw,
            version,
            codegen_hash,
            source_hash,
            flags,
            header_crc,
        })
    }

    pub fn read_next(&mut self) -> io::Result<Option<EventRecord>> {
        if !self.header_read {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "read_next called before read_log_header",
            ));
        }

        let mut hdr = [0u8; RECORD_HEADER_LEN];
        match self.r.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let seq = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let task_id = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let kind = u16::from_le_bytes(hdr[16..18].try_into().unwrap());
        let payload_len = u32::from_le_bytes(hdr[18..22].try_into().unwrap()) as usize;

        if payload_len > 16 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("payload_len too large: {}", payload_len),
            ));
        }

        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.r.read_exact(&mut payload)?;
        }

        Ok(Some(EventRecord {
            seq,
            task_id,
            kind,
            payload,
        }))
    }
}

impl EventReader<BufReader<File>> {
    pub fn open(path: &Path) -> io::Result<Self> {
        let f = File::open(path)?;
        Ok(EventReader::new(BufReader::new(f)))
    }
}
