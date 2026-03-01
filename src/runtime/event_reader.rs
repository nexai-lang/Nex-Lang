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
pub const KIND_EVIDENCE_FINAL: u16 = 34;

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

        let seq = u64::from_le_bytes([
            hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7],
        ]);
        let task_id = u64::from_le_bytes([
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15],
        ]);
        let kind = u16::from_le_bytes([hdr[16], hdr[17]]);
        let payload_len = u32::from_le_bytes([hdr[18], hdr[19], hdr[20], hdr[21]]) as usize;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn build_log_header(flags: u16) -> [u8; LOG_HEADER_LEN] {
        let mut header = [0u8; LOG_HEADER_LEN];
        header[0..4].copy_from_slice(&LOG_MAGIC);
        header[4..6].copy_from_slice(&LOG_VERSION.to_le_bytes());
        header[70..72].copy_from_slice(&flags.to_le_bytes());
        let crc = crc32_ieee(&header[0..72]);
        header[72..76].copy_from_slice(&crc.to_le_bytes());
        header
    }

    fn encode_record(seq: u64, task_id: u64, kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&task_id.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn read_next_rejects_oversize_payload_len() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_log_header(0));

        let mut rec = Vec::new();
        rec.extend_from_slice(&0u64.to_le_bytes());
        rec.extend_from_slice(&0u64.to_le_bytes());
        rec.extend_from_slice(&KIND_TASK_STARTED.to_le_bytes());
        rec.extend_from_slice(&((16 * 1024 * 1024 + 1) as u32).to_le_bytes());
        bytes.extend_from_slice(&rec);

        let mut reader = EventReader::new(Cursor::new(bytes));
        reader.read_log_header().expect("header should parse");

        let err = reader
            .read_next()
            .expect_err("oversize payload_len must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("payload_len too large"));
    }

    #[test]
    fn read_next_rejects_truncated_record_payload() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_log_header(0));

        let payload = [1u8, 2, 3, 4];
        let mut rec = encode_record(1, 0, KIND_TASK_STARTED, &payload);
        rec.pop();
        bytes.extend_from_slice(&rec);

        let mut reader = EventReader::new(Cursor::new(bytes));
        reader.read_log_header().expect("header should parse");

        let err = reader
            .read_next()
            .expect_err("truncated record payload must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn hostile_streams_never_panic() {
        let mut seed: u64 = 0xD00D_F00D_1234_5678;
        let mut corpus: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0],
            vec![0x4E, 0x45, 0x58],
            b"NEXL".to_vec(),
            build_log_header(0).to_vec(),
        ];

        for i in 0..64usize {
            let len = (i * 13) % 257;
            let mut v = Vec::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                v.push((seed & 0xFF) as u8);
            }
            corpus.push(v);
        }

        for (idx, bytes) in corpus.iter().enumerate() {
            let caught = std::panic::catch_unwind(|| {
                let mut reader = EventReader::new(Cursor::new(bytes.clone()));
                if reader.read_log_header().is_ok() {
                    loop {
                        match reader.read_next() {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                }
            });

            assert!(
                caught.is_ok(),
                "event_reader panicked on hostile input case {}",
                idx
            );
        }
    }
}
