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

use crate::runtime::crc32::crc32_ieee;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

pub const LOG_MAGIC: [u8; 4] = *b"NEXL";
pub const LOG_VERSION: u16 = 1;

// === KIND VALUES MUST MATCH CODEGEN ===
pub const KIND_TASK_SPAWNED: u16 = 1;

// Legacy name: codegen uses this value for "CapabilityAttempted"
pub const KIND_CAPABILITY_INVOKED: u16 = 2;

pub const KIND_FUEL_EXHAUSTED: u16 = 3;
pub const KIND_RESOURCE_VIOLATION: u16 = 4;

// Capability Audit (v0.5.7.x) — MUST match codegen
pub const KIND_CAPABILITY_ALLOWED: u16 = 6;
pub const KIND_CAPABILITY_DENIED: u16 = 7;

// Reserved high kinds
pub const KIND_RUN_STARTED: u16 = 0xFFFE;
pub const KIND_RUN_FINISHED: u16 = 0xFFFF;

pub const LOG_HEADER_LEN: usize = 4 + 2 + 32 + 32 + 2 + 4; // 76
pub const RECORD_HEADER_LEN: usize = 8 + 8 + 2 + 4; // 22

#[derive(Debug, Clone, Copy)]
pub struct LogHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub codegen_hash: [u8; 32],
    pub source_hash: [u8; 32],
    pub flags: u16,
    pub header_crc: u32,
    pub raw: [u8; LOG_HEADER_LEN],
}

#[derive(Debug, Clone)]
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

impl EventReader<BufReader<File>> {
    /// Convenience: open a log from disk.
    pub fn open(path: &Path) -> io::Result<Self> {
        let f = File::open(path)?;
        Ok(Self::new(BufReader::new(f)))
    }
}

impl<R: Read> EventReader<R> {
    pub fn new(r: R) -> Self {
        Self {
            r,
            header_read: false,
        }
    }

    pub fn read_log_header(&mut self) -> io::Result<LogHeader> {
        if self.header_read {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log header already read",
            ));
        }

        let mut raw = [0u8; LOG_HEADER_LEN];
        self.read_exact_failfast(&mut raw)?;

        let magic = [raw[0], raw[1], raw[2], raw[3]];
        let version = u16::from_le_bytes([raw[4], raw[5]]);

        if magic != LOG_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad log magic: expected {:?}, got {:?}", LOG_MAGIC, magic),
            ));
        }

        if version != LOG_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported log version: expected {}, got {}",
                    LOG_VERSION, version
                ),
            ));
        }

        let mut codegen_hash = [0u8; 32];
        codegen_hash.copy_from_slice(&raw[6..38]);

        let mut source_hash = [0u8; 32];
        source_hash.copy_from_slice(&raw[38..70]);

        let flags = u16::from_le_bytes([raw[70], raw[71]]);

        let header_crc = u32::from_le_bytes([raw[72], raw[73], raw[74], raw[75]]);
        let computed_crc = crc32_ieee(&raw[0..72]);

        if header_crc != computed_crc {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "header CRC mismatch: expected {:08x}, computed {:08x}",
                    header_crc, computed_crc
                ),
            ));
        }

        self.header_read = true;

        Ok(LogHeader {
            magic,
            version,
            codegen_hash,
            source_hash,
            flags,
            header_crc,
            raw,
        })
    }

    pub fn read_next(&mut self) -> io::Result<Option<EventRecord>> {
        if !self.header_read {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log header not read",
            ));
        }

        let mut hdr = [0u8; RECORD_HEADER_LEN];
        match self.read_exact_or_clean_eof(&mut hdr)? {
            Some(()) => {}
            None => return Ok(None),
        }

        let seq = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let task_id = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let kind = u16::from_le_bytes(hdr[16..18].try_into().unwrap());
        let payload_len = u32::from_le_bytes(hdr[18..22].try_into().unwrap()) as usize;

        // Hard cap to prevent hostile logs from allocating insane memory.
        const MAX_PAYLOAD_LEN: usize = 64 * 1024 * 1024;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("payload_len too large: {}", payload_len),
            ));
        }

        let mut payload = vec![0u8; payload_len];
        self.read_exact_failfast(&mut payload)?;

        Ok(Some(EventRecord {
            seq,
            task_id,
            kind,
            payload,
        }))
    }

    fn read_exact_failfast(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.r.read_exact(buf).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("log read failed (unexpected EOF/corruption): {}", e),
            )
        })
    }

    /// Reads exactly buf.len() bytes, but returns Ok(None) if EOF occurs *cleanly* at the start.
    fn read_exact_or_clean_eof(&mut self, buf: &mut [u8]) -> io::Result<Option<()>> {
        if buf.is_empty() {
            return Ok(Some(()));
        }

        // Try to read 1 byte first to distinguish "clean EOF" vs "mid-record EOF".
        let mut first = [0u8; 1];
        match self.r.read(&mut first) {
            Ok(0) => return Ok(None), // clean EOF
            Ok(1) => {
                buf[0] = first[0];
                self.read_exact_failfast(&mut buf[1..])?;
                Ok(Some(()))
            }
            Ok(_) => unreachable!(),
            Err(e) => Err(e),
        }
    }
}
