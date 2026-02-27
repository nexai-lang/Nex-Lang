#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;

use super::event_reader::{
    EventReader, KIND_IO_DECISION, KIND_IO_PAYLOAD, KIND_IO_REQUEST, KIND_IO_RESULT,
    KIND_RUN_FINISHED,
};
use super::event_recorder::try_recorder;

pub const IO_INLINE_PAYLOAD_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoKind {
    FsRead,
    FsWrite,
    NetConnect,
    NetSend,
    NetRecv,
}

impl IoKind {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::FsRead => 1,
            Self::FsWrite => 2,
            Self::NetConnect => 3,
            Self::NetSend => 4,
            Self::NetRecv => 5,
        }
    }

    #[inline]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::FsRead),
            2 => Some(Self::FsWrite),
            3 => Some(Self::NetConnect),
            4 => Some(Self::NetSend),
            5 => Some(Self::NetRecv),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetConnId(pub u64);

impl NetConnId {
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoErrorKind {
    NotFound,
    PermissionDenied,
    PayloadTooLargeForReplay,
    ReplayMismatch,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoError {
    pub kind: IoErrorKind,
    pub message: Option<String>,
}

impl IoError {
    #[inline]
    fn from_std(err: &std::io::Error) -> Self {
        let kind = match err.kind() {
            std::io::ErrorKind::NotFound => IoErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied => IoErrorKind::PermissionDenied,
            _ => IoErrorKind::Other,
        };

        Self {
            kind,
            message: None,
        }
    }

    #[inline]
    fn policy_denied() -> Self {
        Self {
            kind: IoErrorKind::PermissionDenied,
            message: Some("io blocked by decision".to_string()),
        }
    }

    #[inline]
    fn payload_too_large_for_replay(size: u64) -> Self {
        Self {
            kind: IoErrorKind::PayloadTooLargeForReplay,
            message: Some(format!(
                "replay payload omitted for size {} (> {} bytes)",
                size, IO_INLINE_PAYLOAD_CAP
            )),
        }
    }

    #[inline]
    fn replay_mismatch(msg: impl Into<String>) -> Self {
        Self {
            kind: IoErrorKind::ReplayMismatch,
            message: Some(msg.into()),
        }
    }

    #[inline]
    fn replay_recorded_failure() -> Self {
        Self {
            kind: IoErrorKind::Other,
            message: Some("replay recorded io failure".to_string()),
        }
    }

    #[inline]
    fn replay_not_supported() -> Self {
        Self {
            kind: IoErrorKind::Other,
            message: Some("replay mode requires deterministic io result source".to_string()),
        }
    }

    #[inline]
    fn unknown_connection(conn: NetConnId) -> Self {
        Self {
            kind: IoErrorKind::NotFound,
            message: Some(format!("unknown tcp connection id {}", conn.as_u64())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMode {
    Live,
    Replay,
}

pub trait DecisionSource {
    fn next_io_decision(&mut self, kind: IoKind, path: &str) -> Result<bool, IoError>;
}

pub struct AllowDecisionSource;

impl DecisionSource for AllowDecisionSource {
    fn next_io_decision(&mut self, _kind: IoKind, _path: &str) -> Result<bool, IoError> {
        Ok(true)
    }
}

pub struct ReplayDecisionSource {
    decisions: VecDeque<bool>,
}

impl ReplayDecisionSource {
    pub fn new(decisions: Vec<bool>) -> Self {
        Self {
            decisions: decisions.into(),
        }
    }
}

impl DecisionSource for ReplayDecisionSource {
    fn next_io_decision(&mut self, _kind: IoKind, _path: &str) -> Result<bool, IoError> {
        self.decisions
            .pop_front()
            .ok_or_else(IoError::replay_not_supported)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayIoPayload {
    pub hash64: u64,
    pub size: u64,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayIoOp {
    pub kind: IoKind,
    pub path: String,
    pub allowed: bool,
    pub payload: Option<ReplayIoPayload>,
    pub result_success: bool,
    pub result_size: u64,
}

pub fn replay_io_ops_from_log(path: &Path) -> Result<Vec<ReplayIoOp>, IoError> {
    let file = fs::File::open(path).map_err(|e| IoError::from_std(&e))?;
    let mut reader = EventReader::new(BufReader::new(file));
    reader
        .read_log_header()
        .map_err(|e| IoError::replay_mismatch(format!("failed to read event log header: {}", e)))?;

    struct PendingReplayOp {
        kind: IoKind,
        path: String,
        allowed: Option<bool>,
        payload: Option<ReplayIoPayload>,
    }

    let mut pending: Option<PendingReplayOp> = None;
    let mut out = Vec::new();

    while let Some(ev) = reader
        .read_next()
        .map_err(|e| IoError::replay_mismatch(format!("failed to read event record: {}", e)))?
    {
        if ev.kind == KIND_RUN_FINISHED {
            break;
        }

        match ev.kind {
            KIND_IO_REQUEST => {
                if pending.is_some() {
                    return Err(IoError::replay_mismatch(format!(
                        "IoRequest before previous IO completed at seq={}",
                        ev.seq
                    )));
                }
                let (kind, path) = decode_io_request(&ev.payload)?;
                pending = Some(PendingReplayOp {
                    kind,
                    path,
                    allowed: None,
                    payload: None,
                });
            }
            KIND_IO_DECISION => {
                let allowed = decode_io_decision(&ev.payload)?;
                let Some(state) = pending.as_mut() else {
                    return Err(IoError::replay_mismatch(format!(
                        "IoDecision without IoRequest at seq={}",
                        ev.seq
                    )));
                };
                if state.allowed.is_some() {
                    return Err(IoError::replay_mismatch(format!(
                        "duplicate IoDecision at seq={}",
                        ev.seq
                    )));
                }
                state.allowed = Some(allowed);
            }
            KIND_IO_PAYLOAD => {
                let payload = decode_io_payload(&ev.payload)?;
                let Some(state) = pending.as_mut() else {
                    return Err(IoError::replay_mismatch(format!(
                        "IoPayload without IoRequest at seq={}",
                        ev.seq
                    )));
                };
                match state.allowed {
                    Some(true) => {}
                    Some(false) => {
                        return Err(IoError::replay_mismatch(format!(
                            "IoPayload after denied IoDecision at seq={}",
                            ev.seq
                        )));
                    }
                    None => {
                        return Err(IoError::replay_mismatch(format!(
                            "IoPayload before IoDecision at seq={}",
                            ev.seq
                        )));
                    }
                }
                if state.payload.is_some() {
                    return Err(IoError::replay_mismatch(format!(
                        "duplicate IoPayload at seq={}",
                        ev.seq
                    )));
                }
                state.payload = Some(payload);
            }
            KIND_IO_RESULT => {
                let (result_success, result_size) = decode_io_result(&ev.payload)?;
                let Some(state) = pending.take() else {
                    return Err(IoError::replay_mismatch(format!(
                        "IoResult without IoRequest at seq={}",
                        ev.seq
                    )));
                };
                let Some(allowed) = state.allowed else {
                    return Err(IoError::replay_mismatch(format!(
                        "IoResult before IoDecision at seq={}",
                        ev.seq
                    )));
                };

                if !allowed && result_success {
                    return Err(IoError::replay_mismatch(format!(
                        "IoResult.success=true after denied IoDecision at seq={}",
                        ev.seq
                    )));
                }

                if allowed {
                    let Some(payload) = state.payload.clone() else {
                        return Err(IoError::replay_mismatch(format!(
                            "missing IoPayload for allowed IO at seq={}",
                            ev.seq
                        )));
                    };

                    if payload.size != result_size {
                        return Err(IoError::replay_mismatch(format!(
                            "IoResult.size={} != IoPayload.size={} at seq={}",
                            result_size, payload.size, ev.seq
                        )));
                    }

                    match state.kind {
                        IoKind::FsRead => {
                            validate_inline_read_payload("fs_read", &payload, ev.seq)?
                        }
                        IoKind::FsWrite => validate_no_bytes_payload("fs_write", &payload, ev.seq)?,
                        IoKind::NetConnect => validate_net_connect_payload(&payload, ev.seq)?,
                        IoKind::NetSend => validate_net_send_payload(&payload, ev.seq)?,
                        IoKind::NetRecv => {
                            validate_inline_read_payload("net_recv", &payload, ev.seq)?
                        }
                    }

                    out.push(ReplayIoOp {
                        kind: state.kind,
                        path: state.path,
                        allowed,
                        payload: Some(payload),
                        result_success,
                        result_size,
                    });
                } else {
                    if state.payload.is_some() {
                        return Err(IoError::replay_mismatch(format!(
                            "IoPayload present for denied IO at seq={}",
                            ev.seq
                        )));
                    }
                    out.push(ReplayIoOp {
                        kind: state.kind,
                        path: state.path,
                        allowed,
                        payload: None,
                        result_success,
                        result_size,
                    });
                }
            }
            _ => {
                if pending.is_some() {
                    return Err(IoError::replay_mismatch(format!(
                        "unexpected event kind {} while IO operation pending at seq={}",
                        ev.kind, ev.seq
                    )));
                }
            }
        }
    }

    if pending.is_some() {
        return Err(IoError::replay_mismatch(
            "log ended with incomplete IO operation",
        ));
    }

    Ok(out)
}

pub trait IoProxy {
    fn fs_read(&mut self, path: &str) -> Result<Vec<u8>, IoError>;
    fn fs_write(&mut self, path: &str, data: &[u8]) -> Result<(), IoError>;
    fn net_connect(&mut self, host: &str, port: u16) -> Result<NetConnId, IoError>;
    fn net_send(&mut self, conn: NetConnId, data: &[u8]) -> Result<(), IoError>;
    fn net_recv(&mut self, conn: NetConnId, max: u32) -> Result<Vec<u8>, IoError>;
}

pub struct DefaultIoProxy {
    mode: ExecMode,
    decisions: Box<dyn DecisionSource + Send>,
    replay_ops: VecDeque<ReplayIoOp>,
    next_conn_id: u64,
    tcp_connections: BTreeMap<NetConnId, TcpStream>,
}

impl DefaultIoProxy {
    pub fn new() -> Self {
        Self {
            mode: ExecMode::Live,
            decisions: Box::new(AllowDecisionSource),
            replay_ops: VecDeque::new(),
            next_conn_id: 1,
            tcp_connections: BTreeMap::new(),
        }
    }

    pub fn new_replay(decisions: Vec<bool>) -> Self {
        Self {
            mode: ExecMode::Replay,
            decisions: Box::new(ReplayDecisionSource::new(decisions)),
            replay_ops: VecDeque::new(),
            next_conn_id: 1,
            tcp_connections: BTreeMap::new(),
        }
    }

    pub fn new_replay_with_ops(ops: Vec<ReplayIoOp>) -> Self {
        let decisions = ops.iter().map(|op| op.allowed).collect::<Vec<_>>();
        Self {
            mode: ExecMode::Replay,
            decisions: Box::new(ReplayDecisionSource::new(decisions)),
            replay_ops: ops.into(),
            next_conn_id: 1,
            tcp_connections: BTreeMap::new(),
        }
    }

    pub fn new_replay_from_log(path: &Path) -> Result<Self, IoError> {
        let ops = replay_io_ops_from_log(path)?;
        Ok(Self::new_replay_with_ops(ops))
    }

    #[inline]
    fn should_record(&self) -> bool {
        self.mode == ExecMode::Live
    }

    fn record_request(kind: IoKind, path: &str) {
        if let Some(rec) = try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_io_request(0, kind, path);
            }
        }
    }

    fn record_decision(allowed: bool) {
        if let Some(rec) = try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_io_decision(0, allowed);
            }
        }
    }

    fn record_payload(hash64: u64, size: u64, bytes: Option<&[u8]>) {
        if let Some(rec) = try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_io_payload(0, hash64, size, bytes);
            }
        }
    }

    fn record_result(success: bool, size: u64) {
        if let Some(rec) = try_recorder() {
            if let Ok(mut r) = rec.lock() {
                let _ = r.record_io_result(0, success, size);
            }
        }
    }

    fn decide(&mut self, kind: IoKind, path: &str) -> Result<bool, IoError> {
        self.decisions.next_io_decision(kind, path)
    }

    fn replay_take_op(&mut self, kind: IoKind, path: &str) -> Result<ReplayIoOp, IoError> {
        let allowed = self.decide(kind, path)?;
        let op = self.replay_ops.pop_front().ok_or_else(|| {
            IoError::replay_mismatch(format!(
                "missing replay IO operation for {:?} path {}",
                kind, path
            ))
        })?;

        if op.kind != kind {
            return Err(IoError::replay_mismatch(format!(
                "replay IO kind mismatch: expected {:?}, got {:?}",
                kind, op.kind
            )));
        }

        if op.path != path {
            return Err(IoError::replay_mismatch(format!(
                "replay IO path mismatch: expected {}, got {}",
                path, op.path
            )));
        }

        if op.allowed != allowed {
            return Err(IoError::replay_mismatch(format!(
                "replay IoDecision mismatch for {}: event_stream={} op={}",
                path, allowed, op.allowed
            )));
        }

        Ok(op)
    }

    #[inline]
    fn net_connect_path(host: &str, port: u16) -> String {
        format!("tcp://{}:{}", host, port)
    }

    #[inline]
    fn net_send_path(conn: NetConnId) -> String {
        format!("tcp://conn/{}", conn.as_u64())
    }

    #[inline]
    fn net_recv_path(conn: NetConnId, max: u32) -> String {
        format!("tcp://conn/{}?max={}", conn.as_u64(), max)
    }

    #[inline]
    fn alloc_conn_id(&mut self) -> NetConnId {
        let id = NetConnId(self.next_conn_id);
        self.next_conn_id = self.next_conn_id.saturating_add(1);
        id
    }

    fn net_connect_live(&mut self, host: &str, port: u16) -> Result<NetConnId, IoError> {
        let path = Self::net_connect_path(host, port);
        Self::record_request(IoKind::NetConnect, &path);

        let allowed = self.decide(IoKind::NetConnect, &path)?;
        Self::record_decision(allowed);

        if !allowed {
            Self::record_result(false, 0);
            return Err(IoError::policy_denied());
        }

        let conn = self.alloc_conn_id();
        let conn_bytes = conn.as_u64().to_le_bytes();
        Self::record_payload(
            fnv1a64(&conn_bytes),
            conn_bytes.len() as u64,
            Some(&conn_bytes),
        );

        match TcpStream::connect((host, port)) {
            Ok(stream) => {
                self.tcp_connections.insert(conn, stream);
                Self::record_result(true, conn_bytes.len() as u64);
                Ok(conn)
            }
            Err(err) => {
                Self::record_result(false, conn_bytes.len() as u64);
                Err(IoError::from_std(&err))
            }
        }
    }

    fn net_send_live(&mut self, conn: NetConnId, data: &[u8]) -> Result<(), IoError> {
        let path = Self::net_send_path(conn);
        Self::record_request(IoKind::NetSend, &path);

        let allowed = self.decide(IoKind::NetSend, &path)?;
        Self::record_decision(allowed);

        let size = data.len() as u64;
        if !allowed {
            Self::record_result(false, size);
            return Err(IoError::policy_denied());
        }

        let inline = if data.len() <= IO_INLINE_PAYLOAD_CAP {
            Some(data)
        } else {
            None
        };
        Self::record_payload(fnv1a64(data), size, inline);

        let Some(stream) = self.tcp_connections.get_mut(&conn) else {
            Self::record_result(false, size);
            return Err(IoError::unknown_connection(conn));
        };

        match stream.write_all(data) {
            Ok(()) => {
                Self::record_result(true, size);
                Ok(())
            }
            Err(err) => {
                Self::record_result(false, size);
                Err(IoError::from_std(&err))
            }
        }
    }

    fn net_recv_live(&mut self, conn: NetConnId, max: u32) -> Result<Vec<u8>, IoError> {
        let path = Self::net_recv_path(conn, max);
        Self::record_request(IoKind::NetRecv, &path);

        let allowed = self.decide(IoKind::NetRecv, &path)?;
        Self::record_decision(allowed);

        if !allowed {
            Self::record_result(false, 0);
            return Err(IoError::policy_denied());
        }

        let max_len = usize::try_from(max).unwrap_or(usize::MAX);
        let Some(stream) = self.tcp_connections.get_mut(&conn) else {
            let empty: [u8; 0] = [];
            Self::record_payload(fnv1a64(&empty), 0, Some(&empty));
            Self::record_result(false, 0);
            return Err(IoError::unknown_connection(conn));
        };

        let mut buf = vec![0u8; max_len];
        match stream.read(&mut buf) {
            Ok(read_len) => {
                buf.truncate(read_len);
                let hash64 = fnv1a64(&buf);
                let size = read_len as u64;
                let inline = if buf.len() <= IO_INLINE_PAYLOAD_CAP {
                    Some(buf.as_slice())
                } else {
                    None
                };
                Self::record_payload(hash64, size, inline);
                Self::record_result(true, size);
                Ok(buf)
            }
            Err(err) => {
                let empty: [u8; 0] = [];
                Self::record_payload(fnv1a64(&empty), 0, Some(&empty));
                Self::record_result(false, 0);
                Err(IoError::from_std(&err))
            }
        }
    }

    fn fs_read_live(&mut self, path: &str) -> Result<Vec<u8>, IoError> {
        Self::record_request(IoKind::FsRead, path);

        let allowed = self.decide(IoKind::FsRead, path)?;
        Self::record_decision(allowed);

        if !allowed {
            Self::record_result(false, 0);
            return Err(IoError::policy_denied());
        }

        match fs::read(path) {
            Ok(bytes) => {
                let size = bytes.len() as u64;
                let hash64 = fnv1a64(&bytes);
                let inline = if bytes.len() <= IO_INLINE_PAYLOAD_CAP {
                    Some(bytes.as_slice())
                } else {
                    None
                };
                Self::record_payload(hash64, size, inline);
                Self::record_result(true, size);
                Ok(bytes)
            }
            Err(err) => {
                let empty: [u8; 0] = [];
                Self::record_payload(fnv1a64(&empty), 0, Some(&empty));
                Self::record_result(false, 0);
                Err(IoError::from_std(&err))
            }
        }
    }

    fn fs_write_live(&mut self, path: &str, data: &[u8]) -> Result<(), IoError> {
        Self::record_request(IoKind::FsWrite, path);

        let allowed = self.decide(IoKind::FsWrite, path)?;
        Self::record_decision(allowed);

        let size = data.len() as u64;

        if !allowed {
            Self::record_result(false, size);
            return Err(IoError::policy_denied());
        }

        let hash64 = fnv1a64(data);
        Self::record_payload(hash64, size, None);

        match fs::write(path, data) {
            Ok(()) => {
                Self::record_result(true, size);
                Ok(())
            }
            Err(err) => {
                Self::record_result(false, size);
                Err(IoError::from_std(&err))
            }
        }
    }

    fn fs_read_replay(&mut self, path: &str) -> Result<Vec<u8>, IoError> {
        let op = self.replay_take_op(IoKind::FsRead, path)?;

        if !op.allowed {
            if op.payload.is_some() {
                return Err(IoError::replay_mismatch(
                    "denied fs_read must not carry IoPayload",
                ));
            }
            if op.result_success {
                return Err(IoError::replay_mismatch(
                    "denied fs_read cannot have success=true IoResult",
                ));
            }
            return Err(IoError::policy_denied());
        }

        let payload = op.payload.ok_or_else(|| {
            IoError::replay_mismatch("allowed fs_read missing IoPayload in replay stream")
        })?;

        if op.result_size != payload.size {
            return Err(IoError::replay_mismatch(format!(
                "fs_read replay IoResult.size={} does not match IoPayload.size={}",
                op.result_size, payload.size
            )));
        }

        if !op.result_success {
            return Err(IoError::replay_recorded_failure());
        }

        match payload.bytes {
            Some(bytes) => {
                if bytes.len() as u64 != payload.size {
                    return Err(IoError::replay_mismatch(format!(
                        "fs_read replay inline bytes len {} does not match size {}",
                        bytes.len(),
                        payload.size
                    )));
                }
                let computed = fnv1a64(&bytes);
                if computed != payload.hash64 {
                    return Err(IoError::replay_mismatch(format!(
                        "fs_read replay payload hash mismatch: expected {}, computed {}",
                        payload.hash64, computed
                    )));
                }
                Ok(bytes)
            }
            None => {
                if payload.size > IO_INLINE_PAYLOAD_CAP as u64 {
                    Err(IoError::payload_too_large_for_replay(payload.size))
                } else {
                    Err(IoError::replay_mismatch(
                        "fs_read replay payload missing inline bytes",
                    ))
                }
            }
        }
    }

    fn fs_write_replay(&mut self, path: &str, data: &[u8]) -> Result<(), IoError> {
        let op = self.replay_take_op(IoKind::FsWrite, path)?;

        if !op.allowed {
            if op.payload.is_some() {
                return Err(IoError::replay_mismatch(
                    "denied fs_write must not carry IoPayload",
                ));
            }
            if op.result_success {
                return Err(IoError::replay_mismatch(
                    "denied fs_write cannot have success=true IoResult",
                ));
            }
            return Err(IoError::policy_denied());
        }

        let payload = op.payload.ok_or_else(|| {
            IoError::replay_mismatch("allowed fs_write missing IoPayload in replay stream")
        })?;

        if payload.bytes.is_some() {
            return Err(IoError::replay_mismatch(
                "fs_write IoPayload.bytes must be None",
            ));
        }

        let expected_size = data.len() as u64;
        if payload.size != expected_size {
            return Err(IoError::replay_mismatch(format!(
                "fs_write payload size mismatch: payload={} data={}",
                payload.size, expected_size
            )));
        }

        let computed = fnv1a64(data);
        if payload.hash64 != computed {
            return Err(IoError::replay_mismatch(format!(
                "fs_write payload hash mismatch: payload={} data={}",
                payload.hash64, computed
            )));
        }

        if op.result_size != expected_size {
            return Err(IoError::replay_mismatch(format!(
                "fs_write IoResult.size mismatch: result={} expected={}",
                op.result_size, expected_size
            )));
        }

        if op.result_success {
            Ok(())
        } else {
            Err(IoError::replay_recorded_failure())
        }
    }

    fn net_connect_replay(&mut self, host: &str, port: u16) -> Result<NetConnId, IoError> {
        let path = Self::net_connect_path(host, port);
        let op = self.replay_take_op(IoKind::NetConnect, &path)?;

        if !op.allowed {
            if op.payload.is_some() {
                return Err(IoError::replay_mismatch(
                    "denied net_connect must not carry IoPayload",
                ));
            }
            if op.result_success {
                return Err(IoError::replay_mismatch(
                    "denied net_connect cannot have success=true IoResult",
                ));
            }
            return Err(IoError::policy_denied());
        }

        let payload = op.payload.ok_or_else(|| {
            IoError::replay_mismatch("allowed net_connect missing IoPayload in replay stream")
        })?;
        validate_net_connect_payload(&payload, 0)?;

        if op.result_size != payload.size {
            return Err(IoError::replay_mismatch(format!(
                "net_connect IoResult.size mismatch: result={} payload={}",
                op.result_size, payload.size
            )));
        }

        let bytes = payload
            .bytes
            .as_ref()
            .ok_or_else(|| IoError::replay_mismatch("net_connect payload missing conn id bytes"))?;
        let conn = NetConnId(u64::from_le_bytes(
            bytes[..8].try_into().expect("conn id bytes"),
        ));

        if op.result_success {
            Ok(conn)
        } else {
            Err(IoError::replay_recorded_failure())
        }
    }

    fn net_send_replay(&mut self, conn: NetConnId, data: &[u8]) -> Result<(), IoError> {
        let path = Self::net_send_path(conn);
        let op = self.replay_take_op(IoKind::NetSend, &path)?;

        if !op.allowed {
            if op.payload.is_some() {
                return Err(IoError::replay_mismatch(
                    "denied net_send must not carry IoPayload",
                ));
            }
            if op.result_success {
                return Err(IoError::replay_mismatch(
                    "denied net_send cannot have success=true IoResult",
                ));
            }
            return Err(IoError::policy_denied());
        }

        let payload = op
            .payload
            .ok_or_else(|| IoError::replay_mismatch("allowed net_send missing IoPayload"))?;
        validate_net_send_payload(&payload, 0)?;

        let expected_size = data.len() as u64;
        if payload.size != expected_size {
            return Err(IoError::replay_mismatch(format!(
                "net_send payload size mismatch: payload={} data={}",
                payload.size, expected_size
            )));
        }

        let computed = fnv1a64(data);
        if payload.hash64 != computed {
            return Err(IoError::replay_mismatch(format!(
                "net_send payload hash mismatch: payload={} data={}",
                payload.hash64, computed
            )));
        }

        if let Some(bytes) = payload.bytes.as_ref() {
            if bytes.as_slice() != data {
                return Err(IoError::replay_mismatch(
                    "net_send inline payload bytes do not match provided data",
                ));
            }
        }

        if op.result_size != expected_size {
            return Err(IoError::replay_mismatch(format!(
                "net_send IoResult.size mismatch: result={} expected={}",
                op.result_size, expected_size
            )));
        }

        if op.result_success {
            Ok(())
        } else {
            Err(IoError::replay_recorded_failure())
        }
    }

    fn net_recv_replay(&mut self, conn: NetConnId, max: u32) -> Result<Vec<u8>, IoError> {
        let path = Self::net_recv_path(conn, max);
        let op = self.replay_take_op(IoKind::NetRecv, &path)?;

        if !op.allowed {
            if op.payload.is_some() {
                return Err(IoError::replay_mismatch(
                    "denied net_recv must not carry IoPayload",
                ));
            }
            if op.result_success {
                return Err(IoError::replay_mismatch(
                    "denied net_recv cannot have success=true IoResult",
                ));
            }
            return Err(IoError::policy_denied());
        }

        let payload = op
            .payload
            .ok_or_else(|| IoError::replay_mismatch("allowed net_recv missing IoPayload"))?;

        if op.result_size != payload.size {
            return Err(IoError::replay_mismatch(format!(
                "net_recv IoResult.size mismatch: result={} payload={}",
                op.result_size, payload.size
            )));
        }

        if !op.result_success {
            return Err(IoError::replay_recorded_failure());
        }

        match payload.bytes {
            Some(bytes) => {
                if bytes.len() as u64 != payload.size {
                    return Err(IoError::replay_mismatch(format!(
                        "net_recv replay inline bytes len {} does not match size {}",
                        bytes.len(),
                        payload.size
                    )));
                }
                if (bytes.len() as u64) > u64::from(max) {
                    return Err(IoError::replay_mismatch(format!(
                        "net_recv replay payload size {} exceeds max {}",
                        bytes.len(),
                        max
                    )));
                }
                let computed = fnv1a64(&bytes);
                if computed != payload.hash64 {
                    return Err(IoError::replay_mismatch(format!(
                        "net_recv replay payload hash mismatch: expected {}, computed {}",
                        payload.hash64, computed
                    )));
                }
                Ok(bytes)
            }
            None => {
                if payload.size > IO_INLINE_PAYLOAD_CAP as u64 {
                    Err(IoError::payload_too_large_for_replay(payload.size))
                } else {
                    Err(IoError::replay_mismatch(
                        "net_recv replay payload missing inline bytes",
                    ))
                }
            }
        }
    }
}

impl IoProxy for DefaultIoProxy {
    fn fs_read(&mut self, path: &str) -> Result<Vec<u8>, IoError> {
        match self.mode {
            ExecMode::Live => self.fs_read_live(path),
            ExecMode::Replay => self.fs_read_replay(path),
        }
    }

    fn fs_write(&mut self, path: &str, data: &[u8]) -> Result<(), IoError> {
        match self.mode {
            ExecMode::Live => self.fs_write_live(path, data),
            ExecMode::Replay => self.fs_write_replay(path, data),
        }
    }

    fn net_connect(&mut self, host: &str, port: u16) -> Result<NetConnId, IoError> {
        match self.mode {
            ExecMode::Live => self.net_connect_live(host, port),
            ExecMode::Replay => self.net_connect_replay(host, port),
        }
    }

    fn net_send(&mut self, conn: NetConnId, data: &[u8]) -> Result<(), IoError> {
        match self.mode {
            ExecMode::Live => self.net_send_live(conn, data),
            ExecMode::Replay => self.net_send_replay(conn, data),
        }
    }

    fn net_recv(&mut self, conn: NetConnId, max: u32) -> Result<Vec<u8>, IoError> {
        match self.mode {
            ExecMode::Live => self.net_recv_live(conn, max),
            ExecMode::Replay => self.net_recv_replay(conn, max),
        }
    }
}

fn decode_io_request(payload: &[u8]) -> Result<(IoKind, String), IoError> {
    if payload.len() < 3 {
        return Err(IoError::replay_mismatch(format!(
            "IoRequest payload too short: {}",
            payload.len()
        )));
    }

    let kind = IoKind::from_u8(payload[0]).ok_or_else(|| {
        IoError::replay_mismatch(format!("invalid IoRequest kind code {}", payload[0]))
    })?;

    let path_len = u16::from_le_bytes(payload[1..3].try_into().expect("path len bytes")) as usize;
    if payload.len() != 3 + path_len {
        return Err(IoError::replay_mismatch(format!(
            "IoRequest payload length mismatch: expected {}, got {}",
            3 + path_len,
            payload.len()
        )));
    }

    let path = std::str::from_utf8(&payload[3..])
        .map_err(|e| IoError::replay_mismatch(format!("IoRequest path utf8: {}", e)))?
        .to_string();

    Ok((kind, path))
}

fn decode_io_decision(payload: &[u8]) -> Result<bool, IoError> {
    if payload.len() != 1 {
        return Err(IoError::replay_mismatch(format!(
            "IoDecision payload length mismatch: expected 1, got {}",
            payload.len()
        )));
    }

    match payload[0] {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(IoError::replay_mismatch(format!(
            "invalid IoDecision allowed value {}",
            v
        ))),
    }
}

fn decode_io_result(payload: &[u8]) -> Result<(bool, u64), IoError> {
    if payload.len() != 9 {
        return Err(IoError::replay_mismatch(format!(
            "IoResult payload length mismatch: expected 9, got {}",
            payload.len()
        )));
    }

    let success = match payload[0] {
        0 => false,
        1 => true,
        v => {
            return Err(IoError::replay_mismatch(format!(
                "invalid IoResult success value {}",
                v
            )));
        }
    };

    let size = u64::from_le_bytes(payload[1..9].try_into().expect("result size bytes"));
    Ok((success, size))
}

fn decode_io_payload(payload: &[u8]) -> Result<ReplayIoPayload, IoError> {
    if payload.len() < 17 {
        return Err(IoError::replay_mismatch(format!(
            "IoPayload payload too short: {}",
            payload.len()
        )));
    }

    let hash64 = u64::from_le_bytes(payload[0..8].try_into().expect("payload hash bytes"));
    let size = u64::from_le_bytes(payload[8..16].try_into().expect("payload size bytes"));

    match payload[16] {
        0 => {
            if payload.len() != 17 {
                return Err(IoError::replay_mismatch(format!(
                    "IoPayload payload length mismatch: expected 17, got {}",
                    payload.len()
                )));
            }
            Ok(ReplayIoPayload {
                hash64,
                size,
                bytes: None,
            })
        }
        1 => {
            if payload.len() < 21 {
                return Err(IoError::replay_mismatch(format!(
                    "IoPayload bytes payload too short: {}",
                    payload.len()
                )));
            }
            let len =
                u32::from_le_bytes(payload[17..21].try_into().expect("payload bytes len")) as usize;
            if payload.len() != 21 + len {
                return Err(IoError::replay_mismatch(format!(
                    "IoPayload bytes length mismatch: expected {}, got {}",
                    21 + len,
                    payload.len()
                )));
            }
            Ok(ReplayIoPayload {
                hash64,
                size,
                bytes: Some(payload[21..].to_vec()),
            })
        }
        v => Err(IoError::replay_mismatch(format!(
            "invalid IoPayload has_bytes value {}",
            v
        ))),
    }
}

fn validate_inline_read_payload(
    op_name: &str,
    payload: &ReplayIoPayload,
    seq: u64,
) -> Result<(), IoError> {
    if let Some(bytes) = payload.bytes.as_ref() {
        if bytes.len() as u64 != payload.size {
            return Err(IoError::replay_mismatch(format!(
                "IoPayload bytes length {} != size {} for {} at seq={}",
                bytes.len(),
                payload.size,
                op_name,
                seq
            )));
        }
        let computed = fnv1a64(bytes);
        if computed != payload.hash64 {
            return Err(IoError::replay_mismatch(format!(
                "IoPayload hash mismatch for {} at seq={}: expected {} computed {}",
                op_name, seq, payload.hash64, computed
            )));
        }
    } else if payload.size <= IO_INLINE_PAYLOAD_CAP as u64 {
        return Err(IoError::replay_mismatch(format!(
            "IoPayload missing inline bytes for {} size {} at seq={}",
            op_name, payload.size, seq
        )));
    }

    Ok(())
}

fn validate_no_bytes_payload(
    op_name: &str,
    payload: &ReplayIoPayload,
    seq: u64,
) -> Result<(), IoError> {
    if payload.bytes.is_some() {
        return Err(IoError::replay_mismatch(format!(
            "IoPayload.bytes must be absent for {} at seq={}",
            op_name, seq
        )));
    }
    Ok(())
}

fn validate_net_send_payload(payload: &ReplayIoPayload, seq: u64) -> Result<(), IoError> {
    if let Some(bytes) = payload.bytes.as_ref() {
        if bytes.len() as u64 != payload.size {
            return Err(IoError::replay_mismatch(format!(
                "IoPayload bytes length {} != size {} for net_send at seq={}",
                bytes.len(),
                payload.size,
                seq
            )));
        }
        let computed = fnv1a64(bytes);
        if computed != payload.hash64 {
            return Err(IoError::replay_mismatch(format!(
                "IoPayload hash mismatch for net_send at seq={}: expected {} computed {}",
                seq, payload.hash64, computed
            )));
        }
    }
    Ok(())
}

fn validate_net_connect_payload(payload: &ReplayIoPayload, seq: u64) -> Result<(), IoError> {
    if payload.size != 8 {
        return Err(IoError::replay_mismatch(format!(
            "IoPayload.size must be 8 for net_connect at seq={}: got {}",
            seq, payload.size
        )));
    }

    let bytes = payload.bytes.as_ref().ok_or_else(|| {
        IoError::replay_mismatch(format!(
            "IoPayload.bytes missing for net_connect at seq={}",
            seq
        ))
    })?;

    if bytes.len() != 8 {
        return Err(IoError::replay_mismatch(format!(
            "IoPayload.bytes length must be 8 for net_connect at seq={}: got {}",
            seq,
            bytes.len()
        )));
    }

    let computed = fnv1a64(bytes);
    if computed != payload.hash64 {
        return Err(IoError::replay_mismatch(format!(
            "IoPayload hash mismatch for net_connect at seq={}: expected {} computed {}",
            seq, payload.hash64, computed
        )));
    }

    Ok(())
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(all(test, feature = "coop_scheduler"))]
mod tests {
    use super::{DefaultIoProxy, IoKind, IoProxy, NetConnId};
    use crate::replay::verify_log;
    use crate::runtime::event_reader::{
        EventReader, KIND_IO_DECISION, KIND_IO_PAYLOAD, KIND_IO_REQUEST, KIND_IO_RESULT,
        KIND_RUN_FINISHED, LOG_HEADER_LEN, RECORD_HEADER_LEN,
    };
    use crate::runtime::event_recorder::EventRecorder;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn coop_fs_read_emits_deterministic_io_events_and_replay_fails_on_corrupt_decision() {
        let base = std::env::temp_dir().join("nex_io_proxy_step3_live_decision_mismatch");
        let out_dir = base.join("out");
        let fixture = base.join("nex_io_proxy_fixture_step3.txt");

        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");
        fs::write(&fixture, b"nex-io-fixture").expect("write fixture");

        let events_path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open local recorder");
        rec.record_task_started(0).expect("record root started");
        rec.record_io_request(
            0,
            IoKind::FsRead,
            fixture.to_str().expect("fixture path utf8"),
        )
        .expect("record io request");
        rec.record_io_decision(0, true).expect("record io decision");
        rec.record_io_payload(
            0,
            super::fnv1a64(b"nex-io-fixture"),
            b"nex-io-fixture".len() as u64,
            Some(b"nex-io-fixture"),
        )
        .expect("record io payload");
        rec.record_io_result(0, true, b"nex-io-fixture".len() as u64)
            .expect("record io result");
        rec.record_task_finished(0, 0)
            .expect("record root finished");
        rec.record_run_finished(0, 0).expect("record run finished");
        drop(rec);

        let raw_bytes = fs::read(&events_path).expect("read events.bin");
        let canonical_bytes = trim_to_first_run_finished(&raw_bytes);
        let canonical_path = out_dir.join("events.canonical.bin");
        fs::write(&canonical_path, &canonical_bytes).expect("write canonical events");

        let file = fs::File::open(&canonical_path).expect("open canonical events");
        let mut reader = EventReader::new(BufReader::new(file));
        reader.read_log_header().expect("read log header");

        let mut events = Vec::new();
        while let Some(ev) = reader.read_next().expect("read next event") {
            events.push(ev);
        }

        let req_idx = events
            .iter()
            .position(|ev| {
                if ev.kind != KIND_IO_REQUEST || ev.payload.len() < 3 {
                    return false;
                }
                let Some(kind) = IoKind::from_u8(ev.payload[0]) else {
                    return false;
                };
                if kind != IoKind::FsRead {
                    return false;
                }
                let path_len = u16::from_le_bytes([ev.payload[1], ev.payload[2]]) as usize;
                if ev.payload.len() != 3 + path_len {
                    return false;
                }
                let Ok(path) = std::str::from_utf8(&ev.payload[3..]) else {
                    return false;
                };
                path.ends_with("nex_io_proxy_fixture_step3.txt")
            })
            .expect("missing fs_read IoRequest event for fixture path");
        let e1 = &events[req_idx];
        let decision_idx = events
            .iter()
            .enumerate()
            .skip(req_idx + 1)
            .find_map(|(idx, ev)| (ev.kind == KIND_IO_DECISION).then_some(idx))
            .expect("missing IoDecision after IoRequest");
        let payload_idx = events
            .iter()
            .enumerate()
            .skip(decision_idx + 1)
            .find_map(|(idx, ev)| (ev.kind == KIND_IO_PAYLOAD).then_some(idx))
            .expect("missing IoPayload after IoDecision");
        let result_idx = events
            .iter()
            .enumerate()
            .skip(payload_idx + 1)
            .find_map(|(idx, ev)| (ev.kind == KIND_IO_RESULT).then_some(idx))
            .expect("missing IoResult after IoPayload");
        let e2 = &events[decision_idx];
        let e3 = &events[payload_idx];
        let e4 = &events[result_idx];

        assert_eq!(e2.kind, KIND_IO_DECISION, "IoDecision order mismatch");
        assert_eq!(e3.kind, KIND_IO_PAYLOAD, "IoPayload order mismatch");
        assert_eq!(e4.kind, KIND_IO_RESULT, "IoResult order mismatch");

        assert!(
            !e1.payload.is_empty(),
            "IoRequest payload should not be empty"
        );
        let req_kind = IoKind::from_u8(e1.payload[0]).expect("decode io kind");
        assert_eq!(req_kind, IoKind::FsRead);
        let path_len = u16::from_le_bytes([e1.payload[1], e1.payload[2]]) as usize;
        assert_eq!(e1.payload.len(), 3 + path_len);
        let logged_path = std::str::from_utf8(&e1.payload[3..]).expect("utf8 io request path");
        assert!(
            logged_path.ends_with("nex_io_proxy_fixture_step3.txt"),
            "unexpected io request path: {}",
            logged_path
        );

        assert_eq!(e2.payload, vec![1u8], "IoDecision must be allowed=true");

        assert!(e3.payload.len() >= 17, "IoPayload too short");
        let payload_size = u64::from_le_bytes(e3.payload[8..16].try_into().expect("payload size"));
        assert_eq!(payload_size, b"nex-io-fixture".len() as u64);

        assert_eq!(e4.payload.len(), 9, "IoResult payload length");
        assert_eq!(e4.payload[0], 1u8, "IoResult success must be true");
        let result_size = u64::from_le_bytes(e4.payload[1..9].try_into().expect("size bytes"));
        assert_eq!(result_size, b"nex-io-fixture".len() as u64);

        verify_log(&canonical_path).expect("replay should accept valid IO stream");

        let bad = out_dir.join("events.corrupt_io_decision.bin");
        let mut bytes = canonical_bytes;
        let records = parse_records(&bytes);
        let io_decision = records
            .iter()
            .find(|r| r.kind == KIND_IO_DECISION)
            .expect("missing IoDecision record in produced log");
        bytes[io_decision.payload_offset] = 0u8;
        refresh_run_hash(&mut bytes);
        fs::write(&bad, &bytes).expect("write corrupted io decision log");

        let err = verify_log(&bad).expect_err("corrupted IoDecision should fail replay");
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("IoResult expected after IoDecision/IoPayload"),
            "unexpected replay error after IoDecision corruption: {}",
            msg
        );
    }

    #[test]
    fn replay_fs_read_returns_recorded_bytes_without_touching_fs() {
        let base = std::env::temp_dir().join("nex_io_proxy_step3_replay_read_virtualized");
        let out_dir = base.join("out");
        let fixture = base.join("fixture.txt");

        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");
        let expected = b"replay-virtualized-read".to_vec();
        fs::write(&fixture, &expected).expect("write fixture");

        let events_path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open local recorder");
        rec.record_task_started(0).expect("task started");
        rec.record_io_request(0, IoKind::FsRead, fixture.to_str().expect("fixture utf8"))
            .expect("io request");
        rec.record_io_decision(0, true).expect("io decision");
        rec.record_io_payload(
            0,
            super::fnv1a64(&expected),
            expected.len() as u64,
            Some(&expected),
        )
        .expect("io payload");
        rec.record_io_result(0, true, expected.len() as u64)
            .expect("io result");
        rec.record_task_finished(0, 0).expect("task finished");
        rec.record_run_finished(0, 0).expect("run finished");
        drop(rec);

        verify_log(&events_path).expect("valid replay log");

        fs::remove_file(&fixture).expect("delete source fixture");
        assert!(
            !fixture.exists(),
            "fixture should be gone before replay read"
        );

        let mut replay_proxy =
            DefaultIoProxy::new_replay_from_log(&events_path).expect("build replay proxy from log");
        let replayed = replay_proxy
            .fs_read(fixture.to_str().expect("fixture utf8"))
            .expect("replay read should use recorded bytes");
        assert_eq!(replayed, expected, "replay must return recorded bytes");
    }

    #[test]
    fn replay_fs_write_does_not_write_but_verifies_hash() {
        let base = std::env::temp_dir().join("nex_io_proxy_step3_replay_write_virtualized");
        let out_dir = base.join("out");
        let target = base.join("target.txt");

        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");
        let data = b"replay-virtualized-write".to_vec();

        let events_path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open local recorder");
        rec.record_task_started(0).expect("task started");
        rec.record_io_request(0, IoKind::FsWrite, target.to_str().expect("target utf8"))
            .expect("io request");
        rec.record_io_decision(0, true).expect("io decision");
        rec.record_io_payload(0, super::fnv1a64(&data), data.len() as u64, None)
            .expect("io payload");
        rec.record_io_result(0, true, data.len() as u64)
            .expect("io result");
        rec.record_task_finished(0, 0).expect("task finished");
        rec.record_run_finished(0, 0).expect("run finished");
        drop(rec);

        verify_log(&events_path).expect("valid replay log");

        if target.exists() {
            fs::remove_file(&target).expect("remove pre-existing target");
        }

        let mut replay_proxy =
            DefaultIoProxy::new_replay_from_log(&events_path).expect("build replay proxy from log");
        replay_proxy
            .fs_write(target.to_str().expect("target utf8"), &data)
            .expect("replay write should verify and not write to disk");

        assert!(
            !target.exists(),
            "replay fs_write must not create real filesystem output"
        );
    }

    #[test]
    fn replay_net_recv_returns_recorded_bytes_without_network() {
        let base = std::env::temp_dir().join("nex_io_proxy_step4_net_recv");
        let out_dir = base.join("out");

        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local test server");
        let port = listener.local_addr().expect("listener addr").port();
        let mut live_proxy = DefaultIoProxy::new();
        let conn = live_proxy
            .net_connect("127.0.0.1", port)
            .expect("live net_connect");
        let (mut server_stream, _) = listener.accept().expect("accept client");
        server_stream.write_all(b"HELLO").expect("write HELLO");
        let live_bytes = live_proxy.net_recv(conn, 64).expect("live net_recv");
        assert_eq!(live_bytes, b"HELLO");
        drop(live_proxy);

        let events_path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open local recorder");
        rec.record_task_started(0).expect("task started");
        record_net_connect_success(&mut rec, "127.0.0.1", port, conn);
        record_net_recv_success(&mut rec, conn, 64, &live_bytes);
        rec.record_task_finished(0, 0).expect("task finished");
        rec.record_run_finished(0, 0).expect("run finished");
        drop(rec);

        verify_log(&events_path).expect("valid net recv log");

        let mut replay_proxy =
            DefaultIoProxy::new_replay_from_log(&events_path).expect("build replay proxy");
        let replay_conn = replay_proxy
            .net_connect("127.0.0.1", port)
            .expect("replay net_connect should not touch network");
        assert_eq!(replay_conn, conn, "replay must return recorded conn id");
        let replayed = replay_proxy
            .net_recv(replay_conn, 64)
            .expect("replay net_recv should use recorded bytes");
        assert_eq!(replayed, b"HELLO");
    }

    #[test]
    fn replay_net_send_does_not_send_but_verifies_hash() {
        let base = std::env::temp_dir().join("nex_io_proxy_step4_net_send");
        let out_dir = base.join("out");

        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&out_dir).expect("create out dir");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local test server");
        let port = listener.local_addr().expect("listener addr").port();
        let mut live_proxy = DefaultIoProxy::new();
        let conn = live_proxy
            .net_connect("127.0.0.1", port)
            .expect("live net_connect");
        let (mut server_stream, _) = listener.accept().expect("accept client");
        live_proxy.net_send(conn, b"PING").expect("live net_send");
        drop(live_proxy);

        let mut received = [0u8; 4];
        server_stream
            .read_exact(&mut received)
            .expect("read PING from client");
        assert_eq!(&received, b"PING", "server should receive live send");

        let events_path = out_dir.join("events.bin");
        let mut rec = EventRecorder::open(&out_dir, "events.bin").expect("open local recorder");
        rec.record_task_started(0).expect("task started");
        record_net_connect_success(&mut rec, "127.0.0.1", port, conn);
        record_net_send_success(&mut rec, conn, b"PING");
        rec.record_task_finished(0, 0).expect("task finished");
        rec.record_run_finished(0, 0).expect("run finished");
        drop(rec);

        verify_log(&events_path).expect("valid net send log");

        let mut replay_proxy =
            DefaultIoProxy::new_replay_from_log(&events_path).expect("build replay proxy");
        let replay_conn = replay_proxy
            .net_connect("127.0.0.1", port)
            .expect("replay net_connect should not touch network");
        replay_proxy
            .net_send(replay_conn, b"PING")
            .expect("replay net_send should verify payload and not send");

        let bad = out_dir.join("events.corrupt_net_send_hash.bin");
        let mut bytes = fs::read(&events_path).expect("read net events");
        let records = parse_records(&bytes);
        let payload_records: Vec<&RecordRef> = records
            .iter()
            .filter(|r| r.kind == KIND_IO_PAYLOAD)
            .collect();
        let send_payload = payload_records
            .last()
            .expect("missing net_send IoPayload record");
        bytes[send_payload.payload_offset] ^= 0x01;
        refresh_run_hash(&mut bytes);
        fs::write(&bad, &bytes).expect("write corrupted net send log");

        let err = match DefaultIoProxy::new_replay_from_log(&bad) {
            Ok(_) => panic!("corrupted net send hash should fail replay"),
            Err(err) => err,
        };
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("IoPayload hash mismatch for net_send"),
            "unexpected replay error for corrupted net send hash: {}",
            msg
        );
    }

    fn record_net_connect_success(rec: &mut EventRecorder, host: &str, port: u16, conn: NetConnId) {
        let path = format!("tcp://{}:{}", host, port);
        let conn_bytes = conn.as_u64().to_le_bytes();
        rec.record_io_request(0, IoKind::NetConnect, &path)
            .expect("net_connect request");
        rec.record_io_decision(0, true)
            .expect("net_connect decision");
        rec.record_io_payload(0, super::fnv1a64(&conn_bytes), 8, Some(&conn_bytes))
            .expect("net_connect payload");
        rec.record_io_result(0, true, 8)
            .expect("net_connect result");
    }

    fn record_net_send_success(rec: &mut EventRecorder, conn: NetConnId, data: &[u8]) {
        let path = format!("tcp://conn/{}", conn.as_u64());
        rec.record_io_request(0, IoKind::NetSend, &path)
            .expect("net_send request");
        rec.record_io_decision(0, true).expect("net_send decision");
        rec.record_io_payload(0, super::fnv1a64(data), data.len() as u64, Some(data))
            .expect("net_send payload");
        rec.record_io_result(0, true, data.len() as u64)
            .expect("net_send result");
    }

    fn record_net_recv_success(rec: &mut EventRecorder, conn: NetConnId, max: u32, bytes: &[u8]) {
        let path = format!("tcp://conn/{}?max={}", conn.as_u64(), max);
        rec.record_io_request(0, IoKind::NetRecv, &path)
            .expect("net_recv request");
        rec.record_io_decision(0, true).expect("net_recv decision");
        rec.record_io_payload(0, super::fnv1a64(bytes), bytes.len() as u64, Some(bytes))
            .expect("net_recv payload");
        rec.record_io_result(0, true, bytes.len() as u64)
            .expect("net_recv result");
    }

    #[derive(Debug, Clone)]
    struct RecordRef {
        kind: u16,
        record_offset: usize,
        record_len: usize,
        payload_offset: usize,
        payload_len: usize,
    }

    fn parse_records(bytes: &[u8]) -> Vec<RecordRef> {
        assert!(bytes.len() >= LOG_HEADER_LEN, "log too short for header");
        let mut out = Vec::new();
        let mut pos = LOG_HEADER_LEN;
        while pos < bytes.len() {
            assert!(
                pos + RECORD_HEADER_LEN <= bytes.len(),
                "truncated record header at offset {}",
                pos
            );
            let kind = read_u16_le(bytes, pos + 16);
            let payload_len = read_u32_le(bytes, pos + 18) as usize;
            let payload_offset = pos + RECORD_HEADER_LEN;
            let record_len = RECORD_HEADER_LEN + payload_len;
            assert!(
                payload_offset + payload_len <= bytes.len(),
                "truncated payload at offset {}",
                payload_offset
            );
            out.push(RecordRef {
                kind,
                record_offset: pos,
                record_len,
                payload_offset,
                payload_len,
            });
            pos += record_len;
        }
        out
    }

    fn refresh_run_hash(bytes: &mut [u8]) {
        let records = parse_records(bytes);
        let run_idx = records
            .iter()
            .position(|r| r.kind == KIND_RUN_FINISHED)
            .expect("missing RunFinished for hash refresh");
        let run_ref = &records[run_idx];
        assert_eq!(
            run_idx,
            records.len() - 1,
            "RunFinished must be last record"
        );
        assert!(
            run_ref.payload_len >= 36,
            "RunFinished payload must contain exit_code + hash"
        );

        let mut hasher = Sha256::new();
        hasher.update(&bytes[..LOG_HEADER_LEN]);
        for rec in &records[..run_idx] {
            hasher.update(&bytes[rec.record_offset..rec.record_offset + rec.record_len]);
        }
        let digest = hasher.finalize();
        let start = run_ref.payload_offset + 4;
        let end = start + 32;
        bytes[start..end].copy_from_slice(&digest[..]);
    }

    fn trim_to_first_run_finished(bytes: &[u8]) -> Vec<u8> {
        let records = parse_records(bytes);
        let run_idx = records
            .iter()
            .position(|r| r.kind == KIND_RUN_FINISHED)
            .expect("missing RunFinished in log");
        let end = records[run_idx].record_offset + records[run_idx].record_len;
        bytes[..end].to_vec()
    }

    fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(bytes[off..off + 4].try_into().expect("u32 LE"))
    }

    fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(bytes[off..off + 2].try_into().expect("u16 LE"))
    }
}
