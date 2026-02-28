// src/runtime/event_recorder.rs
#![allow(dead_code)]

use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
};

use sha2::{Digest, Sha256};

use super::crc32::crc32_ieee;
use super::event::{
    BusDecision, BusRecv, BusSend, BusSendRequest, BusSendResult, CapabilityInvoked, ChannelClosed,
    ChannelCreated, DeadlockDetected, DeadlockEdge, EncodeLE, EventHeader, EventKind,
    EvidenceFinal, EvidenceVersion, FuelDebit, FuelReason, IoBegin, IoDecision, IoPayload,
    IoRequest, IoResult, MessageBlocked, MessageDelivered, MessageSent, PickTask,
    ResourceViolation, RunFinished, SchedInit, SchedState, SchedStatePayload, TaskCancelled,
    TaskFinished, TaskJoined, TaskSpawned, TaskStarted, TickEnd, TickStart, YieldKind,
    YieldPayload, EVENT_MAGIC, EVENT_VERSION,
};
use super::event_sink::EventSink;
use super::identity::{self, IdentityProvider};
use super::io_proxy::IoKind;
use super::jsonl_sink::JsonlSink;

const LOG_HEADER_LEN: usize = 76;

static EVENT_SEQ: AtomicU64 = AtomicU64::new(0);
static RECORDER: OnceLock<Mutex<EventRecorder>> = OnceLock::new();

#[inline]
pub fn recorder() -> &'static Mutex<EventRecorder> {
    RECORDER.get().expect("EventRecorder not initialized")
}

#[inline]
pub fn try_recorder() -> Option<&'static Mutex<EventRecorder>> {
    RECORDER.get()
}

pub fn init_global_recorder(out_dir: impl AsRef<Path>, file_name: &str) -> io::Result<()> {
    let recorder = EventRecorder::open(out_dir.as_ref(), file_name)?;
    RECORDER
        .set(Mutex::new(recorder))
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "Recorder already initialized"))
}

pub fn init_global_recorder_with_jsonl(
    out_dir: impl AsRef<Path>,
    bin_name: &str,
    jsonl_name: &str,
) -> io::Result<()> {
    init_global_recorder(out_dir.as_ref(), bin_name)?;

    let mut rec = recorder()
        .lock()
        .map_err(|_| io::Error::other("Mutex poisoned"))?;

    rec.attach_jsonl_sink(out_dir.as_ref(), jsonl_name)
}

pub struct EventRecorder {
    out_path: PathBuf,
    writer: BufWriter<File>,
    hasher: Sha256,
    event_count: u64,
    wrote_preamble: bool,
    sinks: Vec<Box<dyn EventSink>>,

    flags: u16,
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
    policy_hash: [u8; 32],
    agent_id: u32,
    evidence_emitted: bool,
}

impl EventRecorder {
    pub fn open(out_dir: &Path, file_name: &str) -> io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;

        let out_path = out_dir.join(file_name);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&out_path)?;

        Ok(Self {
            out_path,
            writer: BufWriter::new(file),
            hasher: Sha256::new(),
            event_count: 0,
            wrote_preamble: false,
            sinks: Vec::new(),
            flags: 0,
            codegen_hash: [0u8; 32],
            source_hash: [0u8; 32],
            policy_hash: [0u8; 32],
            agent_id: 0,
            evidence_emitted: false,
        })
    }

    pub fn attach_jsonl_sink(&mut self, out_dir: &Path, jsonl_name: &str) -> io::Result<()> {
        std::fs::create_dir_all(out_dir)?;
        let path = out_dir.join(jsonl_name);
        let sink = JsonlSink::new(&path)?;
        self.sinks.push(Box::new(sink));
        Ok(())
    }

    pub fn set_hashes(
        &mut self,
        codegen_hash: [u8; 32],
        source_hash: [u8; 32],
        policy_hash: [u8; 32],
    ) {
        self.codegen_hash = codegen_hash;
        self.source_hash = source_hash;
        self.policy_hash = policy_hash;
    }

    pub fn set_agent_id(&mut self, agent_id: u32) {
        self.agent_id = agent_id;
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
    }

    fn ensure_preamble(&mut self) -> io::Result<()> {
        if self.wrote_preamble {
            return Ok(());
        }

        let mut header = [0u8; LOG_HEADER_LEN];
        header[0..4].copy_from_slice(&EVENT_MAGIC);
        header[4..6].copy_from_slice(&EVENT_VERSION.to_le_bytes());
        header[6..38].copy_from_slice(&self.codegen_hash);
        header[38..70].copy_from_slice(&self.source_hash);
        header[70..72].copy_from_slice(&self.flags.to_le_bytes());
        header[72..76].copy_from_slice(&0u32.to_le_bytes());

        let crc = crc32_ieee(&header[0..72]);
        header[72..76].copy_from_slice(&crc.to_le_bytes());

        self.write_and_hash(&header)?;
        self.writer.flush()?;

        self.wrote_preamble = true;
        Ok(())
    }

    pub fn record_event(
        &mut self,
        task_id: u64,
        kind: EventKind,
        payload: &[u8],
    ) -> io::Result<u64> {
        self.ensure_preamble()?;

        let seq = EVENT_SEQ.fetch_add(1, Ordering::Relaxed);

        let header = EventHeader {
            seq,
            task_id,
            kind,
            payload_len: payload.len() as u32,
        };

        let header_bytes = header.encode();
        let mut record_bytes = Vec::with_capacity(EventHeader::ENCODED_LEN + payload.len());
        record_bytes.extend_from_slice(&header_bytes);
        record_bytes.extend_from_slice(payload);

        self.write_and_hash(&record_bytes)?;
        self.event_count = self.event_count.saturating_add(1);
        self.writer.flush()?;

        for sink in &mut self.sinks {
            sink.on_event(&header, payload)?;
            sink.flush()?;
        }

        Ok(seq)
    }

    pub fn record_task_spawned(&mut self, parent: u64, child: u64) -> io::Result<u64> {
        let payload = TaskSpawned { parent, child }.to_bytes_le();
        self.record_event(parent, EventKind::TaskSpawned, &payload)
    }

    pub fn record_task_started(&mut self, task: u64) -> io::Result<u64> {
        let payload = TaskStarted.to_bytes_le();
        self.record_event(task, EventKind::TaskStarted, &payload)
    }

    pub fn record_task_finished(&mut self, task: u64, exit: i32) -> io::Result<u64> {
        let payload = TaskFinished { exit_code: exit }.to_bytes_le();
        self.record_event(task, EventKind::TaskFinished, &payload)
    }

    pub fn record_task_cancelled(&mut self, task: u64, reason: u32) -> io::Result<u64> {
        let payload = TaskCancelled {
            reason_code: reason,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::TaskCancelled, &payload)
    }

    pub fn record_task_joined(&mut self, task: u64, joined: u64) -> io::Result<u64> {
        let payload = TaskJoined {
            joined_task: joined,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::TaskJoined, &payload)
    }

    pub fn record_sched_init(&mut self, task: u64, tick0: u64) -> io::Result<u64> {
        let payload = SchedInit { tick0 }.to_bytes_le();
        self.record_event(task, EventKind::SchedInit, &payload)
    }

    pub fn record_sched_state(
        &mut self,
        task: u64,
        from: SchedState,
        to: SchedState,
        tick: u64,
    ) -> io::Result<u64> {
        let payload = SchedStatePayload { from, to, tick }.to_bytes_le();
        self.record_event(task, EventKind::SchedState, &payload)
    }

    pub fn record_tick_start(&mut self, task: u64, tick: u64) -> io::Result<u64> {
        let payload = TickStart { tick }.to_bytes_le();
        self.record_event(task, EventKind::TickStart, &payload)
    }

    pub fn record_tick_end(
        &mut self,
        task: u64,
        tick: u64,
        runnable: u32,
        blocked: u32,
    ) -> io::Result<u64> {
        let payload = TickEnd {
            tick,
            runnable,
            blocked,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::TickEnd, &payload)
    }

    pub fn record_pick_task(
        &mut self,
        task: u64,
        tick: u64,
        task_id: u32,
        reason: &str,
    ) -> io::Result<u64> {
        let payload = PickTask {
            tick,
            task_id,
            reason: reason.to_string(),
        }
        .to_bytes_le();
        self.record_event(task, EventKind::PickTask, &payload)
    }

    pub fn record_yield(
        &mut self,
        task: u64,
        tick: u64,
        task_id: u32,
        kind: YieldKind,
    ) -> io::Result<u64> {
        let payload = YieldPayload {
            tick,
            task_id,
            kind,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::r#Yield, &payload)
    }

    pub fn record_fuel_debit(
        &mut self,
        task: u64,
        tick: u64,
        task_id: u32,
        amount: u32,
        reason: FuelReason,
    ) -> io::Result<u64> {
        let payload = FuelDebit {
            tick,
            task_id,
            amount,
            reason,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::FuelDebit, &payload)
    }

    pub fn record_io_begin(&mut self, task: u64, req_id: u64) -> io::Result<u64> {
        let payload = IoBegin { req_id }.to_bytes_le();
        self.record_event(task, EventKind::IoBegin, &payload)
    }

    pub fn record_io_request(&mut self, task: u64, kind: IoKind, path: &str) -> io::Result<u64> {
        let payload = IoRequest {
            kind,
            path: path.to_string(),
        }
        .to_bytes_le();
        self.record_event(task, EventKind::IoRequest, &payload)
    }

    pub fn record_io_request_with_req(
        &mut self,
        task: u64,
        req_id: u64,
        kind: IoKind,
        path: &str,
    ) -> io::Result<u64> {
        let path_bytes = path.as_bytes();
        let path_len = path_bytes.len().min(u16::MAX as usize) as u16;
        let mut payload = Vec::with_capacity(8 + 1 + 2 + path_len as usize);
        payload.extend_from_slice(&req_id.to_le_bytes());
        payload.push(kind.as_u8());
        payload.extend_from_slice(&path_len.to_le_bytes());
        payload.extend_from_slice(&path_bytes[..path_len as usize]);
        self.record_event(task, EventKind::IoRequest, &payload)
    }

    pub fn record_io_decision(&mut self, task: u64, allowed: bool) -> io::Result<u64> {
        let payload = IoDecision { allowed }.to_bytes_le();
        self.record_event(task, EventKind::IoDecision, &payload)
    }

    pub fn record_io_decision_with_reason(
        &mut self,
        task: u64,
        req_id: u64,
        allowed: bool,
        reason_code: u32,
    ) -> io::Result<u64> {
        let mut payload = Vec::with_capacity(13);
        payload.extend_from_slice(&req_id.to_le_bytes());
        payload.push(if allowed { 1 } else { 0 });
        payload.extend_from_slice(&reason_code.to_le_bytes());
        self.record_event(task, EventKind::IoDecision, &payload)
    }

    pub fn record_io_result(&mut self, task: u64, success: bool, size: u64) -> io::Result<u64> {
        let payload = IoResult { success, size }.to_bytes_le();
        self.record_event(task, EventKind::IoResult, &payload)
    }

    pub fn record_io_result_with_req(
        &mut self,
        task: u64,
        req_id: u64,
        success: bool,
        size: u64,
        code: Option<u8>,
    ) -> io::Result<u64> {
        let mut payload = Vec::with_capacity(18);
        payload.extend_from_slice(&req_id.to_le_bytes());
        payload.push(if success { 1 } else { 0 });
        payload.extend_from_slice(&size.to_le_bytes());
        payload.push(code.unwrap_or(u8::MAX));
        self.record_event(task, EventKind::IoResult, &payload)
    }

    pub fn record_io_payload(
        &mut self,
        task: u64,
        hash64: u64,
        size: u64,
        bytes: Option<&[u8]>,
    ) -> io::Result<u64> {
        let payload = IoPayload {
            hash64,
            size,
            bytes: bytes.map(|b| b.to_vec()),
        }
        .to_bytes_le();
        self.record_event(task, EventKind::IoPayload, &payload)
    }

    pub fn record_io_payload_with_req(
        &mut self,
        task: u64,
        req_id: u64,
        hash64: u64,
        size: u64,
        bytes: Option<&[u8]>,
    ) -> io::Result<u64> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&req_id.to_le_bytes());
        payload.extend_from_slice(&hash64.to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        match bytes {
            Some(b) => {
                let len_u32 = u32::try_from(b.len()).unwrap_or(u32::MAX);
                payload.push(1);
                payload.extend_from_slice(&len_u32.to_le_bytes());
                payload.extend_from_slice(&b[..len_u32 as usize]);
            }
            None => payload.push(0),
        }
        self.record_event(task, EventKind::IoPayload, &payload)
    }

    pub fn record_bus_send(
        &mut self,
        task: u64,
        req_id: u64,
        sender: u32,
        receiver: u32,
        kind: u16,
        payload_len: u32,
        payload_hash64: u64,
    ) -> io::Result<u64> {
        let payload = BusSend {
            req_id,
            sender,
            receiver,
            kind,
            payload_len,
            payload_hash64,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::BusSend, &payload)
    }

    pub fn record_bus_recv(&mut self, task: u64, req_id: u64, receiver: u32) -> io::Result<u64> {
        let payload = BusRecv { req_id, receiver }.to_bytes_le();
        self.record_event(task, EventKind::BusRecv, &payload)
    }

    pub fn record_bus_send_request(
        &mut self,
        task: u64,
        req_id: u64,
        sender: u32,
        receiver: u32,
        schema_id: u32,
        bytes: u32,
    ) -> io::Result<u64> {
        let payload = BusSendRequest {
            req_id,
            sender,
            receiver,
            schema_id,
            bytes,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::BusSendRequest, &payload)
    }

    pub fn record_bus_decision(
        &mut self,
        task: u64,
        req_id: u64,
        allowed: bool,
        reason_code: u32,
    ) -> io::Result<u64> {
        let payload = BusDecision {
            req_id,
            allowed,
            reason_code,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::BusDecision, &payload)
    }

    pub fn record_bus_send_result(&mut self, task: u64, req_id: u64, ok: bool) -> io::Result<u64> {
        let payload = BusSendResult { req_id, ok }.to_bytes_le();
        self.record_event(task, EventKind::BusSendResult, &payload)
    }

    pub fn record_channel_created(
        &mut self,
        task: u64,
        req_id: u64,
        channel_id: u64,
        schema_id: u64,
        limits_digest: u64,
    ) -> io::Result<u64> {
        let payload = ChannelCreated {
            req_id,
            channel_id,
            schema_id,
            limits_digest,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::ChannelCreated, &payload)
    }

    pub fn record_channel_closed(
        &mut self,
        task: u64,
        req_id: u64,
        channel_id: u64,
    ) -> io::Result<u64> {
        let payload = ChannelClosed { req_id, channel_id }.to_bytes_le();
        self.record_event(task, EventKind::ChannelClosed, &payload)
    }

    pub fn record_message_sent(
        &mut self,
        task: u64,
        req_id: u64,
        channel_id: u64,
        sender_id: u32,
        sender_seq: u64,
        schema_id: u64,
        hash64: u64,
        size: u32,
    ) -> io::Result<u64> {
        let payload = MessageSent {
            req_id,
            channel_id,
            sender_id,
            sender_seq,
            schema_id,
            hash64,
            size,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::MessageSent, &payload)
    }

    pub fn record_message_delivered(
        &mut self,
        task: u64,
        req_id: u64,
        channel_id: u64,
        receiver_id: u32,
        sender_id: u32,
        sender_seq: u64,
        hash64: u64,
        size: u32,
    ) -> io::Result<u64> {
        let payload = MessageDelivered {
            req_id,
            channel_id,
            receiver_id,
            sender_id,
            sender_seq,
            hash64,
            size,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::MessageDelivered, &payload)
    }

    pub fn record_message_blocked(
        &mut self,
        task: u64,
        req_id: u64,
        channel_id: u64,
        receiver_id: u32,
    ) -> io::Result<u64> {
        let payload = MessageBlocked {
            req_id,
            channel_id,
            receiver_id,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::MessageBlocked, &payload)
    }

    pub fn record_deadlock_detected(
        &mut self,
        task: u64,
        tick: u64,
        blocked: u32,
        kind: u8,
    ) -> io::Result<u64> {
        let payload = DeadlockDetected {
            tick,
            blocked,
            kind,
        }
        .to_bytes_le();
        self.record_event(task, EventKind::DeadlockDetected, &payload)
    }

    pub fn record_deadlock_edge(
        &mut self,
        task: u64,
        from: u32,
        to: u32,
        reason: u8,
    ) -> io::Result<u64> {
        let payload = DeadlockEdge { from, to, reason }.to_bytes_le();
        self.record_event(task, EventKind::DeadlockEdge, &payload)
    }

    pub fn record_capability_invoked(
        &mut self,
        task: u64,
        payload: CapabilityInvoked,
    ) -> io::Result<u64> {
        let bytes = payload.to_bytes_le();
        self.record_event(task, EventKind::CapabilityInvoked, &bytes)
    }

    pub fn record_resource_violation(
        &mut self,
        task: u64,
        code: u32,
        digest: [u8; 32],
    ) -> io::Result<u64> {
        let payload = ResourceViolation {
            violation_code: code,
            detail_digest: digest,
        }
        .to_bytes_le();

        self.record_event(task, EventKind::ResourceViolation, &payload)
    }

    fn identity_provider(&self) -> identity::FileIdentityProvider {
        identity::default_file_identity_provider(self.agent_id)
    }

    pub fn record_evidence_final(&mut self, root: u64) -> io::Result<u64> {
        self.ensure_preamble()?;

        if self.evidence_emitted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "EvidenceFinal already recorded",
            ));
        }

        let run_hash_arr = self.current_stream_hash();

        let provider = self.identity_provider();
        let version = identity::EvidenceVersion::v0_8_1();
        let signature = identity::sign_evidence_v0_8_1_with_provider(
            &provider,
            version,
            self.agent_id,
            self.source_hash,
            self.codegen_hash,
            self.policy_hash,
            run_hash_arr,
        )?;

        let payload = EvidenceFinal {
            version: EvidenceVersion {
                format: version.format,
                hash_alg: version.hash_alg.as_u32(),
                sig_alg: version.sig_alg.as_u32(),
            },
            agent_id: self.agent_id,
            source_hash: self.source_hash,
            codegen_hash: self.codegen_hash,
            policy_hash: self.policy_hash,
            run_hash: run_hash_arr,
            public_key_b64: identity::encode_b64(&provider.public_key()?),
            signature_b64: identity::encode_b64(&signature),
            provider_id: provider.provider_id().to_string(),
        }
        .to_bytes_le();

        let seq = self.record_event(root, EventKind::EvidenceFinal, &payload)?;
        self.evidence_emitted = true;
        Ok(seq)
    }

    pub fn record_run_finished(&mut self, root: u64, exit: i32) -> io::Result<u64> {
        if !self.evidence_emitted {
            let _ = self.record_evidence_final(root)?;
        }

        let arr = self.current_stream_hash();

        let payload = RunFinished {
            exit_code: exit,
            run_hash_excluding_finish: arr,
        }
        .to_bytes_le();

        self.record_event(root, EventKind::RunFinished, &payload)
    }

    fn write_and_hash(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes)?;
        self.hasher.update(bytes);
        Ok(())
    }

    fn current_stream_hash(&self) -> [u8; 32] {
        let digest = self.hasher.clone().finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..]);
        out
    }
}
