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
    CapabilityInvoked, EncodeLE, EventHeader, EventKind, FuelDebit, FuelReason, PickTask,
    ResourceViolation, RunFinished, SchedInit, SchedState, SchedStatePayload, TaskCancelled,
    TaskFinished, TaskJoined, TaskSpawned, TaskStarted, TickEnd, TickStart, YieldKind,
    YieldPayload, EVENT_MAGIC, EVENT_VERSION,
};
use super::event_sink::EventSink;
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
    wrote_preamble: bool,
    sinks: Vec<Box<dyn EventSink>>,

    flags: u16,
    codegen_hash: [u8; 32],
    source_hash: [u8; 32],
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
            wrote_preamble: false,
            sinks: Vec::new(),
            flags: 0,
            codegen_hash: [0u8; 32],
            source_hash: [0u8; 32],
        })
    }

    pub fn attach_jsonl_sink(&mut self, out_dir: &Path, jsonl_name: &str) -> io::Result<()> {
        std::fs::create_dir_all(out_dir)?;
        let path = out_dir.join(jsonl_name);
        let sink = JsonlSink::new(&path)?;
        self.sinks.push(Box::new(sink));
        Ok(())
    }

    pub fn set_hashes(&mut self, codegen_hash: [u8; 32], source_hash: [u8; 32]) {
        self.codegen_hash = codegen_hash;
        self.source_hash = source_hash;
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

        self.write_and_hash(&header_bytes)?;
        self.write_and_hash(payload)?;
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

    pub fn record_run_finished(&mut self, root: u64, exit: i32) -> io::Result<u64> {
        let hash = self.hasher.clone().finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash[..]);

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
}
