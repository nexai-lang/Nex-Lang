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

use super::event::{
    CapabilityInvoked, EncodeLE, EventHeader, EventKind, FuelExhausted, ResourceViolation,
    RunFinished, TaskCancelled, TaskFinished, TaskJoined, TaskSpawned, TaskStarted, EVENT_MAGIC,
    EVENT_VERSION,
};
use super::event_sink::EventSink;
use super::jsonl_sink::JsonlSink;

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
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Mutex poisoned"))?;

    rec.attach_jsonl_sink(out_dir.as_ref(), jsonl_name)
}

pub struct EventRecorder {
    out_path: PathBuf,
    writer: BufWriter<File>,
    hasher: Sha256,
    wrote_preamble: bool,
    sinks: Vec<Box<dyn EventSink>>,
}

impl EventRecorder {
    pub fn open(out_dir: &Path, file_name: &str) -> io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;

        let out_path = out_dir.join(file_name);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out_path)?;

        Ok(Self {
            out_path,
            writer: BufWriter::new(file),
            hasher: Sha256::new(),
            wrote_preamble: false,
            sinks: Vec::new(),
        })
    }

    pub fn attach_jsonl_sink(&mut self, out_dir: &Path, jsonl_name: &str) -> io::Result<()> {
        std::fs::create_dir_all(out_dir)?;
        let path = out_dir.join(jsonl_name);
        let sink = JsonlSink::new(&path)?;
        self.sinks.push(Box::new(sink));
        Ok(())
    }

    fn ensure_preamble(&mut self) -> io::Result<()> {
        if self.wrote_preamble {
            return Ok(());
        }

        let mut pre = Vec::new();
        pre.extend_from_slice(&EVENT_MAGIC);
        pre.extend_from_slice(&EVENT_VERSION.to_le_bytes());

        self.write_and_hash(&pre)?;
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

        for sink in self.sinks.iter_mut() {
            sink.on_event(&header, payload)?;
            sink.flush()?;
        }

        Ok(seq)
    }

    // ---- Lifecycle ----

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

    // ---- Capability / Policy ----

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
