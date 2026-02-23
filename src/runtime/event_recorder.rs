// src/runtime/event_recorder.rs
//
// Canonical binary event recorder for NEX v0.5.x with fan-out sinks.
//
// Rules enforced:
// 1) Canonical supremacy: write+hash binary FIRST, then call sinks.
// 2) Deterministic encoding: event.rs uses explicit LE conversions.
// 3) Fail-fast: sink IO errors propagate (audit integrity).
// 4) Append-only: OpenOptions append, no truncation.
//
// Note: remaining nondeterminism from OS thread interleavings will be eliminated by the
// deterministic scheduler deliverable later in v0.5.x.

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
    CapabilityInvoked, EncodeLE, EventHeader, EventKind, FuelExhausted, ResourceViolation, RunFinished,
    TaskSpawned, EVENT_MAGIC, EVENT_VERSION,
};
use super::event_sink::EventSink;
use super::jsonl_sink::JsonlSink;

/// Global monotonic sequence counter.
static EVENT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Global recorder handle (single instance).
static RECORDER: OnceLock<Mutex<EventRecorder>> = OnceLock::new();

/// Fetch the global recorder. Panics if not initialized.
#[inline]
pub fn recorder() -> &'static Mutex<EventRecorder> {
    RECORDER.get().expect("EventRecorder not initialized")
}

/// Initialize the global recorder exactly once (binary only).
pub fn init_global_recorder(out_dir: impl AsRef<Path>, file_name: &str) -> io::Result<()> {
    let out_dir = out_dir.as_ref().to_path_buf();
    let file_name = file_name.to_owned();

    let recorder = EventRecorder::open(&out_dir, &file_name)?;
    RECORDER
        .set(Mutex::new(recorder))
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "EventRecorder already initialized"))?;
    Ok(())
}

/// Initialize the global recorder and attach a JsonlSink.
/// This is the simplest v0.5 Step 3 wiring.
pub fn init_global_recorder_with_jsonl(
    out_dir: impl AsRef<Path>,
    bin_name: &str,
    jsonl_name: &str,
) -> io::Result<()> {
    init_global_recorder(out_dir.as_ref(), bin_name)?;

    // Attach sink
    let mut rec = recorder()
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "EventRecorder mutex poisoned"))?;

    rec.attach_jsonl_sink(out_dir.as_ref(), jsonl_name)
}

/// Canonical binary event recorder.
pub struct EventRecorder {
    out_path: PathBuf,
    writer: BufWriter<File>,
    hasher: Sha256,

    bytes_written: u64,
    wrote_preamble: bool,

    sinks: Vec<Box<dyn EventSink>>,
}

impl EventRecorder {
    /// Open (or create) an append-only binary event stream in `out_dir`.
    pub fn open(out_dir: &Path, file_name: &str) -> io::Result<Self> {
        if file_name.trim().is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "file_name must be non-empty"));
        }

        std::fs::create_dir_all(out_dir)?;

        let out_path = out_dir.join(file_name);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(false)
            .open(&out_path)?;

        Ok(Self {
            out_path,
            writer: BufWriter::new(file),
            hasher: Sha256::new(),
            bytes_written: 0,
            wrote_preamble: false,
            sinks: Vec::new(),
        })
    }

    #[inline]
    pub fn path(&self) -> &Path {
        &self.out_path
    }

    /// Attach a sink (fan-out). Sinks are invoked AFTER binary write+hash.
    pub fn add_sink(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    /// Convenience: attach JsonlSink writing to `out_dir/jsonl_name`.
    pub fn attach_jsonl_sink(&mut self, out_dir: &Path, jsonl_name: &str) -> io::Result<()> {
        if jsonl_name.trim().is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "jsonl_name must be non-empty"));
        }
        std::fs::create_dir_all(out_dir)?;
        let jsonl_path = out_dir.join(jsonl_name);
        let sink = JsonlSink::new(&jsonl_path)?;
        self.add_sink(Box::new(sink));
        Ok(())
    }

    fn ensure_preamble(&mut self) -> io::Result<()> {
        if self.wrote_preamble {
            return Ok(());
        }

        // [magic:4][version:u16]
        let mut pre = Vec::with_capacity(4 + 2);
        pre.extend_from_slice(&EVENT_MAGIC);
        pre.extend_from_slice(&EVENT_VERSION.to_le_bytes());

        // Canonical supremacy: preamble is part of the canonical byte stream and hash.
        self.write_bytes_and_hash(&pre)?;
        self.flush_strict_binary()?;

        self.wrote_preamble = true;
        Ok(())
    }

    /// Canonical record function.
    ///
    /// Ordering rules:
    /// 1) assign seq
    /// 2) write+hash header
    /// 3) write+hash payload
    /// 4) flush binary (append-only integrity)
    /// 5) invoke sinks (fail-fast)
    /// 6) flush sinks
    pub fn record_event(&mut self, task_id: u64, kind: EventKind, payload_bytes: &[u8]) -> io::Result<u64> {
        self.ensure_preamble()?;

        let seq = EVENT_SEQ.fetch_add(1, Ordering::Relaxed);

        let header = EventHeader {
            seq,
            task_id,
            kind,
            payload_len: u32::try_from(payload_bytes.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "payload too large to fit into u32 payload_len",
                )
            })?,
        };

        let header_bytes = header.encode();

        // ---- Canonical supremacy: write+hash first ----
        self.write_bytes_and_hash(&header_bytes)?;
        self.write_bytes_and_hash(payload_bytes)?;
        self.flush_strict_binary()?; // minimize loss; append-only intent

        // ---- Fan-out sinks (fail-fast) ----
        for sink in self.sinks.iter_mut() {
            sink.on_event(&header, payload_bytes)?;
        }
        for sink in self.sinks.iter_mut() {
            sink.flush()?;
        }

        Ok(seq)
    }

    #[inline]
    pub fn record_task_spawned(&mut self, parent_task: u64, child_task: u64) -> io::Result<u64> {
        let payload = TaskSpawned {
            parent: parent_task,
            child: child_task,
        }
        .to_bytes_le();

        self.record_event(parent_task, EventKind::TaskSpawned, &payload)
    }

    #[inline]
    pub fn record_capability_invoked(&mut self, task_id: u64, payload: CapabilityInvoked) -> io::Result<u64> {
        let bytes = payload.to_bytes_le();
        self.record_event(task_id, EventKind::CapabilityInvoked, &bytes)
    }

    #[inline]
    pub fn record_fuel_exhausted(&mut self, task_id: u64, budget_before: u64, cost: u64) -> io::Result<u64> {
        let bytes = FuelExhausted { budget_before, cost }.to_bytes_le();
        self.record_event(task_id, EventKind::FuelExhausted, &bytes)
    }

    #[inline]
    pub fn record_resource_violation(
        &mut self,
        task_id: u64,
        violation_code: u32,
        detail_digest: [u8; 32],
    ) -> io::Result<u64> {
        let bytes = ResourceViolation {
            violation_code,
            detail_digest,
        }
        .to_bytes_le();

        self.record_event(task_id, EventKind::ResourceViolation, &bytes)
    }

    /// Snapshot hash of canonical stream so far (excluding any future events).
    #[inline]
    pub fn run_hash_snapshot(&self) -> [u8; 32] {
        let h = self.hasher.clone();
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out[..]);
        arr
    }

    /// Append RunFinished, embedding hash excluding the finish event.
    pub fn record_run_finished(&mut self, root_task_id: u64, exit_code: i32) -> io::Result<u64> {
        let hash_excl_finish = self.run_hash_snapshot();

        let payload = RunFinished {
            exit_code,
            run_hash_excluding_finish: hash_excl_finish,
        }
        .to_bytes_le();

        self.record_event(root_task_id, EventKind::RunFinished, &payload)
    }

    #[inline]
    fn flush_strict_binary(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    #[inline]
    fn write_bytes_and_hash(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes)?;
        self.hasher.update(bytes);
        self.bytes_written = self
            .bytes_written
            .checked_add(bytes.len() as u64)
            .expect("bytes_written overflow");
        Ok(())
    }

    #[inline]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}